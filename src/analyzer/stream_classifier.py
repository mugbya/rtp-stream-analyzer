"""
RTP 流分类器
区分音频流和视频流，识别流方向。
"""

# 标准音频 PT (Payload Type)
AUDIO_PT = {0, 3, 8, 9, 18}  # PCMU, GSM, PCMA, G722, G729

# 常见视频 PT（动态分配，通常 96-127）
VIDEO_PT_RANGE = range(96, 128)

# 动态 PT（96-127）按媒体种类独立分配：同一号码在 audio 与 video 两个 m= 行
# 里可以指不同编码（实测：audio 96=OPUS、video 96=H264），只看 PT 号无法
# 区分音视频。除静态 PT 表外按三类证据判定：
# 1. SDP 端口绑定：流两端 (ip,port) 命中 SDP 宣告的媒体端点（权威）；
# 2. rtpmap：该 PT 只出现在某一类媒体的 rtpmap 里；
# 3. 实测 RTP 时钟率：发送端媒体时钟对协议是固定的（OPUS=48kHz、
#    视频=90kHz），从时间戳增量/到达间隔中位数估计，无信令抓包也能判。
AUDIO_CLOCK_EST = (7200, 8800, 43000, 53000)   # 落入区间视为音频（8k/48k）
VIDEO_CLOCK_EST = (81000, 99000)               # 落入区间视为视频（90k）


def resolve_stream_kind(port_pairs, pts, est_clock=None,
                        port_kinds=None, pt_maps=None):
    """判定一条流是音频还是视频，返回 (kind, codec_name, clock_rate)。

    Args:
        port_pairs: 流的 (src_ip, src_port, dst_ip, dst_port) 列表。
        pts: 流出现过的 PT 集合。
        est_clock: 实测 RTP 时钟率估计（Hz），无样本时为 None。
        port_kinds: {(ip, port): 'audio'|'video'}，SDP 宣告的媒体端点。
        pt_maps: {'audio': {pt: {'name','rate'}}, 'video': {...}}，SDP rtpmap。

    Returns:
        (kind, codec, clock)：kind 为 'audio'|'video'|'unknown'；codec 为
        编码名（SDP rtpmap > 静态表，判不出为 None）；clock 为 RTP 时钟率。
    """
    kind = None
    codec = None
    clock = None
    main_pt = sorted(pts)[0] if pts else None

    # 1. SDP 端口绑定：媒体只发往/发自宣告的媒体端口，命中即定种类
    if port_kinds and port_pairs:
        hits = {'audio': 0, 'video': 0}
        for pp in port_pairs:
            for ip, port in ((pp[0], pp[1]), (pp[2], pp[3])):
                k = port_kinds.get((ip, port))
                if k:
                    hits[k] += 1
        if hits['audio'] and not hits['video']:
            kind = 'audio'
        elif hits['video'] and not hits['audio']:
            kind = 'video'

    # 2. rtpmap：该 PT 只在一类媒体的 rtpmap 里出现（两端同号复用时无结论）
    if kind is None and pt_maps and main_pt is not None:
        in_audio = main_pt in pt_maps.get('audio', {})
        in_video = main_pt in pt_maps.get('video', {})
        if in_audio and not in_video:
            kind = 'audio'
        elif in_video and not in_audio:
            kind = 'video'

    # 3. 实测时钟率：无信令的抓包里唯一可靠的信号
    if kind is None and est_clock:
        lo8, hi8, lo48, hi48 = AUDIO_CLOCK_EST
        vlo, vhi = VIDEO_CLOCK_EST
        if lo48 <= est_clock <= hi48 or lo8 <= est_clock <= hi8:
            kind = 'audio'
        elif vlo <= est_clock <= vhi:
            kind = 'video'

    # 4. 静态 PT 表兜底：动态 PT 无任何证据时维持旧口径（96-127 视为视频）
    if kind is None and main_pt is not None:
        if main_pt in AUDIO_PT:
            kind = 'audio'
        elif main_pt in VIDEO_PT_RANGE:
            kind = 'video'

    if kind == 'audio':
        entry = (pt_maps or {}).get('audio', {}).get(main_pt)
        codec = (entry or {}).get('name') or PT_NAMES.get(main_pt)
        clock = (entry or {}).get('rate') or (
            48000 if codec and codec.upper().startswith('OPUS') else AUDIO_CLOCK_RATE)
    elif kind == 'video':
        entry = (pt_maps or {}).get('video', {}).get(main_pt)
        codec = (entry or {}).get('name')
        clock = (entry or {}).get('rate') or VIDEO_CLOCK_RATE
    return kind, codec, clock

# 已知的音频 PT 名称
PT_NAMES = {
    0: 'PCMU (G.711 μ-law)',
    3: 'GSM',
    8: 'PCMA (G.711 A-law)',
    9: 'G722',
    18: 'G729',
}


def classify_stream(stream_info: dict) -> str:
    """根据 PT 分类流类型。
    
    Args:
        stream_info: {'count': int, 'pt': [int, ...], ...}
        
    Returns:
        'audio' | 'video' | 'unknown'
    """
    pts = stream_info.get('pt', [])
    if not pts:
        return 'unknown'
    
    for pt in pts:
        if pt in AUDIO_PT:
            return 'audio'
    for pt in pts:
        if pt in VIDEO_PT_RANGE:
            return 'video'
    return 'unknown'


def classify_all_streams(streams: dict) -> dict:
    """对所有流进行分类。

    流信息里带 kind（rtp_parser 结合 SDP/时钟率解析出的种类）时直接采用；
    没有时回退到按 PT 号判断。注意动态 PT（96-127）按媒体种类独立分配，
    只看 PT 号会把 OPUS 音频误判成视频——带信令的抓包应依赖 kind。

    Returns:
        {
            'audio': {ssrc: stream_info, ...},
            'video': {ssrc: stream_info, ...},
            'unknown': {ssrc: stream_info, ...},
        }
    """
    result = {'audio': {}, 'video': {}, 'unknown': {}}
    for ssrc, info in streams.items():
        kind = info.get('kind') or classify_stream(info)
        result[kind if kind in result else 'unknown'][ssrc] = info
    return result


# RTP 时钟率（Hz）：把时间戳增量换算成媒体时间用。G722 采样 16kHz 但
# 按 RFC 3551 其 RTP 时钟仍是 8000；动态 PT 96-127 按视频惯例取 90000
AUDIO_CLOCK_RATE = 8000
VIDEO_CLOCK_RATE = 90000


def get_clock_rate(pt: int):
    """获取 PT 对应的 RTP 时钟率，未知 PT 返回 None。"""
    if pt in AUDIO_PT:
        return AUDIO_CLOCK_RATE
    if pt in VIDEO_PT_RANGE:
        return VIDEO_CLOCK_RATE
    return None


def get_pt_name(pt: int) -> str:
    """获取 PT 的可读名称。"""
    if pt in PT_NAMES:
        return PT_NAMES[pt]
    if pt in VIDEO_PT_RANGE:
        return f'Dynamic (Video, PT={pt})'
    return f'Unknown (PT={pt})'


def identify_direction(stream_info: dict, server_ip: str = None) -> str:
    """识别流方向：入站还是出站（相对服务器）。
    
    Args:
        stream_info: 流信息
        server_ip: 服务器 IP（如果已知）
        
    Returns:
        'inbound' | 'outbound' | 'unknown'
    """
    port_pairs = stream_info.get('port_pairs', [])
    if not port_pairs or not server_ip:
        return 'unknown'
    
    for pp in port_pairs:
        src_ip, src_port, dst_ip, dst_port = pp
        if dst_ip == server_ip:
            return 'inbound'
        if src_ip == server_ip:
            return 'outbound'
    return 'unknown'


def detect_server_ip(all_streams: dict, sip_events: list = None) -> str:
    """自动检测服务器 IP（通常是 FS 端）。

    主判定：各 IP 在 RTP 端口对里的出现次数，服务器转发所有流必然最多。
    单侧抓包（只传终端或坐席的 pcap）时所有端点出现次数必然打平，数不出
    服务器——此时用 SIP INVITE 的 Via 头数消歧：
    - 只有 1 条 Via：INVITE 是主叫终端自发 → 服务器是 INVITE 的目标；
    - 有 ≥2 条 Via：INVITE 经 FS 转发而来（抓包点在被叫侧）→ 服务器是
      INVITE 的来源。

    Args:
        all_streams: {ssrc: {port_pairs, ...}}，全部抓包的 RTP 流。
        sip_events: 各抓包的 SIP 事件（含 via_count），无信令时为空。

    Returns:
        推测的服务器 IP，或 None
    """
    ip_connections = {}
    for ssrc, info in all_streams.items():
        for pp in info.get('port_pairs', []):
            src_ip = pp[0]
            dst_ip = pp[2]
            ip_connections[src_ip] = ip_connections.get(src_ip, 0) + 1
            ip_connections[dst_ip] = ip_connections.get(dst_ip, 0) + 1

    if not ip_connections:
        return None

    # 连接数最多的 IP 可能是服务器；唯一最大值时直接采用
    ranked = sorted(ip_connections.items(), key=lambda kv: kv[1], reverse=True)
    if len(ranked) == 1 or ranked[0][1] > ranked[1][1]:
        return ranked[0][0]

    # 打平（单侧抓包的典型形态）：信令消歧，只在候选 IP 命中时采用
    inv = next((ev for ev in sip_events or []
                if ev.get('method') == 'INVITE'), None)
    if inv is not None and inv.get('via_count'):
        via = inv['via_count']
        candidate = inv.get('dst') if via == 1 else inv.get('src')
        if candidate in ip_connections:
            return candidate
    return ranked[0][0]


def _norm_ip_cond(cond):
    """归一化 src_is/dst_is 的 IP 条件。

    单个 IP（str）→ 单元素元组；否则原样（list/tuple/set 均可 `in` 匹配）。
    不能把 IP 字符串当子串做 `in` 判断（如 '10.1' in '10.1.2.3' 会误命中）。
    """
    if cond is None:
        return None
    if isinstance(cond, str):
        return (cond,)
    return tuple(cond)


def pick_call_stream(cap: dict, call_ssrcs, src_is=None, dst_is=None):
    """在一份抓包里按收发 IP 条件选通话音频流（多个命中取包数最多的）。

    Args:
        cap: extract_rtp_packets 的输出（含 streams）。
        call_ssrcs: 通话的候选 SSRC 集合。
        src_is / dst_is: 要求流出现在 src→dst 方向的 IP 条件，None 不限制。
            可传单个 IP 字符串，或 IP 可迭代对象（NAT 场景下同一端有信令 IP
            与 SDP 宣告的别名地址，任一命中即可）。

    Returns:
        命中的 SSRC，或 None。
    """
    src_cond = _norm_ip_cond(src_is)
    dst_cond = _norm_ip_cond(dst_is)
    best, best_n = None, 0
    for ssrc in call_ssrcs:
        info = (cap.get('streams') or {}).get(ssrc)
        if not info:
            continue
        # 动态 PT 音频（如 OPUS@96）靠解析时标注的 kind 识别
        if info.get('kind') != 'audio' and \
                not any(pt in AUDIO_PT for pt in info.get('pt', [])):
            continue
        for pp in info.get('port_pairs') or []:
            if src_cond and pp[0] not in src_cond:
                continue
            if dst_cond and pp[2] not in dst_cond:
                continue
            if info['count'] > best_n:
                best, best_n = ssrc, info['count']
            break
    return best