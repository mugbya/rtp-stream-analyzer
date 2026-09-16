"""
分段延迟链路定位

把"哪一侧听到的声音延迟大"拆成逐段测量（主叫→坐席 / 坐席→主叫 两个方向）：

- 端点→FS 网络段：同一 (SSRC, seq) 的包在端点抓包与 FS 抓包里的到达时刻差
  （calc_cross_capture_delay）。两台抓包机时钟不同步时，测量值里混入恒定
  偏移（clock_offset_ms 为中位数估计），绝对值仅供参考；去偏移后的波动
  （detrended_p95）才反映该段的抖动/突发。
- FS 内部处理段：同一抓包内"入站 SSRC → 出站 SSRC"的转发间隔
  （calc_fs_internal_delay），单一时钟、测量精确，是链路中最可信的一段。
- FS→端点网络段：同跨抓包匹配。

时钟偏移的消除：同一段路径往返两个方向的测量之和会抵消偏移（上行含
C_端−C_FS，反向下行含 C_FS−C_端），roundtrip 一节给出该无偏移参考值，
用它判断"这条链路整体是否偏慢"。接收端抖动缓冲与播放设备等应用层延迟
在抓包中不可见，不在测量范围。
"""
from analyzer.delay_analyzer import calc_cross_capture_delay, calc_fs_internal_delay
from analyzer.stream_classifier import pick_call_stream

# 跨抓包段：去时钟偏移后的 P95 波动超过此值，视为该段抖动/突发偏大
CROSS_HIGH_P95_MS = 150.0
# FS 内部段：均值超过此值视为处理延迟偏高（与结论阈值一致）
FS_INTERNAL_HIGH_MS = 50.0
# 往返参考值（上+下两段均值之和）超过此值提示链路整体偏慢
ROUNDTRIP_HIGH_MS = 300.0

_ROLE_NAMES = {'terminal': '主叫', 'seat': '被叫'}


def build_delay_chains(captures: dict, call: dict, server_ip: str,
                       parties: dict = None) -> dict:
    """按通话的两个方向构建分段延迟链路。

    Args:
        captures: {role: rtp_data}，rtp_data 需带 _role / packets / streams。
        call: detect_calls 输出的单通通话（ssrcs / is_p2p）。
        server_ip: 服务器 IP。
        parties: extract_call_parties 的输出 {'caller_ip', 'answerer_ip',
            ...}，SIP 识别的双方 IP，可选；缺失时无法从 FS 抓包兜底选流。

    Returns:
        {
            'available': bool,
            'p2p': bool,
            'directions': [{label, speaker, listener, verdict, verdict_text,
                            segments: [{kind, name, ssrc, available, count,
                                       mean, p50, p95, clock_offset_ms,
                                       detrended_p95, status, note}],
                            total_mean, total_note}],
            'roundtrip': [{pair, ms, status, note}],
            'notes': [全局说明...],
        }
    """
    call_ssrcs = set(call.get('ssrcs') or [])
    fs_cap = captures.get('fs') or captures.get('FS')
    p2p = bool(call.get('is_p2p'))
    parties = parties or {}

    specs = []
    for speaker_role, listener_role, spk_key, lst_key in (
            ('terminal', 'seat', 'caller_ip', 'answerer_ip'),
            ('seat', 'terminal', 'answerer_ip', 'caller_ip')):
        specs.append({
            'speaker_role': speaker_role,
            'listener_role': listener_role,
            'speaker_ip': parties.get(spk_key),
            'listener_ip': parties.get(lst_key),
            'speaker_name': _ROLE_NAMES.get(speaker_role, speaker_role),
            'listener_name': _ROLE_NAMES.get(listener_role, listener_role),
        })

    directions = []
    segments_by_key = {}     # (role, 'up'|'down') -> 段结果，供往返合并
    for spec in specs:
        d, segs = _chain_for_direction(captures, fs_cap, call_ssrcs,
                                       server_ip, p2p, spec)
        if d is not None:
            directions.append(d)
            segments_by_key.update(segs)

    roundtrips = []
    for role in ('terminal', 'seat'):
        up = segments_by_key.get((role, 'up'))
        down = segments_by_key.get((role, 'down'))
        if not (up and down and up.get('available') and down.get('available')):
            continue
        name = _ROLE_NAMES.get(role, role)
        ms = round(up['mean'] + down['mean'], 1)
        roundtrips.append({
            'pair': f'{name}端往返（{name}→FS→{name}）',
            'ms': ms,
            'status': 'high' if ms > ROUNDTRIP_HIGH_MS else 'ok',
            'note': '往返两段的时钟偏移互相抵消，此值不含抓包间时钟差',
        })

    available = any(s.get('available') for d in directions
                    for s in d['segments']) or bool(roundtrips)

    notes = []
    if p2p:
        notes.append('点对点直连：链路只有一段网络路径，无 FS 内部段')
    else:
        notes.append('跨抓包段的绝对延迟同时包含真实传播时延与抓包机时钟偏移，'
                     '单段测量无法区分二者；往返之和可抵消时钟偏移，'
                     '见往返参考值')
        notes.append('接收端抖动缓冲与播放设备延迟不在抓包中体现，'
                     '测量值为网络传输 + FS 处理延迟')
    return {'available': available, 'p2p': p2p, 'directions': directions,
            'roundtrip': roundtrips, 'notes': notes}


def _chain_for_direction(captures, fs_cap, call_ssrcs, server_ip, p2p, spec):
    """构建一个方向的分段链路。完全无数据时返回 (None, {})。"""
    spk_cap = captures.get(spec['speaker_role'])
    lst_cap = captures.get(spec['listener_role'])
    if not spk_cap and not lst_cap and not fs_cap:
        return None, {}

    peer_of_speaker = spec['listener_ip'] if p2p else server_ip
    peer_of_listener = spec['speaker_ip'] if p2p else server_ip

    # 选流：上行=发言端发出的流（端点抓包优先，FS 抓包按发言端 IP 兜底）；
    # 下行=听者收到的流（端点抓包优先，FS 抓包按听者 IP 兜底）。
    # p2p 且无 SIP 双方 IP 时退化为"端点抓包内取最大通话流"（方向标注可能
    # 随抓包内容互换，但两段测量仍然成立）
    uplink = None
    if spk_cap:
        if peer_of_speaker:
            uplink = pick_call_stream(spk_cap, call_ssrcs, dst_is=peer_of_speaker)
        if uplink is None and p2p:
            uplink = pick_call_stream(spk_cap, call_ssrcs)
    if uplink is None and fs_cap and spec['speaker_ip']:
        uplink = pick_call_stream(fs_cap, call_ssrcs, src_is=spec['speaker_ip'])
    downlink = None
    if lst_cap:
        if peer_of_listener:
            downlink = pick_call_stream(lst_cap, call_ssrcs, src_is=peer_of_listener)
        if downlink is None and p2p:
            downlink = pick_call_stream(lst_cap, call_ssrcs)
    if downlink is None and fs_cap and spec['listener_ip']:
        downlink = pick_call_stream(fs_cap, call_ssrcs, dst_is=spec['listener_ip'])

    if uplink is None and downlink is None:
        return None, {}

    if p2p:
        segments = [_cross_segment(
            spk_cap, lst_cap, uplink if uplink is not None else downlink,
            f"直连（{spec['speaker_name']} → {spec['listener_name']}）",
            f"{spec['speaker_name']}端抓包", f"{spec['listener_name']}端抓包")]
        segs = {}
    else:
        up_seg = _cross_segment(
            spk_cap, fs_cap, uplink, f"{spec['speaker_name']} → FS",
            f"{spec['speaker_name']}端抓包", 'FS 抓包')
        fs_seg = _fs_segment(fs_cap, uplink, downlink, spec)
        down_seg = _cross_segment(
            fs_cap, lst_cap, downlink, f"FS → {spec['listener_name']}",
            'FS 抓包', f"{spec['listener_name']}端抓包")
        segments = [up_seg, fs_seg, down_seg]
        segs = {(spec['speaker_role'], 'up'): up_seg,
                (spec['listener_role'], 'down'): down_seg}

    avail = [s for s in segments if s['available']]
    highs = [s for s in avail if s['status'] == 'high']
    if not avail:
        verdict, text = 'unavailable', '缺少可比对的抓包点，无法测量该方向延迟'
    elif highs:
        verdict = 'high'
        text = '以下段延迟/波动偏高：' + '、'.join(s['name'] for s in highs)
        if len(avail) < len(segments):
            text += '（另有未测到的段，见明细）'
    elif len(avail) < len(segments):
        verdict = 'partial'
        text = ('已测到的段延迟正常；'
                + '、'.join(s['name'] for s in segments if not s['available'])
                + ' 未测到（缺抓包点）')
    else:
        verdict, text = 'ok', '各段延迟均在正常范围'

    total_mean = round(sum(s['mean'] for s in avail), 1) if avail else None
    total_note = None
    if any(s['kind'] == 'cross' and s['available'] for s in avail):
        total_note = '跨抓包段的均值含抓包间时钟偏移，仅供参考'
    label = f"{spec['speaker_name']} → {spec['listener_name']}"
    return {'label': label, 'speaker': spec['speaker_name'],
            'listener': spec['listener_name'], 'verdict': verdict,
            'verdict_text': text, 'segments': segments,
            'total_mean': total_mean, 'total_note': total_note}, segs


def _cross_segment(cap_a, cap_b, ssrc, name, a_name, b_name) -> dict:
    """跨抓包网络段：同一 (SSRC, seq) 在两个抓包点的到达时刻差。"""
    seg = _seg_base('cross', name, ssrc)
    if ssrc is None:
        seg['note'] = '未识别该段媒体流'
        return seg
    missing = [n for c, n in ((cap_a, a_name), (cap_b, b_name)) if c is None]
    if missing:
        seg['note'] = f"缺少{'、'.join(missing)}，无法比对到达时刻"
        return seg
    r = calc_cross_capture_delay(cap_a['packets'], cap_b['packets'], ssrc,
                                 a_name, b_name)
    if r['count'] == 0:
        seg['note'] = (f'两个抓包点未匹配到共同包'
                       f'（{a_name}或{b_name}可能未覆盖该流）')
        return seg
    offset = r.get('clock_offset_ms')
    det_p95 = round(r.get('detrended_p95', 0.0), 2)
    seg.update({'available': True, 'count': r['count'], 'mean': r['mean'],
                'p50': r['p50'], 'p95': r['p95'],
                'clock_offset_ms': round(offset, 2) if offset is not None else None,
                'detrended_p95': det_p95})
    notes = []
    if offset is not None and abs(offset) > 300:
        notes.append(f'两台抓包机时钟差异约 {offset:.0f}ms（含传播时延），'
                     '绝对值不可信')
    if det_p95 > CROSS_HIGH_P95_MS:
        seg['status'] = 'high'
        notes.append(f'去偏移后 P95 波动 {det_p95:.0f}ms，该段抖动/突发偏大')
    else:
        seg['status'] = 'ok'
        notes.append(f'去偏移后波动 P95 {det_p95:.0f}ms')
    seg['note'] = '；'.join(notes)
    return seg


def _fs_segment(fs_cap, ssrc_in, ssrc_out, spec) -> dict:
    """FS 内部处理段：同一抓包内入站→出站的转发间隔（单时钟，可信）。"""
    seg = _seg_base('fs_internal', 'FS 内部处理', ssrc_in)
    if fs_cap is None:
        seg['note'] = '缺少 FS 抓包，无法测量'
        return seg
    if ssrc_in is None or ssrc_out is None:
        seg['note'] = '未同时识别该方向的入站/出站流'
        return seg
    seg['ssrc'] = f'0x{ssrc_in:08x} → 0x{ssrc_out:08x}'
    r = calc_fs_internal_delay(fs_cap['packets'], ssrc_in, ssrc_out)
    if r['count'] == 0:
        seg['note'] = '入站→出站未匹配到转发对（FS 可能未转发该方向媒体）'
        return seg
    seg.update({'available': True, 'count': r['count'], 'mean': r['mean'],
                'p50': r['p50'], 'p95': r['p95']})
    if r['mean'] >= FS_INTERNAL_HIGH_MS:
        seg['status'] = 'high'
        seg['note'] = f'FS 内部处理延迟偏高（均值 {r["mean"]:.1f}ms）'
    else:
        seg['status'] = 'ok'
        seg['note'] = f'单时钟测量可信（均值 {r["mean"]:.1f}ms）'
    return seg


def _seg_base(kind: str, name: str, ssrc) -> dict:
    return {'kind': kind, 'name': name,
            'ssrc': f'0x{ssrc:08x}' if ssrc is not None else None,
            'available': False, 'count': 0, 'mean': None, 'p50': None,
            'p95': None, 'clock_offset_ms': None, 'detrended_p95': None,
            'status': 'unavailable', 'note': ''}
