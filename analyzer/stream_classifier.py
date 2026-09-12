"""
RTP 流分类器
区分音频流和视频流，识别流方向。
"""

# 标准音频 PT (Payload Type)
AUDIO_PT = {0, 3, 8, 9, 18}  # PCMU, GSM, PCMA, G722, G729

# 常见视频 PT（动态分配，通常 96-127）
VIDEO_PT_RANGE = range(96, 128)

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
    
    Returns:
        {
            'audio': {ssrc: stream_info, ...},
            'video': {ssrc: stream_info, ...},
            'unknown': {ssrc: stream_info, ...},
        }
    """
    result = {'audio': {}, 'video': {}, 'unknown': {}}
    for ssrc, info in streams.items():
        category = classify_stream(info)
        result[category][ssrc] = info
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


def detect_server_ip(all_streams: dict) -> str:
    """自动检测服务器 IP（通常是 SIP 5060 端口 + 多 RTP 流）。
    
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
    
    # 连接数最多的 IP 可能是服务器
    if ip_connections:
        return max(ip_connections, key=ip_connections.get)
    return None