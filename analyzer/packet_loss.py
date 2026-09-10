"""
丢包检测器
通过 RTP 序列号连续性检查丢包情况。
"""
from .rtp_parser import get_stream_packets


def detect_packet_loss(packets: dict, ssrc: int) -> dict:
    """检测指定 SSRC 的丢包情况。
    
    Returns:
        {
            'total_packets': int,
            'total_lost': int,
            'loss_rate_pct': float,
            'loss_events': [(time, count), ...],  # 丢包事件
            'max_consecutive_loss': int,
            'is_clean': bool,
        }
    """
    pkts = get_stream_packets(packets, ssrc)
    if len(pkts) < 2:
        return _empty_loss_result()
    
    seqs = [(p[0], p[1]) for p in pkts]  # (time, seq)
    
    total_lost = 0
    loss_events = []
    max_consecutive = 0
    current_consecutive = 0
    
    for i in range(1, len(seqs)):
        expected = (seqs[i-1][1] + 1) & 0xFFFF
        actual = seqs[i][1]
        if expected != actual:
            lost = (actual - expected) & 0xFFFF
            total_lost += lost
            loss_events.append((seqs[i][0], lost))
            current_consecutive += lost
            max_consecutive = max(max_consecutive, lost)
        else:
            current_consecutive = 0
    
    total = len(pkts) + total_lost
    loss_rate = (total_lost / total * 100) if total > 0 else 0
    
    return {
        'total_packets': len(pkts),
        'total_lost': total_lost,
        'loss_rate_pct': round(loss_rate, 4),
        'loss_events': [(float(t), l) for t, l in loss_events],
        'loss_event_count': len(loss_events),
        'max_consecutive_loss': max_consecutive,
        'is_clean': total_lost == 0,
    }


def detect_all_losses(packets: dict, ssrcs: list, labels: dict = None) -> dict:
    """批量检测多个 SSRC 的丢包。
    
    Args:
        packets: RTP 包字典
        ssrcs: 要检测的 SSRC 列表
        labels: {ssrc: label} 可选标签
        
    Returns:
        {ssrc: loss_result, ...}
    """
    results = {}
    for ssrc in ssrcs:
        label = labels.get(ssrc, f'SSRC=0x{ssrc:08x}') if labels else f'SSRC=0x{ssrc:08x}'
        result = detect_packet_loss(packets, ssrc)
        result['label'] = label
        results[ssrc] = result
    return results


def _empty_loss_result() -> dict:
    return {
        'total_packets': 0, 'total_lost': 0, 'loss_rate_pct': 0,
        'loss_events': [], 'loss_event_count': 0,
        'max_consecutive_loss': 0, 'is_clean': True,
    }