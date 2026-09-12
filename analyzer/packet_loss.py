"""
丢包检测器
通过 RTP 序列号连续性检查丢包情况。

按捕获时间序维护 32 位扩展序号与"缺包集合"：seq 前进留下的缺口记为
待定丢包，迟到的乱序包补上缺口时退还，因此离线统计的丢包数是最终真实
值——乱序不再被回绕运算放大成六万多个"丢包"。乱序本身单独计数；静音
抑制（seq 连续但媒体时间断档）不由 seq 判定，由 ts_continuity 模块用
时间戳标注。
"""
from .rtp_parser import get_stream_packets

# seq 差值超过此值视为倒退（乱序）而非前进
SEQ_BACKWARD = 1 << 15
SEQ_SPACE = 1 << 16


def detect_packet_loss(packets: dict, ssrc: int) -> dict:
    """检测指定 SSRC 的丢包情况。

    Returns:
        {
            'total_packets': int,
            'total_lost': int,
            'loss_rate_pct': float,
            'loss_events': [(time, count), ...],  # 观察到的缺口（含后来被
                                                  # 乱序包补上的，供定位时间点）
            'max_consecutive_loss': int,
            'reorder_count': int,  # 乱序倒退次数（不计入丢包）
            'is_clean': bool,
        }
    """
    pkts = get_stream_packets(packets, ssrc)
    if len(pkts) < 2:
        return _empty_loss_result()

    loss_events = []
    max_consecutive = 0
    current_consecutive = 0
    reorder_count = 0
    missing = set()  # 扩展序号空间里尚未到达的包

    prev_seq = pkts[0][1]
    prev_ext = prev_seq
    cycles = 0
    for time, seq, *_ in pkts[1:]:
        d = (seq - prev_seq) & (SEQ_SPACE - 1)
        if d == 0:
            continue  # 同一 (ssrc, seq) 在提取时已去重，防御性跳过
        if d < SEQ_BACKWARD:
            # 前进（可能越过 65535→0 回绕）
            if seq < prev_seq:
                cycles += 1
            ext = seq + cycles * SEQ_SPACE
            gap = ext - prev_ext - 1
            if gap > 0:
                missing.update(range(prev_ext + 1, ext))
                loss_events.append((float(time), gap))
                current_consecutive += gap
                max_consecutive = max(max_consecutive, gap)
            prev_seq, prev_ext = seq, ext
        else:
            # 倒退 = 迟到的乱序包：若它在此前的缺口里，退还多记的丢包
            ext = seq + cycles * SEQ_SPACE
            if ext in missing:
                missing.discard(ext)
            elif ext - SEQ_SPACE in missing:
                # 回绕边界附近的乱序：缺包记录在上一圈
                missing.discard(ext - SEQ_SPACE)
            reorder_count += 1
            current_consecutive = 0

    total_lost = len(missing)
    total = len(pkts) + total_lost
    loss_rate = (total_lost / total * 100) if total > 0 else 0

    return {
        'total_packets': len(pkts),
        'total_lost': total_lost,
        'loss_rate_pct': round(loss_rate, 4),
        'loss_events': loss_events,
        'loss_event_count': len(loss_events),
        'max_consecutive_loss': max_consecutive,
        'reorder_count': reorder_count,
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
        'max_consecutive_loss': 0, 'reorder_count': 0, 'is_clean': True,
    }
