"""
抖动分析器
分析 RTP 流的包间隔（Inter-packet Gap）稳定性。
"""
import numpy as np


def calc_inter_packet_gaps(packets: dict, ssrc: int, max_gap_ms: float = 200) -> dict:
    """计算指定 SSRC 的包间隔。
    
    Args:
        packets: RTP 包字典
        ssrc: 要分析的 SSRC
        max_gap_ms: 最大合理间隔（超过此值视为异常/静音）
        
    Returns:
        {
            'gaps': [(time, gap_ms), ...],
            'mean': float, 'median': float, 'std': float,
            'p95': float, 'p99': float, 'max': float,
            'abnormal_count': int,  # 间隔 >100ms 的次数
            'expected_interval': float,  # 推算的理想间隔
        }
    """
    from .rtp_parser import get_stream_packets
    
    pkts = get_stream_packets(packets, ssrc)
    if len(pkts) < 2:
        return _empty_gap_result()
    
    gaps = []
    for i in range(1, len(pkts)):
        gap = (pkts[i][0] - pkts[i-1][0]) * 1000
        if 0 < gap < max_gap_ms:
            gaps.append((pkts[i][0], gap))
    
    if not gaps:
        return _empty_gap_result()
    
    vals = [g[1] for g in gaps]
    # 理想间隔 = 出现次数最多的间隔（众数）
    hist, edges = np.histogram(vals, bins=50, range=(0, 50))
    expected = edges[np.argmax(hist)] + (edges[1] - edges[0]) / 2
    
    return {
        'gaps': [(float(t), float(g)) for t, g in gaps],
        'count': len(gaps),
        'mean': round(float(np.mean(vals)), 2),
        'median': round(float(np.median(vals)), 2),
        'std': round(float(np.std(vals)), 2),
        'p95': round(float(np.percentile(vals, 95)), 2),
        'p99': round(float(np.percentile(vals, 99)), 2),
        'max': round(float(np.max(vals)), 2),
        'abnormal_count': sum(1 for v in vals if v > 100),
        'expected_interval': round(float(expected), 1),
    }


def calc_cumulative_drift(packets: dict, ssrc: int, expected_interval_ms: float = None) -> dict:
    """计算累积时钟漂移（相对理想间隔的偏移）。
    
    Returns:
        {
            'drift': [(time, cumulative_offset_ms), ...],
            'total_drift_ms': float,  # 最终累积偏移
            'drift_rate': float,  # 漂移速率 (ms/s)
        }
    """
    from .rtp_parser import get_stream_packets
    
    pkts = get_stream_packets(packets, ssrc)
    if len(pkts) < 2:
        return {'drift': [], 'total_drift_ms': 0, 'drift_rate': 0}
    
    if expected_interval_ms is None:
        gaps_result = calc_inter_packet_gaps(packets, ssrc)
        expected_interval_ms = gaps_result.get('expected_interval', 20)
    
    drift = []
    offset = 0.0
    for i in range(1, len(pkts)):
        actual_gap = (pkts[i][0] - pkts[i-1][0]) * 1000
        offset += actual_gap - expected_interval_ms
        drift.append((pkts[i][0], offset))
    
    total_time = pkts[-1][0] - pkts[0][0]
    drift_rate = (offset / total_time * 1000) if total_time > 0 else 0  # ms/s
    
    return {
        'drift': [(float(t), round(float(o), 2)) for t, o in drift],
        'total_drift_ms': round(float(offset), 2),
        'drift_rate': round(float(drift_rate), 2),
    }


def compare_jitter(results: dict) -> dict:
    """对比多个流的抖动情况。
    
    Args:
        results: {label: gap_result, ...}
        
    Returns:
        {
            'comparison': [{label, mean, std, abnormal_count, expected_interval}, ...],
            'worst_label': str,  # 抖动最严重的流
        }
    """
    comparison = []
    worst_label = None
    worst_std = 0
    
    for label, result in results.items():
        if not result or result['mean'] == 0:
            continue
        item = {
            'label': label,
            'mean': result['mean'],
            'median': result['median'],
            'std': result['std'],
            'abnormal_count': result['abnormal_count'],
            'expected_interval': result['expected_interval'],
        }
        comparison.append(item)
        if result['std'] > worst_std:
            worst_std = result['std']
            worst_label = label
    
    return {
        'comparison': comparison,
        'worst_label': worst_label,
    }


def _empty_gap_result() -> dict:
    return {
        'gaps': [],
        'count': 0,
        'mean': 0, 'median': 0, 'std': 0,
        'p95': 0, 'p99': 0, 'max': 0,
        'abnormal_count': 0,
        'expected_interval': 0,
    }