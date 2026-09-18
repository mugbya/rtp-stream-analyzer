"""
延迟分析器
计算 FS 内部处理延迟、跨抓包网络延迟、端到端延迟。
支持时钟偏移自动检测和修正。
"""
import numpy as np
from collections import defaultdict


def calc_fs_internal_delay(packets_fs: dict, ssrc_in: int, ssrc_out: int) -> dict:
    """计算 FS 内部处理延迟（入站 SSRC → 出站 SSRC）。
    
    使用滑动窗口匹配：对每个入站包，找到时间最接近且 >= 入站时间的出站包。
    
    Args:
        packets_fs: FS 侧 RTP 包字典 {(ssrc, seq): (time, rtp_ts, pt, ...)}
        ssrc_in: 入站 SSRC（如坐席→FS）
        ssrc_out: 出站 SSRC（如 FS→终端）
        
    Returns:
        {
            'delays': [(time, delay_ms), ...],     # 延迟时间序列
            'mean': float, 'median': float, 'p50': float,
            'p95': float, 'p99': float, 'max': float, 'min': float,
            'std': float, 'count': int,
            'outliers_50ms': int, 'outliers_100ms': int,
        }
    """
    in_pkts = sorted([(v[0], k[1]) for k, v in packets_fs.items() if k[0] == ssrc_in])
    out_pkts = sorted([(v[0], k[1]) for k, v in packets_fs.items() if k[0] == ssrc_out])
    
    if not in_pkts or not out_pkts:
        return _empty_delay_result()
    
    delays = []
    j = 0
    for in_time, in_seq in in_pkts:
        while j < len(out_pkts) and out_pkts[j][0] < in_time:
            j += 1
        if j < len(out_pkts):
            delay = (out_pkts[j][0] - in_time) * 1000
            if 0 <= delay < 500:
                delays.append((in_time, delay))
    
    return _summarize_delays(delays)


def calc_cross_capture_delay(packets_a: dict, packets_b: dict, 
                              ssrc: int, label_a: str = 'A', label_b: str = 'B') -> dict:
    """计算跨抓包延迟（同一 SSRC+seq 在两个抓包点的到达时间差）。
    
    Args:
        packets_a: 抓包点 A 的 RTP 包
        packets_b: 抓包点 B 的 RTP 包
        ssrc: 要分析的 SSRC
        label_a, label_b: 标签（用于结果描述）
        
    Returns:
        延迟统计字典，额外包含 'clock_offset_ms'（估算的时钟偏移）
    """
    delays = []
    for key in packets_a:
        if key[0] == ssrc and key in packets_b:
            time_a = packets_a[key][0]
            time_b = packets_b[key][0]
            delay = (time_b - time_a) * 1000
            delays.append((time_a, delay))
    
    result = _summarize_delays(delays)
    result['label'] = f'{label_a} → {label_b}'
    
    # 时钟偏移估算是中位数
    if delays:
        result['clock_offset_ms'] = np.median([d[1] for d in delays])
        # 去偏移后的延迟
        detrended = [d[1] - result['clock_offset_ms'] for d in delays]
        result['detrended_mean'] = float(np.mean(detrended))
        result['detrended_std'] = float(np.std(detrended))
        result['detrended_p95'] = float(np.percentile(detrended, 95))
        result['detrended_p99'] = float(np.percentile(detrended, 99))
    
    return result


def detect_clock_offsets(cross_delays: list) -> dict:
    """检测多个跨抓包延迟中的时钟偏移。
    
    Args:
        cross_delays: [{'ssrc': int, 'label': str, 'clock_offset_ms': float}, ...]
        
    Returns:
        {
            'offsets': {label: offset_ms, ...},
            'max_offset': float,
            'warning': str or None,  # 如果偏移过大则给出警告
        }
    """
    offsets = {}
    for cd in cross_delays:
        if 'clock_offset_ms' in cd:
            offsets[cd['label']] = cd['clock_offset_ms']
    
    warning = None
    if offsets:
        max_off = max(abs(v) for v in offsets.values())
        if max_off > 500:
            warning = (f'Large clock offset detected ({max_off:.0f}ms). '
                       f'Sync NTP on capture machines for more accurate delay measurement.')
    
    return {
        'offsets': offsets,
        'max_offset': max(abs(v) for v in offsets.values()) if offsets else 0,
        'warning': warning,
    }


def estimate_end_to_end_delay(fs_internal_result: dict, 
                               network_delay_a_ms: float = 2,
                               network_delay_b_ms: float = 2) -> dict:
    """估算端到端延迟。
    
    Args:
        fs_internal_result: FS 内部延迟分析结果
        network_delay_a_ms: A→FS 网络延迟估算（默认 2ms LAN）
        network_delay_b_ms: FS→B 网络延迟估算（默认 2ms LAN）
        
    Returns:
        {'total_mean': float, 'total_p95': float, 'total_p99': float, 'breakdown': str}
    """
    if not fs_internal_result or fs_internal_result['count'] == 0:
        return {'total_mean': 0, 'total_p95': 0, 'total_p99': 0, 'breakdown': '数据不足'}
    
    total_mean = fs_internal_result['mean'] + network_delay_a_ms + network_delay_b_ms
    total_p95 = fs_internal_result['p95'] + network_delay_a_ms + network_delay_b_ms
    total_p99 = fs_internal_result['p99'] + network_delay_a_ms + network_delay_b_ms
    
    breakdown = (f'网络A→FS: ~{network_delay_a_ms}ms + '
                 f'FS内部: {fs_internal_result["mean"]:.1f}ms + '
                 f'网络FS→B: ~{network_delay_b_ms}ms = '
                 f'{total_mean:.1f}ms')
    
    return {
        'total_mean': round(total_mean, 1),
        'total_p95': round(total_p95, 1),
        'total_p99': round(total_p99, 1),
        'breakdown': breakdown,
    }


def _summarize_delays(delays: list) -> dict:
    """汇总延迟统计。"""
    if not delays:
        return _empty_delay_result()
    
    vals = [d[1] for d in delays]
    return {
        'delays': [(float(t), float(d)) for t, d in delays],
        'mean': round(float(np.mean(vals)), 2),
        'median': round(float(np.median(vals)), 2),
        'p50': round(float(np.median(vals)), 2),
        'p95': round(float(np.percentile(vals, 95)), 2),
        'p99': round(float(np.percentile(vals, 99)), 2),
        'max': round(float(np.max(vals)), 2),
        'min': round(float(np.min(vals)), 2),
        'std': round(float(np.std(vals)), 2),
        'count': len(delays),
        'outliers_50ms': sum(1 for v in vals if v > 50),
        'outliers_100ms': sum(1 for v in vals if v > 100),
    }


def _empty_delay_result() -> dict:
    return {
        'delays': [],
        'mean': 0, 'median': 0, 'p50': 0, 'p95': 0, 'p99': 0,
        'max': 0, 'min': 0, 'std': 0, 'count': 0,
        'outliers_50ms': 0, 'outliers_100ms': 0,
    }