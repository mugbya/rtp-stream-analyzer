"""
RTP 时间戳连续性检测器
检查 RTP 时间戳的跳变、倒退、重复与 32 位回绕。

RTP 时间戳是发送端的媒体时钟：同一条流里按到达顺序它应单调递增，增量
等于每包携带的媒体时长（如 G.711 20ms 包化 = 增量 160 @ 8kHz）。以它为
基准可以区分：

- ts 跳变（增量远超 seq 缺口能解释的媒体时间）：静音抑制（DTX）期间
  发送端不发包、或发送端时间戳异常——此时 seq 连续、不算丢包；
- ts 倒退：seq 同步倒退是网络乱序（迟到包），seq 前进而 ts 倒退是发送端
  时间戳回退（严重异常）；
- ts 重复（增量 0）：发送端异常或冗余重传；
- ts 回绕：32 位计数器自然溢出，属正常现象，只计数不报事件。

本模块只检测与标注，不修改包数据；实测出的每包时长供音频重建替代
"固定 160 样本"的假设。
"""
from statistics import median
from collections import Counter

from .rtp_parser import get_stream_packets
from .stream_classifier import get_clock_rate, AUDIO_PT

TS_MOD = 1 << 32
# 事件明细最多保留的条数（各类计数不受限，明细截断防止超大报告）
MAX_EVENTS = 50
# seq 差值超过此值视为倒退（乱序）而非前进
SEQ_BACKWARD = 1 << 15


def signed32(x: int) -> int:
    """把 32 位回绕差值转为带符号数：正常推进为小正数，倒退为负数。

    时间戳跨过 2^32 回绕时差值仍是小正数，因此回绕不会误报为跳变。
    """
    x &= TS_MOD - 1
    return x - TS_MOD if x >= (1 << 31) else x


def check_ts_continuity(packets: dict, ssrc: int) -> dict:
    """检测指定 SSRC 流的 RTP 时间戳连续性（按捕获时间序）。

    Returns:
        {
            'is_continuous': bool,      # 无任何异常事件
            'packet_count': int,
            'pt': int,                  # 主 PT（出现次数最多）
            'clock_rate': int or None,  # 主 PT 的时钟率，未知 PT 为 None
            'mode': 'packet'|'frame',   # 逐包核对（音频）/ 帧级核对（视频等）
            'packet_duration_ms': float or None,  # 实测每包媒体时长
            'median_ts_delta': int,     # 实测时间戳增量中位数（ts 单位）
            'wrap_count': int,          # 32 位回绕次数（正常现象）
            'event_count': int,         # 异常事件总数
            'jump_count': int,          # ts 跳变（媒体时间缺口）
            'backward_count': int,      # ts 倒退（seq 顺序时，发送端异常）
            'reorder_count': int,       # seq+ts 同步倒退（网络乱序）
            'duplicate_count': int,     # ts 重复（增量 0）
            'total_media_gap_ms': float,  # 跳变累计缺少的媒体时间
            'media_gaps_ms': [(time, gap_ms), ...],
            'events': [{'time', 'kind', 'seq', 'ts_delta', 'media_gap_ms'}, ...],
        }
    """
    pkts = get_stream_packets(packets, ssrc)
    result = _empty_result()
    if len(pkts) < 2:
        return result

    result['packet_count'] = len(pkts)
    pt = Counter(p[3] for p in pkts).most_common(1)[0][0]
    result['pt'] = pt
    clock_rate = get_clock_rate(pt)
    result['clock_rate'] = clock_rate

    # 检查模式：静态音频 PT 每包自带独立媒体时间，逐包核对；视频/动态 PT
    # 流一帧拆多个包、同帧时间戳相同（RFC 6184），DTMF 事件重传同样共用
    # 时间戳（RFC 4733）——这些流只查倒退/乱序/回绕，重复与逐包跳变不算
    # 异常，否则正常视频流会被刷爆告警
    full_mode = pt in AUDIO_PT
    result['mode'] = 'packet' if full_mode else 'frame'

    # 第一遍：带符号的时间戳增量 → 中位数即实测每包时长（中位数对个别
    # 跳变和倒退稳健；负增量与 0 不参与）
    deltas = [signed32(pkts[i][2] - pkts[i - 1][2]) for i in range(1, len(pkts))]
    positive = [d for d in deltas if d > 0]
    median_delta = int(round(median(positive))) if positive else 0
    result['median_ts_delta'] = median_delta
    if full_mode and clock_rate and median_delta > 0:
        result['packet_duration_ms'] = round(median_delta / clock_rate * 1000, 2)

    jump_threshold = max(median_delta // 2, 1)
    events = result['events']
    # 近期异常步累积的未弥补媒体时间（≤0）：重复/倒退的缺口由后续增量
    # 抵偿，避免"ts 持平一步、下一步 +320 追平"这类自愈行为被误报成跳变
    pending = 0

    for i in range(1, len(pkts)):
        t = float(pkts[i][0])
        seq, ts = pkts[i][1], pkts[i][2]
        prev_seq, prev_ts = pkts[i - 1][1], pkts[i - 1][2]
        d = deltas[i - 1]
        seq_gap = (seq - prev_seq) & 0xFFFF

        # 32 位回绕：原始值变小但带符号差值为正，属正常溢出
        if ts < prev_ts and d > 0:
            result['wrap_count'] += 1

        event = None
        if d < 0:
            if seq_gap >= SEQ_BACKWARD:
                result['reorder_count'] += 1
                event = ('reorder', d, None)
            else:
                result['backward_count'] += 1
                event = ('ts_backward', d, None)
            pending += d - seq_gap * median_delta
        elif d == 0:
            if full_mode:
                result['duplicate_count'] += 1
                event = ('duplicate', 0, None)
                pending -= median_delta
        elif full_mode and median_delta > 0 and seq_gap < SEQ_BACKWARD:
            # 净推进 = 实际增量 - seq 间隔×每包时长 + 未弥补缺口；超出
            # 阈值的部分是 seq 无法解释的媒体时间缺口（静音抑制/发送端
            # 时间戳异常）
            net = d - seq_gap * median_delta + pending
            if net > jump_threshold:
                result['jump_count'] += 1
                gap_ms = round(net / clock_rate * 1000, 1) if clock_rate else None
                if gap_ms is not None:
                    result['media_gaps_ms'].append((t, gap_ms))
                    result['total_media_gap_ms'] += gap_ms
                event = ('ts_jump', d, gap_ms)
                pending = 0
            else:
                pending = min(net, 0)

        if event:
            result['event_count'] += 1
            if len(events) < MAX_EVENTS:
                events.append({
                    'time': t,
                    'kind': event[0],
                    'seq': seq,
                    'ts_delta': event[1],
                    'media_gap_ms': event[2],
                })

    result['total_media_gap_ms'] = round(result['total_media_gap_ms'], 1)
    result['is_continuous'] = result['event_count'] == 0
    return result


def _empty_result() -> dict:
    return {
        'is_continuous': True,
        'packet_count': 0,
        'pt': None,
        'clock_rate': None,
        'mode': None,
        'packet_duration_ms': None,
        'median_ts_delta': 0,
        'wrap_count': 0,
        'event_count': 0,
        'jump_count': 0,
        'backward_count': 0,
        'reorder_count': 0,
        'duplicate_count': 0,
        'total_media_gap_ms': 0.0,
        'media_gaps_ms': [],
        'events': [],
    }
