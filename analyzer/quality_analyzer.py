"""
音画质量异常分析：杂音 / 啸叫 / 削波破音 / 底噪（音频）、花屏（视频）

"有杂音、啸叫、花屏"类投诉在 RTP 抓包层面的可观测证据，逐一对应检测：

音频（仅 G.711 PCMU/PCMA 可解，解码流程与媒体重建一致）：
1. 啸叫/持续单频音——回授啸叫、单音提示音泄漏。特征是频谱上出现一根
   "又高又窄又稳定"的谱峰：帧级 FFT 找显著峰值（峰值远高于谱中位数），
   连续多帧且频率不漂移（±容差）即判定。≥250Hz 报啸叫/持续单频音。
2. 低频嗡声（50/100Hz 电源干扰、地环路）——能量集中在低频段的持续帧。
   用"低频能量占比 ≥85% 且持续"判定，不依赖精确的 bin 对齐。
3. 削波破音——波形顶端被削平：连续多个采样值一字排开且幅度极大。
   自然语音峰值两侧斜率不为零，几乎不会出现连续相等的大幅值采样。
4. 爆点/咔哒声——孤立的脉冲尖峰：本身幅度极大而前后邻域都很小。
5. 底噪——静音帧（无话音）的电平中位数：偏高说明拾音环境/设备底噪明显。
6. 音量——话音帧平均电平过低/过高。
7. RTP 序号/时间戳秩序——序号应每包 +1（缺口即丢包），时间戳按序号
   排列应单调递增（倒退 = 发送端时钟异常）。二者是"重建出来的音视频
   可不可信"的前提：时间戳倒退会让按 seq 拼接的 PCM 错位，杂音类检测
   可能产生假事件；序号缺口意味着拼接里含补零静音，底噪/电平统计要
   结合补零量解读。

视频（RTP 层证据，H.264）：
1. 丢包 → 花屏：视频丢包不像音频那样只缺一瞬间，受损宏块会一直花到
   下一个关键帧（IDR）刷新。把丢包事件映射到"距下一 IDR 的时长"，
   估算花屏累计影响时间。
2. 破损 NAL：FU-A 分片序列中间丢包/未收尾，拼出的帧数据必然损坏——
   这是"解码层一定出错"的直接证据。
3. 关键帧间隔：IDR 间隔越长，每次丢包后的花屏持续越久；全程无 IDR
   说明一旦丢包无法自愈。
4. ffmpeg 解码校验（可选）：对重建出的裸流跑一遍错误级解码，统计
   解码错误行数，作为花屏风险的最终佐证；ffmpeg 不在则跳过。

事件时间均为"相对流第一个包捕获时刻"的秒数，与回放页对时使用。
"""
import bisect
import math
import os
import struct
import subprocess

import audioop
import numpy as np

from analyzer.stream_classifier import get_pt_name
from analyzer.ts_continuity import signed32
from analyzer.packet_loss import detect_packet_loss

# ---------- 音频参数 ----------
_DECODE = {0: 'ulaw', 8: 'alaw'}
SAMPLE_RATE = 8000
ACTIVE_RMS = 500          # 与 silence_analyzer 一致的"有人声"门限

FRAME = 256               # 帧长 32ms @8kHz
HOP = 128                 # 帧移 16ms
TONE_BAND = (250.0, 3900.0)   # 啸叫检测频带（8k 采样奈奎斯特 4kHz）
TONE_PROMINENCE = 40.0    # 谱峰 / 谱中位数 ≥40 倍才够"窄而尖"
TONE_MIN_RMS = 300        # 帧能量下限（排除底噪里的伪峰）
TONE_MIN_FRAMES = 16      # 持续 ≥16 帧（约 0.26s）判为持续单频音，
                          # 短于常见按键音（DTMFA 约 120ms）避免误报
TONE_FREQ_TOL_HZ = 50.0   # 同一事件内允许的频率漂移
HUM_LOW_HZ = 220.0        # 低频嗡声的"低频段"上界
HUM_RATIO = 0.85          # 低频能量占比门限
HUM_MIN_RMS = 800         # 嗡声要有可闻电平
HUM_MIN_FRAMES = 50       # 持续 ≥0.8s
CLIP_MIN_LEVEL = 20000    # 削波采样幅度下限
CLIP_MIN_RUN = 4          # 连续 ≥4 个相等大幅值采样才算削平
CLIP_MIN_RUNS = 2         # 至少出现 2 次平台才报
SPIKE_LEVEL = 24000       # 爆点尖峰幅度
SPIKE_NEIGHBOR = 4000     # 尖峰前后邻域必须都低于此值
NOISE_FLOOR_DBFS = -45.0  # 底噪门限
SPEECH_LOW_DBFS = -27.0   # 话音平均电平过低门限
SPEECH_HIGH_DBFS = -9.0   # 话音平均电平过高门限
MAX_EVENTS = 40           # 每类事件明细最多保留条数


def analyze_audio_quality(packets: dict, ssrc: int) -> dict:
    """对指定 SSRC 音频流做杂音/啸叫类 DSP 检测（需带载荷的抓包数据）。

    按 seq（播放）顺序拼接 PCM；DTX/静音抑制的时间戳缺口补零占位，
    非主 PT 包（如 CN）按一包静音处理，保持与真实播放时间对齐。

    Returns:
        {'packet_count', 'codec', 'decodable', 'duration_s',
         'rtp_integrity': 序号/时间戳秩序判定（见 _rtp_integrity），
         'clipping': {'run_count', 'sample_count', 'events': [...]},
         'clicks': {'count', 'events': [...]},
         'tones': {'count', 'howl_count', 'hum_count', 'events': [...]},
         'noise_floor_dbfs', 'speech_level_dbfs',
         'issues': [{'kind', 'severity', 'message'}],
         'verdict': 'clean'|'noisy'|'bad'|'unknown'}
    """
    result = {
        'packet_count': 0, 'codec': 'unknown', 'decodable': False,
        'duration_s': 0.0,
        'clipping': {'run_count': 0, 'sample_count': 0, 'events': []},
        'clicks': {'count': 0, 'events': []},
        'tones': {'count': 0, 'howl_count': 0, 'hum_count': 0, 'events': []},
        'noise_floor_dbfs': None, 'speech_level_dbfs': None,
        'rtp_integrity': None,
        'issues': [], 'verdict': 'clean',
    }

    stream = {}
    for (k_ssrc, seq), v in packets.items():
        if k_ssrc == ssrc and len(v) >= 8:
            stream[seq] = v
    if not stream:
        return result

    pts = [v[2] for v in stream.values()]
    pt = max(set(pts), key=pts.count)
    result['packet_count'] = len(stream)
    result['codec'] = get_pt_name(pt)
    result['decodable'] = pt in _DECODE
    if not result['decodable']:
        result['verdict'] = 'unknown'
        return result
    decode = audioop.ulaw2lin if _DECODE[pt] == 'ulaw' else audioop.alaw2lin

    seqs = sorted(stream)
    ts_list = [stream[s][1] for s in seqs]
    deltas = [signed32(b - a) for a, b in zip(ts_list, ts_list[1:])]
    positive = sorted(d for d in deltas if d > 0)
    spp = positive[len(positive) // 2] if positive else 0
    if not (0 < spp <= SAMPLE_RATE // 2):
        spp = 160
    result['rtp_integrity'] = _rtp_integrity(
        [(s, stream[s][1], stream[s][2]) for s in seqs], spp, pt, 'packet')

    # 拼接 PCM（含 DTX 补零），媒体时间 = 采样位置 / 采样率
    chunks = []
    zero_filled = 0
    prev_ts = None
    for seq in seqs:
        ts = stream[seq][1]
        if prev_ts is not None:
            gap = signed32(ts - prev_ts) - spp
            if 0 < gap <= 10 * SAMPLE_RATE:      # DTX/静音抑制缺口补零
                chunks.append(np.zeros(gap, dtype=np.float64))
                zero_filled += gap
        payload = stream[seq][7]
        if stream[seq][2] == pt:
            try:
                lin = decode(payload, 2)
            except Exception:
                lin = b'\x00' * (len(payload) * 2)
            chunks.append(np.frombuffer(lin, dtype=np.int16).astype(np.float64))
        else:
            chunks.append(np.zeros(spp, dtype=np.float64))
        prev_ts = ts

    x = np.concatenate(chunks) if chunks else np.zeros(0, dtype=np.float64)
    result['duration_s'] = round(x.size / SAMPLE_RATE, 2)
    result['rtp_integrity']['zero_filled_ms'] = round(
        zero_filled / SAMPLE_RATE * 1000, 1)
    if x.size < FRAME:
        return result

    # —— 帧级分析：RMS / 频谱 ——
    n_frames = (x.size - FRAME) // HOP + 1
    idx = np.arange(FRAME) + HOP * np.arange(n_frames)[:, None]
    frames = x[idx]
    win = np.hanning(FRAME)
    spec = np.abs(np.fft.rfft(frames * win, axis=1))
    freqs = np.fft.rfftfreq(FRAME, 1 / SAMPLE_RATE)
    frame_rms = np.sqrt(np.mean(frames ** 2, axis=1))
    frame_t = (idx[:, 0] + FRAME / 2) / SAMPLE_RATE   # 帧中心媒体时间

    # 1) 啸叫 / 持续单频音：谱峰显著（峰值/谱中位数）、持续、频率稳定，
    #    且无谐波伙伴（2f/3f/f÷2 处也有显著峰 → 是语音谐波结构，不是纯单频）
    band = (freqs >= TONE_BAND[0]) & (freqs <= TONE_BAND[1])
    band_idx = np.where(band)[0]
    band_spec = spec[:, band_idx]
    peak_pos = np.argmax(band_spec, axis=1)
    peak_val = band_spec[np.arange(n_frames), peak_pos]
    peak_freq = freqs[band_idx[peak_pos]]
    med = np.maximum(np.median(spec[:, 1:], axis=1), 1e-6)
    df = freqs[1]                      # bin 宽 31.25Hz
    harm = np.zeros(n_frames, dtype=bool)
    for mult in (2.0, 3.0, 0.5):
        tgt = np.round(peak_freq * mult / df).astype(int)
        idxs = np.where((tgt >= 1) & (tgt < spec.shape[1]))[0]
        if not idxs.size:
            continue
        b = tgt[idxs]
        mag = spec[idxs, b]
        mag = np.maximum(mag, spec[idxs, np.clip(b - 1, 0, None)])
        mag = np.maximum(mag, spec[idxs, np.clip(b + 1, 0, spec.shape[1] - 1)])
        over = np.zeros(n_frames, dtype=bool)
        over[idxs] = mag > 0.25 * peak_val[idxs]
        harm |= over
    is_tone = ((peak_val / med >= TONE_PROMINENCE)
               & (frame_rms >= TONE_MIN_RMS) & ~harm)
    result['tones'] = _track_tones(is_tone, peak_freq, frame_rms, frame_t)

    # 2) 低频嗡声：低频能量占比高的持续帧（与啸叫独立判定）
    low_mask = freqs <= HUM_LOW_HZ
    low_mask[0] = False                       # 排除直流
    low_energy = np.sum(spec[:, low_mask] ** 2, axis=1)
    total_energy = np.sum(spec[:, 1:] ** 2, axis=1)
    low_ratio = low_energy / np.maximum(total_energy, 1e-9)
    is_hum = (low_ratio >= HUM_RATIO) & (frame_rms >= HUM_MIN_RMS)
    hum = _track_runs(is_hum, frame_t, HUM_MIN_FRAMES)
    tones = result['tones']
    tones['hum_count'] = len(hum)
    tones['count'] += len(hum)
    for start, end in hum[:MAX_EVENTS]:
        sel = (frame_t >= start) & (frame_t <= end)
        tones['events'].append({
            'start_s': round(float(start), 2), 'end_s': round(float(end), 2),
            'freq_hz': None, 'band': 'hum',
            'mean_dbfs': _dbfs(np.mean(frame_rms[sel]))})

    # 3) 削波：连续相等的大幅值采样（波形被削平的平台）
    clip_events = []
    for start, length in _bool_runs(np.diff(x) == 0):
        if length + 1 < CLIP_MIN_RUN:
            continue
        level = abs(x[start])
        if level < CLIP_MIN_LEVEL:
            continue
        clip_events.append((start, length + 1, level))
    result['clipping']['run_count'] = len(clip_events)
    result['clipping']['sample_count'] = int(sum(c[1] for c in clip_events))
    for start, length, level in clip_events[:MAX_EVENTS]:
        result['clipping']['events'].append({
            'time_s': round(start / SAMPLE_RATE, 2),
            'ms': round(length / SAMPLE_RATE * 1000, 2),
            'level_dbfs': _dbfs(level)})

    # 4) 爆点：孤立脉冲短突发（幅度极大、突发外围 ±4 采样都很小）
    big = np.abs(x) >= SPIKE_LEVEL
    small = np.abs(x) < SPIKE_NEIGHBOR
    bursts = []
    for s, length in _bool_runs(big):
        if bursts and s - bursts[-1][1] <= 4:   # 相邻尖峰合并为同一爆点
            bursts[-1][1] = s + length
        else:
            bursts.append([s, s + length])
    merged = []
    for s, e in bursts:
        if e - s > 6:               # 长突发不是"孤立爆点"（更像持续异常）
            continue
        if not small[max(s - 4, 0):s].all():
            continue
        if not small[e:min(e + 4, x.size)].all():
            continue
        merged.append((s, e))
    result['clicks']['count'] = len(merged)
    for s, e in merged[:MAX_EVENTS]:
        amp = max(np.abs(x[s:e]).max(), 1)
        result['clicks']['events'].append({
            'time_s': round(s / SAMPLE_RATE, 2),
            'amplitude_dbfs': _dbfs(amp)})

    # 5) 底噪与话音电平
    quiet = frame_rms[frame_rms < ACTIVE_RMS]
    if quiet.size >= 10:
        result['noise_floor_dbfs'] = _dbfs(np.median(quiet))
    speech = frame_rms[frame_rms >= ACTIVE_RMS]
    if speech.size:
        result['speech_level_dbfs'] = _dbfs(np.mean(speech))

    result['issues'] = _audio_issues(result)
    worst = {i['severity'] for i in result['issues']}
    result['verdict'] = ('bad' if 'critical' in worst
                         else 'noisy' if 'warning' in worst else 'clean')
    return result


def _bool_runs(mask: np.ndarray):
    """布尔数组的连续 True 段 [(start, length)]。"""
    if not mask.any():
        return []
    d = np.diff(mask.astype(np.int8))
    starts = list(np.where(d == 1)[0] + 1)
    ends = list(np.where(d == -1)[0] + 1)
    if mask[0]:
        starts.insert(0, 0)
    if mask[-1]:
        ends.append(len(mask))
    return [(int(s), int(e - s)) for s, e in zip(starts, ends)]


def _track_tones(is_tone, peak_freq, frame_rms, frame_t) -> dict:
    """把"单频帧"串成持续事件：先填 1 帧空洞，再按频率漂移分段。"""
    filled = is_tone.copy()
    filled[1:-1] |= np.roll(is_tone, 1)[1:-1] & np.roll(is_tone, -1)[1:-1]
    events = []
    for start, length in _bool_runs(filled):
        if length < TONE_MIN_FRAMES:
            continue
        seg = [start]
        for i in range(start + 1, start + length):
            if abs(peak_freq[i] - peak_freq[seg[0]]) > TONE_FREQ_TOL_HZ:
                if len(seg) >= TONE_MIN_FRAMES:
                    events.append(seg)
                seg = [i]
            else:
                seg.append(i)
        if len(seg) >= TONE_MIN_FRAMES:
            events.append(seg)

    out = []
    for frames_idx in events:
        f_mean = float(np.median(peak_freq[frames_idx]))
        level = _dbfs(np.mean(frame_rms[frames_idx]))
        out.append({
            'start_s': round(float(frame_t[frames_idx[0]]), 2),
            'end_s': round(float(frame_t[frames_idx[-1]]), 2),
            'freq_hz': round(f_mean, 1),
            'band': 'howl' if f_mean >= TONE_BAND[0] else 'hum',
            'mean_dbfs': level})
    return {'count': len(out),
            'howl_count': sum(1 for e in out if e['band'] == 'howl'),
            'hum_count': 0, 'events': out[:MAX_EVENTS]}


def _track_runs(is_flag, frame_t, min_frames):
    """把布尔帧串成持续事件（[(start_t, end_t)]），1 帧空洞自动桥接。"""
    filled = is_flag.copy()
    filled[1:-1] |= np.roll(is_flag, 1)[1:-1] & np.roll(is_flag, -1)[1:-1]
    events = []
    for start, length in _bool_runs(filled):
        if length >= min_frames:
            events.append((float(frame_t[start]),
                           float(frame_t[start + length - 1])))
    merged = []
    for s, e in events:
        if merged and s - merged[-1][1] <= HOP / SAMPLE_RATE * 4:
            merged[-1][1] = e
        else:
            merged.append([s, e])
    return merged


def _dbfs(rms: float) -> float:
    return round(20 * math.log10(max(rms, 1) / 32768), 1)


def _rtp_integrity(items, spp: int, main_pt: int, mode: str = 'packet') -> dict:
    """按序号顺序核对 RTP 序号与时间戳秩序（发送端视角）。

    Args:
        items: 按 seq 排序的 [(seq, ts, pt)]，覆盖该 SSRC 的全部包。
        spp: 每包样本数（实测中位数），用于展示每包媒体时长。
        main_pt: 主载荷类型。时间戳秩序只核对主 PT 包。
        mode: 'packet'（音频，逐包独立媒体时间）| 'frame'（视频等同帧
            多包共用时间戳，重复不算异常，只查倒退）。

    序号应每包 +1（模 65536），缺口即网络丢包——音频拼接按时间戳差额
    补零，视频直接对应花屏。时间戳是发送端媒体时钟：按序号排列应单调
    递增（音频逐包 +每包时长），倒退说明发送端时钟异常——此时按 seq
    拼接的 PCM/帧序与真实播放序错位，本流的质量检测结论可信度下降。
    32 位回绕属正常计数，只统计不报异常。

    非 main PT 包（典型为 RFC 4733 DTMF telephone-event：ts 是"事件起始"
    时刻、重传包重复同一 ts，与音频时钟语义不同）不参与时间戳秩序判定，
    只计数记录——否则正常按键会被误判成"时间戳倒退/重复"。

    Returns:
        {'seq_continuous', 'seq_gaps', 'lost_packets', 'loss_rate_pct',
         'monotonic', 'ts_backward', 'ts_duplicate', 'ts_wrap',
         'median_ts_delta', 'packet_duration_ms', 'zero_filled_ms',
         'other_pt_packets'}
    """
    seq_gaps = lost = 0
    for (a, _, _), (b, _, _) in zip(items, items[1:]):
        d_seq = (b - a) & 0xFFFF
        if d_seq > 1:
            seq_gaps += 1
            lost += d_seq - 1
    ts_backward = ts_duplicate = ts_wrap = other_pt = 0
    prev_ts = None
    for _, ts, pkt_pt in items:
        if pkt_pt != main_pt:
            other_pt += 1
            continue
        if prev_ts is not None:
            d_ts = signed32(ts - prev_ts)
            if d_ts < 0:
                ts_backward += 1
            elif d_ts == 0:
                if mode == 'packet':
                    ts_duplicate += 1
            elif ts < prev_ts:
                ts_wrap += 1
        prev_ts = ts
    return {
        'seq_continuous': lost == 0,
        'seq_gaps': seq_gaps,
        'lost_packets': lost,
        'loss_rate_pct': round(lost / (len(items) + lost) * 100, 2) if lost else 0.0,
        'monotonic': ts_backward == 0,
        'ts_backward': ts_backward,
        'ts_duplicate': ts_duplicate,
        'ts_wrap': ts_wrap,
        'median_ts_delta': spp,
        'packet_duration_ms': round(spp / SAMPLE_RATE * 1000, 2) if spp else None,
        'zero_filled_ms': 0.0,
        'other_pt_packets': other_pt,
    }


def _audio_issues(r: dict) -> list:
    """把检测结果翻译成面向用户的结论（不含流名，由报告层加前缀）。"""
    issues = []
    integ = r.get('rtp_integrity') or {}
    if integ.get('ts_backward'):
        issues.append({
            'kind': 'rtp_order', 'severity': 'critical',
            'message': (f"RTP 时间戳倒退 {integ['ts_backward']} 处（按序号"
                        f"排列后媒体时钟往回走）——发送端时钟异常，按序号"
                        f"拼接的音频会错位，可能产生卡顿杂音，本流杂音类"
                        f"检测结论的可信度也下降")})
    if integ.get('ts_duplicate'):
        issues.append({
            'kind': 'rtp_order', 'severity': 'warning',
            'message': (f"RTP 时间戳重复 {integ['ts_duplicate']} 处（序号"
                        f"前进但媒体时间原地踏步）——发送端时钟停走或冗余"
                        f"重传，听感为重复音/卡顿")})
    if integ.get('lost_packets'):
        issues.append({
            'kind': 'rtp_loss',
            'severity': 'critical' if integ['loss_rate_pct'] >= 3 else 'warning',
            'message': (f"RTP 序号不连续：缺口 {integ['seq_gaps']} 处、丢 "
                        f"{integ['lost_packets']} 包"
                        f"（{integ['loss_rate_pct']:.2f}%）——缺失音频已按"
                        f"静音补零 {integ.get('zero_filled_ms') or 0} ms，"
                        f"丢包处听感为断音/吞字，底噪与电平统计含补零段")})
    elif integ and integ.get('monotonic') and not integ.get('ts_duplicate'):
        extra = (f"（静音抑制补零 {integ['zero_filled_ms']} ms）"
                 if integ.get('zero_filled_ms') else '')
        other = (f"（另有 {integ['other_pt_packets']} 个其他载荷类型包"
                 f"（如 DTMF 电话事件），不参与秩序判定）"
                 if integ.get('other_pt_packets') else '')
        issues.append({
            'kind': 'rtp_ok', 'severity': 'info',
            'message': (f"RTP 序号连续正向（每包 +1）、时间戳单调递增（每包 "
                        f"+{integ.get('median_ts_delta', 0)} ≈ "
                        f"{integ.get('packet_duration_ms')} ms）{extra}{other}"
                        f"——重建音频与杂音/啸叫检测的基础数据可信")})
    tones = r['tones']
    if tones['howl_count']:
        ev = [e for e in tones['events'] if e['band'] == 'howl']
        longest = max(e['end_s'] - e['start_s'] for e in ev)
        freqs = '、'.join(f"{e['freq_hz']:.0f}Hz" for e in ev[:3])
        issues.append({
            'kind': 'howling', 'severity': 'critical',
            'message': (f"检测到啸叫/持续单频音 {tones['howl_count']} 处"
                        f"（{freqs}，最长 {longest:.1f} 秒，电平约 "
                        f"{ev[0]['mean_dbfs']} dBFS）——通话中的尖啸/嘀声，"
                        f"通常为扬声器回授啸叫或单音提示音串入通话")})
    if tones['hum_count']:
        issues.append({
            'kind': 'hum', 'severity': 'warning',
            'message': (f"检测到低频嗡声 {tones['hum_count']} 处（能量集中在"
                        f"低频段持续存在，典型为 50/100Hz 电源干扰、接地环路"
                        f"或设备风扇声串入采集）")})
    clip = r['clipping']
    if clip['run_count'] >= CLIP_MIN_RUNS:
        issues.append({
            'kind': 'clipping',
            'severity': 'critical' if clip['sample_count'] > 200 else 'warning',
            'message': (f"检测到波形削波 {clip['run_count']} 处（共 "
                        f"{clip['sample_count']} 个采样被削平）——发话端音量"
                        f"过大导致破音，听感为沙哑、噼啪的杂音")})
    clicks = r['clicks']
    if clicks['count'] >= 3:
        issues.append({
            'kind': 'clicks', 'severity': 'warning',
            'message': (f"检测到 {clicks['count']} 个爆点/咔哒声（孤立脉冲"
                        f"尖峰）——多为突发电气干扰、设备切换或线路接触不良")})
    nf = r['noise_floor_dbfs']
    if nf is not None and nf > NOISE_FLOOR_DBFS:
        issues.append({
            'kind': 'noise', 'severity': 'warning' if nf > -40 else 'info',
            'message': (f"静音段底噪约 {nf} dBFS，偏高——对方环境噪声或拾音"
                        f"设备底噪会一直传过来，听感为持续的沙沙/电流声")})
    sl = r['speech_level_dbfs']
    if sl is not None and sl < SPEECH_LOW_DBFS:
        issues.append({
            'kind': 'low_level', 'severity': 'info',
            'message': (f"话音平均电平仅 {sl} dBFS，偏低——对方会感觉声音小、"
                        f"发虚（不是杂音，但常与听不清的投诉相关）")})
    elif sl is not None and sl > SPEECH_HIGH_DBFS:
        issues.append({
            'kind': 'high_level', 'severity': 'info',
            'message': (f"话音平均电平 {sl} dBFS，接近满幅——再大就会削波"
                        f"破音，建议调低发送增益")})
    return issues


# ---------- 视频花屏风险 ----------

# RFC 6184 NAL 类型
NAL_IDR, NAL_SPS, NAL_PPS = 5, 7, 8
NAL_STAP_A, NAL_FU_A = 24, 28


def analyze_video_quality(packets: dict, ssrc: int, raw_path: str = None) -> dict:
    """对指定 SSRC 视频流做花屏风险分析（RTP 层 + 可选 ffmpeg 解码校验）。

    Args:
        packets: 带载荷的抓包数据。
        ssrc: 视频 SSRC。
        raw_path: 重建出的 .h264 裸流路径；存在时用 ffmpeg 做错误级解码
            校验，统计解码错误行数（ffmpeg 不可用则跳过）。

    Returns:
        {'packet_count', 'total_lost', 'loss_rate_pct', 'max_consecutive_loss',
         'loss_events': [{'time_s', 'count'}],
         'nal_units', 'idr_count', 'sps_count', 'pps_count',
         'broken_nals', 'idr_interval_max_s', 'first_idr_s',
         'est_artifacts_ms', 'decode_check': 'ok'|'errors'|'skipped'|'unavailable',
         'decode_errors', 'issues', 'verdict': 'ok'|'risk'|'bad'|'unknown'}
    """
    result = {
        'packet_count': 0, 'total_lost': 0, 'loss_rate_pct': 0.0,
        'max_consecutive_loss': 0, 'loss_events': [],
        'nal_units': 0, 'idr_count': 0, 'sps_count': 0, 'pps_count': 0,
        'broken_nals': 0, 'idr_interval_max_s': None, 'first_idr_s': None,
        'est_artifacts_ms': 0.0, 'decode_check': 'skipped', 'decode_errors': None,
        'rtp_integrity': None,
        'issues': [], 'verdict': 'ok',
    }

    stream = {}
    for (k_ssrc, seq), v in packets.items():
        if k_ssrc == ssrc and len(v) >= 8:
            stream[seq] = v
    if not stream:
        result['verdict'] = 'unknown'
        return result
    result['packet_count'] = len(stream)

    loss = detect_packet_loss(packets, ssrc)
    result['total_lost'] = loss['total_lost']
    result['loss_rate_pct'] = loss['loss_rate_pct']
    result['max_consecutive_loss'] = loss['max_consecutive_loss']

    sorted_seqs = sorted(stream)
    v_pts = [stream[s][2] for s in sorted_seqs]
    result['rtp_integrity'] = _rtp_integrity(
        [(s, stream[s][1], stream[s][2]) for s in sorted_seqs], 0,
        max(set(v_pts), key=v_pts.count), mode='frame')
    t0 = stream[sorted_seqs[0]][0]
    t_end = stream[sorted_seqs[-1]][0]
    result['duration_s'] = round(t_end - t0, 2)
    for time, count in (loss['loss_events'] or [])[:MAX_EVENTS]:
        result['loss_events'].append({'time_s': round(time - t0, 2),
                                      'count': count})

    # —— NAL 重组（与 media_extractor 同款 FU-A/STAP-A 逻辑），带完整性追踪 ——
    nal_count = 0
    idr_times = []
    broken = 0
    fua_buffer = None
    fua_corrupt = False
    prev_seq = None

    def _finish_fua():
        """收尾当前 FU-A NAL：统计并按是否破损计数。"""
        nonlocal fua_buffer, fua_corrupt, broken, nal_count
        if fua_buffer is None:
            return
        nal_count += 1
        if fua_corrupt:
            broken += 1
        fua_buffer = None
        fua_corrupt = False

    for seq in sorted_seqs:
        payload = stream[seq][7]
        if not payload or len(payload) < 2:
            continue
        t = stream[seq][0] - t0

        # seq 缺口落在 FU-A 分片中途 → 该 NAL 必然破损
        if prev_seq is not None and fua_buffer is not None:
            d = (seq - prev_seq) & 0xFFFF
            if 1 < d < 0x8000:
                fua_corrupt = True
        prev_seq = seq

        nal_type = payload[0] & 0x1F
        if nal_type == NAL_FU_A:
            fu_header = payload[1]
            start_bit = fu_header & 0x80
            end_bit = fu_header & 0x40
            if start_bit:
                if fua_buffer is not None:
                    fua_corrupt = True      # 上一 NAL 没等到结束分片
                _finish_fua()
                fua_buffer = bytearray(
                    [(payload[0] & 0xE0) | (fu_header & 0x1F)])
                fua_buffer.extend(payload[2:])
                if (fu_header & 0x1F) == NAL_IDR:
                    idr_times.append(t)
            elif fua_buffer is not None:
                fua_buffer.extend(payload[2:])
            elif end_bit:
                broken += 1                 # 收到结尾分片但开头已丢（无法重组）
            if end_bit and fua_buffer is not None:
                _finish_fua()
        elif nal_type == NAL_STAP_A:
            offset = 1
            while offset + 2 <= len(payload):
                nalu_size = struct.unpack('>H', payload[offset:offset + 2])[0]
                offset += 2
                if offset + nalu_size > len(payload):
                    broken += 1             # STAP-A 内部 NAL 不完整
                    break
                inner_type = payload[offset] & 0x1F
                nal_count += 1
                if inner_type == NAL_IDR:
                    idr_times.append(t)
                elif inner_type == NAL_SPS:
                    result['sps_count'] += 1
                elif inner_type == NAL_PPS:
                    result['pps_count'] += 1
                offset += nalu_size
        elif nal_type < 24:
            nal_count += 1
            if nal_type == NAL_IDR:
                idr_times.append(t)
            elif nal_type == NAL_SPS:
                result['sps_count'] += 1
            elif nal_type == NAL_PPS:
                result['pps_count'] += 1
    _finish_fua()

    result['nal_units'] = nal_count
    result['idr_count'] = len(idr_times)
    result['broken_nals'] = broken
    if idr_times:
        result['first_idr_s'] = round(idr_times[0], 2)
        result['idr_interval_max_s'] = round(
            max((b - a for a, b in zip(idr_times, idr_times[1:])), default=0), 2)

    # —— 丢包 → 花屏影响估算：每次丢包花到下一个 IDR 刷新为止 ——
    artifact = 0.0
    for ev in result['loss_events']:
        k = bisect.bisect_right(idr_times, ev['time_s'])
        until = idr_times[k] if k < len(idr_times) else t_end
        artifact += max(until - ev['time_s'], 0)
    if result['total_lost'] and not idr_times:
        artifact = t_end - t0       # 全程无关键帧：丢包影响无法自愈
    result['est_artifacts_ms'] = round(artifact * 1000, 1)

    # —— ffmpeg 解码校验（重建裸流存在时） ——
    if raw_path and os.path.isfile(raw_path):
        try:
            proc = subprocess.run(
                ['ffmpeg', '-v', 'error', '-i', raw_path, '-f', 'null', '-'],
                capture_output=True, text=True, timeout=120)
            lines = [l for l in (proc.stderr or '').splitlines() if l.strip()]
            result['decode_errors'] = len(lines)
            result['decode_check'] = 'errors' if lines else 'ok'
        except FileNotFoundError:
            result['decode_check'] = 'unavailable'
        except subprocess.TimeoutExpired:
            result['decode_check'] = 'skipped'

    result['issues'] = _video_issues(result)
    worst = {i['severity'] for i in result['issues']}
    result['verdict'] = ('bad' if 'critical' in worst
                         else 'risk' if 'warning' in worst else 'ok')
    return result


def _video_issues(r: dict) -> list:
    issues = []
    integ = r.get('rtp_integrity') or {}
    if integ.get('ts_backward'):
        issues.append({
            'kind': 'rtp_order', 'severity': 'critical',
            'message': (f"RTP 时间戳倒退 {integ['ts_backward']} 处——发送端"
                        f"时钟异常，按序号重组的视频帧与真实播放序错位，"
                        f"花屏/卡顿风险高")})
    if r['broken_nals']:
        issues.append({
            'kind': 'broken_nal', 'severity': 'critical',
            'message': (f"{r['broken_nals']} 个视频帧数据因丢包/分片不完整而"
                        f"破损——解码必然出错，对应画面会出现花屏、马赛克"
                        f"或绿屏")})
    if r['decode_check'] == 'errors' and r['decode_errors']:
        issues.append({
            'kind': 'decode_errors', 'severity': 'critical',
            'message': (f"ffmpeg 对重建裸流试解码报 {r['decode_errors']} 处"
                        f"错误——码流确实损坏，与花屏现象直接对应")})
    lost = r['total_lost']
    if lost and r['loss_rate_pct'] >= 1.0:
        issues.append({
            'kind': 'video_loss', 'severity': 'critical',
            'message': (f"视频流丢包 {lost} 包（{r['loss_rate_pct']:.2f}%），"
                        f"丢包处画面会花屏直到关键帧刷新，估算累计花屏影响 "
                        f"{r['est_artifacts_ms'] / 1000:.1f} 秒")})
    elif lost:
        issues.append({
            'kind': 'video_loss', 'severity': 'warning',
            'message': (f"视频流丢包 {lost} 包（{r['loss_rate_pct']:.2f}%）——"
                        f"少量视频丢包就会在丢包时刻出现短暂马赛克/花屏"
                        f"（估算累计影响 {r['est_artifacts_ms'] / 1000:.1f} "
                        f"秒），音频丢同样数量则几乎无感")})
    if r['idr_count'] == 0 and r['nal_units'] and r.get('duration_s', 0) >= 10:
        issues.append({
            'kind': 'no_idr', 'severity': 'warning',
            'message': ("整个抓包未见到关键帧（IDR）——一旦丢包画面无法自行"
                        "恢复，花屏会持续到挂断；请检查终端关键帧间隔配置")})
    elif r['idr_interval_max_s'] and r['idr_interval_max_s'] > 10:
        issues.append({
            'kind': 'idr_gap', 'severity': 'info',
            'message': (f"关键帧间隔最长 {r['idr_interval_max_s']:.0f} 秒——"
                        f"间隔越长，每次丢包后的花屏持续越久，建议终端把关键"
                        f"帧间隔控制在 2~4 秒")})
    return issues
