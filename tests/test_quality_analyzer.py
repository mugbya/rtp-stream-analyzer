"""
Unit tests for media quality analysis: audio anomalies (howling / clipping /
clicks / hum / noise floor) and video corruption risk (loss -> artifacts,
broken NALs, IDR interval), plus report wiring.

Run: python3 tests/test_quality_analyzer.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import audioop
import numpy as np

from analyzer.quality_analyzer import analyze_audio_quality, analyze_video_quality
from analyzer.reporter import generate_report

A, B, C = 0x01010101, 0x02020202, 0x03030303
SR = 8000


def make_packets(ssrc, items, dt=0.02):
    """items: [(seq, ts, pt, payload)] -> extract_rtp_packets 风格 packets。"""
    packets = {}
    for i, (seq, ts, pt, payload) in enumerate(items):
        packets[(ssrc, seq)] = (i * dt, ts, pt, '10.0.0.1', '10.0.0.2', 1, 2,
                                payload)
    return packets


def ulaw_payload(samples):
    return audioop.lin2ulaw(np.asarray(samples, dtype=np.int16).tobytes(), 2)


def audio_items(x, spp=160, pt=0, ts0=1000):
    """把 int16 波形按 spp 切包 -> [(seq, ts, pt, payload)]。"""
    items, ts = [], ts0
    for i in range(0, len(x) - spp + 1, spp):
        items.append((len(items), ts, pt, ulaw_payload(x[i:i + spp])))
        ts += spp
    return items


def speech_like(seconds=3.0, seed=7):
    """拟人声波形：谐波结构 + 共振峰包络 + 底噪 + 音节起伏。

    音质检测应视为干净流（无啸叫/嗡声/削波/爆点）。
    """
    rng = np.random.default_rng(seed)
    n = int(seconds * SR)
    t = np.arange(n) / SR
    f0 = 120 * (1 + 0.03 * np.sin(2 * np.pi * 0.9 * t))
    phase = 2 * np.pi * np.cumsum(f0) / SR
    x = np.zeros(n)
    for k, amp in ((1, 1.0), (2, 0.5), (3, 0.35), (4, 0.2), (5, 0.15),
                   (8, 0.08), (12, 0.05), (20, 0.03)):
        x += amp * np.sin(k * phase)
    # 共振峰：把高频谐波再乘个缓变调制，避免任何频率长期恒定
    x *= (1 + 0.3 * np.sin(2 * np.pi * 3.1 * t))
    # 音节起伏：0.2s 开 / 0.13s 关
    env = (np.mod(t, 0.33) < 0.2).astype(float)
    env = np.convolve(env, np.ones(400) / 400, mode='same')
    x = x * env * 6000 + rng.normal(0, 60, n)   # 底噪 -54dBFS 左右
    return np.clip(x, -32000, 32000).astype(np.int16)


def test_audio_clean_speech():
    """拟人声：verdict clean，无啸叫/嗡声/削波/爆点。"""
    x = speech_like()
    r = analyze_audio_quality(make_packets(A, audio_items(x)), A)
    assert r['decodable'] and r['packet_count'] > 100, r
    assert r['verdict'] == 'clean', r
    assert r['tones']['count'] == 0, r['tones']
    assert r['clipping']['run_count'] == 0, r['clipping']
    assert r['clicks']['count'] == 0, r['clicks']
    assert r['noise_floor_dbfs'] is not None and r['noise_floor_dbfs'] < -45, r
    print("PASS: audio clean speech -> no anomalies")


def test_audio_howling():
    """持续 2.5s 的 1000Hz 单音：判定啸叫，频率约 1kHz。"""
    n = int(2.5 * SR)
    t = np.arange(n) / SR
    tone = (6000 * np.sin(2 * np.pi * 1000 * t)).astype(np.int16)
    r = analyze_audio_quality(make_packets(B, audio_items(tone)), B)
    assert r['tones']['howl_count'] == 1, r['tones']
    ev = r['tones']['events'][0]
    assert abs(ev['freq_hz'] - 1000) < 60, ev
    assert ev['end_s'] - ev['start_s'] > 2.0, ev
    assert r['verdict'] == 'bad', r
    kinds = [i['kind'] for i in r['issues']]
    assert 'howling' in kinds, r['issues']
    print("PASS: audio howling detected at ~1kHz")


def test_audio_hum():
    """持续 2s 的 100Hz 低频嗡声：hum 事件，归为嗡声而非啸叫。"""
    n = int(2.0 * SR)
    t = np.arange(n) / SR
    tone = (4000 * np.sin(2 * np.pi * 100 * t)).astype(np.int16)
    r = analyze_audio_quality(make_packets(C, audio_items(tone)), C)
    assert r['tones']['hum_count'] >= 1, r['tones']
    assert r['tones']['howl_count'] == 0, r['tones']
    kinds = [i['kind'] for i in r['issues']]
    assert 'hum' in kinds, r['issues']
    print("PASS: audio low-frequency hum detected")


def test_audio_ringback_is_prompt_not_howling():
    """开头 1.5s 的 450Hz 回铃音 + 之后 68s 静音：归为提示音(info)而非
    啸叫，不报削波/话音电平，报"全程未检测到话音"，verdict silent。

    对应真实抓包形态：FS→主叫只有一声"嘟"之后全程数字静音（单通）。"""
    t = np.arange(int(1.5 * SR)) / SR
    tone = (6000 * np.sin(2 * np.pi * 450 * t)).astype(np.int16)
    x = np.concatenate([tone, np.zeros(int(68 * SR))]).astype(np.int16)
    r = analyze_audio_quality(make_packets(A, audio_items(x)), A)
    assert r['tones']['howl_count'] == 0, r['tones']
    assert r['tones']['prompt_count'] == 1, r['tones']
    kinds = [i['kind'] for i in r['issues']]
    assert 'howling' not in kinds and 'clipping' not in kinds, r['issues']
    assert 'high_level' not in kinds and 'low_level' not in kinds, r['issues']
    assert 'prompt_tone' in kinds and 'no_speech' in kinds, r['issues']
    assert r['speech_level_dbfs'] is None, r
    assert r['verdict'] == 'silent', r
    print("PASS: ringback tone classified as prompt, stream flagged silent")


def test_audio_steady_noise_is_not_speech():
    """持续背景电平（工频嗡声+底噪）不是话音：报 no_speech，不冒话音电平。

    对应真实抓包形态：主叫设备故障时把 50Hz 嗡声+宽带噪声整通发上来，
    能量过门限但包络无音节起伏——不能算"有人声"。"""
    t = np.arange(int(12 * SR)) / SR
    rng = np.random.default_rng(7)
    x = (600 + 100 * np.sin(2 * np.pi * 50 * t)
         + rng.integers(-80, 80, t.size)).astype(np.int16)
    r = analyze_audio_quality(make_packets(A, audio_items(x)), A)
    assert r['speech_activity'] is False, r
    assert r['speech_level_dbfs'] is None, r
    assert r['steady_level_dbfs'] is not None, r
    kinds = [i['kind'] for i in r['issues']]
    assert 'no_speech' in kinds, r['issues']
    assert 'low_level' not in kinds and 'high_level' not in kinds, r['issues']
    assert r['verdict'] == 'silent', r
    print("PASS: steady background level reported as no_speech, verdict silent")


def test_audio_voice_moments_inside_background():
    """背景电平中短暂的人声：检出话音电平与背景电平，不报 no_speech。

    对应真实抓包形态：设备把工频嗡声/底噪整通发上来，中间短暂出现过
    人声——人声时刻要单独检出，不能整段吞成背景电平。"""
    t = np.arange(int(12 * SR)) / SR
    rng = np.random.default_rng(3)
    x = 600 + 100 * np.sin(2 * np.pi * 50 * t) + rng.integers(-80, 80, t.size)
    for a in (2.0, 7.0):                    # 两段 240ms 的人声（包络≈3×背景）
        for j in range(12):
            s = int((a + j * 0.02) * SR)
            n = int(0.02 * SR)
            amp = 3000 if j % 2 else 2000
            x[s:s + n] = amp * np.sin(2 * np.pi * 200 * np.arange(n) / SR)
    r = analyze_audio_quality(make_packets(A, audio_items(x.astype(np.int16))), A)
    assert r['speech_activity'] is True, r
    assert r['speech_level_dbfs'] is not None, r
    assert r['steady_level_dbfs'] is not None, r
    kinds = [i['kind'] for i in r['issues']]
    assert 'no_speech' not in kinds, r['issues']
    print("PASS: voice moments inside background detected in quality stats")


def test_audio_clipping_inside_tone_not_flagged():
    """单频音事件自身的削平采样不报削波（提示音生成过热 ≠ 发话端破音）。

    300Hz 不在提示音频率表内，事件按啸叫档记录；其削顶被剔除。"""
    t = np.arange(int(1.0 * SR)) / SR
    tone = np.clip(32000 * np.sin(2 * np.pi * 300 * t), -27200, 27200)
    r = analyze_audio_quality(make_packets(A, audio_items(tone.astype(np.int16))), A)
    assert r['tones']['count'] >= 1, r['tones']
    assert r['clipping']['run_count'] == 0, r['clipping']
    print("PASS: clipping flats inside tone events not flagged")


def test_audio_clipping():
    """削波平台（连续相等大幅值采样）：检出削波。"""
    t = np.arange(int(1.0 * SR)) / SR
    sine = 30000 * np.sin(2 * np.pi * 200 * t)
    clipped = np.clip(sine, -28000, 28000)      # 平顶削波
    x = clipped.astype(np.int16)
    r = analyze_audio_quality(make_packets(A, audio_items(x)), A)
    assert r['clipping']['run_count'] >= 2, r['clipping']
    assert r['clipping']['sample_count'] > 20, r['clipping']
    kinds = [i['kind'] for i in r['issues']]
    assert 'clipping' in kinds, r['issues']
    print("PASS: audio clipping detected")


def test_audio_click():
    """孤立脉冲尖峰：检出爆点；干净段不误报。"""
    x = (1000 * np.sin(2 * np.pi * 250 * np.arange(int(1.0 * SR)) / SR)
         ).astype(np.int16)
    x[4000] = 30000
    x[4001] = -30000
    r = analyze_audio_quality(make_packets(A, audio_items(x)), A)
    assert r['clicks']['count'] == 1, r['clicks']
    assert abs(r['clicks']['events'][0]['time_s'] - 4000 / SR) < 0.05, \
        r['clicks']['events']
    print("PASS: audio click spike detected")


def test_audio_noisy_floor():
    """持续明显底噪（RMS≈420 的白噪声）：底噪偏高 issue，verdict noisy。"""
    rng = np.random.default_rng(3)
    x = rng.normal(0, 420, int(2.0 * SR)).astype(np.int16)
    r = analyze_audio_quality(make_packets(A, audio_items(x)), A)
    assert r['noise_floor_dbfs'] is not None and r['noise_floor_dbfs'] > -45, r
    kinds = [i['kind'] for i in r['issues']]
    assert 'noise' in kinds, r['issues']
    assert r['verdict'] == 'noisy', r
    print("PASS: audio high noise floor detected")


def test_audio_undecodable():
    """非 G.711 编码（G722）：decodable=False、verdict unknown。"""
    items = [(i, 1000 + i * 160, 9, b'\x00' * 160) for i in range(50)]
    r = analyze_audio_quality(make_packets(A, items), A)
    assert not r['decodable'] and r['verdict'] == 'unknown', r
    print("PASS: audio undecodable codec -> unknown")


# ---------- RTP 序号/时间戳秩序 ----------

def test_audio_rtp_integrity_clean():
    """连续流：序号每包 +1、时间戳单调递增，rtp_ok 提示进 issues。"""
    r = analyze_audio_quality(make_packets(A, audio_items(speech_like(1.0))), A)
    integ = r['rtp_integrity']
    assert integ['seq_continuous'] and integ['monotonic'], integ
    assert integ['lost_packets'] == 0 and integ['ts_backward'] == 0, integ
    assert integ['median_ts_delta'] == 160 and integ['packet_duration_ms'] == 20.0, integ
    assert any(i['kind'] == 'rtp_ok' for i in r['issues']), r['issues']
    print("PASS: rtp integrity clean -> seq/ts order affirmed")


def test_audio_rtp_ts_backward():
    """时间戳倒退（发送端时钟异常）：critical rtp_order issue。"""
    items = audio_items(speech_like(1.0))
    seq, ts, pt, payload = items[20]
    items[20] = (seq, ts - 480, pt, payload)
    r = analyze_audio_quality(make_packets(A, items), A)
    integ = r['rtp_integrity']
    assert not integ['monotonic'] and integ['ts_backward'] >= 1, integ
    assert any(i['kind'] == 'rtp_order' and i['severity'] == 'critical'
               for i in r['issues']), r['issues']
    print("PASS: ts backward detected as critical")


def test_audio_rtp_ts_duplicate():
    """时间戳重复（序号前进、媒体时间原地踏步）：warning rtp_order issue。"""
    items = audio_items(speech_like(1.0))
    seq, ts, pt, payload = items[15]
    items[15] = (seq, ts - 160, pt, payload)
    r = analyze_audio_quality(make_packets(A, items), A)
    assert r['rtp_integrity']['ts_duplicate'] == 1, r['rtp_integrity']
    assert any(i['kind'] == 'rtp_order' and i['severity'] == 'warning'
               for i in r['issues']), r['issues']
    print("PASS: ts duplicate detected as warning")


def test_audio_rtp_seq_loss():
    """序号缺口（丢 3 包）：补零 60ms 计入，rtp_loss issue。"""
    items = audio_items(speech_like(1.0))
    del items[10:13]
    r = analyze_audio_quality(make_packets(A, items), A)
    integ = r['rtp_integrity']
    assert integ['seq_gaps'] == 1 and integ['lost_packets'] == 3, integ
    assert not integ['seq_continuous'] and integ['zero_filled_ms'] == 60.0, integ
    assert any(i['kind'] == 'rtp_loss' for i in r['issues']), r['issues']
    print("PASS: seq gap loss counted with zero-fill amount")


def dtmf_mixed_items(n_audio=100):
    """音频 + 2 次 DTMF 按键（RFC 4733：事件包 ts=事件起始时刻、落后于
    当前音频时钟；重传包共用同一 ts），seq 交错——复刻真实抓包里
    "时间戳倒退 6 处 + 重复 2 处"的形态。"""
    audio = audio_items(speech_like(n_audio * 0.02 + 0.1))[:n_audio]
    ev_groups = {29: 3, 69: 2}          # 音频包序号 -> 其后插入的事件包数
    items, seq = [], 0
    for i, (aseq, ats, apt, apayload) in enumerate(audio):
        items.append((seq, ats, apt, apayload))
        seq += 1
        if i in ev_groups:
            ev_ts = 1000 + (i - 1) * 160        # 事件起始：落后音频时钟头
            for _ in range(ev_groups[i]):
                items.append((seq, ev_ts, 101, bytes([5, 0, 200, 0])))
                seq += 1
    return items


def test_audio_rtp_dtmf_events_not_flagged():
    """混合 RFC4733 事件包：不误报倒退/重复，秩序判定保持正常。"""
    r = analyze_audio_quality(make_packets(A, dtmf_mixed_items()), A)
    integ = r['rtp_integrity']
    assert integ['monotonic'] and integ['ts_backward'] == 0, integ
    assert integ['ts_duplicate'] == 0, integ
    assert integ['seq_continuous'] and integ['lost_packets'] == 0, integ
    assert integ['other_pt_packets'] == 5, integ
    assert not any(i['kind'] == 'rtp_order' for i in r['issues']), r['issues']
    print("PASS: DTMF event packets exempted from ts order check")


def test_audio_rtp_rollback_still_detected_in_mixed():
    """混合流中纯音频包上的真实时间戳回退仍要被检出。"""
    items = dtmf_mixed_items()
    audio_idx = [k for k, it in enumerate(items) if it[2] == 0]
    k = audio_idx[85]
    items[k] = (items[k][0], items[k][1] - 800, items[k][2], items[k][3])
    r = analyze_audio_quality(make_packets(A, items), A)
    integ = r['rtp_integrity']
    assert not integ['monotonic'] and integ['ts_backward'] >= 1, integ
    assert any(i['kind'] == 'rtp_order' and i['severity'] == 'critical'
               for i in r['issues']), r['issues']
    print("PASS: real ts rollback among audio packets still detected")


# ---------- 视频花屏风险 ----------

def fu_fragments(nal_body, frag_size=40):
    """把一个 NAL body 切成 FU-A 分片载荷列表（首片带 FU indicator/header）。"""
    nal_hdr = 0x65  # IDR slice (type 5)
    frags = []
    for i in range(0, len(nal_body), frag_size):
        first = 1 if i == 0 else 0
        last = 1 if i + frag_size >= len(nal_body) else 0
        fu_header = (first << 7) | (last << 6) | 5
        payload = bytes([0x7C, fu_header]) + nal_body[i:i + frag_size]
        frags.append(payload)
    return frags


def test_video_broken_fragment():
    """FU-A 分片中段丢包：破损帧 +1、丢包映射到花屏影响时长。"""
    frags = fu_fragments(bytes(range(256)) * 2)     # 5 片左右
    items = []
    ts = 3000
    for i, payload in enumerate(frags):
        if i == 2:
            ts += 3000          # 丢包的那片：ts 继续走，seq 跳过
            continue
        items.append((i, ts, 96, payload))
        ts += 3000
    packets = make_packets(B, items, dt=0.04)
    r = analyze_video_quality(packets, B)
    assert r['total_lost'] == 1, r
    assert r['broken_nals'] == 1, r
    assert r['idr_count'] == 1, r
    assert r['est_artifacts_ms'] > 0, r
    assert r['verdict'] == 'bad' and r['issues'], r
    kinds = [i['kind'] for i in r['issues']]
    assert 'broken_nal' in kinds and 'video_loss' in kinds, r['issues']
    print("PASS: video broken FU-A fragment -> corruption detected")


def test_video_clean():
    """无丢包、IDR 正常：verdict ok，无 issues。"""
    items = []
    ts = 3000
    for i in range(60):
        if i % 30 == 0:
            items.append((i, ts, 96, bytes([0x65]) + b'\xaa' * 30))  # IDR
        else:
            items.append((i, ts, 96, bytes([0x41]) + b'\xbb' * 30))  # 非 IDR
        ts += 3000
    packets = make_packets(A, items, dt=0.04)
    r = analyze_video_quality(packets, A)
    assert r['total_lost'] == 0 and r['broken_nals'] == 0, r
    assert r['idr_count'] == 2, r
    assert r['idr_interval_max_s'] == 1.2, r   # 30 包 × 40ms
    assert r['verdict'] == 'ok' and not r['issues'], r
    print("PASS: video clean stream -> ok")


def test_video_no_idr():
    """10s 以上无关键帧 + 有丢包：no_idr 提醒（丢包后画面无法自愈）。"""
    items = []
    ts = 3000
    for i in range(260):
        if i == 100:
            i_seq = i + 1   # 跳一个 seq 制造丢包
        else:
            i_seq = i
        items.append((i_seq, ts, 96, bytes([0x41]) + b'\xbb' * 30))
        ts += 3000
    packets = make_packets(A, items, dt=0.04)
    r = analyze_video_quality(packets, A)
    assert r['idr_count'] == 0 and r['total_lost'] == 1, r
    kinds = [i['kind'] for i in r['issues']]
    assert 'no_idr' in kinds, r['issues']
    print("PASS: video no IDR in 10s+ -> warning")


def test_video_missing_start_fragment():
    """FU-A 首片丢失、结尾片到达：同样计破损帧。"""
    frags = fu_fragments(bytes(range(256)) * 2)
    items = []
    ts, seq = 3000, 0
    for i, payload in enumerate(frags):
        if i == 0:
            seq += 1        # 首片丢失
            continue
        items.append((seq, ts, 96, payload))
        seq += 1
        ts += 3000
    packets = make_packets(C, items, dt=0.04)
    r = analyze_video_quality(packets, C)
    assert r['broken_nals'] == 1, r
    print("PASS: video missing start fragment -> broken NAL")


def test_video_rtp_frame_ts_order():
    """视频同帧多包共用时间戳（frame 模式）：不误报倒退/重复，秩序正常。"""
    items = []
    ts, seq = 3000, 0
    for i in range(60):
        n_pkts = 3 if i % 30 == 0 else 1    # 关键帧拆 3 包，共用同一 ts
        for _ in range(n_pkts):
            payload = (bytes([0x65]) + b'\xaa' * 30 if i % 30 == 0
                       else bytes([0x41]) + b'\xbb' * 30)
            items.append((seq, ts, 96, payload))
            seq += 1
        ts += 3000
    r = analyze_video_quality(make_packets(A, items, dt=0.04), A)
    integ = r['rtp_integrity']
    assert integ['monotonic'] and integ['ts_backward'] == 0, integ
    assert integ['ts_duplicate'] == 0 and integ['seq_continuous'], integ
    assert integ['lost_packets'] == 0, integ
    assert r['verdict'] == 'ok' and not r['issues'], r
    print("PASS: video frame-mode same-ts packets not flagged")


# ---------- 报告接线 ----------

def test_report_wiring():
    """audio_quality/video_quality 的 issues 进入报告结论并带流名前缀。"""
    results = {
        'audio_quality': {
            'seat (SSRC=0x01010101)': {
                'verdict': 'bad',
                'issues': [{'kind': 'howling', 'severity': 'critical',
                            'message': '检测到啸叫/持续单频音 1 处'}],
            },
        },
        'video_quality': {
            'seat (SSRC=0x02020202)': {
                'verdict': 'bad',
                'issues': [{'kind': 'broken_nal', 'severity': 'critical',
                            'message': '1 个视频帧数据破损'}],
            },
        },
    }
    report = generate_report(results)
    assert report['media_quality']['audio']['seat (SSRC=0x01010101)']['verdict'] \
        == 'bad', report['media_quality']
    msgs = [i['message'] for i in report['conclusion']['issues']]
    assert any('检测到啸叫' in m and '被叫端（坐席）' in m for m in msgs), msgs
    assert any('视频帧数据破损' in m and '被叫端（坐席）' in m for m in msgs), msgs
    assert report['conclusion']['overall'] == 'critical', report['conclusion']
    print("PASS: quality issues wired into report conclusion")


if __name__ == '__main__':
    test_audio_clean_speech()
    test_audio_howling()
    test_audio_hum()
    test_audio_ringback_is_prompt_not_howling()
    test_audio_steady_noise_is_not_speech()
    test_audio_voice_moments_inside_background()
    test_audio_clipping_inside_tone_not_flagged()
    test_audio_clipping()
    test_audio_click()
    test_audio_noisy_floor()
    test_audio_undecodable()
    test_audio_rtp_integrity_clean()
    test_audio_rtp_ts_backward()
    test_audio_rtp_ts_duplicate()
    test_audio_rtp_seq_loss()
    test_audio_rtp_dtmf_events_not_flagged()
    test_audio_rtp_rollback_still_detected_in_mixed()
    test_video_broken_fragment()
    test_video_clean()
    test_video_no_idr()
    test_video_missing_start_fragment()
    test_video_rtp_frame_ts_order()
    test_report_wiring()
    print("ALL TESTS PASSED")
