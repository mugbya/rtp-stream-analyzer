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
    assert any('检测到啸叫' in m and '坐席端' in m for m in msgs), msgs
    assert any('视频帧数据破损' in m and '坐席端' in m for m in msgs), msgs
    assert report['conclusion']['overall'] == 'critical', report['conclusion']
    print("PASS: quality issues wired into report conclusion")


if __name__ == '__main__':
    test_audio_clean_speech()
    test_audio_howling()
    test_audio_hum()
    test_audio_clipping()
    test_audio_click()
    test_audio_noisy_floor()
    test_audio_undecodable()
    test_video_broken_fragment()
    test_video_clean()
    test_video_no_idr()
    test_video_missing_start_fragment()
    test_report_wiring()
    print("ALL TESTS PASSED")
