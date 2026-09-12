"""
Unit tests for ts_continuity, fixed packet_loss (reorder refund) and
timestamp-aware audio reconstruction.

Run: python3 tests/test_ts_continuity.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzer.ts_continuity import check_ts_continuity
from analyzer.packet_loss import detect_packet_loss
from analyzer.media_extractor import reconstruct_audio
from analyzer.reporter import generate_report

SSRC = 0x1234


def make_packets(entries, pt=0, payload_len=None):
    """entries: [(time, seq, ts)] -> extract_rtp_packets 风格的 packets 字典。

    payload_len 不为 None 时带 8 元组（含载荷），供音频重建用。
    """
    packets = {}
    for t, seq, ts in entries:
        v = [t, ts, pt, '10.0.0.2', '10.0.0.1', 5000, 6000]
        if payload_len is not None:
            v.append(b'\xd5' * payload_len)
        packets[(SSRC, seq)] = tuple(v)
    return packets


def continuous_entries(n, t0=100.0, seq0=100, ts0=1000, dt=0.02, dts=160):
    """一条理想的 20ms 包化流：seq 连续 +1，ts 连续 +dts。"""
    return [(t0 + i * dt, (seq0 + i) & 0xFFFF, ts0 + i * dts) for i in range(n)]


def test_continuous_stream():
    """理想流：时间戳连续、每包 20ms，无事件、无丢包。"""
    packets = make_packets(continuous_entries(100))
    r = check_ts_continuity(packets, SSRC)
    assert r['is_continuous'] and r['event_count'] == 0
    assert r['median_ts_delta'] == 160 and r['packet_duration_ms'] == 20.0
    assert r['clock_rate'] == 8000 and r['pt'] == 0
    loss = detect_packet_loss(packets, SSRC)
    assert loss['total_lost'] == 0 and loss['is_clean'] and loss['reorder_count'] == 0
    print("PASS: continuous stream -> 20ms/packet, no events, no loss")


def test_silence_jump_marked_not_loss():
    """静音抑制：seq 连续但 ts 跳 1s -> 报跳变、不报丢包。"""
    entries = continuous_entries(100)
    for i in range(50, 100):
        t, s, ts = entries[i]
        entries[i] = (t, s, ts + 8000)
    packets = make_packets(entries)
    r = check_ts_continuity(packets, SSRC)
    assert r['jump_count'] == 1 and r['event_count'] == 1, r
    assert r['is_continuous'] is False
    assert r['total_media_gap_ms'] == 1000.0, r['total_media_gap_ms']
    ev = r['events'][0]
    assert ev['kind'] == 'ts_jump' and ev['media_gap_ms'] == 1000.0 and ev['seq'] == 150
    loss = detect_packet_loss(packets, SSRC)
    assert loss['total_lost'] == 0, loss
    print("PASS: silence suppression -> ts_jump event (1000ms gap), no false loss")


def test_seq_loss_consistent_with_ts():
    """丢 3 包且 ts 缺口与之匹配 -> 正常记丢包，不误报时间戳跳变。"""
    entries = [e for i, e in enumerate(continuous_entries(100)) if i not in (50, 51, 52)]
    packets = make_packets(entries)
    r = check_ts_continuity(packets, SSRC)
    assert r['jump_count'] == 0 and r['is_continuous'], r
    loss = detect_packet_loss(packets, SSRC)
    assert loss['total_lost'] == 3 and loss['loss_event_count'] == 1
    assert loss['max_consecutive_loss'] == 3
    print("PASS: real loss -> 3 lost, no ts_jump")


def test_reorder_refund_not_loss():
    """乱序：106 先于 105 到达 -> 0 丢包（旧实现回绕算成 65486）、乱序 1 次。"""
    entries = continuous_entries(20)
    # 乱序用捕获时间表达：seq 110 比 seq 111 晚 10ms 才被捕获
    t10, t11 = entries[10][0], entries[11][0]
    entries[10] = (t11 + 0.01, entries[10][1], entries[10][2])
    entries[11] = (t10, entries[11][1], entries[11][2])
    packets = make_packets(entries)
    loss = detect_packet_loss(packets, SSRC)
    assert loss['total_lost'] == 0, loss
    assert loss['reorder_count'] == 1 and loss['is_clean']
    r = check_ts_continuity(packets, SSRC)
    assert r['reorder_count'] == 1 and r['jump_count'] == 0 and r['backward_count'] == 0
    print("PASS: reordered pair -> 0 loss + 1 reorder (old code: 65486 lost)")


def test_true_loss_plus_reorder():
    """丢 1 包 + 1 个迟到包 -> 最终丢包数 1，不会被乱序放大。"""
    base = continuous_entries(20)
    entries = [e for e in base if e[1] != 105]           # 丢 seq 105
    late = next(e for e in entries if e[1] == 108)
    entries.remove(late)
    t109 = next(e[0] for e in entries if e[1] == 109)
    entries.append((t109 + 0.01, 108, late[2]))          # 108 迟到
    loss = detect_packet_loss(make_packets(entries), SSRC)
    assert loss['total_lost'] == 1, loss
    assert loss['reorder_count'] == 1 and not loss['is_clean']
    print("PASS: 1 real loss + 1 late packet -> exactly 1 lost")


def test_seq_wrap():
    """seq 越过 65535→0 回绕：不算丢包也不算乱序。"""
    entries = [(100 + i * 0.02, (65530 + i) & 0xFFFF, 1000 + i * 160) for i in range(20)]
    loss = detect_packet_loss(make_packets(entries), SSRC)
    assert loss['total_lost'] == 0 and loss['reorder_count'] == 0, loss
    r = check_ts_continuity(make_packets(entries), SSRC)
    assert r['is_continuous'], r
    print("PASS: seq wrap -> no loss, no reorder")


def test_ts_wrap():
    """ts 越过 2^32 回绕：计 1 次回绕，不报跳变/倒退。"""
    entries = [(100 + i * 0.02, 100 + i, (0xFFFFFF00 + i * 160) & 0xFFFFFFFF)
               for i in range(20)]
    r = check_ts_continuity(make_packets(entries), SSRC)
    assert r['is_continuous'], r['events'][:3]
    assert r['wrap_count'] == 1 and r['jump_count'] == 0 and r['backward_count'] == 0
    print("PASS: ts wrap -> 1 wrap, no false jump")


def test_duplicate_ts():
    """相邻两包 ts 相同 -> duplicate 事件。"""
    entries = continuous_entries(10)
    entries[5] = (entries[5][0], entries[5][1], entries[4][2])
    r = check_ts_continuity(make_packets(entries), SSRC)
    assert r['duplicate_count'] == 1 and r['event_count'] == 1
    assert r['events'][0]['kind'] == 'duplicate'
    print("PASS: duplicate ts -> duplicate event")


def test_ts_backward_with_in_order_seq():
    """seq 顺序但 ts 倒退 1s -> ts_backward（发送端异常，与乱序区分开）。"""
    entries = continuous_entries(10)
    entries[5] = (entries[5][0], entries[5][1], entries[5][2] - 16000)
    r = check_ts_continuity(make_packets(entries), SSRC)
    assert r['backward_count'] == 1, r
    kinds = [e['kind'] for e in r['events']]
    assert 'ts_backward' in kinds and 'reorder' not in kinds, kinds
    print("PASS: ts backward with in-order seq -> ts_backward (not reorder)")


def test_audio_rebuild_30ms_packetization():
    """30ms/240 样本包化 + 丢 2 包：按实测包长重建（旧实现按 160 会算短时长）。"""
    entries = [e for i, e in enumerate(continuous_entries(100, dts=240))
               if i not in (50, 51)]
    packets = make_packets(entries, pt=8, payload_len=240)
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, 'a.wav')
        res = reconstruct_audio(packets, SSRC, out)
    assert res['success'], res['error']
    assert res['samples_per_packet'] == 240 and res['packet_duration_ms'] == 30.0, res
    assert res['silence_filled'] == 2 and res['lost_packets'] == 2
    # 98 存量包 + 2 包静音 = 100 × 240 样本 = 3000ms
    assert abs(res['duration_ms'] - 3000.0) < 1, res['duration_ms']
    print("PASS: 30ms packetization rebuilt with measured 240 samples/packet")


def test_audio_rebuild_ts_jump_filled():
    """seq 连续但 ts 跳变（静音 180ms）：重建补 1440 样本静音，时长不缩水。"""
    entries = continuous_entries(50)
    for i in range(25, 50):
        t, s, ts = entries[i]
        entries[i] = (t, s, ts + 1440)
    packets = make_packets(entries, pt=0, payload_len=160)
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, 'a.wav')
        res = reconstruct_audio(packets, SSRC, out)
    assert res['success'], res['error']
    assert res['ts_gap_filled'] == 1, res
    assert abs(res['ts_extra_silence_ms'] - 180.0) < 0.1, res['ts_extra_silence_ms']
    # 50×160 + 1440 = 9440 样本 = 1180ms
    assert abs(res['duration_ms'] - 1180.0) < 1, res['duration_ms']
    print("PASS: ts jump filled with 1440 silence samples (180ms)")


def test_video_frame_mode():
    """视频流（RFC 6184 同帧多包共用 ts）：重复/跳变不算异常，倒退仍要报。"""
    entries = []
    t, seq = 100.0, 100
    for frame in range(30):
        for _ in range(3):  # 每帧 3 个包，同帧时间戳相同
            entries.append((t, seq, 900000 + frame * 9000))  # 90kHz 时钟，30fps
            seq += 1
            t += 0.01
    packets = make_packets(entries, pt=96)
    r = check_ts_continuity(packets, SSRC)
    assert r['mode'] == 'frame', r
    assert r['duplicate_count'] == 0 and r['jump_count'] == 0
    assert r['is_continuous'], r['events'][:3]

    # 下一帧的包提前到达（捕获序 ts 倒退 + seq 倒退）-> 乱序照常上报
    entries2 = list(entries)
    early = entries2[12]
    entries2[12] = (entries2[9][0] - 0.005, early[1], early[2])
    r2 = check_ts_continuity(make_packets(entries2, pt=96), SSRC)
    assert r2['reorder_count'] == 1 and not r2['is_continuous'], r2
    print("PASS: video frame mode -> same-frame ts normal, reorder still reported")


def test_report_marks_ts_anomaly():
    """报告：时间戳异常进 issues（含缺失媒体时间），小节带事件明细。"""
    label = 'fs (SSRC=0x00001234)'
    results = {
        'ts_continuity': {
            label: {
                'label': label, 'is_continuous': False,
                'event_count': 2, 'jump_count': 1, 'backward_count': 1,
                'reorder_count': 0, 'duplicate_count': 0, 'wrap_count': 0,
                'total_media_gap_ms': 1000.0, 'packet_duration_ms': 20.0,
                'packet_count': 100,
                'events': [{'time': 100.0, 'kind': 'ts_jump', 'seq': 150,
                            'ts_delta': 8160, 'media_gap_ms': 1000.0}],
            },
        },
    }
    report = generate_report(results)
    sec = report['timestamp_continuity']['streams'][label]
    assert sec['event_count'] == 2 and sec['events'][0]['time_str'] == '08:01:40'
    msgs = ' '.join(i['message'] for i in report['conclusion']['issues'])
    assert '时间戳不连续' in msgs and '1.0 秒媒体时间' in msgs, msgs
    assert report['conclusion']['overall'] in ('warning', 'critical')
    print("PASS: report marks ts anomaly in issues + timestamp_continuity section")


if __name__ == '__main__':
    test_continuous_stream()
    test_silence_jump_marked_not_loss()
    test_seq_loss_consistent_with_ts()
    test_reorder_refund_not_loss()
    test_true_loss_plus_reorder()
    test_seq_wrap()
    test_ts_wrap()
    test_duplicate_ts()
    test_ts_backward_with_in_order_seq()
    test_video_frame_mode()
    test_audio_rebuild_30ms_packetization()
    test_audio_rebuild_ts_jump_filled()
    test_report_marks_ts_anomaly()
    print("\n=== ALL TS CONTINUITY TESTS PASSED ===")
