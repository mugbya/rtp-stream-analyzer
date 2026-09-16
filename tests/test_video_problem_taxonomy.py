"""
视频问题分类测试：classify_video_problems 把各检测器结论聚合为
《视频问题》清单里的问题种类（含用户观感词、优先级、排查方向），
按流类别过滤证据，并按 media_type 门控接入 generate_report。

Run: python3 tests/test_video_problem_taxonomy.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzer.problem_taxonomy import classify_problems
from analyzer.reporter import generate_report
from analyzer.video_problem_taxonomy import (
    classify_video_problems, VIDEO_TAXONOMY, VIDEO_UNOBSERVABLE,
)

BASE = {
    'direction': 'auto', 'media_type': 'video',
    'checks': {'delay': True, 'quality': True},
    'num_captures': 1, 'capture_roles': {'fs': 'fs.pcap'},
    'audio_health': None, 'fs_relay': None, 'packet_loss': {}, 'rtcp': {},
    'audio_quality': {}, 'video_quality': {}, 'ts_continuity': {},
    'fs_delay': {}, 'jitter': {}, 'delay_chains': None,
}


def _find(problems, pid):
    return next((p for p in problems if p['id'] == pid), None)


def test_one_way_video_p0():
    """一端视频上行、另一端零下发 → 单通视频 P0，观感词与排查方向齐备。"""
    results = {**BASE, 'fs_relay': {
        'available': True, 'verdict': 'relayed',
        'headline': '各端都有上行、FS 也有下行——媒体确实经过 FS 中转。',
        'advice': '', 'redirects': [], 'notes': [],
        'devices': [
            {'ip': '10.0.0.1', 'label': '主叫端 10.0.0.1',
             'uplink': {'audio': {'pkts': 900, 'span_s': 30.0, 'last_str': None},
                        'video': {'pkts': 500, 'span_s': 30.0, 'last_str': None}},
             'downlink': {'audio': {'pkts': 800, 'span_s': 30.0, 'last_str': None},
                          'video': {'pkts': 400, 'span_s': 30.0, 'last_str': None}}},
            {'ip': '10.0.0.2', 'label': '被叫端 10.0.0.2',
             'uplink': {'audio': {'pkts': 800, 'span_s': 30.0, 'last_str': None},
                        'video': {'pkts': 0, 'span_s': 0.0, 'last_str': None}},
             'downlink': {'audio': {'pkts': 900, 'span_s': 30.0, 'last_str': None},
                          'video': {'pkts': 0, 'span_s': 0.0, 'last_str': None}}},
        ]}}
    out = classify_video_problems(results)
    p = _find(out['problems'], 'no_video')
    assert p, out
    assert p['priority'] == 'P0' and p['severity'] == 'critical', p
    assert '我看不到对方' in p['feel'] and '对方看不到我' in p['feel'], p['feel']
    assert p['category'] == '无画面 / 连通'
    assert any('单通视频' in e and '被叫端' in e for e in p['evidence']), p['evidence']
    assert p['causes'] and p['verify'], p
    assert out['problems'][0]['id'] == 'no_video'
    print("PASS: one-way video classified as P0 with feel words")


def test_relay_redirect_not_one_way():
    """改道（bypass）后 FS 看不到端到端媒体：只报转发结论，不下单通视频判定。"""
    results = {**BASE, 'fs_relay': {
        'available': True, 'verdict': 'redirected',
        'headline': 'FS 已把媒体改道为端到端直连（SDP 透传）',
        'advice': '', 'notes': [], 'redirects': [],
        'devices': [
            {'ip': '10.0.0.1', 'label': '主叫端 10.0.0.1',
             'uplink': {'audio': {'pkts': 0, 'span_s': 0.0, 'last_str': None},
                        'video': {'pkts': 0, 'span_s': 0.0, 'last_str': None}},
             'downlink': {'audio': {'pkts': 0, 'span_s': 0.0, 'last_str': None},
                          'video': {'pkts': 0, 'span_s': 0.0, 'last_str': None}}},
            {'ip': '10.0.0.2', 'label': '被叫端 10.0.0.2',
             'uplink': {'audio': {'pkts': 0, 'span_s': 0.0, 'last_str': None},
                        'video': {'pkts': 0, 'span_s': 0.0, 'last_str': None}},
             'downlink': {'audio': {'pkts': 0, 'span_s': 0.0, 'last_str': None},
                          'video': {'pkts': 0, 'span_s': 0.0, 'last_str': None}}},
        ]}}
    out = classify_video_problems(results)
    p = _find(out['problems'], 'no_video')
    assert p and p['severity'] == 'critical', out
    assert len(p['evidence']) == 1 and '改道' in p['evidence'][0], p['evidence']
    print("PASS: relay redirect reports path verdict only")


def test_corrupt_video():
    """破损帧 + ffmpeg 解码错误 → 花屏 P1，多检测器证据合并。"""
    label = 'fs (SSRC=0x22222222)'
    results = {**BASE, 'video_quality': {label: {
        'packet_count': 3000, 'total_lost': 40, 'loss_rate_pct': 1.3,
        'broken_nals': 6, 'decode_check': 'errors', 'decode_errors': 12,
        'rtp_integrity': {'ts_backward': 0, 'ts_duplicate': 0},
        'issues': [
            {'kind': 'broken_nal', 'severity': 'critical',
             'message': '6 个视频帧数据破损——解码必然出错'},
            {'kind': 'decode_errors', 'severity': 'critical',
             'message': 'ffmpeg 对重建裸流试解码报 12 处错误'},
            {'kind': 'video_loss', 'severity': 'critical',
             'message': '视频流丢包 40 包（1.30%）——花屏直到关键帧'},
        ]}}}
    out = classify_video_problems(results)
    p = _find(out['problems'], 'corrupt_video')
    assert p, out
    assert p['priority'] == 'P1' and p['severity'] == 'critical', p
    assert len(p['evidence']) == 2, p['evidence']
    assert '花屏' in p['feel'] and '马赛克' in p['feel'], p['feel']
    assert any('12 处' in e for e in p['evidence']), p['evidence']
    print("PASS: broken NAL + decode errors merged into corrupt video")


def test_video_loss_with_rtcp():
    """流级丢包与 RTCP RR/NACK 佐证合并进弱网花屏，严重时升到 P1。"""
    label = 'fs (SSRC=0x22222222)'
    results = {**BASE,
               'video_quality': {label: {
                   'total_lost': 50, 'loss_rate_pct': 2.0,
                   'rtp_integrity': {'ts_backward': 0},
                   'issues': [{'kind': 'video_loss', 'severity': 'critical',
                               'message': '视频流丢包 50 包（2.00%），估算花屏 8.0 秒'}]}},
               'rtcp': {label: {
                   'kind': 'video',
                   'rr': {'fraction_lost_pct': 2.0, 'cum_lost': 50, 'jitter': 5},
                   'fb': {'nack': {'packets': 9, 'requested': 25,
                                   'last_time': 0.0, 'reporters': [1]}}}}}
    out = classify_video_problems(results)
    p = _find(out['problems'], 'video_loss')
    assert p, out
    assert p['priority'] == 'P1' and p['severity'] == 'critical', p
    assert len(p['evidence']) == 3, p['evidence']
    assert 'RTCP' in p['sources'] and '音画质量' in p['sources'], p['sources']
    print("PASS: video loss evidence merged from quality + RTCP RR + NACK")


def test_keyframe_and_pli_storm():
    """无 IDR + PLI 频繁 → 关键帧问题 P1。"""
    label = 'fs (SSRC=0x22222222)'
    results = {**BASE,
               'video_quality': {label: {
                   'total_lost': 0, 'nal_units': 900, 'idr_count': 0,
                   'duration_s': 60.0,
                   'rtp_integrity': {'ts_backward': 0},
                   'issues': [{'kind': 'no_idr', 'severity': 'warning',
                               'message': '整个抓包未见到关键帧（IDR）'}]}},
               'rtcp': {label: {
                   'kind': 'video',
                   'fb': {'pli': {'count': 7, 'last_time': 0.0,
                                  'reporters': [1]}}}}}
    out = classify_video_problems(results)
    p = _find(out['problems'], 'keyframe_issue')
    assert p, out
    assert p['priority'] == 'P1' and p['severity'] == 'warning', p
    assert len(p['evidence']) == 2, p['evidence']
    assert any('半天才出画面' in f for f in p['feel']), p['feel']
    assert any('PLI' in e and '7' in e for e in p['evidence']), p['evidence']
    print("PASS: no IDR + PLI storm folded into keyframe issue")


def test_clock_and_low_fps():
    """视频时间戳倒退 → 时钟异常 P1；帧率估算 6fps → 帧率偏低。"""
    label = 'fs (SSRC=0x22222222)'
    results = {**BASE, 'ts_continuity': {label: {
        'packet_count': 3000, 'pt': 96, 'clock_rate': 90000, 'mode': 'frame',
        'event_count': 3, 'jump_count': 0, 'backward_count': 3,
        'reorder_count': 0, 'duplicate_count': 0, 'wrap_count': 0,
        'median_ts_delta': 15000, 'total_media_gap_ms': 0, 'events': []}}}
    out = classify_video_problems(results)
    clock = _find(out['problems'], 'video_clock_anomaly')
    assert clock and clock['severity'] == 'critical', out
    assert any('冻结' in f for f in clock['feel']), clock['feel']
    fps = _find(out['problems'], 'low_fps')
    assert fps and fps['severity'] == 'warning' and fps['priority'] == 'P2', fps
    assert any('6.0' in e or '6.7' in e for e in fps['evidence']), fps['evidence']
    print("PASS: frame-mode ts backward -> clock anomaly; fps estimated")


def test_frame_mode_excluded_from_audio():
    """视频 ts_continuity 不进声音分类（mode=frame），音频倒退不进视频分类。"""
    vlabel = 'fs (SSRC=0x22222222)'
    alabel = 'fs (SSRC=0x11111111)'
    results = {**BASE, 'media_type': 'all',
               'classified_streams': {
                   'audio': {0x11111111: {'pt': [0], 'count': 500}},
                   'video': {0x22222222: {'pt': [96], 'count': 500}}},
               'ts_continuity': {
                   alabel: {'packet_count': 500, 'pt': 0, 'clock_rate': 8000,
                            'mode': 'packet', 'event_count': 2,
                            'jump_count': 2, 'backward_count': 0,
                            'reorder_count': 0, 'duplicate_count': 0,
                            'wrap_count': 0, 'total_media_gap_ms': 320,
                            'events': []},
                   vlabel: {'packet_count': 500, 'pt': 96, 'clock_rate': 90000,
                            'mode': 'frame', 'event_count': 1,
                            'jump_count': 0, 'backward_count': 1,
                            'reorder_count': 0, 'duplicate_count': 0,
                            'wrap_count': 0, 'total_media_gap_ms': 0,
                            'events': []}}}
    audio = classify_problems(results)
    assert not _find(audio['problems'], 'clock_anomaly'), audio['problems']
    drop = _find(audio['problems'], 'dropouts')
    assert drop, '音频 ts 跳变应仍进声音分类'
    video = classify_video_problems(results)
    clock = _find(video['problems'], 'video_clock_anomaly')
    assert clock, video['problems']
    assert not _find(video['problems'], 'dropouts'), video['problems']
    print("PASS: packet/frame mode ts evidence routed by media kind")


def test_packet_loss_kind_routing():
    """视频流丢包归视频分类，音频流丢包归声音分类，互不串台。"""
    results = {**BASE, 'media_type': 'all',
               'classified_streams': {
                   'audio': {0x11111111: {'pt': [0], 'count': 1000}},
                   'video': {0x22222222: {'pt': [96], 'count': 3000}}},
               'packet_loss': {
                   '0x11111111': {'label': 'seat (SSRC=0x11111111)',
                                  'total_packets': 1000, 'total_lost': 50,
                                  'loss_rate_pct': 5.0, 'reorder_count': 0,
                                  'is_clean': False},
                   '0x22222222': {'label': 'fs (SSRC=0x22222222)',
                                  'total_packets': 3000, 'total_lost': 90,
                                  'loss_rate_pct': 3.0, 'reorder_count': 0,
                                  'is_clean': False}}}
    audio = classify_problems(results)
    loss = _find(audio['problems'], 'loss_artifact')
    assert loss, audio['problems']
    assert all('0x22222222' not in e for e in loss['evidence']), loss['evidence']
    video = classify_video_problems(results)
    vloss = _find(video['problems'], 'video_loss')
    assert vloss and vloss['severity'] == 'critical', video['problems']
    assert all('0x11111111' not in e for e in vloss['evidence']), vloss['evidence']
    print("PASS: packet loss evidence routed by stream media kind")


def test_audio_only_call():
    """纯音频通话（无视频流）→ 视频分类不可用并说明排查方向。"""
    results = {**BASE, 'media_type': 'all'}
    out = classify_video_problems(results)
    assert not out['available'] and out['problems'] == [], out
    assert any('视频协商' in n or '没有视频流' in n for n in out['notes']), out['notes']
    print("PASS: audio-only call disables video classification with hint")


def test_report_gating():
    """generate_report 按 media_type 门控：audio 只出声音分类、video 只出
    视频分类、all 两个都出。"""
    results = {**BASE, 'audio_health': {
        'available': True, 'p2p': False,
        'directions': [{'label': '主叫 → 坐席', 'verdict': 'blocked',
                        'verdict_text': '链路断裂', 'legs': []}],
        'summary': ''}}
    r_audio = generate_report({**results, 'media_type': 'audio'})
    assert 'problem_classification' in r_audio, r_audio.keys()
    assert r_audio['problem_classification']['available']
    assert 'video_problem_classification' not in r_audio, r_audio.keys()
    r_video = generate_report({**results, 'media_type': 'video'})
    assert 'video_problem_classification' in r_video, r_video.keys()
    assert 'problem_classification' not in r_video, r_video.keys()
    r_all = generate_report({**results, 'media_type': 'all'})
    assert 'problem_classification' in r_all and 'video_problem_classification' in r_all
    # 视频分类键在 all 下恒存在（纯音频通话时 available=False 而非缺键）
    assert r_all['video_problem_classification']['available'] is False
    print("PASS: report gating by media_type (audio/video/all)")


def test_taxonomy_consistency():
    """分类表自洽：id 唯一、优先级合法、观感词/描述/验证方法非空。"""
    assert len(VIDEO_TAXONOMY) == len(set(VIDEO_TAXONOMY))
    for pid, spec in VIDEO_TAXONOMY.items():
        assert spec['priority'] in ('P0', 'P1', 'P2', 'P3'), pid
        assert spec['feel'] and spec['description'] and spec['causes'] and spec['verify'], pid
    for u in VIDEO_UNOBSERVABLE:
        assert u['feel'] and u['why'] and u['verify'], u
    print("PASS: video taxonomy tables self-consistent")


if __name__ == '__main__':
    test_one_way_video_p0()
    test_relay_redirect_not_one_way()
    test_corrupt_video()
    test_video_loss_with_rtcp()
    test_keyframe_and_pli_storm()
    test_clock_and_low_fps()
    test_frame_mode_excluded_from_audio()
    test_packet_loss_kind_routing()
    test_audio_only_call()
    test_report_gating()
    test_taxonomy_consistency()
    print("ALL TESTS PASSED")
