"""
声音问题分类测试：classify_problems 把各检测器结论聚合为
《声音问题种类》清单里的问题种类（含用户听感词、优先级、排查方向），
并接入 generate_report。

Run: python3 tests/test_problem_taxonomy.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzer.problem_taxonomy import classify_problems, TAXONOMY, UNOBSERVABLE
from analyzer.reporter import generate_report

BASE = {
    'direction': 'auto', 'media_type': 'audio', 'checks': {'delay': True, 'quality': True},
    'num_captures': 1, 'capture_roles': {'seat': 'seat.pcap'},
    'audio_health': None, 'fs_relay': None, 'packet_loss': {}, 'rtcp': {},
    'audio_quality': {}, 'video_quality': {}, 'ts_continuity': {},
    'fs_delay': {}, 'jitter': {}, 'delay_chains': None,
}


def _find(problems, pid):
    return next((p for p in problems if p['id'] == pid), None)


def test_one_way_audio_p0():
    """无声诊断 blocked → 单通 P0，听感词与排查方向齐备。"""
    results = {**BASE, 'audio_health': {
        'available': True, 'p2p': False,
        'directions': [{'label': '主叫 → 被叫', 'speaker': '主叫', 'listener': '被叫',
                        'verdict': 'blocked',
                        'verdict_text': '链路断裂，声音没有传到听者',
                        'legs': []}],
        'summary': '主叫 → 被叫：链路断裂'}}
    out = classify_problems(results)
    p = _find(out['problems'], 'one_way_audio')
    assert p, out
    assert p['priority'] == 'P0' and p['severity'] == 'critical', p
    assert '我听不到对方' in p['feel'] and '对方听不到我' in p['feel'], p['feel']
    assert p['category'] == '无声 / 连通'
    assert any('主叫 → 被叫' in e for e in p['evidence']), p['evidence']
    assert p['causes'] and p['verify'], p
    # P0 应排在最前
    assert out['problems'][0]['id'] == 'one_way_audio'
    print("PASS: one-way audio classified as P0 with feel words")


def test_loss_evidence_merged():
    """丢包被序号缺口、RTCP RR 同时命中 → 合并为同一类问题的多条证据。"""
    results = {**BASE,
               'packet_loss': {'0x11111111': {
                   'label': 'seat (SSRC=0x11111111)', 'total_packets': 1000,
                   'total_lost': 50, 'loss_rate_pct': 5.0, 'reorder_count': 0,
                   'is_clean': False}},
               'rtcp': {'seat (SSRC=0x11111111)': {
                   'rr': {'fraction_lost_pct': 5.0, 'cum_lost': 50}}}}
    out = classify_problems(results)
    p = _find(out['problems'], 'loss_artifact')
    assert p, out
    assert p['priority'] == 'P1' and p['severity'] == 'critical', p
    assert len(p['evidence']) == 2, p['evidence']
    assert '丢包检测' in p['sources'] and 'RTCP' in p['sources'], p['sources']
    assert '电音' in p['feel'] and '机关枪声' in p['feel'], p['feel']
    print("PASS: loss evidence merged from packet loss + RTCP RR")


def test_quality_kinds_mapped():
    """音画质量各 issue kind 归到对应问题种类，正常项 rtp_ok 不进分类。"""
    label = 'seat (SSRC=0x22222222)'
    results = {**BASE, 'audio_quality': {label: {
        'decodable': True, 'codec': 'G.711 PCMU',
        'rtp_integrity': {'ts_backward': 0, 'ts_duplicate': 0},
        'issues': [
            {'kind': 'howling', 'severity': 'critical', 'message': '检测到啸叫 2 处'},
            {'kind': 'clipping', 'severity': 'warning', 'message': '检测到波形削波 3 处'},
            {'kind': 'noise', 'severity': 'warning', 'message': '静音段底噪约 -42 dBFS，偏高'},
            {'kind': 'low_level', 'severity': 'info', 'message': '话音平均电平仅 -31 dBFS，偏低'},
            {'kind': 'rtp_ok', 'severity': 'info', 'message': 'RTP 序号连续正向'},
        ]}}}
    out = classify_problems(results)
    ids = {p['id'] for p in out['problems']}
    assert {'howling', 'clipping', 'noise_floor', 'low_volume', 'narrowband'} <= ids, ids
    assert 'loss_artifact' not in ids, ids
    howl = _find(out['problems'], 'howling')
    assert howl['priority'] == 'P1' and howl['category'] == '回声 / 设备', howl
    assert any('啸叫 2 处' in e for e in howl['evidence'])
    clip = _find(out['problems'], 'clipping')
    assert '破音' in clip['feel'] and clip['category'] == '失真', clip
    # 窄带编码提示是 info 级，不改变排序在前的问题
    nb = _find(out['problems'], 'narrowband')
    assert nb and nb['severity'] == 'info' and any('发闷' in f for f in nb['feel']), nb
    print("PASS: quality issue kinds mapped to taxonomy problems")


def test_ts_and_clock():
    """时间戳跳变 → 断音/内容缺失；倒退 → 时钟异常变调。"""
    label = 'fs (SSRC=0x33333333)'
    results = {**BASE, 'ts_continuity': {label: {
        'packet_count': 500, 'pt': 0, 'clock_rate': 8000, 'mode': 'packet',
        'event_count': 12, 'jump_count': 10, 'backward_count': 2,
        'reorder_count': 0, 'duplicate_count': 0, 'wrap_count': 0,
        'total_media_gap_ms': 640, 'events': []}}}
    out = classify_problems(results)
    drop = _find(out['problems'], 'dropouts')
    assert drop, out
    assert drop['priority'] == 'P1' and drop['severity'] == 'critical', drop
    assert any('640' in e or '0.6' in e for e in drop['evidence']), drop['evidence']
    clock = _find(out['problems'], 'clock_anomaly')
    assert clock and any('变调' in f for f in clock['feel']) \
        and clock['severity'] == 'critical', clock
    print("PASS: ts jumps -> dropouts, ts backward -> clock anomaly")


def test_latency_and_jitter():
    """FS 延迟偏高 + 抖动大 → 延迟/抖动类问题（严重度取最高）。"""
    results = {**BASE,
               'fs_delay': {'count': 100, 'mean': 65.0, 'p95': 120.0, 'p50': 60.0,
                            'p99': 200.0, 'max': 250.0, 'std': 10.0,
                            'outliers_50ms': 5, 'outliers_100ms': 2},
               'jitter': {'seat (SSRC=0x44444444)': {
                   'mean': 20.0, 'median': 20.0, 'std': 15.0, 'p95': 40.0,
                   'abnormal_count': 3, 'expected_interval': 20}}}
    out = classify_problems(results)
    lat = _find(out['problems'], 'latency')
    assert lat, out
    assert lat['severity'] == 'critical' and lat['priority'] == 'P1', lat
    assert len(lat['evidence']) == 2, lat['evidence']
    assert '延迟大' in lat['feel'], lat['feel']
    print("PASS: fs delay + jitter folded into latency problem")


def test_clean_and_unobservable():
    """干净流 → 无问题条目；unobservable 恒在且带人工验证方法。"""
    results = {**BASE, 'audio_quality': {'seat (SSRC=0x55555555)': {
        'decodable': True, 'codec': 'G.711 PCMU',
        'rtp_integrity': {'ts_backward': 0, 'ts_duplicate': 0},
        'issues': []}}}
    out = classify_problems(results)
    assert out['available'], out
    # 干净的 G.711 流只剩 info 级"窄带编码特性说明"，不算问题
    assert not [p for p in out['problems'] if p['severity'] != 'info'], out['problems']
    assert '未发现可归类' in out['summary'], out['summary']
    assert len(out['unobservable']) == len(UNOBSERVABLE) > 0
    wind = next(u for u in out['unobservable'] if u['name'] == '风噪')
    assert wind['verify'], wind
    assert any('抓包' in n for n in out['notes']), out['notes']
    print("PASS: clean stream -> no problems, unobservable list always present")


def test_video_only_scope():
    """仅分析视频流时分类不可用，并给出说明。"""
    results = {**BASE, 'media_type': 'video'}
    out = classify_problems(results)
    assert not out['available'] and out['problems'] == [], out
    assert any('视频' in n for n in out['notes']), out['notes']
    print("PASS: video-only scope disables audio classification")


def test_report_wiring():
    """generate_report 按 media_type 门控：audio 只出声音分类；all 两类都出
    （视频类恒有键，纯音频通话时 available=False 而不是缺键）。"""
    results = {**BASE, 'audio_health': {
        'available': True, 'p2p': False,
        'directions': [{'label': '被叫 → 主叫', 'speaker': '被叫', 'listener': '主叫',
                        'verdict': 'silent_source',
                        'verdict_text': '发声端上行有人声能量但整段近乎静音',
                        'legs': []}],
        'summary': '被叫 → 主叫：发声端静音'}}
    report = generate_report(results)
    pc = report['problem_classification']
    assert pc['available'], pc
    p = _find(pc['problems'], 'one_way_audio')
    assert p and p['priority'] == 'P0', pc
    assert 'video_problem_classification' not in report, report.keys()
    report_all = generate_report({**results, 'media_type': 'all'})
    assert 'problem_classification' in report_all, report_all.keys()
    vpc = report_all['video_problem_classification']
    assert vpc['available'] is False and vpc['problems'] == [], vpc
    print("PASS: problem_classification wired & gated by media_type")


def test_video_evidence_not_in_audio():
    """视频流证据（丢包 / RTCP kind=video）不串进声音分类。"""
    results = {**BASE, 'media_type': 'all',
               'classified_streams': {
                   'audio': {0x11111111: {'pt': [0], 'count': 500}},
                   'video': {0x22222222: {'pt': [96], 'count': 3000}}},
               'packet_loss': {'0x22222222': {
                   'label': 'fs (SSRC=0x22222222)', 'total_packets': 3000,
                   'total_lost': 90, 'loss_rate_pct': 3.0, 'reorder_count': 0,
                   'is_clean': False}},
               'rtcp': {'fs (SSRC=0x22222222)': {
                   'kind': 'video',
                   'rr': {'fraction_lost_pct': 5.0, 'cum_lost': 90}}}}
    out = classify_problems(results)
    loss = _find(out['problems'], 'loss_artifact')
    assert not loss, out['problems']
    assert not out['problems'], out['problems']
    print("PASS: video-kind evidence excluded from audio classification")


def test_streams_and_directions_attribution():
    """问题条目带 streams/directions 归属：流级证据挂流、方向级证据挂方向、
    全局证据（fs_delay）两者皆空——前端据此把问题挂到对应流卡片下。"""
    results = {**BASE,
               'audio_health': {
                   'available': True, 'p2p': False,
                   'directions': [{'label': '主叫 → 被叫', 'speaker': '主叫',
                                   'listener': '被叫', 'verdict': 'blocked',
                                   'verdict_text': '链路断裂', 'legs': []}],
                   'summary': ''},
               'packet_loss': {'0x11111111': {
                   'label': 'seat (SSRC=0x11111111)', 'total_packets': 1000,
                   'total_lost': 50, 'loss_rate_pct': 5.0, 'reorder_count': 0,
                   'is_clean': False}},
               'audio_quality': {'terminal (SSRC=0x22222222)': {
                   'verdict': 'bad', 'codec': 'PCMU', 'decodable': True,
                   'tones': {}, 'clipping': {}, 'clicks': {},
                   'rtp_integrity': {'ts_backward': 3},
                   'issues': [{'kind': 'howling', 'severity': 'critical',
                               'message': '啸叫 2 处'}]}},
               'fs_delay': {'count': 100, 'mean': 80.0, 'p95': 120.0}}
    out = classify_problems(results)
    loss = _find(out['problems'], 'loss_artifact')
    assert loss and loss['streams'] == ['seat (SSRC=0x11111111)'], loss
    assert not loss['directions'], loss
    howl = _find(out['problems'], 'howling')
    assert howl and howl['streams'] == ['terminal (SSRC=0x22222222)'], howl
    one_way = _find(out['problems'], 'one_way_audio')
    assert one_way and one_way['directions'] == ['主叫 → 被叫'], one_way
    assert not one_way['streams'], one_way
    latency = _find(out['problems'], 'latency')
    assert latency and not latency['streams'] and not latency['directions'], latency
    print("PASS: problems carry stream/direction attribution")


def test_taxonomy_consistency():
    """分类表本身的自洽：id 唯一、优先级合法、听感词/描述/验证方法非空。"""
    assert len(TAXONOMY) == len(set(TAXONOMY))
    for pid, spec in TAXONOMY.items():
        assert spec['priority'] in ('P0', 'P1', 'P2', 'P3'), pid
        assert spec['feel'] and spec['description'] and spec['causes'] and spec['verify'], pid
    for u in UNOBSERVABLE:
        assert u['feel'] and u['why'] and u['verify'], u
    print("PASS: taxonomy tables self-consistent")


if __name__ == '__main__':
    test_one_way_audio_p0()
    test_loss_evidence_merged()
    test_quality_kinds_mapped()
    test_ts_and_clock()
    test_latency_and_jitter()
    test_clean_and_unobservable()
    test_video_only_scope()
    test_report_wiring()
    test_video_evidence_not_in_audio()
    test_streams_and_directions_attribution()
    test_taxonomy_consistency()
    print("ALL TESTS PASSED")
