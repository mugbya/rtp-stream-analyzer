"""
Unit tests for silence/energy analysis, RTCP SR/RR parsing, no-sound
direction diagnosis, segmented delay chains, and their report wiring.

Run: python3 tests/test_silence_rtcp_chains.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import audioop
import numpy as np

from analyzer.silence_analyzer import analyze_silence, diagnose_audio
from analyzer.rtcp_parser import parse_rtcp, summarize_rtcp
from analyzer.delay_chains import build_delay_chains
from analyzer.reporter import generate_report

# 合成拓扑：FS 10.0.0.1，主叫(terminal) 10.0.0.2，坐席(seat) 10.0.0.3
A, B, C, D = 0x01010101, 0x02020202, 0x03030303, 0x04040404
SRV, CALLER, SEAT = '10.0.0.1', '10.0.0.2', '10.0.0.3'


def _frag(level, n=160):
    return struct.pack(f'<{n}h', *([level] * n))


def make_packets(ssrc, items):
    """items: [(seq, ts, pt, payload)] -> extract_rtp_packets 风格 packets。"""
    packets = {}
    for i, (seq, ts, pt, payload) in enumerate(items):
        packets[(ssrc, seq)] = (i * 0.02, ts, pt, 8, 8, 8, 8, payload)
    return packets


# 默认电平：音节级起伏的话音样式（每 5 包=100ms 换一档）。
# 恒定电平会被语音活动判定归为"持续背景电平"（平稳包络不是人声），
# 构造"有人声"的用例必须带起伏。
VOICE_BLOCKS = (13000, 2500, 11000, 2000, 9000, 3000)


def _voice_levels(n):
    return [VOICE_BLOCKS[i // 5 % len(VOICE_BLOCKS)] for i in range(n)]


def ulaw_items(n=100, levels=None, pt=0, ts0=1000, spp=160):
    if levels is None:
        levels = _voice_levels(n)
    items, ts = [], ts0
    for i in range(n):
        items.append((i, ts, pt, audioop.lin2ulaw(_frag(levels[i]), 2)))
        ts += spp
    return items


def stream_meta(ssrc, count, src, dst, pts=(0,)):
    return {ssrc: {'count': count, 'pt': list(pts),
                   'port_pairs': [(src, 10000, dst, 20000)]}}


# ---------- analyze_silence ----------

def test_analyze_silence_normal():
    """全程有声：normal、占比 1.0、无数字零包。"""
    r = analyze_silence(make_packets(A, ulaw_items()), A)
    assert r['verdict'] == 'normal' and r['decodable'], r
    assert r['active_ratio'] == 1.0 and r['zero_packets'] == 0, r
    assert r['mean_active_dbfs'] > -30 and r['peak_dbfs'] > -30, r
    assert r['media_ms'] == 2000.0, r
    print("PASS: analyze_silence normal stream")


def test_analyze_silence_digital_silence():
    """数字静音（载荷全零）：silent、zero_packets=全部、first_active=None。"""
    r = analyze_silence(make_packets(B, ulaw_items(levels=[0] * 100)), B)
    assert r['verdict'] == 'silent' and r['zero_packets'] == 100, r
    assert r['first_active_s'] is None and r['mean_active_dbfs'] is None, r
    print("PASS: analyze_silence digital silence")


def test_analyze_silence_dtx_gap_counts_as_silent_media_time():
    """DTX 缺口：未发包的 1 秒计入静音媒体时间（时间加权而非包数加权）。"""
    levels = _voice_levels(50) + [0] * 50
    items, ts = [], 1000
    for i in range(100):
        if i == 50:
            ts += 8000                      # 1 秒 DTX：seq 连续、ts 跳过 1s
        items.append((i, ts, 0, audioop.lin2ulaw(_frag(levels[i]), 2)))
        ts += 160
    r = analyze_silence(make_packets(C, items), C)
    assert r['verdict'] == 'normal', r
    assert abs(r['speech_ms'] - 1000.0) < 1, r
    assert abs(r['media_ms'] - 3000.0) < 1, r   # 100 包×20ms + 1000ms DTX
    assert abs(r['active_ratio'] - 1000.0 / 3000.0) < 0.01, r
    print("PASS: analyze_silence DTX gap = silent media time")


def test_analyze_silence_prompt_tone_excluded():
    """开头 1.5s 的 450Hz 回铃音 + 之后全程静音：提示音不算人声，
    verdict silent，tone_ms 记录提示音时长——"一声嘟后无声"别判成有人声。"""
    sr = 8000
    t = np.arange(int(1.5 * sr)) / sr
    tone = (6000 * np.sin(2 * np.pi * 450 * t)).astype(np.int16)
    items, ts = [], 1000
    for i in range(0, len(tone) - 160 + 1, 160):
        items.append((len(items), ts, 0,
                      audioop.lin2ulaw(tone[i:i + 160].tobytes(), 2)))
        ts += 160
    # seq 接着提示音包继续编（同流 seq 重复会被当作同一个包覆盖掉）
    items += [(len(items) + i, zts, pt, payload)
              for i, (_, zts, pt, payload) in enumerate(
                  ulaw_items(n=925, levels=[0] * 925, ts0=ts))]
    r = analyze_silence(make_packets(A, items), A)
    assert r['verdict'] == 'silent', r
    assert r['active_ratio'] == 0.0, r
    assert r['tone_ms'] >= 1200, r
    assert r['first_active_s'] is None, r
    print("PASS: analyze_silence prompt tone excluded from voice time")


def test_analyze_silence_steady_energy_not_voice():
    """持续背景电平（供电干扰/环境噪声）不是人声：判 silent 并记录电平。

    设备故障时会把平稳电平整通发过来，包能量过门限但包络无起伏——
    不能因为"有声占比高"就判成有人声（qigndao2 主叫上行 78% 有声实为
    50Hz 工频嗡声+底噪）。"""
    r = analyze_silence(make_packets(A, ulaw_items(levels=[8000] * 100)), A)
    assert r['verdict'] == 'silent' and r['speech_activity'] is False, r
    assert r['active_ratio'] == 0.0 and r['first_active_s'] is None, r
    assert r['steady_energy_ms'] == 2000.0, r
    assert abs(r['steady_dbfs'] + 12.2) < 1, r   # 8000 → 约 -12.2 dBFS
    print("PASS: analyze_silence steady background level is not voice")


def test_analyze_silence_voice_inside_background():
    """背景电平之上的人声时刻必须检出，不能整段吞成背景电平。

    对应真实抓包形态（qigndao2 FS→被叫）：工频嗡声/底噪垫底，中间
    短暂出现过人声——整段包络 cv 不高，但突发明显高于背景电平。"""
    levels = [600] * 1500
    for a in (200, 700):                    # 两次 240ms 的人声突发（2~3×背景）
        for j in range(12):
            levels[a + j] = 1800 if j % 2 else 1200
    r = analyze_silence(make_packets(A, ulaw_items(n=1500, levels=levels)), A)
    assert r['speech_activity'] is True, r
    assert r['verdict'] == 'sparse' and r['speech_ms'] >= 300, r
    assert r['steady_energy_ms'] >= 3000, r     # 其余活跃时间是背景电平
    assert r['first_active_s'] is not None, r
    print("PASS: analyze_silence voice moments inside background detected")


def test_analyze_silence_undecodable():
    """不可解编码（动态 PT）：unknown，不做能量判定。"""
    r = analyze_silence(make_packets(0x09999999, ulaw_items(n=10, pt=96)),
                        0x09999999)
    assert r['verdict'] == 'unknown' and not r['decodable'], r
    print("PASS: analyze_silence undecodable codec")


# ---------- RTCP ----------

def test_parse_rtcp_sr_rr():
    """手工构造 SR+RR 复合包：字段逐项核对。"""
    sr = struct.pack('!BBH', 0x80, 200, 6) + struct.pack(
        '!IIIIII', 0x01010101, 4000000000, 0x40000000, 123456, 1000, 160000)
    # RR：sender 0x05050505 报告流 0x02020202（丢包 26/255≈10.2%，累计 1000）
    rr = struct.pack('!BBH', 0x81, 201, 7) + struct.pack('!I', 0x05050505) \
        + struct.pack('!I', 0x02020202) \
        + struct.pack('!BBHIIII', 26, 0, 1000, 2000, 50, 12345, 4)
    pkts = parse_rtcp(sr + rr)
    assert len(pkts) == 2, pkts
    assert pkts[0]['kind'] == 'SR' and pkts[0]['ssrc'] == 0x01010101, pkts[0]
    assert pkts[0]['pkt_count'] == 1000 and pkts[0]['octet_count'] == 160000, pkts[0]
    assert pkts[0]['ntp_sec'] == 4000000000, pkts[0]
    assert pkts[1]['kind'] == 'RR' and pkts[1]['ssrc'] == 0x05050505, pkts[1]
    assert len(pkts[1]['reports']) == 1, pkts[1]
    rep = pkts[1]['reports'][0]
    assert rep['ssrc'] == 0x02020202, rep
    assert rep['fraction_lost_pct'] == round(26 / 255 * 100, 1), rep
    assert rep['cum_lost'] == 1000 and rep['jitter'] == 50, rep
    assert rep['lsr'] == 12345 and rep['dlsr'] == 4, rep
    # 非 RTCP（version!=2）返回空
    assert parse_rtcp(b'\x00' * 32) == []
    print("PASS: parse_rtcp SR/RR fields")


def test_summarize_rtcp_latest_stats_and_reporters():
    """统计值取最新一次上报；reporters 累积所有上报方。"""
    summ = summarize_rtcp({'rtcp_events': [
        {'kind': 'SR', 'ssrc': A, 'time': 1.0, 'pkt_count': 100,
         'octet_count': 16000, 'rtp_ts': 1000, 'ntp_sec': 4000000000,
         'ntp_frac': 0x40000000},
        {'kind': 'RR', 'ssrc': 0x05050505, 'time': 2.0, 'reports': [
            {'ssrc': B, 'fraction_lost_pct': 5.1, 'cum_lost': 10,
             'jitter': 3, 'lsr': 1, 'dlsr': 1}]},
        {'kind': 'RR', 'ssrc': 0x06060606, 'time': 3.0, 'reports': [
            {'ssrc': B, 'fraction_lost_pct': 1.0, 'cum_lost': 12,
             'jitter': 4, 'lsr': 2, 'dlsr': 1}]},
    ]})
    assert summ['sr'][A]['count'] == 1 and summ['sr'][A]['pkt_count'] == 100, summ
    # rr 按被报告的流 SSRC 索引
    assert summ['rr'][B]['count'] == 2, summ
    assert summ['rr'][B]['fraction_lost_pct'] == 1.0, summ   # 最新一次
    assert set(summ['rr'][B]['reporters']) == {0x05050505, 0x06060606}, summ
    print("PASS: summarize_rtcp latest stats + reporters")


# ---------- 无声诊断 ----------

def _diag_captures(b_stream_level=0):
    """FS 场景：A=主叫上行、B=FS→坐席（电平可设）、C=坐席上行、D=FS→主叫。

    b_stream_level=0 → 数字静音；>0 → 话音样式（平稳电平会被语音活动
    判定归为背景电平，不能代表"有人声"）。"""
    b_items = ulaw_items(levels=_voice_levels(100) if b_stream_level
                         else [0] * 100)
    term_cap = {'_role': 'terminal',
                'streams': {**stream_meta(A, 100, CALLER, SRV),
                            **stream_meta(D, 100, SRV, CALLER)}}
    seat_cap = {'_role': 'seat',
                'streams': {**stream_meta(B, 100, SRV, SEAT),
                            **stream_meta(C, 100, SEAT, SRV)}}
    fs_cap = {'_role': 'fs',
              'streams': {**stream_meta(A, 100, CALLER, SRV),
                          **stream_meta(B, 100, SRV, SEAT),
                          **stream_meta(C, 100, SEAT, SRV),
                          **stream_meta(D, 100, SRV, CALLER)}}
    profiles = {
        ('terminal', A): analyze_silence(make_packets(A, ulaw_items()), A),
        ('fs', B): analyze_silence(make_packets(B, b_items), B),
        ('seat', B): analyze_silence(make_packets(B, b_items), B),
        ('seat', C): analyze_silence(make_packets(C, ulaw_items()), C),
        ('fs', C): analyze_silence(make_packets(C, ulaw_items()), C),
        ('fs', A): analyze_silence(make_packets(A, ulaw_items()), A),
        ('fs', D): analyze_silence(make_packets(D, ulaw_items()), D),
        ('terminal', D): analyze_silence(make_packets(D, ulaw_items()), D),
    }
    return {'terminal': term_cap, 'seat': seat_cap, 'fs': fs_cap}, profiles


def test_diagnose_silent_path_and_blocked():
    """主叫→坐席 FS 转出静音 → silent_path；坐席→主叫 FS 未转发 → blocked。"""
    caps, profiles = _diag_captures(b_stream_level=0)
    # 再模拟 FS 未桥接下行：去掉 D 流（FS 与主叫端都抓不到）
    caps['fs']['streams'].pop(D, None)
    caps['terminal']['streams'].pop(D, None)
    profiles.pop(('fs', D))
    profiles.pop(('terminal', D))
    res = diagnose_audio(caps, {'ssrcs': [A, B, C, D], 'is_p2p': False},
                         SRV, profiles, {},
                         {'caller_ip': CALLER, 'answerer_ip': SEAT})
    assert res['available'] and len(res['directions']) == 2, res
    d0, d1 = res['directions']
    assert d0['verdict'] == 'silent_path', d0
    assert d0['legs'][0]['status'] == 'ok', d0           # 主叫上行正常
    assert d0['legs'][1]['status'] == 'silent_path', d0  # FS→坐席腿静音
    assert d1['verdict'] == 'blocked', d1
    assert d1['legs'][0]['status'] == 'ok', d1
    assert d1['legs'][1]['status'] == 'no_source', d1    # FS 未见对应下行流
    assert '断裂点' in d1['verdict_text'], d1
    print("PASS: diagnose silent_path + blocked(FS not forwarding)")


def test_diagnose_all_normal():
    """两条腿都有人声：两方向 ok，summary 为正常文案。"""
    caps, profiles = _diag_captures(b_stream_level=8000)
    res = diagnose_audio(caps, {'ssrcs': [A, B, C, D], 'is_p2p': False},
                         SRV, profiles, {},
                         {'caller_ip': CALLER, 'answerer_ip': SEAT})
    assert res['available'], res
    assert all(d['verdict'] == 'ok' for d in res['directions']), res
    assert '均正常' in res['summary'], res
    print("PASS: diagnose all-normal directions")


def test_diagnose_no_source_when_source_capture_present():
    """主叫端抓包在场但整通无主叫流：上行腿 no_source → 方向 no_source。"""
    caps, profiles = _diag_captures(b_stream_level=8000)
    # 主叫没发：terminal 抓包存在但没有 A；FS 抓包也去掉 A
    caps['terminal']['streams'] = {}
    caps['fs']['streams'].pop(A, None)
    res = diagnose_audio(caps, {'ssrcs': [A, B, C, D], 'is_p2p': False},
                         SRV, profiles, {},
                         {'caller_ip': CALLER, 'answerer_ip': SEAT})
    d0 = res['directions'][0]
    assert d0['label'] == '主叫 → 被叫', res['directions']
    assert d0['verdict'] == 'no_source', d0
    assert d0['legs'][0]['status'] == 'no_source', d0
    print("PASS: diagnose no_source with source capture present")


def test_diagnose_one_sided_profile_no_crash():
    """下行流只在听者抓包有（FS 抓包缺该流/画像）：单侧画像不崩，判 ok。"""
    caps, profiles = _diag_captures(b_stream_level=8000)
    # 模拟 FS 抓包时段缺口：FS 侧没有 B 流也没有 B 画像，坐席侧齐全
    caps['fs']['streams'].pop(B, None)
    profiles.pop(('fs', B))
    res = diagnose_audio(caps, {'ssrcs': [A, B, C, D], 'is_p2p': False},
                         SRV, profiles, {},
                         {'caller_ip': CALLER, 'answerer_ip': SEAT})
    d0 = res['directions'][0]
    assert d0['verdict'] == 'ok', d0
    dn = d0['legs'][1]
    assert dn['presence'] == {'sent_at_source': False,
                              'arrived_at_next': True}, dn
    assert '被叫侧实测有人声' in dn['note'], dn
    assert '源端抓包未见发出' in dn['note'], dn
    print("PASS: diagnose one-sided profile (listener capture only)")


# ---------- 分段延迟链路 ----------

N = 100
PROP, FS_PROC = 0.010, 0.020            # 单向传播 10ms、FS 内部 20ms
OFF_TERM, OFF_FS, OFF_SEAT = 0.0, 0.2, 0.1   # 三台抓包机时钟偏移


def _chain_captures():
    """构造已知真值的 FS 场景抓包（传播 10ms/FS 内部 20ms/时钟差 0.2s/0.1s）。"""
    t_send = [i * 0.02 for i in range(N)]
    t_at_fs_in = [t + PROP for t in t_send]
    t_at_fs_out = [t + PROP + FS_PROC for t in t_send]
    t_at_peer = [t + 2 * PROP + FS_PROC for t in t_send]

    def times(off, ts):
        return {i: t + off for i, t in enumerate(ts)}

    def build(streams):
        pk = {}
        for ssrc, tm in streams.items():
            for seq, t in tm.items():
                pk[(ssrc, seq)] = (t, seq * 160, 0, 0, 0, 0, 0, b'')
        return pk

    def meta(entries):
        return {ssrc: {'count': N, 'pt': [0], 'port_pairs': [pp]}
                for ssrc, pp in entries.items()}

    term_cap = {'_role': 'terminal',
                'packets': build({A: times(OFF_TERM, t_send),
                                  D: times(OFF_TERM, t_at_peer)}),
                'streams': meta({A: (CALLER, 10000, SRV, 20000),
                                 D: (SRV, 20002, CALLER, 30000)})}
    fs_cap = {'_role': 'fs',
              'packets': build({A: times(OFF_FS, t_at_fs_in),
                                C: times(OFF_FS, t_at_fs_in),
                                B: times(OFF_FS, t_at_fs_out),
                                D: times(OFF_FS, t_at_fs_out)}),
              'streams': meta({A: (CALLER, 10000, SRV, 20000),
                               B: (SRV, 20004, SEAT, 30002),
                               C: (SEAT, 30002, SRV, 20004),
                               D: (SRV, 20002, CALLER, 30000)})}
    seat_cap = {'_role': 'seat',
                'packets': build({B: times(OFF_SEAT, t_at_peer),
                                  C: times(OFF_SEAT, t_send)}),
                'streams': meta({B: (SRV, 20004, SEAT, 30002),
                                 C: (SEAT, 30002, SRV, 20004)})}
    return {'terminal': term_cap, 'seat': seat_cap, 'fs': fs_cap}


def test_delay_chains_segments_and_roundtrip():
    """分段测量 + 往返和抵消时钟差：往返 = 真实 20ms。"""
    res = build_delay_chains(_chain_captures(),
                             {'ssrcs': [A, B, C, D], 'is_p2p': False}, SRV,
                             {'caller_ip': CALLER, 'answerer_ip': SEAT})
    assert res['available'] and not res['p2p'], res
    d0, d1 = res['directions']
    assert d0['label'] == '主叫 → 被叫' and d1['label'] == '被叫 → 主叫', d0
    s_up, s_fs, s_down = d0['segments']
    # 跨抓包：均值=传播+时钟差；恒定时延被中位数吸收进偏移（无法区分）
    assert abs(s_up['mean'] - 210.0) < 1.0 and s_up['available'], s_up
    assert abs(s_up['clock_offset_ms'] - 210.0) < 1.0, s_up
    assert s_fs['kind'] == 'fs_internal' and s_fs['available'], s_fs
    assert s_fs['ssrc'] == '0x01010101 → 0x02020202', s_fs
    assert abs(s_down['mean'] - (-90.0)) < 1.0, s_down
    assert d0['verdict'] == 'ok' and d1['verdict'] == 'ok', (d0, d1)
    # 往返参考值：时钟偏移两两抵消，等于真实往返（10+10=20ms）
    rt = {r['pair']: r for r in res['roundtrip']}
    assert abs(rt['主叫端往返（主叫→FS→主叫）']['ms'] - 20.0) < 1.0, rt
    assert abs(rt['被叫端往返（被叫→FS→被叫）']['ms'] - 20.0) < 1.0, rt
    assert all(r['status'] == 'ok' for r in res['roundtrip']), rt
    print("PASS: delay chains segments + offset-free roundtrip")


def test_delay_chains_degraded_without_endpoint_capture():
    """只有 FS 抓包：FS 内部段可测，跨抓包段不可测 → partial。"""
    res = build_delay_chains({'fs': _chain_captures()['fs']},
                             {'ssrcs': [A, B, C, D], 'is_p2p': False}, SRV,
                             {'caller_ip': CALLER, 'answerer_ip': SEAT})
    d = res['directions'][0]
    assert not d['segments'][0]['available'], d
    assert d['segments'][1]['available'], d
    assert d['verdict'] == 'partial', d
    print("PASS: delay chains degrade without endpoint captures")


def test_delay_chains_p2p():
    """p2p 直连：只有一段，两端同 SSRC 匹配。"""
    t_send = [i * 0.02 for i in range(N)]
    pk = {**{(A, i): (t + OFF_TERM, i * 160, 0, 0, 0, 0, 0, b'')
             for i, t in enumerate(t_send)},
          **{(A, i + 1000): (t + OFF_SEAT, i * 160, 0, 0, 0, 0, 0, b'')
             for i, t in enumerate(t_send)}}
    # 同一 (ssrc, seq) 只能有一条记录，改成两端各自独立 seq 空间不行——
    # 跨抓包匹配靠同 seq；这里直接给两份独立 packets
    term = {'_role': 'terminal',
            'packets': {(A, i): (t + OFF_TERM, i * 160, 0, 0, 0, 0, 0, b'')
                        for i, t in enumerate(t_send)},
            'streams': {A: {'count': N, 'pt': [0],
                            'port_pairs': [(CALLER, 10000, SEAT, 20000)]}}}
    seat = {'_role': 'seat',
            'packets': {(A, i): (t + OFF_SEAT, i * 160, 0, 0, 0, 0, 0, b'')
                        for i, t in enumerate(t_send)},
            'streams': {A: {'count': N, 'pt': [0],
                            'port_pairs': [(CALLER, 10000, SEAT, 20000)]}}}
    res = build_delay_chains({'terminal': term, 'seat': seat},
                             {'ssrcs': [A], 'is_p2p': True}, SRV, {})
    assert res['p2p'] and len(res['directions']) == 2, res
    d = res['directions'][0]
    assert d['verdict'] == 'ok' and len(d['segments']) == 1, d
    assert abs(d['segments'][0]['mean'] - 100.0) < 1.0, d   # 0 传播 + 100ms 偏移
    print("PASS: delay chains p2p single segment")


# ---------- 报告接线 ----------

def test_report_new_sections_and_conclusion():
    """新段落进入报告；结论按严重度出 issue；旧式 results 不受影响。"""
    audio_health = {
        'available': True, 'p2p': False,
        'directions': [
            {'label': '主叫 → 被叫', 'speaker': '主叫', 'listener': '被叫',
             'verdict': 'silent_path',
             'verdict_text': '听者收到的是静音：链路中某一段把人声换成了静音',
             'legs': [{'leg': '主叫上行', 'ssrc': '0x01010101', 'status': 'ok',
                       'presence': {'sent_at_source': True,
                                    'arrived_at_next': True},
                       'profiles': [], 'rr': None, 'note': '正常'}]},
        ],
        'summary': '主叫 → 被叫：静音',
    }
    delay_chains = {
        'available': True, 'p2p': False,
        'directions': [
            {'label': '主叫 → 被叫', 'verdict': 'high',
             'verdict_text': '以下段延迟/波动偏高：主叫 → FS',
             'segments': [{'kind': 'cross', 'name': '主叫 → FS',
                           'ssrc': '0x01010101', 'available': True,
                           'count': 50, 'mean': 210.0, 'p50': 210.0,
                           'p95': 260.0, 'clock_offset_ms': 200.0,
                           'detrended_p95': 55.0, 'status': 'ok', 'note': 'ok'}],
             'total_mean': 210.0, 'total_note': '含时钟偏移'}],
        'roundtrip': [{'pair': '主叫端往返（主叫→FS→主叫）', 'ms': 420.0,
                       'status': 'high', 'note': '往返'}],
        'notes': ['注1'],
    }
    results = {
        'audio_health': audio_health,
        'delay_chains': delay_chains,
        'rtcp': {'fs (SSRC=0x01010101)': {
            'sr': {'count': 5, 'last_time': 9.0, 'pkt_count': 500,
                   'octet_count': 80000, 'rtp_ts': 80000,
                   'ntp_sec': 4000000000, 'ntp_frac': 0},
            'rr': {'count': 3, 'last_time': 9.0, 'fraction_lost_pct': 5.1,
                   'cum_lost': 25, 'jitter': 2.0, 'reporters': [0x05050505]}},
        },
    }
    report = generate_report(results)
    assert report['audio_health']['available'] is True, report['audio_health']
    assert report['delay_chains']['roundtrip'][0]['ms'] == 420.0
    assert report['rtcp']['fs (SSRC=0x01010101)']['rr']['cum_lost'] == 25
    issues = report['conclusion']['issues']
    sev = {i['severity'] for i in issues}
    assert 'critical' in sev and 'warning' in sev, sev   # 静音=critical、延迟=warning
    assert any(i['message'].startswith('无声诊断·主叫 → 被叫') for i in issues), issues
    assert any('延迟链路·主叫 → 被叫' in i['message'] for i in issues), issues
    assert any('往返 420.0ms' in i['message'] for i in issues), issues
    assert any('RTCP RR 自报丢包 5.1%' in i['message'] for i in issues), issues

    # 旧式 results（无新键）：段落为 None、无 RTCP 误报、结论正常生成
    old = generate_report({'jitter': {}})
    assert old['audio_health'] is None and old['delay_chains'] is None
    assert old['rtcp'] is None
    assert not any('RTCP' in i['message'] for i in old['conclusion']['issues'])
    print("PASS: report wiring for audio_health / delay_chains / rtcp")


if __name__ == '__main__':
    test_analyze_silence_normal()
    test_analyze_silence_digital_silence()
    test_analyze_silence_dtx_gap_counts_as_silent_media_time()
    test_analyze_silence_prompt_tone_excluded()
    test_analyze_silence_steady_energy_not_voice()
    test_analyze_silence_voice_inside_background()
    test_analyze_silence_undecodable()
    test_parse_rtcp_sr_rr()
    test_summarize_rtcp_latest_stats_and_reporters()
    test_diagnose_silent_path_and_blocked()
    test_diagnose_all_normal()
    test_diagnose_no_source_when_source_capture_present()
    test_diagnose_one_sided_profile_no_crash()
    test_delay_chains_segments_and_roundtrip()
    test_delay_chains_degraded_without_endpoint_capture()
    test_delay_chains_p2p()
    test_report_new_sections_and_conclusion()
    print("\n=== ALL SILENCE/RTCP/CHAINS TESTS PASSED ===")
