"""
Unit tests for call_detector: multi-call grouping and completeness states.

Run: python3 tests/test_call_detector.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzer.call_detector import (
    build_conversations, merge_conversations, group_calls,
    assess_call_completeness, detect_calls, check_capture_consistency,
)

SERVER = '10.0.0.1'
SEAT = '10.0.0.2'
TERM = '10.0.0.3'


def make_rtp_data(streams, capture_start, capture_end, sip_events=None):
    """Build a minimal rtp_data dict like extract_rtp_packets returns.

    streams: list of (ssrc, sport, dport, start, end, first_seq, src_ip, dst_ip, pt, pkt_interval)
    """
    packets = {}
    streams_meta = {}
    for (ssrc, sport, dport, start, end, first_seq, src_ip, dst_ip, pt, interval) in streams:
        n = int((end - start) / interval) + 1
        for i in range(n):
            t = start + i * interval
            seq = (first_seq + i) & 0xFFFF
            packets[(ssrc, seq)] = (t, i * 160, pt, src_ip, dst_ip, sport, dport)
        streams_meta[ssrc] = {'count': n, 'pt': [pt],
                              'ips': [[src_ip, dst_ip]],
                              'port_pairs': [[src_ip, sport, dst_ip, dport]]}
    return {
        'packets': packets,
        'total_count': len(packets),
        'ips': set(),
        'ssrcs': set(),
        'streams': streams_meta,
        'capture_start': capture_start,
        'capture_end': capture_end,
        'sip_events': sip_events or [],
    }


def test_two_sequential_calls():
    """FS capture with 2 sequential calls (no overlap) -> 2 calls."""
    # Call 1: t=100~160, call 2: t=300~360; capture 90~400
    streams = [
        # call1 seat leg: seat->fs (uplink) + fs->seat (downlink)
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
        # call1 terminal leg
        (0x1113, 7000, 8000, 100, 160, 0, TERM, SERVER, 0, 0.02),
        (0x1114, 8000, 7000, 100, 160, 0, SERVER, TERM, 0, 0.02),
        # call2 (new SSRCs, 60s later, port reuse on 6000/5000 would be fine too)
        (0x2221, 5100, 6100, 300, 360, 0, SEAT, SERVER, 8, 0.02),
        (0x2222, 6100, 5100, 300, 360, 0, SERVER, SEAT, 8, 0.02),
        (0x2223, 7100, 8100, 300, 360, 0, TERM, SERVER, 0, 0.02),
        (0x2224, 8100, 7100, 300, 360, 0, SERVER, TERM, 0, 0.02),
    ]
    rd = make_rtp_data(streams, 90, 400,
                       sip_events=[
                           {'time': 95, 'method': 'INVITE', 'call_id': 'a'},
                           {'time': 165, 'method': 'BYE', 'call_id': 'a'},
                           {'time': 295, 'method': 'INVITE', 'call_id': 'b'},
                           {'time': 365, 'method': 'BYE', 'call_id': 'b'},
                       ])
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 2, f"expected 2 calls, got {len(calls)}"
    assert calls[0]['start_str'] and calls[0]['stream_count'] == 4
    assert all(c['completeness']['status'] == 'complete' for c in calls)
    print("PASS: two sequential calls -> 2 calls, both complete")


def test_port_reuse_same_ports():
    """Same port pair reused by a later call (gap > 30s) -> 2 conversations."""
    streams = [
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x2221, 5000, 6000, 300, 360, 0, SEAT, SERVER, 8, 0.02),  # same ports!
    ]
    rd = make_rtp_data(streams, 90, 400)
    convs = build_conversations(rd, 'fs')
    assert len(convs) == 2, f"port reuse should split, got {len(convs)} conversations"
    print("PASS: port reuse splits into 2 conversations")


def test_truncated_head():
    """Capture starts mid-call: uplink first_seq large, no INVITE -> truncated_head."""
    # Call runs 0~120 but capture starts at 50; uplink stream already at seq 2500
    streams = [
        (0x1111, 5000, 6000, 50, 120, 2500, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 50, 120, 9999, SERVER, SEAT, 8, 0.02),
    ]
    # BYE at 125 (after capture? no—capture_end=130, BYE=125 within) -> tail ok
    rd = make_rtp_data(streams, 50, 130,
                       sip_events=[{'time': 125, 'method': 'BYE', 'call_id': 'x'}])
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 1
    pf = calls[0]['completeness']['per_file']['fs']
    assert pf['status'] == 'truncated_head', f"expected truncated_head, got {pf['status']}"
    assert any('seq' in r for r in pf['reasons'])
    print("PASS: truncated_head detected (uplink seq non-zero)")


def test_truncated_tail():
    """Call ends exactly at capture end, no BYE -> truncated_tail."""
    streams = [
        (0x1111, 5000, 6000, 100, 200, 0, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 200, 0, SERVER, SEAT, 8, 0.02),
    ]
    rd = make_rtp_data(streams, 90, 201,  # capture ends 1s after media ends
                       sip_events=[{'time': 95, 'method': 'INVITE', 'call_id': 'x'}])
    calls = detect_calls({'fs': rd}, SERVER)
    pf = calls[0]['completeness']['per_file']['fs']
    assert pf['status'] == 'truncated_tail', f"expected truncated_tail, got {pf['status']}"
    print("PASS: truncated_tail detected (no BYE, ends at capture edge)")


def test_truncated_both():
    """Capture window entirely inside an ongoing call -> truncated_both."""
    # Call 0~300, capture 100~110 (media occupies the whole capture)
    streams = [
        (0x1111, 5000, 6000, 100, 110, 5000, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 110, 30000, SERVER, SEAT, 8, 0.02),
    ]
    rd = make_rtp_data(streams, 100, 110)
    calls = detect_calls({'fs': rd}, SERVER)
    pf = calls[0]['completeness']['per_file']['fs']
    assert pf['status'] == 'truncated_both', f"expected truncated_both, got {pf['status']}"
    print("PASS: truncated_both detected")


def test_edge_gap_without_seq_signal():
    """No uplink streams (only downlink) + starts at capture edge -> truncated_head via gap."""
    # Only downlink (fs->seat) stream, call starts at capture start
    streams = [
        (0x1112, 6000, 5000, 100, 160, 12345, SERVER, SEAT, 8, 0.02),
    ]
    rd = make_rtp_data(streams, 100, 200)  # capture 100~200, media 100~160
    calls = detect_calls({'fs': rd}, SERVER)
    pf = calls[0]['completeness']['per_file']['fs']
    assert pf['status'] == 'truncated_head', f"expected truncated_head, got {pf['status']}"
    print("PASS: truncated_head via edge gap (no uplink streams)")


def test_cross_file_merge():
    """Same call seen at seat and fs captures -> merged into 1 call with 2 files."""
    # Stream 0x1111 (seat->fs) appears in both captures
    seat_rd = make_rtp_data([
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
    ], 90, 170, sip_events=[{'time': 95, 'method': 'INVITE', 'call_id': 'x'}])
    fs_rd = make_rtp_data([
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
        # terminal leg only visible at fs
        (0x1113, 7000, 8000, 100, 160, 0, TERM, SERVER, 0, 0.02),
        (0x1114, 8000, 7000, 100, 160, 0, SERVER, TERM, 0, 0.02),
    ], 90, 170, sip_events=[{'time': 95, 'method': 'INVITE', 'call_id': 'x'},
                            {'time': 165, 'method': 'BYE', 'call_id': 'x'}])
    calls = detect_calls({'seat': seat_rd, 'fs': fs_rd}, SERVER)
    assert len(calls) == 1, f"expected 1 merged call, got {len(calls)}"
    assert set(calls[0]['files']) == {'fs', 'seat'}
    assert calls[0]['stream_count'] == 4
    print("PASS: cross-file merge -> 1 call across 2 files, 4 streams")


def test_concurrent_calls_limitation():
    """Two overlapping concurrent calls at fs get grouped into 1 call (known limitation).

    Documents current behavior: time-overlap clustering cannot separate
    concurrent calls sharing the server IP.
    """
    streams = []
    for base_port, tag in [(5000, 0x11), (9000, 0x33)]:
        streams += [
            (tag * 0x100 + 1, base_port, base_port + 1000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
            (tag * 0x100 + 2, base_port + 1000, base_port, 100, 160, 0, SERVER, SEAT, 8, 0.02),
        ]
    rd = make_rtp_data(streams, 90, 200)
    calls = detect_calls({'fs': rd}, SERVER)
    # Both legs overlap and share server IP -> merged into 1 call (documented limitation)
    print(f"INFO: concurrent overlapping calls grouped into {len(calls)} call(s) (known limitation)")


def test_sip_flow_association_and_dedupe():
    """SIP flow: Call-ID association to calls, cross-file dedupe, CSeq retry kept."""
    def sip(time, method, cid, cseq, src, dst, reason=''):
        return {'time': time, 'method': method, 'call_id': cid, 'cseq': cseq,
                'src': src, 'dst': dst, 'reason': reason}

    streams = [
        # call 1: t=100~160; call 2: t=300~360
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
        (0x2221, 5100, 6100, 300, 360, 0, SEAT, SERVER, 8, 0.02),
        (0x2222, 6100, 5100, 300, 360, 0, SERVER, SEAT, 8, 0.02),
    ]
    # fs sees the full signaling of both calls; seat's capture re-sees call-1
    # messages 0.6s later (clock skew) — must be deduped.
    fs_sip = [
        sip(95, 'INVITE', 'a', 1, SERVER, SEAT),
        sip(96, '100', 'a', 1, SEAT, SERVER, 'Trying'),
        sip(98, '200', 'a', 1, SEAT, SERVER, 'Ok'),
        sip(99, 'ACK', 'a', 1, SERVER, SEAT),
        sip(110, 'INVITE', 'a', 2, SEAT, SERVER),          # auth/re-INVITE retry: new CSeq
        sip(165, 'BYE', 'a', 3, SERVER, SEAT),
        sip(166, '200', 'a', 3, SEAT, SERVER, 'Ok'),
        sip(295, 'INVITE', 'b', 1, SERVER, SEAT),
        sip(365, 'BYE', 'b', 2, SERVER, SEAT),
    ]
    seat_sip = [
        sip(95.6, 'INVITE', 'a', 1, SERVER, SEAT),         # dup of fs@95
        sip(98.6, '200', 'a', 1, SEAT, SERVER, 'Ok'),      # dup of fs@98
    ]
    rd = make_rtp_data(streams, 90, 400, sip_events=fs_sip)
    seat_rd = make_rtp_data([streams[0], streams[1]], 90, 170, sip_events=seat_sip)

    calls = detect_calls({'fs': rd, 'seat': seat_rd}, SERVER)
    assert len(calls) == 2
    f1, f2 = calls[0]['sip_flow'], calls[1]['sip_flow']
    labels1 = [m['label'] for m in f1]
    assert len(f1) == 7, f"expected 7 deduped messages in call 1, got {len(f1)}: {labels1}"
    assert labels1 == ['INVITE', '100 Trying', '200 Ok', 'ACK', 'INVITE', 'BYE', '200 Ok']
    assert all(m['src'] in (SEAT, SERVER) for m in f1)
    assert len(f2) == 2 and f2[0]['label'] == 'INVITE'
    print("PASS: sip flow association (7+2), cross-file dedupe, CSeq retry kept")


def test_back_to_back_calls_no_signaling_bleed():
    """Two calls between the same device pair: each call keeps only its own
    Call-ID group's messages, and completeness cites its own BYE."""
    from datetime import datetime

    def sip(time, method, cid, cseq, src, dst, reason='', sdp=None, cseq_method=''):
        ev = {'time': time, 'method': method, 'call_id': cid, 'cseq': cseq,
              'src': src, 'dst': dst, 'reason': reason, 'cseq_method': cseq_method}
        if sdp:
            ev['sdp'] = sdp
        return ev

    streams = [
        # call A: t=100~110, call B: t=112~124 (same endpoints, new ports);
        # call A also has a video leg using dynamic PT 96
        (0x1111, 5000, 6000, 100, 110, 0, SEAT, SERVER, 0, 0.02),
        (0x1112, 6000, 5000, 100, 110, 0, SERVER, SEAT, 0, 0.02),
        (0x1113, 5200, 6200, 100, 110, 0, SEAT, SERVER, 96, 0.02),
        (0x2221, 5100, 6100, 112, 124, 0, SEAT, SERVER, 8, 0.02),
        (0x2222, 6100, 5100, 112, 124, 0, SERVER, SEAT, 8, 0.02),
    ]
    sdp_a = {'audio': ['PCMU'], 'video': ['H264'],
             'map': {'audio': {'0': 'PCMU'}, 'video': {'96': 'H264'}}}
    fs_sip = [
        sip(99.0, 'INVITE', 'a', 1, SEAT, SERVER, sdp=sdp_a, cseq_method='INVITE'),
        sip(104.0, '200', 'a', 1, SERVER, SEAT, 'Ok', sdp=sdp_a, cseq_method='INVITE'),
        sip(110.0, 'BYE', 'a', 2, SEAT, SERVER, cseq_method='BYE'),
        sip(110.5, '200', 'a', 2, SERVER, SEAT, 'Ok', cseq_method='BYE'),
        sip(111.0, 'INVITE', 'b', 1, SEAT, SERVER, sdp={'audio': ['PCMA']}, cseq_method='INVITE'),
        sip(120.0, '200', 'b', 1, SERVER, SEAT, 'Ok', sdp={'audio': ['PCMA']}, cseq_method='INVITE'),
        sip(124.0, 'BYE', 'b', 2, SEAT, SERVER, cseq_method='BYE'),
        sip(124.5, '200', 'b', 2, SERVER, SEAT, 'Ok', cseq_method='BYE'),
    ]
    rd = make_rtp_data(streams, 90, 200, sip_events=fs_sip)
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 2, f"expected 2 calls, got {len(calls)}"

    call_a, call_b = calls
    assert call_a['sip_call_ids'] == ['a'], f"call A attached {call_a['sip_call_ids']}"
    assert call_b['sip_call_ids'] == ['b'], f"call B attached {call_b['sip_call_ids']}"

    labels_a = [m['label'] for m in call_a['sip_flow']]
    assert labels_a == ['INVITE', '200 Ok', 'BYE', '200 Ok'], labels_a
    assert call_a['sip_flow'][-1]['time_str'] == datetime.fromtimestamp(110.5).strftime('%H:%M:%S')
    labels_b = [m['label'] for m in call_b['sip_flow']]
    assert labels_b == ['INVITE', '200 Ok', 'BYE', '200 Ok'], labels_b

    # Completeness of call A must cite A's own BYE (110), never B's (124)
    reasons_a = ' '.join(call_a['completeness']['per_file']['fs']['reasons'])
    bye_a = datetime.fromtimestamp(110).strftime('%H:%M:%S')
    bye_b = datetime.fromtimestamp(124).strftime('%H:%M:%S')
    assert bye_a in reasons_a and bye_b not in reasons_a, reasons_a
    assert call_a['completeness']['status'] == 'complete'
    assert call_b['completeness']['status'] == 'complete'
    # Codecs come from the PTs actually seen in each call's RTP streams:
    # static PT names for audio, SDP rtpmap for dynamic video PTs
    assert call_a['codecs'] == {'audio': ['PCMU (G.711 μ-law)'], 'video': ['H264']}, call_a['codecs']
    assert call_b['codecs'] == {'audio': ['PCMA (G.711 A-law)'], 'video': []}, call_b['codecs']
    # Talk window = answered media only: RTP at/after the INVITE's 200 OK
    # (104s) and before the first BYE (110s), not the whole 100~110 stream
    fmt = '%H:%M:%S'
    assert call_a['talk_start_str'] == datetime.fromtimestamp(104).strftime(fmt), call_a['talk_start_str']
    assert call_a['talk_end_str'] == datetime.fromtimestamp(110).strftime(fmt), call_a['talk_end_str']
    assert call_a['talk_duration_s'] == 6.0, call_a['talk_duration_s']
    assert call_b['talk_duration_s'] == 4.0, call_b['talk_duration_s']
    # 协商编码 = offer(INVITE) 与 answer(200 OK) SDP 的交集
    assert call_a['negotiated_codecs'] == {'audio': ['PCMU'], 'video': ['H264']}
    assert call_b['negotiated_codecs'] == {'audio': ['PCMA'], 'video': []}
    assert call_a['sdp_answered'] is True
    # 带 SDP 的消息标注了各自列出的编码
    inv_a = next(m for m in call_a['sip_flow'] if m['method'] == 'INVITE')
    assert inv_a['sdp_codecs'] == {'audio': ['PCMU'], 'video': ['H264']}, inv_a
    print("PASS: back-to-back same-pair calls keep signaling and BYE separate")


def test_sip_sdp_parsing():
    """_parse_sip_event extracts audio/video codecs from the SDP body."""
    from analyzer.rtp_parser import _parse_sip_event
    payload = ('INVITE sip:1003@10.0.0.1:5060 SIP/2.0\r\n'
               'From: <sip:1002@10.0.0.2>\r\nTo: <sip:1003@10.0.0.1>\r\n'
               'Call-ID: sdp-cid\r\nCSeq: 1 INVITE\r\n'
               'Content-Type: application/sdp\r\n'
               'Content-Length: 999\r\n'
               '\r\n'
               'v=0\r\n'
               'o=- 123 456 IN IP4 10.0.0.2\r\n'
               'm=audio 16400 RTP/AVP 0 8 101\r\n'
               'a=rtpmap:0 PCMU/8000\r\n'
               'a=rtpmap:8 PCMA/8000\r\n'
               'a=rtpmap:101 telephone-event/8000\r\n'
               'm=video 16402 RTP/AVP 96\r\n'
               'a=rtpmap:96 H264/90000\r\n'
               'a=rtcp-fb:96 nack\r\n'
               'm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n').encode()
    ev = _parse_sip_event(payload)
    assert ev and ev['sdp'] == {
        'audio': ['PCMU', 'PCMA'], 'video': ['H264'],
        'map': {'audio': {'0': 'PCMU', '8': 'PCMA'}, 'video': {'96': 'H264'}},
        # full：编码身份（名字+时钟率），供两腿协商结果对比
        'full': {'audio': [{'name': 'PCMU', 'rate': 8000},
                           {'name': 'PCMA', 'rate': 8000}],
                 'video': [{'name': 'H264', 'rate': 90000}]},
        # map_full：按 PT 直查名字与时钟率，供流种类/重建时钟解析
        'map_full': {'audio': {'0': {'name': 'PCMU', 'rate': 8000},
                               '8': {'name': 'PCMA', 'rate': 8000}},
                     'video': {'96': {'name': 'H264', 'rate': 90000}}},
        # 无 c= 行则没有宣告端点
        'endpoints': [],
    }, ev['sdp']

    # 媒体端点：会话级 c= 为默认连接地址，媒体级 c=（紧跟其 m= 之后）覆盖；
    # 端口 0（拒绝该路媒体）与 0.0.0.0 连接地址（hold）不宣告
    payload_hold = ('INVITE sip:1003@10.0.0.1 SIP/2.0\r\n'
                    'Call-ID: sdp-cid3\r\nCSeq: 1 INVITE\r\n'
                    'Content-Type: application/sdp\r\nContent-Length: 999\r\n'
                    '\r\n'
                    'v=0\r\n'
                    'c=IN IP4 10.0.0.2\r\n'
                    'm=audio 16400 RTP/AVP 0\r\n'
                    'm=video 0 RTP/AVP 96\r\n'
                    'm=video 16404 RTP/AVP 96\r\n'
                    'c=IN IP4 10.0.0.9\r\n'
                    'm=audio 16406 RTP/AVP 8\r\n'
                    'c=IN IP4 0.0.0.0\r\n'
                    'm=video 16408 RTP/AVP 96\r\n').encode()
    ev4 = _parse_sip_event(payload_hold)
    assert ev4['sdp']['endpoints'] == [
        {'kind': 'audio', 'addr': '10.0.0.2', 'port': 16400},
        {'kind': 'video', 'addr': '10.0.0.9', 'port': 16404},
    ], ev4['sdp']['endpoints']

    # 静态 PT（0/8）不带 rtpmap 时按静态表解析；裸 telephone（无 -event 后缀）
    # 同样是 DTMF，排除；无 rtpmap 的动态 PT 没有名字，跳过
    payload2 = ('INVITE sip:1003@10.0.0.1 SIP/2.0\r\n'
                'From: <sip:1002@10.0.0.2>\r\nTo: <sip:1003@10.0.0.1>\r\n'
                'Call-ID: sdp-cid2\r\nCSeq: 1 INVITE\r\n'
                'Content-Type: application/sdp\r\nContent-Length: 999\r\n'
                '\r\n'
                'v=0\r\n'
                'm=audio 16400 RTP/AVP 96 97 98 0 8 101 99 100\r\n'
                'a=rtpmap:96 opus/48000/2\r\n'
                'a=rtpmap:97 speex/16000\r\n'
                'a=rtpmap:98 speex/8000\r\n'
                'a=rtpmap:101 telephone-event/48000\r\n'
                'a=rtpmap:99 telephone\r\n').encode()
    ev3 = _parse_sip_event(payload2)
    assert ev3 and ev3['sdp'] == {
        'audio': ['OPUS', 'SPEEX', 'PCMU', 'PCMA'],
        'video': [],
        'map': {'audio': {'96': 'OPUS', '97': 'SPEEX', '98': 'SPEEX',
                          '0': 'PCMU', '8': 'PCMA'},
                'video': {}},
        # 静态 PT（0/8）无 rtpmap 时按 RFC 3551 补时钟率
        'full': {'audio': [{'name': 'OPUS', 'rate': 48000},
                           {'name': 'SPEEX', 'rate': 16000},
                           {'name': 'SPEEX', 'rate': 8000},
                           {'name': 'PCMU', 'rate': 8000},
                           {'name': 'PCMA', 'rate': 8000}],
                 'video': []},
        'map_full': {'audio': {'96': {'name': 'OPUS', 'rate': 48000},
                               '97': {'name': 'SPEEX', 'rate': 16000},
                               '98': {'name': 'SPEEX', 'rate': 8000},
                               '0': {'name': 'PCMU', 'rate': 8000},
                               '8': {'name': 'PCMA', 'rate': 8000}},
                     'video': {}},
        'endpoints': [],
    }, ev3['sdp']

    # No body / no SDP -> empty dict
    ev2 = _parse_sip_event(b'BYE sip:1002@10.0.0.1 SIP/2.0\r\n'
                           b'Call-ID: x\r\nCSeq: 2 BYE\r\n\r\n')
    assert ev2 and ev2['sdp'] == {}
    print("PASS: SIP SDP codec parsing (audio/video split, telephone-event/application ignored)")


def test_sip_from_to_parsing():
    """_parse_sip_event extracts device identity from From/To headers."""
    from analyzer.rtp_parser import _parse_sip_event
    payload = ('INVITE sip:1003@10.0.0.1:5060 SIP/2.0\r\n'
               'From: "张三" <sip:1002@10.4.157.141>;tag=abc123\r\n'
               'To: <sip:1003@10.0.0.1>\r\n'
               'Call-ID: test-cid@host\r\n'
               'CSeq: 1 INVITE\r\n\r\n').encode()
    ev = _parse_sip_event(payload)
    assert ev and ev['method'] == 'INVITE' and ev['call_id'] == 'test-cid@host'
    assert ev['cseq_method'] == 'INVITE'
    assert ev['from'] == {'name': '张三', 'user': '1002', 'host': '10.4.157.141'}, ev['from']
    assert ev['to'] == {'name': '', 'user': '1003', 'host': '10.0.0.1'}, ev['to']

    # No From/To at all -> no identity (empty value), still parses
    ev2 = _parse_sip_event(b'BYE sip:1002@10.0.0.1 SIP/2.0\r\n'
                           b'Call-ID: x\r\nCSeq: 2 BYE\r\n\r\n')
    assert ev2 and not ev2['from'] and not ev2['to']

    # Compact form headers (f:/t:) also parsed
    ev3 = _parse_sip_event(('INVITE sip:9@x SIP/2.0\r\n'
                            'f: <sip:77@1.1.1.1>\r\nt: "李四" <sip:88@2.2.2.2>\r\n'
                            'Call-ID: y\r\nCSeq: 1 INVITE\r\n\r\n').encode())
    assert ev3['from']['user'] == '77'
    assert ev3['to']['name'] == '李四' and ev3['to']['user'] == '88'
    print("PASS: SIP From/To device identity parsing")


def test_capture_consistency_mismatch():
    """Uploads with no shared call across captures -> consistency warning."""
    seat_rd = make_rtp_data([
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
    ], 90, 170)
    term_rd = make_rtp_data([
        (0x2221, 7000, 8000, 300, 360, 0, TERM, SERVER, 0, 0.02),
        (0x2222, 8000, 7000, 300, 360, 0, SERVER, TERM, 0, 0.02),
    ], 300, 380)
    calls = detect_calls({'seat': seat_rd, 'terminal': term_rd}, SERVER)
    assert len(calls) == 2, f"expected 2 disjoint calls, got {len(calls)}"
    warning = check_capture_consistency(calls, ['seat', 'terminal'])
    assert warning is not None, 'expected mismatch warning'
    assert warning['kind'] == 'mismatch', warning
    assert any(p['a'] == 'seat' and p['b'] == 'terminal'
               for p in warning['pairs']), warning
    # 纵向列表结构：每个角色一行——总体时间段 + 每通通话时间段
    by_role = {r['role']: r for r in warning['roles']}
    assert by_role['seat']['display'] == '被叫端（坐席）'
    assert by_role['seat']['overall'] == {'start': by_role['seat']['calls'][0]['start'],
                                          'end': by_role['seat']['calls'][-1]['end'],
                                          'count': 1}
    assert len(by_role['seat']['calls']) == 1
    assert len(by_role['terminal']['calls']) == 1
    assert all(c['start'] and c['end'] and c['label'].startswith('通话')
               for r in warning['roles'] for c in r['calls'])
    print("PASS: mismatched captures -> consistency warning raised")

    # Same call seen in both captures -> no warning
    shared_rd = make_rtp_data([
        (0x3331, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x3332, 6000, 5000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
    ], 90, 170)
    calls = detect_calls({'seat': shared_rd, 'fs': shared_rd}, SERVER)
    assert len(calls) == 1 and set(calls[0]['files']) == {'fs', 'seat'}
    assert check_capture_consistency(calls, ['seat', 'fs']) is None
    print("PASS: shared call across captures -> no warning")

    # Degenerate cases: single role or no calls -> no warning
    assert check_capture_consistency(calls, ['seat']) is None
    assert check_capture_consistency([], ['seat', 'fs']) is None
    print("PASS: single role / empty calls -> no warning")


def test_negotiated_codecs():
    """协商编码 = SDP offer/answer 交集：应答子集胜出、answer 空表示拒绝该路
    媒体、慢启动 offer 在 200 OK / answer 在 ACK、无应答只剩主叫候选。"""
    from analyzer.call_detector import build_sip_flows

    def sip(time, method, cid, cseq, src, dst, sdp=None, cseq_method=''):
        return {'time': time, 'method': method, 'call_id': cid, 'cseq': cseq,
                'cseq_method': cseq_method or method, 'src': src, 'dst': dst,
                'reason': '', 'sdp': sdp or {}}

    offer_all = {'audio': ['PCMU', 'PCMA', 'G722'], 'video': ['H264', 'H265'],
                 'map': {'audio': {}, 'video': {}}}
    ans_subset = {'audio': ['PCMA', 'G722'], 'video': ['H264'],
                  'map': {'audio': {}, 'video': {}}}
    ans_audio_only = {'audio': ['G722'], 'video': [],
                      'map': {'audio': {}, 'video': {}}}

    # 正常应答：183 早释媒体即 answer，交集保持 offer 顺序
    calls = [{'start': 90, 'end': 200}]
    build_sip_flows(calls, {'fs': {'sip_events': [
        sip(95, 'INVITE', 'a', 1, SEAT, SERVER, sdp=offer_all),
        sip(97, '183', 'a', 1, SERVER, SEAT, sdp=ans_subset),
        sip(104, '200', 'a', 1, SERVER, SEAT, sdp=ans_subset, cseq_method='INVITE'),
        sip(165, 'BYE', 'a', 2, SEAT, SERVER),
    ]}}, server_ip=SERVER)
    assert calls[0]['negotiated_codecs'] == {'audio': ['PCMA', 'G722'],
                                             'video': ['H264']}, calls[0]
    assert calls[0]['sdp_answered'] is True
    print("PASS: negotiated = offer∩answer (183 early answer), offer order kept")

    # 慢启动：offer 在 200 OK、answer 在 ACK；answer 拒绝视频 → 协商无视频，
    # 音频交集为空时以 answer 为准
    calls = [{'start': 290, 'end': 400}]
    build_sip_flows(calls, {'fs': {'sip_events': [
        sip(295, 'INVITE', 'b', 1, SEAT, SERVER),
        sip(300, '200', 'b', 1, SERVER, SEAT, sdp=offer_all, cseq_method='INVITE'),
        sip(301, 'ACK', 'b', 1, SEAT, SERVER, sdp=ans_audio_only),
        sip(365, 'BYE', 'b', 2, SEAT, SERVER),
    ]}}, server_ip=SERVER)
    assert calls[0]['negotiated_codecs'] == {'audio': ['G722'], 'video': []}, \
        calls[0]['negotiated_codecs']
    print("PASS: slow-start offer in 200 OK / answer in ACK; declined video gone")

    # 无应答（486 忙）：只有主叫候选，sdp_answered=False
    calls = [{'start': 490, 'end': 600}]
    build_sip_flows(calls, {'fs': {'sip_events': [
        sip(495, 'INVITE', 'c', 1, SEAT, SERVER, sdp=offer_all),
        sip(497, '486', 'c', 1, SERVER, SEAT),
    ]}}, server_ip=SERVER)
    assert calls[0]['negotiated_codecs'] == {'audio': ['PCMU', 'PCMA', 'G722'],
                                             'video': ['H264', 'H265']}
    assert calls[0]['sdp_answered'] is False
    print("PASS: unanswered call keeps caller candidates, sdp_answered=False")

    # 无任何 SDP：空协商结果
    calls = [{'start': 690, 'end': 800}]
    build_sip_flows(calls, {'fs': {'sip_events': [
        sip(695, 'INVITE', 'd', 1, SEAT, SERVER),
        sip(765, 'BYE', 'd', 2, SEAT, SERVER),
    ]}}, server_ip=SERVER)
    assert calls[0]['negotiated_codecs'] == {'audio': [], 'video': []}
    print("PASS: no SDP at all -> empty negotiated codecs")

    # B2BUA 两条腿信令合并在同一流程：FS 并行转发的 INVITE 其 SDP 用静态 PT
    # 不带 rtpmap，解析不出编码名（audio/video 均为空列表）——配对时必须跳过
    # 这条消息，用终端 offer × FS 应答（183）得出协商结果
    calls = [{'start': 890, 'end': 1000}]
    build_sip_flows(calls, {'fs': {'sip_events': [
        sip(895, 'INVITE', 'e', 1, TERM, SERVER,
            sdp={'audio': ['OPUS', 'SPEEX'], 'video': []}),
        sip(895.5, 'INVITE', 'e', 20, SERVER, SEAT,
            sdp={'audio': [], 'video': []}),
        sip(897, '183', 'e', 1, SERVER, TERM,
            sdp={'audio': ['PCMU'], 'video': ['H264']}),
        sip(965, 'BYE', 'e', 2, TERM, SERVER),
    ]}}, server_ip=SERVER)
    assert calls[0]['negotiated_codecs'] == {'audio': ['PCMU'], 'video': ['H264']}, \
        calls[0]['negotiated_codecs']
    assert calls[0]['sdp_answered'] is True
    print("PASS: B2BUA parallel INVITE with rtpmap-less SDP skipped in pairing")


def test_p2p_direct_call_hint():
    """点对点直连（媒体不经 FS）：通话标记 is_p2p，一致性提示为 p2p 而非传错文件。

    场景：坐席↔终端的通话媒体在两端之间直连（FS 抓包里没有这通通话的任何
    RTP），FS 抓包里只有同时段经服务器转发的其他通话。此时"坐席/终端 与 FS
    之间没有共同通话"不应报传错文件，而应提示点对点直连。
    """
    OTHER = '10.0.0.9'
    direct_streams = [
        (0x4411, 52375, 50192, 100, 160, 0, SEAT, TERM, 96, 0.02),
        (0x4412, 50192, 52375, 100, 160, 0, TERM, SEAT, 96, 0.02),
    ]
    seat_rd = make_rtp_data(direct_streams, 90, 170)
    term_rd = make_rtp_data(direct_streams, 95, 165)
    fs_rd = make_rtp_data([
        (0x5511, 7000, 8000, 100, 160, 0, OTHER, SERVER, 0, 0.02),
        (0x5512, 8000, 7000, 100, 160, 0, SERVER, OTHER, 0, 0.02),
    ], 90, 200)

    calls = detect_calls({'seat': seat_rd, 'fs': fs_rd, 'terminal': term_rd}, SERVER)
    p2p_calls = [c for c in calls if c['is_p2p']]
    assert len(p2p_calls) == 1, f"expected 1 p2p call, got {len(p2p_calls)}"
    assert set(p2p_calls[0]['files']) == {'seat', 'terminal'}, p2p_calls[0]['files']
    assert p2p_calls[0]['p2p_endpoints'] == sorted([SEAT, TERM]), p2p_calls[0]
    # 经服务器转发的其他通话不标 p2p
    assert not any(c['is_p2p'] for c in calls if c not in p2p_calls)

    warning = check_capture_consistency(calls, ['seat', 'fs', 'terminal'],
                                        server_ip=SERVER, server_roles=['fs'])
    assert warning is not None, 'expected p2p warning'
    assert warning['kind'] == 'p2p', warning
    assert '点对点' in warning['message'], warning['message']
    # 不能再出现"疑似传错文件"的旧措辞
    assert '是否传错' not in warning['message'], warning['message']
    assert '可能不是同一次通话' not in warning['message'], warning['message']
    # 提示里给出直连两端 IP 与服务器 IP，方便一眼确认
    assert SEAT in warning['message'] and TERM in warning['message'], warning['message']
    assert SERVER in warning['message'], warning['message']
    # 纵向列表照常给出（FS 端的 1 通是其他通话）
    by_role = {r['role']: r for r in warning['roles']}
    assert len(by_role['fs']['calls']) == 1
    print("PASS: p2p direct call -> is_p2p flag + p2p hint (not 'wrong file')")

    # 反例：FS 侧抓包也参与了这通通话（正常转发）时 SSRC 会合并，不会走到
    # 提示分支；这里验证"服务器侧抓包不缺位"时保持 mismatch——去掉 FS 抓包，
    # 坐席/终端之间共享同一通，无警告
    calls2 = detect_calls({'seat': seat_rd, 'terminal': term_rd}, SERVER)
    assert check_capture_consistency(calls2, ['seat', 'terminal'],
                                     server_ip=SERVER, server_roles=[]) is None
    print("PASS: p2p call shared by both endpoint captures alone -> no warning")

    # 反例 2：失败角色对含非服务器角色（seat 与 terminal 各抓各的不同通话）
    # 时，即使存在 p2p 通话也不能用 p2p 解释
    other_term_rd = make_rtp_data([
        (0x6611, 9000, 9100, 300, 360, 0, TERM, OTHER, 0, 0.02),
        (0x6612, 9100, 9000, 300, 360, 0, OTHER, TERM, 0, 0.02),
    ], 300, 380)
    calls3 = detect_calls({'seat': seat_rd, 'fs': fs_rd,
                           'terminal': other_term_rd}, SERVER)
    warning3 = check_capture_consistency(calls3, ['seat', 'fs', 'terminal'],
                                         server_ip=SERVER, server_roles=['fs'])
    assert warning3 is not None and warning3['kind'] == 'mismatch', warning3
    print("PASS: failing pair without server-side role -> still mismatch")


def test_sip_source_priority_and_retrans_dedupe():
    """Same message captured by seat+fs keeps the FS copy (one clock, stable
    order); a same-CSeq retransmission 15s later is still deduped (30s window)."""
    from analyzer.call_detector import build_sip_flows

    cid = 'prio-test@host'

    def evs(skew, with_retrans):
        base = [
            {'time': 100.0, 'method': 'INVITE', 'reason': '', 'call_id': cid,
             'cseq': 1, 'cseq_method': 'INVITE', 'src': TERM, 'dst': SERVER,
             'sdp': {}, 'from': {}, 'to': {}},
            {'time': 102.0, 'method': '100', 'reason': 'Trying', 'call_id': cid,
             'cseq': 1, 'cseq_method': 'INVITE', 'src': SERVER, 'dst': TERM,
             'sdp': {}, 'from': {}, 'to': {}},
            {'time': 104.0, 'method': '200', 'reason': 'OK', 'call_id': cid,
             'cseq': 1, 'cseq_method': 'INVITE', 'src': SEAT, 'dst': SERVER,
             'sdp': {}, 'from': {}, 'to': {}},
            {'time': 104.1, 'method': 'ACK', 'reason': '', 'call_id': cid,
             'cseq': 1, 'cseq_method': 'ACK', 'src': TERM, 'dst': SERVER,
             'sdp': {}, 'from': {}, 'to': {}},
        ]
        out = []
        for e in base:
            e2 = dict(e)
            e2['time'] += skew
            out.append(e2)
        if with_retrans:
            r = dict(base[2])
            r['time'] = base[2]['time'] + skew + 15.0
            out.append(r)
        return out

    calls = [{'start': 103.0, 'end': 120.0}]
    captures = {
        # seat clock runs ~0.8s behind FS; retransmission only in seat capture
        'seat': {'sip_events': evs(0.8, True)},
        'fs': {'sip_events': evs(0.0, False)},
    }
    build_sip_flows(calls, captures, server_ip=SERVER)
    flow = calls[0]['sip_flow']
    twos = [e for e in flow if e['method'] == '200' and e['cseq_method'] == 'INVITE']
    assert len(twos) == 1, f"expected 1 answer 200 OK, got {len(twos)}: {twos}"
    # kept copy must be the FS one (time 104.0), not the skewed seat copy 104.8
    assert twos[0]['time'] == 104.0, twos[0]
    assert calls[0]['answer_time'] == 104.0
    print("PASS: SIP source priority (FS copy kept) + 15s retransmission deduped")

    # Seat-only capture still works (priority falls back to the only copy)
    calls = [{'start': 103.0, 'end': 120.0}]
    build_sip_flows(calls, {'seat': {'sip_events': evs(0.8, True)}}, server_ip=SERVER)
    flow = calls[0]['sip_flow']
    twos = [e for e in flow if e['method'] == '200' and e['cseq_method'] == 'INVITE']
    assert len(twos) == 1 and twos[0]['time'] == 104.8, twos
    print("PASS: single-capture fallback keeps its own copy")


def _sdp(endpoints, audio='PCMU'):
    """带宣告端点的 SDP 事件体（endpoints: [(addr, port), ...]）。"""
    return {'audio': [audio] if audio else [], 'video': [],
            'map': {'audio': {'0': audio} if audio else {}, 'video': {}},
            'endpoints': [{'kind': 'audio', 'addr': a, 'port': p}
                          for a, p in endpoints]}


def _b2bua_sip_events(cid, term_port, fs_port, seat_port, t_inv, t_bye,
                      with_sdp=True, answerer=SEAT, caller=TERM):
    """B2BUA 一通通话的信令：终端→FS 的 INVITE + FS→坐席的 INVITE，
    两条 200 OK 各自宣告本侧媒体地址，最后 BYE。"""
    other = {'fs_side': (SERVER, fs_port), 'term_side': (caller, term_port),
             'seat_side': (SEAT, seat_port)}
    evs = [
        {'time': t_inv, 'method': 'INVITE', 'call_id': cid, 'cseq': 1,
         'cseq_method': 'INVITE', 'src': caller, 'dst': SERVER,
         'sdp': _sdp([other['term_side']]) if with_sdp else {}},
        {'time': t_inv + 0.5, 'method': 'INVITE', 'call_id': cid, 'cseq': 20,
         'cseq_method': 'INVITE', 'src': SERVER, 'dst': answerer,
         'sdp': _sdp([other['fs_side']]) if with_sdp else {}},
        {'time': t_inv + 4, 'method': '200', 'call_id': cid, 'cseq': 1,
         'cseq_method': 'INVITE', 'src': answerer, 'dst': SERVER,
         'sdp': _sdp([other['seat_side']]) if with_sdp else {}},
        {'time': t_inv + 4.5, 'method': '200', 'call_id': cid, 'cseq': 20,
         'cseq_method': 'INVITE', 'src': SERVER, 'dst': TERM,
         'sdp': _sdp([other['fs_side']]) if with_sdp else {}},
        {'time': t_bye, 'method': 'BYE', 'call_id': cid, 'cseq': 30,
         'cseq_method': 'BYE', 'src': TERM, 'dst': SERVER},
    ]
    return evs


def test_concurrent_calls_split_by_sdp():
    """两通并发的通话经同一 FS（时间重叠聚类并成一通）：SDP 宣告端点把
    它们拆回两通，各自 4 条流、各自的信令流程——不再出现 9 条流。"""
    other = '10.0.0.9'
    streams = [
        # 通话 A：终端↔FS、坐席↔FS（各上下行）
        (0xAA11, 7080, 34576, 100, 160, 0, TERM, SERVER, 0, 0.02),
        (0xAA12, 34576, 7080, 100, 160, 0, SERVER, TERM, 0, 0.02),
        (0xAA13, 6000, 34580, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0xAA14, 34580, 6000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
        # 通话 B：另一对端点（IP 既非 A 的主被叫），完全并发
        (0xBB11, 7180, 34600, 100, 160, 0, other, SERVER, 0, 0.02),
        (0xBB12, 34600, 7180, 100, 160, 0, SERVER, other, 0, 0.02),
        (0xBB13, 6100, 34610, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0xBB14, 34610, 6100, 100, 160, 0, SERVER, SEAT, 8, 0.02),
    ]
    sip = (_b2bua_sip_events('a', 7080, 34576, 6000, 95, 165)
           + _b2bua_sip_events('b', 7180, 34600, 6100, 95, 165,
                               answerer=other))
    rd = make_rtp_data(streams, 90, 200, sip_events=sip)
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 2, f"expected 2 calls, got {len(calls)}"
    a = next(c for c in calls if c['sip_call_ids'] == ['a'])
    b = next(c for c in calls if c['sip_call_ids'] == ['b'])
    assert set(a['ssrcs']) == {0xAA11, 0xAA12, 0xAA13, 0xAA14}, a['ssrcs']
    assert set(b['ssrcs']) == {0xBB11, 0xBB12, 0xBB13, 0xBB14}, b['ssrcs']
    assert a['stream_count'] == 4 and b['stream_count'] == 4
    # 各通的信令流程只含自己的消息（B 的主叫是 other）
    assert all(m['src'] in (TERM, SERVER, SEAT) for m in a['sip_flow'])
    assert any(m['src'] == other for m in b['sip_flow'])
    assert all(c['completeness']['status'] == 'complete' for c in calls)
    print("PASS: concurrent calls through one FS split by SDP endpoints")


def test_foreign_stream_evicted_from_call():
    """通话 A 之外混入一条无信令的他人媒体流（回放里多出的第 9 条流）：
    按通话 A 自己的 SDP 宣告剔出，单独成通可选分析。"""
    other = '10.0.0.9'
    streams = [
        (0xAA11, 7080, 34576, 100, 160, 0, TERM, SERVER, 0, 0.02),
        (0xAA12, 34576, 7080, 100, 160, 0, SERVER, TERM, 0, 0.02),
        (0xAA13, 6000, 34580, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0xAA14, 34580, 6000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
        # 他人通话仅剩的一条腿（不完整的那一通），时间与 A 重叠
        (0xBB11, 7180, 34600, 110, 150, 0, other, SERVER, 0, 0.02),
    ]
    rd = make_rtp_data(streams, 90, 200,
                       sip_events=_b2bua_sip_events('a', 7080, 34576, 6000,
                                                    95, 165))
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 2, f"expected A + evicted foreign call, got {len(calls)}"
    a = next(c for c in calls if c['sip_call_ids'] == ['a'])
    stray = next(c for c in calls if c['sip_call_ids'] != ['a'])
    assert set(a['ssrcs']) == {0xAA11, 0xAA12, 0xAA13, 0xAA14}, a['ssrcs']
    assert set(stray['ssrcs']) == {0xBB11}, stray['ssrcs']
    assert stray['sip_flow'] == []
    print("PASS: foreign un-signaled stream evicted into its own call")


def test_party_filter_without_sdp():
    """信令无 SDP 时退回主叫/被叫 IP 过滤：经 FS 转发、对端既非主叫也非
    被叫的他人流被剔出通话。"""
    other = '10.0.0.9'
    streams = [
        (0xAA11, 7080, 34576, 100, 160, 0, TERM, SERVER, 0, 0.02),
        (0xAA12, 34576, 7080, 100, 160, 0, SERVER, TERM, 0, 0.02),
        (0xAA13, 6000, 34580, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0xAA14, 34580, 6000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
        (0xBB11, 9000, 34600, 100, 160, 0, other, SERVER, 0, 0.02),
        (0xBB12, 34600, 9000, 100, 160, 0, SERVER, other, 0, 0.02),
    ]
    sip = [
        {'time': 95, 'method': 'INVITE', 'call_id': 'a', 'cseq': 1,
         'cseq_method': 'INVITE', 'src': TERM, 'dst': SERVER},
        {'time': 104, 'method': '200', 'call_id': 'a', 'cseq': 1,
         'cseq_method': 'INVITE', 'src': SEAT, 'dst': SERVER},
        {'time': 165, 'method': 'BYE', 'call_id': 'a', 'cseq': 30,
         'cseq_method': 'BYE', 'src': TERM, 'dst': SERVER},
    ]
    rd = make_rtp_data(streams, 90, 200, sip_events=sip)
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 2, f"expected A + evicted other-endpoint call, got {len(calls)}"
    a = next(c for c in calls if c['sip_call_ids'] == ['a'])
    stray = next(c for c in calls if c['sip_call_ids'] != ['a'])
    assert set(a['ssrcs']) == {0xAA11, 0xAA12, 0xAA13, 0xAA14}, a['ssrcs']
    assert set(stray['ssrcs']) == {0xBB11, 0xBB12}, stray['ssrcs']
    print("PASS: caller/callee IP filter evicts other-endpoint streams (no SDP)")


def test_preexisting_calls_with_tail_signaling_separate():
    """服务器侧抓包开始时已有一通进行中的通话（A，信令只剩 BYE），其后紧跟
    一通完整的新通话（B）与另一通同样缺头、只有 re-INVITE/BYE 半截信令的
    通话（C）：三通必须拆开——缺头通话的尾段不得焊进时间重叠的新通话，C 的
    两侧腿（一侧只有带 SDP 的 re-INVITE、一侧只有 BYE）必须合成一通。

    复现 qigndao2_2026_09_14_02.pcap 的真实场景：此前 A 的尾段会并进 B、C
    的 W 侧腿会跟着焊进去，剩 D 侧单独一通没有信令。"""
    Y, Z, D, W = '10.0.0.22', '10.0.0.33', '10.0.0.44', '10.0.0.55'

    def ev(time, method, cid, cseq, src, dst, sdp=None):
        e = {'time': time, 'method': method, 'call_id': cid, 'cseq': cseq,
             'cseq_method': 'INVITE' if method == 'INVITE'
             else ('BYE' if method == 'BYE' else method),
             'src': src, 'dst': dst, 'reason': ''}
        if sdp:
            e['sdp'] = sdp
        return e

    streams = [
        # 通话 A（抓包前已在进行，媒体 100~121，只剩挂断信令）
        (0xA1, 49236, 31330, 100, 121, 7000, Y, SERVER, 8, 0.02),
        (0xA2, 31330, 49236, 100, 121, 300, SERVER, Y, 0, 0.02),
        (0xA3, 60336, 24340, 100, 121, 5000, Z, SERVER, 0, 0.02),
        (0xA4, 24340, 60336, 100, 121, 400, SERVER, Z, 0, 0.02),
        # 通话 C（同样缺头，媒体 100~211；W 侧只有带 SDP 的 re-INVITE，
        # D 侧只剩 BYE）
        (0xC1, 63683, 22840, 100, 211, 9000, W, SERVER, 8, 0.02),
        (0xC2, 22840, 63683, 100, 211, 800, SERVER, W, 0, 0.02),
        (0xC3, 44058, 16848, 100, 211, 11000, D, SERVER, 8, 0.02),
        (0xC4, 16848, 44058, 100, 211, 900, SERVER, D, 0, 0.02),
        # 通话 B（完整新通话：INVITE 156，媒体 157~225）
        (0xB1, 49666, 20146, 157, 224.8, 0, Y, SERVER, 8, 0.02),
        (0xB2, 20146, 49666, 157, 224.8, 0, SERVER, Y, 8, 0.02),
        (0xB3, 64076, 30028, 162.8, 225, 0, Z, SERVER, 0, 0.02),
        (0xB4, 30028, 64076, 162.8, 225, 0, SERVER, Z, 0, 0.02),
    ]
    sip = [
        # A 的半截信令：两侧腿各一条 BYE 事务
        ev(121.2, 'BYE', 'a-y', 99, Y, SERVER),
        ev(121.25, '200', 'a-y', 99, SERVER, Y),
        ev(121.3, 'BYE', 'a-z', 99, Z, SERVER),
        ev(121.35, '200', 'a-z', 99, SERVER, Z),
        # C 的半截信令：W 侧 re-INVITE（SDP 宣告本侧 FS 端口），D 侧只剩 BYE
        ev(142, 'INVITE', 'c-w', 50, SERVER, W,
           sdp=_sdp([(SERVER, 22840)], audio='PCMA')),
        ev(142.5, '200', 'c-w', 50, W, SERVER,
           sdp=_sdp([(W, 63683)], audio='PCMA')),
        ev(211.2, 'BYE', 'c-d', 51, D, SERVER),
        ev(211.25, '200', 'c-d', 51, SERVER, D),
        # B 的完整信令（B2BUA 两腿各一个 Call-ID）
        ev(156, 'INVITE', 'b-y', 1, Y, SERVER, sdp=_sdp([(Y, 49666)])),
        ev(157, '200', 'b-y', 1, SERVER, Y, sdp=_sdp([(SERVER, 20146)])),
        ev(157, 'INVITE', 'b-z', 1, SERVER, Z, sdp=_sdp([(SERVER, 30028)])),
        ev(162, '200', 'b-z', 1, Z, SERVER, sdp=_sdp([(Z, 64076)])),
        ev(224, 'BYE', 'b-y', 2, Y, SERVER),
        ev(224.25, '200', 'b-y', 2, SERVER, Y),
        ev(224.5, 'BYE', 'b-z', 2, SERVER, Z),
        ev(225, '200', 'b-z', 2, Z, SERVER),
    ]
    rd = make_rtp_data(streams, 100, 300, sip_events=sip)
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 3, f"expected 3 calls, got {len(calls)}"
    a = next(c for c in calls if 'a-y' in (c.get('sip_call_ids') or []))
    c = next(c for c in calls if 'c-w' in (c.get('sip_call_ids') or []))
    b = next(c for c in calls if 'b-y' in (c.get('sip_call_ids') or []))
    assert set(a['sip_call_ids']) == {'a-y', 'a-z'}, a['sip_call_ids']
    assert set(c['sip_call_ids']) == {'c-w', 'c-d'}, c['sip_call_ids']
    assert set(b['sip_call_ids']) == {'b-y', 'b-z'}, b['sip_call_ids']
    assert set(a['ssrcs']) == {0xA1, 0xA2, 0xA3, 0xA4}, a['ssrcs']
    assert set(c['ssrcs']) == {0xC1, 0xC2, 0xC3, 0xC4}, c['ssrcs']
    assert set(b['ssrcs']) == {0xB1, 0xB2, 0xB3, 0xB4}, b['ssrcs']
    # A/C 缺头（上行 seq 非零、无开头 INVITE）、挂断已抓到；B 完整
    assert a['completeness']['status'] == 'truncated_head', a['completeness']
    assert c['completeness']['status'] == 'truncated_head', c['completeness']
    assert b['completeness']['status'] == 'complete', b['completeness']
    # A 的信令只有两条 BYE 事务；B 的信令从 INVITE 到自己的 BYE 为止
    assert [m['method'] for m in a['sip_flow']] == ['BYE', '200', 'BYE', '200']
    assert b['sip_flow'][0]['method'] == 'INVITE'
    assert [m['method'] for m in b['sip_flow'][-2:]] == ['BYE', '200']
    print("PASS: pre-existing tail call + truncated call + full call separated")


def _b2bua_relay_events(cid_a, cid_b, caller, term_port, fs_a_ports, seat_port,
                        fs_b_ports, t_inv, t_bye):
    """真实 B2BUA 的两腿信令：A 腿（主叫↔FS）与 B 腿（FS↔被叫）是两个
    Call-ID，各自只宣告本侧端点——FS 的中继端口宣告在对应腿的 SDP 里。"""
    return [
        {'time': t_inv, 'method': 'INVITE', 'call_id': cid_a, 'cseq': 1,
         'cseq_method': 'INVITE', 'src': caller, 'dst': SERVER,
         'sdp': _sdp([(caller, term_port)])},
        {'time': t_inv + 1, 'method': '200', 'call_id': cid_a, 'cseq': 1,
         'cseq_method': 'INVITE', 'src': SERVER, 'dst': caller,
         'sdp': _sdp([(SERVER, fs_a_ports[0]), (SERVER, fs_a_ports[1])])},
        {'time': t_inv + 1, 'method': 'INVITE', 'call_id': cid_b, 'cseq': 1,
         'cseq_method': 'INVITE', 'src': SERVER, 'dst': SEAT,
         'sdp': _sdp([(SERVER, fs_b_ports[0]), (SERVER, fs_b_ports[1])])},
        {'time': t_inv + 5, 'method': '200', 'call_id': cid_b, 'cseq': 1,
         'cseq_method': 'INVITE', 'src': SEAT, 'dst': SERVER,
         'sdp': _sdp([(SEAT, seat_port)])},
        {'time': t_bye, 'method': 'BYE', 'call_id': cid_a, 'cseq': 2,
         'cseq_method': 'BYE', 'src': caller, 'dst': SERVER},
        {'time': t_bye + 0.5, 'method': 'BYE', 'call_id': cid_b, 'cseq': 2,
         'cseq_method': 'BYE', 'src': SERVER, 'dst': SEAT},
    ]


def test_sequential_b2bua_calls_split_with_bridge_streams():
    """先后两通 B2BUA 电话被一条横跨两通的 FS 录音流桥接并成一通：录音流共
    享 FS IP 且与两通都时间重叠，BYE 后面跟着下一通的 INVITE。半呼叫配对
    （A/B 腿媒体并发、端点 ≤2）拆回两通，各通信令到自己的 BYE 为止。"""
    term2 = '10.0.0.4'
    streams = [
        # 通话 1（105-155）：终端 1 ↔ FS、坐席 ↔ FS
        (0xAA11, 7080, 34576, 105, 155, 0, TERM, SERVER, 0, 0.02),
        (0xAA12, 34578, 7080, 105, 155, 0, SERVER, TERM, 0, 0.02),
        (0xAA13, 6000, 34580, 108, 152, 8, SEAT, SERVER, 0, 0.02),
        (0xAA14, 34582, 6000, 108, 152, 8, SERVER, SEAT, 0, 0.02),
        # 通话 2（175-235）：终端 2 ↔ FS、坐席（复用 6000 端口）↔ FS
        (0xBB11, 7084, 34600, 175, 235, 0, term2, SERVER, 0, 0.02),
        (0xBB12, 34602, 7084, 175, 235, 0, SERVER, term2, 0, 0.02),
        (0xBB13, 6000, 34604, 178, 232, 8, SEAT, SERVER, 0, 0.02),
        (0xBB14, 34606, 6000, 178, 232, 8, SERVER, SEAT, 0, 0.02),
        # 桥接流：FS → 录音/等待音服务器，横跨两通电话
        (0xCC11, 40000, 50000, 95, 265, 0, SERVER, '10.0.0.5', 0, 0.02),
        (0xCC12, 40002, 50002, 95, 265, 0, SERVER, '10.0.0.5', 0, 0.02),
    ]
    sip = (_b2bua_relay_events('a1', 'a2', TERM, 7080, (34576, 34578), 6000,
                               (34580, 34582), 95, 160)
           + _b2bua_relay_events('b1', 'b2', term2, 7084, (34600, 34602), 6000,
                                 (34604, 34606), 170, 240))
    rd = make_rtp_data(streams, 90, 300, sip_events=sip)
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 3, f"expected 2 calls + bridge call, got {len(calls)}"
    c1 = next(c for c in calls if 'a1' in (c.get('sip_call_ids') or []))
    c2 = next(c for c in calls if 'b1' in (c.get('sip_call_ids') or []))
    bridge = next(c for c in calls if not (c.get('sip_call_ids') or []))
    assert set(c1['ssrcs']) == {0xAA11, 0xAA12, 0xAA13, 0xAA14}, c1['ssrcs']
    assert set(c2['ssrcs']) == {0xBB11, 0xBB12, 0xBB13, 0xBB14}, c2['ssrcs']
    assert set(bridge['ssrcs']) == {0xCC11, 0xCC12}
    # 关键回归点：每通的信令到自己的 BYE 为止，BYE 之后没有另一通的 INVITE
    for c in (c1, c2):
        flow = c['sip_flow']
        first_bye = next(i for i, m in enumerate(flow) if m['method'] == 'BYE')
        assert all(m['method'] != 'INVITE' for m in flow[first_bye:]), \
            [m['method'] for m in flow[first_bye:]]
    print("PASS: sequential B2BUA calls bridged by a recording stream split; "
          "no INVITE after BYE")


def make_sdp(audio=None, video=None):
    """构造带编码身份（full）的 SDP dict，模拟 _parse_sdp_codecs 输出。

    元素为 'PCMU'（仅名字，时钟率未知）或 ('OPUS', 48000)（名字+时钟率）。
    """
    def ident(item):
        return {'name': item[0], 'rate': item[1]} if isinstance(item, tuple) \
            else {'name': item, 'rate': None}

    audio, video = audio or [], video or []
    return {
        'audio': [i['name'] for i in map(ident, audio)],
        'video': [i['name'] for i in map(ident, video)],
        'map': {'audio': {}, 'video': {}},
        'full': {'audio': list(map(ident, audio)),
                 'video': list(map(ident, video))},
    }


def make_sip_event(time, method, cid, cseq, src, dst, sdp=None,
                   cseq_method=None):
    return {'time': time, 'method': method, 'reason': '', 'call_id': cid,
            'cseq': cseq, 'cseq_method': cseq_method or method,
            'src': src, 'dst': dst, 'from': {}, 'to': {}, 'sdp': sdp or {}}


def test_fs_media_transcode_between_legs():
    """FS 是否参与编解码：B2BUA 两腿协商编码不同 → transcode（必然转码）。

    A 腿（主叫↔FS）协商 PCMU、B 腿（FS↔被叫）协商 G729，媒体又经 FS 转发，
    FS 必须解码再编码。协商编码行展示主叫腿结果，不被被叫腿 offer 污染。
    """
    events = [
        make_sip_event(95, 'INVITE', 'a', 1, SEAT, SERVER,
                       sdp=make_sdp(audio=['PCMU'])),
        make_sip_event(98, '200', 'a', 1, SERVER, SEAT,
                       sdp=make_sdp(audio=['PCMU']), cseq_method='INVITE'),
        make_sip_event(96, 'INVITE', 'b', 1, SERVER, TERM,
                       sdp=make_sdp(audio=['G729'])),
        make_sip_event(100, '200', 'b', 1, TERM, SERVER,
                       sdp=make_sdp(audio=['G729']), cseq_method='INVITE'),
        make_sip_event(165, 'BYE', 'a', 2, SEAT, SERVER),
    ]
    rd = make_rtp_data([
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 0, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 0, 0.02),
        (0x1113, 7000, 8000, 100, 160, 0, TERM, SERVER, 18, 0.02),
        (0x1114, 8000, 7000, 100, 160, 0, SERVER, TERM, 18, 0.02),
    ], 90, 200, sip_events=events)
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 1
    fm = calls[0]['fs_media']
    assert fm['verdict'] == 'transcode', fm
    assert 'PCMU' in fm['text'] and 'G729' in fm['text'], fm
    assert calls[0]['negotiated_codecs'] == {'audio': ['PCMU'], 'video': []}
    # per-leg 协商结果两条腿都导出（主叫侧/被叫侧各一份，前端分两行展示，
    # call_id 供前端把该腿协商行锚到该腿应答行之后）
    npl = calls[0]['negotiated_per_leg']
    assert npl['caller'] == {'audio': ['PCMU'], 'video': [], 'answered': True,
                             'call_id': 'a'}, npl
    assert npl['callee'] == {'audio': ['G729'], 'video': [], 'answered': True,
                             'call_id': 'b'}, npl
    # 每条信令消息也带 call_id（前端按腿锚定用）
    assert all(m.get('call_id') in ('a', 'b') for m in calls[0]['sip_flow'])
    print("PASS: FS transcode detected (leg A PCMU vs leg B G729)")


def test_fs_media_same_codec():
    """两腿协商编码相同 → same（FS 在媒体路径但无需转码）。"""
    events = [
        make_sip_event(95, 'INVITE', 'a', 1, SEAT, SERVER,
                       sdp=make_sdp(audio=['PCMA'])),
        make_sip_event(98, '200', 'a', 1, SERVER, SEAT,
                       sdp=make_sdp(audio=['PCMA']), cseq_method='INVITE'),
        make_sip_event(96, 'INVITE', 'b', 1, SERVER, TERM,
                       sdp=make_sdp(audio=['PCMA'])),
        make_sip_event(100, '200', 'b', 1, TERM, SERVER,
                       sdp=make_sdp(audio=['PCMA']), cseq_method='INVITE'),
        make_sip_event(165, 'BYE', 'a', 2, SEAT, SERVER),
    ]
    rd = make_rtp_data([
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
        (0x1113, 7000, 8000, 100, 160, 0, TERM, SERVER, 8, 0.02),
        (0x1114, 8000, 7000, 100, 160, 0, SERVER, TERM, 8, 0.02),
    ], 90, 200, sip_events=events)
    calls = detect_calls({'fs': rd}, SERVER)
    fm = calls[0]['fs_media']
    assert fm['verdict'] == 'same', fm
    assert 'PCMA' in fm['text'], fm
    npl = calls[0]['negotiated_per_leg']
    assert npl['caller']['audio'] == ['PCMA'] and npl['callee']['audio'] == ['PCMA'], npl
    print("PASS: same codec on both legs -> FS no transcode")


def test_fs_media_bypass():
    """媒体不经 FS（点对点/bypass media）→ FS 不在媒体路径，未参与编解码。"""
    events = [
        make_sip_event(95, 'INVITE', 'a', 1, SEAT, TERM,
                       sdp=make_sdp(audio=['PCMU'])),
        make_sip_event(98, '200', 'a', 1, TERM, SEAT,
                       sdp=make_sdp(audio=['PCMU']), cseq_method='INVITE'),
        make_sip_event(165, 'BYE', 'a', 2, SEAT, TERM),
    ]
    direct = [
        (0x1111, 52375, 50192, 100, 160, 0, SEAT, TERM, 0, 0.02),
        (0x1112, 50192, 52375, 100, 160, 0, TERM, SEAT, 0, 0.02),
    ]
    calls = detect_calls({'seat': make_rtp_data(direct, 90, 200, sip_events=events),
                          'terminal': make_rtp_data(direct, 90, 200)},
                         SERVER)
    assert calls[0]['is_p2p']
    fm = calls[0]['fs_media']
    assert fm['verdict'] == 'bypass', fm
    print("PASS: direct media -> FS not in media path")


def test_fs_media_unknown_single_leg():
    """只抓到一条腿的协商编码（无被叫侧信令）→ 如实标注无法判定。"""
    events = [
        make_sip_event(95, 'INVITE', 'a', 1, SEAT, SERVER,
                       sdp=make_sdp(audio=['PCMA'])),
        make_sip_event(98, '200', 'a', 1, SERVER, SEAT,
                       sdp=make_sdp(audio=['PCMA']), cseq_method='INVITE'),
        make_sip_event(165, 'BYE', 'a', 2, SEAT, SERVER),
    ]
    rd = make_rtp_data([
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 8, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 8, 0.02),
    ], 90, 200, sip_events=events)
    calls = detect_calls({'seat': rd}, SERVER)
    fm = calls[0]['fs_media']
    assert fm['verdict'] == 'unknown', fm
    # 只有主叫腿有 SDP：per-leg 只有 caller 一份，被叫侧缺失
    npl = calls[0]['negotiated_per_leg']
    assert 'caller' in npl and 'callee' not in npl, npl
    print("PASS: single-leg SDP -> verdict unknown (honest)")


def test_fs_media_clock_rate_mismatch():
    """同名字不同时钟率（OPUS/48000 vs OPUS/16000）是不同编码 → transcode；
    一侧时钟率未知时按名字相等视为同种编码 → same。"""
    base = [
        make_sip_event(95, 'INVITE', 'a', 1, SEAT, SERVER,
                       sdp=make_sdp(audio=[('OPUS', 48000)])),
        make_sip_event(98, '200', 'a', 1, SERVER, SEAT,
                       sdp=make_sdp(audio=[('OPUS', 48000)]),
                       cseq_method='INVITE'),
        make_sip_event(96, 'INVITE', 'b', 1, SERVER, TERM,
                       sdp=make_sdp(audio=[('OPUS', 16000)])),
        make_sip_event(100, '200', 'b', 1, TERM, SERVER,
                       sdp=make_sdp(audio=[('OPUS', 16000)]),
                       cseq_method='INVITE'),
        make_sip_event(165, 'BYE', 'a', 2, SEAT, SERVER),
    ]
    rd = make_rtp_data([
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 96, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 96, 0.02),
        (0x1113, 7000, 8000, 100, 160, 0, TERM, SERVER, 96, 0.02),
        (0x1114, 8000, 7000, 100, 160, 0, SERVER, TERM, 96, 0.02),
    ], 90, 200, sip_events=base)
    calls = detect_calls({'fs': rd}, SERVER)
    fm = calls[0]['fs_media']
    assert fm['verdict'] == 'transcode', fm
    assert '48000' in fm['text'] and '16000' in fm['text'], fm
    print("PASS: clock-rate mismatch (OPUS 48k vs 16k) -> transcode")

    # 被叫腿 SDP 无时钟率（旧格式/FS 自产静态 PT）：名字相同即不判转码
    events = [base[0], base[1],
              make_sip_event(96, 'INVITE', 'b', 1, SERVER, TERM,
                             sdp=make_sdp(audio=['OPUS'])),
              make_sip_event(100, '200', 'b', 1, TERM, SERVER,
                             sdp=make_sdp(audio=['OPUS']),
                             cseq_method='INVITE'),
              base[4]]
    rd2 = make_rtp_data([
        (0x1111, 5000, 6000, 100, 160, 0, SEAT, SERVER, 96, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, SEAT, 96, 0.02),
        (0x1113, 7000, 8000, 100, 160, 0, TERM, SERVER, 96, 0.02),
        (0x1114, 8000, 7000, 100, 160, 0, SERVER, TERM, 96, 0.02),
    ], 90, 200, sip_events=events)
    calls = detect_calls({'fs': rd2}, SERVER)
    fm = calls[0]['fs_media']
    assert fm['verdict'] == 'same', fm
    print("PASS: unknown rate on one side falls back to name match -> same")


def test_call_party_pair_unanswered_callee_fallback():
    """未接通的通话（CANCEL/487 收场，无 INVITE 的 200 OK）：被叫取信令对端
    兜底，不因缺 200 OK 而丢失；接通通话的判定不受影响。"""
    from analyzer.call_detector import _call_party_pair
    flow = [
        {'method': 'INVITE', 'kind': 'request', 'src': SERVER, 'dst': TERM,
         'from': {}, 'to': {}},
        {'method': '180', 'kind': 'provisional', 'src': TERM, 'dst': SERVER,
         'from': {}, 'to': {}},
        {'method': 'CANCEL', 'kind': 'request', 'src': SERVER, 'dst': TERM,
         'from': {}, 'to': {}},
        # CANCEL 的 200（cseq 不符）与 487 都不能当接听确认
        {'method': '200', 'kind': 'success', 'cseq_method': 'CANCEL',
         'src': TERM, 'dst': SERVER, 'from': {}, 'to': {}},
        {'method': '487', 'kind': 'failure', 'cseq_method': 'INVITE',
         'src': TERM, 'dst': SERVER, 'from': {}, 'to': {}},
        {'method': 'ACK', 'kind': 'request', 'src': SERVER, 'dst': TERM,
         'from': {}, 'to': {}},
    ]
    assert _call_party_pair(flow, SERVER) == (SERVER, TERM)
    answered = flow[:2] + [
        {'method': '200', 'kind': 'success', 'cseq_method': 'INVITE',
         'src': TERM, 'dst': SERVER, 'from': {}, 'to': {}},
        {'method': 'ACK', 'kind': 'request', 'src': SERVER, 'dst': TERM,
         'from': {}, 'to': {}},
    ]
    assert _call_party_pair(answered, SERVER) == (SERVER, TERM)
    print("PASS: unanswered call callee via peer fallback in party pair")


def test_nat_call_merge_and_alias_downlink():
    """NAT 场景（主叫 SDP 宣告私网地址、RTP 从公网地址发来）：

    主叫同一台设备在媒体层出现两个 IP——SDP 宣告的私网 IP（FS 下行发往
    它）+ 实际上行的公网 IP。旧版设备计数按 IP 直数出 3 台"设备"，A/B
    两个半呼叫拒绝合并，一通电话被拆成两通。现在按"共享同一端点的腿另一
    侧 IP 归并为同一设备"计数后正确并回一通；FS 发往私网地址的下行也归并
    回主叫设备，并给出 rtp-auto-adjust 配置提示。
    """
    from analyzer.media_extractor import extract_call_parties, _party_label

    TERM_PUB, TERM_PRIV = '172.110.249.67', '10.22.68.170'
    streams = [
        # 主叫上行：RTP 实际从 NAT 公网地址发往 FS 的 A 腿媒体端口
        (0x1111, 10002, 22532, 100, 160, 0, TERM_PUB, SERVER, 0, 0.02),
        # FS 下行：发往主叫 SDP 宣告的私网地址
        (0x1112, 22532, 10002, 100, 160, 0, SERVER, TERM_PRIV, 0, 0.02),
        # 被叫腿（无 NAT，上下行同端口对）
        (0x1113, 6000, 22632, 100, 160, 0, SEAT, SERVER, 0, 0.02),
        (0x1114, 22632, 6000, 100, 160, 0, SERVER, SEAT, 0, 0.02),
    ]
    sip = [
        make_sip_event(95, 'INVITE', 'a', 1, TERM_PUB, SERVER,
                       sdp=_sdp([(TERM_PRIV, 10002)])),
        make_sip_event(99, '200', 'a', 1, SERVER, TERM_PUB,
                       sdp=_sdp([(SERVER, 22532)]), cseq_method='INVITE'),
        make_sip_event(96, 'INVITE', 'b', 1, SERVER, SEAT,
                       sdp=_sdp([(SERVER, 22632)])),
        make_sip_event(100, '200', 'b', 1, SEAT, SERVER,
                       sdp=_sdp([(SEAT, 6000)]), cseq_method='INVITE'),
        make_sip_event(165, 'BYE', 'a', 2, TERM_PUB, SERVER),
        make_sip_event(165.5, 'BYE', 'b', 2, SERVER, SEAT),
    ]
    rd = make_rtp_data(streams, 90, 200, sip_events=sip)
    rd['ips'] = {SERVER, TERM_PUB, TERM_PRIV, SEAT}
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 1, f"NAT call split into {len(calls)} calls"
    call = calls[0]
    assert set(call['sip_call_ids']) == {'a', 'b'}, call['sip_call_ids']
    assert call['stream_count'] == 4, call['ssrcs']
    assert call['completeness']['status'] == 'complete'

    # 各腿 SDP 宣告的非服务器 IP 按腿角色导出：主叫腿宣告了私网别名
    assert call['sdp_party_ips'] == {'caller': [TERM_PRIV], 'callee': [SEAT]}, \
        call['sdp_party_ips']

    # FS 发往私网地址的下行归并回主叫设备（不再是"幻影设备"零下行）
    relay = call['fs_relay']
    assert relay['available'] and relay['verdict'] == 'relayed', relay
    caller_dev = next(d for d in relay['devices'] if d['ip'] == TERM_PUB)
    assert caller_dev['downlink']['audio']['pkts'] > 0, caller_dev
    nat_notes = [n for n in relay['notes'] if 'rtp-auto-adjust' in n]
    assert nat_notes and TERM_PRIV in nat_notes[0] and TERM_PUB in nat_notes[0], \
        relay['notes']

    # 媒体清单侧：私网地址标注为主叫的别名地址，不再出现"未知 IP"
    parties = extract_call_parties(call, SERVER)
    assert parties['caller_alt_ips'] == [TERM_PRIV], parties
    assert parties['answerer_alt_ips'] == [], parties
    assert _party_label(TERM_PRIV, parties, SERVER, {}) == '主叫', \
        _party_label(TERM_PRIV, parties, SERVER, {})

    # 信令流程带 SDP 协商媒体：主叫 INVITE 宣告的私网地址不在消息双方信令
    # IP 之内 → 标 NAT 并给出归属与 RTP 实际来源；FS 应答宣告自己的媒体
    # 地址不误标
    inv_a = next(m for m in call['sip_flow'] if m['method'] == 'INVITE'
                 and m.get('call_id') == 'a')
    assert inv_a['sdp_media'] == [
        {'kind': 'audio', 'addr': TERM_PRIV, 'port': 10002,
         'nat': True, 'owner': '主叫', 'via_ip': TERM_PUB}], inv_a['sdp_media']
    ok_a = next(m for m in call['sip_flow'] if m['method'] == '200'
                and m.get('call_id') == 'a')
    assert ok_a['sdp_media'] == [
        {'kind': 'audio', 'addr': SERVER, 'port': 22532}], ok_a['sdp_media']
    print("PASS: NAT call merged into one; alias downlink folded to caller; "
          "alt-IP labeled as caller")


def test_fs_relay_partial_downlink():
    """单向转发缺失（partial_downlink）：FS 收到被叫音频上行却 0 回发，
    判定链排在 partial_uplink 之后、relayed 之前，结论指向 FS 侧发送通道
    （bridge / write codec），明确"不是网络问题"。"""
    streams = [
        (0x1111, 5000, 6000, 100, 160, 0, TERM, SERVER, 0, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, TERM, 0, 0.02),
        # 被叫音频只有上行；FS → 被叫的音频下行整通 0 包
        (0x1113, 7000, 8000, 100, 160, 0, SEAT, SERVER, 0, 0.02),
    ]
    sip = [
        make_sip_event(95, 'INVITE', 'a', 1, TERM, SERVER,
                       sdp=make_sdp(audio=['PCMU'])),
        make_sip_event(99, '200', 'a', 1, SERVER, TERM,
                       sdp=make_sdp(audio=['PCMU']), cseq_method='INVITE'),
        make_sip_event(96, 'INVITE', 'b', 1, SERVER, SEAT,
                       sdp=make_sdp(audio=['PCMU'])),
        make_sip_event(100, '200', 'b', 1, SEAT, SERVER,
                       sdp=make_sdp(audio=['PCMU']), cseq_method='INVITE'),
        make_sip_event(165, 'BYE', 'a', 2, TERM, SERVER),
        make_sip_event(165.5, 'BYE', 'b', 2, SERVER, SEAT),
    ]
    rd = make_rtp_data(streams, 90, 200, sip_events=sip)
    rd['ips'] = {SERVER, TERM, SEAT}
    calls = detect_calls({'fs': rd}, SERVER)
    assert len(calls) == 1, f"expected 1 call, got {len(calls)}"
    relay = calls[0]['fs_relay']
    assert relay['available'] and relay['verdict'] == 'partial_downlink', relay
    seat_dev = next(d for d in relay['devices'] if d['ip'] == SEAT)
    term_dev = next(d for d in relay['devices'] if d['ip'] == TERM)
    assert seat_dev['uplink']['audio']['pkts'] > 0, seat_dev
    assert seat_dev['downlink']['audio']['pkts'] == 0, seat_dev
    assert term_dev['downlink']['audio']['pkts'] > 0, term_dev
    assert '缺音频下发' in relay['headline'] and SEAT in relay['headline'], \
        relay['headline']
    assert 'uuid_dump' in relay['advice'] and '不是网络问题' in relay['advice'], \
        relay['advice']
    # 下行来源核对提示仍如实记录该方向未发生转发
    assert any('该方向未发生转发' in n for n in relay['notes']), relay['notes']
    print("PASS: FS uplink-with-no-downlink -> verdict partial_downlink "
          "pointing at FS send path")


def test_partial_downlink_not_when_partial_uplink():
    """判定优先级：只有部分端点有上行时仍是 partial_uplink（缺上行本身
    已解释缺下行），不叠加 partial_downlink 结论。"""
    streams = [
        (0x1111, 5000, 6000, 100, 160, 0, TERM, SERVER, 0, 0.02),
        (0x1112, 6000, 5000, 100, 160, 0, SERVER, TERM, 0, 0.02),
        # 被叫整通无任何 RTP：partial_uplink，而不是 partial_downlink
    ]
    sip = [
        make_sip_event(95, 'INVITE', 'a', 1, TERM, SERVER,
                       sdp=make_sdp(audio=['PCMU'])),
        make_sip_event(99, '200', 'a', 1, SERVER, TERM,
                       sdp=make_sdp(audio=['PCMU']), cseq_method='INVITE'),
        make_sip_event(96, 'INVITE', 'b', 1, SERVER, SEAT,
                       sdp=make_sdp(audio=['PCMU'])),
        make_sip_event(100, '200', 'b', 1, SEAT, SERVER,
                       sdp=make_sdp(audio=['PCMU']), cseq_method='INVITE'),
        make_sip_event(165, 'BYE', 'a', 2, TERM, SERVER),
        make_sip_event(165.5, 'BYE', 'b', 2, SERVER, SEAT),
    ]
    rd = make_rtp_data(streams, 90, 200, sip_events=sip)
    rd['ips'] = {SERVER, TERM}
    calls = detect_calls({'fs': rd}, SERVER)
    relay = calls[0]['fs_relay']
    assert relay['verdict'] == 'partial_uplink', relay
    print("PASS: callee with no RTP at all stays partial_uplink")


if __name__ == '__main__':
    test_two_sequential_calls()
    test_port_reuse_same_ports()
    test_truncated_head()
    test_truncated_tail()
    test_truncated_both()
    test_edge_gap_without_seq_signal()
    test_cross_file_merge()
    test_sip_flow_association_and_dedupe()
    test_back_to_back_calls_no_signaling_bleed()
    test_sip_from_to_parsing()
    test_sip_sdp_parsing()
    test_concurrent_calls_limitation()
    test_capture_consistency_mismatch()
    test_p2p_direct_call_hint()
    test_negotiated_codecs()
    test_sip_source_priority_and_retrans_dedupe()
    test_concurrent_calls_split_by_sdp()
    test_foreign_stream_evicted_from_call()
    test_party_filter_without_sdp()
    test_preexisting_calls_with_tail_signaling_separate()
    test_sequential_b2bua_calls_split_with_bridge_streams()
    test_fs_media_transcode_between_legs()
    test_fs_media_same_codec()
    test_fs_media_bypass()
    test_fs_media_unknown_single_leg()
    test_fs_media_clock_rate_mismatch()
    test_call_party_pair_unanswered_callee_fallback()
    test_nat_call_merge_and_alias_downlink()
    test_fs_relay_partial_downlink()
    test_partial_downlink_not_when_partial_uplink()
    print("\n=== ALL CALL DETECTOR TESTS PASSED ===")
