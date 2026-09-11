"""
Unit tests for call_detector: multi-call grouping and completeness states.

Run: python3 tests/test_call_detector.py
"""
import os
import sys

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
    }, ev['sdp']

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
    assert by_role['seat']['display'] == '坐席端'
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
    test_sip_source_priority_and_retrans_dedupe()
    print("\n=== ALL CALL DETECTOR TESTS PASSED ===")
