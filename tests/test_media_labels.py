"""
Unit tests for media party labeling: who-to-whom annotation of media streams.

Run: python3 tests/test_media_labels.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzer.media_extractor import (
    describe_media_parties, extract_call_parties, _ident_label,
)

SERVER = '10.0.0.1'
SEAT = '10.0.0.2'
TERM = '10.0.0.3'

CALLER_IDENT = {'name': '张三', 'user': '1001', 'host': TERM}
CALLEE_IDENT = {'name': '李四', 'user': '1002', 'host': SEAT}


def make_sip_flow(server_ip=SERVER):
    """A-leg (terminal->FS) + B-leg (FS->seat) INVITE transaction."""
    return [
        {'method': 'INVITE', 'kind': 'request', 'src': TERM, 'dst': server_ip,
         'from': CALLER_IDENT, 'to': {'name': '', 'user': '1002', 'host': server_ip}},
        {'method': '100', 'kind': 'provisional', 'src': server_ip, 'dst': TERM,
         'from': {}, 'to': {}},
        {'method': 'INVITE', 'kind': 'request', 'src': server_ip, 'dst': SEAT,
         'from': {'name': '', 'user': '1001', 'host': server_ip}, 'to': CALLEE_IDENT},
        {'method': '200', 'kind': 'success', 'cseq_method': 'INVITE',
         'src': SEAT, 'dst': server_ip, 'from': CALLER_IDENT, 'to': CALLEE_IDENT},
        {'method': '200', 'kind': 'success', 'cseq_method': 'INVITE',
         'src': server_ip, 'dst': TERM, 'from': CALLER_IDENT, 'to': CALLEE_IDENT},
        {'method': 'ACK', 'kind': 'request', 'src': TERM, 'dst': server_ip,
         'from': CALLER_IDENT, 'to': CALLEE_IDENT},
        {'method': 'BYE', 'kind': 'request', 'src': TERM, 'dst': server_ip,
         'from': CALLER_IDENT, 'to': CALLEE_IDENT},
    ]


def make_call(ssrcs, flow):
    return {'call_id': 'call_1', 'ssrcs': ssrcs, 'sip_flow': flow}


def make_manifest(entries):
    manifest = {'call_id': 'call_1', 'audio': [], 'video': [], 'unsupported': []}
    for kind, role, ssrc, pairs, direction in entries:
        entry = {'role': role, 'ssrc': f'0x{ssrc:08x}', 'codec': 'PCMU'}
        if direction:
            entry['direction'] = direction
        manifest[kind].append(entry)
    return manifest


def make_captures(pairs_by_role_ssrc):
    """{role: {'streams': {ssrc: {'port_pairs': [[src, sport, dst, dport]]}}}}"""
    captures = {}
    for role, ssrc, pairs in pairs_by_role_ssrc:
        captures.setdefault(role, {'streams': {}})
        captures[role]['streams'][ssrc] = {'port_pairs': pairs}
    return captures


FILES_INFO = [
    {'role': 'fs', 'ips': [SERVER, SEAT, TERM]},
    {'role': 'seat', 'ips': [SEAT, SERVER]},
    {'role': 'terminal', 'ips': [TERM, SERVER]},
]


def test_fs_streams_labeled_with_caller_callee():
    """FS 端 4 条音频流：每条标注 主叫/FS/被叫 之间的真实收发方。"""
    call = make_call([0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD], make_sip_flow())
    captures = make_captures([
        # 主叫上行（终端 -> FS）
        ('fs', 0xAAAA, [[TERM, 7080, SERVER, 34576]]),
        # FS -> 终端 下行
        ('fs', 0xBBBB, [[SERVER, 34578, TERM, 7080]]),
        # 被叫上行（坐席 -> FS）
        ('fs', 0xCCCC, [[SEAT, 6000, SERVER, 34580]]),
        # FS -> 坐席 下行
        ('fs', 0xDDDD, [[SERVER, 34582, SEAT, 6000]]),
    ])
    manifest = make_manifest([
        ('audio', 'fs', 0xAAAA, None, 'inbound'),
        ('audio', 'fs', 0xBBBB, None, 'outbound'),
        ('audio', 'fs', 0xCCCC, None, 'inbound'),
        ('audio', 'fs', 0xDDDD, None, 'outbound'),
    ])
    describe_media_parties(manifest, captures, [call], SERVER, FILES_INFO)

    flows = {e['ssrc']: e['flow'] for e in manifest['audio']}
    assert flows['0x0000aaaa'] == {
        'from': {'label': '主叫 张三（1001）', 'ip': TERM},
        'to': {'label': 'FS', 'ip': SERVER}}, flows['0x0000aaaa']
    assert flows['0x0000bbbb']['from']['label'] == 'FS'
    assert flows['0x0000bbbb']['to']['label'] == '主叫 张三（1001）'
    assert flows['0x0000cccc'] == {
        'from': {'label': '被叫 李四（1002）', 'ip': SEAT},
        'to': {'label': 'FS', 'ip': SERVER}}, flows['0x0000cccc']
    assert flows['0x0000dddd']['from']['label'] == 'FS'
    assert flows['0x0000dddd']['to']['label'] == '被叫 李四（1002）'

    # 拓扑行：主叫 ↔ FS ↔ 被叫
    assert len(manifest['parties']) == 1
    p = manifest['parties'][0]
    assert p['caller']['label'] == '主叫 张三（1001）' and p['caller']['ip'] == TERM
    assert p['server_ip'] == SERVER
    assert p['answerer']['label'] == '被叫 李四（1002）' and p['answerer']['ip'] == SEAT
    print("PASS: FS-side streams labeled caller/FS/callee with real directions")


def test_endpoint_captures_share_ssrc_labels():
    """同一 SSRC 在坐席/终端抓包里：标注相对各自抓包点的收发方。"""
    call = make_call([0xAAAA, 0xDDDD], make_sip_flow())
    captures = make_captures([
        # FS -> 坐席 下行，在坐席端抓到（src=server -> 呼入）
        ('seat', 0xDDDD, [[SERVER, 34582, SEAT, 6000]]),
        # 终端上行，在终端端抓到（dst=server -> 呼出）
        ('terminal', 0xAAAA, [[TERM, 7080, SERVER, 34576]]),
    ])
    manifest = make_manifest([
        ('audio', 'seat', 0xDDDD, None, 'inbound'),
        ('audio', 'terminal', 0xAAAA, None, 'outbound'),
    ])
    describe_media_parties(manifest, captures, [call], SERVER, FILES_INFO)

    seat = manifest['audio'][0]['flow']
    assert seat['from'] == {'label': 'FS', 'ip': SERVER}
    assert seat['to'] == {'label': '被叫 李四（1002）', 'ip': SEAT}

    term = manifest['audio'][1]['flow']
    assert term['from'] == {'label': '主叫 张三（1001）', 'ip': TERM}
    assert term['to'] == {'label': 'FS', 'ip': SERVER}
    print("PASS: endpoint captures label their own receive/send side")


def test_fallback_without_sip_flow():
    """无信令时退化为抓包角色名；FS 抓包里的陌生 IP 显示原始 IP。"""
    call = make_call([0xAAAA, 0xCCCC], [])
    captures = make_captures([
        ('terminal', 0xAAAA, [[TERM, 7080, SERVER, 34576]]),
        ('seat', 0xCCCC, [[SEAT, 6000, SERVER, 34580]]),
        ('fs', 0xEEEE, [['10.9.9.9', 7080, SERVER, 34584]]),
    ])
    manifest = make_manifest([
        ('audio', 'terminal', 0xAAAA, None, 'outbound'),
        ('audio', 'seat', 0xCCCC, None, 'outbound'),
        ('audio', 'fs', 0xEEEE, None, 'inbound'),
    ])
    describe_media_parties(manifest, captures, [call], SERVER, FILES_INFO)

    assert manifest['audio'][0]['flow']['from']['label'] == '终端'
    assert manifest['audio'][0]['flow']['to']['label'] == 'FS'
    assert manifest['audio'][1]['flow']['from']['label'] == '坐席端'
    # FS 抓包里的非主被叫 IP 无法命名
    assert manifest['audio'][2]['flow']['from']['label'] == '10.9.9.9'
    assert manifest['parties'] == []   # 无信令就没有拓扑行
    print("PASS: role-name/IP fallback when SIP signaling is missing")


def test_unsupported_entries_get_flow():
    """未能重建的流也标注谁到谁（方向按端口对自推）。"""
    call = make_call([0xAAAA], make_sip_flow())
    captures = make_captures([
        ('fs', 0xAAAA, [[TERM, 7080, SERVER, 34576]]),
    ])
    manifest = make_manifest([
        ('unsupported', 'fs', 0xAAAA, None, None),
    ])
    describe_media_parties(manifest, captures, [call], SERVER, FILES_INFO)

    flow = manifest['unsupported'][0]['flow']
    assert flow == {'from': {'label': '主叫 张三（1001）', 'ip': TERM},
                    'to': {'label': 'FS', 'ip': SERVER}}, flow
    print("PASS: unsupported entries get flow labels (from src->dst port pair)")


def test_two_calls_distinct_parties():
    """两通通话的不同媒体流各用各的主被叫标注，拓扑行两条。"""
    flow2 = make_sip_flow()
    call2 = {'call_id': 'call_2', 'ssrcs': [0x2222], 'sip_flow': flow2}
    # 第二通：主叫直接是坐席机（坐席外呼），被叫是终端
    flow2[0]['src'] = SEAT
    flow2[0]['from'] = {'name': '王五', 'user': '1003', 'host': SEAT}
    flow2[3]['src'] = TERM
    flow2[4]['src'] = SEAT
    call1 = make_call([0xAAAA], make_sip_flow())
    captures = make_captures([
        ('fs', 0xAAAA, [[TERM, 7080, SERVER, 34576]]),
        ('fs', 0x2222, [[SEAT, 7100, SERVER, 34600]]),
    ])
    manifest = make_manifest([
        ('audio', 'fs', 0xAAAA, None, 'inbound'),
        ('audio', 'fs', 0x2222, None, 'inbound'),
    ])
    describe_media_parties(manifest, captures, [call1, call2], SERVER, FILES_INFO)

    assert manifest['audio'][0]['flow']['from']['label'] == '主叫 张三（1001）'
    assert manifest['audio'][1]['flow']['from']['label'] == '主叫 王五（1003）'
    assert len(manifest['parties']) == 2
    print("PASS: two calls keep distinct party labels and topology chains")


def test_ident_label_format():
    # 话机自报的超长 base64 设备串（显示名与 user 同串）不采用：
    # 解码后仍是超过 20 字符的无空格单 token
    b64 = 'LTU4NTcyODU2NjAwZWYwN2MxMzZkYjIxYzk0NQ'
    assert _ident_label({'name': b64, 'user': b64}) == ''
    assert _ident_label({'name': '', 'user': b64}) == ''
    # base64 分机号解出可读内容
    assert _ident_label({'name': 'Extension ' + b64, 'user': b64}) == \
        'Extension -58572856600ef07c136db21c945'
    # 解不出（含不可打印字节）保持原样
    assert _ident_label({'name': '', 'user': 'abcdefgh1234567'}) == 'abcdefgh1234567'
    assert _ident_label({'name': '张三', 'user': '1001'}) == '张三（1001）'
    assert _ident_label({'name': '1002', 'user': '1002'}) == '1002'
    assert _ident_label({'name': '', 'user': '1002'}) == '1002'
    assert _ident_label({'name': '李四（1002）', 'user': '1002'}) == '李四（1002）'
    assert _ident_label({}) == ''
    print("PASS: SIP identity label formatting")


def test_extract_call_parties_fallbacks():
    """只有 B 腿 INVITE（FS 自产）时：主叫回退到首个请求，被叫仍可识别。"""
    flow = [
        {'method': 'INVITE', 'kind': 'request', 'src': SERVER, 'dst': SEAT,
         'from': {}, 'to': CALLEE_IDENT},
        {'method': '200', 'kind': 'success', 'cseq_method': 'INVITE',
         'src': SEAT, 'dst': SERVER, 'from': {}, 'to': CALLEE_IDENT},
    ]
    parties = extract_call_parties({'sip_flow': flow}, SERVER)
    assert parties['answerer_ip'] == SEAT
    assert parties['answerer_ident'] == CALLEE_IDENT
    # 主叫判不出来（首个非服务器 INVITE 不存在，回退首个请求其源是服务器）
    assert parties['caller_ip'] == SERVER
    # 完全无信令
    empty = extract_call_parties({'sip_flow': []}, SERVER)
    assert empty == {'caller_ip': None, 'caller_ident': {},
                     'answerer_ip': None, 'answerer_ident': {}}
    print("PASS: party extraction fallbacks")


def test_unanswered_call_callee_fallback():
    """未接通的通话（CANCEL/487 收场，无 INVITE 的 200 OK）：被叫取信令
    对端兜底，不整列丢失；转报主叫身份可读。"""
    relayed_caller = {'name': 'Extension LTU4NTcyODU2NjAwNDZkYWY4ZjBlZjA4NzU0OQ',
                      'user': 'LTU4NTcyODU2NjAwNDZkYWY4ZjBlZjA4NzU0OQ', 'host': SERVER}
    flow = [
        {'method': 'INVITE', 'kind': 'request', 'src': SERVER, 'dst': SEAT,
         'from': relayed_caller, 'to': CALLEE_IDENT},
        {'method': '100', 'kind': 'provisional', 'src': SEAT, 'dst': SERVER,
         'from': relayed_caller, 'to': CALLEE_IDENT},
        {'method': '180', 'kind': 'provisional', 'src': SEAT, 'dst': SERVER,
         'from': relayed_caller, 'to': CALLEE_IDENT},
        {'method': 'CANCEL', 'kind': 'request', 'src': SERVER, 'dst': SEAT,
         'from': relayed_caller, 'to': CALLEE_IDENT},
        {'method': '200', 'kind': 'success', 'cseq_method': 'CANCEL',
         'src': SEAT, 'dst': SERVER, 'from': relayed_caller, 'to': CALLEE_IDENT},
        {'method': '487', 'kind': 'failure', 'cseq_method': 'INVITE',
         'src': SEAT, 'dst': SERVER, 'from': relayed_caller, 'to': CALLEE_IDENT},
        {'method': 'ACK', 'kind': 'request', 'src': SERVER, 'dst': SEAT,
         'from': relayed_caller, 'to': CALLEE_IDENT},
    ]
    parties = extract_call_parties({'sip_flow': flow}, SERVER)
    # 200-for-CANCEL（cseq 不符）与 487 都不能当接听确认，被叫靠对端兜底
    assert parties['caller_ip'] == SERVER
    assert parties['answerer_ip'] == SEAT
    assert parties['answerer_ident'] == CALLEE_IDENT
    # FS 转报的主叫身份解出可读内容（base64 里的号码）
    assert _ident_label(relayed_caller) == 'Extension -5857285660046daf8f0ef087549'
    print("PASS: unanswered call keeps callee via peer fallback; relayed caller decoded")


if __name__ == '__main__':
    test_fs_streams_labeled_with_caller_callee()
    test_endpoint_captures_share_ssrc_labels()
    test_fallback_without_sip_flow()
    test_unsupported_entries_get_flow()
    test_two_calls_distinct_parties()
    test_ident_label_format()
    test_extract_call_parties_fallbacks()
    test_unanswered_call_callee_fallback()
    print("\n=== ALL MEDIA PARTY LABEL TESTS PASSED ===")
