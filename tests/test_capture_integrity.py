"""
Unit tests for capture integrity: snaplen-truncated packets, cut-off file
tails (pcap & pcapng), and the user-facing summary/messages.

Run: python3 tests/test_capture_integrity.py
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scapy.all import Ether, IP, UDP, Raw, wrpcap

from analyzer.capture_integrity import (
    build_integrity, merge_integrity, scan_pcap_headers,
)
from analyzer.rtp_parser import extract_rtp_packets


def make_rtp_pcap(path, n=50):
    """Write a pcap with n RTP/PCMU packets (Ether/IP/UDP/RTP, 160B payload)."""
    pkts = []
    for seq in range(n):
        rtp = struct.pack('!BBHII', 0x80, 0, seq, seq * 160, 0x12345678) + b'\xd5' * 160
        pkts.append(Ether() / IP(src='10.0.0.1', dst='10.0.0.2')
                    / UDP(sport=10000, dport=20000) / Raw(rtp))
    wrpcap(path, pkts)
    return path


def rewrite_pcap_records(src, dst, mutate):
    """Rebuild a pcap record-by-record, letting mutate(i, incl, orig, body)
    return (new_incl, new_orig, new_body) for each record."""
    data = open(src, 'rb').read()
    out = bytearray(data[:24])
    off = 24
    i = 0
    while off + 16 <= len(data):
        ts_sec, ts_us, incl, orig = struct.unpack('<IIII', data[off:off + 16])
        body = data[off + 16:off + 16 + incl]
        incl2, orig2, body2 = mutate(i, incl, orig, body)
        out += struct.pack('<IIII', ts_sec, ts_us, incl2, orig2)
        out += body2
        off += 16 + incl
        i += 1
    open(dst, 'wb').write(out)
    return dst


def test_clean_capture_ok():
    path = make_rtp_pcap(os.path.join(tempfile.mkdtemp(), 'clean.pcap'))
    r = extract_rtp_packets(path)
    integ = r['integrity']
    assert integ['status'] == 'ok', integ
    assert integ['notes'] == [], integ
    assert integ['truncated'] == 0 and not integ['file_cut'], integ
    assert integ['all_packets'] == 50, integ
    assert r['total_count'] == 50, r['total_count']


def test_snaplen_truncated_packets_warn():
    """orig_len > incl_len（快照截短）：统计截短数与 RTP 占比，但分析照常。"""
    tmp = tempfile.mkdtemp()
    full = make_rtp_pcap(os.path.join(tmp, 'full.pcap'))

    def cut_first_25(i, incl, orig, body):
        if i < 25:
            return 100, incl, body[:100]
        return incl, orig, body

    path = rewrite_pcap_records(full, os.path.join(tmp, 'trunc.pcap'), cut_first_25)
    r = extract_rtp_packets(path)
    integ = r['integrity']
    assert integ['status'] == 'warn', integ
    assert integ['truncated'] == 25, integ
    assert integ['truncated_rtp'] == 25, integ
    assert integ['max_missing_bytes'] == 114, integ
    assert not integ['file_cut'], integ
    assert len(integ['notes']) == 1 and '截短' in integ['notes'][0], integ['notes']
    # RTP 头（前 12 字节）仍在 → 流照常识别，分析不中断
    assert r['total_count'] == 50, r['total_count']
    assert list(r['streams'])[0] == 0x12345678, r['streams']


def test_file_tail_cut_off():
    """文件尾半截记录：报 file_cut，不再误报快照截短。"""
    tmp = tempfile.mkdtemp()
    full = make_rtp_pcap(os.path.join(tmp, 'full.pcap'))
    data = open(full, 'rb').read()
    path = os.path.join(tmp, 'cut.pcap')
    open(path, 'wb').write(data[:-30])

    r = extract_rtp_packets(path)
    integ = r['integrity']
    assert integ['status'] == 'warn', integ
    assert integ['file_cut'], integ
    assert integ['truncated'] == 0, integ      # 记录头本身不短
    assert len(integ['notes']) == 1 and '中途结束' in integ['notes'][0], integ['notes']
    # scapy 补零后仍解析出全部包，分析不中断
    assert r['total_count'] == 50, r['total_count']


def test_scan_pcap_headers_snaplen():
    tmp = tempfile.mkdtemp()
    full = make_rtp_pcap(os.path.join(tmp, 'full.pcap'))

    def cut(i, incl, orig, body):
        return (64, incl, body[:64]) if i < 3 else (incl, orig, body)

    path = rewrite_pcap_records(full, os.path.join(tmp, 'trunc.pcap'), cut)
    scan = scan_pcap_headers(path)
    assert scan is not None, scan
    assert scan['record_count'] == 50, scan
    assert scan['truncated_records'] == 3, scan
    assert scan['min_captured_trunc'] == 64, scan
    assert not scan['tail_incomplete'], scan
    # 快照长度等于截短包的捕获长度 → 文案给出快照长度
    integ = build_integrity({**scan, 'snaplen': 64,
                             'truncated': 3, 'truncated_rtp': 3,
                             'max_missing_bytes': 150,
                             'all_packets': 50, 'file_cut': False})
    assert '快照长度' in integ['notes'][0], integ['notes']
    # 快照长度对不上（如文件被后处理过）→ 不给误导性的快照说明
    integ2 = build_integrity({**scan, 'truncated': 3, 'truncated_rtp': 3,
                              'max_missing_bytes': 150,
                              'all_packets': 50, 'file_cut': False})
    assert '快照长度' not in integ2['notes'][0], integ2['notes']


def test_pcapng_scan():
    """pcapng：手工构造 SHB+IDB+EPB，含 2 个截短 EPB 与尾部半块。"""

    def epb(ts, cap, orig, data):
        blen = 32 + ((cap + 3) // 4) * 4
        blk = struct.pack('<IIIII', 6, blen, 0, 0, ts)
        blk += struct.pack('<II', cap, orig)
        blk += data + b'\x00' * (((cap + 3) // 4) * 4 - cap)
        return blk + struct.pack('<I', blen)

    shb = (struct.pack('<III', 0x0A0D0D0A, 28, 0x1A2B3C4D)
           + struct.pack('<HH', 1, 0) + b'\xff' * 8 + struct.pack('<I', 28))
    idb = struct.pack('<IIHHI', 1, 20, 1, 0, 96) + struct.pack('<I', 20)
    body = b''.join(epb(i * 1000, cap, orig, b'\xd5' * cap)
                    for i, (cap, orig) in enumerate(
                        [(96, 228), (96, 228), (228, 228)]))
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, 'test.pcapng')
    open(path, 'wb').write(shb + idb + body)

    scan = scan_pcap_headers(path)
    assert scan['snaplen'] == 96, scan
    assert scan['record_count'] == 3, scan
    assert scan['truncated_records'] == 2, scan
    assert not scan['tail_incomplete'], scan

    # 尾部剪掉 10 字节 → 最后一块半截
    path2 = os.path.join(tmp, 'cut.pcapng')
    open(path2, 'wb').write(open(path, 'rb').read()[:-10])
    scan2 = scan_pcap_headers(path2)
    assert scan2['tail_incomplete'], scan2
    assert scan2['truncated_records'] == 2, scan2


def test_build_and_merge_integrity():
    ok = build_integrity({'all_packets': 10})
    assert ok['status'] == 'ok' and ok['notes'] == [], ok

    warn = build_integrity({'all_packets': 10, 'truncated': 2, 'truncated_rtp': 2,
                            'max_missing_bytes': 100})
    assert warn['status'] == 'warn' and len(warn['notes']) == 1, warn
    # header_truncated 优先，且 RTP 计数被封顶对齐
    capped = build_integrity({'all_packets': 10, 'truncated': 3, 'truncated_rtp': 3,
                              'max_missing_bytes': 100, 'header_truncated': 2,
                              'tail_incomplete': True})
    assert capped['truncated'] == 2 and capped['truncated_rtp'] == 2, capped
    assert capped['file_cut'] and len(capped['notes']) == 2, capped['notes']

    merged = merge_integrity([
        {'role': 'fs', 'filename': 'fs.pcap', 'integrity': warn},
        {'role': 'seat', 'filename': 'seat.pcap', 'integrity': ok},
    ])
    assert merged == {'files': [{'role': 'fs', 'filename': 'fs.pcap',
                                 'notes': warn['notes']}]}, merged
    assert merge_integrity([{'role': 'seat', 'filename': 's.pcap',
                             'integrity': ok}]) is None


def test_report_includes_integrity_notes():
    from analyzer.reporter import generate_report
    fname = 'fs.pcap'
    results = {
        'media_type': 'audio',
        'capture_roles': {'fs': fname},
        'capture_integrity': {'fs': build_integrity({
            'all_packets': 10, 'truncated': 4, 'truncated_rtp': 4,
            'max_missing_bytes': 100})},
    }
    report = generate_report(results)
    issues = report['conclusion']['issues']
    assert any('抓包可能不完整' in i['message'] and fname in i['message']
               for i in issues), issues
    assert issues[0]['message'].startswith('抓包可能不完整'), issues
    assert report['conclusion']['overall'] == 'warning', report['conclusion']

    # 无完整性问题时不出现在问题里
    clean = generate_report({'media_type': 'audio', 'capture_roles': {'fs': fname},
                             'capture_integrity': {'fs': build_integrity(
                                 {'all_packets': 10})}})
    assert not any('抓包可能不完整' in i['message']
                   for i in clean['conclusion']['issues'])


def main():
    test_clean_capture_ok()
    test_snaplen_truncated_packets_warn()
    test_file_tail_cut_off()
    test_scan_pcap_headers_snaplen()
    test_pcapng_scan()
    test_build_and_merge_integrity()
    test_report_includes_integrity_notes()
    print("\n=== ALL CAPTURE INTEGRITY TESTS PASSED ===")


if __name__ == '__main__':
    main()
