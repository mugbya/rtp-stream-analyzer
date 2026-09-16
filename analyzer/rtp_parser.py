"""
RTP Packet Parser
Parse pcap/pcapng files and extract all RTP packet information.
"""
from scapy.all import IP, UDP, Raw
from scapy.utils import PcapReader
from scapy.layers.inet import defragment
from collections import defaultdict
import os
import re

from analyzer.rtcp_parser import parse_rtcp
from analyzer.capture_integrity import TRUNC_MIN_BYTES, build_integrity, scan_pcap_headers
from analyzer.stream_classifier import resolve_stream_kind

# SIP requests kept for call detection and per-call signaling flow.
# Dialog-related methods only: REGISTER/OPTIONS/SUBSCRIBE keepalives carry
# unrelated Call-IDs and must not enter call flows.
SIP_METHODS_OF_INTEREST = {'INVITE', 'BYE', 'CANCEL', 'ACK', 'UPDATE', 'PRACK', 'INFO'}

# 每条流用于估计 RTP 时钟率的 (到达时刻, 时间戳) 采样上限（尾部窗口）。
# 中位数对个别时间戳跳变/乱序稳健；64 个样本足够覆盖上千包的流。
CLOCK_SAMPLE_MAX = 64


def _signed32(x: int) -> int:
    """带符号 32 位差值：正常推进为小正数，跨 2^32 回绕不受影响。"""
    x &= (1 << 32) - 1
    return x - (1 << 32) if x >= (1 << 31) else x


def _parse_sip_addr(value: str) -> dict:
    """Parse a From/To header value into {'name', 'user', 'host'}.

    '"张三" <sip:1002@10.4.157.141:5060>;tag=x' ->
        {'name': '张三', 'user': '1002', 'host': '10.4.157.141'}
    """
    out = {'name': '', 'user': '', 'host': ''}
    if not value:
        return out
    m = re.search(r'"([^"]*)"', value)
    if m:
        out['name'] = m.group(1).strip()
    m = re.search(r'<([^>]*)>', value)
    uri = m.group(1) if m else value.strip()
    m = re.match(r'sips?:([^@]*)@([^;>?]+)', uri)
    if m:
        out['user'] = m.group(1).strip()
        out['host'] = m.group(2).split(':')[0].strip()
    elif uri.lower().startswith('tel:'):
        out['user'] = uri[4:].split(';')[0].strip()
    return out


# RFC 3551 静态载荷：m= 行里这些 PT 不带 a=rtpmap 行，按此表解析名字
STATIC_PT_NAMES = {
    '0': 'PCMU', '3': 'GSM', '4': 'G723', '5': 'DVI4', '6': 'DVI4',
    '7': 'LPC', '8': 'PCMA', '9': 'G722', '10': 'L16', '11': 'L16',
    '12': 'QCELP', '13': 'CN', '14': 'MPA', '15': 'G728', '16': 'DVI4',
    '17': 'DVI4', '18': 'G729', '25': 'CELB', '26': 'JPEG', '28': 'NV',
    '31': 'H261', '32': 'MPV', '33': 'MP2T', '34': 'H263',
}

# 静态音频载荷的时钟率（RFC 3551）；静态视频载荷统一 90000。FS 自产 INVITE
# 的 SDP 常用静态 PT 不带 rtpmap，补上时钟率才能与对端 rtpmap 精确对比
STATIC_PT_CLOCK = {
    '0': 8000, '3': 8000, '4': 8000, '5': 8000, '6': 16000, '7': 8000,
    '8': 8000, '9': 8000, '10': 44100, '11': 22050, '12': 8000, '13': 8000,
    '14': 90000, '15': 8000, '16': 11025, '17': 22050, '18': 8000,
}


def _parse_sdp_codecs(body: str) -> dict:
    """Extract audio/video codec info from an SDP body.

    Returns {'audio': [names], 'video': [names], 'map': {'audio': {pt: name},
    'video': {pt: name}}, 'full': {'audio': [{'name', 'rate'}],
    'video': [...]}, 'map_full': {'audio': {pt: {'name', 'rate'}}, ...}} — the
    lists follow the m= line payload order; names come from a=rtpmap lines,
    falling back to the static payload table (dynamic PTs without rtpmap have
    no name and are skipped). DTMF 事件流（telephone-event / telephone）不是
    媒体编码，列表与映射都不收录。The map resolves RTP payload types to codec
    names so the actually-used codecs can be derived from stream PTs. 'full'
    保留时钟率（编码身份），供按腿对比协商结果时区分同名字不同时钟率的编码
    （如 OPUS/48000 vs OPUS/16000）。'map_full' 按 PT 直接查名字与时钟率，
    供流分类（动态 PT 的音/视频判定与重建时钟）使用。
    """
    out = {'audio': [], 'video': [], 'map': {'audio': {}, 'video': {}},
           'full': {'audio': [], 'video': []},
           'map_full': {'audio': {}, 'video': {}}}
    media = None
    order = {'audio': [], 'video': []}   # m= 行的 PT 顺序
    named = {'audio': {}, 'video': {}}   # a=rtpmap 解析出的 pt -> 名字（按媒体隔离：
    rates = {'audio': {}, 'video': {}}   # 音/视频动态 PT 各自独立编号，音频视频同用
                                         # PT 96 时全局表会串台）
    for line in body.replace('\r\n', '\n').split('\n'):
        if line.startswith('m='):
            parts = line.split()
            media = parts[0][2:] if len(parts) > 1 else None
            if media in ('audio', 'video'):
                order[media].extend(parts[3:])
        elif line.startswith('a=rtpmap:') and media in ('audio', 'video'):
            bits = line.split(':', 1)[1].split()
            if len(bits) >= 2:
                named[media][bits[0]] = bits[1].split('/')[0].upper()
                clock = bits[1].split('/')
                if len(clock) > 1 and clock[1].isdigit():
                    rates[media][bits[0]] = int(clock[1])

    for kind in ('audio', 'video'):
        for pt in order[kind]:
            name = named[kind].get(pt) or STATIC_PT_NAMES.get(pt)
            if not name or name.startswith('TELEPHONE'):
                continue
            if name not in out[kind]:
                out[kind].append(name)
            out['map'][kind].setdefault(pt, name)
            rate = rates[kind].get(pt)
            if rate is None and pt in STATIC_PT_NAMES:
                rate = STATIC_PT_CLOCK.get(pt, 90000 if kind == 'video' else 8000)
            ident = {'name': name, 'rate': rate}
            out['map_full'][kind].setdefault(pt, ident)
            if ident not in out['full'][kind]:
                out['full'][kind].append(ident)
    return out


def _parse_sdp_endpoints(body: str) -> list:
    """Extract the media endpoints (kind, addr, port) announced in an SDP body.

    Each m= line is a media the *sender* will receive at the connection
    address — the session-level c= line, overridden by a media-level c= line.
    These (addr, port) pairs identify exactly which RTP streams belong to the
    signaling dialog, so mis-grouped streams can be filtered per call. A port
    of 0 (rejected media) or a 0.0.0.0/hold connection announces nothing.
    """
    endpoints = []
    conn = None      # current connection address (session-level until overridden)
    kind = None      # current m= media kind
    port = None      # current m= port
    for line in body.replace('\r\n', '\n').split('\n'):
        if line.startswith('c='):
            parts = line.split()
            if len(parts) >= 3:
                addr = parts[2].split('/')[0]
                # 0.0.0.0 = hold/placeholder：紧随的 m= 行不宣告端点
                conn = addr if addr and addr != '0.0.0.0' else None
        elif line.startswith('m='):
            if kind and conn and port:
                endpoints.append({'kind': kind, 'addr': conn, 'port': port})
            parts = line.split()
            kind = parts[0][2:] if len(parts) > 1 else None
            port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            if kind not in ('audio', 'video'):
                kind = None
                port = None
    if kind and conn and port:
        endpoints.append({'kind': kind, 'addr': conn, 'port': port})
    return endpoints


def _parse_sip_event(payload: bytes):
    """Best-effort SIP message parsing.

    Keeps signaling requests (INVITE/ACK/BYE/CANCEL) and every response code
    (100-699) so a call's full signaling flow can be replayed.

    Returns {'method': str, 'reason': str, 'call_id': str} or None.
    'method' is the request method, or the numeric status code ('200') for
    responses; 'reason' is the response reason phrase ('' for requests).
    """
    try:
        # 8KB：带视频的 INVITE SDP（含 imageattr 等属性行）可超过 2KB
        text = payload[:8000].decode('utf-8', errors='ignore')
    except Exception:
        return None
    first_line = text.split('\r\n', 1)[0]
    parts = first_line.split()
    reason = ''
    if len(parts) == 3 and parts[2].startswith('SIP/'):
        method = parts[0]            # request: "INVITE sip:... SIP/2.0"
        if method not in SIP_METHODS_OF_INTEREST:
            return None
    elif len(parts) >= 2 and parts[0].startswith('SIP/'):
        method = parts[1]            # response: "SIP/2.0 200 OK"
        reason = ' '.join(parts[2:])
        if not (method.isdigit() and 100 <= int(method) <= 699):
            return None
    else:
        return None
    call_id = ''
    cseq_method = ''
    cseq_num = None
    from_hdr = {}
    to_hdr = {}
    for line in text.split('\r\n'):
        if not call_id and (line.startswith('Call-ID:') or line.startswith('i:')):
            call_id = line.split(':', 1)[1].strip()
        elif not cseq_method and line.startswith('CSeq:'):
            # "CSeq: 1 INVITE" — for responses, identifies which request the
            # response belongs to (REGISTER keepalives are filtered out here)
            cseq_parts = line.split(':', 1)[1].split()
            if cseq_parts:
                cseq_method = cseq_parts[-1]
                try:
                    cseq_num = int(cseq_parts[0])
                except ValueError:
                    pass
        elif not from_hdr and (line.startswith('From:') or line.startswith('f:')):
            from_hdr = _parse_sip_addr(line.split(':', 1)[1])
        elif not to_hdr and (line.startswith('To:') or line.startswith('t:')):
            to_hdr = _parse_sip_addr(line.split(':', 1)[1])
    if not method.isdigit():
        # request: keep only dialog methods
        if method not in SIP_METHODS_OF_INTEREST:
            return None
    elif cseq_method and cseq_method not in SIP_METHODS_OF_INTEREST:
        # response: keep only when it belongs to a dialog method
        return None
    # SDP body (offers in INVITE/200 OK) -> negotiated codec names + announced
    # media endpoints (which ip:port pairs exchange RTP in this dialog)
    body = text.split('\r\n\r\n', 1)[1] if '\r\n\r\n' in text else ''
    sdp = _parse_sdp_codecs(body) if body else {}
    if body:
        sdp['endpoints'] = _parse_sdp_endpoints(body)
    return {'method': method, 'reason': reason, 'call_id': call_id,
            'cseq': cseq_num, 'cseq_method': cseq_method,
            'from': from_hdr, 'to': to_hdr, 'sdp': sdp}


def parse_rtp_header(payload: bytes):
    """Parse RTP header fields.
    
    Returns:
        (pt, seq, timestamp, ssrc, payload_bytes) or None if not a valid RTP packet.
        payload_bytes is the raw encoded media data after the 12-byte RTP header.
    """
    if len(payload) < 12:
        return None
    b0 = payload[0]
    version = (b0 >> 6) & 0x03
    if version != 2:
        return None
    # Exclude RTCP (also version 2): RTCP packet types 200-206 (SR/RR/SDES/
    # BYE/APP/RTPFB/PSFB) live in byte[1] as full values, while RTP's byte[1]
    # is marker+PT and only reaches 200-206 with marker=1 and PT 72-76.
    if payload[1] in range(200, 207):
        return None
    pt = payload[1] & 0x7F
    seq = int.from_bytes(payload[2:4], 'big')
    ts = int.from_bytes(payload[4:8], 'big')
    ssrc = int.from_bytes(payload[8:12], 'big')
    return (pt, seq, ts, ssrc, payload[12:])


def _read_capture(filepath: str):
    """读取抓包文件（等价 rdpcap），文件中途损坏时保留已解析的包。

    返回 (packets, file_cut)。file_cut=True 表示读取中途出错（文件传输出错/
    抓包被强制终止）——像 Wireshark 一样带提示继续分析，而不是整份拒收。
    一个包都读不出时属于格式无效，交由上层报错。
    """
    pkts = []
    try:
        with PcapReader(filepath) as reader:
            for p in reader:
                pkts.append(p)
        return pkts, False
    except Exception:
        if not pkts:
            raise
        return pkts, True


def extract_rtp_packets(filepath: str, include_payload: bool = False) -> dict:
    """Extract all RTP packets from a pcap file.

    Args:
        filepath: Path to pcap/pcapng file.
        include_payload: If True, store the raw RTP payload bytes for each packet.
                         Set to False for upload/preview to save memory.

    Returns:
        {
            'packets': {(ssrc, seq): (capture_time, rtp_ts, pt, src_ip, dst_ip, src_port, dst_port, [payload])},
            'total_count': int,
            'ips': set,
            'ssrcs': set,
            'streams': {ssrc: {'count': int, 'pt': set, 'src_ip': str, 'dst_ip': str,
                               'kind': 'audio'|'video'|'unknown', 'codec': str|None,
                               'clock': int|None, ...}},
            'capture_start': float,   # first packet time in the whole capture (any protocol)
            'capture_end': float,     # last packet time
            'sip_events': [{'time': float, 'method': str, 'reason': str,
                            'call_id': str, 'src': str, 'dst': str}],
            'integrity': {...},       # 抓包完整性（截短/文件尾损坏），照常分析但提示
        }
    """
    raw_pkts, file_cut = _read_capture(filepath)
    # 大 SDP 的 SIP 消息超过 MTU 时会被 IP 分片：只有首片带 UDP 头，SDP 正文
    # 往往落在后续分片里。先重组再遍历，否则这些消息只剩半截、SDP 解析不到
    # （协商编码、媒体端点全丢，直接影响信令流程与通话归属判定）
    pkts = defragment(raw_pkts)
    packets = {}
    ips = set()
    ssrcs = set()
    streams = defaultdict(lambda: {'count': 0, 'pt': set(), 'ips': set(), 'port_pairs': set()})
    capture_start = None
    capture_end = None
    sip_events = []
    rtcp_events = []
    # 时钟率估计采样：每条流保留尾部一段 (到达时刻, RTP时间戳)，供无信令
    # 时按"时间戳推进/真实时间推进"判流种类（OPUS 48kHz / 视频 90kHz）
    ts_samples = defaultdict(list)
    # 抓包完整性统计：wirelen（线上原始长度）> 已捕获长度说明包被截短
    # （快照长度不足或文件尾损坏），对应 Wireshark 的
    # "Packet size limited during capture" 提示
    trunc_all = trunc_rtp = 0
    max_missing = 0
    all_count = 0

    for p in pkts:
        all_count += 1
        t = float(p.time)
        if capture_start is None or t < capture_start:
            capture_start = t
        if capture_end is None or t > capture_end:
            capture_end = t
        wirelen = p.wirelen
        missing = (wirelen - len(p)) if wirelen else 0
        truncated = missing >= TRUNC_MIN_BYTES
        if truncated:
            trunc_all += 1
            max_missing = max(max_missing, missing)
        if IP in p and UDP in p and Raw in p:
            # SIP signaling (completeness signal + per-call flow display)
            if p[UDP].sport == 5060 or p[UDP].dport == 5060:
                ev = _parse_sip_event(bytes(p[Raw]))
                if ev:
                    ev['time'] = t
                    ev['src'] = p[IP].src
                    ev['dst'] = p[IP].dst
                    sip_events.append(ev)
                continue
            rtp = parse_rtp_header(bytes(p[Raw]))
            if rtp:
                pt, seq, ts, ssrc, payload = rtp
                if truncated:
                    trunc_rtp += 1
                src_ip = p[IP].src
                dst_ip = p[IP].dst
                src_port = p[UDP].sport
                dst_port = p[UDP].dport
                key = (ssrc, seq)

                # Only keep the first occurrence of each packet (dedup)
                if key not in packets:
                    if include_payload:
                        packets[key] = (float(p.time), ts, pt, src_ip, dst_ip, src_port, dst_port, payload)
                    else:
                        packets[key] = (float(p.time), ts, pt, src_ip, dst_ip, src_port, dst_port)

                ips.add(src_ip)
                ips.add(dst_ip)
                ssrcs.add(ssrc)
                streams[ssrc]['count'] += 1
                streams[ssrc]['pt'].add(pt)
                streams[ssrc]['ips'].add((src_ip, dst_ip))
                streams[ssrc]['port_pairs'].add((src_ip, src_port, dst_ip, dst_port))
                sample = ts_samples[ssrc]
                if len(sample) >= CLOCK_SAMPLE_MAX:
                    sample.pop(0)
                sample.append((t, ts))
            else:
                # RTCP（SR/RR）：RTP 解析会把类型 200/201 拒掉，落到这里。
                # SR 证明发送端在产媒体并携带 NTP↔RTP 映射，RR 是接收端对
                # 入流的丢包/抖动亲历上报，无声与延迟诊断都用得上
                for ev in parse_rtcp(bytes(p[Raw])):
                    ev['time'] = t
                    ev['src'] = p[IP].src
                    ev['dst'] = p[IP].dst
                    rtcp_events.append(ev)
    
    # —— 流种类/编码解析 ——
    # 动态 PT（96-127）按媒体种类独立分配（audio 96=OPUS 与 video 96=H264 可
    # 同号并存），只看 PT 号会把 OPUS 音频误判成视频。结合本文件 SDP：
    # 1) 媒体端点 (ip,port) → 种类绑定；2) rtpmap 单侧命中；3) 实测时钟率；
    # 4) 静态 PT 表兜底。解析出的 kind/codec/clock 供分类、重建与连续性检测
    # 直接使用。
    port_kinds = {}
    pt_maps = {'audio': {}, 'video': {}}
    for ev in sip_events:
        sdp = ev.get('sdp') or {}
        for ep in sdp.get('endpoints') or []:
            if ep.get('kind') in ('audio', 'video') and ep.get('addr') and ep.get('port'):
                port_kinds.setdefault((ep['addr'], ep['port']), ep['kind'])
        for kind in ('audio', 'video'):
            for pt, ident in ((sdp.get('map_full') or {}).get(kind) or {}).items():
                pt_maps[kind].setdefault(int(pt), ident)

    def _est_clock(ssrc):
        """时间戳推进 / 真实时间推进 的中位数 ≈ 发送端媒体时钟率。"""
        sample = ts_samples.get(ssrc) or []
        rates = []
        for (t0, ts0), (t1, ts1) in zip(sample, sample[1:]):
            dt = t1 - t0
            dts = _signed32(ts1 - ts0)
            if dt > 0.001 and dts > 0:
                rates.append(dts / dt)
        if len(rates) < 4:
            return None
        rates.sort()
        return rates[len(rates) // 2]

    # Convert sets to lists in streams (for JSON serialization)
    streams_clean = {}
    for ssrc, info in streams.items():
        if info['count'] >= 10:  # Filter out streams with too few packets
            kind, codec, clock = resolve_stream_kind(
                info['port_pairs'], info['pt'], est_clock=_est_clock(ssrc),
                port_kinds=port_kinds, pt_maps=pt_maps)
            streams_clean[ssrc] = {
                'count': info['count'],
                'pt': sorted(info['pt']),
                'ips': [list(ip) for ip in info['ips']],
                'port_pairs': [list(pp) for pp in info['port_pairs']],
                'kind': kind,
                'codec': codec,
                'clock': clock,
            }
    
    # 文件级走查：取快照长度与记录头级别的截短数（能区分“快照截短”与
    # “文件尾半包”）；走查失败时退回按包统计
    scan = scan_pcap_headers(filepath) or {}
    scan['file_cut'] = file_cut
    scan['header_truncated'] = scan.get('truncated_records')
    scan.setdefault('truncated', trunc_all)
    scan.setdefault('max_missing_bytes', max_missing)
    scan['all_packets'] = all_count
    scan['truncated_rtp'] = trunc_rtp

    return {
        'packets': packets,
        'total_count': len(packets),
        'ips': ips,
        'ssrcs': ssrcs,
        'streams': streams_clean,
        'capture_start': capture_start,
        'capture_end': capture_end,
        'sip_events': sip_events,
        'rtcp_events': rtcp_events,
        'integrity': build_integrity(scan),
    }


def get_packet_time(packets: dict, ssrc: int, seq: int):
    """Get the capture time of a specific packet."""
    key = (ssrc, seq)
    if key in packets:
        return packets[key][0]
    return None


def get_stream_packets(packets: dict, ssrc: int) -> list:
    """Get all packets for a given SSRC, sorted by capture time.
    
    Returns:
        [(capture_time, seq, rtp_ts, pt, src_ip, dst_ip, src_port, dst_port, [payload]), ...]
        The payload element is present only if include_payload=True was used during extraction.
    """
    result = []
    for k, v in packets.items():
        if k[0] == ssrc:
            result.append((v[0], k[1], v[1], v[2], v[3], v[4], v[5], v[6]) + v[7:])
    result.sort(key=lambda x: x[0])
    return result