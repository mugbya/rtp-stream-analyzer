"""Fast pcap/pcapng Reader —— 纯 struct 的抓包读取器，替代 scapy 逐包解析。

scapy 每个包都要构建完整的协议对象树（Ethernet/IP/UDP/... 各一层），实测
读包占整个解析耗时的八成。而下游分析真正需要的只有：到达时刻、线上长度、
以及 UDP 载荷。这里直接按记录头/协议头偏移切字段，同样的文件快一个数量级。

覆盖范围：
- 容器格式：pcap（含微秒/纳秒、大小端变体）与 pcapng（EPB/SPB/IDB）；
- 链路层：Ethernet（含 VLAN/QinQ）、Linux SLL/SLL2、原始 IP、BSD loopback；
- 网络层：IPv4（含分片重组，SDP 大消息超 MTU 时 SIP 只剩半截的问题由此解决）
  与 IPv6（不含分片重组）；
- 传输层：仅 UDP（RTP/RTCP/SIP 都是 UDP，其他协议只参与包计数与时间统计）。

不认识的格式/链路层抛 UnsupportedCapture，由 rtp_parser 回退 scapy 旧路径，
行为与历史版本完全一致。
"""
import mmap
import os
import socket
import struct

AF_INET6 = socket.AF_INET6
inet_ntoa = socket.inet_ntoa
inet_ntop = socket.inet_ntop


class UnsupportedCapture(Exception):
    """容器格式或链路层不支持：调用方应回退 scapy 兜底路径。"""


class FastPacket:
    """一个抓包记录的最小可用信息（对应 scapy 包对象的精简版）。

    非 UDP 包只有 ts/wirelen/caplen 有意义（src_ip 为 None），它们参与
    抓包时间范围与完整性统计，但不进入 RTP/SIP/RTCP 解析。
    """
    __slots__ = ('ts', 'wirelen', 'caplen', 'src_ip', 'dst_ip', 'sport', 'dport', 'payload')

    def __init__(self, ts, wirelen, caplen, src_ip=None, dst_ip=None,
                 sport=0, dport=0, payload=b''):
        self.ts = ts
        self.wirelen = wirelen
        self.caplen = caplen
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = sport
        self.dport = dport
        self.payload = payload


# pcap 全局头魔数（按大端读出的值 → (字段端序, 时间戳小数部分的除数)）
# 0xA1B2C3D4/0xD4C3B2A1 为微秒变体，0xA1B23C4D/0x4D3CB2A1 为纳秒变体
_PCAP_MAGICS = {
    0xA1B2C3D4: ('>', 1e6), 0xD4C3B2A1: ('<', 1e6),
    0xA1B23C4D: ('>', 1e9), 0x4D3CB2A1: ('<', 1e9),
}
_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_EPB = 0x00000006
_PCAPNG_SPB = 0x00000003

# 链路层类型 → 帧解析器；未列出的抛 UnsupportedCapture 走 scapy 兜底
_LT_ETHERNET = 1
_LT_LOOPBACK = 0
_LT_RAW_IP = 101          # LINKTYPE_RAW；部分旧系统写作 12
_LT_RAW_IP_LEGACY = 12
_LT_SLL = 113
_LT_SLL2 = 276

_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_VLAN_TYPES = (0x8100, 0x88A8, 0x9100)

# 文件尾半截记录的最大补零长度：合法帧最长不过万兆巨帧，超过视为
# 损坏记录的垃圾长度字段，直接停读（完整性走查会报尾部不完整）
_MAX_PAD_RECORD = 65536

_IPPROTO_UDP = 17
# IPv6 扩展头下一头值：这些头按自身长度字段跳过；分片头（44）不做重组
_IPV6_SKIP_EXT = (0, 43, 60, 51)
_IPV6_EXT_AH = 51
_IPPROTO_FRAGMENT = 44


def iter_packets(filepath):
    """逐包产出 FastPacket。格式/链路层不支持抛 UnsupportedCapture。

    文件尾记录只剩半截时停止产出（scapy 会静默补零解析最后半包），截短
    本身由 capture_integrity 的记录头走查兜住并提示，分析照常进行。
    """
    if os.path.getsize(filepath) == 0:
        raise UnsupportedCapture('空文件')
    _ipv4_frag_cache.clear()               # 上一个文件未凑齐的孤片不带过来
    with open(filepath, 'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            magic = int.from_bytes(mm[0:4], 'big')
            if magic in _PCAP_MAGICS:
                yield from _iter_pcap(mm, *_PCAP_MAGICS[magic])
            elif magic == _PCAPNG_SHB:
                yield from _iter_pcapng(mm)
            else:
                raise UnsupportedCapture(f'未知容器格式 0x{magic:08x}')
        finally:
            mm.close()


def _iter_pcap(mm, endian, ts_div):
    linktype = struct.unpack_from(endian + 'I', mm, 20)[0] & 0xFFFF
    parse_frame = _frame_parser(linktype)
    pos = 24
    size = len(mm)
    while pos + 16 <= size:
        ts_sec, ts_frac, incl, orig = struct.unpack_from(endian + 'IIII', mm, pos)
        pos += 16
        if pos + incl > size:
            if incl > _MAX_PAD_RECORD:   # 长度字段离谱（文件损坏），不补零
                return
            # 文件尾记录只剩半截：像 scapy 一样补零解析最后一个包。
            # 拷出补齐成独立 buffer 传入，零字节才会出现在载荷尾部
            padded = mm[pos:size] + b'\x00' * (pos + incl - size)
            yield parse_frame(ts_sec + ts_frac / ts_div, orig, incl,
                              padded, 0, incl)
            return
        yield parse_frame(ts_sec + ts_frac / ts_div, orig, incl, mm, pos, pos + incl)
        pos += incl


def _iter_pcapng(mm):
    bom = struct.unpack_from('<I', mm, 4)[0]
    if bom == 0x1A2B3C4D:
        endian = '<'
    elif bom == 0x4D3C2B1A:
        endian = '>'
    else:
        raise UnsupportedCapture(f'SHB 端序字段异常 0x{bom:08x}')
    shb_len = struct.unpack_from(endian + 'I', mm, 0)[0]
    if shb_len < 28 or shb_len > len(mm):
        raise UnsupportedCapture('SHB 长度异常')
    # 每个 IDB 一条 (帧解析器, 时间戳除数)；EPB 按 iface_id 取用
    interfaces = []
    last_ts = 0.0
    pos = shb_len
    size = len(mm)
    while pos + 12 <= size:
        btype, blen = struct.unpack_from(endian + 'II', mm, pos)
        if blen < 12 or pos + blen > size:
            return                       # 尾部块不完整，到此为止
        if btype == _PCAPNG_IDB:
            interfaces.append(_read_pcapng_idb(mm, pos, blen, endian))
        elif btype == _PCAPNG_EPB:
            iface, tsh, tsl, incl, orig = struct.unpack_from(endian + 'IIIII', mm, pos + 8)
            if iface < len(interfaces):
                parse_frame, ts_div = interfaces[iface]
            else:
                parse_frame, ts_div = _frame_parser(_LT_ETHERNET), 1e6
            data_pos = pos + 28
            if data_pos + incl > pos + blen - 4:
                if incl > _MAX_PAD_RECORD:   # 长度字段离谱（文件损坏），不补零
                    return
                padded = mm[data_pos:pos + blen - 4] + \
                    b'\x00' * (data_pos + incl - (pos + blen - 4))
                ts = ((tsh << 32) | tsl) / ts_div
                last_ts = ts
                yield parse_frame(ts, orig, incl, padded, 0, incl)
                return
            ts = ((tsh << 32) | tsl) / ts_div
            last_ts = ts
            yield parse_frame(ts, orig, incl, mm, data_pos, data_pos + incl)
        elif btype == _PCAPNG_SPB:
            orig = struct.unpack_from(endian + 'I', mm, pos + 8)[0]
            parse_frame, _ = (interfaces[-1] if interfaces
                              else (_frame_parser(_LT_ETHERNET), 1e6))
            # SPB 不带时间戳，沿用上一包时刻；包体只到块尾，防越界读入后续块
            yield parse_frame(last_ts, orig, orig, mm, pos + 12, pos + blen - 4)
        pos += blen


def _read_pcapng_idb(mm, pos, blen, endian):
    """读 IDB：返回 (帧解析器, 时间戳除数)。if_tsresol 缺省为 10^-6 微秒。"""
    linktype = struct.unpack_from(endian + 'H', mm, pos + 8)[0]
    ts_div = 1e6
    opt_pos = pos + 20                     # type(4)+len(4)+linktype(2)+reserved(2)+snaplen(4)
    opt_end = pos + blen - 4               # 块尾长度字段之前
    while opt_pos + 4 <= opt_end:
        code, olen = struct.unpack_from(endian + 'HH', mm, opt_pos)
        if code == 0:                      # opt_endofopt
            break
        if code == 9 and olen >= 1:        # if_tsresol
            flag = mm[opt_pos + 4]
            ts_div = float((2 if flag & 0x80 else 10) ** (flag & 0x7F))
        opt_pos += 4 + olen + ((4 - olen % 4) % 4)
    return _frame_parser(linktype), ts_div


def _frame_parser(linktype):
    """按链路层类型返回 (ts, orig_len, incl_len, mm, off, end) → FastPacket。"""
    if linktype == _LT_ETHERNET:
        return _frame_eth
    if linktype == _LT_SLL:
        return _frame_sll
    if linktype == _LT_SLL2:
        return _frame_sll2
    if linktype in (_LT_RAW_IP, _LT_RAW_IP_LEGACY):
        return _frame_raw_ip
    if linktype == _LT_LOOPBACK:
        return _frame_loopback
    raise UnsupportedCapture(f'链路层类型 {linktype} 不支持')


def _frame_eth(ts, wirelen, caplen, mm, off, end):
    if off + 14 > end:
        return FastPacket(ts, wirelen, caplen)
    etype = struct.unpack_from('!H', mm, off + 12)[0]
    off += 14
    while etype in _VLAN_TYPES:            # VLAN / QinQ：跳过 4 字节标签取真实以太类型
        if off + 4 > end:
            return FastPacket(ts, wirelen, caplen)
        etype = struct.unpack_from('!H', mm, off + 2)[0]
        off += 4
    return _parse_ip(ts, wirelen, caplen, mm, off, end, etype)


def _frame_sll(ts, wirelen, caplen, mm, off, end):
    if off + 16 > end:
        return FastPacket(ts, wirelen, caplen)
    etype = struct.unpack_from('!H', mm, off + 14)[0]
    return _parse_ip(ts, wirelen, caplen, mm, off + 16, end, etype)


def _frame_sll2(ts, wirelen, caplen, mm, off, end):
    if off + 20 > end:
        return FastPacket(ts, wirelen, caplen)
    etype = struct.unpack_from('!H', mm, off)[0]
    return _parse_ip(ts, wirelen, caplen, mm, off + 20, end, etype)


def _frame_raw_ip(ts, wirelen, caplen, mm, off, end):
    if off + 1 > end:
        return FastPacket(ts, wirelen, caplen)
    version = mm[off] >> 4
    return _parse_ip(ts, wirelen, caplen, mm, off, end,
                     _ETH_IPV4 if version == 4 else _ETH_IPV6)


def _frame_loopback(ts, wirelen, caplen, mm, off, end):
    if off + 4 > end:
        return FastPacket(ts, wirelen, caplen)
    family = struct.unpack_from('<I', mm, off)[0]
    return _parse_ip(ts, wirelen, caplen, mm, off + 4, end,
                     _ETH_IPV4 if family == 2 else _ETH_IPV6)


def _parse_ip(ts, wirelen, caplen, mm, off, end, etype):
    if etype == _ETH_IPV4:
        return _parse_ipv4(ts, wirelen, caplen, mm, off, end)
    if etype == _ETH_IPV6:
        return _parse_ipv6(ts, wirelen, caplen, mm, off, end)
    return FastPacket(ts, wirelen, caplen)


def _parse_ipv4(ts, wirelen, caplen, mm, off, end):
    if off + 20 > end or mm[off] >> 4 != 4:
        return FastPacket(ts, wirelen, caplen)
    ihl = (mm[off] & 0x0F) * 4
    if ihl < 20 or off + ihl > end:
        return FastPacket(ts, wirelen, caplen)
    ip_id = struct.unpack_from('!H', mm, off + 4)[0]
    flags_frag = struct.unpack_from('!H', mm, off + 6)[0]
    proto = mm[off + 9]
    src = inet_ntoa(mm[off + 12:off + 16])
    dst = inet_ntoa(mm[off + 16:off + 20])

    if flags_frag & 0x3FFF:                # MF 置位或分片偏移非零：进分片重组
        frag_off = (flags_frag & 0x1FFF) * 8
        more = bool(flags_frag & 0x2000)
        reasm = _ipv4_reassemble((src, dst, ip_id, proto), ts, frag_off, more,
                                 mm[off + ihl:end])
        if reasm is None:
            return FastPacket(ts, wirelen, caplen)
        # 重组包沿用首片到达时刻（与 scapy defragment 一致），否则 SIP 事件
        # 相对其他包的时序会漂移到末片之后
        first_ts, reasm = reasm
        return _parse_udp(first_ts, wirelen, caplen, reasm, 0, src, dst, len(reasm))

    if proto != _IPPROTO_UDP:
        return FastPacket(ts, wirelen, caplen)
    return _parse_udp(ts, wirelen, caplen, mm, off + ihl, src, dst, end)


# IPv4 分片重组缓存：(src, dst, ip_id, proto) → [(偏移, 分片数据, more)]。
# 抓包按时间序读入，同一数据报的分片天然相邻，重组完成即弹出；只为超过
# MTU 的大包付出代价（实际抓包里基本只有大 SDP 的 SIP 消息会分片）。
_ipv4_frag_cache = {}


def _ipv4_reassemble(key, first_ts, frag_off, more, data):
    """按 key 缓存分片直到凑齐，返回 (首片到达时刻, 重组数据)；未齐返回 None。"""
    frags = _ipv4_frag_cache.setdefault(key, [])
    frags.append((frag_off, data, more, first_ts))
    frags.sort(key=lambda fr: fr[0])
    covered = 0
    for off, payload, _more, _ts in frags:
        if off > covered:
            return None                    # 有空洞，等后续分片
        covered = max(covered, off + len(payload))
    last = frags[-1]
    if last[2] or covered != last[0] + len(last[1]):
        return None                        # 末片仍带 MF，或尾部没凑齐
    _ipv4_frag_cache.pop(key, None)
    return frags[0][3], b''.join(fr[1] for fr in frags)


def _parse_ipv6(ts, wirelen, caplen, mm, off, end):
    if off + 40 > end or mm[off] >> 4 != 6:
        return FastPacket(ts, wirelen, caplen)
    payload_len = struct.unpack_from('!H', mm, off + 4)[0]
    src = inet_ntop(AF_INET6, mm[off + 8:off + 24])
    dst = inet_ntop(AF_INET6, mm[off + 24:off + 40])
    if payload_len and off + 40 + payload_len <= end:
        end = off + 40 + payload_len
    nh = mm[off + 6]
    pos = off + 40
    while nh in _IPV6_SKIP_EXT:
        hdr_len = ((mm[pos + 1] + 2) * 4 if nh == _IPV6_EXT_AH
                   else (mm[pos + 1] + 1) * 8)
        if pos + hdr_len > end:
            return FastPacket(ts, wirelen, caplen)
        nh = mm[pos]
        pos += hdr_len
    if nh != _IPPROTO_UDP:                 # 其余（含分片头）不支持，放弃该包
        return FastPacket(ts, wirelen, caplen)
    return _parse_udp(ts, wirelen, caplen, mm, pos, src, dst, end)


def _parse_udp(ts, wirelen, caplen, data, off, src, dst, end):
    """解析 UDP 头并产出 FastPacket。data 为 mmap 或重组后的独立 bytes。

    载荷取到 IP total_len 边界为止，不用 UDP len 字段裁剪——部分包的
    len 字段与实际载荷不符（以太网最短帧补齐/网卡分载），scapy 也是
    这么处理的，保持逐字节兼容。
    """
    if off + 8 > end:
        return FastPacket(ts, wirelen, caplen)
    sport, dport = struct.unpack_from('!HH', data, off)
    payload = bytes(data[off + 8:end])
    return FastPacket(ts, wirelen, caplen, src, dst, sport, dport, payload)
