"""Capture Integrity
抓包文件完整性检测——对应 Wireshark 打开抓包时的两类提示：

1. "Packet size limited during capture"（快照截短）：抓包工具的快照长度
   （snaplen）小于包的真实长度，记录头里 orig_len > incl_len，包体只有前半截。
   载荷被切掉的包不影响 RTP 头解析（前 12 字节往往还在），延迟/抖动/序号等
   统计仍可信，但媒体重建的片段会缺内容。
2. "…cut off in the middle of a packet"（文件尾部不完整）：抓包被强制终止或
   文件传输出错，最后一个记录只剩半截。scapy 会静默补零继续解析，本模块通过
   原始记录头走查发现它。

两类都只提示、不阻断：分析照常进行，结论里注明数据受限的部分。
"""
import os
import struct

# 少于该字节数的“缺失”不视为截断：部分链路层会把帧尾 FCS 计入线上长度，
# 4 字节级别的差额属于统计口径噪声，不是真的丢了载荷
TRUNC_MIN_BYTES = 8

# pcap 全局头魔数（按大端读出的值 → 文件字段的实际端序）
_PCAP_MAGICS = {
    0xA1B2C3D4: '>', 0xD4C3B2A1: '<',
    0xA1B23C4D: '>', 0x4D3CB2A1: '<',
}
# pcapng 端序指示块（SHB）魔数与端序
_SHB_MAGIC = 0x0A0D0D0A
_PCAPNG_EPB = 0x00000006   # Enhanced Packet Block：含 captured/original 长度
_PCAPNG_IDB = 0x00000001   # Interface Description Block：含 snaplen
_PCAPNG_SPB = 0x00000003   # Simple Packet Block：无原始长度，跳过


def scan_pcap_headers(filepath: str) -> dict | None:
    """走查抓包文件的原始记录头，取文件级完整性指标。

    只读头部、seek 跳过包体，开销与包数成正比但与载荷大小无关。

    Returns:
        None 表示格式不认识/走查失败（scapy 那边还有按包的兜底统计）；
        否则 {'snaplen', 'record_count', 'truncated_records',
        'tail_incomplete'}。tail_incomplete=True：文件在最后一个记录中途
        戛然而止（传输出错/抓包强杀）。
    """
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
            if len(magic) < 4:
                return None
            magic = int.from_bytes(magic, 'big')

            if magic in _PCAP_MAGICS:
                endian = _PCAP_MAGICS[magic]
                f.seek(12, 1)                     # 跳到 snaplen 字段
                snaplen = struct.unpack(endian + 'I', f.read(4))[0]
                f.seek(4, 1)                      # link_type
                return _walk_pcap_records(f, endian, snaplen)

            if magic == _SHB_MAGIC:
                return _walk_pcapng_blocks(f)
    except (OSError, struct.error):
        pass
    return None


def _walk_pcap_records(f, endian: str, snaplen: int) -> dict:
    """pcap 记录区走查：逐条读 16 字节记录头，按 incl_len 跳到下一条。"""
    stats = {'snaplen': snaplen or None, 'record_count': 0,
             'truncated_records': 0, 'tail_incomplete': False,
             'min_captured_trunc': None}
    while True:
        hdr = f.read(16)
        if not hdr:
            break
        if len(hdr) < 16:
            stats['tail_incomplete'] = True
            break
        _ts_sec, _ts_frac, incl_len, orig_len = struct.unpack(endian + 'IIII', hdr)
        remaining = _skip(f, incl_len)
        if remaining < incl_len:
            # 包体中途结束：文件尾被截断（scapy 会补零继续解析）
            stats['tail_incomplete'] = True
            break
        stats['record_count'] += 1
        if orig_len - incl_len >= TRUNC_MIN_BYTES:
            stats['truncated_records'] += 1
            stats['min_captured_trunc'] = incl_len \
                if stats['min_captured_trunc'] is None \
                else min(stats['min_captured_trunc'], incl_len)
    return stats


def _walk_pcapng_blocks(f) -> dict | None:
    """pcapng 块走查：从 SHB 开始按块走，取 IDB 的 snaplen 与 EPB 的长短差。

    每个块为 [type 4][length 4][body...][length 4]；SHB 的 byte-order 字段
    （0x1A2B3C4D 按本机端序读出的值）决定后续字段的端序。
    """
    shb = f.read(12)                           # total(4) + bom(4) + 版本(4)
    if len(shb) < 12:
        return None
    bom = struct.unpack('<I', shb[4:8])[0]
    endian = '<' if bom == 0x1A2B3C4D else '>' if bom == 0x4D3C2B1A else None
    if endian is None:
        return None
    stats = {'snaplen': None, 'record_count': 0,
             'truncated_records': 0, 'tail_incomplete': False,
             'min_captured_trunc': None}

    def skip_block(body_len: int, blk_len: int) -> bool:
        """跳过块体并校验尾部 length；文件提前结束/长度不符返回 False。"""
        if body_len > 0 and _skip(f, body_len) < body_len:
            return False
        return f.read(4) == struct.pack(endian + 'I', blk_len)

    total = struct.unpack(endian + 'I', shb[0:4])[0]
    # shb 已读到 pos 16，剩 seglen(8) + 尾 length(4)；skip_block 自己校验尾部
    if not skip_block(total - 20, total):
        stats['tail_incomplete'] = True
        return stats

    while True:
        blk_hdr = f.read(8)
        if not blk_hdr:
            break
        if len(blk_hdr) < 8:
            stats['tail_incomplete'] = True
            break
        btype, blen = struct.unpack(endian + 'II', blk_hdr)
        if blen < 12:
            stats['tail_incomplete'] = True
            break
        body_len = blen - 12                   # 去掉头 8 字节与尾部 length 4 字节
        if btype == _PCAPNG_EPB:
            body = f.read(20)                  # iface(4)+时间戳(8)+两长度(8)
            if len(body) < 20:
                stats['tail_incomplete'] = True
                break
            cap_len, orig_len = struct.unpack(endian + 'II', body[12:20])
            if orig_len - cap_len >= TRUNC_MIN_BYTES:
                stats['truncated_records'] += 1
                stats['min_captured_trunc'] = cap_len \
                    if stats['min_captured_trunc'] is None \
                    else min(stats['min_captured_trunc'], cap_len)
            stats['record_count'] += 1
            if not skip_block(body_len - 20, blen):
                stats['tail_incomplete'] = True
                break
        elif btype == _PCAPNG_IDB:
            body = f.read(min(12, body_len))   # linktype(2)+reserved(2)+snaplen(4)+…
            if stats['snaplen'] is None and len(body) >= 8:
                stats['snaplen'] = struct.unpack(endian + 'I', body[4:8])[0] or None
            if not skip_block(body_len - len(body), blen):
                stats['tail_incomplete'] = True
                break
        else:                                  # SPB/选项块/其他：整块跳过
            if btype == _PCAPNG_SPB:
                stats['record_count'] += 1     # SPB 不带原始长度，无从判截短
            if not skip_block(body_len, blen):
                stats['tail_incomplete'] = True
                break
    return stats


def _skip(f, n: int) -> int:
    """向前跳过 n 字节，返回实际能跳过的字节数（文件提前结束时 < n）。

    seek 越过 EOF 并不会失败，tell() 还会报虚拟位置，所以必须先用文件
    大小把可跳字数钳住——否则损坏的超长长度字段会被当成正常跳过。
    """
    size = os.fstat(f.fileno()).st_size
    can = max(0, min(n, size - f.tell()))
    if can:
        f.seek(can, 1)
    return can


def build_integrity(file_stats: dict) -> dict:
    """把单文件的原始统计汇总成用户可读的完整性结论。

    file_stats: extract_rtp_packets 收集的 {'all_packets', 'truncated',
        'truncated_rtp', 'max_missing_bytes', 'file_cut'}，合并
        scan_pcap_headers 结果后的可选键 'snaplen'、'header_truncated'、
        'tail_incomplete'。header_truncated 是记录头级别的快照截短数
        （不含尾部半包），优先于按包统计的 truncated。

    Returns:
        {'status': 'ok'|'warn', 'notes': [str], ...原始统计}。
        status=warn 时前端/报告照常分析，只追加提示。
    """
    header_truncated = file_stats.get('header_truncated')
    trunc = (header_truncated if header_truncated is not None
             else file_stats.get('truncated', 0))
    file_cut = bool(file_stats.get('file_cut')) or \
        bool(file_stats.get('tail_incomplete'))
    # 按 RTP 分类数来自逐包统计，可能把尾部半包也计进去了，封顶对齐
    rtp_n = min(file_stats.get('truncated_rtp', 0), trunc) \
        if header_truncated is not None else file_stats.get('truncated_rtp', 0)

    out = {
        'status': 'ok',
        'notes': [],
        'all_packets': file_stats.get('all_packets', 0),
        'truncated': trunc,
        'truncated_rtp': rtp_n,
        'max_missing_bytes': file_stats.get('max_missing_bytes', 0),
        'file_cut': file_cut,
        'snaplen': file_stats.get('snaplen'),
    }
    notes = []
    if trunc:
        scope = f'（其中 RTP 媒体包 {rtp_n} 个）' if rtp_n else ''
        # 快照长度只有在确实等于截短包的捕获长度时才展示——它才是截短原因
        snap = ''
        if out['snaplen'] and file_stats.get('min_captured_trunc') == out['snaplen']:
            snap = f'，抓包快照长度 {out["snaplen"]} 字节'
        notes.append(
            f'{trunc} 个包在捕获时被截短{scope}{snap}，'
            f'最多缺失 {out["max_missing_bytes"]} 字节——'
            '这类包的载荷不完整，媒体重建的对应片段会缺内容')
    if file_cut:
        notes.append('抓包文件在最后一个包的中途结束（抓包被强制终止或'
                     '文件传输出错），文件尾部的数据不完整')
    out['notes'] = notes
    out['status'] = 'warn' if notes else 'ok'
    return out


def merge_integrity(items) -> dict | None:
    """多份抓包的完整性汇总：有任何警告即返回逐文件条目供前端渲染。

    Args:
        items: [{'role', 'filename', 'integrity': {...}}, ...]

    Returns:
        None 表示全部完整；否则 {'files': [{'role', 'filename', 'notes'}]}。
    """
    warned = [{'role': it['role'], 'filename': it['filename'],
               'notes': it['integrity'].get('notes', [])}
              for it in items
              if it.get('integrity', {}).get('status') == 'warn']
    return {'files': warned} if warned else None
