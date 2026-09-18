"""
RTCP SR/RR 与反馈包（NACK/PLI/FIR）解析器
从 UDP 载荷里解析 RTCP 复合包中的 SR（200）、RR（201）与传输/载荷反馈
（205 NACK、206 PLI/FIR），供：
- 无声诊断：SR 的包数/字节数证明发送端确实在产媒体；RR 是接收端对每条
  入流的亲历上报（丢包率/抖动），能证明 RTCP 双向可达并给出接收侧视角；
- 视频问题分析：NACK 指名重传丢包、PLI/FIR 请求关键帧——接收端解码层
  "亲历过丢包/等不到参考帧"的直接佐证（视频花屏排查的关键指标）；
- 延迟分析（后续）：SR 携带发送端 NTP↔RTP 时间映射，是跨抓包定位
  单向延迟的锚点。

RTCP 复合包结构（RFC 3550 §6）：一个 UDP 数据报串接若干定长的 RTCP 包，
每个包首字节 version=2、第二字节是包类型，长度字段按 32 位字计（不含
首字）。反馈包结构见 RFC 4585：通用头后跟 被反馈媒体流 SSRC + FCI。
"""
import struct

PT_SR = 200
PT_RR = 201
# RTCP 传输层/载荷反馈（RFC 4585）：RTPFB(205) 的 NACK 指名重传丢包，
# PSFB(206) 的 PLI/FIR 是接收端请求关键帧——视频花屏排查的直接佐证
PT_RTPFB = 205
PT_PSFB = 206
FMT_NACK, FMT_PLI, FMT_FIR = 1, 1, 2
# 一个 UDP 数据报里最多解析的 RTCP 子包数（复合包理论无上限，防御截断）
MAX_SUBPACKETS = 16


def parse_rtcp(payload: bytes) -> list:
    """解析一个 UDP 数据报里的 RTCP 复合包，返回其中的 SR/RR 事件。

    Returns:
        [{'kind': 'SR'|'RR'|'NACK'|'PLI'|'FIR',
          'ssrc': int,                             # 发送本 RTCP 包一方的 SSRC
          'rtp_ts', 'pkt_count', 'octet_count',    # 仅 SR
          'ntp_sec', 'ntp_frac',                   # 仅 SR：发送端墙钟（1900 起）
          'reports': [{'ssrc', 'fraction_lost_pct', 'cum_lost',
                       'ext_high_seq', 'jitter', 'lsr', 'dlsr'}, ...],
          'media_ssrc', ...},                      # 仅 NACK/PLI/FIR（被反馈流）
          NACK 另有 'packets'/'requested'。非 RTCP / 结构不合法返回 []。
    """
    events = []
    offset = 0
    for _ in range(MAX_SUBPACKETS):
        if len(payload) - offset < 4:
            break
        b0 = payload[offset]
        pt = payload[offset + 1]
        if (b0 >> 6) != 2:            # version != 2：不是 RTCP 复合包
            return events if events else []
        words = int.from_bytes(payload[offset + 2:offset + 4], 'big')
        total = (words + 1) * 4
        if total < 4 or offset + total > len(payload):
            break                     # 长度不一致：截断/非 RTCP，丢弃剩余
        chunk = payload[offset:offset + total]
        try:
            if pt == PT_SR and len(chunk) >= 28:
                events.append(_parse_sr(chunk))
            elif pt == PT_RR and len(chunk) >= 8:
                events.append(_parse_rr(chunk))
            elif pt == PT_RTPFB and (b0 & 0x1F) == FMT_NACK and len(chunk) >= 12:
                events.append(_parse_nack(chunk))
            elif pt == PT_PSFB and (b0 & 0x1F) in (FMT_PLI, FMT_FIR) \
                    and len(chunk) >= 12:
                events.append(_parse_psfb(chunk, b0 & 0x1F))
        except struct.error:
            pass
        offset += total
    return events


def _parse_sr(chunk: bytes) -> dict:
    ssrc, ntp_sec, ntp_frac, rtp_ts, pkt_count, octet_count = struct.unpack(
        '!IIIIII', chunk[4:28])
    return {'kind': 'SR', 'ssrc': ssrc, 'ntp_sec': ntp_sec, 'ntp_frac': ntp_frac,
            'rtp_ts': rtp_ts, 'pkt_count': pkt_count, 'octet_count': octet_count,
            'reports': _parse_report_blocks(chunk, 28, rc=chunk[0] & 0x1F)}


def _parse_rr(chunk: bytes) -> dict:
    ssrc = struct.unpack('!I', chunk[4:8])[0]
    return {'kind': 'RR', 'ssrc': ssrc,
            'reports': _parse_report_blocks(chunk, 8, rc=chunk[0] & 0x1F)}


def _parse_nack(chunk: bytes) -> dict:
    """RTPFB NACK（FMT=1）：FCI 为 通用头(8B) + 若干 (seq, BLP) 记录，
    指名重传缺失的包。requested = 1 + BLP 置位数（每条记录最多 17 个 seq）。"""
    media_ssrc = struct.unpack('!I', chunk[8:12])[0]
    requested = 0
    records = 0
    for i in range(12, len(chunk) - 3, 4):
        records += 1
        blp = int.from_bytes(chunk[i + 2:i + 4], 'big')
        requested += 1 + bin(blp).count('1')
    return {'kind': 'NACK', 'ssrc': struct.unpack('!I', chunk[4:8])[0],
            'media_ssrc': media_ssrc, 'packets': records, 'requested': requested}


def _parse_psfb(chunk: bytes, fmt: int) -> dict:
    """PSFB PLI(FMT=1)/FIR(FMT=2)：FCI 为 发送方 SSRC(4B) + 媒体流 SSRC(4B)，
    接收端解码失败/等关键帧时发出，是"这路视频出过问题"的直接佐证。"""
    sender, media = struct.unpack('!II', chunk[4:12])
    return {'kind': 'PLI' if fmt == FMT_PLI else 'FIR', 'ssrc': sender,
            'media_ssrc': media}


def _parse_report_blocks(chunk: bytes, start: int, rc: int) -> list:
    reports = []
    for i in range(min(rc, (len(chunk) - start) // 24)):
        b = chunk[start + i * 24:start + (i + 1) * 24]
        ssrc = struct.unpack('!I', b[0:4])[0]
        fraction_lost = b[4]
        cum_lost = int.from_bytes(b[5:8], 'big')
        ext_high_seq, jitter = struct.unpack('!II', b[8:16])
        lsr, dlsr = struct.unpack('!II', b[16:24])
        reports.append({
            'ssrc': ssrc,
            'fraction_lost_pct': round(fraction_lost / 255 * 100, 1),
            'cum_lost': cum_lost,
            'ext_high_seq': ext_high_seq,
            'jitter': jitter,
            'lsr': lsr,
            'dlsr': dlsr,
        })
    return reports


def summarize_rtcp(rtp_data: dict) -> dict:
    """把一份抓包的 RTCP 事件汇总成按 SSRC 索引的最新状态。

    Args:
        rtp_data: extract_rtp_packets 的输出（含 rtcp_events）。

    Returns:
        {'sr': {ssrc: {'count', 'last_time', 'pkt_count', 'octet_count',
                       'rtp_ts', 'ntp_sec', 'ntp_frac'}},
         'rr': {ssrc: {'count', 'last_time', 'fraction_lost_pct', 'cum_lost',
                       'jitter', 'reporters': [接收端 SSRC...]}},
         'fb': {ssrc: {'nack': {'packets', 'requested', 'last_time',
                                'reporters': [...]},
                       'pli': {'count', 'last_time', 'reporters': [...]},
                       'fir': {'count', 'last_time', 'reporters': [...]}}}}
        fb 按被反馈的媒体流 SSRC 索引（NACK 指名重传、PLI/FIR 请求关键帧），
        只在有反馈事件时出现。
    """
    sr, rr, fb = {}, {}, {}
    for ev in rtp_data.get('rtcp_events') or []:
        t = ev.get('time', 0.0)
        if ev['kind'] == 'SR':
            cur = sr.get(ev['ssrc'])
            if cur is None or t >= cur['last_time']:
                sr[ev['ssrc']] = {
                    'count': (cur['count'] + 1) if cur else 1,
                    'last_time': t,
                    'pkt_count': ev.get('pkt_count'),
                    'octet_count': ev.get('octet_count'),
                    'rtp_ts': ev.get('rtp_ts'),
                    'ntp_sec': ev.get('ntp_sec'),
                    'ntp_frac': ev.get('ntp_frac'),
                }
        elif ev['kind'] == 'RR':
            for rep in ev.get('reports') or []:
                ssrc = rep['ssrc']
                cur = rr.get(ssrc)
                if cur is None:
                    rr[ssrc] = {
                        'count': 1,
                        'last_time': t,
                        'fraction_lost_pct': rep['fraction_lost_pct'],
                        'cum_lost': rep['cum_lost'],
                        'jitter': rep['jitter'],
                        'reporters': [ev['ssrc']],
                    }
                else:
                    # 统计值取最新一次上报，reporters 累积所有上报方
                    cur['count'] += 1
                    if ev['ssrc'] not in cur['reporters']:
                        cur['reporters'].append(ev['ssrc'])
                    if t >= cur['last_time']:
                        cur['last_time'] = t
                        cur['fraction_lost_pct'] = rep['fraction_lost_pct']
                        cur['cum_lost'] = rep['cum_lost']
                        cur['jitter'] = rep['jitter']
        elif ev['kind'] in ('NACK', 'PLI', 'FIR'):
            m = fb.setdefault(ev['media_ssrc'], {})
            key = ev['kind'].lower()
            cur = m.get(key)
            if cur is None:
                m[key] = {'last_time': t, 'reporters': [ev['ssrc']],
                          **({'packets': ev['packets'],
                              'requested': ev['requested']} if key == 'nack'
                             else {'count': 1})}
            else:
                cur['reporters'].append(ev['ssrc'])
                if t >= cur['last_time']:
                    cur['last_time'] = t
                if key == 'nack':
                    cur['packets'] += ev['packets']
                    cur['requested'] += ev['requested']
                else:
                    cur['count'] += 1
    out = {'sr': sr, 'rr': rr}
    if fb:
        out['fb'] = fb
    return out
