"""
RTCP SR/RR 解析器
从 UDP 载荷里解析 RTCP 复合包中的 SR（200）与 RR（201），供：
- 无声诊断：SR 的包数/字节数证明发送端确实在产媒体；RR 是接收端对每条
  入流的亲历上报（丢包率/抖动），能证明 RTCP 双向可达并给出接收侧视角；
- 延迟分析（后续）：SR 携带发送端 NTP↔RTP 时间映射，是跨抓包定位
  单向延迟的锚点。

RTP 复合包结构（RFC 3550 §6）：一个 UDP 数据报串接若干定长的 RTCP 包，
每个包首字节 version=2、第二字节是包类型，长度字段按 32 位字计（不含
首字）。这里只取 SR/RR，SDES/BYE/APP 忽略。
"""
import struct

PT_SR = 200
PT_RR = 201
# 一个 UDP 数据报里最多解析的 RTCP 子包数（复合包理论无上限，防御截断）
MAX_SUBPACKETS = 16


def parse_rtcp(payload: bytes) -> list:
    """解析一个 UDP 数据报里的 RTCP 复合包，返回其中的 SR/RR 事件。

    Returns:
        [{'kind': 'SR'|'RR', 'ssrc': int,          # 发送本 RTCP 包一方的 SSRC
          'rtp_ts', 'pkt_count', 'octet_count',     # 仅 SR
          'ntp_sec', 'ntp_frac',                    # 仅 SR：发送端墙钟（1900 起）
          'reports': [{'ssrc', 'fraction_lost_pct', 'cum_lost',
                       'ext_high_seq', 'jitter', 'lsr', 'dlsr'}, ...]}, ...]
        非 RTCP / 结构不合法返回 []。
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
                       'jitter', 'reporters': [接收端 SSRC...]}}}
    """
    sr, rr = {}, {}
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
        else:
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
    return {'sr': sr, 'rr': rr}
