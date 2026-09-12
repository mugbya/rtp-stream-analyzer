"""
Call Detector
Group RTP streams into calls and assess capture completeness.

Concepts:
- conversation (leg): a bidirectional media flow between two IP:port endpoints,
  possibly seen in multiple capture files (matched by SSRC). Each phone call
  typically has several legs: at the FS capture the seat leg + terminal leg,
  and each side carries separate audio and video legs.
- call: a group of legs belonging to the same phone call, clustered by time
  overlap + shared IP. Concurrent/interleaved calls through the same server
  cluster into one group, so each call's own signaling is used to split them
  again (refine_calls): a leg belongs to a call only when one of its endpoint
  ip:port pairs was announced in that call's SDP (c=/m= lines), or — without
  SDP — touches the caller/answerer IP the flow identifies. Legs evicted this
  way re-cluster into their own calls (typically a second call with missing
  signaling), which become selectable analysis targets like any other.

Completeness signals (in priority order):
1. SIP signaling: INVITE before media start -> head captured; BYE after media
   end -> tail captured.
2. Uplink first sequence number: a stream originating at an endpoint with
   first_seq ~ 0 was captured from its beginning.
3. Time edge: media starting/ending right at the capture boundary suggests
   the call was already in progress / still ongoing when capture started/ended.
"""
from collections import defaultdict
from datetime import datetime

from analyzer.stream_classifier import AUDIO_PT, PT_NAMES

# Inactivity gap that splits one port pair into two conversations (port reuse
# by a later call). RTP flows at 20ms intervals, so an active call never has
# a 30s packet gap.
PORT_REUSE_GAP_S = 30.0
# Time overlap ratio required to cluster legs into the same call
CALL_OVERLAP_RATIO = 0.7
# Media starting this close to capture start -> suspect truncated head
HEAD_EDGE_S = 3.0
# Media ending this close to capture end -> suspect truncated tail
TAIL_EDGE_S = 3.0
# Uplink first seq <= this counts as "captured from stream start"
SEQ_FRESH_MAX = 50

STATUS_LABELS = {
    'complete': '完整',
    'truncated_head': '缺开头（抓包时通话已在进行）',
    'truncated_tail': '缺结尾（抓包结束时通话未结束）',
    'truncated_both': '首尾都不完整',
}


def build_conversations(rtp_data: dict, role: str) -> list:
    """Group RTP packets of one capture file into bidirectional conversations.

    A conversation is identified by its endpoint pair (both directions merged),
    and split on long inactivity gaps (port reuse across sequential calls).
    """
    packets = rtp_data['packets']
    per_key = defaultdict(list)
    for (ssrc, seq), v in packets.items():
        t, rtp_ts, pt, src_ip, dst_ip, sport, dport = v[:7]
        key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
        per_key[key].append((t, ssrc, seq, pt, src_ip, sport, dst_ip, dport))

    conversations = []
    for key, events in per_key.items():
        events.sort(key=lambda e: e[0])
        # Split on inactivity gaps: a new call reusing this port pair starts
        # a fresh conversation (new SSRCs).
        segments = []
        for ev in events:
            if not segments or ev[0] - segments[-1][-1][0] > PORT_REUSE_GAP_S:
                segments.append([])
            segments[-1].append(ev)

        for seg in segments:
            streams = {}
            for (t, ssrc, seq, pt, src_ip, sport, dst_ip, dport) in seg:
                if ssrc not in streams:
                    streams[ssrc] = {
                        'pt': pt,
                        'src_ip': src_ip, 'src_port': sport,
                        'dst_ip': dst_ip, 'dst_port': dport,
                        'first_seq': seq,
                        'first_seq_by_file': {role: seq},
                        'count': 0, 'start': t, 'end': t,
                    }
                s = streams[ssrc]
                s['count'] += 1
                s['start'] = min(s['start'], t)
                s['end'] = max(s['end'], t)

            conv = {
                'key': key,
                'endpoints': [key[0], key[1]],
                'ips': {key[0][0], key[1][0]},
                'start': seg[0][0],
                'end': seg[-1][0],
                'duration': seg[-1][0] - seg[0][0],
                'streams': streams,
                'ssrc_set': set(streams),
                'files': {role},
                'per_file_time': {role: (seg[0][0], seg[-1][0])},
            }
            conversations.append(conv)
    return conversations


def merge_conversations(all_convs: list) -> list:
    """Merge conversations from different capture files sharing an SSRC.

    The same media stream appears with identical SSRC at every capture point
    it passes through, so shared SSRC means the same leg seen twice.
    """
    merged = []
    for conv in sorted(all_convs, key=lambda c: c['start']):
        target = None
        for m in merged:
            if m['ssrc_set'] & conv['ssrc_set']:
                target = m
                break
        if target is None:
            merged.append(dict(conv))  # shallow copy; nested sets replaced below
            continue
        # Merge into target
        target['files'] |= conv['files']
        target['start'] = min(target['start'], conv['start'])
        target['end'] = max(target['end'], conv['end'])
        target['duration'] = target['end'] - target['start']
        for role, (s, e) in conv['per_file_time'].items():
            if role in target['per_file_time']:
                ps, pe = target['per_file_time'][role]
                target['per_file_time'][role] = (min(ps, s), max(pe, e))
            else:
                target['per_file_time'][role] = (s, e)
        for ssrc, st in conv['streams'].items():
            if ssrc in target['streams']:
                ts = target['streams'][ssrc]
                ts['count'] += st['count']
                ts['start'] = min(ts['start'], st['start'])
                ts['end'] = max(ts['end'], st['end'])
                ts['first_seq_by_file'].update(st['first_seq_by_file'])
            else:
                target['streams'][ssrc] = st
        target['ssrc_set'] |= conv['ssrc_set']
    return merged


def group_calls(conversations: list) -> list:
    """Cluster conversations into calls.

    Legs belong to the same call when their time ranges overlap strongly and
    they share at least one IP (opposite legs share the server IP; same-side
    audio/video legs share the endpoint IP). Sequential calls never overlap,
    so they stay separate. Concurrent calls sharing the server IP get merged
    here — refine_calls splits them again using each call's own signaling.
    """
    n = len(conversations)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    for i in range(n):
        for j in range(i + 1, n):
            a, b = conversations[i], conversations[j]
            if a['ssrc_set'] & b['ssrc_set']:
                union(i, j)
                continue
            if not (a['ips'] & b['ips']):
                continue
            overlap = max(0.0, min(a['end'], b['end']) - max(a['start'], b['start']))
            if overlap > CALL_OVERLAP_RATIO * max(min(a['duration'], b['duration']), 1e-9):
                union(i, j)

    groups = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(conversations[i])

    calls = []
    for legs in groups.values():
        start = min(l['start'] for l in legs)
        end = max(l['end'] for l in legs)
        calls.append({
            'legs': legs,
            'start': start,
            'end': end,
            'duration': end - start,
            'ssrcs': set().union(*[l['ssrc_set'] for l in legs]),
            'files': set().union(*[l['files'] for l in legs]),
        })
    calls.sort(key=lambda c: c['start'])
    return calls


def _fmt_time(t):
    return datetime.fromtimestamp(t).strftime('%H:%M:%S')


def assess_call_completeness(call: dict, file_info: dict, server_ip: str = None) -> dict:
    """Assess completeness of one call per capture file it appears in.

    file_info: {role: {'capture_start', 'capture_end', 'sip_events'}}.
    Returns {'status': overall, 'per_file': {role: {'status', 'reasons'}}}.
    """
    per_file = {}
    for role in sorted(call['files']):
        fi = file_info.get(role)
        if not fi or not fi.get('capture_start'):
            continue
        cap_start, cap_end = fi['capture_start'], fi['capture_end']
        sip_events = fi.get('sip_events', [])
        # Call time range as seen in this file
        c_start = min(l['per_file_time'][role][0] for l in call['legs'] if role in l['per_file_time'])
        c_end = max(l['per_file_time'][role][1] for l in call['legs'] if role in l['per_file_time'])

        reasons = []

        # Only trust this call's own signaling (by Call-ID) when available;
        # otherwise any INVITE/BYE near the media range is the fallback.
        call_ids = call.get('sip_call_ids') or set()

        # --- head ---
        head_truncated = False
        invites = [e for e in sip_events if e['method'] == 'INVITE'
                   and e['time'] <= c_start + 1.0
                   and (not call_ids or e.get('call_id') in call_ids)]
        if invites:
            reasons.append(f"INVITE {_fmt_time(invites[0]['time'])} 早于媒体开始，通话开头已抓到")
        else:
            # Uplink streams: originate at an endpoint (src != server)
            uplink_seqs = []
            for leg in call['legs']:
                if role not in leg['per_file_time']:
                    continue
                for ssrc, st in leg['streams'].items():
                    if server_ip and st['src_ip'] != server_ip and role in st['first_seq_by_file']:
                        uplink_seqs.append(st['first_seq_by_file'][role])
            if uplink_seqs and max(uplink_seqs) <= SEQ_FRESH_MAX:
                reasons.append(f"上行流首包 seq={min(uplink_seqs)}，媒体流从头被捕获")
            elif uplink_seqs:
                head_truncated = True
                reasons.append(f"上行流首包 seq={min(uplink_seqs)}（明显非零，流已进行一段时间）")
            elif c_start - cap_start < HEAD_EDGE_S:
                head_truncated = True
                reasons.append(f"通话开始距抓包开始仅 {c_start - cap_start:.1f}s（抓包时通话已在进行）")

        # --- tail ---
        tail_truncated = False
        byes = [e for e in sip_events if e['method'] == 'BYE'
                and e['time'] >= c_end - 1.0
                and (not call_ids or e.get('call_id') in call_ids)]
        if byes:
            reasons.append(f"BYE {_fmt_time(byes[-1]['time'])} 晚于媒体结束，通话挂断已抓到")
        else:
            tail_gap = cap_end - c_end
            if tail_gap < TAIL_EDGE_S:
                tail_truncated = True
                reasons.append(f"通话结束距抓包结束仅 {tail_gap:.1f}s（抓包结束时通话可能仍在进行）")
            else:
                reasons.append(f"媒体结束后抓包又持续 {tail_gap:.1f}s，通话自然结束")

        if head_truncated and tail_truncated:
            status = 'truncated_both'
        elif head_truncated:
            status = 'truncated_head'
        elif tail_truncated:
            status = 'truncated_tail'
        else:
            status = 'complete'

        per_file[role] = {'status': status, 'reasons': reasons}

    # Overall = worst status across files
    order = {'complete': 0, 'truncated_head': 1, 'truncated_tail': 1, 'truncated_both': 2}
    overall = 'complete'
    for pf in per_file.values():
        if order[pf['status']] > order[overall]:
            overall = pf['status']
    return {'status': overall, 'per_file': per_file}


# Events whose timestamps differ by less than this across capture files are the
# same signaling packet seen at two capture points (capture clocks differ by <1s
# but retransmissions can persist tens of seconds; same CSeq+method+src+dst is
# definitionally one message of one transaction)
SIP_DUP_WINDOW_S = 30.0
# 同一条信令在多个抓包里都有副本时保留哪份：FS 端单一时钟、两侧腿都看得见，
# 时序自洽，最优先；其次终端（主叫端）；最后坐席端。混用不同机器时钟的消息
# 会因时钟偏差在时间线上排错序
ROLE_PRIORITY = {'fs': 0, 'terminal': 1, 'seat': 2}
# A Call-ID group attaches to a call when its first message falls within this
# distance of the call's media range
SIP_ASSOC_WINDOW_S = 15.0


def build_sip_flows(calls: list, captures: dict, server_ip: str = None) -> None:
    """Attach a deduplicated SIP signaling flow to each detected call (in place).

    Signaling messages are grouped by Call-ID; each group is attached to the
    ONE call whose media range best overlaps the group's time span (window +
    max-overlap), so back-to-back calls between the same endpoints never leak
    signaling into each other's flow. Also sets call['sip_call_ids'] so
    completeness assessment only trusts this call's own INVITE/BYE, and
    call['answer_time'] / call['bye_time'] for the answered-media window.
    """
    all_events = []
    for role, rd in captures.items():
        for ev in rd.get('sip_events', []):
            all_events.append({
                'time': ev.get('time', 0.0),
                'method': ev.get('method', ''),
                'reason': ev.get('reason', ''),
                'call_id': ev.get('call_id', ''),
                'cseq': ev.get('cseq'),
                'cseq_method': ev.get('cseq_method', ''),
                'from': ev.get('from') or {},
                'to': ev.get('to') or {},
                'sdp': ev.get('sdp') or {},
                'src': ev.get('src', ''),
                'dst': ev.get('dst', ''),
                'file': role,
            })
    if not all_events:
        for c in calls:
            c['sip_flow'] = []
            c['answer_time'] = c['bye_time'] = None
            c['negotiated_codecs'] = {'audio': [], 'video': []}
            c['negotiated_per_leg'] = {}
            c['leg_codecs'] = {}
            c['sdp_endpoints'] = set()
            c['sdp_endpoints_by_cid'] = {}
            c['sdp_dialog_ranges'] = {}
            c['party_ips'] = set()
        return

    all_events.sort(key=lambda e: e['time'])
    deduped = []
    for ev in all_events:
        dup_idx = None
        for i in reversed(range(len(deduped))):
            seen = deduped[i]
            if ev['time'] - seen['time'] > SIP_DUP_WINDOW_S:
                break
            # Same CSeq number => retransmission of the same message (seen at
            # another capture point or repeated on the wire). A different CSeq
            # is a new transaction (e.g. INVITE resent with auth credentials).
            if (ev['call_id'] == seen['call_id'] and ev['method'] == seen['method']
                    and ev['cseq'] == seen['cseq']
                    and ev['src'] == seen['src'] and ev['dst'] == seen['dst']):
                dup_idx = i
                break
        if dup_idx is None:
            deduped.append(ev)
        elif (ROLE_PRIORITY.get(ev['file'], 9)
                < ROLE_PRIORITY.get(deduped[dup_idx]['file'], 9)):
            # 同一条消息的多抓包副本：换成本次上传里优先级更高的那份，
            # 保证整条时间线出自同一台机器的时钟
            deduped[dup_idx] = ev
    deduped.sort(key=lambda e: e['time'])

    # Group remaining messages by Call-ID
    by_call_id = defaultdict(list)
    for ev in deduped:
        by_call_id[ev['call_id']].append(ev)

    # Each Call-ID group belongs to exactly one call: among calls whose
    # association window covers the group's first message, pick the one with
    # the most SDP-announced media endpoints matching the call's actual media
    # legs (so concurrent calls that overlap in time still get their own
    # dialogs), then the largest overlap between group span and call media
    # range (ties broken by distance of the group start from the media range).
    attach = {}
    for cid, evs in by_call_id.items():
        g0, g1 = evs[0]['time'], evs[-1]['time']
        announced = set()
        for e in evs:
            for ep in (e.get('sdp') or {}).get('endpoints') or []:
                if ep.get('addr') and ep.get('port'):
                    announced.add((ep['addr'], ep['port']))
        best_idx, best_key = None, None
        for idx, call in enumerate(calls):
            lo = call['start'] - SIP_ASSOC_WINDOW_S
            hi = call['end'] + SIP_ASSOC_WINDOW_S
            if not (lo <= g0 <= hi):
                continue
            overlap = max(0.0, min(g1, call['end']) - max(g0, call['start']))
            dist = max(0.0, call['start'] - g0) + max(0.0, g0 - call['end'])
            hits = 0
            if announced:
                leg_pairs = set()
                for leg in call['legs']:
                    leg_pairs |= {(ip, p) for ip, p in leg['endpoints']}
                hits = len(announced & leg_pairs)
            key = (-hits, -overlap, dist)
            if best_key is None or key < best_key:
                best_idx, best_key = idx, key
        if best_idx is not None:
            attach[cid] = best_idx

    for idx, call in enumerate(calls):
        flow = [e for cid, i in attach.items() if i == idx for e in by_call_id[cid]]
        flow.sort(key=lambda e: e['time'])
        call['sip_call_ids'] = {cid for cid, i in attach.items() if i == idx}
        # 本通话信令里宣告的媒体端点（SDP c=/m= 行的 ip:port），按 Call-ID 分组：
        # 精确圈定本通话的 RTP 流，供 refine_calls 把误并入的其他通话腿剔除/
        # 拆分。B2BUA 一通电话的 A/B 腿是两个 Call-ID，分组保留这一结构
        by_cid_eps = {}
        by_cid_range = {}
        for cid in call['sip_call_ids']:
            eps = set()
            for e in by_call_id[cid]:
                for ep in (e.get('sdp') or {}).get('endpoints') or []:
                    if ep.get('addr') and ep.get('port'):
                        eps.add((ep['addr'], ep['port']))
            times = [e['time'] for e in by_call_id[cid] if e.get('time') is not None]
            if eps:
                by_cid_eps[cid] = eps
            if times:
                by_cid_range[cid] = (min(times), max(times))
        call['sdp_endpoints_by_cid'] = by_cid_eps
        # 每个 Call-ID 的信令时间范围：媒体只可能落在 INVITE 之后、BYE之前，
        # 供 refine_calls 的强匹配排除「端口复用」造成的跨通话误命中
        call['sdp_dialog_ranges'] = by_cid_range
        call['sdp_endpoints'] = set().union(*by_cid_eps.values()) if by_cid_eps else set()
        # 主叫/被叫 IP（无 SDP 宣告时的兜底过滤依据）
        call['party_ips'] = _call_party_ips(flow, server_ip)
        # 本通话会话里的 SDP：rtpmap 列出的编码 + PT→编码名映射（用于把
        # RTP 流实际使用的动态 PT 解析成编码名）
        sdp_codecs = {'audio': [], 'video': [], 'map': {'audio': {}, 'video': {}}}
        for cid in call['sip_call_ids']:
            for e in by_call_id[cid]:
                sdp = e.get('sdp') or {}
                for kind in ('audio', 'video'):
                    for name in sdp.get(kind, []):
                        if name not in sdp_codecs[kind]:
                            sdp_codecs[kind].append(name)
                    for pt, name in (sdp.get('map') or {}).get(kind, {}).items():
                        sdp_codecs['map'][kind].setdefault(pt, name)
        call['sdp_codecs'] = sdp_codecs
        # 应答/挂断时刻（用于「接通后媒体」区间）：应答 = INVITE 事务的 200 OK，
        # 优先取被叫设备发出的（B2BUA 里它先于服务器发给主叫的 200 OK）；挂断 =
        # 本通话第一条 BYE
        answers = [e['time'] for e in flow
                   if e['method'] == '200' and e.get('cseq_method') == 'INVITE']
        if server_ip:
            from_dev = [e['time'] for e in flow
                        if e['method'] == '200' and e.get('cseq_method') == 'INVITE'
                        and e['src'] != server_ip]
            if from_dev:
                answers = from_dev
        call['answer_time'] = min(answers) if answers else None
        byes = [e['time'] for e in flow if e['method'] == 'BYE']
        call['bye_time'] = min(byes) if byes else None

        # —— 每条腿（Call-ID）的 SDP offer/answer 配对 ——
        # B2BUA 一通电话两条腿各一个 Call-ID，两条腿的 INVITE 各自带 SDP（都
        # 是 offer），跨腿配对会把两条腿的 offer 错配成 offer/answer，所以按
        # Call-ID 分组后各自独立配对：每组第一条带编码名的 SDP 是 offer，其后
        # 第一条是 answer（183 早释应答或 200 OK；慢启动时 offer 在 200 OK、
        # answer 在 ACK）。FS 自产 INVITE 的 SDP 若解析不出编码名（audio/video
        # 均空）对"协商了什么"没有信息量，配对时跳过。
        # 腿角色：INVITE 发自服务器的是被叫腿（FS→被叫），发往服务器的是主叫
        # 腿；服务器 INVITE 不可见时退回「流程首条 INVITE 所在 Call-ID 是主
        # 叫腿」——B2BUA 的被叫腿 INVITE 必然晚于主叫腿。
        first_inv_cid = next((e['call_id'] for e in flow
                              if e['method'] == 'INVITE'), None)
        leg_codecs = {}
        for cid in call['sip_call_ids']:
            sdp_msgs = [e for e in by_call_id[cid]
                        if e.get('sdp')
                        and (e['sdp'].get('audio') or e['sdp'].get('video'))]
            if not sdp_msgs:
                continue
            negotiated, answered = _negotiate_leg(sdp_msgs)
            inv = next((e for e in by_call_id[cid] if e['method'] == 'INVITE'),
                       None)
            if inv is None:
                role = 'callee'   # 无 INVITE 副本的对话框按被叫腿处理
            elif server_ip and inv['src'] == server_ip:
                role = 'callee'
            elif server_ip and inv['dst'] == server_ip:
                role = 'caller'
            else:
                role = 'caller' if cid == first_inv_cid else 'callee'
            leg_codecs[cid] = {'role': role, 'answered': answered, **negotiated}
        call['leg_codecs'] = leg_codecs
        # 展示用协商编码按腿拆开（主叫侧/被叫侧各一份）：前端先分别摆出两
        # 条腿各协商定了什么编码，再接 fs_media 的转码判定——判定本身就是
        # 对比这两份结果，展示顺序与判定依据一致。每份带 answered 标志，
        # 只有 offer 没等到 answer 的腿如实标为"候选"。
        negotiated_per_leg = {}
        shown = None
        for role in ('caller', 'callee'):
            leg = _pick_leg(leg_codecs, role)
            if leg is None:
                continue
            leg_cid = next((cid for cid, l in leg_codecs.items() if l is leg),
                           None)
            names = {}
            for kind in ('audio', 'video'):
                names[kind] = list(dict.fromkeys(
                    c['name'] for c in leg[kind]))
            # call_id 供前端把该腿的协商行锚到这条腿自己的应答消息行之后
            negotiated_per_leg[role] = {**names, 'answered': leg['answered'],
                                        'call_id': leg_cid}
            if shown is None:
                shown = leg
        call['negotiated_per_leg'] = negotiated_per_leg
        # 旧汇总字段：主叫腿协商结果（无主叫腿 SDP 时退回任一腿），保持
        # 向后兼容；两腿差异由 fs_media 判定单独给出
        fallback = (negotiated_per_leg.get('caller')
                    or negotiated_per_leg.get('callee')
                    or {'audio': [], 'video': []})
        call['negotiated_codecs'] = {'audio': list(fallback['audio']),
                                     'video': list(fallback['video'])}
        call['sdp_answered'] = shown['answered'] if shown else False

        call['sip_flow'] = [{
            'time': e['time'],
            'time_str': _fmt_time(e['time']),
            'method': e['method'],
            'cseq_method': e.get('cseq_method', ''),
            'src': e['src'],
            'dst': e['dst'],
            # 所属腿（Call-ID）：前端按腿把协商行锚到该腿应答行之后
            'call_id': e.get('call_id'),
            'from': e.get('from') or {},
            'to': e.get('to') or {},
            'label': e['method'] + (' ' + e['reason'] if e['reason'] else ''),
            'kind': _sip_kind(e['method']),
            # 带 SDP 的消息（offer/answer）标注其列出的编码，供前端把协商
            # 编码行插到应答行之后
            'sdp_codecs': ({k: e['sdp'][k] for k in ('audio', 'video')
                            if e['sdp'].get(k)} if e.get('sdp') else None),
        } for e in flow]


def _sip_kind(method: str) -> str:
    """Message category for frontend coloring."""
    if method in ('INVITE', 'ACK', 'BYE', 'CANCEL', 'UPDATE', 'PRACK'):
        return 'request'
    if method.isdigit():
        code = int(method)
        if code < 200:
            return 'provisional'
        if code < 300:
            return 'success'
    return 'error'


def _sdp_codec_idents(sdp: dict, kind: str) -> list:
    """SDP 消息里某路媒体的编码身份列表（{'name', 'rate'}，m= 行顺序）。

    'full' 由 SDP 解析生成；手工构造/旧格式的 SDP 只有名字列表时回退——
    时钟率未知，两腿对比时按名字相等处理。
    """
    full = (sdp.get('full') or {}).get(kind)
    if full:
        return [{'name': c['name'], 'rate': c.get('rate')} for c in full]
    return [{'name': n, 'rate': None} for n in sdp.get(kind) or []]


def _codec_match(a: dict, b: dict) -> bool:
    """两编码是否视为同一种：名字相同，且任一方未报时钟率或时钟率一致。

    时钟率不同（如 OPUS/48000 vs OPUS/16000）是不同的编码格式，FS 必须转码。
    """
    if a['name'] != b['name']:
        return False
    ra, rb = a.get('rate'), b.get('rate')
    return ra is None or rb is None or ra == rb


def _negotiate_leg(sdp_msgs: list) -> tuple:
    """一个 Call-ID（= B2BUA 的一条腿）内的 offer/answer 配对。

    返回 ({'audio': [编码身份], 'video': [编码身份]}, 是否收到应答)。
    协商结果 = 双方列出编码的交集（保持 offer 顺序）；交集为空以 answer 为
    准（应答方决定，含拒绝某路媒体）；无 answer 时只有候选，谈不上协商。
    """
    offer = sdp_msgs[0]['sdp']
    answer = sdp_msgs[1]['sdp'] if len(sdp_msgs) > 1 else None
    negotiated = {}
    for kind in ('audio', 'video'):
        offered = _sdp_codec_idents(offer, kind)
        if answer is None:
            negotiated[kind] = offered
            continue
        ans = _sdp_codec_idents(answer, kind)
        negotiated[kind] = [c for c in offered
                            if any(_codec_match(c, a) for a in ans)] or ans
    return negotiated, answer is not None


def _pick_leg(leg_codecs: dict, role: str) -> dict | None:
    """取该角色、带编码数据的腿；有多条时（并发振铃的分叉目标各占一条被叫
    腿）优先真正应答的那条，分叉目标未应答的 offer 只代表候选。"""
    cands = [l for l in leg_codecs.values()
             if l.get('role') == role and (l.get('audio') or l.get('video'))]
    if not cands:
        return None
    answered = [l for l in cands if l.get('answered')]
    return (answered or cands)[0]


def _fmt_ident(c: dict) -> str:
    return c['name'] + (f"/{c['rate']}" if c.get('rate') else '')


def _compare_leg_codecs(caller: dict, callee: dict) -> dict | None:
    """对比两腿协商编码，判定 FS 是否参与转码。无可比数据返回 None。"""
    diff_parts, same_parts = [], []
    for kind in ('audio', 'video'):
        la, lb = caller.get(kind) or [], callee.get(kind) or []
        if not la or not lb:
            continue   # 该路媒体单侧无候选（被应答方拒绝或没抓到），跳过
        common = [c for c in la if any(_codec_match(c, x) for x in lb)]
        label = '音频' if kind == 'audio' else '视频'
        if common:
            same_parts.append(
                f"{label} {'/'.join(_fmt_ident(c) for c in common)}")
        else:
            diff_parts.append(
                f"{label}：主叫侧 {'/'.join(_fmt_ident(c) for c in la)}，"
                f"被叫侧 {'/'.join(_fmt_ident(c) for c in lb)}")
    if not diff_parts and not same_parts:
        return None
    if diff_parts:
        return {'verdict': 'transcode',
                'text': '两腿协商编码不同（' + '；'.join(diff_parts) +
                        '），FS 必然参与转码'}
    return {'verdict': 'same',
            'text': '两腿协商编码相同（' + '；'.join(same_parts) +
                    '），FS 无需转码'}


def _call_party_pair(flow: list, server_ip: str = None) -> tuple:
    """从信令流程识别主叫/被叫 IP（口径与 media_extractor.extract_call_parties
    一致，只取 IP）：主叫 = 第一个非服务器侧 INVITE 的源（回退首个请求），
    被叫 = INVITE 事务 200 OK 的非服务器发送方。识别不出返回 None。"""
    if not flow:
        return None, None
    inv = next((m for m in flow if m['method'] == 'INVITE'
                and m.get('src') != server_ip), None)
    if inv is None:
        inv = next((m for m in flow if m.get('kind') == 'request'
                    or not m['method'].isdigit()), None)
    if inv is None:
        inv = flow[0]
    ok = next((m for m in flow if m['method'] == '200'
               and m.get('cseq_method') == 'INVITE'
               and m.get('src') != server_ip), None)
    return (inv.get('src') if inv else None,
            ok.get('src') if ok else None)


def _call_party_ips(flow: list, server_ip: str = None) -> set:
    """主叫/被叫 IP 集合（供无 SDP 宣告时的兜底腿过滤）。"""
    return {ip for ip in _call_party_pair(flow, server_ip) if ip}


def _rebuild_call(call: dict) -> None:
    """腿集合变动后重算通话的时间范围 / SSRC / 抓包文件集合。"""
    legs = call['legs']
    call['start'] = min(l['start'] for l in legs)
    call['end'] = max(l['end'] for l in legs)
    call['duration'] = call['end'] - call['start']
    call['ssrcs'] = set().union(*[l['ssrc_set'] for l in legs]) if legs else set()
    call['files'] = set().union(*[l['files'] for l in legs]) if legs else set()


def _make_call(legs: list) -> dict:
    """用一组腿构造与 group_calls 输出同构的通话对象。"""
    call = {'legs': list(legs)}
    _rebuild_call(call)
    return call


def _legs_time_overlap(legs_a: list, legs_b: list) -> float:
    """两组腿媒体时间的重叠秒数（取成对重叠的最大值）。"""
    best = 0.0
    for a in legs_a:
        for b in legs_b:
            ov = min(a['end'], b['end']) - max(a['start'], b['start'])
            if ov > best:
                best = ov
    return best


def _split_call_by_sdp(call: dict, by_cid: dict, server_ip: str = None,
                       ranges: dict = None):
    """按各 Call-ID 的 SDP 宣告端点拆分/净化一通误合并的通话。

    返回 {'kept': [...], 'orphans': [...], 'new_calls': [[legs], ...]}。

    流端点 (ip,port) 命中某 Call-ID 宣告集合、且媒体时间落在该对话框信令
    时间范围内的（强匹配）归属该信令组——先后两通电话复用媒体端口时，两通
    的对话框会宣告相同的 (ip,port)，靠时间范围排除跨通话误命中；仅非服务
    器 IP 命中的（弱匹配，如同通话后来才协商出的新媒体端口——服务器 IP 被
    所有经转发的流共享，不算数）留在通话内；两者都不命中的是其他通话的流，
    剔出。强匹配信令组能按共享 Call-ID 合并（如同通话 re-INVITE 前后的宣
    告）。

    B2BUA 一通电话的 A/B 腿各是一个 Call-ID，经服务器转发时各自只宣告一端
    （半呼叫形状）。同一通话的 A/B 腿媒体并发，而先后两通电话的腿不重叠——
    据此把「腿时间重叠、且合并后非服务器端点不超过两端」的半形状组合并成完
    整呼叫单元（并发通话各自的端点对不上，冒出的第 3 个端点会挡住合并）。
    合并后存在 ≥2 个完整单元时按单元拆成多通——经同一服务器的先后/并发通话
    会因时间重叠或共享 IP 聚成一通，靠这一步拆回。
    """
    legs = call['legs']
    announced_ips = {ip for eps in by_cid.values() for ip, _p in eps}
    announced_ips -= {server_ip}

    strong, weak, foreign = {}, [], []
    ranges = ranges or {}
    for leg in legs:
        pairs = {(ip, p) for ip, p in leg['endpoints']}
        sig = frozenset()
        for cid, eps in by_cid.items():
            if not eps & pairs:
                continue
            rng = ranges.get(cid)
            if rng and (leg['start'] > rng[1] or rng[0] > leg['end']):
                continue   # 媒体时间在该对话框之外：端口复用的另一通话
            sig |= {cid}
        if sig:
            strong.setdefault(sig, []).append(leg)
        elif set(leg['ips']) & announced_ips:
            weak.append(leg)
        else:
            foreign.append(leg)

    if not strong:
        return None

    # 合并共享 Call-ID 的签名组（传递闭包），单元携带各自的腿
    units = []
    for sig, ls in strong.items():
        merged = [u for u in units if u['cids'] & sig]
        rest = [u for u in units if not (u['cids'] & sig)]
        cids, ulegs = set(sig), list(ls)
        for u in merged:
            cids |= u['cids']
            ulegs.extend(u['legs'])
        units = rest + [{'cids': cids, 'legs': ulegs}]

    def unit_ips(u) -> set:
        return {ip for cid in u['cids'] for ip, _p in by_cid[cid]} - {server_ip}

    # 半形状单元按腿时间重叠并成完整呼叫单元；并起来会冒出第 3 个非服务器
    # 端点的不并（那是另一通电话的端点）
    fulls = [u for u in units if len(unit_ips(u)) >= 2]
    partials = [u for u in units if len(unit_ips(u)) < 2]
    changed = True
    while changed:
        changed = False
        for i, u1 in enumerate(partials):
            for u2 in partials[i + 1:]:
                if len(unit_ips(u1) | unit_ips(u2)) > 2:
                    continue
                if _legs_time_overlap(u1['legs'], u2['legs']) <= 0:
                    continue
                u1['cids'] |= u2['cids']
                u1['legs'] = u1['legs'] + u2['legs']
                partials.remove(u2)
                changed = True
                break
            if changed:
                break
    fulls += [u for u in partials if len(unit_ips(u)) >= 2]
    # 仍不成形的散单元（同通话后来的 re-INVITE / 新媒体端口信令）：腿并进
    # 时间重叠最多的完整单元；与谁都不重叠的腿剔出
    for u in [p for p in partials if len(unit_ips(p)) < 2]:
        target = max(fulls, key=lambda f: _legs_time_overlap(f['legs'], u['legs']),
                     default=None)
        if target and _legs_time_overlap(target['legs'], u['legs']) > 0:
            target['legs'] = target['legs'] + u['legs']
        else:
            foreign.extend(u['legs'])

    if len(fulls) < 2:
        return {'kept': [l for ls in strong.values() for l in ls] + weak,
                'orphans': foreign, 'new_calls': []}

    # 拆成多通：第一单元留在原通话对象，其余单元作为新通话返回；弱匹配腿按
    # 宣告 IP + 时间重叠归入单元，归不进任何单元的剔出
    orphan = list(foreign)
    for leg in weak:
        lips = set(leg['ips']) - {server_ip}
        target, best_ov = None, 0.0
        for u in fulls:
            if not lips & unit_ips(u):
                continue
            ov = _legs_time_overlap(u['legs'], [leg])
            if ov > best_ov:
                target, best_ov = u, ov
        if target:
            target['legs'].append(leg)
        else:
            orphan.append(leg)
    return {'kept': fulls[0]['legs'],
            'orphans': orphan,
            'new_calls': [u['legs'] for u in fulls[1:]]}


def _split_call_by_parties(call: dict, server_ip: str = None):
    """无 SDP 宣告时的兜底：按信令识别的主叫/被叫 IP 剔除无关腿。

    经服务器转发的腿要求对端 IP 是主叫或被叫（否则任何经过服务器的他人通
    话都能蹭进来）；不经服务器的腿（点对点直连）要求两端至少一端命中。"""
    parties = call.get('party_ips') or set()
    if not parties:
        return None

    def ok(leg):
        ips = set(leg['ips'])
        if server_ip and server_ip in ips:
            others = ips - {server_ip}
            return bool(others & parties) if others else True
        return bool(ips & parties)

    kept = [l for l in call['legs'] if ok(l)]
    orphans = [l for l in call['legs'] if not ok(l)]
    if not kept or not orphans:
        return None   # 无可剔，或全部被剔（判定不可信，如信令 IP≠媒体 IP）
    return {'kept': kept, 'orphans': orphans, 'new_calls': []}


def refine_calls(calls: list, server_ip: str = None) -> list:
    """按每通通话自己的信令剔除误并入的他人通话腿，拆开被合并的通话（就地）。

    group_calls 以「时间重叠 + 共享 IP」聚类，经同一服务器的并发/交错通话会
    并成一通——媒体回放里随之混入其他通话的流（流条数超出单通话上限，出现
    既非主叫也非被叫的端点）。每通通话自己的信令能精确圈定它的媒体：优先用
    SDP 宣告端点（_split_call_by_sdp），无 SDP 时退回主叫/被叫 IP
    （_split_call_by_parties）。

    被剔出的腿与拆分出的腿重新聚类成新的通话（通常是缺信令/信令不全的另一
    通，照样可选来分析）；之后 detect_calls 会重跑一次信令关联（按 SDP 端点
    命中数优先），让各通拿到自己的 Call-ID 流程。
    """
    orphans = []
    new_calls = []
    for call in calls:
        by_cid = call.get('sdp_endpoints_by_cid') or {}
        if by_cid:
            split = _split_call_by_sdp(call, by_cid, server_ip,
                                       call.get('sdp_dialog_ranges'))
        else:
            split = _split_call_by_parties(call, server_ip)
        if not split:
            continue
        call['legs'] = split['kept']
        orphans.extend(split['orphans'])
        new_calls.extend(split['new_calls'])
    for legs in new_calls:
        calls.append(_make_call(legs))
    if orphans:
        for c in group_calls(orphans):
            calls.append(c)
    for call in calls:
        if call['legs']:
            _rebuild_call(call)
    return calls


def _is_direct_media(call: dict, server_ip: str | None) -> bool:
    """通话媒体是否完全不经服务器转发（点对点直连）。

    正常经服务器转发的通话，每条腿必有一端是服务器 IP；所有腿的端点都不含
    服务器 IP，说明媒体在两个端点之间直连（终端直拨坐席 / 旁路媒体）。
    """
    if not server_ip:
        return False
    return all(server_ip not in leg['ips'] for leg in call['legs'])


def _leg_pt_sides(call: dict, server_ip: str = None) -> dict:
    """无（完整）腿 SDP 时的兜底：按媒体路径把通话的腿分到主叫/被叫两侧，
    收集每侧实际使用的音频编码名（RTP 流真实出现的 PT 反查：动态 PT 用全
    流程 SDP rtpmap，静态 PT 用内置表并去掉括号说明，保持与 SDP 名可互比）。

    腿的归侧依据非服务器端点 IP：只与主叫 IP 通信的腿是主叫侧，只与被叫 IP
    通信的是被叫侧；两端直连的腿（p2p）与识别不出的腿不归侧。主被叫 IP 缺
    一或重合（信令只见到单侧）时返回空，表示不可比。
    """
    caller_ip, callee_ip = _call_party_pair(call.get('sip_flow') or [], server_ip)
    if not caller_ip or not callee_ip or caller_ip == callee_ip:
        return {}
    sdp_map = (call.get('sdp_codecs') or {}).get('map') or {}
    sides = {'caller': set(), 'callee': set()}
    for leg in call['legs']:
        others = set(leg['ips']) - ({server_ip} if server_ip else set())
        side = ('caller' if others == {caller_ip}
                else 'callee' if others == {callee_ip} else None)
        if side is None:
            continue
        for st in leg['streams'].values():
            name = ((sdp_map.get('audio') or {}).get(str(st['pt']))
                    or PT_NAMES.get(st['pt'], '').split(' (')[0])
            if name:
                sides[side].add(name)
    return {k: v for k, v in sides.items() if v}


def _fs_media_verdict(call: dict, is_p2p: bool, server_ip: str = None) -> dict:
    """判定「FS 参与编解码了吗」，供 SIP 流程展示。

    - bypass：媒体不经 FS（点对点直连 / FS bypass media），FS 不在媒体路径，
      未参与编解码；
    - transcode：两腿协商编码不同，FS 作为 B2BUA 必然解码再编码（转码）；
    - same：两腿编码相同，FS 即使在媒体路径也没有编码格式转换发生（是否
      透传/重打包不影响该结论）；
    - unknown：数据不足——只见到一条腿的协商编码、无 SDP 且 RTP PT 反查也
      不可比（如动态 PT 无 rtpmap）。

    SDP 对比不可行时用每条腿实际使用的音频 PT 反查编码名兜底（结论标注
    推断来源）。
    """
    if is_p2p:
        return {'verdict': 'bypass',
                'text': '媒体在两端之间直连（点对点 / bypass media），'
                        'FS 不在媒体路径，未参与编解码'}
    caller = _pick_leg(call.get('leg_codecs') or {}, 'caller')
    callee = _pick_leg(call.get('leg_codecs') or {}, 'callee')
    if caller and callee:
        res = _compare_leg_codecs(caller, callee)
        if res:
            return res
    sides = _leg_pt_sides(call, server_ip)
    if sides.get('caller') and sides.get('callee'):
        a = sorted(sides['caller'])
        b = sorted(sides['callee'])
        if a == b:
            return {'verdict': 'same',
                    'text': f"两腿实际使用的编码相同（{'、'.join(a)}），"
                            'FS 无需转码（依 RTP 载荷类型推断）'}
        return {'verdict': 'transcode',
                'text': f"主叫侧使用 {'、'.join(a)}，被叫侧使用 {'、'.join(b)}，"
                        'FS 参与转码（依 RTP 载荷类型推断）'}
    return {'verdict': 'unknown',
            'text': '未能同时看到两条腿的协商编码或实际编码，无法判定'}


def detect_calls(captures: dict, server_ip: str = None) -> list:
    """Detect calls across all uploaded captures.

    Args:
        captures: {role: rtp_data} from extract_rtp_packets (payload not needed).
        server_ip: detected server IP (for uplink identification).

    Returns:
        API-ready call list, sorted by start time:
        [{call_id, start, start_str, end_str, duration_s, files, stream_count,
          media_types, ssrcs, completeness: {status, per_file}, sip_flow: [...]}]
    """
    all_convs = []
    file_info = {}
    for role, rd in captures.items():
        all_convs.extend(build_conversations(rd, role))
        file_info[role] = {
            'capture_start': rd.get('capture_start'),
            'capture_end': rd.get('capture_end'),
            'sip_events': rd.get('sip_events', []),
        }

    merged = merge_conversations(all_convs)
    raw_calls = group_calls(merged)
    build_sip_flows(raw_calls, captures, server_ip)
    # 并发/交错通话会被时间重叠聚类并成一通：按每通自己的信令（SDP 宣告端点，
    # 无 SDP 时主被叫 IP）剔出误并入的腿并重聚类
    refine_calls(raw_calls, server_ip)
    # 拆分出的新通话也要拿到自己的信令流程/Call-ID，重跑一次关联
    build_sip_flows(raw_calls, captures, server_ip)

    results = []
    for idx, call in enumerate(raw_calls):
        completeness = assess_call_completeness(call, file_info, server_ip)

        pts = set()
        for leg in call['legs']:
            for st in leg['streams'].values():
                pts.add(st['pt'])
        media_types = []
        if any(pt in AUDIO_PT for pt in pts):
            media_types.append('audio')
        if any(96 <= pt <= 127 for pt in pts):
            media_types.append('video')

        # 实际使用的编码：由 RTP 流里真实出现的 PT 反查（静态 PT 名优先，
        # 动态 PT 96~127 靠 SDP rtpmap 解析；SDP 列出的是候选，不代表在用）。
        # 视频动态 PT 连 SDP 都没有时只能标注 PT 并说明 SDP 未抓到。
        sdp_map = (call.get('sdp_codecs') or {}).get('map') or {}

        def _pt_codec(kind, pt):
            return PT_NAMES.get(pt) or (sdp_map.get(kind) or {}).get(str(pt))

        codecs = {
            'audio': sorted({n for pt in pts if pt in AUDIO_PT
                             for n in [_pt_codec('audio', pt)] if n}),
            'video': sorted({n for pt in pts if 96 <= pt <= 127
                             for n in [_pt_codec('video', pt)] if n}),
        }
        if not codecs['video']:
            codecs['video'] = sorted({f'PT {pt}（SDP 未抓到）' for pt in pts if 96 <= pt <= 127})

        # 接通后媒体区间（通话区间 ≠ 通话媒体区间）：FS 从主叫一呼叫就可能开始
        # 收录 RTP（含回铃音等早期媒体），这里只统计被叫应答之后、首条 BYE 之前
        # 本通话 SSRC 的 RTP 包——即双方真正交换媒体的那段。
        ans, bye = call.get('answer_time'), call.get('bye_time')
        talk = (call['start'], call['end'])
        if ans is not None or bye is not None:
            lo = ans if ans is not None else call['start']
            hi = bye if bye is not None else call['end']
            in_win = [v[0] for rd in captures.values()
                      for (ssrc, _seq), v in rd['packets'].items()
                      if ssrc in call['ssrcs'] and lo <= v[0] <= hi]
            if in_win:
                talk = (min(in_win), max(in_win))
        talk_dur = talk[1] - talk[0]

        p2p = _is_direct_media(call, server_ip)
        results.append({
            'call_id': f'call_{idx + 1}',
            'start': call['start'],
            'start_str': _fmt_time(call['start']),
            'end_str': _fmt_time(call['end']),
            'duration_s': round(call['duration'], 1),
            'answer_time': call.get('answer_time'),
            'bye_time': call.get('bye_time'),
            'talk_start_str': _fmt_time(talk[0]),
            'talk_end_str': _fmt_time(talk[1]),
            'talk_duration_s': round(talk_dur, 1),
            'files': sorted(call['files']),
            'stream_count': len(call['ssrcs']),
            'media_types': media_types,
            'codecs': codecs,
            'negotiated_codecs': call.get('negotiated_codecs') or {'audio': [], 'video': []},
            'negotiated_per_leg': call.get('negotiated_per_leg') or {},
            'fs_media': _fs_media_verdict(call, p2p, server_ip),
            'sdp_answered': call.get('sdp_answered', True),
            'ssrcs': sorted(call['ssrcs']),
            'is_p2p': p2p,
            # 点对点直连时给出两端 IP，供提示文案直接展示（一眼确认）
            'p2p_endpoints': sorted({ip for leg in call['legs']
                                     for ip in leg['ips']}) if p2p else [],
            'completeness': completeness,
            'sip_flow': call.get('sip_flow', []),
            'sip_call_ids': sorted(call.get('sip_call_ids', set())),
        })
    return results


# 上传角色 → 展示名（跨抓包一致性提示用）
ROLE_DISPLAY = {'seat': '坐席端', 'fs': 'FS 端', 'terminal': '终端（主叫端）'}


def check_capture_consistency(calls: list, roles, server_ip: str = None,
                              server_roles=None) -> dict | None:
    """检查多份抓包之间是否至少共享一通通话（传错文件检测）。

    同一次通话的媒体流 SSRC 在每个经过的抓包点都相同，会被合并进同一通；
    因此正常情况下坐席端 / FS 端 / 终端三份抓包至少共同覆盖一通通话。若某
    两个角色之间找不到任何共同通话，说明这几个文件很可能不是同一次通话。

    例外：点对点直连通话（媒体不经服务器转发，如终端直拨坐席）只会出现在
    两个端点各自的抓包里，服务器抓包里天然没有。当所有"无共同通话"的角色
    对都含服务器侧抓包、且其余角色之间存在共享的点对点通话时，说明不是传
    错文件，提示改为点对点直连（kind='p2p'）：可直接选择该通话分析，服务
    器抓包的数据不会参与。

    Args:
        calls: detect_calls 的结果列表（需含 is_p2p / p2p_endpoints）。
        roles: 上传角色列表。
        server_ip: 检测到的服务器 IP（点对点判据依赖它）。
        server_roles: 抓包点位于服务器的角色（该抓包的 IP 集合含 server_ip），
            缺省回退为 {'fs'}。

    Returns:
        None 表示一致；否则 {
            'kind': 'p2p' | 'mismatch',
            'message': 提示文本,
            'roles': [{'role', 'display',
                       'overall': {'start', 'end', 'count'},
                       'calls': [{'label', 'start', 'end'}, ...]}, ...],
            'pairs': [{'a', 'b'}, ...]（无共同通话的角色对），
        }。roles 供前端渲染纵向列表：每份抓包一行（总体时间段 + 每通通话时间段）。
    """
    roles = list(dict.fromkeys(r for r in roles if r))
    if len(roles) < 2 or not calls:
        return None

    role_calls = {r: [c for c in calls if r in c['files']] for r in roles}
    pairs = []
    for i, a in enumerate(roles):
        for b in roles[i + 1:]:
            if not any({a, b} <= set(c['files']) for c in calls):
                pairs.append({'a': a, 'b': b})
    if not pairs:
        return None

    server_side = {r for r in (server_roles or []) if r in roles}
    if not server_side and 'fs' in roles:
        server_side = {'fs'}

    kind, message = 'mismatch', None
    # 点对点解释成立的条件：每个失败角色对都含服务器侧抓包（服务器抓不到
    # 这通电话），且非服务器角色之间确实共享着一通媒体直连的通话（两端都
    # 抓到，说明是同一通，而不是各抓各的）
    direct_calls = [c for c in calls
                    if c.get('is_p2p') and len(c['files']) >= 2] if server_side else []
    if direct_calls and all(server_side & {p['a'], p['b']} for p in pairs):
        kind = 'p2p'
        message = _p2p_message(direct_calls, pairs, role_calls,
                               server_side, server_ip)

    role_items = []
    for r in roles:
        cs = sorted(role_calls[r], key=lambda c: c['start'])
        overall = ({'start': cs[0]['start_str'], 'end': cs[-1]['end_str'],
                    'count': len(cs)} if cs else {'count': 0})
        role_items.append({
            'role': r,
            'display': ROLE_DISPLAY.get(r, r),
            'overall': overall,
            'calls': [{'label': f"通话 {c['call_id'].split('_')[-1]}",
                       'start': c['start_str'], 'end': c['end_str']} for c in cs],
        })

    if message is None:
        total_pairs = len(roles) * (len(roles) - 1) // 2
        scope = ('任意两端抓包之间都没有同一通通话' if len(pairs) == total_pairs
                 else '部分抓包两两之间没有同一通通话')
        message = (f'这几份抓包里可能不是同一次通话：{scope}。'
                   '请确认上传的文件是否传错；如需继续，请选择其中一通通话单独分析。')
    return {'kind': kind, 'message': message, 'roles': role_items, 'pairs': pairs}


def _p2p_message(direct_calls: list, pairs: list, role_calls: dict,
                 server_side: set, server_ip: str) -> str:
    """点对点直连提示文案：给出直连两端 IP 与服务器 IP，方便一眼确认。"""
    call = direct_calls[0]
    sharers = '、'.join(ROLE_DISPLAY.get(r, r) for r in call['files']
                        if r not in server_side)
    endpoints = ' ↔ '.join(call.get('p2p_endpoints') or [])
    servers = '、'.join(sorted({ROLE_DISPLAY.get(r, r) for r in server_side
                                if any(r in (p['a'], p['b']) for p in pairs)}))
    n = max(len(role_calls.get(r, [])) for r in server_side)
    count = f'{len(direct_calls)} 通点对点直连通话' if len(direct_calls) > 1 else '点对点直连通话'
    return (f'检测到{count}：{sharers}之间的通话媒体为端到端直连（{endpoints}），'
            f'未经过 {servers}（{server_ip}），因此 {servers}的抓包里没有这通通话'
            f'（其抓到的 {n} 通为该服务器同时段的其他通话）。'
            f'文件没有传错，选择这通通话分析即可，分析不会使用 {servers}的数据。')
