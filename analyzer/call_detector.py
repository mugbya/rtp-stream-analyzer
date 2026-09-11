"""
Call Detector
Group RTP streams into calls and assess capture completeness.

Concepts:
- conversation (leg): a bidirectional media flow between two IP:port endpoints,
  possibly seen in multiple capture files (matched by SSRC). Each phone call
  typically has several legs: at the FS capture the seat leg + terminal leg,
  and each side carries separate audio and video legs.
- call: a group of legs belonging to the same phone call, clustered by time
  overlap + shared IP.

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
    so they stay separate. Concurrent calls can be mis-grouped (known limit).
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
# same signaling packet seen at two capture points (capture clocks differ by <1s)
SIP_DUP_WINDOW_S = 3.0
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
        return

    all_events.sort(key=lambda e: e['time'])
    deduped = []
    for ev in all_events:
        dup = False
        for seen in reversed(deduped):
            if ev['time'] - seen['time'] > SIP_DUP_WINDOW_S:
                break
            # Same CSeq number => retransmission of the same message (seen at
            # another capture point or repeated on the wire). A different CSeq
            # is a new transaction (e.g. INVITE resent with auth credentials).
            if (ev['call_id'] == seen['call_id'] and ev['method'] == seen['method']
                    and ev['cseq'] == seen['cseq']
                    and ev['src'] == seen['src'] and ev['dst'] == seen['dst']):
                dup = True
                break
        if not dup:
            deduped.append(ev)

    # Group remaining messages by Call-ID
    by_call_id = defaultdict(list)
    for ev in deduped:
        by_call_id[ev['call_id']].append(ev)

    # Each Call-ID group belongs to exactly one call: among calls whose
    # association window covers the group's first message, pick the one with
    # the largest overlap between group span and call media range (ties broken
    # by distance of the group start from the media range).
    attach = {}
    for cid, evs in by_call_id.items():
        g0, g1 = evs[0]['time'], evs[-1]['time']
        best_idx, best_key = None, None
        for idx, call in enumerate(calls):
            lo = call['start'] - SIP_ASSOC_WINDOW_S
            hi = call['end'] + SIP_ASSOC_WINDOW_S
            if not (lo <= g0 <= hi):
                continue
            overlap = max(0.0, min(g1, call['end']) - max(g0, call['start']))
            dist = max(0.0, call['start'] - g0) + max(0.0, g0 - call['end'])
            key = (-overlap, dist)
            if best_key is None or key < best_key:
                best_idx, best_key = idx, key
        if best_idx is not None:
            attach[cid] = best_idx

    for idx, call in enumerate(calls):
        flow = [e for cid, i in attach.items() if i == idx for e in by_call_id[cid]]
        flow.sort(key=lambda e: e['time'])
        call['sip_call_ids'] = {cid for cid, i in attach.items() if i == idx}
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
        call['sip_flow'] = [{
            'time_str': _fmt_time(e['time']),
            'method': e['method'],
            'cseq_method': e.get('cseq_method', ''),
            'src': e['src'],
            'dst': e['dst'],
            'from': e.get('from') or {},
            'to': e.get('to') or {},
            'label': e['method'] + (' ' + e['reason'] if e['reason'] else ''),
            'kind': _sip_kind(e['method']),
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

        results.append({
            'call_id': f'call_{idx + 1}',
            'start': call['start'],
            'start_str': _fmt_time(call['start']),
            'end_str': _fmt_time(call['end']),
            'duration_s': round(call['duration'], 1),
            'talk_start_str': _fmt_time(talk[0]),
            'talk_end_str': _fmt_time(talk[1]),
            'talk_duration_s': round(talk_dur, 1),
            'files': sorted(call['files']),
            'stream_count': len(call['ssrcs']),
            'media_types': media_types,
            'codecs': codecs,
            'ssrcs': sorted(call['ssrcs']),
            'completeness': completeness,
            'sip_flow': call.get('sip_flow', []),
            'sip_call_ids': sorted(call.get('sip_call_ids', set())),
        })
    return results
