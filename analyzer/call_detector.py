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
  cluster into one group, so refine_calls re-binds ALL legs against ALL
  signaling dialogs globally: a leg binds to a dialog when one of its endpoint
  ip:port pairs was announced in that dialog's SDP (and its media time
  intersects the dialog), or — for dialogs without SDP — when the leg's device
  IP matches the dialog's signaling peers and its media end/start hugs the
  dialog's last/first message. Legs sharing a dialog merge into one unit;
  units merge only when their media overlaps and no third non-server endpoint
  appears (B2BUA half-call shape). Leftover legs re-cluster into their own
  calls (typically a second call with missing signaling), which become
  selectable analysis targets like any other.

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
# 腿的媒体结束/开始贴近对话框末条/首条消息这个距离内，才允许按对端 IP 绑定
# （无 SDP 宣告的对话框）。同一设备同时刻的多通电话里，只有与该对话框同呼
# 叫的那通腿会贴着它的 BYE/INVITE 结束或开始。对话框时间窗两端也按此距离
# 放宽（媒体在 BYE 前零点几秒停流、在 INVITE 后零点几秒才开始，都算相交）
DIALOG_BIND_PROX_S = 6.0
# 半呼叫形状合并时，两个单元的媒体结束时间相差不得超过此值——同通话两侧
# 腿在挂断时同时停流。只看「时间重叠 + 端点 ≤2」会把共享同一设备 IP 的两
# 个不同通话的半边链式焊成一团
END_ALIGN_S = 3.0

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
            # Uplink streams: originate at an endpoint (src != server). Judge
            # only streams already flowing near the call's media start: a
            # stream appearing later mid-call (e.g. new SSRC after a
            # re-INVITE) has a first seq that says nothing about whether the
            # call's beginning was captured.
            uplink_seqs = []
            for leg in call['legs']:
                if role not in leg['per_file_time']:
                    continue
                for ssrc, st in leg['streams'].items():
                    if (server_ip and st['src_ip'] != server_ip
                            and role in st['first_seq_by_file']):
                        uplink_seqs.append(
                            (st['start'], st['first_seq_by_file'][role]))
            early = [seq for start, seq in uplink_seqs
                     if start <= c_start + HEAD_EDGE_S]
            if early and max(early) <= SEQ_FRESH_MAX:
                reasons.append(f"上行流首包 seq={min(early)}，媒体流从头被捕获")
            elif early:
                head_truncated = True
                seq_span = (str(min(early)) if min(early) == max(early)
                            else f"{min(early)}~{max(early)}")
                reasons.append(f"上行流首包 seq={seq_span}（明显非零，流已进行一段时间）")
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
            c['sip_peers_by_cid'] = {}
            c['media_redirects'] = []
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
    # dialogs), then the most non-server signaling-peer IPs matching the call's
    # media endpoints (dialogs without SDP have no announced endpoints to
    # match), then the largest overlap between group span and call media
    # range (ties broken by distance of the group start from the media range).
    attach = {}
    for cid, evs in by_call_id.items():
        g0, g1 = evs[0]['time'], evs[-1]['time']
        announced = set()
        for e in evs:
            for ep in (e.get('sdp') or {}).get('endpoints') or []:
                if ep.get('addr') and ep.get('port'):
                    announced.add((ep['addr'], ep['port']))
        peers = {ip for e in evs for ip in (e.get('src'), e.get('dst'))
                 if ip and ip != server_ip}
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
                for leg in call.get('legs') or []:
                    leg_pairs |= {(ip, p) for ip, p in leg['endpoints']}
                hits = len(announced & leg_pairs)
            peer_hits = 0
            if peers:
                leg_ips = set()
                for leg in call.get('legs') or []:
                    leg_ips |= set(leg['ips'])
                leg_ips.discard(server_ip)
                peer_hits = len(peers & leg_ips)
            key = (-hits, -peer_hits, -overlap, dist)
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
        by_cid_peers = {}
        for cid in call['sip_call_ids']:
            eps = set()
            peers = set()
            for e in by_call_id[cid]:
                for ep in (e.get('sdp') or {}).get('endpoints') or []:
                    if ep.get('addr') and ep.get('port'):
                        eps.add((ep['addr'], ep['port']))
                for ip in (e.get('src'), e.get('dst')):
                    if ip and ip != server_ip:
                        peers.add(ip)
            times = [e['time'] for e in by_call_id[cid] if e.get('time') is not None]
            if eps:
                by_cid_eps[cid] = eps
            if times:
                by_cid_range[cid] = (min(times), max(times))
            if peers:
                by_cid_peers[cid] = peers
        call['sdp_endpoints_by_cid'] = by_cid_eps
        # 每个 Call-ID 的信令时间范围：媒体只可能落在 INVITE 之后、BYE之前，
        # 供 refine_calls 的强匹配排除「端口复用」造成的跨通话误命中
        call['sdp_dialog_ranges'] = by_cid_range
        # 每个 Call-ID 的信令对端 IP（非服务器侧 src/dst）：无 SDP 宣告的对话
        # 框（如抓包前已建立、只剩 re-INVITE/BYE 的通话）靠它把媒体腿绑定到
        # 所属通话
        call['sip_peers_by_cid'] = by_cid_peers
        call['sdp_endpoints'] = set().union(*by_cid_eps.values()) if by_cid_eps else set()
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

        # —— 媒体改道（bypass media / SDP 透传）检测 ——
        # FS 中转媒体时，它自己产出的 SDP 一律宣告 FS 的媒体地址；若 FS 发出
        # 的消息里宣告的媒体端点是通话中另一台设备的 ip:port，说明 FS 把另一
        # 条腿的 SDP 原样透传了出去——媒体被改道为端到端直连，此后不再经过
        # FS（实测上表现为各端在改道后停止向 FS 上行 RTP）
        dev_ips = {ip for leg in (call.get('legs') or [])
                   for ip in (leg.get('ips') or [])}
        if server_ip:
            dev_ips.discard(server_ip)
        flow_redirects = {}
        for i, e in enumerate(flow):
            if server_ip and e['src'] != server_ip:
                continue
            hits = [ep for ep in (e.get('sdp') or {}).get('endpoints') or []
                    if ep.get('addr') in dev_ips]
            if hits:
                flow_redirects[i] = {
                    'targets': sorted({ep['addr'] for ep in hits}),
                    'ports': sorted({ep['port'] for ep in hits if ep.get('port')}),
                }
        call['media_redirects'] = [
            {'time': flow[i]['time'], 'time_str': _fmt_time(flow[i]['time']),
             'method': flow[i]['method'],
             'label': flow[i]['method'] + (' ' + flow[i]['reason']
                                           if flow[i]['reason'] else ''),
             'dst': flow[i]['dst'], 'call_id': flow[i].get('call_id'),
             **info}
            for i, info in flow_redirects.items()
        ]

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
            # FS 在此消息里把对端媒体地址透传给了本端（媒体改道证据），供
            # 信令阶梯图在消息行上直接标注
            'media_redirect': flow_redirects.get(i),
        } for i, e in enumerate(flow)]


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

    按时间顺序扫描该腿带 SDP 的消息，以信令事务（CSeq）为单位配对，取
    **最后一轮完整配对**作为该腿的协商结果——407 鉴权重发、桥接 blink
    re-INVITE、会话刷新 re-INVITE 都会重新协商编码，实际生效的是最后一轮：

    - 带 SDP 的 INVITE 是 offer（其应答 1xx/2xx 的 CSeq 与之一致才算它的
      answer；200 OK 之后再配 183 会被覆盖，最终答案以最终应答为准）；
    - 无 SDP 的 blink INVITE 之后，设备在 200 OK 里发 offer、FS 的 ACK 带
      answer（慢启动同理：offer 在 200 OK、answer 在 ACK）；
    - FS 自产 INVITE 的 SDP 若解析不出编码名（audio/video 均空）对"协商了
      什么"没有信息量，调用方已过滤。

    返回 ({'audio': [编码身份], 'video': [编码身份]}, 是否收到应答)。
    协商结果 = 双方列出编码的交集（保持 offer 顺序）；交集为空以 answer 为
    准（应答方决定，含拒绝某路媒体）；无 answer 时只有候选，谈不上协商。
    """
    negotiated = None
    answered = False
    pending = None     # 待应答的 offer {'sdp':…, 'cseq':…}
    last_cseq = None   # 最近一轮配对的 offer 事务号：同事务的最终应答覆盖早先的 183
    last_offer_sdp = None
    for e in sdp_msgs:
        sdp = e.get('sdp') or {}
        if not (sdp.get('audio') or sdp.get('video')):
            continue
        if e['method'] == 'INVITE':
            pending = {'sdp': sdp, 'cseq': e.get('cseq')}
            continue
        if e['method'].isdigit():
            if pending is not None and e.get('cseq') == pending['cseq']:
                negotiated = _pair_offer_answer(pending['sdp'], sdp)
                answered = True
                last_cseq = pending['cseq']
                last_offer_sdp = pending['sdp']
                pending = None
            elif pending is None and e.get('cseq') == last_cseq:
                # 同一事务更晚的应答（183 早释 → 200 OK 最终应答）覆盖更新
                negotiated = _pair_offer_answer(last_offer_sdp, sdp)
            elif pending is None:
                # 无 SDP 的 blink re-INVITE 之后，应答方在 200 OK 里发 offer
                pending = {'sdp': sdp, 'cseq': e.get('cseq')}
            continue
        if e['method'] == 'ACK' and pending is not None \
                and e.get('cseq') == pending['cseq']:
            negotiated = _pair_offer_answer(pending['sdp'], sdp)
            answered = True
            last_cseq = pending['cseq']
            last_offer_sdp = pending['sdp']
            pending = None
    if negotiated is None and pending is not None:
        # 只有 offer 没等到应答：如实给候选
        negotiated = _pair_offer_answer(pending['sdp'], None)
        answered = False
    if negotiated is None:
        negotiated = {'audio': [], 'video': []}
    return negotiated, answered


def _pair_offer_answer(offer: dict, answer: dict | None) -> dict:
    """一轮 offer/answer 的协商结果：交集（offer 顺序），空则以 answer 为准。"""
    negotiated = {}
    for kind in ('audio', 'video'):
        offered = _sdp_codec_idents(offer, kind)
        if answer is None:
            negotiated[kind] = offered
            continue
        ans = _sdp_codec_idents(answer, kind)
        negotiated[kind] = [c for c in offered
                            if any(_codec_match(c, a) for a in ans)] or ans
    return negotiated


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
    被叫 = INVITE 事务 200 OK 的非服务器发送方；未接通（CANCEL/486/480/487
    收场）没有 200 OK 时，被叫退而取信令里出现最多的非服务器对端。识别不出
    返回 None。"""
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
    callee = ok.get('src') if ok else None
    if callee is None:
        caller_ip = inv.get('src') if inv else None
        peers = {}
        for m in flow:
            for ip in (m.get('src'), m.get('dst')):
                if ip and ip != server_ip and ip != caller_ip:
                    peers[ip] = peers.get(ip, 0) + 1
        if peers:
            callee = max(peers, key=peers.get)
    return (inv.get('src') if inv else None, callee)


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


def _dialog_views(calls: list, server_ip: str = None) -> dict:
    """汇总所有通话信令里的对话框（Call-ID）信息，形成全局视图。

    第一轮信令关联只是按时间窗口尽力而为，可能把多个对话框并进同一通，也
    可能漏掉归属；拆分必须面对全部对话框一次做完——逐通话拆分会把缺头/缺尾
    通话的残腿错并进时间重叠的其他通话（服务器侧抓包里截到多通进行中的通话
    时必然如此）。返回 {cid: {'eps': SDP 宣告 (ip,port) 集,
    'range': (首条, 末条) 信令时间, 'peers': 非服务器侧信令对端 IP 集}}。
    """
    views = {}
    for call in calls:
        eps_by = call.get('sdp_endpoints_by_cid') or {}
        ranges = call.get('sdp_dialog_ranges') or {}
        peers_by = call.get('sip_peers_by_cid') or {}
        for cid in set(eps_by) | set(ranges) | set(peers_by):
            v = views.setdefault(
                cid, {'eps': set(), 'range': None, 'peers': set()})
            v['eps'] |= eps_by.get(cid) or set()
            v['peers'] |= peers_by.get(cid) or set()
            rng = ranges.get(cid)
            if rng:
                lo, hi = v['range'] or rng
                v['range'] = (min(lo, rng[0]), max(hi, rng[1]))
    return views


def refine_calls(calls: list, server_ip: str = None) -> list:
    """按信令对话框与媒体腿的全局绑定关系重建通话分组（就地）。

    group_calls 以「时间重叠 + 共享 IP」聚类，经同一服务器的并发/交错通话会
    并成一通——媒体回放里随之混入其他通话的流（流条数超出单通话上限，出现
    既非主叫也非被叫的端点）。对话框与媒体腿的对应关系是全局事实，一次性重
    绑：

    1. 强绑定——腿的端点 (ip,port) 命中对话框的 SDP 宣告、且媒体时间与对话
       框相交（允许媒体早于对话框首条消息：抓包开始前已建立的通话只有
       re-INVITE/BYE 落在抓包里，媒体却从头就在）；先后两通电话复用媒体端
       口时靠时间相交排除跨通话误命中；
    2. 对端绑定——无 SDP 宣告的对话框（只剩 BYE/re-INVITE 的半截信令）按
       信令对端 IP 绑定未强绑定的腿：腿的非服务器 IP 命中对端、媒体与对话
       框相交，多候选取媒体结束/开始贴对话框末条/首条消息最近的（同一设备
       的并发通话里只有同呼叫的那通贴着它的 BYE 挂断）；唯一的腿×对话框组合
       直接绑定，不要求贴近；
    3. 共享对话框的腿聚成组件；组件两两按「媒体时间重叠 + 合并后非服务器
       端点 ≤2 + 媒体结束时间对齐」并成通话——B2BUA 一通电话两侧腿媒体并
       发、挂断时同时停流，且只涉及两个设备端点（半呼叫形状）；冒出第 3 个
       端点、或挂断时刻对不上（共享同一设备 IP 的另一通电话会同时并发）即
       另一通电话；
    4. 没绑上任何对话框的腿（RTCP 端口对、信令全缺的媒体）：非服务器 IP 与
       某组件相交且时间重叠的归入，否则按旧规则（时间重叠 + 共享 IP）自聚
       成无信令通话。

    之后 detect_calls 会重跑一次信令关联（SDP 端点命中 + 对端 IP 命中优先），
    让各通拿到自己的 Call-ID 流程。
    """
    views = _dialog_views(calls, server_ip)
    if not calls or not views:
        return calls

    legs = [leg for call in calls for leg in call['legs']]

    def devips(leg) -> set:
        ips = set(leg['ips'])
        if server_ip:
            ips.discard(server_ip)
        return ips

    def crosses(leg, rng) -> bool:
        # 对话框时间窗两端放宽：BYE 前媒体先停、INVITE 后媒体才起，都算相交
        return not (leg['start'] > rng[1] + DIALOG_BIND_PROX_S
                    or rng[0] - DIALOG_BIND_PROX_S > leg['end'])

    # 1. 强绑定：SDP 宣告端点命中 + 媒体时间与对话框相交
    bound = {}
    for i, leg in enumerate(legs):
        pairs = {(ip, p) for ip, p in leg['endpoints']}
        cids = {cid for cid, v in views.items()
                if v['eps'] & pairs
                and (not v['range'] or crosses(leg, v['range']))}
        if cids:
            bound[i] = cids

    # 2. 对端绑定：无 SDP 宣告的对话框按信令对端 IP 绑定剩余腿
    cand_cids = {}    # 腿 -> 候选对话框集
    cand_legs = defaultdict(set)   # 对话框 -> 候选腿集
    for i, leg in enumerate(legs):
        if i in bound:
            continue
        dev = devips(leg)
        if not dev:
            continue
        for cid, v in views.items():
            if v['eps'] or not v['range'] or not v['peers']:
                continue
            if (dev & v['peers']) and crosses(leg, v['range']):
                cand_cids.setdefault(i, set()).add(cid)
                cand_legs[cid].add(i)
    for i, cids in cand_cids.items():
        leg = legs[i]
        if len(cids) == 1 and len(cand_legs[next(iter(cids))]) == 1:
            bound[i] = set(cids)   # 唯一组合：不问远近
            continue
        best = None
        for cid in cids:
            hi = views[cid]['range'][1]
            lo = views[cid]['range'][0]
            d = min(abs(leg['end'] - hi), abs(leg['start'] - lo))
            if d <= DIALOG_BIND_PROX_S and (best is None or d < best[0]):
                best = (d, cid)
        if best:
            bound[i] = {best[1]}

    # 3. 共享对话框的腿聚成组件（并查集），再按半呼叫形状两两合并
    parent = list(range(len(legs)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    by_cid = defaultdict(list)
    for i, cids in bound.items():
        for cid in cids:
            by_cid[cid].append(i)
    for members in by_cid.values():
        for j in members[1:]:
            ri, rj = find(members[0]), find(j)
            if ri != rj:
                parent[rj] = ri

    comp_members = defaultdict(list)
    for i in bound:
        comp_members[find(i)].append(i)
    units = [{'legs': [legs[i] for i in members],
              'cids': set().union(*(bound[i] for i in members))}
             for members in comp_members.values()]

    def unit_devips(u) -> set:
        ips = set()
        for leg in u['legs']:
            ips |= devips(leg)
        for cid in u['cids']:
            ips |= {ip for ip, _p in views[cid]['eps']}
        if server_ip:
            ips.discard(server_ip)
        return ips

    def unit_end(u) -> float:
        return max(leg['end'] for leg in u['legs'])

    changed = True
    while changed:
        changed = False
        for i in range(len(units)):
            for j in range(i + 1, len(units)):
                if (len(unit_devips(units[i]) | unit_devips(units[j])) > 2
                        or abs(unit_end(units[i]) - unit_end(units[j])) > END_ALIGN_S
                        or _legs_time_overlap(units[i]['legs'],
                                              units[j]['legs']) <= 0):
                    continue
                units[i]['cids'] |= units[j]['cids']
                units[i]['legs'] += units[j]['legs']
                del units[j]
                changed = True
                break
            if changed:
                break

    # 4. 未绑定任何对话框的腿：非服务器 IP 命中某组件且时间重叠的归入组件
    orphans = []
    for i, leg in enumerate(legs):
        if i in bound:
            continue
        dev = devips(leg)
        target, best_ov = None, 0.0
        for u in units:
            if not (dev & unit_devips(u)):
                continue
            ov = _legs_time_overlap(u['legs'], [leg])
            if ov > best_ov:
                target, best_ov = u, ov
        if target:
            target['legs'].append(leg)
        else:
            orphans.append(leg)

    result = [_make_call(u['legs']) for u in units]
    if orphans:
        result.extend(group_calls(orphans))
    result.sort(key=lambda c: (c['start'], c['end']))
    calls[:] = result
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

    - bypass：媒体不经 FS（点对点直连 / bypass media），FS 不在媒体路径，
      未参与编解码；
    - transcode：两腿协商编码不同，FS 作为 B2BUA 必然解码再编码（转码）；
    - same：两腿编码相同，FS 即使在媒体路径也没有编码格式转换发生（是否
      透传/重打包不影响该结论）；
    - unknown：数据不足——只见到一条腿的协商编码、无 SDP 且 RTP PT 反查也
      不可比（如动态 PT 无 rtpmap）。

    SDP 对比不可行时用每条腿实际使用的音频 PT 反查编码名兜底（结论标注
    推断来源）。媒体已被改道（SDP 透传）时 FS 不在媒体路径，转码问题随之
    无意义，直接给 bypass 结论。
    """
    if is_p2p:
        return {'verdict': 'bypass',
                'text': '媒体在两端之间直连（点对点 / bypass media），'
                        'FS 不在媒体路径，未参与编解码'}
    redirs = call.get('media_redirects') or []
    if redirs:
        r0 = redirs[0]
        return {'verdict': 'bypass',
                'text': f"FS 已在 {r0['time_str']} 把媒体改道为端到端直连"
                        '（SDP 透传），FS 不在媒体路径，未参与编解码'}
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


def _fs_relay_verdict(call: dict, captures: dict, server_ip: str) -> dict | None:
    """判定这通通话的音视频流有没有经过 FS 转发，给出排查方向提示。

    实测判据是各设备与 FS 之间的 RTP 上/下行（腿内每条 SSRC 流方向恒定），
    信令判据是 SDP 透传改道（media_redirects）。结论按排查优先级组织：
    1. 中转问题优先——FS 改道直连（SDP 透传）、或两端都没有向 FS 上行 RTP，
       说明媒体没走 FS 中转，先查 FS 中转配置（bypass media / 媒体地址通告），
       不要先怀疑网络；
    2. 网络问题其次——只有部分端点/媒体有上行时（发了的和没发的混着），
       才往网络方向排查。

    Returns None 表示无需此判定（点对点直连通话已有专门提示，或无服务器 IP）。
    """
    if not server_ip:
        return None
    # 全部腿都不经过服务器：点对点直连，转发判定无意义（另有提示）
    if not any(server_ip in leg['ips'] for leg in call['legs']):
        return None
    # 转发判定只能由服务器侧抓包下结论：别的抓包点看不到"是否发给了 FS"
    if not any(server_ip in (rd.get('ips') or set()) for rd in captures.values()):
        return {'available': True, 'verdict': 'insufficient',
                'headline': '没有 FS 侧抓包，无法判断媒体是否经过 FS 中转'
                            '（需在 FS 上或其镜像口抓包）',
                'advice': '', 'redirects': [], 'devices': [], 'notes': []}

    # 每台设备与 FS 之间按媒体类别的上下行实测
    stream_kinds = _stream_kinds(captures)
    stats = {}   # device_ip -> {'up': {kind: agg}, 'down': {kind: agg}}
    for leg in call['legs']:
        if server_ip not in leg['ips']:
            continue
        for ssrc, st in leg['streams'].items():
            if st['src_ip'] == server_ip:
                direction, dev = 'down', st['dst_ip']
            elif st['dst_ip'] == server_ip:
                direction, dev = 'up', st['src_ip']
            else:
                continue
            kind = _pt_kind(stream_kinds, ssrc, st['pt'])
            if not kind:
                continue
            agg = (stats.setdefault(dev, {'up': {}, 'down': {}})[direction]
                        .setdefault(kind, {'pkts': 0,
                                           'first': st['start'], 'last': st['end']}))
            agg['pkts'] += st['count']
            agg['first'] = min(agg['first'], st['start'])
            agg['last'] = max(agg['last'], st['end'])

    # 期望参与转发的设备集：信令识别出的主叫/被叫，缺信令时退回媒体腿上
    # 与 FS 通信过的非服务器 IP
    caller_ip, callee_ip = _call_party_pair(call.get('sip_flow') or [], server_ip)
    expected = [ip for ip in (caller_ip, callee_ip) if ip and ip != server_ip]
    if not expected:
        expected = sorted({ip for leg in call['legs'] if server_ip in leg['ips']
                           for ip in leg['ips']} - {server_ip})

    def _label(ip):
        if ip == caller_ip:
            return f'主叫端 {ip}'
        if ip == callee_ip:
            return f'被叫端 {ip}'
        return f'端点 {ip}'

    call_dur = max(call['duration'], 0.001)
    devices = []
    for ip in expected:
        s = stats.get(ip, {'up': {}, 'down': {}})
        devices.append({
            'ip': ip, 'label': _label(ip),
            'uplink': {k: {'pkts': s['up'].get(k, {}).get('pkts', 0),
                           'span_s': round(max(0.0, s['up'].get(k, {}).get('last', 0)
                                               - s['up'].get(k, {}).get('first', 0)), 1),
                           'last_str': _fmt_time(s['up'][k]['last']) if k in s['up'] else None}
                       for k in ('audio', 'video')},
            'downlink': {k: {'pkts': s['down'].get(k, {}).get('pkts', 0),
                             'span_s': round(max(0.0, s['down'].get(k, {}).get('last', 0)
                                                 - s['down'].get(k, {}).get('first', 0)), 1),
                             'last_str': _fmt_time(s['down'][k]['last']) if k in s['down'] else None}
                         for k in ('audio', 'video')},
        })

    redirs = call.get('media_redirects') or []
    notes = []
    up_devs = [d for d in devices if any(v['pkts'] > 0 for v in d['uplink'].values())]
    no_up_devs = [d for d in devices if not any(v['pkts'] > 0 for v in d['uplink'].values())]

    if redirs:
        r0 = redirs[0]
        headline = (f"FS 在 {r0['time_str']} 用 {r0['label']} 把媒体改道为端到端直连"
                    f"（SDP 透传，向 {_label(r0['dst']) if r0['dst'] != server_ip else r0['dst']}"
                    f" 宣告 {'、'.join(r0['targets'])} 的媒体地址），"
                    '此后音视频流不再经过 FS 转发。')
        # 佐证：各端上行是否随改道一并停止（改道时刻 ±5 秒内停 = 服从了新
        # SDP，是干净的信令性停止，不是网络丢包的形态）
        stopped, kept = [], []
        for d in up_devs:
            lasts = [v['last_str'] and stats[d['ip']]['up'][k]['last']
                     for k, v in d['uplink'].items() if v['pkts'] > 0]
            if lasts and all(abs(t - r0['time']) <= 5.0 for t in lasts):
                stopped.append(d['label'])
            elif lasts:
                kept.append(d['label'])
        if stopped:
            notes.append(f"{'、'.join(stopped)}的 RTP 上行在改道时刻即停止——"
                         '各端服从了新 SDP，属干净的信令性停止，不是网络丢包')
        if kept:
            notes.append(f"{'、'.join(kept)}在改道后仍有上行（FS 侧仍在收部分媒体）")
        advice = ('排查优先级：这是中转问题，不是网络问题。先确认 FS 的媒体旁路'
                  '配置（bypass_media / bypass_media_after_bridge 等）是否符合预期；'
                  '本抓包点看不到端到端直连的媒体，若要确认两端是否真正收到对方的'
                  '音视频，需在两端本地抓包验证。')
    elif not up_devs:
        names = '、'.join(d['label'] for d in devices) or '两端'
        headline = (f'{names}都没有向 FS 发送任何 RTP——'
                    '音视频流没有经过 FS 中转。')
        advice = ('排查优先级：两端都不往 FS 发媒体 → 优先排查中转问题：'
                  'FS 是否配置了 bypass media、信令里宣告的媒体地址是否指向 FS、'
                  '两端是否拿到了彼此地址在直连；确认后才是网络问题。')
    elif no_up_devs:
        sent = '、'.join(d['label'] for d in up_devs)
        missing = '、'.join(d['label'] for d in no_up_devs)
        headline = (f'只有 {sent} 向 FS 发送了媒体，{missing} 没有任何上行 RTP。')
        advice = ('排查优先级：一部分发了、一部分没发 → 这种情况才考虑网络问题：'
                  '先在未发送端本地抓包，确认它确实在发（排除终端自身不发），'
                  '再逐段检查链路、防火墙/NAT。')
    else:
        headline = '各端都有上行、FS 也有下行——媒体确实经过 FS 中转。'
        advice = ''
    # 下行来源核对：FS 的下行应能被对端的上行解释（转发包数 1:1）。
    # 对端没发过、或包数远小于下行，说明该下行不是转发——FS 本地媒体源
    # （彩铃/视频公告/MOH 等），这直接影响"FS 是否在转发"的结论。
    for d in devices:
        peer = next((x for x in devices if x['ip'] != d['ip']), None)
        if not peer:
            continue
        for kind, kname in (('audio', '音频'), ('video', '视频')):
            up = peer['uplink'][kind]
            down = d['downlink'][kind]
            if not down['pkts']:
                if up['pkts']:
                    notes.append(f"FS 从未向 {d['label']} 下发{kname}"
                                 f"（0 包，而对端 {peer['label']} 上行过"
                                 f" {up['pkts']} 包）——该方向未发生转发")
                continue
            if not up['pkts']:
                notes.append(f"FS 向 {d['label']} 下发了 {down['pkts']} 包{kname}，"
                             f"但 {peer['label']} 从未上行过{kname}——该下行并非"
                             '转发，应是 FS 本地媒体源（如彩铃/视频公告/MOH）')
            elif down['span_s'] > 30 and down['pkts'] > up['pkts'] * 4:
                notes.append(f"FS 向 {d['label']} 下发{kname} {down['pkts']} 包"
                             f"（覆盖约 {down['span_s']} 秒），而 {peer['label']}"
                             f" 上行仅 {up['pkts']} 包（约 {up['span_s']} 秒）——"
                             '下行主体并非来自对端的转发')

    return {'available': True, 'verdict': (
                'redirected' if redirs else
                'no_relay' if not up_devs else
                'partial_uplink' if no_up_devs else 'relayed'),
            'headline': headline, 'advice': advice,
            'redirects': [{'time_str': r['time_str'], 'label': r['label'],
                           'dst': _label(r['dst']) if r['dst'] != server_ip else r['dst'],
                           'targets': '、'.join(r['targets'])}
                          for r in redirs],
            'devices': devices,
            'notes': notes}


def _stream_kinds(captures: dict) -> dict:
    """收集各抓包解析出的流种类（{ssrc: 'audio'|'video'}）。

    动态 PT（96-127）按媒体种类独立分配（audio 96=OPUS 与 video 96=H264 可
    同号并存），媒体种类以解析阶段按 SDP 端口绑定/时钟率判定的 kind 为准。
    """
    kinds = {}
    for rd in captures.values():
        for ssrc, info in (rd.get('streams') or {}).items():
            kind = info.get('kind')
            if kind and ssrc not in kinds:
                kinds[ssrc] = kind
    return kinds


def _pt_kind(kinds: dict, ssrc, pt: int) -> str | None:
    """一条流的媒体种类：解析标注优先，静态 PT 表兜底。"""
    return kinds.get(ssrc) or ('audio' if pt in AUDIO_PT
                               else 'video' if 96 <= pt <= 127 else None)


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
    # 并发/交错通话会被时间重叠聚类并成一通：把全部媒体腿与全部信令对话框
    # 全局重绑（SDP 宣告端点 / 无 SDP 时信令对端 IP），按半呼叫形状拆回各自
    # 的通话
    refine_calls(raw_calls, server_ip)
    # 拆分出的新通话也要拿到自己的信令流程/Call-ID，重跑一次关联
    build_sip_flows(raw_calls, captures, server_ip)

    results = []
    stream_kinds = _stream_kinds(captures)
    for idx, call in enumerate(raw_calls):
        completeness = assess_call_completeness(call, file_info, server_ip)

        stream_pts = {}
        for leg in call['legs']:
            for ssrc, st in leg['streams'].items():
                stream_pts.setdefault(ssrc, st['pt'])
        kinds = {ssrc: _pt_kind(stream_kinds, ssrc, pt)
                 for ssrc, pt in stream_pts.items()}
        media_types = []
        if any(k == 'audio' for k in kinds.values()):
            media_types.append('audio')
        if any(k == 'video' for k in kinds.values()):
            media_types.append('video')

        # 实际使用的编码：由 RTP 流真实出现的 PT 反查（静态 PT 名优先，动态
        # PT 96~127 靠 SDP rtpmap 解析；SDP 列出的是候选，不代表在用）。
        # 动态 PT 音频（如 OPUS@96）按解析出的种类归侧，不能只看 PT 号。
        sdp_map = (call.get('sdp_codecs') or {}).get('map') or {}

        def _pt_codec(kind, pt):
            return PT_NAMES.get(pt) or (sdp_map.get(kind) or {}).get(str(pt))

        codecs = {
            'audio': sorted({n for ssrc, pt in stream_pts.items()
                             if kinds[ssrc] == 'audio'
                             for n in [_pt_codec('audio', pt)] if n}),
            'video': sorted({n for ssrc, pt in stream_pts.items()
                             if kinds[ssrc] == 'video'
                             for n in [_pt_codec('video', pt)] if n}),
        }
        if not codecs['video']:
            codecs['video'] = sorted({f'PT {pt}（SDP 未抓到）'
                                      for ssrc, pt in stream_pts.items()
                                      if kinds[ssrc] == 'video'})

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
            # FS 媒体转发判定：这通话的音视频流到底有没有经过 FS 转发
            # （点对点直连时为 None，已有专门提示）
            'fs_relay': (None if p2p
                         else _fs_relay_verdict(call, captures, server_ip)),
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
