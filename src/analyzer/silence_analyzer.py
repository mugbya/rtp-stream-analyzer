"""
静音/能量分析与无声诊断

"没听到声音"在 RTP 层面有五种成因，逐一对应检查（按媒体路径从源到汇）：

1. 发言端根本没发流（未接通/未采集/未开麦）——抓包里无该方向流；
2. 流发了但没到下一跳（NAT/防火墙/FS 未桥接）——发言端抓包有、FS 抓包无；
3. 包在路上丢光——逐抓包点丢包率（packet_loss 模块负责，这里引用结论）；
4. 包在但内容是静音——seq/ts 完全连续、零丢包，载荷却全是数字零：
   静音键/采集故障。RTP 层面"完全正常"就是没声，这是最容易被漏掉的一层；
5. FS 收到了但没转发/转出静音——FS 入站流正常、FS→听者出站流缺失或静音。

能量统计按媒体时间加权而不是按包数：开静音抑制（DTX/VAD）的终端在静音
期间不发包，按包数统计会把"只有说话时才发包"误判成一直有人声；按时间戳
推进的媒体时间统计（未发包的缺口=静音）才能还原真实的人声占比。

"有人声"还要排除稳态单频音（回铃音/忙音/提示音）：一声 450Hz 回铃音
能量再大也不是人声，不能把"只响了一声嘟之后全程静音"的流撑过门限
判成"有人声"——这正是单通抓包里最常见的形态。

方向诊断按抓包角色锚定（terminal=主叫端、seat=坐席端、fs=FS），不依赖
SIP 也能工作；有信令时用主叫/被叫 IP 从 FS 抓包补选流。每条腿在"源端
抓包 → 下一跳抓包"两个点上检查流的存在性，并用能量画像判定该方向
"声音死在哪一段"。
"""
import math

import audioop
import numpy as np

from analyzer.quality_analyzer import FRAME, _voice_mask, tone_intervals
from analyzer.stream_classifier import get_pt_name, pick_call_stream
from analyzer.ts_continuity import signed32

# 判定"有人声"的单包 RMS 门限（16bit 线性 PCM，≈ -36 dBFS）。
# G.711 静音帧解码后 RMS≈0，室内噪声通常 <300，正常说话 >1000
ACTIVE_RMS = 500
SAMPLE_RATE = 8000         # G.711 采样率（与 quality_analyzer 一致）
# 有声媒体时间占比低于此值视为"基本没人说话"（全程静音=0）
SILENT_RATIO = 0.02
# 单个时间戳缺口最多计入的静音媒体时间（秒）：时间戳重置不当作超长静音
MAX_GAP_S = 10.0
# 说话/静音区间明细最多保留条数
MAX_SPANS = 40

_DECODE = {0: 'ulaw', 8: 'alaw'}


def analyze_silence(packets: dict, ssrc: int) -> dict:
    """分析指定 SSRC 音频流的能量与静音占比（需带载荷的抓包数据）。

    Returns:
        {
            'packet_count': int,
            'codec': str,                 # 解码用编码名
            'decodable': bool,            # 仅 PCMU/PCMA 可解
            'active_ratio': float,        # 有声媒体时间占比（含 DTX 缺口，
                                          # 已剔除提示音/单频音段）
            'speech_ms': float,           # 有声媒体时间
            'media_ms': float,            # 有声+静音媒体时间（不含重置缺口）
            'tone_ms': float,             # 稳态单频音（提示音等）媒体时间
            'speech_activity': bool|None, # 活跃段包络起伏像人声？
                                          # False=只有平稳背景电平（无话音）
            'steady_energy_ms': float,    # 仅 speech_activity=False 时有：
            'steady_dbfs': float,         #   背景电平时长与电平值
            'zero_packets': int,          # 解码后全零的包（数字静音）
            'active_packets': int,
            'mean_active_dbfs': float|None,  # 有人声的包平均电平
            'peak_dbfs': float|None,
            'first_active_s': float|None,    # 流开始到第一声（None=全程无）
            'spans': [[start, end, active], ...],  # 区间（捕获时间，合并）
            'span_count': int,
            'verdict': 'normal'|'sparse'|'silent'|'unknown',
        }
    """
    result = {
        'packet_count': 0, 'codec': 'unknown', 'decodable': False,
        'active_ratio': 0.0, 'speech_ms': 0.0, 'media_ms': 0.0,
        'tone_ms': 0.0, 'zero_packets': 0, 'active_packets': 0,
        'mean_active_dbfs': None, 'peak_dbfs': None, 'first_active_s': None,
        'spans': [], 'span_count': 0, 'verdict': 'unknown',
    }

    stream = {}
    for (k_ssrc, seq), v in packets.items():
        if k_ssrc == ssrc and len(v) >= 8:
            stream[seq] = v
    if not stream:
        return result

    pts = [v[2] for v in stream.values()]
    pt = max(set(pts), key=pts.count)
    result['packet_count'] = len(stream)
    result['codec'] = get_pt_name(pt)
    result['decodable'] = pt in _DECODE
    if not result['decodable']:
        return result
    decode = audioop.ulaw2lin if _DECODE[pt] == 'ulaw' else audioop.alaw2lin

    # 每包时长以时间戳增量中位数为准（包化不一定是 20ms/160 样本）
    seqs = sorted(stream)
    ts_list = [stream[s][1] for s in seqs]
    deltas = [signed32(b - a) for a, b in zip(ts_list, ts_list[1:])]
    positive = sorted(d for d in deltas if d > 0)
    spp = positive[len(positive) // 2] if positive else 0
    if not (0 < spp <= 8000 // 2):
        spp = 160

    # —— 第一遍：逐包解码取能量，并按媒体时间拼接 PCM（DTX 缺口补零，
    # 与真实播放时间对齐），供稳态单频音（提示音）剔除做帧级检测 ——
    pkt_t, pkt_ts, pkt_rms = [], [], []
    media_pos = []                  # 每包在媒体时间轴上的起始样本位置
    pcm = []
    pos = 0
    prev_ts = None
    peak = 0
    zero_packets = 0
    for seq in seqs:
        t, ts, p = stream[seq][0], stream[seq][1], stream[seq][2]
        if prev_ts is not None:
            gap = signed32(ts - prev_ts) - spp
            if 0 < gap <= MAX_GAP_S * 8000:
                pos += gap
                pcm.append(np.zeros(gap, dtype=np.float64))
        prev_ts = ts
        media_pos.append(pos)
        if p != pt:
            # 非主 PT（如 CN 舒适噪声 PT 13）：按一包静音计
            pkt_rms.append(0)
            pcm.append(np.zeros(spp, dtype=np.float64))
        else:
            lin = decode(stream[seq][7], 2)
            rms = audioop.rms(lin, 2)
            peak = max(peak, rms)
            if rms == 0:
                zero_packets += 1
            pkt_rms.append(rms)
            pcm.append(np.frombuffer(lin, dtype=np.int16).astype(np.float64))
        pkt_t.append(t)
        pkt_ts.append(ts)
        pos += spp

    # —— 提示音剔除：稳态单频段（回铃音/忙音/啸叫/嗡声）不是人声 ——
    # 一声 450Hz 回铃音能量再大也不能把"之后全程静音"的流判成有人声
    tone_iv = []
    try:
        x_all = np.concatenate(pcm) if pcm else np.zeros(0)
        tone_iv = tone_intervals(x_all)
    except Exception:
        tone_iv = []

    def _tone_overlap(i: int) -> int:
        """第 i 包与单频音段重叠的样本数（段边缘留一个 FFT 帧余量）。"""
        s, e = media_pos[i], media_pos[i] + spp
        ov = 0
        for a, b in tone_iv:                  # 已按起始时间排序
            # 事件时间是帧中心时间（有 ±半帧量化误差），加上帧窗口本身
            # 覆盖信号起振的模糊，余量取一个整帧
            lo = int(a * SAMPLE_RATE) - FRAME
            hi = int(b * SAMPLE_RATE) + FRAME
            if hi <= s:
                continue
            if lo >= e:
                break
            ov += min(hi, e) - max(lo, s)
        return ov

    is_active = [rms >= ACTIVE_RMS and _tone_overlap(i) < spp / 4
                 for i, rms in enumerate(pkt_rms)]

    # —— 语音活动判定：有能量 ≠ 有人声 ——
    # 设备故障时会把持续背景电平（供电干扰/环境噪声）整通发过来，包
    # 能量同样过门限，"有声占比"会虚高。_voice_mask 在活跃包里分出
    # 人声：整体起伏像人声就全算；整体平则只保留明显高于背景电平的
    # 突发段（"背景音里的人声时刻"），其余记为背景电平时间
    act_pos = [i for i, act in enumerate(is_active) if act]
    vmask = _voice_mask([pkt_rms[i] for i in act_pos])
    steady_ms = steady_dbfs = None
    if vmask is None:
        speech_activity = None
    elif not vmask.any():
        # 活跃能量全是平稳背景电平：不计入人声时间
        speech_activity = False
        steady_ms = round(len(act_pos) * spp / 8000 * 1000, 1)
        steady_dbfs = round(_dbfs(sum(pkt_rms[i] for i in act_pos)
                                  / max(len(act_pos), 1)), 1)
        is_active = [False] * len(pkt_rms)
    else:
        speech_activity = True
        keep = {act_pos[j] for j in range(len(vmask)) if vmask[j]}
        idle = [i for i in act_pos if i not in keep]
        if idle:
            steady_ms = round(len(idle) * spp / 8000 * 1000, 1)
            steady_dbfs = round(_dbfs(sum(pkt_rms[i] for i in idle)
                                      / len(idle)), 1)
        is_active = [i in keep for i in range(len(pkt_rms))]

    # —— 第二遍：按剔除后的判定累计媒体时间与区间 ——
    speech_samples = silent_samples = 0
    spans = []
    first_active = None
    active_rms_vals = []
    for i in range(len(pkt_ts)):
        if i:
            gap = signed32(pkt_ts[i] - pkt_ts[i - 1]) - spp
            if 0 < gap <= MAX_GAP_S * 8000:
                silent_samples += gap

        if is_active[i]:
            speech_samples += spp
            active_rms_vals.append(pkt_rms[i])
            if first_active is None:
                first_active = pkt_t[i]
        else:
            silent_samples += spp

        if spans and spans[-1][2] == is_active[i]:
            spans[-1][1] = pkt_t[i]
        else:
            spans.append([pkt_t[i], pkt_t[i], is_active[i]])

    result['zero_packets'] = zero_packets
    result['active_packets'] = sum(is_active)
    result['tone_ms'] = round(sum(b - a for a, b in tone_iv) * 1000, 1)
    result['speech_activity'] = speech_activity
    if steady_ms is not None:
        result['steady_energy_ms'] = steady_ms
        result['steady_dbfs'] = steady_dbfs
    total = speech_samples + silent_samples
    result['speech_ms'] = round(speech_samples / 8000 * 1000, 1)
    result['media_ms'] = round(total / 8000 * 1000, 1)
    result['active_ratio'] = round(speech_samples / total, 4) if total else 0.0
    if active_rms_vals:
        result['mean_active_dbfs'] = round(
            _dbfs(sum(active_rms_vals) / len(active_rms_vals)), 1)
    if peak:
        result['peak_dbfs'] = round(_dbfs(peak), 1)
    if first_active is not None:
        result['first_active_s'] = round(first_active - stream[seqs[0]][0], 1)

    merged = []
    for s in spans:
        if merged and merged[-1][2] == s[2] and s[0] - merged[-1][1] < 0.5:
            merged[-1][1] = s[1]
        else:
            merged.append(s)
    result['span_count'] = len(merged)
    result['spans'] = [[round(a, 2), round(b, 2), c]
                       for a, b, c in merged[:MAX_SPANS]]

    ratio = result['active_ratio']
    result['verdict'] = ('normal' if ratio >= SILENT_RATIO
                         else 'sparse' if ratio > 0 else 'silent')
    return result


def _dbfs(rms: float) -> float:
    return 20 * math.log10(max(rms, 1) / 32768)


# 方向判定优先级：数值越大问题越严重（用于单腿状态兜底排序）
_VERDICT_ORDER = {'ok': 0, 'unknown': 1, 'silent_path': 2, 'silent_source': 3,
                  'blocked': 4, 'no_source': 5}

_VERDICT_TEXT = {
    'ok': '媒体链路正常：发声端发出的流各段都存在且有人声',
    'unknown': '数据不足，无法判定该方向（缺对应抓包点或编码不可解）',
    'blocked': '媒体流在路径中断裂（单通最常见成因：NAT/防火墙/FS 未桥接转发）',
    'silent_source': '发声端发出的就是静音：包在发、时间戳正常，但内容无人声'
                     '（静音键/采集故障）',
    'silent_path': '听者收到的是静音：链路中某一段把人声换成了静音'
                   '（常见：发声端静音键/采集故障，或 FS 转码/混音问题），'
                   '具体见各腿备注',
    'no_source': '该方向没有发现任何音频流（未发声/未接通）',
}


def diagnose_audio(captures: dict, call: dict, server_ip: str,
                   profiles: dict, rtcp_by_role: dict = None,
                   parties: dict = None) -> dict:
    """按通话的两个方向做无声诊断。

    Args:
        captures: {role: rtp_data}，rtp_data 需带 _role 字段（=role）。
        call: detect_calls 输出的单通通话（含 ssrcs / is_p2p）。
        server_ip: 服务器 IP。
        profiles: {(role, ssrc): analyze_silence 结果}。
        rtcp_by_role: {role: summarize_rtcp 结果}，可选。听者的 RTCP RR 是
            "听者视角收到了什么"的佐证。
        parties: extract_call_parties 的输出 {'caller_ip', 'answerer_ip',
            ...}，SIP 识别的双方 IP，可选；缺失时无法从 FS 抓包兜底选流。

    Returns:
        {'available': bool, 'p2p': bool, 'directions': [...], 'summary': str}
    """
    call_ssrcs = set(call.get('ssrcs') or [])
    fs_cap = captures.get('fs') or captures.get('FS')
    p2p = bool(call.get('is_p2p'))
    parties = parties or {}

    # 两个方向：主叫(terminal)→坐席(seat)、坐席→主叫
    specs = []
    for speaker_role, listener_role, spk_key, lst_key in (
            ('terminal', 'seat', 'caller_ip', 'answerer_ip'),
            ('seat', 'terminal', 'answerer_ip', 'caller_ip')):
        specs.append({
            'speaker_role': speaker_role,
            'listener_role': listener_role,
            'speaker_ip': parties.get(spk_key),
            'listener_ip': parties.get(lst_key),
            # NAT 别名：该端 SDP 宣告的另一个媒体地址（如私网 IP）。FS 侧流
            # 的收发地址可能落在这个别名上而非信令 IP，选流时长一并尝试
            'speaker_alt_ips': parties.get(spk_key.replace('_ip', '_alt_ips')) or [],
            'listener_alt_ips': parties.get(lst_key.replace('_ip', '_alt_ips')) or [],
            'speaker_name': '主叫' if speaker_role == 'terminal' else '被叫',
            'listener_name': '被叫' if listener_role == 'seat' else '主叫',
        })

    directions = []
    any_data = False
    for spec in specs:
        spk_cap = captures.get(spec['speaker_role'])
        lst_cap = captures.get(spec['listener_role'])
        if not spk_cap and not lst_cap and not fs_cap:
            continue
        d = _diagnose_direction(spk_cap, lst_cap, fs_cap, call_ssrcs,
                                server_ip, p2p, profiles, rtcp_by_role or {},
                                spec)
        if d is not None:
            directions.append(d)
            if d['verdict'] != 'unknown':
                any_data = True

    if not directions or not any_data:
        return {'available': False, 'p2p': p2p, 'directions': directions,
                'summary': '抓包数据不足，无法做无声方向诊断'
                           '（需至少一个端点抓包；FS 抓包可补全链路）'}

    bad = [d for d in directions if d['verdict'] != 'ok']
    if not bad:
        summary = '两个方向的音频链路均正常（各段流都存在且有人声）'
    else:
        summary = '；'.join(f"{d['label']}：{d['verdict_text']}" for d in bad)
    return {'available': True, 'p2p': p2p, 'directions': directions,
            'summary': summary}


def _diagnose_direction(spk_cap, lst_cap, fs_cap, call_ssrcs, server_ip,
                        p2p, profiles, rtcp_by_role, spec):
    """诊断一个方向（speaker→listener）。完全无数据时返回 None。"""
    speaker_role = spec['speaker_role']
    listener_role = spec['listener_role']
    peer_of_speaker = spec['listener_ip'] if p2p else server_ip
    peer_of_listener = spec['speaker_ip'] if p2p else server_ip

    # —— 选流 ——
    # 上行流：优先从发言端抓包选（最靠近源头），FS 抓包按发言端 IP 兜底
    uplink, uplink_at = None, None
    if spk_cap and peer_of_speaker:
        uplink = pick_call_stream(spk_cap, call_ssrcs, dst_is=peer_of_speaker)
        uplink_at = speaker_role
    if uplink is None and fs_cap and spec['speaker_ip']:
        uplink = pick_call_stream(fs_cap, call_ssrcs,
                                  src_is=[spec['speaker_ip'],
                                          *spec.get('speaker_alt_ips', [])])
        uplink_at = 'fs'
    # 下行流：优先从听者抓包选（最靠近汇），FS 抓包按听者 IP 兜底
    downlink, downlink_at = None, None
    if lst_cap and peer_of_listener:
        downlink = pick_call_stream(lst_cap, call_ssrcs, src_is=peer_of_listener)
        downlink_at = listener_role
    if downlink is None and fs_cap and spec['listener_ip']:
        downlink = pick_call_stream(fs_cap, call_ssrcs,
                                    dst_is=[spec['listener_ip'],
                                            *spec.get('listener_alt_ips', [])])
        downlink_at = 'fs'

    if uplink is None and downlink is None:
        return None    # 该方向一条流都没见到（含抓包缺失），无可诊断

    if p2p:
        legs = [_judge_leg(
            f"直连（{spec['speaker_name']} → {spec['listener_name']}）",
            uplink, uplink_at, downlink, downlink_at,
            spk_cap, lst_cap, profiles, rtcp_by_role,
            speaker_role, listener_role)]
    else:
        legs = [
            _judge_leg(f"{spec['speaker_name']}上行（{spec['speaker_name']} → FS）",
                       uplink, uplink_at, None, None,
                       spk_cap, fs_cap, profiles, rtcp_by_role,
                       speaker_role, listener_role),
            _judge_leg(f"{spec['listener_name']}下行（FS → {spec['listener_name']}）",
                       None, None, downlink, downlink_at,
                       fs_cap, lst_cap, profiles, rtcp_by_role,
                       speaker_role, listener_role),
        ]

    # 方向级判定按"路径顺序"归并，不是简单取最严重：
    # 上行腿就断了 → 断裂；源头没发声 → 无源；下行缺流但上行在发 →
    # 是 FS 没转发出去（也归为断裂）；再按静音归属
    if p2p:
        verdict = legs[0]['status']
    else:
        up, down = legs[0]['status'], legs[-1]['status']
        statuses = [up, down]
        if 'blocked' in statuses:
            verdict = 'blocked'
        elif up == 'no_source':
            verdict = 'no_source'
        elif down == 'no_source':
            # 上行在发、FS 侧没有对应的下行流：FS 未桥接转发
            verdict = 'blocked'
        elif 'silent_source' in statuses:
            verdict = 'silent_source'
        elif 'silent_path' in statuses:
            verdict = 'silent_path'
        else:
            verdict = max(statuses, key=lambda v: _VERDICT_ORDER.get(v, 1))

    label = f"{spec['speaker_name']} → {spec['listener_name']}"
    text = _VERDICT_TEXT[verdict]
    if verdict == 'blocked':
        # 常规断裂列出 blocked 腿；FS 未转发（下行 no_source）时列出该腿
        dead = [l['leg'] for l in legs if l['status'] == 'blocked'] \
            or [l['leg'] for l in legs if l['status'] == 'no_source']
        text += f'——断裂点：{"、".join(dead)}'
    return {'label': label, 'speaker': spec['speaker_name'],
            'listener': spec['listener_name'],
            'verdict': verdict, 'verdict_text': text, 'legs': legs}


_ROLE_DISPLAY = {'terminal': '主叫', 'seat': '被叫', 'fs': 'FS'}


def _judge_leg(leg_name, src_ssrc, src_at, dst_ssrc, dst_at,
               src_cap, dst_cap, profiles, rtcp_by_role,
               speaker_role, listener_role):
    """一条腿的判定：流在源端有没有发、到没到下一跳、各点能量如何。

    uplink / p2p 腿：src_ssrc=源端发现的流；downlink 腿：dst_ssrc=听者端
    发现的流。两侧 SSRC 本是同一条媒体（经 FS 时换成下行新 SSRC），这里
    按"源端发出的"与"下一跳到达的"分别取能量画像。
    """
    ssrc = src_ssrc if src_ssrc is not None else dst_ssrc
    presence = {'sent_at_source': None, 'arrived_at_next': None}
    notes = []
    if ssrc is None:
        # 该腿没有可认定的流：源端抓包在场 → 真没发；源端抓包缺失 → 无法确认
        status = 'no_source' if src_cap is not None else 'unknown'
        note = ('该方向未发现音频流（未发声/未接通）' if status == 'no_source'
                else '未发现该方向的音频流（源端抓包缺失，无法确认是否发声）')
        return {'leg': leg_name, 'ssrc': None, 'kind': 'leg',
                'status': status, 'presence': presence,
                'profiles': [], 'rr': None, 'note': note}

    ssrc_hex = f'0x{ssrc:08x}'
    presence['sent_at_source'] = (ssrc in (src_cap.get('streams') or {})) \
        if src_cap is not None else None
    presence['arrived_at_next'] = (ssrc in (dst_cap.get('streams') or {})) \
        if dst_cap is not None else None
    sent, arrived = presence['sent_at_source'], presence['arrived_at_next']

    # 能量画像：源端（发了什么）与下一跳（收到了什么）各取一份
    side_profiles = []
    for side, cap in (('source', src_cap), ('next', dst_cap)):
        if cap is None:
            continue
        p = profiles.get((cap.get('_role'), ssrc))
        if p and p.get('packet_count'):
            side_profiles.append({'side': side, 'role': cap.get('_role'),
                                  'profile': p})

    status = 'unknown'
    if sent is True and arrived is False:
        status = 'blocked'
        notes.append('源端在发、下一跳抓包未见到达（网络/NAT 断裂，'
                     '或下一跳抓包未覆盖该时段）')
    elif sent is False and arrived is True:
        notes.append('下一跳在收、源端抓包未见发出（源端抓包时段缺口，'
                     '发送本身正常）')

    src_p = next((e for e in side_profiles if e['side'] == 'source'), None)
    next_p = next((e for e in side_profiles if e['side'] == 'next'), None)
    src_v = src_p['profile']['verdict'] if src_p else None
    next_v = next_p['profile']['verdict'] if next_p else None

    def _desc(entry):
        p = entry['profile']
        role = _ROLE_DISPLAY.get(entry['role'], entry['role'])
        tone = (f"，其中 {p['tone_ms'] / 1000:.1f}s 为提示音/单频音已剔除"
                if p.get('tone_ms') else '')
        steady = (f"；另有持续背景电平（约 {p['steady_dbfs']} dBFS，无说话"
                  f"起伏，疑似供电干扰/环境噪声）"
                  if p.get('steady_energy_ms') else '')
        if p['verdict'] == 'silent':
            zero = f"，{p['zero_packets']} 包为数字零" if p['zero_packets'] \
                else ''
            return (f"{role}侧实测全程无人声（有声占比 {p['active_ratio']:.1%}"
                    f"{zero}{tone}{steady}）")
        if p['verdict'] == 'sparse':
            return (f"{role}侧仅 {p['active_ratio']:.1%} 时间有人声"
                    f"（{p['speech_ms'] / 1000:.1f}s/{p['media_ms'] / 1000:.0f}s"
                    f"{tone}{steady}）")
        if p['verdict'] == 'unknown':
            return f"{role}侧编码不可解（{p['codec']}），无法判定能量"
        return (f"{role}侧实测有人声（占比 {p['active_ratio']:.1%}，"
                f"均值 {p['mean_active_dbfs']} dBFS{tone}{steady}）")

    for entry in (src_p, next_p):
        # 某侧抓包缺该流/画像为空时 entry 为 None，只描述存在的一侧
        if entry is not None:
            notes.append(_desc(entry))

    # 静音归属：src_at 是端点角色时可直接断言"发声端发的是静音"；源端是
    # FS 中转视角（src_at 为 None/'fs'）时无法确认发声端，归为途中并备注
    if src_v == 'silent' and src_at in (speaker_role, listener_role):
        status = 'silent_source'
        notes.append('静音源头在发声端：发出即静音（静音键/采集故障）')
    elif 'silent' in (src_v, next_v):
        if status == 'unknown':
            status = 'silent_path'
        if src_v == 'normal':
            notes.append('发声端有声、下一跳收到静音：静音产生于这段链路')
        else:
            notes.append('本段链路为静音（未直接观测到发声端能量，静音可能'
                         '来自发声端本身或其上游）')
    elif 'normal' in (src_v, next_v) or 'sparse' in (src_v, next_v):
        if status == 'unknown':
            status = 'ok'
    # 全部 unknown 时保持 unknown

    # 接收端 RTCP RR 佐证（听者视角的丢包）
    rr = None
    dst_role = dst_cap.get('_role') if dst_cap else None
    if dst_role and dst_role in rtcp_by_role \
            and ssrc in rtcp_by_role[dst_role].get('rr', {}):
        rr = rtcp_by_role[dst_role]['rr'][ssrc]
        if (rr.get('fraction_lost_pct') or 0) > 2:
            notes.append(f"接收端 RTCP RR 自报丢包 {rr['fraction_lost_pct']}%")

    return {'leg': leg_name, 'ssrc': ssrc_hex, 'kind': 'leg',
            'status': status, 'presence': presence,
            'profiles': [e['profile'] for e in side_profiles],
            'rr': rr, 'note': '；'.join(notes)}
