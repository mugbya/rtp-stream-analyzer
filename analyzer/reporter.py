"""
报告生成器
汇总所有分析结果，生成结构化报告。
"""
import json
from datetime import datetime


def generate_report(analysis_results: dict) -> dict:
    """生成完整的分析报告。
    
    Args:
        analysis_results: 包含所有分析结果的字典
        
    Returns:
        结构化报告字典
    """
    report = {
        'metadata': {
            'generated_at': datetime.now().isoformat(),
            'direction': analysis_results.get('direction', 'unknown'),
            'media_type': analysis_results.get('media_type', 'unknown'),
            'num_captures': analysis_results.get('num_captures', 0),
            'capture_roles': analysis_results.get('capture_roles', {}),
        },
        'topology': _build_topology(analysis_results),
        'streams': _build_stream_summary(analysis_results),
        'delay': _build_delay_summary(analysis_results),
        'jitter': _build_jitter_summary(analysis_results),
        'packet_loss': _build_loss_summary(analysis_results),
        'timestamp_continuity': _build_ts_summary(analysis_results),
        'clock_offset': _build_clock_summary(analysis_results),
        'audio_health': analysis_results.get('audio_health'),
        'delay_chains': analysis_results.get('delay_chains'),
        'rtcp': analysis_results.get('rtcp'),
        'media_quality': {
            'audio': analysis_results.get('audio_quality') or {},
            'video': analysis_results.get('video_quality') or {},
        },
        'conclusion': _build_conclusion(analysis_results),
    }
    return report


def _build_topology(results: dict) -> dict:
    """构建网络拓扑摘要。"""
    ips_info = results.get('ips_info', {})
    topology = {
        'endpoints': [],
        'server': None,
        'connections': [],
    }
    
    for role, info in ips_info.items():
        if 'ips' in info:
            for ip in info['ips']:
                if ip not in ('0.0.0.0', '255.255.255.255') and not ip.startswith('224.'):
                    topology['endpoints'].append({
                        'role': role,
                        'ip': ip,
                        'stream_count': info.get('stream_count', 0),
                    })
    
    server_ip = results.get('detected_server_ip')
    if server_ip:
        topology['server'] = server_ip
    
    return topology


def _build_stream_summary(results: dict) -> dict:
    """构建流摘要。"""
    streams = results.get('streams', {})
    classified = results.get('classified_streams', {})
    
    summary = {
        'total_audio': len(classified.get('audio', {})),
        'total_video': len(classified.get('video', {})),
        'total_unknown': len(classified.get('unknown', {})),
        'audio_streams': [],
        'video_streams': [],
    }
    
    for ssrc, info in classified.get('audio', {}).items():
        summary['audio_streams'].append({
            'ssrc': f'0x{ssrc:08x}',
            'pt': info.get('pt', []),
            'packet_count': info.get('count', 0),
            'ips': info.get('ips', []),
        })
    
    for ssrc, info in classified.get('video', {}).items():
        summary['video_streams'].append({
            'ssrc': f'0x{ssrc:08x}',
            'pt': info.get('pt', []),
            'packet_count': info.get('count', 0),
            'ips': info.get('ips', []),
        })
    
    return summary


def _build_delay_summary(results: dict) -> dict:
    """构建延迟摘要。"""
    fs_delay = results.get('fs_delay', {})
    cross_delays = results.get('cross_delays', [])
    e2e = results.get('end_to_end', {})
    
    return {
        'fs_internal': {
            'mean': fs_delay.get('mean', 0),
            'p50': fs_delay.get('p50', 0),
            'p95': fs_delay.get('p95', 0),
            'p99': fs_delay.get('p99', 0),
            'max': fs_delay.get('max', 0),
            'std': fs_delay.get('std', 0),
            'count': fs_delay.get('count', 0),
            'outliers_50ms': fs_delay.get('outliers_50ms', 0),
            'outliers_100ms': fs_delay.get('outliers_100ms', 0),
            'available': fs_delay.get('count', 0) > 0,
        },
        'cross_capture': [
            {
                'label': cd.get('label', ''),
                'mean': cd.get('mean', 0),
                'p95': cd.get('p95', 0),
                'clock_offset_ms': cd.get('clock_offset_ms', 0),
            }
            for cd in (cross_delays or [])
        ],
        'end_to_end': e2e,
    }


def _build_jitter_summary(results: dict) -> dict:
    """构建抖动摘要。"""
    jitter = results.get('jitter', {})
    summary = {}
    
    for label, data in (jitter or {}).items():
        summary[label] = {
            'mean': data.get('mean', 0),
            'median': data.get('median', 0),
            'std': data.get('std', 0),
            'p95': data.get('p95', 0),
            'abnormal_count': data.get('abnormal_count', 0),
            'expected_interval': data.get('expected_interval', 0),
        }
    
    return summary


def _build_loss_summary(results: dict) -> dict:
    """构建丢包摘要。"""
    packet_loss = results.get('packet_loss', {})
    summary = {}

    for ssrc, data in (packet_loss or {}).items():
        summary[ssrc] = {
            'label': data.get('label', ''),
            'total_packets': data.get('total_packets', 0),
            'total_lost': data.get('total_lost', 0),
            'loss_rate_pct': data.get('loss_rate_pct', 0),
            'reorder_count': data.get('reorder_count', 0),
            'is_clean': data.get('is_clean', True),
        }

    return summary


def _build_ts_summary(results: dict) -> dict:
    """构建时间戳连续性摘要。"""
    ts = results.get('ts_continuity', {})
    streams = {}

    for label, data in (ts or {}).items():
        streams[label] = {
            'is_continuous': data.get('is_continuous', True),
            'packet_count': data.get('packet_count', 0),
            'pt': data.get('pt'),
            'clock_rate': data.get('clock_rate'),
            'mode': data.get('mode'),
            'packet_duration_ms': data.get('packet_duration_ms'),
            'event_count': data.get('event_count', 0),
            'jump_count': data.get('jump_count', 0),
            'backward_count': data.get('backward_count', 0),
            'reorder_count': data.get('reorder_count', 0),
            'duplicate_count': data.get('duplicate_count', 0),
            'wrap_count': data.get('wrap_count', 0),
            'total_media_gap_ms': data.get('total_media_gap_ms', 0),
            # 事件明细带可读时间与前后包信息（最多 20 条，完整计数见上面各字段）
            'events': [
                {
                    'time_str': datetime.fromtimestamp(ev['time']).strftime('%H:%M:%S'),
                    'kind': ev['kind'],
                    'seq': ev['seq'],
                    'ts': ev.get('ts'),
                    'prev_seq': ev.get('prev_seq'),
                    'prev_ts': ev.get('prev_ts'),
                    'ts_delta': ev['ts_delta'],
                    'media_gap_ms': ev['media_gap_ms'],
                    'arrival_gap_ms': ev.get('arrival_gap_ms'),
                }
                for ev in (data.get('events') or [])[:20]
            ],
        }

    return {'streams': streams}


# 抓包文件角色 → 展示名（issue 文案用；stream 键仍保留原始 label）
ROLE_LABELS = {
    'fs': 'FS 服务器端', 'FS': 'FS 服务器端',
    'seat': '坐席端', '坐席': '坐席端', 'zuoxi': '坐席端',
    'terminal': '终端 / 主叫端', '终端': '终端 / 主叫端',
    'caller': '终端 / 主叫端', '主叫': '终端 / 主叫端',
}


def _pretty_label(label: str) -> str:
    """把 "role (SSRC=0x…)" 的角色前缀换成中文展示名。"""
    role, sep, rest = label.partition(' (')
    return f'{ROLE_LABELS.get(role, role)} ({rest}' if sep else label


def _gap_human(gap_ms: float) -> str:
    """把累计媒体时间缺口换成人类可读的单位。"""
    if gap_ms >= 60000:
        return f'{gap_ms / 60000:.1f} 分钟'
    if gap_ms >= 1000:
        return f'{gap_ms / 1000:.1f} 秒'
    return f'{gap_ms:.0f} 毫秒'


def _ts_explain(data: dict, gap_ms: float) -> str:
    """生成时间戳异常的直白解释（分现象说明 + 影响评估）。

    面向非专业用户：RTP 时间戳是发送端给每包声音盖的"媒体时钟"标记，
    正常随包一路增大；异常即位置对不上。
    """
    lines = ['发送端给每一包声音都盖了一个"时间戳"，标记这段声音在整通'
             '电话里的位置，正常情况下它随包一路增大。异常就是它的位置对不上：']
    if data.get('jump_count', 0):
        lines.append('・声音内容突然断开：相邻两包之间少了一段声音。如果对方正'
                     '处于静音（没说话），这是"静音抑制"的正常省流量做法；如果'
                     '发生在有人说话时，说明发送端丢了一段声音。')
    if data.get('backward_count', 0):
        lines.append('・声音时间往回走：包到达的先后顺序没乱，但时间戳却倒退'
                     '——通常是发送端（终端或服务器）时钟异常，可能表现为'
                     '卡顿、杂音。')
    if data.get('reorder_count', 0):
        lines.append('・数据包晚到/乱序：网络把包的先后顺序打乱了，播放端一般'
                     '能自动恢复，通常无需处理。')
    if data.get('duplicate_count', 0):
        lines.append('・同一时刻声音重复：同一段声音被发了两遍（或发送端时钟停'
                     '了一下），可能是发送端故障或冗余重传。')
    if gap_ms >= 1:
        lines.append(f'影响评估：整通电话累计缺少约 {_gap_human(gap_ms)}的声音内容。')
    else:
        lines.append('影响评估：声音内容本身没有缺失。')
    return '\n'.join(lines)


def _build_clock_summary(results: dict) -> dict:
    """构建时钟偏移摘要。"""
    clock_info = results.get('clock_info', {})
    return {
        'offsets': clock_info.get('offsets', {}),
        'max_offset_ms': clock_info.get('max_offset', 0),
        'warning': clock_info.get('warning'),
    }


def _build_conclusion(results: dict) -> dict:
    """生成结论（所有面向用户的文案使用中文）。"""
    fs_delay = results.get('fs_delay', {})
    jitter = results.get('jitter', {})
    packet_loss = results.get('packet_loss', {})

    issues = []
    ok_items = []

    # FS 内部延迟评估
    if fs_delay.get('count', 0) > 0:
        if fs_delay['mean'] < 20 and fs_delay['p95'] < 50:
            ok_items.append('FS 内部处理延迟健康（均值 < 20ms）')
        elif fs_delay['mean'] < 50:
            issues.append({
                'severity': 'warning',
                'message': f'FS 处理延迟偏高（均值 {fs_delay["mean"]:.1f}ms）',
            })
        else:
            issues.append({
                'severity': 'critical',
                'message': f'FS 处理延迟过高（均值 {fs_delay["mean"]:.1f}ms）',
            })

        if fs_delay['outliers_50ms'] > 0:
            issues.append({
                'severity': 'warning',
                'message': f'检测到 {fs_delay["outliers_50ms"]} 次 > 50ms 的延迟尖峰',
            })
    else:
        issues.append({
            'severity': 'info',
            'message': '未捕获 FS 抓包——无法测量 FS 内部处理延迟',
        })

    # 抖动评估
    if jitter:
        for label, data in jitter.items():
            if data.get('std', 0) > 10:
                issues.append({
                    'severity': 'warning',
                    'message': f'{label}: 抖动偏大（标准差 {data["std"]:.1f}ms）',
                })
            elif data.get('abnormal_count', 0) > 0:
                issues.append({
                    'severity': 'info',
                    'message': f'{label}: 检测到 {data["abnormal_count"]} 处异常包间隔',
                })
            else:
                ok_items.append(f'{label}: 间隔稳定（标准差 {data.get("std", 0):.1f}ms）')

    # 丢包评估
    if packet_loss:
        all_clean = all(d.get('is_clean', True) for d in packet_loss.values())
        if all_clean:
            ok_items.append('所有流均未检测到丢包')
        else:
            for ssrc, data in packet_loss.items():
                if not data.get('is_clean', True):
                    issues.append({
                        'severity': 'critical',
                        'message': (f'{data.get("label", "")}: 丢失 {data["total_lost"]} 包'
                                    f'（丢包率 {data["loss_rate_pct"]:.2f}%）'),
                    })
                elif data.get('reorder_count', 0) > 0:
                    issues.append({
                        'severity': 'info',
                        'message': (f'{data.get("label", "")}: 检测到 {data["reorder_count"]} '
                                    f'个乱序包（未计入丢包）'),
                    })

    # 时间戳连续性评估。文案面向非专业用户（"RTP 时间戳"直说成"声音时间
    # 轴"）；issue 附带 stream（对应 timestamp_continuity.streams 的键）与
    # explain（逐现象的直白解释），前端据此渲染可点击的逐包前后对照
    ts_continuity = results.get('ts_continuity') or {}
    for label, data in ts_continuity.items():
        n = data.get('event_count', 0)
        if n == 0:
            continue
        parts = []
        if data.get('jump_count', 0):
            parts.append(f"声音内容突然断开 {data['jump_count']} 处")
        if data.get('backward_count', 0):
            parts.append(f"声音时间往回走 {data['backward_count']} 处"
                         f"（发送端时钟异常）")
        if data.get('reorder_count', 0):
            parts.append(f"数据包晚到/乱序 {data['reorder_count']} 处")
        if data.get('duplicate_count', 0):
            parts.append(f"同一时刻声音重复 {data['duplicate_count']} 处")
        gap = data.get('total_media_gap_ms') or 0
        if gap >= 1:
            gap_part = f'累计缺少约 {_gap_human(gap)}的声音内容，'
            impact = ('人耳基本听不出来' if gap < 50
                      else '可能有轻微卡顿感' if gap < 300
                      else '可能出现明显断音、吞字')
        else:
            gap_part = ''
            impact = ('虽然声音内容没有缺失，但时间倒退/重复若频繁出现，'
                      '可能引起卡顿或杂音')
        issues.append({
            'severity': 'critical' if data.get('backward_count', 0) else 'warning',
            'message': (f'{_pretty_label(label)}: 这条流的声音时间轴异常：'
                        f'{"、".join(parts)}，{gap_part}{impact}'),
            'stream': label,
            'explain': _ts_explain(data, gap),
        })
    if ts_continuity and all(d.get('event_count', 0) == 0 for d in ts_continuity.values()):
        ok_items.append('所有流的声音时间轴连续（无断开/倒退/重复）')

    # FS 媒体转发判定（音视频流是否真的经过 FS 转发 + 排查方向）
    fs_relay = results.get('fs_relay') or {}
    if fs_relay.get('available'):
        v = fs_relay.get('verdict')
        if v in ('redirected', 'no_relay'):
            issues.append({
                'severity': 'critical',
                'message': f"FS 媒体转发：{fs_relay.get('headline', '')}",
            })
        elif v == 'partial_uplink':
            issues.append({
                'severity': 'warning',
                'message': f"FS 媒体转发：{fs_relay.get('headline', '')}",
            })
        elif v == 'relayed':
            ok_items.append('FS 媒体转发正常：各端媒体均经过 FS 中转')
        for n in fs_relay.get('notes') or []:
            issues.append({'severity': 'warning',
                           'message': f'FS 媒体转发：{n}'})

    # 无声诊断评估（directions 按主叫→坐席 / 坐席→主叫给出链路级判定）
    audio_health = results.get('audio_health') or {}
    if audio_health.get('available'):
        for d in audio_health.get('directions', []):
            v = d.get('verdict')
            label = f"无声诊断·{d.get('label', '')}"
            if v in ('blocked', 'no_source', 'silent_source', 'silent_path'):
                issues.append({
                    'severity': 'critical',
                    'message': f'{label}: {d.get("verdict_text", "")}',
                })
            elif v == 'unknown':
                issues.append({
                    'severity': 'info',
                    'message': f'{label}: 数据不足，无法判定（缺对应抓包点'
                               f'或编码不可解）',
                })
            else:
                ok_items.append(f'{label}: 链路正常，各段都有人声')

    # 分段延迟链路评估
    delay_chains = results.get('delay_chains') or {}
    if delay_chains.get('available'):
        for d in delay_chains.get('directions', []):
            if d.get('verdict') == 'high':
                issues.append({
                    'severity': 'warning',
                    'message': f"延迟链路·{d.get('label', '')}: "
                               f"{d.get('verdict_text', '')}",
                })
            elif d.get('verdict') == 'ok':
                ok_items.append(f"延迟链路·{d.get('label', '')}: 各段延迟正常")
        for r in delay_chains.get('roundtrip', []):
            if r.get('status') == 'high':
                issues.append({
                    'severity': 'warning',
                    'message': f"延迟链路·{r.get('pair', '')}: 往返 {r['ms']}ms，"
                               f'链路整体偏慢',
                })

    # 音画质量分析（杂音/啸叫/削波破音/底噪 + 视频花屏风险）：
    # 每条流的 issues 逐条进结论并带上流名前缀，检测通过的流进 ok_items
    for kind, entries in (('audio', results.get('audio_quality') or {}),
                          ('video', results.get('video_quality') or {})):
        for label, q in entries.items():
            for issue in q.get('issues') or []:
                issues.append({
                    'severity': issue.get('severity', 'warning'),
                    'message': f'{_pretty_label(label)}: {issue.get("message", "")}',
                })
            if q.get('verdict') in ('clean', 'ok'):
                ok_items.append(f'{_pretty_label(label)}: ' +
                                ('音质检测通过（无啸叫/杂音/削波）'
                                 if kind == 'audio'
                                 else '视频流未发现花屏风险因素'))

    # RTCP 接收端报告评估（RR 是接收端对收流质量的亲历上报）
    rtcp = results.get('rtcp') or {}
    for label, entry in rtcp.items():
        rr = entry.get('rr')
        if not rr:
            continue
        lost_pct = rr.get('fraction_lost_pct') or 0
        if lost_pct > 2:
            issues.append({
                'severity': 'warning',
                'message': (f'{_pretty_label(label)}: 接收端 RTCP RR 自报丢包 '
                            f'{lost_pct}%（累计 {rr.get("cum_lost", 0)} 包）'),
            })
        else:
            ok_items.append(f'{_pretty_label(label)}: 接收端 RR 丢包 {lost_pct}%')
    if results.get('rtcp') is not None and not rtcp:
        issues.append({
            'severity': 'info',
            'message': '未捕获 RTCP 报告——接收端视角的丢包/抖动不可观测'
                       '（抓包点未覆盖 RTCP 端口，或终端未启用 RTCP）',
        })

    # 根因分析
    root_cause = None
    if not issues:
        root_cause = ('RTP 层面未发现明显问题。延迟可能来自应用层'
                      '（抖动缓冲、音频设备、编码器缓冲），建议检查终端音频配置。')
    elif any(i['severity'] == 'critical' for i in issues):
        root_cause = 'RTP 层面发现严重问题，请检查 FS 配置与网络状况。'
    else:
        root_cause = '发现轻微问题，建议持续观察，并考虑调整终端缓冲参数。'
    
    return {
        'issues': issues,
        'ok_items': ok_items,
        'root_cause': root_cause,
        'overall': 'healthy' if len(issues) == 0 else ('warning' if not any(
            i['severity'] == 'critical' for i in issues) else 'critical'),
    }