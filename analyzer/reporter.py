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
            'mode': data.get('mode'),
            'packet_duration_ms': data.get('packet_duration_ms'),
            'event_count': data.get('event_count', 0),
            'jump_count': data.get('jump_count', 0),
            'backward_count': data.get('backward_count', 0),
            'reorder_count': data.get('reorder_count', 0),
            'duplicate_count': data.get('duplicate_count', 0),
            'wrap_count': data.get('wrap_count', 0),
            'total_media_gap_ms': data.get('total_media_gap_ms', 0),
            # 事件明细带可读时间（最多 20 条，完整计数见上面各字段）
            'events': [
                {
                    'time_str': datetime.fromtimestamp(ev['time']).strftime('%H:%M:%S'),
                    'kind': ev['kind'],
                    'seq': ev['seq'],
                    'ts_delta': ev['ts_delta'],
                    'media_gap_ms': ev['media_gap_ms'],
                }
                for ev in (data.get('events') or [])[:20]
            ],
        }

    return {'streams': streams}


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

    # 时间戳连续性评估
    ts_continuity = results.get('ts_continuity') or {}
    for label, data in ts_continuity.items():
        n = data.get('event_count', 0)
        if n == 0:
            continue
        parts = []
        if data.get('jump_count', 0):
            parts.append(f"时间戳跳变 {data['jump_count']} 次")
        if data.get('backward_count', 0):
            parts.append(f"时间戳倒退 {data['backward_count']} 次（seq 顺序未变，发送端异常）")
        if data.get('reorder_count', 0):
            parts.append(f"乱序倒退 {data['reorder_count']} 次")
        if data.get('duplicate_count', 0):
            parts.append(f"时间戳重复 {data['duplicate_count']} 次")
        gap = data.get('total_media_gap_ms') or 0
        if gap >= 60000:
            gap_txt = f'，累计缺少 {gap / 60000:.1f} 分钟媒体时间'
        elif gap >= 1000:
            gap_txt = f'，累计缺少 {gap / 1000:.1f} 秒媒体时间'
        elif gap >= 1:
            gap_txt = f'，累计缺少 {gap:.0f}ms 媒体时间'
        else:
            gap_txt = ''
        issues.append({
            'severity': 'critical' if data.get('backward_count', 0) else 'warning',
            'message': f'{label}: RTP 时间戳不连续（{"、".join(parts)}）{gap_txt}',
        })
    if ts_continuity and all(d.get('event_count', 0) == 0 for d in ts_continuity.values()):
        ok_items.append('所有流 RTP 时间戳连续（无跳变/倒退/重复）')

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