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
            'is_clean': data.get('is_clean', True),
        }
    
    return summary


def _build_clock_summary(results: dict) -> dict:
    """构建时钟偏移摘要。"""
    clock_info = results.get('clock_info', {})
    return {
        'offsets': clock_info.get('offsets', {}),
        'max_offset_ms': clock_info.get('max_offset', 0),
        'warning': clock_info.get('warning'),
    }


def _build_conclusion(results: dict) -> dict:
    """生成结论。"""
    fs_delay = results.get('fs_delay', {})
    jitter = results.get('jitter', {})
    packet_loss = results.get('packet_loss', {})
    
    issues = []
    ok_items = []
    
    # FS delay evaluation
    if fs_delay.get('count', 0) > 0:
        if fs_delay['mean'] < 20 and fs_delay['p95'] < 50:
            ok_items.append('FS internal processing delay is healthy (< 20ms)')
        elif fs_delay['mean'] < 50:
            issues.append({
                'severity': 'warning',
                'message': f'FS processing delay is elevated (mean={fs_delay["mean"]:.1f}ms)',
            })
        else:
            issues.append({
                'severity': 'critical',
                'message': f'FS processing delay is HIGH (mean={fs_delay["mean"]:.1f}ms)',
            })
        
        if fs_delay['outliers_50ms'] > 0:
            issues.append({
                'severity': 'warning',
                'message': f'{fs_delay["outliers_50ms"]} delay spikes > 50ms detected',
            })
    else:
        issues.append({
            'severity': 'info',
            'message': 'FS capture not available - cannot measure FS internal delay',
        })
    
    # Jitter evaluation
    if jitter:
        for label, data in jitter.items():
            if data.get('std', 0) > 10:
                issues.append({
                    'severity': 'warning',
                    'message': f'{label}: high jitter (std={data["std"]:.1f}ms)',
                })
            elif data.get('abnormal_count', 0) > 0:
                issues.append({
                    'severity': 'info',
                    'message': f'{label}: {data["abnormal_count"]} abnormal gaps detected',
                })
            else:
                ok_items.append(f'{label}: clean (std={data.get("std", 0):.1f}ms)')
    
    # Packet loss evaluation
    if packet_loss:
        all_clean = all(d.get('is_clean', True) for d in packet_loss.values())
        if all_clean:
            ok_items.append('No packet loss detected on any stream')
        else:
            for ssrc, data in packet_loss.items():
                if not data.get('is_clean', True):
                    issues.append({
                        'severity': 'critical',
                        'message': (f'{data.get("label", "")}: {data["total_lost"]} packets lost '
                                    f'({data["loss_rate_pct"]:.2f}%)'),
                    })
    
    # Root cause analysis
    root_cause = None
    if not issues:
        root_cause = ('RTP-level analysis shows no significant issues. '
                      'The delay may be in the application layer (jitter buffer, audio device, codec). '
                      'Check endpoint audio configuration.')
    elif any(i['severity'] == 'critical' for i in issues):
        root_cause = 'Critical issues detected at RTP level. Check FS configuration and network.'
    else:
        root_cause = 'Minor issues detected. Monitor and consider endpoint buffer tuning.'
    
    return {
        'issues': issues,
        'ok_items': ok_items,
        'root_cause': root_cause,
        'overall': 'healthy' if len(issues) == 0 else ('warning' if not any(
            i['severity'] == 'critical' for i in issues) else 'critical'),
    }