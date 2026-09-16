"""
RTP Stream Analyzer - Flask Web Application
音视频流延迟/抖动分析平台
"""
import os
import json
import re
import uuid
import shutil
import threading
import time
from datetime import date
from flask import Flask, render_template, request, jsonify, send_file, url_for

from analyzer.rtp_parser import extract_rtp_packets, get_stream_packets
from analyzer.stream_classifier import (
    classify_all_streams, get_pt_name, detect_server_ip
)
from analyzer.delay_analyzer import (
    calc_fs_internal_delay, calc_cross_capture_delay,
    detect_clock_offsets, estimate_end_to_end_delay,
)
from analyzer.jitter_analyzer import calc_inter_packet_gaps, compare_jitter
from analyzer.packet_loss import detect_all_losses
from analyzer.ts_continuity import check_ts_continuity
from analyzer.charts import generate_analysis_chart
from analyzer.reporter import generate_report
from analyzer.media_extractor import (
    generate_all_media, get_media_urls, describe_media_parties, extract_call_parties,
)
from analyzer.silence_analyzer import analyze_silence, diagnose_audio
from analyzer.rtcp_parser import summarize_rtcp
from analyzer.delay_chains import build_delay_chains
from analyzer.quality_analyzer import analyze_audio_quality, analyze_video_quality
from analyzer.call_detector import detect_calls, check_capture_consistency
from analyzer.capture_integrity import merge_integrity

# 默认 True（本地 python app.py 调试）；systemd 部署设 FLASK_DEBUG=0 走 gunicorn 生产模式
DEBUG = os.environ.get('FLASK_DEBUG', '1') == '1'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['OUTPUT_FOLDER'] = os.path.join(os.path.dirname(__file__), 'outputs')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB
# 自动清理：outputs（图表/媒体文件）与 uploads（上传的抓包）超过保留时长
# 即被后台线程删除，两处共用同一保留时长
app.config['FILE_RETENTION_HOURS'] = 2            # 保留时长（小时）
app.config['FILE_CLEANUP_INTERVAL_MINUTES'] = 10  # 清理巡检间隔（分钟）

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

# 存储分析会话
sessions = {}


def _latest_mtime(path):
    """目录树内（含自身）最新的 mtime，作为"最后一次有写入"的时间。

    会话目录的媒体文件写在 audio/、video/ 子目录里，目录自身的 mtime
    停在子目录创建时刻，只看它会把仍在写入的目录误判为超时。
    """
    try:
        latest = os.path.getmtime(path)
    except OSError:
        return 0.0
    for root, _dirs, files in os.walk(path):
        for entry in [root] + [os.path.join(root, f) for f in files]:
            try:
                latest = max(latest, os.path.getmtime(entry))
            except OSError:
                pass
    return latest


def _cleanup_tree_once(root, cutoff):
    """递归清理 root 下超过保留时长的内容：目录按树内最新 mtime 整树删除，
    散落文件按自身 mtime 删除；被清空的目录一并移除。
    单个条目删除失败（被并发写入/占用）跳过即可，不影响其余清理。
    """
    if not os.path.isdir(root):
        return
    for name in os.listdir(root):
        path = os.path.join(root, name)
        try:
            if os.path.isdir(path):
                if _latest_mtime(path) < cutoff:
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    _cleanup_tree_once(path, cutoff)  # 目录整体未超时，清理其内部
                    if not os.listdir(path):
                        os.rmdir(path)  # 内部已清空，删除空目录
            elif os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            continue


def _cleanup_stale_files_once():
    """按保留时长清理 outputs（图表/媒体）与 uploads（上传的抓包），
    超过保留时长的内容被删除，两处共用 FILE_RETENTION_HOURS。"""
    cutoff = time.time() - app.config['FILE_RETENTION_HOURS'] * 3600
    _cleanup_tree_once(app.config['OUTPUT_FOLDER'], cutoff)
    _cleanup_tree_once(app.config['UPLOAD_FOLDER'], cutoff)


def _start_file_cleaner():
    """启动清理后台线程：启动时先清一次历史遗留，再按间隔巡检。"""

    def _loop():
        interval = max(60, int(app.config['FILE_CLEANUP_INTERVAL_MINUTES']) * 60)
        while True:
            try:
                _cleanup_stale_files_once()
            except Exception:
                pass  # 清理尽力而为，任何异常都不能影响主服务
            time.sleep(interval)

    threading.Thread(target=_loop, name='file-cleaner', daemon=True).start()


# debug 热重载下 Werkzeug 会让父子进程各执行一遍本模块，只有真正对外
# 提供服务的子进程带 WERKZEUG_RUN_MAIN=true，借此避免父进程重复起线程
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not DEBUG:
    _start_file_cleaner()


@app.route('/')
def index():
    """主页：上传和配置"""
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload_files():
    """上传抓包文件并自动识别端点角色。"""
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_id)
    os.makedirs(session_dir, exist_ok=True)
    
    files_info = []
    all_ips = set()
    all_streams = {}
    rtp_captures = {}  # role -> rtp_data（不含载荷，供通话检测使用）

    for key in request.files:
        file = request.files[key]
        if file.filename:
            # 展示名保留用户上传的原始文件名（含中文）；secure_filename 会把
            # 非 ASCII 字符全部删掉（"坐席端.pcap" → "pcap"），不能用于展示
            filename = file.filename
            # 磁盘存储名用 uuid 生成、仅保留原扩展名，规避路径穿越/同名互覆/
            # 超长文件名问题；抓包解析按文件内容嗅探，不依赖文件名
            ext = os.path.splitext(filename)[1].lower()
            ext = ext if re.fullmatch(r'\.[A-Za-z0-9]{1,10}', ext) else ''
            stored_name = uuid.uuid4().hex + ext
            filepath = os.path.join(session_dir, stored_name)
            file.save(filepath)

            # 解析 RTP；无法解析的文件直接报错（其余文件不受影响）
            try:
                rtp_data = extract_rtp_packets(filepath)
            except Exception:
                return jsonify({'error': f'文件 {filename} 无法解析为抓包文件'
                                         '（格式不支持或已损坏）'}), 400
            rtp_captures[key] = rtp_data

            # 收集流信息
            for ssrc, info in rtp_data['streams'].items():
                all_streams[ssrc] = info

            all_ips.update(rtp_data['ips'])

            files_info.append({
                'role': key,
                'filename': filename,
                'stored': stored_name,
                'total_packets': rtp_data['total_count'],
                'ips': sorted([ip for ip in rtp_data['ips']
                              if not ip.startswith('224.') and not ip.startswith('239.')
                              and ip not in ('0.0.0.0', '255.255.255.255')]),
                'stream_count': len(rtp_data['streams']),
                # 抓包完整性（截短/文件尾损坏）：只提示，不阻断分析
                'integrity': rtp_data['integrity'],
            })

    # 自动检测服务器 IP
    server_ip = detect_server_ip(all_streams)

    # 通话检测：将流按通话分组并评估每通的抓包完整性
    calls = detect_calls(rtp_captures, server_ip)

    # 服务器侧抓包：抓包点位于服务器上（其 IP 集合含 server_ip，通常是 FS 端）。
    # 点对点直连提示需要它来区分"FS 抓不到这通电话"和"传错文件"。
    server_roles = [r for r, rd in rtp_captures.items()
                    if server_ip and server_ip in rd.get('ips', set())]

    # 跨抓包一致性：各抓包之间是否共享同一通通话（不共享 → 很可能传错文件；
    # 若是点对点直连通话则给出对应提示）
    capture_warning = check_capture_consistency(calls, rtp_captures.keys(),
                                                server_ip=server_ip,
                                                server_roles=server_roles)

    # 抓包完整性汇总：哪些文件有截短包/文件尾损坏（有提示但继续分析）
    integrity_warning = merge_integrity(files_info)

    # 分类流
    classified = classify_all_streams(all_streams)

    # 识别可用的延迟方向
    available_directions = _detect_available_directions(files_info, server_ip, classified)

    # 保存会话
    sessions[session_id] = {
        'files': files_info,
        'server_ip': server_ip,
        'streams': all_streams,
        'classified': classified,
        'session_dir': session_dir,
        'calls': calls,
        'capture_warning': capture_warning,
        'integrity_warning': integrity_warning,
    }

    return jsonify({
        'session_id': session_id,
        'files': files_info,
        'server_ip': server_ip,
        'audio_streams': len(classified.get('audio', {})),
        'video_streams': len(classified.get('video', {})),
        'available_directions': available_directions,
        'calls': calls,
        'capture_warning': capture_warning,
        'integrity_warning': integrity_warning,
    })


@app.route('/api/analyze', methods=['POST'])
def run_analysis():
    """执行分析。"""
    data = request.get_json()
    session_id = data.get('session_id')
    direction = data.get('direction', 'auto')
    media_type = data.get('media_type', 'audio')
    call_id = data.get('call_id')
    # 分析内容开关：延迟类分析需要 ≥2 个抓包点或 FS 抓包，单端抓包时前端
    # 会禁用该选项；音画质量分析单端即可做。未传时保持全开（兼容旧调用）。
    checks = data.get('checks') or {}
    check_delay = bool(checks.get('delay', True))
    check_quality = bool(checks.get('quality', True))

    if session_id not in sessions:
        return jsonify({'error': 'Session not found'}), 404

    session = sessions[session_id]
    session_dir = session['session_dir']
    files_info = session['files']
    all_streams = session['streams']
    classified = session['classified']
    server_ip = session.get('server_ip')
    calls = session.get('calls') or []
    
    # 加载所有抓包数据（含 RTP 载荷，用于音视频重建）
    # _role 为规范化角色（terminal/seat/fs），供无声诊断/延迟链路按角色锚定
    captures = {}
    for fi in files_info:
        filepath = os.path.join(session_dir, fi['stored'])
        cap = extract_rtp_packets(filepath, include_payload=True)
        cap['_role'] = _canonical_role(fi['role'])
        captures[fi['role']] = cap
    
    # 根据媒体类型筛选流
    if media_type == 'audio':
        target_streams = classified.get('audio', {})
    elif media_type == 'video':
        target_streams = classified.get('video', {})
    else:
        target_streams = {**classified.get('audio', {}), **classified.get('video', {})}

    # 通话过滤：选中某通通话时，分析范围限定为该通话的流。
    # 多通混杂会把不同通话的延迟/抖动拼在一起，导致结果失真。
    selected_call = None
    if call_id:
        selected_call = next((c for c in calls if c['call_id'] == call_id), None)
    elif len(calls) == 1:
        # 只有一通通话时自动选中，行为与旧版一致
        selected_call = calls[0]

    call_ssrcs = None
    if selected_call:
        call_ssrcs = set(selected_call['ssrcs'])
        target_streams = {s: info for s, info in target_streams.items()
                          if s in call_ssrcs}

    results = {
        'direction': direction,
        'media_type': media_type,
        'checks': {'delay': check_delay, 'quality': check_quality},
        'call_id': selected_call['call_id'] if selected_call else None,
        'num_captures': len(captures),
        'capture_roles': {fi['role']: fi['filename'] for fi in files_info},
        'ips_info': {fi['role']: {'ips': fi['ips'], 'stream_count': fi['stream_count']} 
                     for fi in files_info},
        'detected_server_ip': server_ip,
        'streams': all_streams,
        'classified_streams': classified,
        # 每份抓包的完整性结论（截短/文件尾损坏），报告据此加数据说明
        'capture_integrity': {role: cap['integrity']
                              for role, cap in captures.items()
                              if cap.get('integrity')},
    }
    
    # === 抖动分析 ===
    jitter_results = {}
    for role, cap in captures.items():
        for ssrc in target_streams:
            if ssrc in cap['streams']:
                label = f"{role} (SSRC=0x{ssrc:08x})"
                gap_result = calc_inter_packet_gaps(cap['packets'], ssrc)
                if gap_result['count'] > 0:
                    jitter_results[label] = gap_result
    
    results['jitter'] = jitter_results
    
    # === 丢包分析 ===
    loss_results = {}
    for role, cap in captures.items():
        ssrcs = [s for s in target_streams if s in cap['streams']]
        if ssrcs:
            labels = {s: f"{role} (SSRC=0x{s:08x})" for s in ssrcs}
            loss_results.update(detect_all_losses(cap['packets'], ssrcs, labels))
    
    results['packet_loss'] = loss_results

    # === 时间戳连续性 ===
    # 检查每条流的 RTP 时间戳是否单调连续（跳变/倒退/重复），异常会在
    # 报告里标注；实测的每包时长也用于音频重建
    ts_results = {}
    for role, cap in captures.items():
        for ssrc in target_streams:
            if ssrc in cap['streams']:
                label = f"{role} (SSRC=0x{ssrc:08x})"
                # 种类/时钟率来自解析结果：动态 PT 音频（OPUS@96）按 48kHz
                # 时钟逐包核对，否则会被当视频流（90kHz、帧级）漏检
                kind_info = (classified.get('audio', {}).get(ssrc)
                             or classified.get('video', {}).get(ssrc) or {})
                ts_result = check_ts_continuity(
                    cap['packets'], ssrc,
                    clock_rate=kind_info.get('clock'),
                    full_mode=(kind_info.get('kind') == 'audio')
                    if kind_info.get('kind') else None)
                if ts_result['packet_count'] > 0:
                    ts_result['label'] = label
                    ts_results[label] = ts_result

    results['ts_continuity'] = ts_results

    # === 无声诊断（静音/能量分析）+ RTCP 收发报告 + 分段延迟链路 ===
    # 这三项以"通话"为单位、按规范化角色（主叫端/坐席端/FS）锚定方向；
    # 未选中通话时没有方向语义，仅给出不可用说明
    canon_captures = {}
    for cap in captures.values():
        canon_captures[cap['_role']] = cap

    rtcp_by_role = {role: summarize_rtcp(cap)
                    for role, cap in canon_captures.items()}
    rtcp_results = {}
    silence_profiles = {}
    for role, cap in canon_captures.items():
        summ = rtcp_by_role[role]
        for ssrc in target_streams:
            info = cap['streams'].get(ssrc)
            if not info:
                continue
            # 流种类用分类结果（SDP 端口绑定/时钟率解析），动态 PT 音频
            # （如 OPUS@96）只看 PT 号会被误判成视频
            is_audio = ssrc in classified.get('audio', {})
            is_video = ssrc in classified.get('video', {})
            if not is_audio and not is_video:
                continue
            if is_audio:
                silence_profiles[(role, ssrc)] = analyze_silence(cap['packets'], ssrc)
            entry = {'kind': 'audio' if is_audio else 'video'}
            if ssrc in summ['sr']:
                entry['sr'] = summ['sr'][ssrc]
            if ssrc in summ['rr']:
                entry['rr'] = summ['rr'][ssrc]
            fb = summ.get('fb', {}).get(ssrc)
            if fb:
                entry['fb'] = fb
            rtcp_results[f"{role} (SSRC=0x{ssrc:08x})"] = entry
    results['rtcp'] = rtcp_results

    if selected_call:
        parties = extract_call_parties(selected_call, server_ip)
        results['audio_health'] = diagnose_audio(
            canon_captures, selected_call, server_ip,
            silence_profiles, rtcp_by_role, parties)
        # 无声诊断属于"内容是否有人声"的质量范畴，单端也可做，不受延迟开关限制
        if check_delay:
            results['delay_chains'] = build_delay_chains(
                canon_captures, selected_call, server_ip, parties)
        else:
            results['delay_chains'] = {
                'available': False, 'directions': [], 'roundtrip': [],
                'notes': ['未勾选延迟分析，跳过分段延迟链路测量']}
        # FS 媒体转发判定（上传识别时已按通话算好）：音视频流是否真的
        # 经过 FS 转发、被改道/缺失时的排查方向提示
        results['fs_relay'] = selected_call.get('fs_relay')
    else:
        results['audio_health'] = {
            'available': False, 'directions': [],
            'summary': '未选中通话，无法按方向做无声诊断（请先选择通话）'}
        results['delay_chains'] = {
            'available': False, 'directions': [], 'roundtrip': [],
            'notes': ['未选中通话，无法按方向定位链路延迟']}

    # === 音视频重建 ===
    # 输出目录按日期组织: outputs/YYYY-MM-DD/<session_id>/
    # 便于定期清理脚本按日期目录删除。
    # 提前到质量分析之前：视频裸流重建后才能做 ffmpeg 解码校验
    output_date = date.today().isoformat()
    media_dir = os.path.join(app.config['OUTPUT_FOLDER'], output_date, session_id)
    media_types = media_type if media_type in ('audio', 'video') else 'all'
    media_manifest = generate_all_media(captures, classified, media_dir,
                                        server_ip, media_types,
                                        ssrc_filter=call_ssrcs,
                                        call_id=selected_call['call_id'] if selected_call else None)
    media_manifest = get_media_urls(media_manifest, session_id, output_date)
    # 给每条媒体流标注收发双方（谁到谁），并在清单汇总通话拓扑（主叫↔FS↔被叫）
    describe_media_parties(media_manifest, captures, calls, server_ip, files_info)
    results['media_manifest'] = media_manifest
    results['media_dir'] = media_dir

    # === 音画质量分析（杂音/啸叫/削波破音/底噪 + 花屏风险） ===
    # 音频对解码后的 PCM 做 DSP 检测；视频把丢包映射到"花到下一个关键帧"
    # 的影响时长，并用重建裸流做 ffmpeg 解码校验
    audio_quality, video_quality = {}, {}
    if check_quality:
        for role, cap in captures.items():
            for ssrc in target_streams:
                info = cap['streams'].get(ssrc)
                if not info:
                    continue
                label = f"{role} (SSRC=0x{ssrc:08x})"
                if ssrc in classified.get('audio', {}):
                    audio_quality[label] = analyze_audio_quality(cap['packets'], ssrc)
                elif ssrc in classified.get('video', {}):
                    entry = next((e for e in media_manifest.get('video', [])
                                  if e.get('role') == role
                                  and e.get('ssrc') == f'0x{ssrc:08x}'), None)
                    raw_path = entry.get('raw_path') if entry else None
                    video_quality[label] = analyze_video_quality(
                        cap['packets'], ssrc, raw_path=raw_path)
    results['audio_quality'] = audio_quality
    results['video_quality'] = video_quality

    # === FS 内部延迟 ===
    fs_delay = None
    if check_delay and ('fs' in captures or 'FS' in captures):
        fs_role = 'fs' if 'fs' in captures else 'FS'
        fs_cap = captures[fs_role]

        # 找入站和出站 SSRC 对
        # 策略：寻找同一媒体类型中，方向相反的 SSRC 对
        fs_delay = _find_and_calc_fs_delay(fs_cap['packets'], target_streams, server_ip)

    results['fs_delay'] = fs_delay or {}

    # === 跨抓包延迟 ===
    cross_delays = []
    if check_delay and len(captures) >= 2:
        roles = list(captures.keys())
        for i in range(len(roles)):
            for j in range(i + 1, len(roles)):
                for ssrc in target_streams:
                    if (ssrc in captures[roles[i]]['streams'] and 
                        ssrc in captures[roles[j]]['streams']):
                        cd = calc_cross_capture_delay(
                            captures[roles[i]]['packets'],
                            captures[roles[j]]['packets'],
                            ssrc,
                            roles[i], roles[j]
                        )
                        if cd['count'] > 0:
                            cross_delays.append(cd)
    
    results['cross_delays'] = cross_delays
    
    # === 时钟偏移检测 ===
    clock_info = detect_clock_offsets(cross_delays)
    results['clock_info'] = clock_info
    
    # === 端到端延迟 ===
    if fs_delay and fs_delay.get('count', 0) > 0:
        results['end_to_end'] = estimate_end_to_end_delay(fs_delay)
    
    # === 生成瀑布图数据 ===
    if check_delay and len(captures) >= 3:
        results['waterfall'] = _build_waterfall_data(captures, target_streams, server_ip)
    
    # === 生成图表 ===
    chart_path = generate_analysis_chart(app.config['OUTPUT_FOLDER'], results)
    results['chart_path'] = chart_path
    results['chart_url'] = url_for('serve_chart', 
                                   filename=os.path.basename(chart_path))
    
    # === 生成报告 ===
    report = generate_report(results)
    results['report'] = report
    
    # 保存结果到会话
    session['results'] = results

    return jsonify({
        'success': True,
        'call_id': selected_call['call_id'] if selected_call else None,
        'chart_url': results['chart_url'],
        'report': report,
        'media_manifest': {
            'call_id': media_manifest.get('call_id'),
            'parties': media_manifest.get('parties', []),
            'audio': media_manifest.get('audio', []),
            'video': media_manifest.get('video', []),
            'unsupported': media_manifest.get('unsupported', []),
        },
        'summary': {
            # fs_delay_mean/p95：未测（未勾选延迟或无 FS 抓包）时为 None，
            # 前端据此显示"未测量"而非误导性的 0.0ms
            'fs_delay_mean': fs_delay.get('mean') if fs_delay else None,
            'fs_delay_p95': fs_delay.get('p95') if fs_delay else None,
            'jitter_streams': len(jitter_results),
            'packet_loss_clean': all(d.get('is_clean', True) for d in loss_results.values()),
            'ts_clean': all(d.get('event_count', 0) == 0 for d in ts_results.values()),
            'clock_warning': clock_info.get('warning'),
            'media_quality': _quality_flags(results),
            'delay_checked': check_delay,
            'quality_checked': check_quality,
            'overall': report['conclusion']['overall'],
        },
    })


@app.route('/api/session/<session_id>', methods=['GET'])
def get_session(session_id):
    """获取会话信息。"""
    if session_id not in sessions:
        return jsonify({'error': 'Session not found'}), 404
    
    session = sessions[session_id]
    
    # results 中可能包含不可 JSON 序列化的字段（packets 字典等），只返回可序列化的部分
    results = session.get('results')
    safe_results = None
    if results:
        safe_results = {
            'direction': results.get('direction'),
            'media_type': results.get('media_type'),
            'call_id': results.get('call_id'),
            'chart_url': results.get('chart_url'),
            'report': results.get('report'),
            'summary': _build_summary(results),
            'media_manifest': results.get('media_manifest'),
        }
    
    return jsonify({
        'files': session['files'],
        'server_ip': session['server_ip'],
        'audio_streams': len(session['classified'].get('audio', {})),
        'video_streams': len(session['classified'].get('video', {})),
        'calls': session.get('calls') or [],
        'capture_warning': session.get('capture_warning'),
        'integrity_warning': session.get('integrity_warning'),
        'results': safe_results,
    })


def _quality_flags(results):
    """音画质量检测汇总（供摘要卡片）：checked=是否测过，clean=是否全部正常。"""
    entries = list((results.get('audio_quality') or {}).values()) + \
        list((results.get('video_quality') or {}).values())
    verdicts = [e.get('verdict') for e in entries if e.get('verdict')]
    return {
        'checked': bool(verdicts),
        'clean': bool(verdicts) and all(v in ('clean', 'ok') for v in verdicts),
    }


def _build_summary(results):
    """从 results 构建摘要（与 /api/analyze 响应中的 summary 一致）。"""
    report = results.get('report') or {}
    conclusion = report.get('conclusion') or {}
    fs_delay = results.get('fs_delay') or {}
    loss_results = results.get('packet_loss') or {}
    checks = results.get('checks') or {}
    return {
        # fs_delay_mean/p95：未测（未勾选延迟或无 FS 抓包）时为 None，
        # 前端据此显示"未测量"而非误导性的 0.0ms
        'fs_delay_mean': fs_delay.get('mean') if fs_delay else None,
        'fs_delay_p95': fs_delay.get('p95') if fs_delay else None,
        'jitter_streams': len(results.get('jitter') or {}),
        'packet_loss_clean': all(d.get('is_clean', True) for d in loss_results.values()),
        'ts_clean': all(d.get('event_count', 0) == 0
                        for d in (results.get('ts_continuity') or {}).values()),
        'clock_warning': (results.get('clock_info') or {}).get('warning'),
        'media_quality': _quality_flags(results),
        'delay_checked': bool(checks.get('delay', True)),
        'quality_checked': bool(checks.get('quality', True)),
        'overall': conclusion.get('overall'),
    }


@app.route('/media/<path:filepath>')
def serve_media(filepath):
    """提供生成的音视频文件（WAV/MP4/H.264）。"""
    full_path = os.path.join(app.config['OUTPUT_FOLDER'], filepath)
    
    # 安全校验：路径必须位于 OUTPUT_FOLDER 内（防目录穿越）
    real_full = os.path.realpath(full_path)
    real_output = os.path.realpath(app.config['OUTPUT_FOLDER'])
    if not real_full.startswith(real_output + os.sep):
        return 'Forbidden', 403
    if not os.path.isfile(full_path):
        return 'File not found', 404
    
    # 根据扩展名设置正确的 MIME 类型
    ext = os.path.splitext(filepath)[1].lower()
    mime_map = {
        '.wav': 'audio/wav',
        '.mp4': 'video/mp4',
        '.h264': 'video/h264',
    }
    mimetype = mime_map.get(ext, 'application/octet-stream')
    return send_file(full_path, mimetype=mimetype)


@app.route('/charts/<filename>')
def serve_chart(filename):
    """提供图表文件。"""
    return send_file(os.path.join(app.config['OUTPUT_FOLDER'], filename),
                     mimetype='image/png')


@app.route('/results/<session_id>')
def results_page(session_id):
    """结果展示页。"""
    if session_id not in sessions:
        return "Session not found", 404
    return render_template('results.html', session_id=session_id)


def _canonical_role(role):
    """把上传时的角色文件名规范成 terminal/seat/fs（保留未知角色原样）。"""
    r = (role or '').strip().lower()
    if r == 'fs':
        return 'fs'
    if r in ('seat', 'zuoxi', '坐席'):
        return 'seat'
    if r in ('terminal', 'caller', '终端', '主叫'):
        return 'terminal'
    return role


def _detect_available_directions(files_info, server_ip, classified):
    """根据上传的文件自动检测可用的分析方向。"""
    roles = [fi['role'] for fi in files_info]
    directions = []
    
    has_fs = 'fs' in roles or 'FS' in roles
    has_seat = 'seat' in roles or '坐席' in roles or 'zuoxi' in roles
    has_terminal = 'terminal' in roles or '终端' in roles or 'caller' in roles or '主叫' in roles
    
    if has_seat and has_fs:
        directions.append({
            'id': 'seat_to_fs',
            'label': '坐席 → FS 传输延迟',
            'available': True,
            'requires': ['坐席端', 'FS端'],
        })
    
    if has_fs and has_terminal:
        directions.append({
            'id': 'fs_to_terminal',
            'label': 'FS → 终端 传输延迟',
            'available': True,
            'requires': ['FS端', '终端'],
        })
    
    if has_seat and has_fs and has_terminal:
        directions.append({
            'id': 'seat_to_terminal',
            'label': '坐席 → 终端 端到端延迟',
            'available': True,
            'requires': ['坐席端', 'FS端', '终端'],
        })
    
    if has_fs:
        directions.append({
            'id': 'fs_internal',
            'label': 'FS 内部处理延迟',
            'available': True,
            'requires': ['FS端'],
        })
    
    if not directions:
        directions.append({
            'id': 'single_capture',
            'label': '单端抖动/丢包分析',
            'available': True,
            'requires': ['任意一端'],
        })
    
    return directions


def _has_ssrc(packets, ssrc):
    """检查 packets 字典中是否包含某个 SSRC。"""
    for key in packets:
        if key[0] == ssrc:
            return True
    return False


def _find_and_calc_fs_delay(fs_packets, target_streams, server_ip):
    """在 FS 抓包中寻找入站/出站 SSRC 对并计算延迟。"""
    from analyzer.rtp_parser import get_stream_packets
    
    # 按端口对分组，找双向 RTP 流
    inbound = {}
    outbound = {}
    
    for ssrc in target_streams:
        if not _has_ssrc(fs_packets, ssrc):
            continue
        pkts = get_stream_packets(fs_packets, ssrc)
        if not pkts:
            continue
        # 根据目标 IP 判断方向
        dst_ip = pkts[0][5]  # dst_ip
        if server_ip and dst_ip == server_ip:
            inbound[ssrc] = pkts
        elif server_ip and pkts[0][4] == server_ip:  # src_ip
            outbound[ssrc] = pkts
    
    # 如果根据 IP 无法判断，按端口对匹配
    if not inbound or not outbound:
        port_pairs = {}
        for ssrc in target_streams:
            if not _has_ssrc(fs_packets, ssrc):
                continue
            pkts = get_stream_packets(fs_packets, ssrc)
            if pkts:
                pp = (pkts[0][4], pkts[0][6], pkts[0][5], pkts[0][7])
                port_pairs[ssrc] = pp
        
        # 找互为反向的端口对
        for ssrc_a, pp_a in port_pairs.items():
            for ssrc_b, pp_b in port_pairs.items():
                if ssrc_a != ssrc_b:
                    if (pp_a[0] == pp_b[2] and pp_a[1] == pp_b[3] and
                        pp_a[2] == pp_b[0] and pp_a[3] == pp_b[1]):
                        inbound[ssrc_a] = get_stream_packets(fs_packets, ssrc_a)
                        outbound[ssrc_b] = get_stream_packets(fs_packets, ssrc_b)
    
    # 对每对入站/出站计算延迟，取最好的结果
    best_result = None
    for ssrc_in in inbound:
        for ssrc_out in outbound:
            if ssrc_in != ssrc_out:
                result = calc_fs_internal_delay(fs_packets, ssrc_in, ssrc_out)
                if result['count'] > 0:
                    if best_result is None or result['count'] > best_result['count']:
                        best_result = result
                        best_result['ssrc_in'] = f'0x{ssrc_in:08x}'
                        best_result['ssrc_out'] = f'0x{ssrc_out:08x}'
    
    return best_result


def _build_waterfall_data(captures, target_streams, server_ip):
    """构建瀑布图数据。"""
    # 简化实现：需要在多个抓包中找同一媒体流的对应包
    # 这里返回空，实际需要在 delay_analyzer 中关联
    return []


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=DEBUG)