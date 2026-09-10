/**
 * RTP Stream Analyzer - 前端交互逻辑
 */

let sessionId = null;
let uploadedCount = 0;

document.addEventListener('DOMContentLoaded', () => {
    setupFileUploads();
    setupAnalyzeButton();
});

// ====== 文件上传 ======
function setupFileUploads() {
    const fileInputs = document.querySelectorAll('.file-input');
    const uploadBtn = document.getElementById('btn-upload');

    fileInputs.forEach(input => {
        input.addEventListener('change', (e) => {
            const file = e.target.files[0];
            const role = input.dataset.role;
            const box = document.getElementById('box-' + role);
            const nameDiv = document.getElementById('name-' + role);

            if (file) {
                box.classList.add('has-file');
                nameDiv.textContent = file.name;
                uploadedCount++;
            } else {
                box.classList.remove('has-file');
                nameDiv.textContent = '';
                uploadedCount = Math.max(0, uploadedCount - 1);
            }

            uploadBtn.disabled = uploadedCount === 0;
        });
    });

    uploadBtn.addEventListener('click', uploadFiles);
}

async function uploadFiles() {
    const btn = document.getElementById('btn-upload');
    const status = document.getElementById('upload-status');
    btn.disabled = true;
    status.innerHTML = '<span class="text-primary"><div class="spinner-border spinner-border-sm me-2"></div>正在上传并识别...</span>';

    const formData = new FormData();
    const fileInputs = document.querySelectorAll('.file-input');
    let hasFiles = false;

    fileInputs.forEach(input => {
        if (input.files[0]) {
            formData.append(input.dataset.role, input.files[0]);
            hasFiles = true;
        }
    });

    if (!hasFiles) {
        status.innerHTML = '<span class="text-danger">请至少上传一个抓包文件</span>';
        btn.disabled = false;
        return;
    }

    try {
        const resp = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            status.innerHTML = `<span class="text-danger">${data.error}</span>`;
            btn.disabled = false;
            return;
        }

        sessionId = data.session_id;
        status.innerHTML = '<span class="text-success">✓ 上传成功，已识别 ' + data.files.length + ' 个文件</span>';

        // 显示识别结果
        showDetectionResults(data);
        // 显示分析配置
        showConfigPanel(data);

    } catch (err) {
        status.innerHTML = `<span class="text-danger">上传失败: ${err.message}</span>`;
        btn.disabled = false;
    }
}

// ====== 识别结果展示 ======
function showDetectionResults(data) {
    const section = document.getElementById('detection-section');
    section.classList.remove('d-none');

    // 服务器
    const badgeServer = document.getElementById('badge-server');
    if (data.server_ip) {
        badgeServer.textContent = '服务器: ' + data.server_ip;
        badgeServer.className = 'badge bg-success me-2';
    } else {
        badgeServer.textContent = '服务器: 未检测到（单端分析模式）';
        badgeServer.className = 'badge bg-secondary me-2';
    }

    // 流统计
    document.getElementById('badge-audio').textContent = '音频流: ' + data.audio_streams;
    document.getElementById('badge-video').textContent = '视频流: ' + data.video_streams;

    // 文件详情
    let detail = '<table class="table table-sm table-bordered"><thead><tr><th>角色</th><th>文件名</th><th>包数</th><th>IP</th><th>流数</th></tr></thead><tbody>';
    data.files.forEach(f => {
        detail += `<tr>
            <td><strong>${f.role}</strong></td>
            <td>${f.filename}</td>
            <td>${f.total_packets.toLocaleString()}</td>
            <td>${f.ips.join(', ')}</td>
            <td>${f.stream_count}</td>
        </tr>`;
    });
    detail += '</tbody></table>';
    document.getElementById('streams-detail').innerHTML = detail;
}

// ====== 分析配置面板 ======
function showConfigPanel(data) {
    const section = document.getElementById('config-section');
    section.classList.remove('d-none');

    const container = document.getElementById('direction-options');
    const directions = data.available_directions;

    if (directions.length === 0) {
        container.innerHTML = '<p class="text-muted">未检测到可分析的方向</p>';
        return;
    }

    let html = '';
    directions.forEach((dir, idx) => {
        const disabled = !dir.available;
        const reqStr = dir.requires.join(' + ');
        html += `
            <label class="direction-option ${disabled ? 'disabled' : ''} ${idx === 0 ? 'selected' : ''}">
                <input type="radio" name="direction" value="${dir.id}" 
                       ${disabled ? 'disabled' : ''} ${idx === 0 ? 'checked' : ''}
                       style="display:none">
                ${dir.label}
                <span class="badge bg-light text-dark">${reqStr}</span>
            </label>
        `;
    });
    container.innerHTML = html;

    // 方向选项点击切换
    container.querySelectorAll('.direction-option:not(.disabled)').forEach(opt => {
        opt.addEventListener('click', () => {
            container.querySelectorAll('.direction-option').forEach(o => o.classList.remove('selected'));
            opt.classList.add('selected');
            opt.querySelector('input').checked = true;
        });
    });
}

// ====== 执行分析 ======
function setupAnalyzeButton() {
    document.getElementById('btn-analyze').addEventListener('click', runAnalysis);
}

async function runAnalysis() {
    if (!sessionId) {
        alert('请先上传抓包文件');
        return;
    }

    const btn = document.getElementById('btn-analyze');
    const status = document.getElementById('analyze-status');
    btn.disabled = true;
    status.innerHTML = '<span class="text-warning"><div class="spinner-border spinner-border-sm me-2"></div>正在分析中，请稍候...</span>';

    // 获取选中的方向
    const dirRadio = document.querySelector('input[name="direction"]:checked');
    const direction = dirRadio ? dirRadio.value : 'auto';

    // 获取媒体类型
    const mediaRadio = document.querySelector('input[name="media-type"]:checked');
    const mediaType = mediaRadio ? mediaRadio.value : 'audio';

    try {
        const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionId,
                direction: direction,
                media_type: mediaType,
            }),
        });
        const data = await resp.json();

        if (data.error) {
            status.innerHTML = `<span class="text-danger">${data.error}</span>`;
            btn.disabled = false;
            return;
        }

        status.innerHTML = '<span class="text-success">✓ 分析完成</span>';
        showResults(data);

    } catch (err) {
        status.innerHTML = `<span class="text-danger">分析失败: ${err.message}</span>`;
        btn.disabled = false;
    }
}

    // ====== 结果展示 ======
    function showResults(data) {
    const section = document.getElementById('result-section');
    section.classList.remove('d-none');

    // 摘要
    const summary = data.summary;
    let summaryHtml = '<div class="row g-2">';
    summaryHtml += _summaryCard('FS 内部延迟', summary.fs_delay_mean.toFixed(1) + 'ms',
                                'P95: ' + summary.fs_delay_p95.toFixed(1) + 'ms', 'primary');
    summaryHtml += _summaryCard('抖动流数', summary.jitter_streams, '已分析', 'success');
    summaryHtml += _summaryCard('丢包状态',
                                summary.packet_loss_clean ? '✓ 无丢包' : '✗ 有丢包',
                                '', summary.packet_loss_clean ? 'success' : 'danger');
    summaryHtml += _summaryCard('综合评估',
                                summary.overall === 'healthy' ? '✓ 健康' :
                                summary.overall === 'warning' ? '⚠ 注意' : '✗ 异常',
                                '', summary.overall === 'healthy' ? 'success' :
                                summary.overall === 'warning' ? 'warning' : 'danger');
    summaryHtml += '</div>';
    document.getElementById('result-summary').innerHTML = summaryHtml;

    // 图表
    if (data.chart_url) {
        document.getElementById('result-chart').src = data.chart_url;
    }

    // 报告
    if (data.report && data.report.conclusion) {
        const c = data.report.conclusion;
        let reportHtml = `<div class="alert alert-${c.overall === 'healthy' ? 'success' : c.overall === 'warning' ? 'warning' : 'danger'}">`;
        reportHtml += `<strong>根因分析：</strong>${c.root_cause}</div>`;

        if (c.issues && c.issues.length > 0) {
            reportHtml += '<h6>发现的问题</h6><ul class="list-group mb-3">';
            c.issues.forEach(i => {
                const sev = i.severity === 'critical' ? 'danger' :
                           i.severity === 'warning' ? 'warning' : 'info';
                reportHtml += `<li class="list-group-item list-group-item-${sev}">${i.message}</li>`;
            });
            reportHtml += '</ul>';
        }

        if (c.ok_items && c.ok_items.length > 0) {
            reportHtml += '<h6>正常项</h6><ul class="list-group mb-3">';
            c.ok_items.forEach(item => {
                reportHtml += `<li class="list-group-item list-group-item-success">✓ ${item}</li>`;
            });
            reportHtml += '</ul>';
        }

        document.getElementById('result-report').innerHTML = reportHtml;
    }

    // 音视频回放
    showMedia(data.media_manifest);

    // 滚动到结果区域
    section.scrollIntoView({ behavior: 'smooth' });
}

// ====== 音视频回放展示 ======
const ROLE_NAMES = { seat: '坐席端', fs: 'FS 服务器端', terminal: '终端 / 主叫端' };
const ROLE_ICONS = { seat: 'bi-headset', fs: 'bi-server', terminal: 'bi-phone' };
const DIR_NAMES = { inbound: '呼入（接收）', outbound: '呼出（发送）', unknown: '方向未知' };
const DIR_BADGE = { inbound: 'bg-info', outbound: 'bg-success', unknown: 'bg-secondary' };

function showMedia(manifest) {
    const section = document.getElementById('media-section');
    const container = document.getElementById('media-container');

    if (!manifest || (!manifest.audio?.length && !manifest.video?.length && !manifest.unsupported?.length)) {
        section.classList.add('d-none');
        return;
    }
    section.classList.remove('d-none');

    // 按角色分组
    const byRole = {};

    (manifest.audio || []).forEach(e => {
        if (!byRole[e.role]) byRole[e.role] = { audio: [], video: [] };
        byRole[e.role].audio.push(e);
    });
    (manifest.video || []).forEach(e => {
        if (!byRole[e.role]) byRole[e.role] = { audio: [], video: [] };
        byRole[e.role].video.push(e);
    });

    let html = '';
    for (const [role, media] of Object.entries(byRole)) {
        const roleName = ROLE_NAMES[role] || role;
        const roleIcon = ROLE_ICONS[role] || 'bi-question-circle';
        html += `
            <div class="mb-4">
                <h6 class="mb-3">
                    <i class="bi ${roleIcon} text-primary"></i>
                    ${roleName}
                    <span class="badge bg-light text-dark">${media.audio.length + media.video.length} 个媒体流</span>
                </h6>`;

        // 音频
        media.audio.forEach(a => {
            html += _mediaItem(a, 'audio');
        });
        // 视频
        media.video.forEach(v => {
            html += _mediaItem(v, 'video');
        });
        html += '</div>';
    }

    // 不支持的编解码
    if (manifest.unsupported && manifest.unsupported.length > 0) {
        html += '<div class="alert alert-warning small mt-2"><strong>未能重建的流：</strong><ul class="mb-0">';
        manifest.unsupported.forEach(u => {
            html += `<li>${ROLE_NAMES[u.role] || u.role} (SSRC=${u.ssrc}) — ${u.codec}: ${u.reason}</li>`;
        });
        html += '</ul></div>';
    }

    container.innerHTML = html;
}

function _mediaItem(entry, kind) {
    const dirName = DIR_NAMES[entry.direction] || entry.direction;
    const dirBadge = DIR_BADGE[entry.direction] || 'bg-secondary';
    const dur = entry.duration_ms ? (entry.duration_ms / 1000).toFixed(1) + 's' : '';

    let meta = `<span class="badge ${dirBadge} me-1">${dirName}</span>
                <span class="badge bg-dark me-1">${entry.codec || ''}</span>
                <span class="text-muted small">SSRC: ${entry.ssrc}`;
    if (dur) meta += ` · 时长 ${dur}`;
    if (entry.total_packets) meta += ` · ${entry.total_packets} 包`;
    if (entry.lost_packets) meta += ` · 丢 ${entry.lost_packets} 包`;
    meta += '</span>';

    let player;
    if (kind === 'audio') {
        player = `<audio controls preload="none" class="w-100 mt-1">
                    <source src="${entry.url}" type="audio/wav">
                    您的浏览器不支持音频播放。
                  </audio>`;
    } else {
        player = `<video controls preload="metadata" class="w-100 mt-1" style="max-height: 300px;">
                    <source src="${entry.url}" type="${entry.mp4_available ? 'video/mp4' : 'video/h264'}">
                    您的浏览器不支持视频播放。
                  </video>`;
    }

    return `
        <div class="border rounded p-2 mb-2 bg-light">
            <div>${meta}</div>
            ${player}
            <a href="${entry.url}" download class="btn btn-sm btn-outline-secondary mt-1">
                <i class="bi bi-download"></i> 下载
            </a>
        </div>
    `;
}

function _summaryCard(title, value, subtitle, color) {
    return `
        <div class="col-6 col-md-3">
            <div class="card border-${color}">
                <div class="card-body text-center py-2">
                    <small class="text-muted">${title}</small>
                    <h4 class="text-${color} mb-0">${value}</h4>
                    ${subtitle ? `<small class="text-muted">${subtitle}</small>` : ''}
                </div>
            </div>
        </div>
    `;
}