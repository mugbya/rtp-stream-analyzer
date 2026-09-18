/**
 * RTP Stream Analyzer - 前端交互逻辑
 */

let sessionId = null;
let uploadedCount = 0;
let detectedCalls = [];
let detectedServerIp = null;
let ipRoleMap = {};  // ip -> 角色名（用于 SIP 流程里把 IP 显示为端点名）
// 抓包完整性警告（上传响应的 integrity_warning，null = 完整）。
// 点击"开始分析"时若存在则弹窗让用户确认：继续分析 / 放弃分析；
// 本会话内确认过一次后不再重复弹窗
let integrityWarning = null;
let integrityConfirmed = false;
let pendingCallIdOverride = null;   // 弹窗确认期间暂存的通话切换参数

// ====== 展示常量 ======
const ROLE_NAMES = { seat: '被叫端（坐席）', fs: '服务端（FS）', terminal: '主叫端（终端）' };

// 通话完整性状态：完整=绿 / 缺头/缺尾=黄 / 首尾都不完整=红
const CALL_STATUS = {
    complete:       { label: '完整',       badge: 'bg-success',        icon: 'bi-check-circle-fill' },
    truncated_head: { label: '缺开头',     badge: 'bg-warning text-dark', icon: 'bi-skip-start-fill' },
    truncated_tail: { label: '缺结尾',     badge: 'bg-warning text-dark', icon: 'bi-skip-end-fill' },
    truncated_both: { label: '首尾不完整', badge: 'bg-danger',         icon: 'bi-exclamation-triangle-fill' },
};

function callLabel(callId) {
    return (callId || '').replace('call_', '通话 ');
}

document.addEventListener('DOMContentLoaded', () => {
    setupFileUploads();
    setupAnalyzeButton();
    setupMediaTypeCards();
    setupDelayToggle();
});

// ====== 媒体类型卡片选中态 ======
// 卡片即 label 包住 radio，点击原生切换；这里只负责把选中样式同步到卡片边框
function setupMediaTypeCards() {
    const radios = document.querySelectorAll('input[name="media-type"]');
    radios.forEach(radio => {
        radio.addEventListener('change', () => {
            document.querySelectorAll('.media-type-option').forEach(o => o.classList.remove('selected'));
            radio.closest('.media-type-option').classList.add('selected');
        });
    });
}

// ====== 延迟开关与延迟方向联动 ======
// "延迟方向"只在分析延迟时有意义：取消勾选延迟测量（或单端抓包被禁用）时整列置灰
function setupDelayToggle() {
    const delayCheck = document.getElementById('check-delay');
    if (delayCheck) delayCheck.addEventListener('change', syncDirectionCol);
}

// 方向列可用的判定：延迟测量勾选且未被禁用。showConfigPanel 与手动切换共用
function syncDirectionCol() {
    const delayCheck = document.getElementById('check-delay');
    const dirCol = document.getElementById('direction-col');
    if (!delayCheck || !dirCol) return;
    dirCol.classList.toggle('opacity-50', !(delayCheck.checked && !delayCheck.disabled));
}

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
        detectedCalls = data.calls || [];
        // 新上传 = 新会话：记录完整性警告并重置确认状态（重新弹窗）
        integrityWarning = data.integrity_warning || null;
        integrityConfirmed = false;
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

    // IP → 角色映射（SIP 流程展示用）。
    // 只有各端自己的抓包能命名自己的 IP；FS 抓包里的非服务器 IP 既可能是坐席
    // 也可能是终端，保留原始 IP 显示。
    detectedServerIp = data.server_ip;
    ipRoleMap = {};
    const sortedFiles = (data.files || []).slice()
        .sort((a, b) => (a.role === 'fs' || a.role === 'FS' ? 1 : 0) - (b.role === 'fs' || b.role === 'FS' ? 1 : 0));
    sortedFiles.forEach(f => {
        const isFs = f.role === 'fs' || f.role === 'FS';
        (f.ips || []).forEach(ip => {
            if (ip === data.server_ip) return;
            if (isFs && ip in ipRoleMap) return;   // fs 只补没有名字的 IP
            ipRoleMap[ip] = isFs ? null : (ROLE_NAMES[f.role] || f.role);
        });
    });

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
    // 抓包完整性提醒（截短包/文件尾损坏）：像 Wireshark 一样提示但继续分析
    detail += _integrityWarningHtml(data.files);
    document.getElementById('streams-detail').innerHTML = detail;

    // 通话列表 + 完整性状态 + 跨抓包一致性提醒
    renderCalls(data.calls || [], data.capture_warning, data.files);
}

// ====== 通话检测展示 ======
// FS 参与编解码判定的卡片徽章（后端 fs_media.verdict）：bypass 已由「点对点
// 直连」徽章表达，unknown 数据不足不给徽章（阶梯图里有灰字说明）
const FS_MEDIA_BADGES = {
    transcode: '<span class="badge bg-danger"><i class="bi bi-shuffle"></i> 服务端转码（FS）</span>',
    same: '<span class="badge bg-success"><i class="bi bi-check2-circle"></i> 服务端未转码</span>',
};

// FS 媒体转发检测（后端 fs_relay.verdict）：结论样式与提示块配色。
// redirected = FS 用 SDP 透传把媒体改道成端到端直连；no_relay = 两端都没往
// FS 发媒体；partial_uplink = 一部分发了另一部分没发（才考虑网络问题）
const FS_RELAY_META = {
    redirected:     {alert: 'alert-danger',   badge: 'bg-danger',
                     icon: 'bi-signpost-split', label: '媒体已改道直连'},
    no_relay:       {alert: 'alert-danger',   badge: 'bg-danger',
                     icon: 'bi-x-octagon-fill', label: '未经过服务端中转'},
    partial_uplink: {alert: 'alert-warning',  badge: 'bg-warning text-dark',
                     icon: 'bi-exclamation-triangle-fill', label: '部分上行缺失'},
    relayed:        {alert: 'alert-success',  badge: 'bg-success',
                     icon: 'bi-check-circle-fill', label: '服务端正常转发（FS）'},
    insufficient:   {alert: 'alert-secondary', badge: 'bg-secondary',
                     icon: 'bi-question-circle', label: '无法判断'},
};

// FS 媒体转发提示块：结论一句话 + 各端与 FS 之间的上下行实测表 + 改道/
// 佐证明细 + 按优先级的排查建议（先中转配置、后网络）
function _fsRelayHtml(r) {
    if (!r || r.available === false) return '';
    const meta = FS_RELAY_META[r.verdict] || FS_RELAY_META.insufficient;
    let html = `<div class="alert ${meta.alert} w-100 mb-2 py-2 small">` +
        `<strong><i class="bi ${meta.icon} me-1"></i>FS 媒体转发检测：${meta.label}</strong>` +
        `<div class="mt-1">${_esc(r.headline || '')}</div>`;
    const devs = r.devices || [];
    if (devs.length) {
        html += '<div class="table-responsive mt-1"><table class="table table-sm table-bordered mb-1 bg-white">' +
            '<thead><tr><th>端点</th><th>上行 → FS 音频</th><th>上行 → FS 视频</th>' +
            '<th>FS 下行 → 音频</th><th>FS 下行 → 视频</th></tr></thead><tbody>';
        const cell = v => (!v || !v.pkts)
            ? '<span class="text-muted">0 包</span>'
            : `${v.pkts} 包<span class="text-muted">${v.span_s ? `（${v.span_s}s）` : ''}</span>`;
        devs.forEach(d => {
            html += `<tr><td><strong>${_esc(d.label || d.ip)}</strong></td>` +
                `<td>${cell(d.uplink?.audio)}</td><td>${cell(d.uplink?.video)}</td>` +
                `<td>${cell(d.downlink?.audio)}</td><td>${cell(d.downlink?.video)}</td></tr>`;
        });
        html += '</tbody></table></div>';
    }
    const lists = (r.redirects || []).map(x =>
        `<li>${_esc(x.time_str)} ${_esc(x.label || '')}：向 ${_esc(x.dst || '')} 宣告了 ${_esc(x.targets || '')} 的媒体地址</li>`)
        .concat((r.notes || []).map(n => `<li>${_esc(n)}</li>`));
    if (lists.length) html += `<ul class="mb-1 ps-3">${lists.join('')}</ul>`;
    if (r.advice) html += `<div class="mt-1"><strong>排查建议：</strong>${_esc(r.advice)}</div>`;
    return html + '</div>';
}

// 折叠标题里的协商编码摘要：优先按腿展示（主叫 … / 被叫 …），与阶梯图的
// 两行协商行、FS 转码判定一一对应；旧会话数据没有 per-leg 字段时回退为
// 单份 negotiated_codecs（主叫腿汇总）
function _legNegotiationSummary(c) {
    const fmt = leg => ['audio', 'video'].map(k =>
        leg[k]?.length ? `${k === 'audio' ? '音频' : '视频'} ${leg[k].join('/')}` : ''
    ).filter(Boolean).join('，');
    const npl = c.negotiated_per_leg || {};
    const parts = [];
    for (const [role, name] of [['caller', '主叫'], ['callee', '被叫']]) {
        if (!npl[role]) continue;
        const t = fmt(npl[role]);
        if (t) parts.push(`${name} ${t}`);
    }
    if (parts.length) return parts.join(' / ');
    const t = fmt(c.negotiated_codecs || {});
    return t ? `协商 ${t}` : '';
}

// 通话来源标注：这通通话出现在哪些上传抓包里。全部上传抓包都包含 → 绿色
// 说明“N 份抓包均有”；缺了抓包 → 黄色警示；只出现在一份抓包 → 红色醒目
// （其余抓包点没有这通电话的媒体流：可能是抓包时段不重叠，也可能是点对点
// 直连绕过了服务端）。uploads 为上传响应里的文件列表（元素带 role）
function _callSourceBadges(c, uploads) {
    const roles = (uploads || []).map(f => f.role);
    const present = (c.files || []).map(f => ROLE_NAMES[f] || f);
    if (roles.length < 2) {
        return present.length
            ? `<span class="text-muted small">来源：${present.join(' / ')}</span>` : '';
    }
    const missing = (c.files_missing
        || roles.filter(r => !(c.files || []).includes(r)))
        .map(r => ROLE_NAMES[r] || r);
    if (!missing.length) {
        return `<span class="badge bg-success-subtle text-success-emphasis" ` +
            `title="这通通话的媒体流在上传的全部 ${roles.length} 份抓包里都出现了">` +
            `<i class="bi bi-check2-all"></i> ${roles.length} 份抓包均有（${present.join('、')}）</span>`;
    }
    if (present.length === 1) {
        const p2pNote = c.is_p2p
            ? `；该通话媒体为端到端直连，不经服务端，其余抓包没有它属正常现象`
            : '';
        return `<span class="badge bg-danger" title="这通通话只在上传的 1 份抓包里出现，` +
            `其余 ${missing.length} 份（${missing.join('、')}）没有它的媒体流——` +
            `可能是抓包时段与这通电话不重叠，或媒体/信令没有经过那些抓包点${p2pNote}">` +
            `<i class="bi bi-exclamation-triangle"></i> 仅见于 ${present[0]}</span>`;
    }
    return `<span class="badge bg-warning text-dark" title="这通通话只在 ` +
        `${present.join('、')}的抓包里出现，${missing.join('、')}的抓包里没有">` +
        `<i class="bi bi-files"></i> 见于 ${present.join('、')}</span>`;
}

function renderCalls(calls, captureWarning, uploads) {
    const container = document.getElementById('calls-detail');

    if (!calls.length) {
        container.innerHTML = (captureWarning ? _captureWarningHtml(captureWarning) : '') +
            '<p class="text-muted small mb-0 mt-2">' +
            '未检测到通话（抓包中没有 RTP 媒体流）</p>';
        return;
    }

    let html = `<h6 class="mt-3 mb-2">
        <i class="bi bi-telephone text-primary"></i>
        检测到 <span class="badge bg-primary fs-6">${calls.length}</span> 通通话
    </h6>`;
    if (captureWarning) html = _captureWarningHtml(captureWarning) + html;

    calls.forEach(c => {
        const st = CALL_STATUS[c.completeness.status] || CALL_STATUS.complete;
        const media = c.media_types.map(m => m === 'audio' ? '音频' : '视频').join('+') || '未知';
        const relay = c.fs_relay;
        const relayMeta = relay && FS_RELAY_META[relay.verdict];
        const relayBadge = relayMeta && relay.verdict !== 'insufficient'
            ? `<span class="badge ${relayMeta.badge}"><i class="bi ${relayMeta.icon}"></i> ${relayMeta.label}</span>`
            : '';

        let reasons = '';
        for (const [role, pf] of Object.entries(c.completeness.per_file || {})) {
            const pst = CALL_STATUS[pf.status] || CALL_STATUS.complete;
            reasons += `<div class="mb-1">
                <strong>${ROLE_NAMES[role] || role}</strong>
                <span class="badge ${pst.badge}">${pst.label}</span>
                <ul class="mb-0 text-muted ps-3">
                    ${(pf.reasons || []).map(r => `<li>${r}</li>`).join('')}
                </ul>
            </div>`;
        }

        const flow = c.sip_flow || [];
        let flowHtml = '';
        if (flow.length) {
            const msgCount = _sipParties(flow).msgs.length;
            // 摘要行给出两腿各自协商的编码与 FS 媒体处理判定，不用展开
            const negTxt = _legNegotiationSummary(c);
            const fmShort = {transcode: 'FS 转码', same: 'FS 未转码',
                             bypass: '媒体不经 FS'}[c.fs_media?.verdict] || '';
            flowHtml = `<details class="mt-1">
                <summary class="text-muted small" style="cursor:pointer">
                    SIP 信令流程（${msgCount} 条消息${negTxt ? ` · ${negTxt}` : ''}${fmShort ? ` · ${fmShort}` : ''}）
                </summary>
                <div class="mt-2 p-2 border rounded bg-white">
                    <div class="sip-flow">${_sipLadder(flow, c)}</div>
                </div>
            </details>`;
        }

        html += `
        <div class="border rounded p-2 mb-2 bg-light">
            <div class="d-flex flex-wrap align-items-center gap-2">
                <strong>${callLabel(c.call_id)}</strong>
                <span class="text-muted small">${c.start_str} ~ ${c.end_str}（${c.duration_s}s）</span>
                <span class="badge ${st.badge}"><i class="bi ${st.icon}"></i> ${st.label}</span>
                ${c.is_p2p ? '<span class="badge bg-info text-dark"><i class="bi bi-arrow-left-right"></i> 点对点直连</span>' : ''}
                ${FS_MEDIA_BADGES[c.fs_media?.verdict] || ''}
                ${relayBadge}
                <span class="badge bg-light text-dark">${c.stream_count} 条流</span>
                <span class="badge bg-light text-dark">${media}</span>
                ${_callSourceBadges(c, uploads)}
                ${_callPartyChain(flow)}
            </div>
            ${_fsRelayHtml(relay)}
            ${flowHtml}
            ${reasons ? `<details class="mt-1">
                <summary class="text-muted small" style="cursor:pointer">完整性判断依据</summary>
                <div class="mt-1">${reasons}</div>
            </details>` : ''}
        </div>`;
    });

    container.innerHTML = html;
}

// ====== SIP 信令流程展示 ======
function _ipName(ip) {
    return ipRoleMap[ip] || ip;
}

const SIP_KIND_CLASS = { request: 'sip-req', provisional: 'sip-prov', success: 'sip-ok', error: 'sip-err' };

// 时序阶梯图：只保留「谁打给谁」—— 经服务器为左(主叫)/中(FS)/右(被叫)三列，
// 点对点为左右两列；并发振铃的分叉目标等其他参与方及其消息不展示。
// From/To 显示名/分机号是抓包里的自由文本，插入 innerHTML 前需转义
function _esc(s) {
    return String(s).replace(/[&<>"']/g,
        c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// 每列设备 IP 的 SIP 身份（分机号/显示名）：
// - 主叫：主叫自己发出的第一个请求的 From（UAC 自报身份）。
// - 被叫：呼向被叫的 INVITE 的 To（被叫分机号）。不能用被叫响应里的 From——
//   RFC 3261 要求响应回显请求的 From，那只是主叫身份的副本。
function _sipIdents(msgs, caller, answerer) {
    const idents = {};
    const usable = h => h && (h.user || h.name);
    if (caller) {
        const m = msgs.find(m => m.src === caller && usable(m.from));
        if (m) idents[caller] = m.from;
    }
    if (answerer) {
        const m = msgs.find(m => m.dst === answerer && m.method === 'INVITE' && usable(m.to)) ||
                  msgs.find(m => m.dst === answerer && usable(m.to));
        if (m) idents[answerer] = m.to;
    }
    return idents;
}

// SIP 身份按抓包原文展示，不做 base64 解码——平台分机号本身可能就是这种
// 串（"LTE2Nzcx..."），解码反而得到错误内容
function _identLabel(id) {
    if (!id) return '';
    if (id.name && id.user && id.name !== id.user && !id.name.includes(id.user))
        return `${id.name}（${id.user}）`;
    return id.name || id.user || '';
}

function _sipParties(flow) {
    const ips = [flow[0].src];
    flow.forEach(m => {
        if (!ips.includes(m.src)) ips.push(m.src);
        if (!ips.includes(m.dst)) ips.push(m.dst);
    });
    const server = detectedServerIp && ips.includes(detectedServerIp) ? detectedServerIp : null;
    // 主叫：第一个非服务器侧发出的 INVITE；被叫：INVITE 事务 200 OK 的非服务器发送方
    // （用 CSeq 方法判断归属，排除 CANCEL/BYE 的 200 Ok 干扰）
    const inv = flow.find(m => m.method === 'INVITE' && m.src !== server) ||
                flow.find(m => m.kind === 'request') || flow[0];
    const caller = inv.src;
    const ok = flow.find(m => m.method === '200' && m.cseq_method === 'INVITE' && m.src !== server);
    let answerer = ok ? ok.src : null;
    // 未接通的通话（CANCEL/486/480/487 收场）没有 INVITE 的 200 OK：被叫退而
    // 取信令里出现最多的非服务器对端（正常就是被叫设备），保证被叫腿不会从
    // 阶梯图整列消失
    if (!answerer) {
        const peers = {};
        flow.forEach(m => [m.src, m.dst].forEach(ip => {
            if (ip && ip !== server && ip !== caller) peers[ip] = (peers[ip] || 0) + 1;
        }));
        const ranked = Object.entries(peers).sort((a, b) => b[1] - a[1]);
        answerer = ranked.length ? ranked[0][0]
            : (inv.dst !== server && inv.dst !== caller ? inv.dst : null);
    }

    const cols = [caller];
    if (server && server !== caller) cols.push(server);
    if (answerer && !cols.includes(answerer)) cols.push(answerer);
    let msgs = flow.filter(m => cols.includes(m.src) && cols.includes(m.dst));
    if (!msgs.length) msgs = flow;   // 兜底：判定失败时不过滤
    return { cols, server, caller, answerer, msgs };
}

// SDP 消息的线上小标记：INVITE 行标「支持」（主叫/re-INVITE 报的支持列表），
// 带 SDP 的 1xx（如 183 早释）标「早期应答」（先建早媒体的那次应答），200 OK
// 标「最终应答」（正式接通的应答）——一条腿两次应答是正常流程，标签区分开
// 免得误读为重复；ACK 等 SDP 仍标「应答」（慢启动时 200 OK 带 offer、ACK 里
// 才是 answer）。完整编码列表由 _sdpListRow 在该消息行下方独立成行展示，
// 不受信令线跨度裁剪；FS 自产 INVITE 的 SDP 用静态 PT 无 rtpmap、解析不出
// 编码名，标记与列表都不显示
function _sdpTag(m) {
    if (m.method === 'INVITE') return '支持';
    if (m.kind === 'provisional') return '早期应答';
    if (m.kind === 'success') return '最终应答';
    return '应答';
}

function _sdpTags(m) {
    const sc = m.sdp_codecs;
    if (!sc || !(sc.audio?.length || sc.video?.length)) return '';
    return `<span class="sl-sdp" title="下方独立行列出该消息 SDP 的完整编码列表">` +
        `<i class="bi bi-file-earmark-code"></i> ${_sdpTag(m)}</span>`;
}

// FS 把对端媒体地址透传给本端的消息行标注（媒体改道直连的证据行）
function _redirectTag(m) {
    if (!m.media_redirect) return '';
    return `<span class="sl-sdp" title="FS 在此消息里把对端的媒体地址透传给了本端——媒体改道为端到端直连，不再经过 FS">` +
        `<i class="bi bi-signpost-split"></i> 媒体改道</span>`;
}

// SDP 完整编码列表行：挂在消息行下方独立成行，可完整换行
function _sdpListRow(m) {
    const sc = m.sdp_codecs;
    if (!sc || !(sc.audio?.length || sc.video?.length)) return '';
    const parts = [];
    if (sc.audio?.length) parts.push(`音频 ${sc.audio.join(' / ')}`);
    if (sc.video?.length) parts.push(`视频 ${sc.video.join(' / ')}`);
    return `<div class="sl-sdplist"><span class="sl-sdp">` +
        `<i class="bi bi-file-earmark-code"></i> ${_sdpTag(m)}</span> ${parts.join('，')}</div>`;
}

function _sipLadder(flow, call) {
    if (!flow || !flow.length) return '';
    const { cols, server, caller, answerer, msgs } = _sipParties(flow);
    const idents = _sipIdents(msgs, caller, answerer);
    const n = cols.length;
    const colOf = ip => Math.max(0, cols.indexOf(ip));
    const pct = v => (v * 100).toFixed(3) + '%';

    let html = `<div class="sl-head"><span class="sl-gutter"></span>` +
        `<div class="sl-track" style="grid-template-columns:repeat(${n},1fr)">`;
    cols.forEach(ip => {
        let name, ipSub = '';
        if (ip === server) {
            name = 'FS 服务器';
            ipSub = ip;
        } else {
            const label = _esc(_identLabel(idents[ip]));
            name = label || _ipName(ip);
            if (name !== ip) ipSub = ip;   // 有身份名时，IP 缩进副行保留
        }
        // FS 自己发 INVITE 的外呼腿（服务端只抓到 FS→被叫的半边时必然如此）：
        // From 头是 FS 转报的原始主叫身份，主叫端点不在抓包里，挂注在 FS 列展示
        let relay = '';
        if (ip === server && caller === server && idents[ip]) {
            const lbl = _identLabel(idents[ip]);
            if (lbl) relay = lbl;
        }
        const badge = ip === caller ? '<span class="sl-role bg-primary text-white">主叫</span>'
            : ip === answerer ? '<span class="sl-role bg-success text-white">被叫</span>' : '';
        html += `<div class="sl-p"><div class="sl-name"${ipSub ? ` title="${name}"` : ''}>${name}</div>` +
            (ipSub ? `<div class="sl-ip">${ipSub}</div>` : '') +
            (relay ? `<div class="sl-ip" title="${_esc(relay)}">主叫(转报): ${_esc(relay)}</div>` : '') +
            badge + `</div>`;
    });
    html += `</div></div><div class="sl-body"><div class="sl-lines">`;
    cols.forEach((ip, i) => {
        html += `<i class="sl-line" style="left:${pct((i + 0.5) / n)}"></i>`;
    });
    html += `</div>`;
    // RTP 部分：编码标签 + 媒体开始/结束标线，按媒体时间插入消息时间线——
    // 两条标线成对落在首条 BYE 行之前（开始线在上、结束线在下）。time_str
    // 是定宽 HH:MM:SS，可直接比较。
    // 带 SDP 编码的消息在行下追加一条独立列表行；rowBefore/rowAfter 记录
    // 每条消息的行区间，供标线/协商行按消息下标锚定。
    const rows = [];
    const rowBefore = {}, rowAfter = {};
    msgs.forEach((m, i) => {
        const a = colOf(m.src), b = colOf(m.dst);
        const kindCls = SIP_KIND_CLASS[m.kind] || '';
        let inner;
        if (a === b) {
            inner = `<div class="sl-msg ${kindCls} sl-self" style="left:${pct((a + 0.5) / n)}">` +
                `<span class="lb">${m.label}${_sdpTags(m)}${_redirectTag(m)}</span></div>`;
        } else {
            const lo = Math.min(a, b), hi = Math.max(a, b);
            const lSeg = a < b ? '<i class="ln"></i>' : '<i class="ln arr-l"></i>';
            const rSeg = a < b ? '<i class="ln arr-r"></i>' : '<i class="ln"></i>';
            inner = `<div class="sl-msg ${kindCls}" ` +
                `style="left:${pct((lo + 0.5) / n)};width:${pct((hi - lo) / n)}">` +
                `${lSeg}<span class="lb">${m.label}${_sdpTags(m)}${_redirectTag(m)}</span>${rSeg}</div>`;
        }
        rowBefore[i] = rows.length;
        rows.push(`<div class="sl-row"><span class="sl-t">${m.time_str}</span>` +
            `<div class="sl-track" style="grid-template-columns:repeat(${n},1fr)">${inner}</div></div>`);
        const list = _sdpListRow(m);
        if (list) rows.push(list);
        rowAfter[i] = rows.length;
    });
    if (call) {
        // 标线成对放在首条 BYE 行之前：开始线在上、结束线在下，媒体区间作为
        // 挂断前的整体标注展示。RTP 首末包时间（talk_*，无信令时后端回退为
        // 整段媒体）只用于标签显示。不按应答 200 OK 给开始线单独锚位——缺头
        // 通话抓到的应答是中途 re-INVITE，开始线会被锚到图中间 100 之前
        const sStr = call.talk_start_str || call.start_str;
        const eStr = call.talk_end_str || call.end_str;
        const dur = call.talk_duration_s ?? call.duration_s;
        const codecs = call.codecs || {};
        const chips = [];
        if (codecs.audio?.length)
            chips.push(`<span class="badge text-bg-light border"><i class="bi bi-music-note-beamed"></i> 音频 ${codecs.audio.join(' / ')}</span>`);
        if (codecs.video?.length)
            chips.push(`<span class="badge text-bg-light border"><i class="bi bi-camera-video"></i> 视频 ${codecs.video.join(' / ')}</span>`);
        // 结束位置：首条 BYE 行之前；无 BYE 再按媒体结束时间插
        let ek = msgs.findIndex(m => m.method === 'BYE');
        if (ek === -1)
            ek = eStr ? msgs.findIndex(m => m.time_str >= eStr) : -1;
        // 两条标线同一行位（ei），先插结束线再插开始线 → 开始线在上
        let ei = ek === -1 ? rows.length : rowBefore[ek];
        let si = ei;
        if (eStr)
            rows.splice(ei, 0, `<div class="sl-marker sl-end"><span class="lb">` +
                `<i class="bi bi-stop-fill"></i> RTP 媒体结束 ${eStr}（持续 ${dur}s）</span></div>`);
        if (sStr)
            rows.splice(si, 0, `<div class="sl-marker sl-start"><span class="lb">` +
                `<i class="bi bi-play-fill"></i> RTP 媒体开始 ${sStr}</span></div>`);
        if (chips.length)
            rows.splice(si + 1, 0, `<div class="sl-codecs">${chips.join('')}</div>`);
        // 两腿协商编码（后端按 Call-ID 配对好）：主叫侧、被叫侧各一行，先
        // 摆出每条腿各定了什么编码，再接下面的 FS 转码判定行——判定本身就是
        // 对比这两行，展示顺序与判定依据一致。旧会话数据没有 per-leg 字段时
        // 回退为单行主叫腿汇总。
        // 只认带编码名的 SDP 行：FS 自产 INVITE 的 SDP（无 rtpmap）在
        // 后端配对时已被跳过，这里保持一致，协商行锚在其正主应答行
        // （含列表子行）之后
        // 只认带编码名的 SDP 行：FS 自产 INVITE 的 SDP（无 rtpmap）在
        // 后端配对时已被跳过，这里保持一致。同时按腿（call_id）记住每条腿
        // 最后一条 SDP 行的行号——该腿的协商行锚在这行（= 该腿应答行）之后，
        // 即协商完成的时刻，不早于该腿的应答出现在图上
        const sdpRows = [];
        const legAnchors = {};
        msgs.forEach((m, i) => {
            if (m.sdp_codecs &&
                (m.sdp_codecs.audio?.length || m.sdp_codecs.video?.length)) {
                sdpRows.push(rowAfter[i]);
                if (m.call_id) legAnchors[m.call_id] = rowAfter[i];
            }
        });
        // 旧会话数据（协商行无 call_id）的兜底锚点：第二条 SDP 行之后
        let ni = sdpRows.length >= 2 ? sdpRows[1]
               : sdpRows.length === 1 ? sdpRows[0] : si;
        ni = Math.min(ni, si);
        const fmtLegChips = leg => {
            const chips = [];
            if (leg.audio?.length)
                chips.push(`<span class="badge text-bg-light border"><i class="bi bi-music-note-beamed"></i> 音频 ${leg.audio.join(' / ')}</span>`);
            if (leg.video?.length)
                chips.push(`<span class="badge text-bg-light border"><i class="bi bi-camera-video"></i> 视频 ${leg.video.join(' / ')}</span>`);
            return chips;
        };
        // 待插入行列表 {anchor, prio, html}：统一按锚点从大到小 splice（大
        // 锚点先插不会影响更小的锚点位置）。同锚点时 prio 大的先插、最终排
        // 在后面——判定行因此排在同位置的协商行之后
        const inserts = [];
        const npl = call.negotiated_per_leg || {};
        [['caller', '主叫', 'bi-telephone-outbound'],
         ['callee', '被叫', 'bi-telephone-inbound']].forEach(([key, name, icon]) => {
            const leg = npl[key];
            if (!leg) return;
            const chips = fmtLegChips(leg);
            if (!chips.length) return;
            const label = leg.answered === false
                ? `${name}候选编码（未收到应答）` : `${name}侧协商`;
            const anchor = (leg.call_id && legAnchors[leg.call_id] != null)
                ? Math.min(legAnchors[leg.call_id], si) : ni;
            inserts.push({anchor, prio: 0, html:
                `<span class="text-muted small me-1"><i class="bi ${icon}"></i> ${label}</span>${chips.join('')}`});
        });
        if (!inserts.length) {
            const chips = fmtLegChips(call.negotiated_codecs || {});
            if (chips.length) {
                const negLabel = call.sdp_answered === false
                    ? '主叫候选编码（未收到应答）' : '协商编码';
                inserts.push({anchor: ni, prio: 0, html:
                    `<span class="text-muted small me-1"><i class="bi bi-handshake"></i> ${negLabel}</span>${chips.join('')}`});
            }
        }
        // FS 是否参与编解码（后端对比两腿协商编码 + 媒体路径判定）：固定在
        // RTP 媒体开始标线之前——两腿协商全部结束、呼叫接通之后才有结论，
        // 转码结论着色强调；unknown 也如实展示（灰字）
        const fm = call.fs_media;
        if (fm && fm.verdict) {
            const meta = {
                transcode: {cls: 'bg-danger', label: 'FS 参与转码'},
                same: {cls: 'bg-success', label: 'FS 未转码'},
                bypass: {cls: 'bg-info text-dark', label: '媒体不经 FS'},
                unknown: {cls: 'bg-light text-dark', label: '无法判定'},
            }[fm.verdict] || {cls: 'bg-light text-dark', label: 'FS 媒体处理'};
            inserts.push({anchor: si, prio: 1, html:
                `<span class="badge ${meta.cls} me-1"><i class="bi bi-cpu"></i> ${meta.label}</span>` +
                `<span class="small${fm.verdict === 'unknown' ? ' text-muted' : ''}">${_esc(fm.text || '')}</span>`});
        }
        inserts.sort((a, b) => (b.anchor - a.anchor) || ((b.prio || 0) - (a.prio || 0)));
        for (const it of inserts)
            rows.splice(it.anchor, 0, `<div class="sl-codecs">${it.html}</div>`);
    }
    return html + rows.join('') + `</div>`;
}

// 卡片头部的「谁打给谁」摘要：主叫 → （FS）→ 被叫，身份与阶梯图列头一致
function _callPartyChain(flow) {
    if (!flow || !flow.length) return '';
    const { server, caller, answerer, msgs } = _sipParties(flow);
    const idents = _sipIdents(msgs, caller, answerer);
    const seg = (badge, badgeCls, ip, id) => {
        const name = _esc(_identLabel(id) || _ipName(ip));
        return `<span class="badge ${badgeCls}">${badge}</span>` +
            `<span class="text-truncate d-inline-block align-bottom" style="max-width:380px" title="${name}">${name}</span>` +
            `<span class="text-muted">${ip}</span>`;
    };
    const arrow = '<i class="bi bi-arrow-right text-muted"></i>';
    let html = seg('主叫', 'bg-primary', caller, idents[caller]);
    if (server) html += arrow + '<span class="badge bg-dark">FS</span>';
    if (answerer) html += arrow + seg('被叫', 'bg-success', answerer, idents[answerer]);
    return `<span class="d-inline-flex align-items-center gap-1 flex-wrap small">${html}</span>`;
}

// ====== 分析配置面板 ======
function showConfigPanel(data) {
    const section = document.getElementById('config-section');
    section.classList.remove('d-none');

    // 延迟可测性：需要 ≥2 个抓包点（跨抓包传输延迟）或含 FS 抓包（FS 内部延迟）。
    // 单端抓包测不了延迟，自动禁用"延迟测量"；抖动/丢包与音画质量不受影响。
    const files = data.files || [];
    const delayAvailable = files.length >= 2 ||
        files.some(f => (f.role || '').toLowerCase() === 'fs');
    const delayCheck = document.getElementById('check-delay');
    const delayHint = document.getElementById('check-delay-hint');
    if (delayCheck) {
        delayCheck.disabled = !delayAvailable;
        delayCheck.checked = delayAvailable;
        if (delayHint) {
            delayHint.classList.toggle('d-none', delayAvailable);
            delayHint.textContent = delayAvailable
                ? '' : '仅单端抓包无法测量延迟（需 ≥2 个抓包点或含 FS 抓包），已自动禁用；抖动/丢包与音画质量仍可分析';
        }
        syncDirectionCol();
    }

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

    // 通话选择（多通通话时显示）
    renderCallSelector(data.calls || [], data.capture_warning);
}

// 抓包完整性提醒（截短包/文件尾损坏）：像 Wireshark 的提示——只告知数据
// 受限，不阻断分析。files 来自上传响应/会话接口，元素带 integrity 字段
function _integrityWarningHtml(files) {
    const rows = (files || []).filter(f => f.integrity && f.integrity.status === 'warn')
        .map(f => `<li><strong>${ROLE_NAMES[f.role] || f.role}</strong>（${_esc(f.filename)}）：` +
            `<ul class="list-unstyled mb-0 ms-3 text-muted">${(f.integrity.notes || [])
                .map(n => `<li>${_esc(n)}</li>`).join('')}</ul></li>`);
    if (!rows.length) return '';
    return `<div class="alert alert-warning w-100 mb-2 py-2 small mt-2">
        <strong><i class="bi bi-crop me-1"></i>抓包可能不完整（已按现有数据继续分析）</strong>
        <ul class="mb-1 mt-2 ps-3">${rows.join('')}</ul>
        <div class="text-muted">截短的包缺失部分载荷，可能影响媒体重建与统计精度；建议确认抓包快照长度，必要时重新抓包或重新导出文件。</div>
    </div>`;
}

// 抓包不完整确认弹窗：点击"开始分析"时拦截，让用户明确选择继续分析或
// 放弃。确认过一次后本会话内不再重复弹窗（被动横幅仍保留作说明）
function showIntegrityConfirmModal() {
    let el = document.getElementById('integrity-confirm-modal');
    if (!el) {
        el = document.createElement('div');
        el.className = 'modal fade';
        el.id = 'integrity-confirm-modal';
        el.tabIndex = -1;
        el.setAttribute('aria-hidden', 'true');
        el.innerHTML = `
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="bi bi-exclamation-triangle text-warning me-1"></i>抓包可能不完整
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="关闭"></button>
                    </div>
                    <div class="modal-body small">
                        <ul id="integrity-confirm-files" class="mb-2 ps-3"></ul>
                        <div class="text-muted">截短的包缺失部分载荷，可能影响媒体重建与统计精度；建议确认抓包快照长度，必要时重新抓包或重新导出文件。</div>
                        <div class="mt-2 fw-bold">是否仍要继续分析？</div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">
                            <i class="bi bi-x-circle me-1"></i>放弃分析
                        </button>
                        <button type="button" class="btn btn-warning" id="integrity-confirm-go">
                            <i class="bi bi-play-circle me-1"></i>继续分析
                        </button>
                    </div>
                </div>
            </div>`;
        document.body.appendChild(el);
        el.querySelector('#integrity-confirm-go').addEventListener('click', () => {
            integrityConfirmed = true;
            const override = pendingCallIdOverride;
            pendingCallIdOverride = null;
            bootstrap.Modal.getOrCreateInstance(el).hide();
            runAnalysis(override);
        });
    }
    // 填充逐文件明细（integrity_warning.files: {role, filename, notes}）
    const files = (integrityWarning && integrityWarning.files) || [];
    el.querySelector('#integrity-confirm-files').innerHTML = files.map(f =>
        `<li class="mb-1"><strong>${ROLE_NAMES[f.role] || f.role}</strong>（${_esc(f.filename)}）：` +
        `<ul class="list-unstyled ms-3 text-muted mb-0">${(f.notes || [])
            .map(n => `<li>${_esc(n)}</li>`).join('')}</ul></li>`).join('');
    if (window.bootstrap && window.bootstrap.Modal) {
        bootstrap.Modal.getOrCreateInstance(el).show();
    } else {
        // Bootstrap JS 不可用时的兜底：原生确认框
        if (window.confirm('抓包可能不完整，是否仍要继续分析？（确定=继续，取消=放弃）')) {
            integrityConfirmed = true;
            const override = pendingCallIdOverride;
            pendingCallIdOverride = null;
            runAnalysis(override);
        }
    }
}

// 跨抓包一致性提醒——纵向列表：每份抓包一行，先给总体时间段，再缩进列出
// 每通通话的时间段。kind='p2p'（点对点直连）不是错误，用 info 样式区分于
// kind='mismatch'（疑似传错文件）的警告样式
function _captureWarningHtml(w) {
    const rows = (w.roles || []).map(r => {
        const ov = r.overall || {};
        const head = ov.count
            ? `${r.display}：${ov.start} ~ ${ov.end}（${ov.count} 通）`
            : `${r.display}：未检测到通话`;
        const subs = (r.calls || []).map(c =>
            `<li class="ms-4 text-muted">└ ${c.label}：${c.start} ~ ${c.end}</li>`).join('');
        return `<li>${head}${subs ? `<ul class="list-unstyled mb-0">${subs}</ul>` : ''}</li>`;
    }).join('');
    const p2p = w.kind === 'p2p';
    const cls = p2p ? 'alert-info' : 'alert-warning';
    const icon = p2p ? 'bi-info-circle' : 'bi-exclamation-triangle';
    const title = p2p ? '点对点直连提示' : '抓包一致性提醒';
    return `<div class="alert ${cls} w-100 mb-2 py-2 small">
        <strong><i class="bi ${icon} me-1"></i>${title}</strong>
        <div class="mt-1">${w.message}</div>
        <ul class="list-unstyled mb-0 mt-2">${rows}</ul>
    </div>`;
}

// ====== 通话选择器 ======
function renderCallSelector(calls, captureWarning) {
    const section = document.getElementById('call-select-section');
    const container = document.getElementById('call-options');

    if (calls.length <= 1) {
        section.classList.add('d-none');
        return;
    }
    section.classList.remove('d-none');

    // 默认选覆盖抓包最多的一通（多端共有的通话最可能是想分析的），其次完整的
    let defaultIdx = 0, bestScore = -1;
    calls.forEach((c, idx) => {
        const score = c.files.length * 2 + (c.completeness.status === 'complete' ? 1 : 0);
        if (score > bestScore) { bestScore = score; defaultIdx = idx; }
    });

    let html = captureWarning ? _captureWarningHtml(captureWarning) : '';
    calls.forEach((c, idx) => {
        const st = CALL_STATUS[c.completeness.status] || CALL_STATUS.complete;
        const checked = idx === defaultIdx ? 'checked' : '';
        const p2pBadge = c.is_p2p
            ? ' <span class="badge bg-info text-dark"><i class="bi bi-arrow-left-right"></i> 点对点直连</span>' : '';
        const fmBadge = FS_MEDIA_BADGES[c.fs_media?.verdict] || '';
        html += `
            <label class="direction-option">
                <input type="radio" name="call-select" value="${c.call_id}" ${checked} style="display:none">
                ${callLabel(c.call_id)} ${c.start_str}~${c.end_str}（${c.duration_s}s）${p2pBadge}${fmBadge}
                <span class="badge ${st.badge}">${st.label}</span>
            </label>`;
    });
    // 抓包之间没有共同通话时，混合分析会把不同通话搅在一起，直接不给选
    if (!captureWarning) {
        html += `
            <label class="direction-option">
                <input type="radio" name="call-select" value="all" style="display:none">
                全部通话（混合分析）
                <span class="badge bg-danger">结果易失真</span>
            </label>`;
    } else {
        const note = captureWarning.kind === 'p2p'
            ? '存在点对点直连通话（分析它不会使用 FS 数据），请选择要分析的通话。'
            : '抓包之间可能不是同一次通话，请以其中一通为准进行分析。';
        html += `<div class="w-100 text-muted small">${note}</div>`;
    }

    container.innerHTML = html;

    const def = container.querySelector(`input[value="${calls[defaultIdx].call_id}"]`);
    if (def) def.closest('.direction-option').classList.add('selected');

    container.querySelectorAll('.direction-option').forEach(opt => {
        opt.addEventListener('click', () => {
            container.querySelectorAll('.direction-option').forEach(o => o.classList.remove('selected'));
            opt.classList.add('selected');
            opt.querySelector('input').checked = true;
        });
    });
}

// ====== 执行分析 ======
function setupAnalyzeButton() {
    document.getElementById('btn-analyze').addEventListener('click', () => runAnalysis());
}

// 分析进行中标志：防止面板按钮并发触发两次分析
let analyzing = false;

// 组装一次分析的完整参数（请求体口径统一）。
// 音画质量没有独立开关：随 media_type（分析范围）恒开，后端按范围筛选的流做检测
function currentAnalysisParams(callId) {
    const dirRadio = document.querySelector('input[name="direction"]:checked');
    const mediaRadio = document.querySelector('input[name="media-type"]:checked');
    const checkDelay = document.getElementById('check-delay');
    return {
        call_id: callId,
        direction: dirRadio ? dirRadio.value : 'auto',
        media_type: mediaRadio ? mediaRadio.value : 'audio',
        checks: {
            delay: checkDelay ? (checkDelay.checked && !checkDelay.disabled) : true,
        },
    };
}

async function runAnalysis(callIdOverride = null) {
    if (!sessionId) {
        alert('请先上传抓包文件');
        return;
    }
    if (analyzing) return;

    // 抓包不完整：先弹窗让用户确认（继续分析 / 放弃分析），确认过不再重复
    if (integrityWarning && !integrityConfirmed) {
        pendingCallIdOverride = callIdOverride;
        showIntegrityConfirmModal();
        return;
    }

    // 获取选中的通话（多通时；"all" = 全部混合）
    let callId = callIdOverride;
    if (callId === null) {
        const callRadio = document.querySelector('input[name="call-select"]:checked');
        if (callRadio && callRadio.value !== 'all') {
            callId = callRadio.value;
        }
    }
    const params = currentAnalysisParams(callId);

    analyzing = true;
    const btn = document.getElementById('btn-analyze');
    const status = document.getElementById('analyze-status');
    btn.disabled = true;
    status.innerHTML = '<span class="text-warning"><div class="spinner-border spinner-border-sm me-2"></div>正在分析中，请稍候...</span>';

    try {
        const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, ...params }),
        });
        const data = await resp.json();

        if (data.error) {
            status.innerHTML = `<span class="text-danger">${data.error}</span>`;
            return;
        }

        // 结果页（/results/<会话id>）是唯一的结果展示入口：分析结论由后端
        // 存进会话，跳转过去统一展示。首页不再内嵌渲染结果，避免两套展示
        // 逻辑各自维护（展示逻辑只存在于 templates/results.html）
        status.innerHTML = '<span class="text-success">✓ 分析完成，正在打开结果页…</span>';
        window.location.href = `/results/${sessionId}`;

    } catch (err) {
        status.innerHTML = `<span class="text-danger">分析失败: ${err.message}</span>`;
    } finally {
        // 跳转完成前恢复按钮；导航成功后页面随即卸载
        analyzing = false;
        btn.disabled = false;
    }
}
