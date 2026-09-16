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
const ROLE_NAMES = { seat: '被叫端（坐席）', fs: 'FS 服务器端', terminal: '主叫端（终端）' };
const ROLE_ICONS = { seat: 'bi-headset', fs: 'bi-server', terminal: 'bi-phone' };
const DIR_NAMES = { inbound: '呼入（接收）', outbound: '呼出（发送）', unknown: '方向未知' };
const DIR_BADGE = { inbound: 'bg-info', outbound: 'bg-success', unknown: 'bg-secondary' };

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
    renderCalls(data.calls || [], data.capture_warning);
}

// ====== 通话检测展示 ======
// FS 参与编解码判定的卡片徽章（后端 fs_media.verdict）：bypass 已由「点对点
// 直连」徽章表达，unknown 数据不足不给徽章（阶梯图里有灰字说明）
const FS_MEDIA_BADGES = {
    transcode: '<span class="badge bg-danger"><i class="bi bi-shuffle"></i> FS 转码</span>',
    same: '<span class="badge bg-success"><i class="bi bi-check2-circle"></i> FS 未转码</span>',
};

// FS 媒体转发检测（后端 fs_relay.verdict）：结论样式与提示块配色。
// redirected = FS 用 SDP 透传把媒体改道成端到端直连；no_relay = 两端都没往
// FS 发媒体；partial_uplink = 一部分发了另一部分没发（才考虑网络问题）
const FS_RELAY_META = {
    redirected:     {alert: 'alert-danger',   badge: 'bg-danger',
                     icon: 'bi-signpost-split', label: '媒体已改道直连'},
    no_relay:       {alert: 'alert-danger',   badge: 'bg-danger',
                     icon: 'bi-x-octagon-fill', label: '未经过 FS 中转'},
    partial_uplink: {alert: 'alert-warning',  badge: 'bg-warning text-dark',
                     icon: 'bi-exclamation-triangle-fill', label: '部分上行缺失'},
    relayed:        {alert: 'alert-success',  badge: 'bg-success',
                     icon: 'bi-check-circle-fill', label: 'FS 正常转发'},
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

function renderCalls(calls, captureWarning) {
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
        const files = c.files.map(f => ROLE_NAMES[f] || f).join(' / ');
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
                <span class="text-muted small">${files}</span>
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

// ====== 报告 issue：时间戳异常逐包明细（点击展开"前后相关内容"）======
// 现象的直白名称（kind 来自 ts_continuity 检测器）
const TS_KIND_TXT = {
    ts_jump: '声音断开',
    ts_backward: '时间倒退',
    reorder: '包晚到(乱序)',
    duplicate: '声音重复',
};

// 切换某条 issue 的逐包明细展开/收起，箭头随之转向
function toggleIssueDetail(headEl) {
    const li = headEl.closest('li');
    const detail = li.querySelector('.issue-detail');
    if (!detail) return;
    detail.classList.toggle('d-none');
    const chevron = headEl.querySelector('.issue-chevron');
    if (chevron) chevron.classList.toggle('open');
}

function renderTsEventTable(streamData) {
    // 时间戳增量换算成毫秒（音频流有时钟率；视频等 frame 模式只有 ts 单位）。
    // 发送端中途重置时间戳基准时增量会是天文数字，直接罗列没有意义，按幅度归为
    // "大幅跳变/倒退"
    const rate = streamData.clock_rate;
    const deltaTxt = ev => {
        if (ev.ts_delta === undefined || ev.ts_delta === null) return '—';
        if (!rate) return `${ev.ts_delta} (ts)`;
        const ms = ev.ts_delta / rate * 1000;
        if (Math.abs(ms) >= 60000) return ms > 0 ? '大幅跳变' : '大幅倒退';
        return `${ms.toFixed(0)}ms`;
    };
    const gapTxt = ev => (ev.media_gap_ms === null || ev.media_gap_ms === undefined)
        ? '—' : `${ev.media_gap_ms}ms`;
    let rows = '';
    streamData.events.forEach(ev => {
        rows += `<tr>` +
            `<td class="text-nowrap">${ev.time_str}</td>` +
            `<td>${TS_KIND_TXT[ev.kind] || ev.kind}</td>` +
            `<td class="text-nowrap">#${ev.prev_seq ?? '—'} / ${ev.prev_ts ?? '—'}</td>` +
            `<td class="text-nowrap">#${ev.seq} / ${ev.ts ?? '—'}</td>` +
            `<td>${deltaTxt(ev)}</td>` +
            `<td>${gapTxt(ev)}</td>` +
            `</tr>`;
    });
    const truncated = streamData.event_count > streamData.events.length
        ? `<div class="text-muted small mb-1">仅列出前 ${streamData.events.length} 处（本流共 ${streamData.event_count} 处），完整计数见上方文字。</div>`
        : '';
    return `${truncated}` +
        `<div class="table-responsive"><table class="table table-sm table-bordered issue-table mb-0">` +
        `<thead><tr><th>时间</th><th>现象</th><th>前一个包 seq / 时间戳</th>` +
        `<th>本包 seq / 时间戳</th><th>时间戳增量</th><th>缺失声音</th></tr></thead>` +
        `<tbody>${rows}</tbody></table></div>`;
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

// 平台/话机常把号码编码成 base64 当分机号（From/To 里出现 "Extension LTU4NT..."
// 这类不可读串）：能解出可读 ASCII 的 token 就地替换，解不出保持原样
function _decodeIdents(s) {
    return String(s).replace(/[A-Za-z0-9+/]{16,}={0,2}/g, tok => {
        try {
            const bin = atob(tok);
            if (/^[\x20-\x7e]+$/.test(bin)) return bin;
        } catch (e) { /* 不是 base64，按原样保留 */ }
        return tok;
    });
}

function _identLabel(id) {
    if (!id) return '';
    if (id.name && id.user && id.name !== id.user && !id.name.includes(id.user))
        return _decodeIdents(`${id.name}（${id.user}）`);
    return _decodeIdents(id.name || id.user || '');
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
            `<span class="text-truncate d-inline-block align-bottom" style="max-width:240px" title="${name}">${name}</span>` +
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
    // 单端抓包测不了延迟，自动禁用"延迟测量"，但抖动/丢包与音画质量不受影响。
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
        const dirCol = document.getElementById('direction-col');
        if (dirCol) dirCol.classList.toggle('opacity-50', !delayAvailable);
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

// 分析进行中标志：防止面板按钮与结果区切换通话并发触发两次分析
let analyzing = false;

// 分析结果缓存（本会话内）：key = 会话 + 通话 + 方向 + 媒体类型 + 分析项。
// 已分析过的通话再切回来时直接复用历史结论，不重复分析
const analysisCache = new Map();

// 组装一次分析的完整参数（请求体与缓存 key 共用，保证口径一致）
function currentAnalysisParams(callId) {
    const dirRadio = document.querySelector('input[name="direction"]:checked');
    const mediaRadio = document.querySelector('input[name="media-type"]:checked');
    const checkDelay = document.getElementById('check-delay');
    const checkQuality = document.getElementById('check-quality');
    return {
        call_id: callId,
        direction: dirRadio ? dirRadio.value : 'auto',
        media_type: mediaRadio ? mediaRadio.value : 'audio',
        checks: {
            delay: checkDelay ? (checkDelay.checked && !checkDelay.disabled) : true,
            quality: checkQuality ? checkQuality.checked : true,
        },
    };
}

const _analysisCacheKey = params =>
    JSON.stringify({ session_id: sessionId, ...params });

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

    // 获取选中的通话（多通时；"all" = 全部混合）。
    // 结果区"切换通话"会直接传入 callIdOverride，优先于面板当前选择
    let callId = callIdOverride;
    if (callId === null) {
        const callRadio = document.querySelector('input[name="call-select"]:checked');
        if (callRadio && callRadio.value !== 'all') {
            callId = callRadio.value;
        }
    }
    const params = currentAnalysisParams(callId);
    const cacheKey = _analysisCacheKey(params);

    // 相同参数已分析过：直接使用历史结论，不重复分析
    if (analysisCache.has(cacheKey)) {
        document.getElementById('analyze-status').innerHTML =
            '<span class="text-success">✓ 该通话此前已分析过，已直接使用历史结论（未重新分析）</span>';
        showResults(analysisCache.get(cacheKey));
        return;
    }

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

        analysisCache.set(cacheKey, data);
        status.innerHTML = '<span class="text-success">✓ 分析完成</span>';
        showResults(data);

    } catch (err) {
        status.innerHTML = `<span class="text-danger">分析失败: ${err.message}</span>`;
    } finally {
        // 分析结束后恢复按钮：同一会话可换一通通话再次分析，无需重新上传
        analyzing = false;
        btn.disabled = false;
    }
}

    // ====== 结果展示 ======
    function showResults(data) {
    const section = document.getElementById('result-section');
    section.classList.remove('d-none');

    // 摘要
    const summary = data.summary;
    let summaryHtml = '<div class="row g-3">';
    // 未勾选延迟分析或缺少 FS 抓包时，FS 内部延迟未测——如实显示，不用 0.0ms 误导
    summaryHtml += (summary.fs_delay_mean != null)
        ? _summaryCard('bi-speedometer2', 'FS 内部延迟',
                       summary.fs_delay_mean.toFixed(1) + '<span class="stat-unit">ms</span>',
                       'P95 ' + summary.fs_delay_p95.toFixed(1) + 'ms', 'primary')
        : _summaryCard('bi-speedometer2', 'FS 内部延迟', '未测量',
                       summary.delay_checked === false ? '未勾选延迟分析' : '缺少 FS 端抓包',
                       'secondary');
    summaryHtml += _summaryCard('bi-activity', '抖动流数', summary.jitter_streams, '已分析', 'success');
    summaryHtml += _summaryCard('bi-shield-exclamation', '丢包状态',
                                summary.packet_loss_clean ? '无丢包' : '有丢包',
                                '', summary.packet_loss_clean ? 'success' : 'danger');
    summaryHtml += _summaryCard('bi-clock-history', '时间戳',
                                summary.ts_clean === false ? '异常' : '连续',
                                '', summary.ts_clean === false ? 'warning' : 'success');
    if (summary.media_quality && summary.media_quality.checked) {
        summaryHtml += _summaryCard(summary.media_quality.clean ? 'bi-music-note-beamed' : 'bi-exclamation-diamond',
                                    '音画质量', summary.media_quality.clean ? '正常' : '有异常',
                                    '杂音/啸叫/花屏检测', summary.media_quality.clean ? 'success' : 'danger');
    }
    summaryHtml += _summaryCard('bi-clipboard2-pulse', '综合评估',
                                summary.overall === 'healthy' ? '健康' :
                                summary.overall === 'warning' ? '注意' : '异常',
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
                const streamData = i.stream && data.report.timestamp_continuity &&
                    data.report.timestamp_continuity.streams[i.stream];
                const hasEvents = !!(streamData && streamData.events && streamData.events.length);
                reportHtml += `<li class="list-group-item list-group-item-${sev}">`;
                if (hasEvents) {
                    reportHtml += `<div class="issue-clickable" onclick="toggleIssueDetail(this)" title="点击展开/收起逐包明细">` +
                                  `<i class="bi bi-chevron-right issue-chevron"></i>${_esc(i.message)}</div>`;
                } else {
                    reportHtml += _esc(i.message);
                }
                if (i.explain) reportHtml += `<div class="issue-explain">${_esc(i.explain).replace(/\n/g, '<br>')}</div>`;
                if (hasEvents) reportHtml += `<div class="issue-detail d-none">${renderTsEventTable(streamData)}</div>`;
                reportHtml += '</li>';
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

        // 声音/视频问题分类：区块开头带"流质量速览"（每条流的结论徽章与关键
        // 指标）。原独立"音画质量分析"块与之重复，已并入不再单独展示
        if (data.report.problem_classification) {
            reportHtml += renderProblemClassification(
                data.report.problem_classification, data.report.media_quality);
        }
        if (data.report.video_problem_classification) {
            reportHtml += renderVideoProblemClassification(
                data.report.video_problem_classification, data.report.media_quality);
        }

        document.getElementById('result-report').innerHTML = reportHtml;
    }

    // 多通通话切换提示：标明当前分析的通话，支持一键换一通重新分析
    renderCallSwitchBanner(data.call_id);

    // 音视频回放
    showMedia(data.media_manifest);

    // 滚动到结果区域
    section.scrollIntoView({ behavior: 'smooth' });
}

// ====== 结果区通话切换 ======
// 抓包里检测到多通通话时，在结果区顶部提示当前分析的是哪一通，并支持一键
// 切换到其他通话重新分析（沿用面板当前的方向/媒体类型/分析内容设置）
function renderCallSwitchBanner(currentCallId) {
    const banner = document.getElementById('call-switch-banner');
    if (!banner) return;
    if (!detectedCalls || detectedCalls.length < 2) {
        banner.classList.add('d-none');
        return;
    }
    const curTxt = currentCallId
        ? `当前分析的是<strong>${callLabel(currentCallId)}</strong>，` +
          '可切换到其他通话（标有「已分析」的直接复用历史结论）：'
        : '当前分析的是全部通话混合的结果，建议选择具体通话：';
    const btns = detectedCalls.map(c => {
        const st = CALL_STATUS[c.completeness.status] || CALL_STATUS.complete;
        const cur = c.call_id === currentCallId;
        const title = `${c.start_str} ~ ${c.end_str} · ${c.stream_count} 条流`;
        const fmBadge = FS_MEDIA_BADGES[c.fs_media?.verdict] || '';
        const cachedBadge = analysisCache.has(_analysisCacheKey(
            currentAnalysisParams(c.call_id)))
            ? ' <span class="badge bg-secondary"><i class="bi bi-clock-history"></i> 已分析</span>'
            : '';
        return `<button type="button" class="btn btn-sm ${cur ? 'btn-primary' : 'btn-outline-primary'}"
                    ${cur ? 'disabled' : ''} onclick="switchCall('${c.call_id}')" title="${title}">
                    <i class="bi bi-telephone"></i> ${callLabel(c.call_id)}
                    <span class="badge ${st.badge} ms-1"><i class="bi ${st.icon}"></i> ${st.label}</span>${fmBadge}${cachedBadge}
                    <span class="ms-1 small">${title}</span>
                </button>`;
    }).join('');
    banner.classList.remove('d-none');
    banner.innerHTML = `
        <div class="alert alert-info mb-0 text-start">
            <div class="d-flex flex-wrap align-items-center gap-2">
                <strong><i class="bi bi-collection me-1"></i>检测到 ${detectedCalls.length} 通通话</strong>
                <span class="small">${curTxt}</span>
            </div>
            <div class="d-flex flex-wrap gap-2 mt-2">${btns}</div>
        </div>`;
}

function switchCall(callId) {
    if (analyzing) return;
    // 同步配置面板的通话选择（单选框 + 高亮），两处状态保持一致
    const radio = document.querySelector(`input[name="call-select"][value="${callId}"]`);
    if (radio) {
        document.querySelectorAll('#call-options .direction-option').forEach(o => o.classList.remove('selected'));
        radio.checked = true;
        radio.closest('.direction-option').classList.add('selected');
    }
    // 分析进行中禁用切换按钮并就地提示，防止重复触发（完成后随结果重绘恢复）
    const banner = document.getElementById('call-switch-banner');
    if (banner) {
        banner.querySelectorAll('button').forEach(b => { b.disabled = true; });
        const note = document.createElement('div');
        note.className = 'w-100 small text-primary mt-1';
        note.innerHTML = '<div class="spinner-border spinner-border-sm me-2"></div>正在重新分析…';
        banner.appendChild(note);
    }
    runAnalysis(callId);
}

// ====== 流质量速览（并入声音/视频问题分类区块）======
// 原独立"音画质量分析"块与问题分类展示的是同一批检测结论，已并入避免重复。
// 音画质量专用徽章（音频 clean/noisy/bad，视频 ok/risk/bad）
const QUALITY_BADGES = {
    clean: ['success', '干净'],
    noisy: ['warning', '有杂音'],
    bad: ['danger', '异常'],
    ok: ['success', '无花屏风险'],
    risk: ['warning', '花屏风险'],
};

// ====== 声音问题分类（对照《声音问题种类》清单） ======
// 把各检测器结论按问题种类聚合展示：种类描述 + 用户听感词 + 证据 +
// 排查方向。默认只展开"严重"级卡片，注意/提示级一律收进折叠区，
// 点开才看。抓包看不到的听感问题单独折叠列出人工验证方法。
const PRIO_BADGE = {P0: 'danger', P1: 'warning', P2: 'info', P3: 'secondary'};

function _problemCard(p, feelNoun) {
    feelNoun = feelNoun || '听感';
    let html = '<div class="border rounded p-2 mb-2">';
    html += '<div class="d-flex flex-wrap align-items-center gap-2">' +
            `<span class="badge bg-${PRIO_BADGE[p.priority] || 'secondary'}">${p.priority}</span>` +
            `<strong>${_esc(p.name)}</strong>` +
            `<span class="badge bg-light text-dark border">${_esc(p.category)}</span>` +
            `<code class="small">${_esc(p.term)}</code>` +
            `<span class="badge bg-${p.severity === 'critical' ? 'danger' : p.severity === 'warning' ? 'warning' : 'secondary'}">` +
            `${p.severity === 'critical' ? '严重' : p.severity === 'warning' ? '注意' : '提示'}</span>` +
            '</div>';
    html += `<div class="small mt-1">用户${feelNoun}：` +
            p.feel.map(f => `<span class="badge bg-warning-subtle text-dark border border-warning-subtle me-1 fw-normal">“${_esc(f)}”</span>`).join('') +
            '</div>';
    html += `<div class="small text-muted mt-1">${_esc(p.description)}</div>`;
    if (p.evidence && p.evidence.length) {
        html += '<div class="small mt-1"><strong>证据：</strong><ul class="mb-0 ps-4">';
        p.evidence.forEach(e => { html += `<li>${_esc(e)}</li>`; });
        html += '</ul></div>';
    }
    html += `<div class="small mt-1"><strong>排查方向：</strong>${_esc((p.causes || []).join('；'))}</div>`;
    html += `<div class="small"><strong>验证方法：</strong>${_esc((p.verify || []).join('；'))}</div>`;
    html += '</div>';
    return html;
}

// 声音/视频问题分类共用一套卡片布局，只差标题、清单名、空态文案与
// "听感/观感"用词
function renderProblemClassification(pc, mq) {
    return _renderProblemSection(pc, '声音问题分类', '声音问题种类',
                                 '抓包层面未发现可归类的声音问题。', '听感', mq, 'audio');
}

function renderVideoProblemClassification(pc, mq) {
    return _renderProblemSection(pc, '视频问题分类', '视频问题',
                                 '抓包层面未发现可归类的视频问题。', '观感', mq, 'video');
}

function _renderProblemSection(pc, title, docName, emptyText, feelNoun, mq, kind) {
    if (!pc || !pc.available) return '';
    let html = `<h6 class="mt-3">${_esc(title)}` +
        ` <span class="text-muted small fw-normal">对照《${_esc(docName)}》清单，把检测结论对号入座</span></h6>`;
    // 区块开头放"流质量速览"：每条流的结论徽章 + 关键指标，替代原独立块
    html += _qualityOverview(mq, kind);
    html += `<div class="alert alert-secondary py-2 small mb-2">${_esc(pc.summary)}</div>`;
    (pc.notes || []).forEach(n => {
        html += `<p class="small text-muted mb-2">${_esc(n)}</p>`;
    });
    if (!pc.problems.length) {
        html += `<div class="alert alert-success py-2 mb-2">${_esc(emptyText)}</div>`;
    }
    const severe = pc.problems.filter(p => p.severity === 'critical');
    const minor = pc.problems.filter(p => p.severity !== 'critical');
    severe.forEach(p => { html += _problemCard(p, feelNoun); });
    if (minor.length) {
        // 注意/提示级一律默认收起，点开才看；无严重级卡片时仅去掉"另有"前缀
        const label = (severe.length ? '另有 ' : '') +
            `${minor.length} 类注意/提示级问题（点开展开查看）`;
        html += `<details class="mt-1">` +
                `<summary class="small text-muted user-select-none">${label}</summary>` +
                '<div class="mt-2">';
        minor.forEach(p => { html += _problemCard(p, feelNoun); });
        html += '</div></details>';
    }
    if (pc.unobservable && pc.unobservable.length) {
        html += `<details class="mt-2"><summary class="small text-muted user-select-none">另有 ${pc.unobservable.length} 类${_esc(feelNoun)}问题无法仅凭抓包确认（点开看原因与人工验证方法）</summary>`;
        html += '<div class="table-responsive mt-1"><table class="table table-sm table-bordered small mb-0">' +
                '<thead><tr><th>类别</th><th>问题</th><th>用户' + _esc(feelNoun) + '</th><th>为什么抓包看不到</th><th>人工验证方法</th></tr></thead><tbody>';
        pc.unobservable.forEach(u => {
            html += `<tr><td>${_esc(u.category)}</td><td>${_esc(u.name)}</td>` +
                    `<td>${u.feel.map(f => `“${_esc(f)}”`).join(' ')}</td>` +
                    `<td>${_esc(u.why)}</td><td>${_esc(u.verify)}</td></tr>`;
        });
        html += '</tbody></table></div></details>';
    }
    return html;
}

// 音频流关键指标徽章（原每流卡片的指标行，速览复用）
function _audioQualityChips(q) {
    if (q.verdict === 'unknown') {
        return [`${q.codec || ''} 编码不可解（仅 PCMU/PCMA 支持音质检测）`];
    }
    const chips = [];
    if (q.tones?.howl_count) chips.push(`啸叫/单频音 ${q.tones.howl_count} 处`);
    if (q.tones?.hum_count) chips.push(`低频嗡声 ${q.tones.hum_count} 处`);
    if (q.clipping?.run_count) chips.push(`削波 ${q.clipping.run_count} 处`);
    if (q.clicks?.count) chips.push(`爆点 ${q.clicks.count} 个`);
    if (q.noise_floor_dbfs != null) chips.push(`底噪 ${q.noise_floor_dbfs} dBFS`);
    if (q.speech_level_dbfs != null) chips.push(`话音 ${q.speech_level_dbfs} dBFS`);
    const integ = q.rtp_integrity;
    if (integ) {
        if (integ.monotonic && !integ.lost_packets && !integ.ts_duplicate) {
            chips.push(`RTP 秩序正常（每包 +${integ.median_ts_delta} ≈ ${integ.packet_duration_ms}ms）`);
        } else {
            if (integ.lost_packets) chips.push(`序号缺口 ${integ.seq_gaps} 处（丢 ${integ.lost_packets} 包）`);
            if (integ.ts_backward) chips.push(`时间戳倒退 ${integ.ts_backward} 处`);
            if (integ.ts_duplicate) chips.push(`时间戳重复 ${integ.ts_duplicate} 处`);
        }
        if (integ.other_pt_packets) chips.push(`其他PT包 ${integ.other_pt_packets} 个（DTMF 事件等，不参与秩序判定）`);
    }
    if (!chips.length) chips.push('未检测到异常');
    return chips;
}

// 视频流关键指标徽章（原每流卡片的指标行，速览复用）
function _videoQualityChips(q) {
    const chips = [];
    if (q.total_lost) chips.push(`丢包 ${q.total_lost} 包（${q.loss_rate_pct}%)`);
    if (q.rtp_integrity?.ts_backward) chips.push(`时间戳倒退 ${q.rtp_integrity.ts_backward} 处`);
    if (q.broken_nals) chips.push(`破损帧 ${q.broken_nals} 个`);
    chips.push(`IDR 关键帧 ${q.idr_count ?? 0} 个`);
    if (q.idr_interval_max_s != null) chips.push(`最长间隔 ${q.idr_interval_max_s}s`);
    if (q.est_artifacts_ms) chips.push(`估算花屏 ${(q.est_artifacts_ms / 1000).toFixed(1)}s`);
    if (q.decode_check === 'ok') chips.push('解码校验通过');
    else if (q.decode_check === 'errors') chips.push(`解码错误 ${q.decode_errors} 处`);
    else if (q.decode_check === 'unavailable') chips.push('解码校验跳过（无 ffmpeg）');
    return chips;
}

// 流质量速览：一条流一行——流名 + 结论徽章 + 关键指标；检测提示默认收起
function _qualityOverviewRow(label, q, kind) {
    const badge = QUALITY_BADGES[q.verdict] || ['secondary', q.verdict];
    const chips = kind === 'video' ? _videoQualityChips(q) : _audioQualityChips(q);
    let html = '<div class="border rounded p-2 mb-1">' +
        '<div class="d-flex flex-wrap align-items-center gap-1">' +
        `<strong class="me-1">${_esc(label)}</strong>` +
        `<span class="badge bg-${badge[0]}">${_esc(badge[1])}</span>`;
    chips.forEach(c => {
        html += `<span class="badge bg-light text-dark border">${_esc(c)}</span>`;
    });
    html += '</div>';
    if (q.issues && q.issues.length) {
        html += `<details class="mt-1"><summary class="small text-muted user-select-none">${q.issues.length} 条检测提示（点开展开）</summary>`;
        q.issues.forEach(i => {
            const sev = i.severity === 'critical' ? 'danger' : i.severity === 'warning' ? 'warning' : 'secondary';
            html += `<div class="mt-1 small"><span class="badge bg-${sev} me-1">${i.severity === 'critical' ? '严重' : i.severity === 'warning' ? '注意' : '提示'}</span>${_esc(i.message)}</div>`;
        });
        html += '</details>';
    }
    html += '</div>';
    return html;
}

// 某类媒体（audio/video）的速览条，插在对应问题分类区块开头；没有流时整体省略
function _qualityOverview(mq, kind) {
    const entries = Object.entries((mq && mq[kind]) || {});
    if (!entries.length) return '';
    let html = '<div class="mb-2">' +
        '<div class="small text-muted mb-1">流质量速览（每条流的检测结论与关键指标，' +
        '详细归因与排查方向见下方问题卡片）：</div>';
    entries.forEach(([label, q]) => { html += _qualityOverviewRow(label, q, kind); });
    html += '</div>';
    return html;
}

// ====== 音视频回放展示 ======
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
    // 所属通话标注（分析限定在某通通话时）
    if (manifest.call_id) {
        html += `<div class="mb-2">
            <span class="badge bg-primary"><i class="bi bi-telephone"></i> ${callLabel(manifest.call_id)}</span>
            <span class="text-muted small">以下媒体流均来自该通话</span>
        </div>`;
    }
    // 通话拓扑：先一句话说清每条腿谁到谁（主叫 ↔ FS ↔ 被叫），细节在每条流开头标注
    const parties = manifest.parties || [];
    if (parties.length) {
        html += `<div class="mb-3 small d-flex flex-wrap align-items-center gap-1">` +
            `<i class="bi bi-diagram-3 text-primary"></i>` +
            parties.map(_partyChainHtml).join('<span class="text-muted mx-1">；</span>') +
            `<span class="text-muted ms-1">—— 每条媒体流的收发双方标注在各流开头</span></div>`;
    }
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
            const flow = u.flow ? `（${_esc(u.flow.from.label)} → ${_esc(u.flow.to.label)}）` : '';
            html += `<li>${ROLE_NAMES[u.role] || u.role} (SSRC=${u.ssrc})${flow} — ${u.codec}: ${u.reason}</li>`;
        });
        html += '</ul></div>';
    }

    container.innerHTML = html;
}

// 通话拓扑链：主叫 ↔ FS ↔ 被叫（各端称呼 + IP），来自后端 SIP 信令识别
function _partyChainHtml(p) {
    const seg = s => s ? `<strong>${_esc(s.label || '')}</strong>` +
        (s.ip ? `<span class="text-muted ms-1">${s.ip}</span>` : '') : '';
    let html = seg(p.caller);
    html += ` <i class="bi bi-arrow-left-right text-muted mx-1"></i> ` +
        `<span class="badge bg-dark">FS</span>` +
        (p.server_ip ? `<span class="text-muted ms-1">${p.server_ip}</span>` : '');
    if (p.answerer) {
        html += ` <i class="bi bi-arrow-left-right text-muted mx-1"></i> ` + seg(p.answerer);
    }
    return html;
}

function _mediaItem(entry, kind) {
    const dirName = DIR_NAMES[entry.direction] || entry.direction;
    const dirBadge = DIR_BADGE[entry.direction] || 'bg-secondary';
    const dur = entry.duration_ms ? (entry.duration_ms / 1000).toFixed(1) + 's' : '';

    // 谁到谁：发送方 → 接收方（SIP 识别的主叫/被叫身份，无信令时为角色名或 IP）
    let head = `<span class="badge ${dirBadge} me-1">${dirName}</span>`;
    if (entry.flow) {
        const side = s => `<strong>${_esc(s.label || '')}</strong>` +
            (s.ip && s.label !== s.ip ? `<span class="text-muted small ms-1">${s.ip}</span>` : '');
        head += side(entry.flow.from) +
            ` <i class="bi bi-arrow-right text-muted mx-1"></i> ` + side(entry.flow.to) + ' ';
    }

    let meta = `<span class="badge bg-dark me-1">${entry.codec || ''}</span>
                <span class="text-muted small">SSRC: ${entry.ssrc}`;
    if (dur) meta += ` · 时长 ${dur}`;
    if (entry.total_packets) meta += ` · ${entry.total_packets} 包`;
    if (entry.lost_packets) meta += ` · 丢 ${entry.lost_packets} 包`;
    if (entry.packet_duration_ms && entry.packet_duration_ms !== 20) {
        meta += ` · 每包 ${entry.packet_duration_ms}ms`;
    }
    if (entry.ts_gap_filled) meta += ` · 时间戳跳变补静音 ${entry.ts_gap_filled} 处`;
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
            <div>${head}</div>
            <div class="mt-1">${meta}</div>
            ${player}
            <a href="${entry.url}" download class="btn btn-sm btn-outline-secondary mt-1">
                <i class="bi bi-download"></i> 下载
            </a>
        </div>
    `;
}

function _summaryCard(icon, title, value, subtitle, color) {
    return `
        <div class="col-6 col-md-4 col-xl">
            <div class="stat-card stat-${color}">
                <div class="stat-icon"><i class="bi ${icon}"></i></div>
                <div>
                    <div class="stat-title">${title}</div>
                    <div class="stat-value">${value}</div>
                    ${subtitle ? `<div class="stat-sub">${subtitle}</div>` : ''}
                </div>
            </div>
        </div>
    `;
}