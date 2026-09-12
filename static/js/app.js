/**
 * RTP Stream Analyzer - 前端交互逻辑
 */

let sessionId = null;
let uploadedCount = 0;
let detectedCalls = [];
let detectedServerIp = null;
let ipRoleMap = {};  // ip -> 角色名（用于 SIP 流程里把 IP 显示为端点名）

// ====== 展示常量 ======
const ROLE_NAMES = { seat: '坐席端', fs: 'FS 服务器端', terminal: '终端 / 主叫端' };
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
        detectedCalls = data.calls || [];
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
    document.getElementById('streams-detail').innerHTML = detail;

    // 通话列表 + 完整性状态 + 跨抓包一致性提醒
    renderCalls(data.calls || [], data.capture_warning);
}

// ====== 通话检测展示 ======
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
            // 摘要行直接给出双方协商的编码（SDP offer/answer 交集），不用展开
            const neg = c.negotiated_codecs || {};
            const negTxt = [
                neg.audio?.length ? `音频 ${neg.audio.join('/')}` : '',
                neg.video?.length ? `视频 ${neg.video.join('/')}` : '',
            ].filter(Boolean).join('，');
            flowHtml = `<details class="mt-1">
                <summary class="text-muted small" style="cursor:pointer">
                    SIP 信令流程（${msgCount} 条消息${negTxt ? ` · 协商 ${negTxt}` : ''}）
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
                <span class="badge bg-light text-dark">${c.stream_count} 条流</span>
                <span class="badge bg-light text-dark">${media}</span>
                <span class="text-muted small">${files}</span>
                ${_callPartyChain(flow)}
            </div>
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
    const answerer = ok ? ok.src : null;

    const cols = [caller];
    if (server && server !== caller) cols.push(server);
    if (answerer && !cols.includes(answerer)) cols.push(answerer);
    let msgs = flow.filter(m => cols.includes(m.src) && cols.includes(m.dst));
    if (!msgs.length) msgs = flow;   // 兜底：判定失败时不过滤
    return { cols, server, caller, answerer, msgs };
}

// SDP 消息的线上小标记：INVITE 行标「支持」（主叫/re-INVITE 报的支持列表），
// 其余（183/200/ACK）标「应答」（应答方从中选定/确认的列表）。完整编码列表
// 由 _sdpListRow 在该消息行下方独立成行展示，不受信令线跨度裁剪；FS 自产
// INVITE 的 SDP 用静态 PT 无 rtpmap、解析不出编码名，标记与列表都不显示
function _sdpTags(m) {
    const sc = m.sdp_codecs;
    if (!sc || !(sc.audio?.length || sc.video?.length)) return '';
    const tag = m.method === 'INVITE' ? '支持' : '应答';
    return `<span class="sl-sdp" title="下方独立行列出该消息 SDP 的完整编码列表">` +
        `<i class="bi bi-file-earmark-code"></i> ${tag}</span>`;
}

// SDP 完整编码列表行：挂在消息行下方独立成行，可完整换行
function _sdpListRow(m) {
    const sc = m.sdp_codecs;
    if (!sc || !(sc.audio?.length || sc.video?.length)) return '';
    const tag = m.method === 'INVITE' ? '支持' : '应答';
    const parts = [];
    if (sc.audio?.length) parts.push(`音频 ${sc.audio.join(' / ')}`);
    if (sc.video?.length) parts.push(`视频 ${sc.video.join(' / ')}`);
    return `<div class="sl-sdplist"><span class="sl-sdp">` +
        `<i class="bi bi-file-earmark-code"></i> ${tag}</span> ${parts.join('，')}</div>`;
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
        const badge = ip === caller ? '<span class="sl-role bg-primary text-white">主叫</span>'
            : ip === answerer ? '<span class="sl-role bg-success text-white">被叫</span>' : '';
        html += `<div class="sl-p"><div class="sl-name"${ipSub ? ` title="${name}"` : ''}>${name}</div>` +
            (ipSub ? `<div class="sl-ip">${ipSub}</div>` : '') + badge + `</div>`;
    });
    html += `</div></div><div class="sl-body"><div class="sl-lines">`;
    cols.forEach((ip, i) => {
        html += `<i class="sl-line" style="left:${pct((i + 0.5) / n)}"></i>`;
    });
    html += `</div>`;
    // RTP 部分：编码标签 + 媒体开始/结束标线，按媒体时间插入消息时间线——
    // 开始线落在媒体首包之后（紧贴 200 OK 应答一侧），结束线落在媒体末包
    // 之前（紧贴 BYE 挂断一侧）。time_str 是定宽 HH:MM:SS，可直接比较。
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
                `<span class="lb">${m.label}${_sdpTags(m)}</span></div>`;
        } else {
            const lo = Math.min(a, b), hi = Math.max(a, b);
            const lSeg = a < b ? '<i class="ln"></i>' : '<i class="ln arr-l"></i>';
            const rSeg = a < b ? '<i class="ln arr-r"></i>' : '<i class="ln"></i>';
            inner = `<div class="sl-msg ${kindCls}" ` +
                `style="left:${pct((lo + 0.5) / n)};width:${pct((hi - lo) / n)}">` +
                `${lSeg}<span class="lb">${m.label}${_sdpTags(m)}</span>${rSeg}</div>`;
        }
        rowBefore[i] = rows.length;
        rows.push(`<div class="sl-row"><span class="sl-t">${m.time_str}</span>` +
            `<div class="sl-track" style="grid-template-columns:repeat(${n},1fr)">${inner}</div></div>`);
        const list = _sdpListRow(m);
        if (list) rows.push(list);
        rowAfter[i] = rows.length;
    });
    if (call) {
        // 标线锚定在信令行上，确保两条线之间不夹应答/挂断握手的其余指令：
        // 开始线紧跟被叫应答的 200 OK 行（answer_time 由后端从该通话信令中
        // 选出），结束线落在首条 BYE 行之前。RTP 首末包时间（talk_*，无信令
        // 时后端回退为整段媒体）只用于标签显示，行锚定失败才按时间插。
        const sStr = call.talk_start_str || call.start_str;
        const eStr = call.talk_end_str || call.end_str;
        const dur = call.talk_duration_s ?? call.duration_s;
        const codecs = call.codecs || {};
        const chips = [];
        if (codecs.audio?.length)
            chips.push(`<span class="badge text-bg-light border"><i class="bi bi-music-note-beamed"></i> 音频 ${codecs.audio.join(' / ')}</span>`);
        if (codecs.video?.length)
            chips.push(`<span class="badge text-bg-light border"><i class="bi bi-camera-video"></i> 视频 ${codecs.video.join(' / ')}</span>`);
        // 开始位置：answer_time 对应的 200 OK 行之后 → 首条 200(cseq INVITE) 行
        // 之后 → 媒体开始时间之后，逐级兜底。锚点先按消息下标算（mk/ek），
        // 再经 rowBefore/rowAfter 换算成行下标（SDP 消息可能带列表子行）
        let mk = -1;
        if (call.answer_time != null)
            mk = msgs.findIndex(m => m.time === call.answer_time) + 1;
        if (mk <= 0)
            mk = msgs.findIndex(m => m.method === '200' && m.cseq_method === 'INVITE') + 1;
        if (mk <= 0) {
            mk = sStr ? msgs.findIndex(m => m.time_str > sStr) : -1;
            if (mk === -1) mk = msgs.length;
        }
        // 多抓包时被叫 200 OK 可能以坐席副本的时钟排在 answer_time 行之后
        // （应答握手尾巴），把锚点后移到握手结束（ACK/200-INVITE 连续段之后），
        // 保证两条标线之间不出现任何信令行
        while (mk < msgs.length &&
               (msgs[mk].method === 'ACK' ||
                (msgs[mk].method === '200' && msgs[mk].cseq_method === 'INVITE')))
            mk++;
        // 结束位置：首条 BYE 行之前；无 BYE 再按媒体结束时间插
        let ek = msgs.findIndex(m => m.method === 'BYE');
        if (ek === -1)
            ek = eStr ? msgs.findIndex(m => m.time_str >= eStr) : -1;
        let si = mk >= msgs.length ? rows.length : rowAfter[mk];
        let ei = ek === -1 ? rows.length : rowBefore[ek];
        si = Math.min(si, ei);
        if (eStr)
            rows.splice(ei, 0, `<div class="sl-marker sl-end"><span class="lb">` +
                `<i class="bi bi-stop-fill"></i> RTP 媒体结束 ${eStr}（持续 ${dur}s）</span></div>`);
        if (sStr)
            rows.splice(si, 0, `<div class="sl-marker sl-start"><span class="lb">` +
                `<i class="bi bi-play-fill"></i> RTP 媒体开始 ${sStr}</span></div>`);
        if (chips.length)
            rows.splice(si + 1, 0, `<div class="sl-codecs">${chips.join('')}</div>`);
        // 协商编码（SDP offer/answer 交集，后端算好）：插在 SDP 应答行之后，
        // 即协商完成的时刻；SDP 行不在可见列里时退到媒体开始标线前。
        // 注意本 splice 必须最后做：ni ≤ si，插在前不会打乱上面两行的锚点
        const neg = call.negotiated_codecs || {};
        const negChips = [];
        if (neg.audio?.length)
            negChips.push(`<span class="badge text-bg-light border"><i class="bi bi-music-note-beamed"></i> 音频 ${neg.audio.join(' / ')}</span>`);
        if (neg.video?.length)
            negChips.push(`<span class="badge text-bg-light border"><i class="bi bi-camera-video"></i> 视频 ${neg.video.join(' / ')}</span>`);
        if (negChips.length) {
            const sdpRows = [];
            // 只认带编码名的 SDP 行：FS 自产 INVITE 的 SDP（无 rtpmap）在
            // 后端配对时已被跳过，这里保持一致，协商行锚在其正主应答行
            // （含列表子行）之后
            msgs.forEach((m, i) => {
                if (m.sdp_codecs &&
                    (m.sdp_codecs.audio?.length || m.sdp_codecs.video?.length))
                    sdpRows.push(rowAfter[i]);
            });
            let ni = sdpRows.length >= 2 ? sdpRows[1]
                   : sdpRows.length === 1 ? sdpRows[0] : si;
            ni = Math.min(ni, si);
            const negLabel = call.sdp_answered === false
                ? '主叫候选编码（未收到应答）' : '协商编码';
            rows.splice(ni, 0, `<div class="sl-codecs">` +
                `<span class="text-muted small me-1"><i class="bi bi-handshake"></i> ${negLabel}</span>` +
                `${negChips.join('')}</div>`);
        }
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
        html += `
            <label class="direction-option">
                <input type="radio" name="call-select" value="${c.call_id}" ${checked} style="display:none">
                ${callLabel(c.call_id)} ${c.start_str}~${c.end_str}（${c.duration_s}s）${p2pBadge}
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

    // 获取选中的通话（多通时；"all" = 全部混合）
    let callId = null;
    const callRadio = document.querySelector('input[name="call-select"]:checked');
    if (callRadio && callRadio.value !== 'all') {
        callId = callRadio.value;
    }

    try {
        const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionId,
                direction: direction,
                media_type: mediaType,
                call_id: callId,
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
    summaryHtml += _summaryCard('时间戳',
                                summary.ts_clean === false ? '⚠ 异常' : '✓ 连续',
                                '', summary.ts_clean === false ? 'warning' : 'success');
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