# -*- coding: utf-8 -*-
"""app.js（web/static/js/app.js）中文文案 → 英文条目。

形态约束（重要，见下）：
1. 全部为【精确条目】，不使用 {} 模式条目。
2. 全部条目的中文字面量长度 >= 6 字符。

原因：src/i18n.py 的 _repl() 用 m.group(idx + 1) 判定命中分支，一旦字典里
存在模式条目（每个比精确条目多占 1 个捕获组），排在它之后的条目分支判定
就会错位（命中 A 却返回 B 的英文，或整句漏翻）。i18n_entries_web.py 里已有
'音频流: {}' / '视频流: {}' 两个模式条目（字面量 5 字符），因此本文件的
条目必须满足：
  - 不含 {}（否则自身也可能错位）；
  - 字面量 > 5 字符（排序必定在这两个模式条目之前，判定不受影响）。

为此部分短文案（表头、按钮、'音频'/'视频' 等单词）的键带上了紧邻的源码
上下文（HTML 闭合标签、label: '...'、return '...';、join('、') 等）来凑足
长度；键值成对替换后引号/反引号数量不变，输出的 JS 仍然语法有效。en 中的
${ 均来自源码插值原样保留（键里带上了插值的 ${，替换后仍是合法插值）。

不在本文件内的中文：app.js 注释、后端注入的运行时文案（m.label、r.headline、
w.text、i.text、fm.text、r.advice、pf.reasons、dir.label 等，归后端字典）。
"""

ENTRIES = [
    # --- 角色与通话状态常量（ROLE_NAMES / CALL_STATUS）---
    ("label: '完整'", "label: 'Complete'"),
    ("label: '缺开头'", "label: 'Missing start'"),
    ("label: '缺结尾'", "label: 'Missing end'"),
    ("label: '首尾不完整'", "label: 'Incomplete at both ends'"),
    ('被叫端（坐席）', 'Callee (agent)'),
    ('服务端（FS）', 'Server (FreeSWITCH)'),
    ('主叫端（终端）', 'Caller (terminal)'),
    ("'通话 ');", "'Call ');"),  # .replace('call_', '通话 ')

    # --- SIP Call-ID 展示 ---
    ("'（无信令）'", "'(no signaling)'"),
    ('}（共 ${', '} (${'),  # ${ids[0]}（共 ${ids.length} 条腿）
    (' 条腿）`;', ' legs)`;'),
    ('该通话没有抓到 SIP 信令', 'No SIP signaling was captured for this call'),
    ('Call-ID（可复制去 Wireshark 过滤）：\\n', 'Call-ID (copy to filter in Wireshark):\\n'),
    ('：同一抓包点共捕获 ', ': captured '),
    (' 次（含重传）', ' times at the same capture point (including retransmissions)'),

    # --- 上传 ---
    ('仅支持 pcap / pcapng / cap 文件', 'Only pcap / pcapng / cap files are supported'),
    ('正在上传（分片并发）', 'Uploading (chunked, concurrent)'),
    (" '正在上传')", " 'Uploading')"),
    ('请至少上传一个抓包文件', 'Please upload at least one capture file'),
    ('✓ 上传成功，已识别 ', '✓ Upload succeeded, '),
    (' 个文件</span>', ' files</span>'),
    ('>上传失败: ${', '>Upload failed: ${'),
    ('上传完成，正在解析抓包与识别通话…', 'Upload complete, parsing captures and detecting calls…'),
    ('网络错误，请检查连接后重试', 'Network error, please check your connection and try again'),
    ('上传完成，正在合并分片并识别通话…', 'Upload complete, merging chunks and detecting calls…'),

    # --- 识别结果展示 ---
    ("'服务器: '", "'Server: '"),
    ('服务器: 未检测到（单端分析模式）', 'Server: not detected (single-endpoint analysis mode)'),
    ('<th>角色</th><th>文件名</th><th>包数</th><th>IP</th><th>流数</th>',
     '<th>Role</th><th>Filename</th><th>Packets</th><th>IP</th><th>Streams</th>'),

    # --- FS 媒体/转发判定 ---
    ('服务端转码（FS）', 'Transcoding at server (FS)'),
    ('服务端未转码', 'No transcoding at server'),
    ('媒体已改道直连', 'Media rerouted to a direct connection'),
    ('未经过服务端中转', 'Does not go through the server'),
    ('部分上行缺失', 'Partial uplink missing'),
    ('服务端正常转发（FS）', 'Relayed by server normally (FS)'),
    ("label: '无法判断'", "label: 'Cannot determine'"),
    ('FS 媒体转发检测：', 'FS media relay check: '),
    ('<th>端点</th>', '<th>Endpoint</th>'),
    ('上行 → FS 音频', 'Uplink → FS audio'),
    ('上行 → FS 视频', 'Uplink → FS video'),
    ('FS 下行 → 音频', 'FS downlink → audio'),
    ('FS 下行 → 视频', 'FS downlink → video'),
    ('>0 包</span>', '>0 packets</span>'),
    ('} 包<span', '} packets<span'),
    ('排查建议：</strong>', 'Troubleshooting suggestions:</strong>'),
    ('}：向 ${', '}: announced to ${'),  # ${...}：向 ${...} 宣告了 ${...} 的媒体地址
    (' 宣告了 ${', ', advertising media address ${'),
    (' 的媒体地址', ''),

    # --- 协商编码摘要 / 通话来源徽章 ---
    ("'音频' : '视频'", "'Audio' : 'Video'"),  # ? '音频' : '视频'
    ("'视频' : '音频'", "'Video' : 'Audio'"),
    ('</i> 音频 ${', '</i> Audio ${'),
    ('</i> 视频 ${', '</i> Video ${'),
    ('`音频 ${', '`Audio ${'),
    ('`视频 ${', '`Video ${'),
    ("'caller', '主叫'", "'caller', 'Caller'"),
    ("'callee', '被叫'", "'callee', 'Callee'"),
    ('>主叫</span>', '>Caller</span>'),
    ('>被叫</span>', '>Callee</span>'),
    ("seg('主叫', 'bg-primary'", "seg('Caller', 'bg-primary'"),
    ("seg('被叫', 'bg-success'", "seg('Callee', 'bg-success'"),
    ('`协商 ${', '`Negotiated: ${'),
    ('来源：${present', 'Source: ${present'),
    ('这通通话的媒体流在上传的全部 ', 'The media streams of this call appeared in all '),
    (' 份抓包里都出现了', ' uploaded captures'),
    (' 份抓包均有（', ' captures, all of which contain it ('),
    ('}）</span>', '})</span>'),
    ('；该通话媒体为端到端直连，不经服务端，其余抓包没有它属正常现象',
     "; this call's media is an end-to-end direct stream that does not pass through the server, so its absence from the other captures is normal"),
    ('这通通话只在上传的 1 份抓包里出现，',
     'This call appears in only 1 of the uploaded captures; '),
    ('`其余 ${', '`the remaining ${'),
    (' 份（${missing', ' captures (${missing'),
    ('）没有它的媒体流——', ') contain no media streams from it — '),
    ('可能是抓包时段与这通电话不重叠，或媒体/信令没有经过那些抓包点',
     'possibly because the capture period does not overlap this call, or the media/signaling did not pass through those capture points'),
    (' 仅见于 ${', ' Only seen in ${'),
    ('这通通话只在 ', 'This call appears only in the captures of '),
    ('的抓包里出现，', ' but not in the captures of '),
    ('的抓包里没有', ''),
    (' 见于 ${', ' Seen in ${'),
    ('}：${_esc', '}: ${_esc'),

    # --- 多网卡/NAT 地址归并提醒 ---
    (' ↔ 别名 ', ' ↔ alias '),
    ('多网卡/NAT 地址归并提醒（推断结果）', 'Multi-NIC/NAT address merge notice (inferred)'),

    # --- 通话卡片 ---
    ('未检测到通话（抓包中没有 RTP 媒体流）', 'No calls detected (no RTP media streams in the captures)'),
    ('：未检测到通话', ': no calls detected'),
    ('检测到 <span', 'Detected <span'),
    ('</span> 通通话', '</span> call(s)'),
    ("|| '未知'", "|| 'Unknown'"),
    ('信令未完成</strong>', 'Signaling not completed</strong>'),
    ("'FS 转码'", "'FS transcodes'"),
    ("'FS 未转码'", "'FS does not transcode'"),
    ('媒体不经 FS', 'Media bypasses FS'),
    ('SIP 信令流程（', 'SIP signaling flow ('),
    (' 条消息${', ' messages${'),
    ('放大到弹窗查看完整信令流程，不用滚动', 'Open in a dialog to view the full signaling flow without scrolling'),
    ('</i> 放大', '</i> Enlarge'),
    ('> 点对点直连</span>', '> P2P direct connection</span>'),
    (' 条流</span>', ' streams</span>'),
    ('完整性判断依据', 'Completeness check details'),
    (' · SIP 信令流程', ' · SIP signaling flow'),

    # --- 阶梯图 ---
    ("return '支持';", "return 'Offer';"),
    ("return '早期应答';", "return 'Early answer';"),
    ("return '最终应答';", "return 'Final answer';"),
    ("return '应答';", "return 'Answer';"),
    ('下方独立行列出该消息 SDP 的完整编码列表',
     "The full codec list of this message's SDP is listed on a separate line below"),
    ('FS 在此消息里把对端的媒体地址透传给了本端——媒体改道为端到端直连，不再经过 FS',
     "In this message FS passes the peer's media address through to this endpoint — media is rerouted to an end-to-end direct connection, no longer going through FS"),
    (' 媒体改道</span>', ' Media rerouted</span>'),
    ('该地址不在本消息双方信令 IP 之内（NAT/多网卡场景：终端宣告的',
     'This address is not among the signaling IPs of both sides of this message (NAT/multi-NIC scenario: the address announced by the terminal'),
    ('地址与 RTP 实际来源不同），仍属于本通通话',
     ' differs from the actual RTP source), but it still belongs to this call'),
    ('在 SDP 里宣告的另一个地址（NAT/多网卡）：RTP 实际从 ',
     ' announced another address in SDP (NAT/multi-NIC): RTP actually comes from '),
    ('在 SDP 里宣告的另一个地址（NAT/多网卡）', ' announced another address in SDP (NAT/multi-NIC)'),
    (' 发来——属于', ', which belongs to '),
    ('那一端，不是其他通话的设备', "'s side, not a device of another call"),
    ('⚠NAT/多网卡', '⚠NAT/multi-NIC'),
    ('该消息 SDP 宣告的', "This message's SDP announced "),
    ('媒体地址">', ' media address">'),
    ('该端在 SDP 里宣告了另一个媒体地址 ', 'This endpoint announced another media address '),
    ('（NAT/多网卡）：RTP 实际从本端信令 IP 发来', '(NAT/multi-NIC): RTP actually comes from its own signaling IP'),
    (' 协商媒体</span>', ' Negotiated media</span>'),
    ("'FS 服务器'", "'FS server'"),
    ('主叫(转报): ', 'Caller (relayed): '),
    ('RTP 媒体结束 ', 'RTP media end '),
    ('（持续 ${dur', ' (lasted ${dur'),
    ('s）</span>', 's)</span>'),
    ('RTP 媒体开始 ', 'RTP media start '),
    ('候选编码（未收到应答）', ' candidate codecs (no answer received)'),
    ('}侧协商`;', '} side negotiated`;'),
    ('主叫候选编码（未收到应答）', 'Caller candidate codecs (no answer received)'),
    ("'协商编码';", "'Negotiated codecs';"),
    ('FS 参与转码', 'FS participates in transcoding'),
    ("label: '无法判定'", "label: 'Cannot determine'"),
    ('FS 媒体处理', 'FS media handling'),
    (">原始大小';", ">Actual size';"),
    (">适应窗口';", ">Fit to window';"),
    ('媒体 IP：', 'Media IPs: '),
    ('`（${v.span_s', '`(${v.span_s'),
    ('s）` : ', 's)` : '),
    ('}（${c.duration_s', '} (${c.duration_s'),
    ('s）${p2pBadge', 's)${p2pBadge'),
    # 仅含全角标点、无汉字的文案（前面的汉字扫描会漏掉）
    ('}（${id.user}）`;', '} (${id.user})`;'),  # ${id.name}（${id.user}）
    ('>（${_esc(f.filename)}）：', '>(${_esc(f.filename)}): '),  # 抓包完整性明细两处
    (" : ''}）", " : ''})"),  # SIP 信令流程（…）模板收尾的全角括号

    # --- 分析配置面板 ---
    ('仅单端抓包无法测量延迟（需 ≥2 个抓包点或含 FS 抓包），已自动禁用；抖动/丢包与音画质量仍可分析',
     'Delay cannot be measured from a single-endpoint capture (requires ≥2 capture points or an FS capture); it has been disabled automatically. Jitter/packet loss and A/V quality can still be analyzed'),
    ('未检测到可分析的方向', 'No analyzable directions detected'),

    # --- 抓包完整性提醒与确认弹窗 ---
    ('抓包可能不完整（已按现有数据继续分析）', 'Captures may be incomplete (analysis continued with the data available)'),
    ('截短的包缺失部分载荷，可能影响媒体重建与统计精度；建议确认抓包快照长度，必要时重新抓包或重新导出文件。',
     'Truncated packets are missing part of their payload, which may affect media reconstruction and statistics. Check the capture snapshot length, and re-capture or re-export if necessary.'),
    ('抓包可能不完整', 'Captures may be incomplete'),
    ('是否仍要继续分析？', 'Do you still want to continue the analysis?'),
    ('</i>放弃分析', '</i>Cancel analysis'),
    ('</i>继续分析', '</i>Continue analysis'),
    ('抓包可能不完整，是否仍要继续分析？（确定=继续，取消=放弃）',
     'Captures may be incomplete. Continue the analysis anyway? (OK = continue, Cancel = discard)'),

    # --- 跨抓包一致性提醒 / 通话选择器 ---
    ('}：${ov.start', '}: ${ov.start'),
    ('（${ov.count} 通）`', ' (${ov.count} calls)`'),
    ('}：${c.start', '}: ${c.start'),
    ('点对点直连提示', 'P2P direct connection notice'),
    ('抓包一致性提醒', 'Capture consistency notice'),
    ('已自动选中唯一的通话，可直接点「开始分析」',
     'The only call is selected automatically; just click "Start Analysis"'),
    ('全部通话（混合分析）', 'All calls (mixed analysis)'),
    ('>结果易失真</span>', '>Results may be distorted</span>'),
    ('存在点对点直连通话（分析它不会使用 FS 数据），请选择要分析的通话。',
     'There is a P2P direct-connection call (analyzing it will not use FS data). Please select the call to analyze.'),
    ('抓包之间可能不是同一次通话，请以其中一通为准进行分析。',
     'The captures may not belong to the same call; please analyze one specific call.'),

    # --- 执行分析 ---
    ('请先上传抓包文件', 'Please upload capture files first'),
    ('正在分析中，已用 ', 'Analyzing… '),
    (' 秒…</span>', ' s elapsed</span>'),
    ('✓ 分析完成，正在打开结果页…', '✓ Analysis complete, opening the results page…'),
    ('分析失败: ${', 'Analysis failed: ${'),

    # --- join 分隔符（运行时拼接的顿号/逗号改半角） ---
    ("join('、')", "join(', ')"),
    ("join('，')", "join(', ')"),
]

# 补漏：单端抓包禁用延迟提示(完整句优先,避免句中"音画质量"等短条目截胡)
ENTRIES += [
    ('仅单端抓包无法测量延迟（需 ≥2 个抓包点或含 FS 抓包），已自动禁用；抖动/丢包与音画质量仍可分析',
     'Delay cannot be measured from a single capture (needs ≥2 capture points or an FS capture); it has been disabled automatically. Jitter, packet loss and audio/video quality can still be analyzed'),
]

# 文件头注释
ENTRIES += [
    ('前端交互逻辑', 'frontend interaction logic'),
]
