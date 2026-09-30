"""i18n 字典 —— Web 层文案（模板 index/base/results/session_expired + static/js/app.js）。

条目格式：(中文, 英文)。含 {} 的为模式条目，{} 匹配变量值（数字、文件名、
${...} 插值等），两边占位符数量必须一致。维护规则：
  - JS 源码条目按 app.js 源文件里的字面量写（含引号内的部分，不含引号本身）；
  - 模板条目按浏览器渲染后的文本写（Jinja 变量已落地的样子，变量处用 {}）；
  - 更长、更具体的条目优先匹配（引擎按字面量长度排序）。
"""

ENTRIES = [
    # --- base.html / index.html / session_expired.html ---
    ('音视频流延迟 & 抖动分析平台', 'Audio/Video Stream Delay & Jitter Analysis'),
    ('使用上有问题？', 'Questions about usage?'),
    ('微信扫码加我沟通', 'scan the QR code to reach me on WeChat'),
    ('点击二维码可放大', 'Click the QR code to enlarge'),
    ('微信', 'WeChat'),
    ('联系', 'Contact'),
    ('微信联系', 'Contact on WeChat'),
    ('关闭', 'Close'),
    ('微信二维码', 'WeChat QR code'),
    ('微信二维码（放大）', 'WeChat QR code (enlarged)'),
    ('微信扫一扫，加上好友后即可反馈使用问题', 'Scan with WeChat, add me as a friend and share your feedback'),
    ('在线RTP 音视频流分析', 'Online RTP Audio/Video Stream Analysis'),
    ('上传抓包文件，自动分析延迟、抖动、丢包', 'Upload capture files for automatic delay, jitter and packet-loss analysis'),

    # --- index.html 上传区 ---
    ('上传抓包文件', 'Upload capture files'),
    ('支持 pcap / pcapng 格式。可上传 1~3 个文件，系统自动识别端点角色。',
     'Supports pcap / pcapng. Upload 1-3 files; endpoint roles are detected automatically.'),
    ('缺失某个抓包点时，对应的分析项会自动置灰。',
     'If a capture point is missing, the related analysis items are greyed out automatically.'),
    ('点击卡片选择文件，或把抓包文件直接拖到对应端的卡片上。',
     'Click a card to choose files, or drag capture files onto the matching card.'),
    ('主叫端抓包（终端）', 'Caller capture (terminal)'),
    ('服务端抓包（FS）', 'Server capture (FS)'),
    ('被叫端抓包（坐席）', 'Callee capture (agent)'),
    ('（可选项）', '(optional)'),
    ('上传并识别', 'Upload & Detect'),
    ('流识别结果', 'Stream Detection Result'),
    ('服务器: 检测中...', 'Server: detecting...'),
    ('音频流: {}', 'Audio streams: {}'),
    ('视频流: {}', 'Video streams: {}'),
    ('选择分析参数', 'Analysis Options'),
    ('选择通话', 'Select call'),
    ('多通通话混在一起分析会使延迟/抖动结果失真，建议选择具体通话',
     'Mixing multiple calls distorts delay/jitter results — pick a specific call'),
    ('分析范围（先选媒体类型）', 'Scope (pick media type first)'),
    ('仅音频', 'Audio only'),
    ('杂音 / 啸叫 / 断音吞字等声音问题，只分析音频流',
     'For noise / howling / dropouts — analyzes audio streams only'),
    ('仅视频', 'Video only'),
    ('花屏 / 马赛克 / 卡顿冻结等画面问题，只分析视频流',
     'For artifacts / macroblocking / freezes — analyzes video streams only'),
    ('音视频都分析', 'Audio & video'),
    ('声音 + 画面两侧问题都查，音频流和视频流都分析',
     'Checks both sound and picture; analyzes audio and video streams'),
    ('分析内容', 'What to analyze'),
    ('延迟测量', 'Delay measurement'),
    ('（服务端内部 / 跨抓包 / 端到端，可选）', '(server-internal / cross-capture / end-to-end)'),
    ('音画质量（杂音/啸叫/花屏等）已随「分析范围」自动包含，无需单独勾选',
     'Audio/video quality checks (noise, howling, artifacts...) are included automatically with the scope above'),
    ('延迟方向', 'Delay direction'),
    ('自动根据上传的抓包文件识别可用方向', 'Available directions are detected from the uploaded captures'),
    ('开始分析', 'Start analysis'),
]

# 全角标点:英文输出统一为半角(中文语境下这些标点只出现在中文文案里)
ENTRIES += [
    ('，', ', '),
    ('、', ', '),
    ('：', ': '),
    ('（', ' ('),
    ('）', ')'),
]

# aria-label 完整条目(避免被碎片化翻译)
ENTRIES += [
    ('微信扫码联系', 'Contact via WeChat QR'),
    ('微信扫一扫，加上好友后即可反馈使用问题', 'Scan with WeChat, add me as a friend and share your feedback'),
]
