"""i18n 字典 —— 后端解析/检测层文案（除报告生成外的 analyzer 模块）。

来源文件：
- src/analyzer/call_detector.py       通话归属 / 抓包完整性 / FS 转发判定 / 一致性提示
- src/analyzer/capture_integrity.py   抓包文件完整性提示
- src/analyzer/delay_analyzer.py      延迟分解说明
- src/analyzer/delay_chains.py        分段延迟链路
- src/analyzer/media_extractor.py     媒体重建错误 / 通话双方称呼
- jitter_analyzer / packet_loss / rtp_parser / rtcp_parser /
  stream_classifier / ts_continuity 无用户可见中文（仅注释与 docstring）。

说明：f-string 插值落地后的最终渲染文本若再含中文（如「主叫端 x.x.x.x」「音频」），
一律把该原子作为字面量写进条目（或拆成静态片段条目），避免 {} 通配把中文
捕获后原样带回英文输出；{} 只用于捕获纯数字 / IP / 时间等非中文插值。
"""

ENTRIES = [
    # ---------- call_detector.py：通话抓包完整性状态 ----------
    ('完整', 'Complete'),
    ('缺开头（抓包时通话已在进行）',
     'Missing beginning (the call was already in progress when capture started)'),
    ('缺结尾（抓包结束时通话未结束）',
     'Missing end (the call had not ended when capture stopped)'),
    ('首尾都不完整', 'Incomplete at both ends'),
    ('INVITE {} 早于媒体开始，通话开头已抓到',
     'INVITE {} precedes media start; the beginning of the call was captured'),
    ('上行流首包 seq={}，媒体流从头被捕获',
     'Uplink stream first sequence number {}, media captured from the very beginning'),
    ('上行流首包 seq={}（明显非零，流已进行一段时间）',
     'Uplink stream first sequence number {} (clearly non-zero; the stream had been running for a while)'),
    ('通话开始距抓包开始仅 {}s（抓包时通话已在进行）',
     'The call started only {}s after capture began (the call was already in progress when capture started)'),
    ('BYE {} 晚于媒体结束，通话挂断已抓到',
     'BYE {} follows media end; the call hang-up was captured'),
    ('通话结束距抓包结束仅 {}s（抓包结束时通话可能仍在进行）',
     'The call ended only {}s before capture stopped (the call may still have been in progress when capture ended)'),
    ('媒体结束后抓包又持续 {}s，通话自然结束',
     'Capture continued for another {}s after media ended; the call ended naturally'),

    # ---------- call_detector.py：通用角色 / 媒体称谓（高频原子） ----------
    ('主叫端 {}', 'Caller (terminal) {}'),
    ('被叫端 {}', 'Callee (agent) {}'),
    ('端点 {}', 'Endpoint {}'),
    ('主叫', 'Caller'),
    ('被叫', 'Callee'),
    ('音频', 'audio'),
    ('视频', 'video'),
    ('两端', 'Both endpoints'),
    ('被叫端（坐席）', 'Callee (agent)'),
    ('主叫端（终端）', 'Caller (terminal)'),
    ('FS 端', 'FS side'),

    # ---------- call_detector.py：SIP 信令完整性问题 ----------
    ('共发送 {} 次（含重传），', 'sent {} times in total (including retransmissions), '),
    ('{} 发出的 INVITE（Call-ID {}）', 'INVITE sent at {} (Call-ID {}) '),
    ('未收到任何响应——SIP 事务未完成，信令没打通：对端/服务器没有回（不可达、拒收或离线），'
     '呼叫建立不起来。若抓包点只抓到单向信令也会漏收响应，换到双向路径上的抓包点核对。',
     'No response of any kind was received — the SIP transaction never completed and the signaling never got '
     'through: the peer/server did not reply (unreachable, rejected, or offline), so the call could not be '
     'established. If the capture point only saw one-way signaling, responses may also have been missed; '
     'verify with a capture point on the bidirectional path.'),
    ('只收到临时响应（{}），未收到最终应答——呼叫没有被接通也没有被明确拒绝：对端/服务器停在振铃或'
     '早媒体阶段后事务悬挂（超时、CANCEL 或最终应答没有出现在抓包里）。',
     'Only provisional responses were received ({}), with no final answer — the call was neither answered nor '
     'explicitly rejected: the peer/server stalled at ringing or early media and the transaction hung '
     '(timed out, CANCELed, or the final answer never appeared in the capture).'),

    # ---------- call_detector.py：两腿协商编码对比（FS 转码判定） ----------
    ('音频：主叫侧 {}，被叫侧 {}', 'audio: caller side {}, callee side {}'),
    ('视频：主叫侧 {}，被叫侧 {}', 'video: caller side {}, callee side {}'),
    ('两腿协商编码不同（', 'The two legs negotiated different codecs ('),
    ('），FS 必然参与转码', '), so FS must be transcoding'),
    ('两腿协商编码相同（', 'The two legs negotiated the same codecs ('),
    ('），FS 无需转码', '), so FS does not need to transcode'),
    ('媒体在两端之间直连（点对点 / bypass media），FS 不在媒体路径，未参与编解码',
     'Media flows directly between the two endpoints (peer-to-peer / bypass media); FS is not in the media '
     'path and took no part in encoding/decoding'),
    ('FS 已在 {} 把媒体改道为端到端直连（SDP 透传），FS 不在媒体路径，未参与编解码',
     'FS redirected media to an end-to-end direct connection at {} (SDP passthrough); FS is not in the media '
     'path and took no part in encoding/decoding'),
    ('两腿实际使用的编码相同（{}），FS 无需转码（依 RTP 载荷类型推断）',
     'The codecs actually used by the two legs are the same ({}), so FS does not need to transcode '
     '(inferred from RTP payload types)'),
    ('主叫侧使用 {}，被叫侧使用 {}，FS 参与转码（依 RTP 载荷类型推断）',
     'Caller side uses {}, callee side uses {}, FS takes part in transcoding (inferred from RTP payload types)'),
    ('未能同时看到两条腿的协商编码或实际编码，无法判定',
     'Could not see the negotiated or actually used codecs of both legs at the same time; cannot determine'),

    # ---------- call_detector.py：FS 媒体转发判定 ----------
    ('没有 FS 侧抓包，无法判断媒体是否经过 FS 中转（需在 FS 上或其镜像口抓包）',
     'No FS-side capture available; cannot determine whether media went through FS relay '
     '(a capture on FS or its mirror port is required)'),
    ('FS 的音频下行发往 SDP 宣告地址 ', 'FS sends audio downlink to the SDP-announced address '),
    ('FS 的视频下行发往 SDP 宣告地址 ', 'FS sends video downlink to the SDP-announced address '),
    ('（主叫端 {} 的另一个地址，该端 RTP 实际来源是 {}）——NAT 场景下若该端收不到下行，检查 FS 的 '
     'rtp-auto-adjust（RTP 对端地址自动调整）配置',
     ' (another address of Caller (terminal) {}; the actual RTP source of that endpoint is {}) — in NAT '
     'scenarios, if that endpoint receives no downlink, check the FS rtp-auto-adjust (automatic adjustment '
     'of the RTP peer address) configuration'),
    ('（被叫端 {} 的另一个地址，该端 RTP 实际来源是 {}）——NAT 场景下若该端收不到下行，检查 FS 的 '
     'rtp-auto-adjust（RTP 对端地址自动调整）配置',
     ' (another address of Callee (agent) {}; the actual RTP source of that endpoint is {}) — in NAT '
     'scenarios, if that endpoint receives no downlink, check the FS rtp-auto-adjust (automatic adjustment '
     'of the RTP peer address) configuration'),
    ('（端点 {} 的另一个地址，该端 RTP 实际来源是 {}）——NAT 场景下若该端收不到下行，检查 FS 的 '
     'rtp-auto-adjust（RTP 对端地址自动调整）配置',
     ' (another address of Endpoint {}; the actual RTP source of that endpoint is {}) — in NAT '
     'scenarios, if that endpoint receives no downlink, check the FS rtp-auto-adjust (automatic adjustment '
     'of the RTP peer address) configuration'),
    ('FS 在 {} 用 {} 把媒体改道为端到端直连（SDP 透传，向 主叫端 {} 宣告 {} 的媒体地址），'
     '此后音视频流不再经过 FS 转发。',
     'FS redirected media to an end-to-end direct connection at {} via {} (SDP passthrough, announcing media '
     'addresses {} to Caller (terminal) {}); from then on, audio/video streams no longer go through FS relay.'),
    ('FS 在 {} 用 {} 把媒体改道为端到端直连（SDP 透传，向 被叫端 {} 宣告 {} 的媒体地址），'
     '此后音视频流不再经过 FS 转发。',
     'FS redirected media to an end-to-end direct connection at {} via {} (SDP passthrough, announcing media '
     'addresses {} to Callee (agent) {}); from then on, audio/video streams no longer go through FS relay.'),
    ('FS 在 {} 用 {} 把媒体改道为端到端直连（SDP 透传，向 端点 {} 宣告 {} 的媒体地址），'
     '此后音视频流不再经过 FS 转发。',
     'FS redirected media to an end-to-end direct connection at {} via {} (SDP passthrough, announcing media '
     'addresses {} to Endpoint {}); from then on, audio/video streams no longer go through FS relay.'),
    ('FS 在 {} 用 {} 把媒体改道为端到端直连（SDP 透传，向 {} 宣告 {} 的媒体地址），'
     '此后音视频流不再经过 FS 转发。',
     'FS redirected media to an end-to-end direct connection at {} via {} (SDP passthrough, announcing media '
     'addresses {} to {}); from then on, audio/video streams no longer go through FS relay.'),
    ('的 RTP 上行在改道时刻即停止——各端服从了新 SDP，属干净的信令性停止，不是网络丢包',
     ' RTP uplink stopped right at the redirection moment — every endpoint obeyed the new SDP; this is a clean '
     'signaling-driven stop, not network packet loss'),
    ('在改道后仍有上行（FS 侧仍在收部分媒体）',
     ' still had uplink after the redirection (FS was still receiving some media)'),
    ('排查优先级：这是中转问题，不是网络问题。先确认 FS 的媒体旁路配置（bypass_media / '
     'bypass_media_after_bridge 等）是否符合预期；本抓包点看不到端到端直连的媒体，若要确认两端是否真正'
     '收到对方的音视频，需在两端本地抓包验证。',
     'Priority of troubleshooting: this is a relaying problem, not a network problem. First confirm whether '
     'the FS media bypass configuration (bypass_media / bypass_media_after_bridge, etc.) matches expectations; '
     'this capture point cannot see the end-to-end direct media, so to confirm whether both endpoints actually '
     'receive each other\'s audio/video, capture locally at both endpoints to verify.'),
    ('都没有向 FS 发送任何 RTP——音视频流没有经过 FS 中转。',
     ' sent no RTP to FS at all — the audio/video streams never went through FS relay.'),
    ('排查优先级：两端都不往 FS 发媒体 → 优先排查中转问题：FS 是否配置了 bypass media、信令里宣告的'
     '媒体地址是否指向 FS、两端是否拿到了彼此地址在直连；确认后才是网络问题。',
     'Priority of troubleshooting: neither endpoint sends media to FS → investigate the relaying problem '
     'first: whether FS has bypass media configured, whether the media address announced in the signaling '
     'points to FS, and whether the two endpoints obtained each other\'s addresses and connected directly; '
     'only after ruling these out should network problems be considered.'),
    ('只有 ', 'Only '),
    (' 向 FS 发送了媒体，', ' sent media to FS, while '),
    (' 没有任何上行 RTP。', ' has no uplink RTP at all.'),
    ('排查优先级：一部分发了、一部分没发 → 这种情况才考虑网络问题：先在未发送端本地抓包，确认它确实'
     '在发（排除终端自身不发），再逐段检查链路、防火墙/NAT。',
     'Priority of troubleshooting: some endpoints sent while others did not → only in this case should '
     'network problems be considered: first capture locally on the non-sending endpoint to confirm it really '
     'is sending (rule out the endpoint itself not sending), then check each link segment, firewall/NAT.'),
    (' 缺音频下发（对端上行 {} 包，FS 回发 0 包）',
     ' is missing audio downlink (the peer sent {} packets uplink, FS returned 0 packets)'),
    (' 缺视频下发（对端上行 {} 包，FS 回发 0 包）',
     ' is missing video downlink (the peer sent {} packets uplink, FS returned 0 packets)'),
    ('各端都在向 FS 发送媒体，但 FS 收到后从未回发——',
     'Every endpoint is sending media to FS, but FS never sends anything back — '),
    ('，单向转发缺失（听者侧单通）',
     '; one-way forwarding is missing (the listening side has one-way audio)'),
    ('排查优先级：这不是网络问题——FS 与该端点之间的其他媒体流正常，对端也一直在等（持续探测、RTCP '
     '显示该类媒体零接收）。FS 收得到上行却没回发，查 FS 侧该腿的音频发送通道：bridge 是否真正建立、'
     'write codec 是否激活（uuid_dump / show channels）、该平台对这条腿有无 bypass / 媒体方向相关的特殊配置。',
     'Priority of troubleshooting: this is not a network problem — other media streams between FS and that '
     'endpoint are normal, and the peer keeps waiting (continuous probing; RTCP shows zero reception of that '
     'media type). FS receives the uplink but never sends it back; check the audio transmit path of that leg '
     'on the FS side: whether the bridge is truly established, whether the write codec is active '
     '(uuid_dump / show channels), and whether the platform has any special bypass / media-direction '
     'configuration for this leg.'),
    ('各端都有上行、FS 也有下行——媒体确实经过 FS 中转。',
     'Every endpoint has uplink and FS has downlink — media is indeed going through FS relay.'),
    ('FS 从未向 ', 'FS never sent '),
    (' 下发音频（0 包，而对端 ', ' audio downlink (0 packets, while peer '),
    (' 下发视频（0 包，而对端 ', ' video downlink (0 packets, while peer '),
    (' 上行过 {} 包）——该方向未发生转发',
     ' sent {} packets uplink) — no forwarding occurred in this direction'),
    ('FS 向 ', 'FS sent '),
    (' 下发了 {} 包音频', ' {} audio packets downlink'),
    (' 下发了 {} 包视频', ' {} video packets downlink'),
    ('，但 ', ', but '),
    (' 从未上行过音频——该下行并非转发，应是 FS 本地媒体源（如彩铃/视频公告/MOH）',
     ' never sent any audio uplink — this downlink is not forwarded; it must be FS-local media '
     '(ringback tone / video announcement / MOH, etc.)'),
    (' 从未上行过视频——该下行并非转发，应是 FS 本地媒体源（如彩铃/视频公告/MOH）',
     ' never sent any video uplink — this downlink is not forwarded; it must be FS-local media '
     '(ringback tone / video announcement / MOH, etc.)'),
    (' 下发音频 {} 包（覆盖约 {} 秒），而 ',
     ' audio downlink: {} packets (covering about {} s), while '),
    (' 下发视频 {} 包（覆盖约 {} 秒），而 ',
     ' video downlink: {} packets (covering about {} s), while '),
    (' 上行仅 {} 包（约 {} 秒）——下行主体并非来自对端的转发',
     ' sent only {} packets uplink (about {} s) — the bulk of this downlink does not come from forwarding '
     'the peer\'s traffic'),

    # ---------- call_detector.py：NAT 多地址归并提醒 ----------
    ('主叫端媒体出现两个地址：RTP 实际从 {} 发来，SDP 宣告的媒体地址是 {}（FS 的下行发往它）',
     'The caller\'s media shows two addresses: RTP actually arrives from {}, while the SDP-announced media '
     'address is {} (FS sends downlink to it)'),
    ('被叫端媒体出现两个地址：RTP 实际从 {} 发来，SDP 宣告的媒体地址是 {}（FS 的下行发往它）',
     'The callee\'s media shows two addresses: RTP actually arrives from {}, while the SDP-announced media '
     'address is {} (FS sends downlink to it)'),
    ('。工具按「FS 的同一媒体端口会话只有一个对端」这一启发式把两个地址归并为同一台设备，这通电话因此'
     '合并为一通。注意：这是推断而非确凿事实——若两个地址实际不属于同一台设备（如中间设备改写了地址、'
     '抓包混入了其他流的媒体），归并后该端的上/下行统计会被并到一起，包数、丢包、延迟的归属可能失真；'
     'NAT 场景下 FS 的下行发往 SDP 宣告地址而非 RTP 实际上行来源，若该地址从 FS 不可达，该端会收不到'
     '下行（单通），需核对 FS 的 rtp-auto-adjust（RTP 对端地址自动调整）配置。',
     '. The tool merges the two addresses into one device using the heuristic that an FS media-port session '
     'has only one peer, and this phone call is therefore merged into one. Note: this is an inference, not a '
     'proven fact — if the two addresses actually belong to different devices (e.g. a middlebox rewrote the '
     'address, or the capture mixed in media from other streams), the merged uplink/downlink statistics will '
     'be combined and the attribution of packet counts, packet loss, and delay may be distorted; in NAT '
     'scenarios FS sends downlink to the SDP-announced address rather than the actual uplink source, and if '
     'that address is unreachable from FS the endpoint receives no downlink (one-way audio), so check the FS '
     'rtp-auto-adjust (automatic adjustment of the RTP peer address) configuration.'),
    ('PT {}（SDP 未抓到）', 'PT {} (not found in the captured SDP)'),

    # ---------- call_detector.py：跨抓包一致性 / 点对点直连提示 ----------
    ('通话 {}', 'Call {}'),
    ('任意两端抓包之间都没有同一通通话',
     'no single call is shared between any two of the captures'),
    ('部分抓包两两之间没有同一通通话',
     'some pairs of captures share no single call'),
    ('这几份抓包里可能不是同一次通话：',
     'These captures may not be from the same call: '),
    ('。请确认上传的文件是否传错；如需继续，请选择其中一通通话单独分析。',
     '. Please check whether the uploaded files were mixed up; to continue, select one of the calls and '
     'analyze it separately.'),
    (' 通点对点直连通话：', ' peer-to-peer direct calls: '),
    ('点对点直连通话：', 'a peer-to-peer direct call: '),
    ('检测到', 'Detected '),
    ('之间的通话媒体为端到端直连（',
     ': media of the call between them flows end-to-end directly ('),
    ('），未经过 ', '), not passing through '),
    ('（{}），因此 ', ' ({}); therefore '),
    ('的抓包里没有这通通话（其抓到的 ',
     '\'s capture does not contain this call (the '),
    (' 通为该服务器同时段的其他通话）。文件没有传错，选择这通通话分析即可，分析不会使用 ',
     ' calls it captured are other calls on that server in the same period). The files were not mixed up; '
     'just select this call to analyze — the analysis will not use '),
    ('的数据。', '\'s data.'),

    # ---------- capture_integrity.py：抓包文件完整性提示 ----------
    (' 个包在捕获时被截短', ' packets were truncated when captured'),
    ('（其中 RTP 媒体包 {} 个）', ' ({} of them RTP media packets)'),
    ('，抓包快照长度 {} 字节', ', capture snapshot length {} bytes'),
    ('，最多缺失 {} 字节——这类包的载荷不完整，媒体重建的对应片段会缺内容',
     ', with at most {} bytes missing — the payloads of these packets are incomplete, so the corresponding '
     'segments of the reconstructed media will lack content'),
    ('抓包文件在最后一个包的中途结束（抓包被强制终止或文件传输出错），文件尾部的数据不完整',
     'The capture file ends in the middle of the last packet (the capture was force-terminated or the file '
     'transfer failed); the data at the end of the file is incomplete'),

    # ---------- delay_analyzer.py ----------
    ('数据不足', 'Insufficient data'),
    ('网络A→FS: ~{}ms + FS内部: {}ms + 网络FS→B: ~{}ms = {}ms',
     'Network A→FS: ~{} ms + FS internal: {} ms + Network FS→B: ~{} ms = {} ms'),

    # ---------- delay_chains.py：角色 / 段名称 ----------
    ('主叫端往返（主叫→FS→主叫）', 'Caller round trip (caller→FS→caller)'),
    ('被叫端往返（被叫→FS→被叫）', 'Callee round trip (callee→FS→callee)'),
    ('主叫端抓包', 'caller-side capture'),
    ('被叫端抓包', 'callee-side capture'),
    ('FS 抓包', 'FS capture'),
    ('主叫 → FS', 'caller → FS'),
    ('被叫 → FS', 'callee → FS'),
    ('FS → 主叫', 'FS → caller'),
    ('FS → 被叫', 'FS → callee'),
    ('主叫 → 被叫', 'caller → callee'),
    ('被叫 → 主叫', 'callee → caller'),
    ('直连（主叫 → 被叫）', 'Direct (caller → callee)'),
    ('直连（被叫 → 主叫）', 'Direct (callee → caller)'),

    # ---------- delay_chains.py：链路结论与分段说明 ----------
    ('往返两段的时钟偏移互相抵消，此值不含抓包间时钟差',
     'The clock offsets of the two legs cancel each other out; this value excludes the inter-capture clock '
     'difference'),
    ('点对点直连：链路只有一段网络路径，无 FS 内部段',
     'Peer-to-peer direct connection: the path is a single network segment with no FS-internal segment'),
    ('跨抓包段的绝对延迟同时包含真实传播时延与抓包机时钟偏移，单段测量无法区分二者；往返之和可抵消'
     '时钟偏移，见往返参考值',
     'The absolute delay of cross-capture segments includes both true propagation delay and capture-machine '
     'clock offset, and a single-segment measurement cannot distinguish the two; the sum of a round trip '
     'cancels the clock offset — see the round-trip reference values'),
    ('接收端抖动缓冲与播放设备延迟不在抓包中体现，测量值为网络传输 + FS 处理延迟',
     'Receiver jitter buffer and playback device delays do not show up in the capture; the measured value is '
     'network transport + FS processing delay'),
    ('缺少可比对的抓包点，无法测量该方向延迟',
     'No comparable capture points available; cannot measure the delay in this direction'),
    ('以下段延迟/波动偏高：', 'The following segments have high delay/variance: '),
    ('（另有未测到的段，见明细）', ' (some segments were not measured; see details)'),
    ('已测到的段延迟正常；', 'Measured segments have normal delay; '),
    (' 未测到（缺抓包点）', ' not measured (missing capture point)'),
    ('各段延迟均在正常范围', 'The delay of every segment is within the normal range'),
    ('跨抓包段的均值含抓包间时钟偏移，仅供参考',
     'The mean of cross-capture segments includes the inter-capture clock offset; for reference only'),
    ('未识别该段媒体流', 'The media stream for this segment was not identified'),
    ('缺少', 'missing '),
    ('，无法比对到达时刻', ', so arrival times cannot be compared'),
    ('两个抓包点未匹配到共同包（主叫端抓包或FS 抓包可能未覆盖该流）',
     'The two capture points matched no common packets (the caller-side capture or FS capture may not cover '
     'this stream)'),
    ('两个抓包点未匹配到共同包（被叫端抓包或FS 抓包可能未覆盖该流）',
     'The two capture points matched no common packets (the callee-side capture or FS capture may not cover '
     'this stream)'),
    ('两个抓包点未匹配到共同包（主叫端抓包或被叫端抓包可能未覆盖该流）',
     'The two capture points matched no common packets (the caller-side capture or callee-side capture may '
     'not cover this stream)'),
    ('两个抓包点未匹配到共同包（被叫端抓包或主叫端抓包可能未覆盖该流）',
     'The two capture points matched no common packets (the callee-side capture or caller-side capture may '
     'not cover this stream)'),
    ('两个抓包点未匹配到共同包（FS 抓包或主叫端抓包可能未覆盖该流）',
     'The two capture points matched no common packets (the FS capture or caller-side capture may not cover '
     'this stream)'),
    ('两个抓包点未匹配到共同包（FS 抓包或被叫端抓包可能未覆盖该流）',
     'The two capture points matched no common packets (the FS capture or callee-side capture may not cover '
     'this stream)'),
    ('两台抓包机时钟差异约 {}ms（含传播时延），绝对值不可信',
     'The clock difference between the two capture machines is about {} ms (including propagation delay); '
     'the absolute value is not trustworthy'),
    ('去偏移后 P95 波动 {}ms，该段抖动/突发偏大',
     'The P95 variance after offset removal is {} ms; jitter/burstiness of this segment is high'),
    ('去偏移后波动 P95 {}ms', 'P95 variance after offset removal: {} ms'),
    ('FS 内部处理', 'FS internal processing'),
    ('缺少 FS 抓包，无法测量', 'FS capture missing; cannot measure'),
    ('未同时识别该方向的入站/出站流',
     'The inbound/outbound streams of this direction were not both identified'),
    ('入站→出站未匹配到转发对（FS 可能未转发该方向媒体）',
     'No forwarding pair matched from inbound to outbound (FS may not have forwarded media in this direction)'),
    ('FS 内部处理延迟偏高（均值 {}ms）',
     'FS internal processing delay is high (mean {} ms)'),
    ('单时钟测量可信（均值 {}ms）',
     'Single-clock measurement is reliable (mean {} ms)'),

    # ---------- media_extractor.py：媒体重建错误 ----------
    ('OPUS 音频需要 ffmpeg 解码（未检测到 ffmpeg）',
     'OPUS audio requires ffmpeg for decoding (ffmpeg not detected)'),
    ('ffmpeg 解码超时', 'ffmpeg decoding timed out'),

    # ---------- media_extractor.py：通话双方称呼 ----------
    ('主叫 {}', 'Caller {}'),
    ('被叫 {}', 'Callee {}'),
    ('被叫 {}（经FS）', 'Callee {} (via FS)'),
    ('被叫（经FS）', 'Callee (via FS)'),
]
