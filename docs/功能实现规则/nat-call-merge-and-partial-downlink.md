# NAT 场景通话合并与单向转发缺失检测

> 对应抓包样本：`fs-2026-09-20-01.pcap`（FS 服务端抓包，FreeSWITCH B2BUA 一通通话）
> 涉及改动：`src/analyzer/callDetector.ts`、`src/analyzer/mediaExtractor.ts`、`src/analyzer/types.ts`、`src/analyzer/problemTaxonomy.ts`、`src/analyzer/reporter.ts`

## 背景

一通经过 FreeSWITCH 中转的通话（主叫 172.110.249.67、被叫 172.110.249.65、FS 172.110.3.151），主叫侧终端位于 NAT 后（SDP 宣告私网地址 10.22.68.170，RTP 实际从公网 172.110.249.67 发出）。在该样本上先后暴露了三个问题：

1. 一通通话被拆成多通；
2. 回放清单里出现一个不属于通话三方的"未知 IP"；
3. 服务端抓包应看到 4 路音频，实际只有 3 路——缺失的恰是 FS → 被叫方向的音频，且工具此前无法直接定位这种"FS 收到上行却不回发"的单通形态。

## 问题 1：一通通话被检测成多通

### 现象（改动前）

一通通话本应识别为一通、包含 A/B 两条腿。实际被识别成**两通独立的通话，每通只有半条腿**：一通持有主叫半呼叫（主叫方向的媒体腿 + A 腿 Call-ID），另一通持有被叫半呼叫（被叫方向的媒体腿 + B 腿 Call-ID）。

### 原因

`refineCalls` 的"半呼叫形状"合并规则要求：两个半呼叫的结束时刻对齐（±3 秒）、时间重叠、且**合并后设备端点数 ≤ 2**。NAT 场景下同一个终端贡献了两个 IP（SDP 宣告的私网 IP 10.22.68.170 + 实际发送 RTP 的公网 IP 172.110.249.67），朴素按 IP 去重数出来是 3 台"设备"（主叫×2 + 被叫），第三个条件失败，两个半呼叫拒绝合并——各自成了"一通通话"。

### 修复

设备计数改为**按端点共享关系做并查集别名归并**（`deviceCount`）：若两条腿在一侧使用完全相同的端点（ip:port 相同）而对端 IP 不同，则它们对端的两个 IP 实际是同一台设备（一个 FS RTP 会话只有一对端），归入同一设备。归并后再统计真实设备数，与 ≤ 2 的阈值比较。

修复后该样本识别为一通通话，A/B 两条腿（两个 Call-ID）正确归并，NAT 别名 IP 不再顶爆计数。

## 问题 2：回放清单出现未知 IP

### 原因

FS 的下行音频发往主叫 SDP 宣告的私网地址 10.22.68.170，该地址不在信令识别的通话三方（主叫/被叫/FS）内，回放清单按原始地址生成了"未知 IP"条目。

### 修复

- `CallInfo` 新增 `sdpPartyIps`：从各腿 SDP 宣告端点（`sdpEndpointsByCid` × `legCodecs`）提取的双方附加 IP；
- `CallParties` 新增 `callerAltIps` / `answererAltIps`，`mediaExtractor` 的 `partyLabel` 命中别名时同样标注为"主叫/被叫 + 终端标识"。10.22.68.170 现在正确显示为"主叫 LTU4LinePhoneTest02 的另一个地址"。

## 问题 3：FS 收到上行却不回发——单向转发缺失检测（`partial_downlink`）

### 抓包定位结论（以样本为例）

FS 收到被叫音频上行 1555 包，但整通 31 秒内向被叫的音频下行 **0 包**。判定为 FS 侧问题的证据链：

- 被叫音频 RTCP SR 的 *Reception report count = 0* 持续到通话结束——终端自己宣告从未收到音频；
- 同一对 IP 上 FS → 被叫的 H264 视频下发 1495 包、被叫视频 RR 显示 0% 丢包——网络路径畅通，排除链路/防火墙/NAT；
- 双方 SDP 均为干净 `sendrecv` PCMA，无方向限制、无编码不匹配——排除信令；
- FS → 主叫方向的音频下发（1819 包）正常——FS 自身的发送能力没问题。

排查方向收敛在 FS 的 B 腿音频发送通道：bridge 是否真正建立、write codec 是否激活（`uuid_dump` / `show channels`）、有无 bypass_media 或媒体方向相关的特殊配置。

### 检测实现

`fsRelayVerdict` 新增判定分支 **`partial_downlink`**（单向转发缺失，听者侧单通）：

- 触发条件：无 SDP 透传改道、全部端点都有上行，但 FS 收到某端对端的某类媒体后对该端 0 回发；
- 判定链：`redirected` → `no_relay` → `partial_uplink` → `partial_downlink` → `relayed`；
- 归类：`problemTaxonomy` 与 `reporter` 中与 `redirected` / `no_relay` 同级，归入 `one_way_audio`，**critical**；
- 建议文案指向 FS 侧发送通道（bridge / write codec / uuid_dump / bypass 配置），明确"不是网络问题"。

配套修复了统计归并中的一个误报：FS 下行按对端 SDP 宣告地址发送，NAT 场景下该地址与端的上行来源不同，原统计会把同一下行拆给一台"幻影设备"。现在统计循环内构建 `aliasToParty` 映射（SDP 宣告地址 → 信令识别的端 IP），下行归并到真实设备，并生成一条提示：NAT 场景下若该端收不到下行，检查 FS 的 `rtp-auto-adjust`（RTP 对端地址自动调整）配置。

## 验证

复现/回归脚本（在 `rtpshark/` 下运行，样本路径按需替换）：

```bash
pnpm exec tsc --noEmit
pnpm dlx tsx test/reproRelayVerdict.ts /Users/mugbya/Desktop/fs-2026-09-20-01.pcap
pnpm dlx tsx test/reproCallCount.ts
pnpm dlx tsx test/reproRealManifest.ts /Users/mugbya/Desktop/fs-2026-09-20-01.pcap
pnpm dlx tsx test/reproManifestAll.ts /Users/mugbya/Desktop/fs-2026-09-20-01.pcap
pnpm dlx tsx test/reproLadderNat.ts /Users/mugbya/Desktop/fs-2026-09-20-01.pcap
```

- `reproRelayVerdict`：判定为 `partial_downlink`，主叫设备下行恢复为音频 1819 包（别名归并生效），headline 精确指向"被叫端缺音频下发（对端上行 1823 包，FS 回发 0 包）"，附 NAT `rtp-auto-adjust` 提示；
- `reproCallCount`：基线 / NAT / SSRC 重写 / 残留信令 / 并发等全部用例通过（"时钟偏差"用例为本次改动前即存在的跨抓包时钟偏移问题，与本次无关）；
- 回放清单与分类清单 repro 输出正常，未知 IP 已归并到主叫标签下。

## 展示层：把 NAT 与协商端口摆到明面上

排查 NAT 场景问题时，光在通话卡片里"判定对了"还不够——分析者需要直接看到"谁宣告了哪个地址、协商用了哪些端口"。为此：

### SIP 信令阶梯图（`src/ui/Ladder.tsx`）

- `SipFlowItem` 新增 `sdpMedia`：每条带 SDP 的消息里宣告的媒体地址/端口（`kind/addr/port`，同值去重）；
- 每条带 SDP 的消息行后插入"SDP 协商媒体"行，逐路展示 `🎵 音频 ip:port` / `🎬 视频 ip:port`——当时协商用了哪些端口一目了然；
- **NAT 红色标注**：宣告地址不在本消息双方信令 IP 之内的，用红色 `⚠NAT` 徽章标出，并在 tooltip 里注明归属与实际发流地址。判定链：`sdpPartyIps` 按腿角色命中 → "主叫/被叫在 SDP 里宣告的另一个地址（NAT）：RTP 实际从 {信令 IP} 发来——属于主叫/被叫那一端，不是其他通话的设备"；未命中角色的未知地址也给通用提示。信令 IP（如被叫宣告自己的公网地址）不会误标；
- 同一条腿重复协商且端口不变时不重复展示。

样本上的实际效果：主叫 INVITE 的 SDP 行显示红色 `🎵 音频 10.22.68.170:10002 ⚠NAT`（tooltip：实际从 172.110.249.67 发来），FS 应答与被叫 200 OK 的协商端口正常灰色展示。

### 音视频回放卡片（`mediaExtractor` / `pipeline` / `ResultsView`）

- `MediaPartyEndpoint` 新增 `nat` 标记：`describeMediaParties` 标注收发方时，地址归属某端但不是该端信令 IP 的（即 `callerAltIps` / `answererAltIps` 命中）置位；
- `MediaEntry` 透传为 `natIps`，回放卡片在徽章行显示红色 `⚠ NAT 地址 {ip}`，tooltip 说明"仍属于本通通话的主叫/被叫，不是其他通话的设备"。

样本上的实际效果："FS → 主叫" 音频流的收端 10.22.68.170 显示红色 NAT 徽章；其余流不受影响。

## Python 版（rtp-stream-analyzer）同源移植

以上三项核心修复与配套的 NAT 统计归并已同步移植到本仓库的 Python 实现（2026-09-20）：

- `src/analyzer/call_detector.py`
  - `refine_calls` 半呼叫合并的设备计数改为 `_device_count`：非服务器 IP 并集上做并查集别名归并——共享同一端点（ip:port 相同）的两条腿，另一侧 IP 视为同一台设备；NAT 别名 IP 不再顶爆 ≤2 阈值把 A/B 腿拆成两通；
  - `_fs_relay_verdict` 新增 `partial_downlink` 分支（无改道、全部端点都有上行、FS 收到某端对端上行却 0 回发同类媒体），判定链 `redirected → no_relay → partial_uplink → partial_downlink → relayed`；统计前按 `sdp_endpoints_by_cid × leg_codecs` 构建 SDP 宣告地址 → 端 IP 的别名映射，下行归并到真实设备，并生成 `rtp-auto-adjust` 配置提示；
  - `detect_calls` 结果新增 `sdp_party_ips`（各腿 SDP 宣告的非服务器 IP，按主叫/被叫腿分组）；
  - `build_sip_flows` 的每条信令消息新增 `sdp_media`：该消息 SDP 当时宣告的媒体地址/端口（kind/addr/port，同值去重）；宣告地址不在本消息双方信令 IP 之内的置 `nat` 并按腿角色给 `owner`（主叫/被叫）与 `via_ip`（该端 RTP 实际来源的信令 IP），信令 IP 不会误标。
- `web/templates/results.html`（信令阶梯图）
  - 每条带 SDP 的消息行下插入「协商媒体」行，逐路展示 🎵 音频 ip:port / 🎬 视频 ip:port——当时协商用了哪些端口一目了然；
  - NAT 地址标红色 `⚠NAT` 徽章，tooltip 注明归属与实际发流地址（"主叫/被叫在 SDP 里宣告的另一个地址（NAT）：RTP 实际从 {信令 IP} 发来——属于主叫/被叫那一端，不是其他通话的设备"）；
  - 同一条腿重复协商且端口不变时不重复展示（按 Call-ID 去重）。
- `src/analyzer/media_extractor.py`
  - `extract_call_parties` 新增 `caller_alt_ips` / `answerer_alt_ips`（该端 SDP 宣告 IP 里除信令 IP 外的别名，同一 IP 两腿都宣告过的不算别名）；
  - `_party_label` 命中别名时同样标注"主叫/被叫"，NAT 私网地址不再显示为"未知 IP"；
  - `describe_media_parties` 的流标注新增 `flow.from/to.nat` 布尔标记（收发地址命中别名时置位），供展示层加 NAT 徽章。
- `src/analyzer/problem_taxonomy.py` / `src/analyzer/reporter.py`：`partial_downlink` 与 `redirected` / `no_relay` 同级归入 `one_way_audio`，**critical**。
- 测试：`tests/test_call_detector.py` 新增 `test_nat_call_merge_and_alias_downlink`（NAT 一通合一 + 别名下行归并 + rtp-auto-adjust 提示 + alt-IP 标注）、`test_fs_relay_partial_downlink`、`test_partial_downlink_not_when_partial_uplink`（判定优先级回归）；`tests/test_media_labels.py` 更新流标注结构（`nat` 字段）。

回放区"媒体链路 / 每张流卡片的媒体行"为 rtpshark（TS/React）侧实现，Python 版的 Web 模板暂未引入对应组件，流级 `nat` 标记已随 `flow` 数据导出，后续展示可直取；信令阶梯图的「协商媒体」行与 NAT 红标已在 Python 版实现（见上）。

### 回放补实际媒体地址（三段式/两段式组头 + 每张流卡片）

回放区的"主叫 → 服务端 → 被叫"（三段式）与直连（两段式）组头原本只有称呼，看不出实际收发地址。补齐两处：

- **组头下加"媒体链路"行**：按拓扑（`manifest.parties`）展示实际 IP 链路，如 `媒体链路 172.110.249.67 → 172.110.3.151 → 172.110.249.65`（反向组自动倒序）；直连组同样映射两端 IP；
- **每张流卡片加"媒体"行**：展示抓包点视角的真实 `src:port → dst:port`，如 FS→主叫卡片显示 `媒体 172.110.3.151:22532 → 10.22.68.170:10002`——NAT 场景下能直接看出这段流实际发往哪个 IP。数据由 `MediaPartyEndpoint` 新增的 `port` 字段经 `MediaEntry.flowIps` 透传。
