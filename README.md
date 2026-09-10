# RTP Stream Analyzer

VoIP 通话 RTP 音视频流分析平台。上传抓包文件（pcap/pcapng），自动分析**延迟、抖动、丢包**，并从 RTP 流**重建音频/视频供回放**。

## 功能

### 1. 延迟 / 抖动 / 丢包分析
- **FS 内部处理延迟**：在 FS 抓包中匹配入站/出站 SSRC 对，测量转发耗时
- **跨抓包传输延迟**：同一 SSRC 在不同抓包点的到达时间差（自动修正抓包机器间的时钟偏移）
- **端到端延迟估算**：FS 延迟 + 网络传输
- **抖动分析**：包间隔稳定性（均值/中位数/标准差/P95/P99/异常间隔）
- **丢包检测**：基于 RTP 序列号连续性
- 生成 9 面板分析图表 + 结构化结论报告（含问题分级与根因建议）

### 2. 音视频重建与回放
- **音频**：从 RTP 载荷重建 G.711 PCMU（μ-law）/ PCMA（A-law）为 WAV 文件
  - 按序列号排序，丢包位置自动补静音
  - 按抓包文件（坐席/FS/终端）分组，区分**呼出（该端发送）**与**呼入（该端接收）**
- **视频**：H.264 流去分片（FU-A/STAP-A，RFC 6184）导出裸流，调用 ffmpeg 转换为 MP4
- 网页内直接播放 / 下载

### 3. 自适应抓包数量
支持上传 1~3 个抓包文件（坐席端 / FS 端 / 终端端任意组合），系统自动识别可用分析项：

| 上传组合 | 可用分析 |
|---|---|
| 单端 | 抖动 + 丢包 |
| 坐席 + FS | 坐席↔FS 传输延迟 + FS 内部延迟 |
| FS + 终端 | FS↔终端 传输延迟 + FS 内部延迟 |
| 三端齐全 | 端到端延迟 + 全部分析项 |

## 环境要求

- Python 3.8+（开发环境为 3.11）
- **ffmpeg**（可选，视频转 MP4 需要）：`brew install ffmpeg`
- 其余依赖见 `requirements.txt`

## 安装

```bash
cd rtp-stream-analyzer
pip3 install -r requirements.txt
```

## 启动

```bash
python3 app.py
```

浏览器访问 **http://localhost:5050**

## 使用流程

1. **上传**：选择 1~3 个抓包文件（pcap/pcapng），点击「上传并识别」
2. **确认识别结果**：系统显示检测到的服务器 IP、音频/视频流数量
3. **选择分析参数**：延迟方向（自动根据上传文件列出可选项）+ 媒体类型（音频/视频/全部）
4. **查看结果**：摘要卡片 → 9 面板图表 → 音视频回放 → 详细报告
5. **回放媒体**：在「音视频回放」区按端点分组试听/观看，可下载

## 项目结构

```
rtp-stream-analyzer/
├── app.py                       # Flask 主入口
├── requirements.txt
├── README.md
├── analyzer/
│   ├── rtp_parser.py            # RTP 解析（含载荷提取）
│   ├── stream_classifier.py     # 音频/视频流分类、方向识别
│   ├── delay_analyzer.py        # 延迟分析（FS内部/跨抓包/时钟偏移修正）
│   ├── jitter_analyzer.py       # 抖动分析
│   ├── packet_loss.py           # 丢包检测
│   ├── media_extractor.py       # 音频/视频重建（G.711→WAV、H.264→MP4）
│   ├── charts.py                # matplotlib 图表生成
│   └── reporter.py              # 汇总报告
├── templates/
│   ├── base.html                # Bootstrap 5 基础模板
│   ├── index.html               # 上传+配置+结果页
│   └── results.html             # 独立结果页（含媒体回放）
├── static/
│   ├── css/style.css
│   └── js/app.js
├── uploads/<session_id>/        # 上传的抓包文件
└── outputs/                     # 生成的媒体与图表
```

## 输出目录与清理

生成的音频/视频按**日期**组织，便于定期清理：

```
outputs/
├── 2026-09-11/                  # 按天分目录
│   └── <session_id>/
│       ├── audio/
│       │   ├── seat_outbound_0x1234abcd.wav    # 坐席端发送的音频
│       │   ├── seat_inbound_0x5678ef01.wav     # 坐席端接收的音频
│       │   ├── fs_inbound_0x9abc2345.wav
│       │   └── terminal_inbound_0xdef06789.wav
│       ├── video/
│       │   ├── seat_outbound_0xaaaa1111.mp4    # H.264 → MP4
│       │   └── seat_outbound_0xaaaa1111.h264   # 原始裸流（ffmpeg 失败时保留）
│       └── media_manifest.json   # 媒体清单（含每个流的元信息）
└── chart_xxx.png                 # 分析图表
```

### 清理脚本（crontab 示例）

```bash
# 删除 30 天前的媒体输出（按日期目录名判断）
find outputs/ -maxdepth 1 -type d -name "20[2-9][0-9]-[0-9][0-9]-[0-9][0-9]" -mtime +30 -exec rm -rf {} +

# 同时清理对应的上传文件（按 mtime）
find uploads/ -mindepth 1 -maxdepth 1 -type d -mtime +30 -exec rm -rf {} +
```

> 注意：会话数据存在内存中（`sessions` 字典），重启后丢失。媒体文件在磁盘上，靠上述脚本清理。

## API

| 路由 | 方法 | 说明 |
|---|---|---|
| `/` | GET | 主页 |
| `/api/upload` | POST | 上传抓包（multipart，字段名 seat/fs/terminal） |
| `/api/analyze` | POST | 执行分析 `{"session_id", "direction", "media_type"}` |
| `/api/session/<id>` | GET | 会话信息与结果（含 media_manifest） |
| `/media/<date>/<session_id>/...` | GET | 媒体文件（WAV/MP4） |
| `/charts/<filename>` | GET | 分析图表 PNG |
| `/results/<session_id>` | GET | 独立结果页 |

## 支持的编解码

| 类型 | 编解码 | 重建支持 |
|---|---|---|
| 音频 | G.711 PCMU (PT=0) | ✅ WAV |
| 音频 | G.711 PCMA (PT=8) | ✅ WAV |
| 音频 | GSM / G.722 / G.729 | ❌（页面会提示） |
| 视频 | H.264 (PT=96+) | ✅ MP4（需 ffmpeg）/ H.264 裸流 |

## 已知限制

- 时钟偏移：不同抓包机器时钟可能有数百毫秒偏差，跨抓包延迟会自动检测并修正，偏差过大时报告会给出警告
- 视频流按动态 PT（96-127）识别，若实际是 Opus 等动态音频 PT 会被误分为视频
- 重建音频时按 20ms/包 补静音，实际包长不同时会有轻微时长偏差
