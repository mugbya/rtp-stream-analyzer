# 服务器安装 FFmpeg（Rocky Linux）

> 适用：RTP Stream Analyzer 的部署服务器（Rocky 8/9，RHEL 系通用）。
> 本项目服务器（Rocky 9）已按「方式一：RPM Fusion 源」装好 ffmpeg 5.1.10，此文档同时作为重装/换机时的 runbook。

## 为什么需要

`analyzer/media_extractor.py` 用 `subprocess` 按 PATH 直接调用 `ffmpeg`（无绝对路径、无 Python 依赖包替代），用途是把 RTP 抓包里的 **OPUS 音频**解码成可播放的 WAV：

- **G.711 音频**：纯 Python 重建，**不依赖 ffmpeg**，没装也完全可用；
- **OPUS 音频**：必须 ffmpeg（RTP 载荷先封成 Ogg Opus，再交 ffmpeg 解码），未安装时页面提示「OPUS 音频需要 ffmpeg 解码（未检测到 ffmpeg）」，其余功能不受影响。

与 CI 无关：GitHub Actions 的测试机每次全新环境，工作流里会自己 `apt install ffmpeg`；本文档只管服务器运行环境。

## 方式一：RPM Fusion 源（推荐）

ffmpeg 因授权原因不在 RHEL/Rocky 官方源，标准做法是 EPEL + CRB + RPM Fusion 三件套，root 执行：

```bash
# 1. EPEL 源
dnf install -y epel-release

# 2. 启用 CRB（CodeReady Builder）；Rocky 8 上该仓库叫 powertools：
#    dnf config-manager --set-enabled powertools
dnf config-manager --set-enabled crb

# 3. RPM Fusion free 源（中科大镜像国内快；官方地址
#    https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-$(rpm -E %rhel).noarch.rpm 较慢）
dnf install -y https://mirrors.ustc.edu.cn/rpmfusion/free/el/rpmfusion-free-release-$(rpm -E %rhel).noarch.rpm

# 4. 安装
dnf install -y ffmpeg
```

`$(rpm -E %rhel)` 会自动展开成 8 或 9，无需手改。

### 验证

```bash
ffmpeg -version | head -3
# 应输出版本信息；确认 configuration 里带 --enable-libopus（OPUS 解码必需，RPM Fusion 版自带）
ffmpeg -encoders 2>/dev/null | grep -w libopus
# 应输出 ... V... libopus  libopus Opus ...
```

## 方式二：静态编译版（不想加源时）

```bash
curl -LO https://johnvansickle.com/ffmpeg/releases/ffmpeg-release-amd64-static.tar.xz
tar xf ffmpeg-release-amd64-static.tar.xz
install -m 755 ffmpeg-*-amd64-static/ffmpeg /usr/local/bin/ffmpeg
ffmpeg -version
```

- 单文件、零依赖；该站点国内访问可能慢，可先本地下载再 `scp` 上去；
- `/usr/local/bin` 在 systemd 服务的默认 PATH 里，同样无需改单元文件。

## 常见问题

| 现象 | 原因/处理 |
| --- | --- |
| `dnf config-manager` 报无 crb 仓库 | Rocky 8 仓库名是 `powertools`，换命令 |
| RPM Fusion 包 GPG 校验失败 / 镜像缺包 | 换官方地址 mirrors.rpmfusion.org 重试，或换其他国内镜像 |
| 应用仍提示「未检测到 ffmpeg」 | `which ffmpeg` 确认在 `/usr/bin` 或 `/usr/local/bin`；服务刚装完不用重启，subprocess 每次新起进程，PATH 有即可 |
| `ffmpeg: error while loading shared libraries` | 静态版误装了动态依赖版；用方式一或确认下的是 `*-static` 包 |
