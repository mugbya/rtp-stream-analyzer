# 自动部署说明

推送 `main` 分支后，GitHub Actions 自动：rsync 同步代码到服务器 → 首次部署自举（建 venv、装 systemd 单元）→ 更新依赖 → 重启服务 → 健康检查。失败会在 Actions 页面标红并保留现场。

```
git push origin main
        │
        ▼
rsync 代码 ──► /opt/rtp-stream-analyzer/app
                │  （venv 不存在则自动创建；systemd 单元随代码同步，有变化自动更新）
                ▼
pip install -r requirements.txt
systemctl restart rtp-stream-analyzer
curl http://127.0.0.1:5050/ 健康检查
        │
        ▼
Nginx (80→443, 多域名共用证书) ──► 127.0.0.1:5050
```

**服务器上不需要任何手动初始化**：SSH 免密、Python 环境你已就绪，venv 和 systemd 单元由工作流在首次部署时自举完成。

> 按你的选择，CI 不跑测试：部署后的健康检查（服务起得来、首页能访问）是唯一自动门禁。推送前想验证代码，本地跑一遍测试：`for f in tests/test_*.py; do python3 "$f"; done`

## 前置条件（都已满足/仅核对）

- root 可 SSH 登录服务器（公钥已配好）
- 服务器有 `python3` ≥ 3.9 且带 venv 模块、已装 `rsync`（部署过 Python 服务一般都有；没有就 `dnf install -y rsync`）
- 服务器已装 `ffmpeg`（OPUS 音频回放依赖，`media_extractor.py` 按 PATH 直接调用），安装步骤见 [docs/服务器安装-ffmpeg.md](../docs/服务器安装-ffmpeg.md)

## 一次性配置（共 3 步）

### 1. 生成部署密钥对（在你自己的电脑上）

```bash
ssh-keygen -t ed25519 -C "rtp-analyzer-deploy" -f rtp-analyzer-deploy -N ""
```

生成 `rtp-analyzer-deploy`（私钥，第 2 步用）和 `rtp-analyzer-deploy.pub`（公钥，追加到服务器 `/root/.ssh/authorized_keys`）。私钥别提交进仓库、别传给任何人。

### 2. 配置 GitHub Secrets

仓库页面 → **Settings → Secrets and variables → Actions → New repository secret**，添加：

| Secret | 值 | 说明 |
|---|---|---|
| `SSH_HOST` | 服务器 IP | |
| `SSH_USER` | `root` | 登录、服务、目录都用 root |
| `SSH_PORT` | `22` | 可选，改过 SSH 端口才需要 |
| `SSH_PRIVATE_KEY` | `rtp-analyzer-deploy` 文件全文 | 含 `BEGIN/END OPENSSH PRIVATE KEY` 首尾行 |

### 3. 推送代码

```bash
git push origin main
```

GitHub → Actions 页面能看到工作流运行；全绿即部署完成，服务已在服务器的 `127.0.0.1:5050` 运行。也可以在 Actions 页面手动 **Run workflow** 重新部署。

## Nginx 反代（80→443 HTTPS、多域名共用一张证书）

工作流只把服务跑在 `127.0.0.1:5050`，对外访问统一走你服务器上已有的 Nginx。HTTPS 用 acme.sh 签**一张多域名共用证书**，本服务和其他几个服务都引用它：

1. 编辑 [deploy/nginx-rtp-stream-analyzer.conf](nginx-rtp-stream-analyzer.conf)，把两处 `server_name` 换成你的**全部域名**（空格分隔，都指向这一个服务）；域名 DNS 解析到服务器 IP（你自己配置）
2. 服务器上签共用证书（acme.sh **DNS 验证**，域名在 DNSPod/腾讯云解析时直接可用，不依赖 nginx 状态、不要求 80 端口可达）：

```bash
~/.acme.sh/acme.sh --issue --server letsencrypt --dns dns_dp \
  -d rtp-analyzer.cn -d rtp-analyzer.com -d rtp-analyzer.site
```

3. 安装到固定路径并设置续期后自动重载（**先做这步再放配置**，否则 `nginx -t` 会因证书文件不存在而失败）：

```bash
~/.acme.sh/acme.sh --install-cert -d 主域名 \
  --fullchain-file /etc/nginx/ssl/shared.fullchain.pem \
  --key-file       /etc/nginx/ssl/shared.key.pem \
  --reloadcmd      "nginx -s reload"
```

4. 拷配置并重载：

```bash
scp deploy/nginx-rtp-stream-analyzer.conf root@服务器IP:/etc/nginx/conf.d/rtp-stream-analyzer.conf
nginx -t && systemctl reload nginx
```

之后 `https://任一域名/` 都访问同一个应用（80 自动跳 443）。以后要给证书加域名：重新执行第 2 步（域名列表写全、第一个 `-d` 不变），再执行一遍第 3 步即可；旧的单域证书可用 `acme.sh --remove -d 旧域名` 清理。配置里已处理大文件上传的坑：`client_max_body_size 600m`（默认 1MB 会 413）、5 分钟读写超时、上传不落盘缓冲。

## 日常发布

改完代码 `git push origin main` 即可。CI 不跑测试；测试套件还在 `tests/` 里，推送前想验证就在本地跑：`for f in tests/test_*.py; do python3 "$f"; done`。

## 运维命令

```bash
systemctl status rtp-stream-analyzer      # 服务状态
journalctl -u rtp-stream-analyzer -f      # 实时日志
journalctl -u rtp-stream-analyzer -n 200  # 最近 200 行
systemctl restart rtp-stream-analyzer
```

代码目录 `/opt/rtp-stream-analyzer/app`（Python 代码在其下的 `src/`，配置在根目录 `config.py`）；venv `/opt/rtp-stream-analyzer/venv`；上传的抓包和产出文件在应用目录的 `var/uploads/`、`var/outputs/`（超过保留时长自动清理，见 `config.py` 的 `FILE_RETENTION_HOURS`）。

## 生产模式说明

- 服务器上以 gunicorn 运行（单 worker + 8 线程，`FLASK_DEBUG=0`），本地 `python src/app.py` 仍是 debug 模式，互不影响。
- 分析会话存于应用进程内存，所以必须单 worker；改多进程会导致会话随机丢失。
- 按你的要求整套以 root 运行（SSH 与服务同账号）；以后想收紧权限，把 service 的 `User`/`Group` 改成专用账号并调整 `/opt/rtp-stream-analyzer` 属主即可。
- gunicorn 只监听 `127.0.0.1:5050`，不对公网暴露，入口只有 Nginx 的 80 端口。

## 故障排查

- **Actions 挂在 SSH keyscan/连接**：Secrets 填错（IP/端口/私钥），或安全组/防火墙没放行来自 GitHub Runner 的 22 端口。
- **挂在 venv 创建**：服务器 `python3 --version` 低于 3.9 或缺 venv 模块，`dnf install -y python3.12` 后重跑。
- **挂在 rsync**：服务器没装，`dnf install -y rsync` 后重跑。
- **健康检查失败**：`journalctl -u rtp-stream-analyzer -n 100`，常见是依赖安装失败或 5050 被占用。
- **Nginx 上传 413**：没拷贝上面的 Nginx 配置或没 reload，`client_max_body_size` 没生效。
- **域名访问不通**：按顺序查——① `dig A 域名 +short` 是否返回服务器 IP（证书的 DNS 验证不需要 A 记录，所以签发成功≠A 记录已加，漏加会导致只有这个域名打不开）；② DNS 没生效、Nginx 没 reload，或安全组没放行 80/443 端口；③ 本机 `curl -k -H 'Host: 你的域名' https://127.0.0.1/` 可区分是 Nginx 问题还是网络问题。
- **`nginx -t` 报证书文件不存在**：先完成 acme.sh 的 `--issue` + `--install-cert`（README「Nginx 反代」第 2、3 步），再放这个 server 配置。
- **`--install-cert` 报 `No such file or directory`**：acme.sh 不会自动建父目录，先 `mkdir -p /etc/nginx/ssl` 再重跑。
- **nginx 起不来报 `no start line: Expecting: TRUSTED CERTIFICATE`**：证书文件存在但内容无效（多半是 install-cert 没装成功留下的空文件），重跑 `--install-cert`，并确认文件开头是 `-----BEGIN CERTIFICATE-----`（`head -1` 查看）。
- **`--install-cert` 报 `fullchain.cer: No such file or directory`**：acme.sh 里的源证书残缺（上次 `--issue` 签发失败留下的），`--issue --force` 重签后再安装。
- **`--issue --nginx` 报 `It seems that the nginx config is not correct`**：nginx 模式签发前会自检 nginx 配置，配置本身有坏文件（如引用空证书）就整个卡住。改用 `--dns dns_dp` 验证（本部署默认方式），完全不碰 nginx。
- **DNS 验证报 `Invalid status ... NXDOMAIN looking up TXT`**：CA 在公网查不到这个域名（域名刚注册/NS 刚切到 DNSPod 还没生效，或注册商的 DNS 服务器没指向 DNSPod）。`dig NS 域名 +short` 看 NS 是否为 `*.dnspod.net`；NS 正常就等几分钟重跑，NS 不对先去注册商改 DNS 服务器。多域名签发是整单成败，可将未生效域名从列表去掉先签其余的，生效后再补签。

## 使用统计（/admin/stats）

访问人数、执行分析次数、访客省市分布由服务端自己统计（SQLite，`data/stats.db`，随服务自动建表），不依赖第三方统计服务。

- **访问人数**：首页/结果页打开时记录，种一年期 cookie（`vid`）做去重，页面展示 UV（去重人数）和 PV（浏览次数）。
- **执行分析**：`/api/analyze` 成功完成一次分析记一条，附带媒体类型与通话；无 cookie 的调用按 IP 去重。
- **地域**：用 ip2region 离线库（`data/ip2region.xdb`，随仓库分发）解析 Nginx 传来的 `X-Real-IP`，精确到省/市，全程不出网。
- **域名来源**：Nginx 转发时带上的 `Host` 头就是访客用的域名，访问与分析都会记录，管理页有各域名的分布对比。

### 访问统计页

无登录功能，靠密钥 URL 鉴权（密钥不对返回 404，不暴露页面存在）：

1. 取密钥：服务器上设置了 `ADMIN_STATS_KEY` 环境变量就用它；没设置则首次启动自动生成在 `data/admin_key.txt`：

   ```bash
   cat /opt/rtp-stream-analyzer/app/data/admin_key.txt
   ```

2. 首次访问：`https://你的域名/admin/stats?key=密钥` —— 校验通过后种一年期 cookie。
3. 之后直接打开 `https://你的域名/admin/stats` 即可。

页面内容：今日/累计的访问与执行汇总卡片、近 30 天逐日数据、域名来源分布、省/市地域分布、最近访问与最近分析明细（IP 展示时打码最后一段）。

### 注意事项

- 部署工作流已排除 `data/stats.db*` 与 `data/admin_key.txt`（运行时数据，rsync 不会覆盖/删除）；`data/ip2region.xdb` 随代码同步。
- xdb 数据文件约每月更新一次（IP 库会过期），想更新就到 [ip2region 发布页](https://github.com/lionsoul2014/ip2region/releases) 下载新版 `ip2region_v4.xdb` 覆盖 `data/ip2region.xdb`。
