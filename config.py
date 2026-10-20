"""集中配置 —— 所有可调参数都在这一个文件里，改这里即可，无需翻业务代码。

部分参数支持环境变量覆盖（本地调试/容器化时不用改代码），
未列出环境变量的参数直接改本文件的值。
"""
import os

# 仓库根目录（config.py 所在目录），运行时目录均以它为基准
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv(path):
    """把 .env 里的 KEY=VALUE 灌进环境变量（真实环境变量优先，不覆盖）。

    不引入 python-dotenv 依赖：只支持 KEY=VALUE 与 # 注释行，值两侧成对
    的单/双引号会剥掉。.env 被 .gitignore 忽略，本机与生产各自的私密
    配置（如 COS 桶地址）写在这个文件里，不必改动被 git 管理的文件。
    """
    try:
        with open(path, encoding='utf-8') as fp:
            lines = fp.readlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


# 必须在读任何环境变量之前加载（下面 HOST/PORT/COS_DOWNLOAD_BASE 等都吃它）
_load_dotenv(os.path.join(BASE_DIR, '.env'))

# ---------------------------------------------------------------------------
# Web 服务
# ---------------------------------------------------------------------------
HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
PORT = int(os.environ.get('FLASK_PORT', '5050'))
# 默认 True（本地 python src/app.py 调试）；systemd 部署设 FLASK_DEBUG=0 走 gunicorn 生产模式
DEBUG = os.environ.get('FLASK_DEBUG', '1') == '1'

# ---------------------------------------------------------------------------
# 多语言（按访问域名切语言，一套代码一套部署）
# ---------------------------------------------------------------------------
# 域名（去掉端口、小写）→ 界面语言。未列出的域名用 DEFAULT_LANGUAGE。
# 实现方式：中文字典整体替换（src/i18n.py），英文站把渲染结果/接口数据里的
# 中文按字典换成英文，字典没有的条目保持中文兜底。
DOMAIN_LANGUAGES = {
    'rtp-analyzer.com': 'en',   # 英文站
    'rtp-analyzer.cn': 'zh',    # 中文站
    'rtp-analyzer.site': 'zh',  # 中文站
}
DEFAULT_LANGUAGE = 'zh'

# ---------------------------------------------------------------------------
# 目录
# ---------------------------------------------------------------------------
DATA_DIR = os.path.join(BASE_DIR, 'data')        # 持久数据（不被自动清理）
RUNTIME_DIR = os.path.join(BASE_DIR, 'var')      # 易失运行时数据（自动清理）

# 上传的抓包与生成的媒体文件，按保留时长自动清理
UPLOAD_FOLDER = os.path.join(RUNTIME_DIR, 'uploads')
OUTPUT_FOLDER = os.path.join(RUNTIME_DIR, 'outputs')

# 桌面版安装包下载目录：把安装包放进这里，/download 页面自动列出。
# 位于 DATA_DIR，是持久数据，不会被自动清理线程删除
DOWNLOADS_DIR = os.path.join(DATA_DIR, 'downloads')

# 腾讯云 COS 下载源（可选）。配置后 /download 页会自动列出 COS 桶里的安装包，
# 下载直连 COS/CDN 不占用本机带宽；往 COS 上传/替换文件，页面自动更新。
# 取值形如 https://<bucket-appid>.cos.<region>.myqcloud.com
# 要求桶允许匿名列举（公有读权限）；未配置或列举失败时只展示本地目录
COS_DOWNLOAD_BASE = os.environ.get('COS_DOWNLOAD_BASE', '')
# COS 列举结果缓存秒数：避免每次打开下载页都请求 COS
COS_LIST_CACHE_SECONDS = 60

# GitHub Releases 备用下载渠道（可选）。填仓库地址即可，下载页顶部会出现
# "也可从 GitHub Releases 下载"入口并展示最新版本号；国内访问 GitHub 不稳，
# 页面清单仍以 COS/本地目录为主，这里只是第二渠道
GITHUB_REPO_URL = os.environ.get('GITHUB_REPO_URL', '')
# 最新版本号查询结果缓存秒数（GitHub 未认证 API 限流 60 次/小时/IP）
GITHUB_RELEASE_CACHE_SECONDS = 600

# ---------------------------------------------------------------------------
# 上传限制
# ---------------------------------------------------------------------------
MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 单次上传总大小上限：500MB

# 解析结果缓存阈值：分析阶段复用已解析过的抓包（含载荷），同一会话换
# 媒体类型/换通话重跑时不再重复解析。超过该大小的抓包不缓存（载荷占
# 内存大），改为每次分析时现解析
PARSE_CACHE_MAX_BYTES = 100 * 1024 * 1024  # 100MB

# ---------------------------------------------------------------------------
# 自动清理：outputs（媒体文件）与 uploads（上传的抓包）超过保留时长
# 即被后台线程删除，两处共用同一保留时长
# ---------------------------------------------------------------------------
FILE_RETENTION_HOURS = 2            # 保留时长（小时）
FILE_CLEANUP_INTERVAL_MINUTES = 10  # 清理巡检间隔（分钟）

# ---------------------------------------------------------------------------
# 访问统计（src/stats.py）
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(DATA_DIR, 'stats.db')
ADMIN_KEY_PATH = os.path.join(DATA_DIR, 'admin_key.txt')
XDB_PATH = os.path.join(DATA_DIR, 'ip2region.xdb')
