"""
访问/使用统计 —— SQLite 存储 + ip2region 离线地域解析

记录两类事件：
- 访问（页面打开）：谁（cookie 去重）在什么时间、从哪个省市、看了哪个页面
- 分析（执行分析）：一次成功完成的分析，附带媒体类型/通话

给 /admin/stats 管理页提供汇总查询。全部尽力而为：统计出错不能影响主业务，
所有对外函数内部兜底吞异常。
"""
import os
import sys

# 与 src/app.py 相同的路径引导：仓库根目录（config.py）加入 sys.path
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

import re
import sqlite3
import threading
import time
import uuid

from ip2region import searcher as xdb_searcher
from ip2region import util as xdb_util

import config

# 数据与密钥都放 data/ 下（已在 .gitignore 排除运行时文件），路径集中在 config.py
DATA_DIR = config.DATA_DIR
DB_PATH = config.DB_PATH
ADMIN_KEY_PATH = config.ADMIN_KEY_PATH
XDB_PATH = config.XDB_PATH

_visitor_cookie = 'vid'      # 访客去重 cookie（一年有效）
_admin_cookie = 'admin_key'  # 管理页校验通过后种的免登录 cookie

# xdb 全量载入内存（约 11MB，查询零 IO），进程内只建一次
_xdb_lock = threading.Lock()
_xdb_buffer = None


def _load_xdb():
    global _xdb_buffer
    if _xdb_buffer is None:
        with _xdb_lock:
            if _xdb_buffer is None and os.path.isfile(XDB_PATH):
                _xdb_buffer = xdb_util.load_content_from_file(XDB_PATH)
    return _xdb_buffer


def client_ip(request):
    """访客真实 IP：Nginx 反代已把原地址写入 X-Real-IP，直连时退回 remote_addr。"""
    ip = (request.headers.get('X-Real-IP') or '').strip()
    return ip or (request.remote_addr or '')


def lookup_region(ip):
    """IP → (省, 市)。解析失败/内网地址返回 ('未知', '')。"""
    if not ip or not _load_xdb():
        return '未知', ''
    # 内网/回环/保留地址不在库里，直接标注，避免落成误导性的"未知"
    if (ip.startswith('127.') or ip.startswith('10.') or
            ip.startswith('192.168.') or ip.startswith('169.254.')):
        return '内网/本地', ''
    m = re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip)
    if m or ip.startswith('fc') or ip.startswith('fd') or ip.startswith('fe80'):
        return '内网/本地', ''
    try:
        s = xdb_searcher.new_with_buffer(xdb_util.IPv4, _xdb_buffer)
        # v4 库字段：国家|省份|城市|运营商|国家码，"0" 表示缺省
        parts = s.search(ip).split('|')
        province = parts[1] if len(parts) > 1 and parts[1] != '0' else ''
        city = parts[2] if len(parts) > 2 and parts[2] != '0' else ''
        if province == 'Reserved':
            return '内网/本地', ''
        return province or '未知', city
    except Exception:
        return '未知', ''


def ensure_visitor_id(request):
    """取访客去重 ID：已有 cookie 直接用，没有则生成（由调用方种回响应）。"""
    return request.cookies.get(_visitor_cookie) or uuid.uuid4().hex


def visitor_cookie_name():
    return _visitor_cookie


def admin_cookie_name():
    return _admin_cookie


def get_admin_key():
    """管理页密钥：优先环境变量 ADMIN_STATS_KEY；否则首次访问自动生成并
    落盘 data/admin_key.txt（journalctl 启动日志里也会提示取法）。"""
    key = os.environ.get('ADMIN_STATS_KEY', '').strip()
    if key:
        return key
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.isfile(ADMIN_KEY_PATH):
            with open(ADMIN_KEY_PATH, encoding='utf-8') as f:
                key = f.read().strip()
            if key:
                return key
        key = uuid.uuid4().hex
        with open(ADMIN_KEY_PATH, 'w', encoding='utf-8') as f:
            f.write(key)
        return key
    except Exception:
        return ''


# --- SQLite ---

def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=10000')
    return conn


def _init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    with _connect() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                day TEXT NOT NULL,
                vid TEXT NOT NULL,
                ip TEXT DEFAULT '',
                province TEXT DEFAULT '',
                city TEXT DEFAULT '',
                path TEXT DEFAULT '',
                domain TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_visits_day ON visits(day);
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                day TEXT NOT NULL,
                vid TEXT NOT NULL,
                ip TEXT DEFAULT '',
                province TEXT DEFAULT '',
                city TEXT DEFAULT '',
                session_id TEXT DEFAULT '',
                media_type TEXT DEFAULT '',
                call_id TEXT DEFAULT '',
                domain TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_analyses_day ON analyses(day);
        ''')


def _migrate():
    """给早期建的库补新列（CREATE IF NOT EXISTS 不会改已有表结构）。"""
    with _connect() as conn:
        for table in ('visits', 'analyses'):
            cols = {r[1] for r in conn.execute(f'PRAGMA table_info({table})')}
            if 'domain' not in cols:
                conn.execute(
                    f'ALTER TABLE {table} ADD COLUMN domain TEXT DEFAULT ""')


_init_db()
_migrate()


def request_domain(request):
    """访客来自哪个域名：Nginx 已把 $host 写进 Host 头，去掉端口即可。"""
    return (request.host or '').split(':')[0].strip().lower()


def record_visit(vid, ip, path, domain=''):
    try:
        province, city = lookup_region(ip)
        now = time.time()
        with _connect() as conn:
            conn.execute(
                'INSERT INTO visits (ts, day, vid, ip, province, city, '
                'path, domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (int(now), time.strftime('%Y-%m-%d', time.localtime(now)),
                 vid, ip, province, city, path, domain or ''))
    except Exception:
        pass  # 统计是旁路功能，任何失败都不影响主流程


def record_analysis(vid, ip, session_id, media_type, call_id, domain=''):
    try:
        province, city = lookup_region(ip)
        now = time.time()
        with _connect() as conn:
            conn.execute(
                'INSERT INTO analyses (ts, day, vid, ip, province, city, '
                'session_id, media_type, call_id, domain) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (int(now), time.strftime('%Y-%m-%d', time.localtime(now)),
                 vid, ip, province, city, session_id or '',
                 media_type or '', str(call_id or ''), domain or ''))
    except Exception:
        pass


# --- 管理页查询 ---

def _q(sql, args=()):
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def _mask_ip(ip):
    """展示用 IP 打码：223.104.5.66 → 223.104.5.*，非 IPv4 原样。"""
    parts = ip.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return '.'.join(parts[:3]) + '.*'
    return (ip[:8] + '…') if len(ip) > 12 else ip


def query_summary():
    """今日/累计的访问与执行数据（PV=浏览量，UV=按访客 cookie 去重）。"""
    today = time.strftime('%Y-%m-%d')
    rows = _q('''
        SELECT
          (SELECT COUNT(*) FROM visits) AS pv_total,
          (SELECT COUNT(DISTINCT vid) FROM visits) AS uv_total,
          (SELECT COUNT(*) FROM visits WHERE day=?) AS pv_today,
          (SELECT COUNT(DISTINCT vid) FROM visits WHERE day=?) AS uv_today,
          (SELECT COUNT(*) FROM analyses) AS an_total,
          (SELECT COUNT(DISTINCT vid) FROM analyses) AS an_uv_total,
          (SELECT COUNT(*) FROM analyses WHERE day=?) AS an_today,
          (SELECT COUNT(DISTINCT vid) FROM analyses WHERE day=?) AS an_uv_today
    ''', (today, today, today, today))
    return rows[0] if rows else {}


def query_daily(days=30):
    """近 N 天逐日：浏览量 / 访客数 / 分析次数 / 执行分析人数。"""
    return _q('''
        SELECT d.day,
               COALESCE(v.pv, 0) AS pv,
               COALESCE(v.uv, 0) AS uv,
               COALESCE(a.cnt, 0) AS analyses,
               COALESCE(a.uv, 0) AS analysts
        FROM (SELECT day FROM visits GROUP BY day
              UNION
              SELECT day FROM analyses GROUP BY day) d
        LEFT JOIN (SELECT day, COUNT(*) pv, COUNT(DISTINCT vid) uv
                   FROM visits GROUP BY day) v ON v.day = d.day
        LEFT JOIN (SELECT day, COUNT(*) cnt, COUNT(DISTINCT vid) uv
                   FROM analyses GROUP BY day) a ON a.day = d.day
        ORDER BY d.day DESC LIMIT ?
    ''', (days,))


def query_regions(limit=50):
    """地域分布：省 → 市，各自的访客数、浏览量、分析次数。"""
    return _q('''
        SELECT v.province, v.city, v.uv, v.pv,
               COALESCE(a.cnt, 0) AS analyses
        FROM (SELECT province, city,
                     COUNT(DISTINCT vid) AS uv, COUNT(*) AS pv
              FROM visits WHERE province != ''
              GROUP BY province, city ORDER BY pv DESC LIMIT ?) v
        LEFT JOIN (SELECT province, city, COUNT(*) AS cnt
                   FROM analyses GROUP BY province, city) a
          ON a.province = v.province AND a.city = v.city
    ''', (limit,))


def query_domains(limit=10):
    """域名来源分布：各域名的访客数、浏览量、分析次数。"""
    return _q('''
        SELECT v.domain,
               v.uv, v.pv,
               COALESCE(a.cnt, 0) AS analyses
        FROM (SELECT domain,
                     COUNT(DISTINCT vid) AS uv, COUNT(*) AS pv
              FROM visits
              GROUP BY domain ORDER BY pv DESC LIMIT ?) v
        LEFT JOIN (SELECT domain, COUNT(*) AS cnt
                   FROM analyses GROUP BY domain) a
          ON a.domain = v.domain
    ''', (limit,))


def query_recent_visits(limit=50):
    rows = _q('SELECT * FROM visits ORDER BY id DESC LIMIT ?', (limit,))
    for r in rows:
        r['ip_masked'] = _mask_ip(r['ip'])
        r['time'] = time.strftime('%m-%d %H:%M:%S', time.localtime(r['ts']))
    return rows


def query_recent_analyses(limit=50):
    rows = _q('SELECT * FROM analyses ORDER BY id DESC LIMIT ?', (limit,))
    for r in rows:
        r['ip_masked'] = _mask_ip(r['ip'])
        r['time'] = time.strftime('%m-%d %H:%M:%S', time.localtime(r['ts']))
    return rows
