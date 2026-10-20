"""桌面版下载页与安装包下载路由测试。"""
import os
import time

import pytest

import config
import stats as stats_mod


@pytest.fixture
def client(tmp_path, monkeypatch):
    # 下载目录与统计库都指向临时路径：不污染真实 data/ 目录
    dl = tmp_path / 'downloads'
    dl.mkdir()
    monkeypatch.setattr(config, 'DOWNLOADS_DIR', str(dl))
    monkeypatch.setattr(stats_mod, 'DB_PATH', str(tmp_path / 'stats.db'))
    # COS 下载源默认关闭，并清掉模块级列举缓存（避免用例间串味）
    monkeypatch.setattr(config, 'COS_DOWNLOAD_BASE', '')
    import app as app_mod
    app_mod._cos_list_cache['ts'] = 0.0
    app_mod._cos_list_cache['good'] = []

    from app import app as flask_app
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as c:
        yield c, dl


def _touch(path, mtime=None):
    path.write_bytes(b'installer-bytes')
    ts = mtime if mtime is not None else time.time()
    os.utime(path, (ts, ts))


def test_download_page_empty(client):
    c, _ = client
    resp = c.get('/download')
    assert resp.status_code == 200
    assert '暂无可供下载的安装包' in resp.get_data(as_text=True)


def test_download_page_groups_and_order(client):
    c, dl = client
    _touch(dl / 'analyzer-win64.exe')
    _touch(dl / 'analyzer.dmg')
    _touch(dl / 'analyzer.deb')
    _touch(dl / 'portable.zip')
    _touch(dl / '.hidden.exe')          # 隐藏文件不进清单
    (dl / 'subdir.exe').mkdir()         # 子目录不进清单

    html = c.get('/download').get_data(as_text=True)
    # 分组按 Windows → macOS → Linux → 其他 出现，空组不出现
    assert html.index('Windows') < html.index('macOS') < \
        html.index('Linux') < html.index('其他')
    for name in ('analyzer-win64.exe', 'analyzer.dmg',
                 'analyzer.deb', 'portable.zip'):
        assert name in html
    assert '.hidden.exe' not in html
    assert 'subdir' not in html


def test_download_file_serves_as_attachment(client):
    c, dl = client
    _touch(dl / 'analyzer-win64.exe')
    resp = c.get('/download/analyzer-win64.exe')
    assert resp.status_code == 200
    assert resp.data == b'installer-bytes'
    assert 'attachment' in resp.headers['Content-Disposition']


def test_download_file_missing(client):
    c, _ = client
    assert c.get('/download/no-such-file.exe').status_code == 404


def test_download_file_blocks_traversal(client):
    """目录穿越（../、绝对路径、隐藏文件）一律 404/403。"""
    c, _ = client
    assert c.get('/download/..%2f..%2fconfig.py').status_code == 404
    assert c.get('/download/.hidden.exe').status_code == 404
    assert c.get('/download/%2e%2e%2fdata%2fadmin_key.txt').status_code == 404


# ---------------------------------------------------------------------------
# COS 下载源：匿名列举 + 缓存 + 失败回退 + 与本地目录合并
# ---------------------------------------------------------------------------

COS_BASE = 'https://rtp-analyzer-123456.cos.ap-guangzhou.myqcloud.com'

COS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Contents><Key>RTPAnalyzer-2.0.0-win64.exe</Key><Size>52428800</Size><LastModified>2026-10-19T08:00:00.000Z</LastModified></Contents>
  <Contents><Key>RTPAnalyzer-2.0.0-arm64.dmg</Key><Size>62914560</Size><LastModified>2026-10-18T08:00:00.000Z</LastModified></Contents>
  <Contents><Key>docs/</Key><Size>0</Size><LastModified>2026-10-17T08:00:00.000Z</LastModified></Contents>
  <Contents><Key>.hidden.exe</Key><Size>1</Size><LastModified>2026-10-17T08:00:00.000Z</LastModified></Contents>
  <Contents><Key>version.json</Key><Size>120</Size><LastModified>2026-10-19T09:00:00.000Z</LastModified></Contents>
  <Contents><Key>rtpshark_0.4.0_macos_arm64.app.tar.gz</Key><Size>40960000</Size><LastModified>2026-10-19T09:00:00.000Z</LastModified></Contents>
  <Contents><Key>发布说明.txt</Key><Size>300</Size><LastModified>2026-10-19T09:00:00.000Z</LastModified></Contents>
</ListBucketResult>"""


@pytest.fixture
def cos_client(client, monkeypatch):
    """开启 COS 下载源，用桩函数替代真实 HTTP。"""
    import app as app_mod
    monkeypatch.setattr(config, 'COS_DOWNLOAD_BASE', COS_BASE)
    monkeypatch.setattr(config, 'COS_LIST_CACHE_SECONDS', 60)
    calls = []
    monkeypatch.setattr(app_mod, '_cos_http_get', lambda url: calls.append(url) or COS_XML.encode())
    c, dl = client
    return c, dl, calls


def test_cos_items_listed_with_direct_urls(cos_client):
    c, _dl, calls = cos_client
    html = c.get('/download').get_data(as_text=True)
    assert 'RTPAnalyzer-2.0.0-win64.exe' in html
    assert '50.0 MB' in html
    assert COS_BASE + '/RTPAnalyzer-2.0.0-win64.exe' in html
    assert COS_BASE + '/RTPAnalyzer-2.0.0-arm64.dmg' in html
    # 目录占位项、隐藏文件与 json/xml 元数据文件不进清单
    assert 'docs/' not in html
    assert '.hidden.exe' not in html
    assert 'version.json' not in html
    assert '.txt' not in html
    # updater 解包用的 .app.tar.gz 不进清单
    assert '.app.tar.gz' not in html
    # 芯片架构说明标签
    assert 'M 系列芯片（Apple Silicon）' in html
    assert '64 位（Intel/AMD）' in html


def test_cos_listing_is_cached(cos_client):
    c, _dl, calls = cos_client
    c.get('/download')
    c.get('/download')
    assert len(calls) == 1  # 缓存窗口内只请求一次 COS


def test_cos_failure_falls_back_to_last_good(cos_client, monkeypatch):
    c, _dl, calls = cos_client
    assert c.get('/download').status_code == 200

    import app as app_mod
    app_mod._cos_list_cache['ts'] = 0.0  # 令缓存过期

    def _boom(url):
        raise OSError('cos unreachable')
    monkeypatch.setattr(app_mod, '_cos_http_get', _boom)
    html = c.get('/download').get_data(as_text=True)
    assert 'RTPAnalyzer-2.0.0-win64.exe' in html  # 回退最近一次成功结果


def test_cos_and_local_merge_local_wins(cos_client):
    c, dl, _calls = cos_client
    _touch(dl / 'RTPAnalyzer-2.0.0-win64.exe')  # 与 COS 同名
    html = c.get('/download').get_data(as_text=True)
    # 本地条目优先：URL 是本站下载路由而非 COS 直链
    assert '/download/RTPAnalyzer-2.0.0-win64.exe' in html


def test_only_latest_version_per_platform_arch(client):
    """同一「平台+架构」只展示最新一个版本，历史版本不上页面。"""
    c, dl = client
    now = time.time()
    _touch(dl / 'RTPAnalyzer-1.0.0-win64.exe', mtime=now - 86400)
    _touch(dl / 'RTPAnalyzer-2.0.0-win64.exe', mtime=now)
    _touch(dl / 'RTPAnalyzer-2.0.0-arm64.dmg', mtime=now)
    _touch(dl / 'RTPAnalyzer-2.0.0-x64.dmg', mtime=now - 7200)
    _touch(dl / 'RTPAnalyzer-1.0.0-portable.zip', mtime=now - 86400)
    _touch(dl / 'RTPAnalyzer-2.0.0-portable.zip', mtime=now)

    html = c.get('/download').get_data(as_text=True)
    # Windows x64 与 zip（其他）都只留最新的
    assert 'RTPAnalyzer-2.0.0-win64.exe' in html
    assert 'RTPAnalyzer-1.0.0-win64.exe' not in html
    assert 'RTPAnalyzer-2.0.0-portable.zip' in html
    assert 'RTPAnalyzer-1.0.0-portable.zip' not in html
    # macOS 不同芯片各自保留最新版
    assert 'RTPAnalyzer-2.0.0-arm64.dmg' in html
    assert 'RTPAnalyzer-2.0.0-x64.dmg' in html
