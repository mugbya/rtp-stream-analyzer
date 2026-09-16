"""
Unit tests for the auto-cleanup of outputs/ and uploads/: the retention
cutoff applies to root chart files, per-session directory trees and uploaded
pcap session dirs; empty parent dirs are removed; fresh trees are never
touched even when their own dir mtime is old.

Run: python3 tests/test_output_cleanup.py
"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import app as app_module


def _backdate(path, hours_ago):
    """Set mtime of path to hours_ago before now."""
    t = time.time() - hours_ago * 3600
    os.utime(path, (t, t))


def _with_tmp_dirs(retention_hours):
    """Point OUTPUT_FOLDER/UPLOAD_FOLDER at fresh temp dirs with the given
    retention. Returns (dirs, run_cleanup, restore)."""
    tmp = {
        'outputs': tempfile.mkdtemp(prefix='outputs-cleanup-test-'),
        'uploads': tempfile.mkdtemp(prefix='uploads-cleanup-test-'),
    }
    old = {k: app_module.app.config[k] for k in
           ('OUTPUT_FOLDER', 'UPLOAD_FOLDER', 'FILE_RETENTION_HOURS')}
    app_module.app.config['OUTPUT_FOLDER'] = tmp['outputs']
    app_module.app.config['UPLOAD_FOLDER'] = tmp['uploads']
    app_module.app.config['FILE_RETENTION_HOURS'] = retention_hours

    def restore():
        app_module.app.config.update(old)

    return tmp, app_module._cleanup_stale_files_once, restore


def test_default_retention_config():
    """两小时保留时长是默认配置项，outputs 与 uploads 共用。"""
    assert app_module.app.config['FILE_RETENTION_HOURS'] == 2


def test_stale_root_chart_removed_fresh_kept():
    """根目录散落的图表文件超时删除、未超时保留。"""
    dirs, cleanup, restore = _with_tmp_dirs(retention_hours=2)
    try:
        old_chart = os.path.join(dirs['outputs'], 'analysis_old.png')
        fresh_chart = os.path.join(dirs['outputs'], 'analysis_new.png')
        open(old_chart, 'w').close()
        open(fresh_chart, 'w').close()
        _backdate(old_chart, hours_ago=3)

        cleanup()

        assert not os.path.exists(old_chart)
        assert os.path.exists(fresh_chart)
    finally:
        restore()


def test_stale_session_tree_removed_empty_date_dir_removed():
    """outputs 超时会话目录整树删除，清空后的日期目录一并删除。"""
    dirs, cleanup, restore = _with_tmp_dirs(retention_hours=2)
    try:
        date_dir = os.path.join(dirs['outputs'], '2026-09-15')
        session = os.path.join(date_dir, 'session-a')
        audio_dir = os.path.join(session, 'audio')
        os.makedirs(audio_dir)
        wav = os.path.join(audio_dir, 'terminal_in_0001.wav')
        open(wav, 'w').close()
        # 分析完成后整棵树都不再有写入：所有层级一起回写旧 mtime
        _backdate(wav, hours_ago=3)
        _backdate(audio_dir, hours_ago=3)
        _backdate(session, hours_ago=3)
        _backdate(date_dir, hours_ago=3)

        cleanup()

        assert not os.path.exists(session)
        assert not os.path.exists(date_dir)  # 空日期目录也被清掉
    finally:
        restore()


def test_fresh_tree_kept_despite_old_dir_mtime():
    """目录自身 mtime 很旧但树内有新文件时不能误删（正在写入的会话）。"""
    dirs, cleanup, restore = _with_tmp_dirs(retention_hours=2)
    try:
        date_dir = os.path.join(dirs['outputs'], '2026-09-16')
        session = os.path.join(date_dir, 'session-b')
        os.makedirs(os.path.join(session, 'video'))
        mp4 = os.path.join(session, 'video', 'fs_out_0002.mp4')
        open(mp4, 'w').close()  # 刚写入的新文件
        _backdate(session, hours_ago=3)
        _backdate(date_dir, hours_ago=3)

        cleanup()

        assert os.path.exists(mp4)
    finally:
        restore()


def test_mixed_date_dir_keeps_fresh_session_and_date_dir():
    """同一日期目录下新会话保留时，日期目录本身也必须保留。"""
    dirs, cleanup, restore = _with_tmp_dirs(retention_hours=2)
    try:
        date_dir = os.path.join(dirs['outputs'], '2026-09-16')
        stale_session = os.path.join(date_dir, 'session-old')
        fresh_session = os.path.join(date_dir, 'session-new')
        os.makedirs(stale_session)
        os.makedirs(fresh_session)
        open(os.path.join(stale_session, 'old.wav'), 'w').close()
        fresh_file = os.path.join(fresh_session, 'new.wav')
        open(fresh_file, 'w').close()
        _backdate(os.path.join(stale_session, 'old.wav'), hours_ago=3)
        _backdate(stale_session, hours_ago=3)

        cleanup()

        assert not os.path.exists(stale_session)
        assert os.path.exists(fresh_file)
        assert os.path.exists(date_dir)
    finally:
        restore()


def test_stale_upload_session_removed_fresh_kept():
    """uploads 的会话目录（内含上传抓包）超时整树删除，未超时保留。"""
    dirs, cleanup, restore = _with_tmp_dirs(retention_hours=2)
    try:
        stale_dir = os.path.join(dirs['uploads'], 'session-old')
        fresh_dir = os.path.join(dirs['uploads'], 'session-new')
        os.makedirs(stale_dir)
        os.makedirs(fresh_dir)
        old_pcap = os.path.join(stale_dir, 'old.pcap')
        fresh_pcap = os.path.join(fresh_dir, 'new.pcap')
        open(old_pcap, 'w').close()
        open(fresh_pcap, 'w').close()
        _backdate(old_pcap, hours_ago=3)
        _backdate(stale_dir, hours_ago=3)

        cleanup()

        assert not os.path.exists(stale_dir)
        assert os.path.exists(fresh_pcap)
    finally:
        restore()


def test_zero_retention_clears_everything():
    """保留时长为 0 时 outputs 与 uploads 全部被清理（配置项确实生效）。"""
    dirs, cleanup, restore = _with_tmp_dirs(retention_hours=0)
    try:
        session = os.path.join(dirs['outputs'], '2026-09-16', 'session-c')
        os.makedirs(session)
        open(os.path.join(session, 'a.wav'), 'w').close()
        open(os.path.join(dirs['outputs'], 'analysis_today.png'), 'w').close()
        upload = os.path.join(dirs['uploads'], 'session-d')
        os.makedirs(upload)
        open(os.path.join(upload, 'b.pcap'), 'w').close()

        cleanup()

        assert os.listdir(dirs['outputs']) == []
        assert os.listdir(dirs['uploads']) == []
    finally:
        restore()


def main():
    test_default_retention_config()
    test_stale_root_chart_removed_fresh_kept()
    test_stale_session_tree_removed_empty_date_dir_removed()
    test_fresh_tree_kept_despite_old_dir_mtime()
    test_mixed_date_dir_keeps_fresh_session_and_date_dir()
    test_stale_upload_session_removed_fresh_kept()
    test_zero_retention_clears_everything()
    print("\n=== ALL FILE CLEANUP TESTS PASSED ===")


if __name__ == '__main__':
    main()
