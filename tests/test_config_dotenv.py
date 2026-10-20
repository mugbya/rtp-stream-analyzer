"""config._load_dotenv：.env 加载规则（不覆盖已有环境变量、剥引号、忽略注释）。"""
import os

import config


def test_load_dotenv_parses_and_does_not_override(monkeypatch, tmp_path):
    monkeypatch.setenv('DOTENV_EXISTING', 'from-real-env')
    env_path = tmp_path / '.env'
    env_path.write_text(
        '# 注释行\n'
        'DOTENV_NEW=https://bucket.cos.ap-shanghai.myqcloud.com\n'
        'DOTENV_QUOTED="quoted value"\n'
        "DOTENV_SINGLE='single'\n"
        'DOTENV_EXISTING=should-not-win\n'
        '无等号的行\n',
        encoding='utf-8')

    config._load_dotenv(str(env_path))

    try:
        assert os.environ['DOTENV_NEW'] == 'https://bucket.cos.ap-shanghai.myqcloud.com'
        assert os.environ['DOTENV_QUOTED'] == 'quoted value'
        assert os.environ['DOTENV_SINGLE'] == 'single'
        assert os.environ['DOTENV_EXISTING'] == 'from-real-env'
    finally:
        for key in ('DOTENV_NEW', 'DOTENV_QUOTED', 'DOTENV_SINGLE'):
            monkeypatch.delenv(key, raising=False)


def test_load_dotenv_missing_file_is_silent(tmp_path):
    # 文件不存在不报错（生产没建 .env 也能正常启动）
    config._load_dotenv(str(tmp_path / 'no-such.env'))
