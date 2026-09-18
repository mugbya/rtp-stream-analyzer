"""pytest 共享配置：把仓库根目录（config.py）与 src/（analyzer、app 等包）加入 sys.path。"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_HERE)
_SRC_DIR = os.path.join(_ROOT_DIR, 'src')
for _p in (_ROOT_DIR, _SRC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)
