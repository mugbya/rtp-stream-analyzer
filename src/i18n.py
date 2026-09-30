"""轻量多语言：按域名切语言，中文字典整体替换为英文。

设计：界面文案以中文为源（模板 / app.js / 后端生成的报告文案都是中文），
英文站不维护第二套模板，而是在输出层按字典把中文替换成英文：

  - HTML 响应（模板渲染结果）→ 整体替换（app.py 的 after_request 钩子）
  - JSON 响应（/api/*，后端生成的报告/警告文案）→ 深度遍历替换字符串值
  - /static/js/app.js → 按语言翻译源码后下发

字典条目两种形态（ZH_EN，见 i18n_entries*.py）：
  - 精确条目  ("上传抓包文件", "Upload capture files")
  - 模式条目  ("共 {} 条记录", "{} records in total")   {} 匹配变量值（数字、
              文件名等），英文里 {} 表示该值放回的位置，两边 {} 数量必须一致
字典没有的中文保持原样（兜底），新增文案只需补条目。

匹配引擎（性能关键，勿改回"一个大正则全文扫描"）：
曾用 1176 条分支的大正则对全文逐位置扫描，带前导 {} 通配的条目在每个
ASCII 位置都要做通配展开试探，一个英文页面要数秒。现在改为锚点定位：
  1. 每个条目选一个**以中文字符开头**的字面量段作锚点（如 "延迟 {} ms"
     的锚点是 "延迟"），按锚点前两个字符建索引；
  2. 扫描时用一个"锚点首字符集合"的小正则跳过全部非锚点字符（纯英文/
     标记区域零成本），只在锚点出现处逐条验证；
  3. 验证时 {} 按固定窗口（≤120 字符）在锚点左右找相邻字面量，两侧
     取"最早起点"（即允许的最大窗口），等价于正则的最左匹配语义。
语义与大正则版有一点刻意差异：通配条目不再能从"最左侧任意位置"抢跑
（那会吞掉别的精确条目、把长句拦腰截断），而是以锚点出现处为准——
实测这让长句翻译更准。code 模式（HTML 渲染文本 / JS 源码）下 {} 通配
不跨引号，防止吞掉字符串字面量之外的代码；JSON 按单值翻译不受限。
"""
import re

# 条目来源（拆多个文件便于并行维护：web 模板 / web JS / 后端报告 / 后端杂项）
from i18n_entries_web import ENTRIES as _E_WEB
from i18n_entries_web_results import ENTRIES as _E_RESULTS
from i18n_entries_web_js import ENTRIES as _E_JS
from i18n_entries_backend_report import ENTRIES as _E_REPORT
from i18n_entries_backend_misc import ENTRIES as _E_MISC

ZH_EN = _E_WEB + _E_RESULTS + _E_JS + _E_REPORT + _E_MISC

_HAS_ZH = re.compile(r'[一-龥]')
_ASCII_QUOTE = re.compile(r'["\'`]')
_MAX_WILD = 120        # {} 通配最多匹配的字符数


def _make_valid(code):
    """返回该模式下通配内容是否允许跨越某字符的判定函数。"""
    if code:
        def valid(ch):
            return ch != '\n' and ch not in '\'"`'
    else:
        def valid(ch):
            return ch != '\n'
    return valid


class _Entry:
    __slots__ = ('lits', 'anchor', 'k', 'en_parts', 'en_parts_code', 'prio')

    def __init__(self, zh, en):
        self.lits = zh.split('{}')            # {} 之间的字面量段
        self.en_parts = en.split('{}')
        # code 模式（HTML 渲染 / JS 源码）用的替换文本：条目英文里的 ASCII
        # 引号原样塞进宿主字符串字面量会把语法截断（如 receiver's 进单引号
        # 串），中文侧不含 ASCII 引号的"自然语句"条目统一转成弯引号——
        # 显示几乎无差，且与任何引号上下文兼容。中文侧本身带 ASCII 引号的
        # 条目是"代码式"替换（引号来自源码、成对出现），必须保持原样。
        if _ASCII_QUOTE.search(zh):
            self.en_parts_code = self.en_parts
        else:
            safe = en.replace("'", '’').replace('`', '’')
            if '"' in safe:
                out, is_open = [], False
                for ch in safe:
                    if ch == '"':
                        out.append('“' if not is_open else '”')
                        is_open = not is_open
                    else:
                        out.append(ch)
                safe = ''.join(out)
            self.en_parts_code = safe.split('{}')
        self.prio = len(zh.replace('{}', ''))  # 字面量总长，长的优先
        # 锚点：取**最早**含中文字符的字面量段——匹配起点尽量前移，长条目
        # 才会先于"锚点在其内部"的短条目被处理（否则条目内部的中文会被
        # 短条目先吃掉，长条目自身因部分文字已被消费而无法匹配）。
        # 段里没有中文的条目（纯全角标点）退回最长段。
        cands = [s for s in self.lits if _HAS_ZH.search(s)]
        self.anchor = cands[0] if cands else max(
            (s for s in self.lits if s), key=len)
        self.k = self.lits.index(self.anchor)  # 锚点段序号

_idx2 = {}       # 锚点前两字符 -> [entry]
_idx1 = {}       # 单字锚点
_first_re = None  # 所有锚点首字符的集合（用于跳过无关位置）


def _build():
    """建立锚点索引。启动后首次翻译时执行一次。"""
    global _idx2, _idx1, _first_re
    seen = set()
    entries = []
    for zh, en in ZH_EN:
        if zh in seen:
            continue
        seen.add(zh)
        if zh.count('{}') != en.count('{}'):
            raise ValueError('i18n 条目 {} 与 {} 的占位符数量不一致'.format(zh, en))
        entries.append(_Entry(zh, en))
    # 同一锚点下长条目排前面：同位置命中时优先更具体的中文
    _idx2, _idx1 = {}, {}
    firsts = set()
    for e in sorted(entries, key=lambda e: -e.prio):
        a = e.anchor
        firsts.add(a[0])
        if len(a) >= 2:
            _idx2.setdefault(a[:2], []).append(e)
        else:
            _idx1.setdefault(a, []).append(e)
    _first_re = re.compile('[' + re.escape(''.join(sorted(firsts))) + ']')


def _right_side(text, e, k, cur, valid, pieces):
    """从锚点向右匹配 lits[k] 之后的字面量与通配。成功返回匹配终点，失败 None。"""
    lits = e.lits
    n = len(lits) - 1
    for j in range(k, n):
        nxt = lits[j + 1]
        occ = text.find(nxt, cur, cur + _MAX_WILD + len(nxt))
        if occ < 0 or occ - cur > _MAX_WILD:
            return None
        for i in range(cur, occ):
            if not valid(text[i]):
                return None
        pieces[j] = text[cur:occ]
        cur = occ + len(nxt)
    return cur


def _left_side(text, e, k, p, cursor, valid, pieces):
    """从锚点向左匹配 lits[k] 之前的字面量与通配。成功返回匹配起点，失败 None。

    同一条目的多个起点里取最早的那个（等价正则"最左优先"）：左侧通配取
    允许范围内的最大窗口。cursor 之前的文本已被上一处匹配消费，不许跨入。
    """
    lits = e.lits
    s = p
    for j in range(k, 0, -1):
        prev = lits[j - 1]
        # 通配窗口与文字段都不得越过 cursor（已消费区）：整个匹配必须完整
        # 落在 [cursor, …) 内，否则会与已应用的替换交错，输出被打乱
        lim = s - len(prev) - cursor
        if lim < 0:
            return None
        wmax = min(_MAX_WILD, lim)
        v = 0
        while v < wmax and valid(text[s - 1 - v]):
            v += 1
        w = None
        for cand in range(min(wmax, v), -1, -1):
            if text.startswith(prev, s - cand - len(prev)):
                w = cand
                break
        if w is None:
            return None
        pieces[j - 1] = text[s - w:s]
        s = s - w - len(prev)
    return s


def _assemble(e, pieces, code):
    parts = e.en_parts_code if code else e.en_parts
    out = [parts[0]]
    for k, piece in enumerate(pieces):
        out.append(piece)
        out.append(parts[k + 1])
    return ''.join(out)


def _sub(text, code):
    """锚点定位 + 逐条验证的替换主循环。"""
    valid = _make_valid(code)
    out = []
    cursor = 0
    for m in _first_re.finditer(text):
        p = m.start()
        if p < cursor:
            continue
        cands = _idx2.get(text[p:p + 2]) or _idx1.get(text[p])
        if not cands:
            continue
        for e in cands:
            # 索引键只是锚点前两字符，长锚点未必真在此处，先整体验证
            if not text.startswith(e.anchor, p):
                continue
            pieces = [''] * (len(e.lits) - 1)
            end = _right_side(text, e, e.k, p + len(e.anchor), valid, pieces)
            if end is None:
                continue
            start = _left_side(text, e, e.k, p, cursor, valid, pieces)
            if start is None:
                continue
            out.append(text[cursor:start])
            out.append(_assemble(e, pieces, code))
            cursor = end
            break
    out.append(text[cursor:])
    return ''.join(out)


def translate(text, code=False):
    """中文 → 英文（按字典）。无中文直接原样返回。

    code=True 用于"源码/标记文本"（HTML 渲染结果、JS 源码）：{} 通配不跨
    引号，防止模式条目吞掉字符串字面量之外的代码；纯文本（JSON 值）用默认。
    """
    if not text or not _HAS_ZH.search(text):
        return text
    if _first_re is None:
        _build()
    return _sub(text, code)


def deep_translate(obj):
    """递归翻译 JSON 结构里的字符串值（dict 的键不翻译）。"""
    if isinstance(obj, str):
        return translate(obj)
    if isinstance(obj, list):
        return [deep_translate(x) for x in obj]
    if isinstance(obj, dict):
        return {k: deep_translate(v) for k, v in obj.items()}
    return obj


def fingerprint():
    """字典内容指纹：app.js 的缓存版本号要带上它——字典更新（文案改了）
    而 app.js 文件本身没变时，版本号也要变，浏览器才会拉新文件。"""
    import hashlib
    # SALT 随翻译引擎的产出规则变化而递增：产出变了但字典没变时，
    # 指纹也要变，否则浏览器还用旧版本号命中旧缓存
    payload = ('code-sanitize-v1\x00' + '\x00'.join(
        zh + '\x01' + en for zh, en in ZH_EN))
    return hashlib.md5(payload.encode('utf-8')).hexdigest()[:8]
