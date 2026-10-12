# -*- coding: utf-8 -*-
"""中文 PII recognizer（§5.2）：四类强校验规则 + NER 占位接口。

设计要点（对应文档 §5.2 表）：
- 全角→半角归一化在候选扫描之前完成，返回的偏移均基于归一化后文本。
- 校验位错误的候选【不替换】（文档明确：这是 FP 主要来源）。
"""
import re

# ---------- 归一化 ----------

# 全角 ASCII 整段（U+FF01–U+FF5E）→ 半角；此前只映射了数字，导致
# 全角 Ｘ（身份证校验位）、全角 ＠/．（邮箱）、全角字母（USCC）成为绕过面
_FW = {0xFF01 + i: chr(0x21 + i) for i in range(0x5E)}
_FW_DASH = {0x2012: '-', 0x2013: '-', 0x2014: '-', 0x2212: '-'}
# 全角空格/中文字符分隔空格 → 半角空格（落入数字之间分隔符剔除逻辑）
_IDEAL_SPACE = {0x3000: ' ', 0x2002: ' ', 0x2003: ' '}
# ASCII 小写 → 大写（1:1，偏移不变）：覆盖小写变体的身份证校验位与 USCC
_LOWER = {0x61 + i: 0x41 + i for i in range(26)}
# 零宽/不可见字符：常用作「分隔符插入」绕过（138<ZWSP>1234<ZWSP>4321），直接剔除
_ZW = set('\u200b\u200c\u200d\u2060\ufeff\u00ad')


def normalize(text: str) -> str:
    return normalize_mapped(text)[0]


def normalize_mapped(text: str):
    """归一化并返回 (归一化文本, 偏移映射)，映射[i] = 归一化文本第 i 字符在原文本的下标。

    用于把"归一化后扫出的区间"还原回原文坐标（§5.2：先归一化再匹配）。
    所有替换均 1:1（translate 阶段），剔除阶段（零宽字符、数字间分隔符）通过
    显式索引链保持映射正确。
    """
    # 1) 1:1 替换：全角→半角 / 连字符归一 / "转"→'-'，再过一道小写→大写
    #    （两次 translate 均 1:1，偏移不变；全角小写７ｘ 先转半角小写再转大写）
    t = text.translate({**_FW, **_FW_DASH, **_IDEAL_SPACE})
    t = t.replace('转', '-')
    t = t.translate(_LOWER)
    # 2) 剔除零宽字符，保留「归一化串下标 → 原文下标」映射链
    idx = [i for i, ch in enumerate(t) if ch not in _ZW]
    t = ''.join(t[i] for i in idx)
    # 3) 剔除夹在数字之间的分隔符
    out, p = [], []
    i, n = 0, len(t)
    while i < n:
        if t[i] in '- ' and i > 0 and i + 1 < n and t[i - 1].isdigit() and t[i + 1].isdigit():
            i += 1
            continue  # 删除，不映射
        out.append(t[i])
        p.append(idx[i])
        i += 1
    return ''.join(out), p


# ---------- ID card: ISO 7064 MOD 11-2 ----------

_W11 = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_ID_RE = re.compile(r'(?<!\d)(\d{17})([0-9Xx])(?!\d)')


def _id_check(first17: str) -> str:
    r = sum(int(c) * w for c, w in zip(first17, _W11)) % 11
    return '10X98765432'[r]


def find_id_cards(t: str):
    out = []
    for m in _ID_RE.finditer(t):
        first17, last = m.group(1), m.group(2).upper()
        if last == 'X' and m.group(2) == 'x':
            pass  # 小写 x 视为 X
        if _id_check(first17) == last:
            out.append((m.start(), m.end(), 'CN_ID_CARD'))
    return out


# ---------- Mobile: 1[3-9]\d{9}，剥离 +86/86 前缀 ----------

_MOB_RE = re.compile(r'(?<!\d)(?:\+?86[- ]?)?(1[3-9])(\d{9})(?!\d)')


def find_mobiles(t: str):
    out = []
    for m in _MOB_RE.finditer(t):
        start = m.start(1)  # 从本地号段开始，不含 86 前缀
        out.append((start, m.end(), 'CN_MOBILE'))
    return out


# ---------- Bank card: 16-19 位 + Luhn + BIN 前缀 ----------

_BIN_PREFIXES = ('62', '60', '65', '35', '40', '41', '42', '43', '44', '45',
                 '46', '47', '48', '49', '51', '52', '53', '54', '55', '81')
_BANK_RE = re.compile(r'(?<!\d)(\d{16,19})(?!\d)')


def _luhn_ok(s: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(s)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_bank_cards(t: str):
    out = []
    for m in _BANK_RE.finditer(t):
        s = m.group(1)
        if s.startswith(_BIN_PREFIXES) and _luhn_ok(s):
            out.append((m.start(), m.end(), 'CN_BANK_CARD'))
    return out


# ---------- USCC: GB 32100 模 31 ----------

_USCC_CHARS = '0123456789ABCDEFGHJKLMNPQRTUWXY'
_USCC_VAL = {c: (ord(c) - 48 if c.isdigit() else ord(c) - 55) for c in _USCC_CHARS}
_W31 = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]
_USCC_RE = re.compile(r'(?<![0-9A-Z])([0-9A-HJ-NP-RT-UW-Y]{17})([0-9A-HJ-NP-RT-UW-Y])(?![0-9A-Z])')


def _uscc_check(body17: str) -> str:
    s = sum(_USCC_VAL[c] * w for c, w in zip(body17, _W31))
    return _USCC_CHARS[(31 - s % 31) % 31]


def find_usccs(t: str):
    out = []
    for m in _USCC_RE.finditer(t):
        if _uscc_check(m.group(1)) == m.group(2):
            out.append((m.start(), m.end(), 'CN_USCC'))
    return out


# ---------- Email / masked id ----------

_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')


def find_emails(t: str):
    return [(m.start(), m.end(), 'EMAIL') for m in _EMAIL_RE.finditer(t)]


_MASKED_ID_RE = re.compile(r'(?<!\d)(\d{6}\*{4}\d{4})(?!\d)')  # 历史遮蔽值 320102****4321 风格


def find_masked_ids(t: str):
    return [(m.start(), m.end(), 'CN_ID_CARD_MASKED') for m in _MASKED_ID_RE.finditer(t)]


_MASKED_MOB_RE = re.compile(r'(?<!\d)(1[3-9]\d)\s*-\s*\*{4}\s*-\s*(\d{4})(?!\d)')


def find_masked_mobiles(t: str):
    return [(m.start(), m.end(), 'CN_MOBILE_MASKED') for m in _MASKED_MOB_RE.finditer(t)]


# ---------- 汇总入口 ----------

STRONG_DETECTORS = [
    find_id_cards,
    find_mobiles,
    find_bank_cards,
    find_usccs,
    find_emails,
    find_masked_ids,
    find_masked_mobiles,
]


def detect_strong(text: str):
    """先归一化（全角/分隔符/"转"）再扫，区间映射回原文；去重叠（保留最长）。"""
    norm, pos = normalize_mapped(text)
    found = []
    for fn in STRONG_DETECTORS:
        for s, e, ty in fn(norm):
            found.append((pos[s], pos[e - 1] + 1, ty))
    found.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    merged, last_end = [], -1
    for s, e, ty in found:
        if s >= last_end:
            merged.append((s, e, ty))
            last_end = e
    return merged


def detect(text: str, ner_fn=None):
    """detect_strong + 可选本地 NER（CN_NAME / CN_ADDRESS）。

    ner_fn: callable(text) -> [(start, end, 'CN_NAME'|'CN_ADDRESS')]
    NER 未加载时返回 None 占位（按 §5.2：NER 不达标 → 该类归更高级别）。
    """
    spans = detect_strong(text)
    if ner_fn is not None:
        spans.extend(ner_fn(text))
        spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        merged, last_end = [], -1
        for s, e, ty in spans:
            if s >= last_end:
                merged.append((s, e, ty))
                last_end = e
        return merged
    return spans
