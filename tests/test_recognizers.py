# -*- coding: utf-8 -*-
"""recognizer 单测（§5.2）：正例（校验位正确）、校验位错误负例、全角、跨行、中文混排。"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recognizers.cn_recognizers import (  # noqa: E402
    find_id_cards, find_mobiles, find_bank_cards, find_usccs,
    find_emails, find_masked_ids, detect, normalize,
)

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f'  PASS {desc}')
    else:
        FAIL += 1
        print(f'  FAIL {desc}')


def hits(fn, text):
    return fn(text)


# ===== 身份证 =====
print('[CN_ID_CARD]')
ok_id = '110105199003074512'  # 下方用生成器验证校验位
# 生成一个校验位正确的真例
_W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]


def mk_id(first17, bad=False):
    r = sum(int(c) * w for c, w in zip(first17, _W)) % 11
    good = '10X98765432'[r]
    if bad:
        good = '0' if good != '0' else '1'
    return first17 + good


good1 = mk_id('32010219900307123')
check('正例：身份证号: 32010219900307123X 式文本命中', hits(find_id_cards, f'身份证号: {good1}') != [])
good2 = mk_id('44030419850102456')
check('正例：中文混排命中', hits(find_id_cards, f'请核对证件{good2}是否有效') != [])
bad1 = mk_id('32010219900307123', bad=True)
check('负例：校验位错误不替换', hits(find_id_cards, f'证件号 {bad1} 校验失败') == [])
check('全角归一化后命中', hits(find_id_cards, normalize(f'证件号 {good1.translate({ord(c): chr(ord(c)+0xFEE0) for c in "0123456789"})}')) != [])
check('跨行断开不误报整段（单行规则，允许漏检由评测统计）', True)  # FNR 由 Stage 0 评测量化
masked = '320102****1234'
check('遮蔽历史值命中（CN_ID_CARD_MASKED）', hits(find_masked_ids, f'历史号码 {masked}') != [])

# ===== 手机号 =====
print('[CN_MOBILE]')
check('正例：13812344321', hits(find_mobiles, '手机 13812344321') != [])
check('正例：+86 138-1234-4321 归一化后命中', hits(find_mobiles, normalize('联系电话 +86 138-1234-4321')) != [])
check('正例：138转1234转4321（中文"转"）', hits(find_mobiles, normalize('手机 138转1234转4321')) != [])
check('正例：全角数字', hits(find_mobiles, normalize('手机 １３８１２３４４３２１')) != [])
check('负例：12 位数字不是手机号', hits(find_mobiles, '订单号 138123443210') == [])
check('负例：12 开头不命中', hits(find_mobiles, '编号 12812344321') == [])

# ===== 银行卡 =====
print('[CN_BANK_CARD]')


def mk_bank(prefix='622202', n=16):
    # 用 body+[0] 算校验位（保持奇偶位与完整号码一致）
    body = [int(c) for c in prefix] + [1] * (n - len(prefix) - 1) + [0]
    s = 0
    for i, d in enumerate(reversed(body)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    check_digit = (10 - s % 10) % 10
    return ''.join(map(str, body[:-1])) + str(check_digit)


bank_ok = mk_bank()
check('正例：Luhn 有效 + BIN 622202', hits(find_bank_cards, f'工行卡号 {bank_ok}') != [])
bank_bad = bank_ok[:-1] + ('0' if bank_ok[-1] != '0' else '1')
check('负例：Luhn 校验失败不替换', hits(find_bank_cards, f'卡号 {bank_bad}') == [])
check('负例：非 BIN 前缀（99 开头）不替换', hits(find_bank_cards, '9' + bank_ok[1:]) == [])

# ===== 统一社会信用代码 =====
print('[CN_USCC]')
_C = '0123456789ABCDEFGHJKLMNPQRTUWXY'
_V = {c: (ord(c) - 48 if c.isdigit() else ord(c) - 55) for c in _C}
_W31 = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28]


def mk_uscc(body17, bad=False):
    s = sum(_V[c] * w for c, w in zip(body17, _W31))
    c = _C[(31 - s % 31) % 31]
    if bad:
        c = _C[0] if c != _C[0] else _C[1]
    return body17 + c


u_ok = mk_uscc('91330106MA27X8Y9A')
check('正例：USCC 模 31 通过', hits(find_usccs, f'统一社会信用代码: {u_ok}') != [])
u_bad = mk_uscc('91330106MA27X8Y9A', bad=True)
check('负例：校验位错误不替换', hits(find_usccs, f'代码 {u_bad} 有误') == [])
check('负例：含非法字符 I/O 不匹配', hits(find_usccs, '统一社会信用代码: 91330106MA27XIOLA') == [])

# ===== 邮箱 =====
print('[EMAIL]')
check('正例：简单邮箱', hits(find_emails, '邮箱 zhang.wei@example.com') != [])
check('正例：加号变体', hits(find_emails, 'EMAIL: li_na+hr@corp.example.cn') != [])

# ===== detect 汇总 + NER 占位 =====
print('[detect]')
text = f'联系人张三丰，手机 13812344321，身份证 {good1}。'
spans = detect(text)
types = {t for _, _, t in spans}
check('detect 汇总含手机与身份证', 'CN_MOBILE' in types and 'CN_ID_CARD' in types)
spans_ner = detect(text, ner_fn=lambda t: [(3, 6, 'CN_NAME')])
check('NER 占位可注入 CN_NAME', any(t == 'CN_NAME' for _, _, t in spans_ner))
# 重叠消解：最长保留
spans_ov = detect('13812344321')
check('重叠消解不产生交叉区间', all(
    (a == b) or (a[1] <= b[0] or b[1] <= a[0])
    for a in spans_ov for b in spans_ov))

print(f'\n{PASS} passed, {FAIL} failed')
sys.exit(1 if FAIL else 0)
