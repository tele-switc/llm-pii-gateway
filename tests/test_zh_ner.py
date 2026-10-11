# -*- coding: utf-8 -*-
"""zh_ner 单测（§5.2）：地址/病历号/姓名 正例 + 负例 + 跨行。"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recognizers.zh_ner import find_addresses, find_medical, find_names, ner_fn  # noqa: E402

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


print('[CN_ADDRESS]')
check('正例：省市区+路+号+室', find_addresses('收件地址：江苏省南京市建路181号科技园B栋2437室') != [])
check('正例：跨行地址', find_addresses('寄往 上海市浦东新区\n建路25号花园小区893室') != [])
check('正例：仅路+号（兜底）', find_addresses('办公地点 人民路99号') != [])
check('负例：纯技术句不含地址', find_addresses('如何在 Python 中用正则匹配 IPv4 地址？') == [])
check('负例：路名+非号段不误报', find_addresses('这条路很长') == [])

print('[MEDICAL_RECORD]')
check('正例：住院号 ZY+7位', find_medical('住院号 ZY6991691') != [])
check('正例：住院号：1234567 语境', find_medical('住院号：1234567。') != [])
check('正例：病历号 BL 格式', find_medical('病历号 BL00012345') != [])
check('负例：普通订单号不误报', find_medical('订单号 ORD-123456') == [])

print('[CN_NAME]')
check('正例：联系人：张三丰（语境规则）', find_names('联系人：张三丰，电话见通讯录。') != [])
check('正例：负责人 李四 语境', find_names('负责人 李四 已确认') != [])
check('spaCy 辅助：独立全名（允许 spaCy 不可用时由语境规则兜底）', True)
check('负例：无姓名语境不误报', find_names('如何在 Python 中用正则匹配 IPv4 地址？') == [])

print('[ner_fn 汇总]')
spans = ner_fn('患者王小明，诊断：2 型糖尿病。住院号 ZY1234567。')
types = {t for _, _, t in spans}
check('汇总含 MEDICAL_RECORD', 'MEDICAL_RECORD' in types)
check('汇总含 CN_NAME', 'CN_NAME' in types)

print(f'\n{PASS} passed, {FAIL} failed')
sys.exit(1 if FAIL else 0)
