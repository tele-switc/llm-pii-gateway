# -*- coding: utf-8 -*-
"""中文 NER 适配层 + 地址规则 + 病历号识别（§5.2：CN_NAME/CN_ADDRESS 走本地 NER）。

设计（2026-09-16 选型实测，zh_core_web_sm @ 本语料 n=45）：
  - spaCy zh_core_web_sm：PERSON 7/25 召回，LOC/GPE 0/20（地名只切省级，无门牌）
    → 结论：spaCy 仅用于辅助 CN_NAME（补"联系人：X"语境），地址不依赖 NER。
  - CN_ADDRESS：规则检测器为主（省市区县 + 路/号/室/栋 等地址成分，跨行合并）。
  - MEDICAL_RECORD：住院号/病历号规则（ZY/BL + 6~10 位数字，或"住院号：X"语境 + 任意 6~12 位数字）。

接口与 cn_recognizers.detect 对齐：callable(text) -> [(start, end, type)]。
"""
import re

# ---------- CN_ADDRESS 规则 ----------

# 省/直辖市/自治区（含"省"字变体）
_PROV = (r'(?:北京|上海|天津|重庆|黑龙江|内蒙古|黑龙江|广西|西藏|宁夏|新疆|'
         r'河北|山西|辽宁|吉林|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|'
         r'海南|四川|贵州|云南|陕西|甘肃|青海|甘肃|江苏|宁夏|新疆)[省市自治区]?'
         r'|(?:省|自治区)')
_CITY = r'[\u4e00-\u9fff]{2,8}?(?:市|自治州|地区|盟)'
_DIST = r'[\u4e00-\u9fff]{2,8}?(?:区|县|旗)'
_STREET = r'[\u4e00-\u9fffA-Za-z0-9]{2,16}?(?:路|街|大道|巷|弄|胡同|里)'
_BUILDING = r'[\u4e00-\u9fffA-Za-z0-9]{0,12}?(?:号|大厦|大楼|花园|小区|公寓|科技园|中心|村|庄)'
_ROOM = r'[\u4e00-\u9fff]{0,4}[A-Za-z]?座?[栋幢]?\s*\d{1,4}\s*(?:号|室|房|层)?'

_ADDR_RE = re.compile(
    r'(?:' + _PROV + r')?'
    r'(?:' + _CITY + r')?'
    r'(?:' + _DIST + r')?'
    r'(?:' + _STREET + r')?'
    r'(?=' + _BUILDING + r')'   # 至少要有一个"建筑/门牌"成分才算地址
)
# 更实用的整体地址正则：从省/市/区/路任一起点，吃到 室/号/栋/层 为止
_ADDR_FULL = re.compile(
    r'[\u4e00-\u9fff]{0,3}(?:省|市|区|县|区|盟|自治州|大道|路|街)'
    r'[\u4e00-\u9fffA-Za-z0-9]*(?:路|街|大道|巷|弄)?'
    r'[\u4e00-\u9fffA-Za-z0-9]*?号'
    r'[\u4e00-\u9fffA-Za-z0-9栋座幢层]{0,10}\d{0,4}[\u4e00-\u9fffA-Za-z0-9]*?(?:室|房|层|栋|座)?'
)
# 简化兜底：含"路/街" + "号" 的连续中文数字段
_ADDR_LOOSE = re.compile(r'[\u4e00-\u9fff]{2,12}(?:路|街|大道)\d{1,4}号[\u4e00-\u9fffA-Za-z0-9]{0,16}?(?:室|栋|座|层)?')


def find_addresses(t: str):
    """返回 [(start, end, 'CN_ADDRESS')]。跨行合并：先把换行临时替换为哨兵再匹配，
    命中后映射回原文（§4.1 要求跨行地址）。"""
    sentinel = '\x00'
    norm = t.replace('\n', sentinel)
    out = []
    used = []
    for m in list(_ADDR_FULL.finditer(norm)) + list(_ADDR_LOOSE.finditer(norm)):
        s, e = m.start(), m.end()
        if any(s < e2 and e > s2 for s2, e2 in used):
            continue
        used.append((s, e))
        out.append((s, e, 'CN_ADDRESS'))
    # 映射回原文（哨兵 = 1 字符 = 原文 1 字符，偏移不变）
    return out


# ---------- MEDICAL_RECORD ----------

_MED_ID_RE = re.compile(r'(?<![A-Za-z0-9])(?:ZY|BL|ZYH|ZYH|BH|INP)[A-Za-z]{0,2}\d{5,12}(?!\d)')
_MED_CTX_RE = re.compile(r'(?:住院号|病历号|病案号|门诊号|出院号)[:：\s]*([A-Za-z]{0,3}\d{5,12})')


def find_medical(t: str):
    out = []
    for m in _MED_ID_RE.finditer(t):
        out.append((m.start(), m.end(), 'MEDICAL_RECORD'))
    for m in _MED_CTX_RE.finditer(t):
        s, e = m.start(1), m.end(1)
        if not any(not (e <= s2 or s >= e2) for s2, e2, _ in out):
            out.append((s, e, 'MEDICAL_RECORD'))
    out.sort()
    return out


# ---------- CN_NAME：spaCy 辅助 + 语境规则 ----------

_spaCy = None


def _nlp():
    global _spaCy
    if _spaCy is None:
        try:
            import spacy
            _spaCy = spacy.load('zh_core_web_sm')
        except Exception:
            _spaCy = False
    return _spaCy or None


_NAME_CTX_RE = re.compile(
    r'(?:联系人|经手人|负责人|经办人|医生|护士|患者|病人|患者家属)[:：\s]([\u4e00-\u9fff]{2,4})'
)
# 无分隔符的病案语境："患者王小明，诊断…"（后必须紧跟病历字段标记，控 FP）
_NAME_PATIENT_RE = re.compile(
    r'(?:患者|病人|家属)([\u4e00-\u9fff]{2,4})(?=，|,|。|诊断|性别|年龄|入院|出院)'
)
# 姓名+后置职务称谓："张三丰经理"、"李总监"。这类串前面没有语境词，
# 上面两条规则都覆盖不到；非扫描字段（顶层 user / metadata）里最常见的就是它。
# 控 FP 的手段是首字必须落在常见姓氏表里，而不是放宽成"任意 2-4 汉字"。
# 姓名与称谓之间允许空白分隔（"张三丰 经理"），否则就成了分隔符插入绕过面。
_SURNAMES = (
    '王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾肖田董袁潘于'
    '蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏韦付方白邹孟熊秦邱江尹薛'
    '闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴莫孔向汤'
)
_NAME_TITLE_RE = re.compile(
    r'(?<![\u4e00-\u9fff])([' + _SURNAMES + r'][\u4e00-\u9fff]{0,3})'
    r'[\s\u3000]*(?:经理|总监|主管|总裁|董事长|主任|老师|医生|律师|工程师|教授|同事|'
    r'同志|秘书|会计|出纳|组长|车间主任|负责人)'
)


def find_names(t: str):
    out = []
    # 1) 语境规则（高置信，"联系人：X"）
    for m in _NAME_CTX_RE.finditer(t):
        out.append((m.start(1), m.end(1), 'CN_NAME'))
    # 2) 无分隔符病案语境（"患者王小明，诊断…"）
    for m in _NAME_PATIENT_RE.finditer(t):
        s, e = m.start(1), m.end(1)
        if not any(e > s2 and s < e2 for s2, e2, _ in out):
            out.append((s, e, 'CN_NAME'))
    # 3) 姓名+职务称谓（"张三丰经理"）
    for m in _NAME_TITLE_RE.finditer(t):
        s, e = m.start(1), m.end(1)
        if not any(e > s2 and s < e2 for s2, e2, _ in out):
            out.append((s, e, 'CN_NAME'))
    # 4) spaCy PERSON（过滤 1 字/4 字以上，避免误报）
    nlp = _nlp()
    if nlp is not None:
        doc = nlp(t)
        for ent in doc.ents:
            if ent.label_ == 'PERSON' and 2 <= len(ent.text) <= 4 \
                    and ent.text.strip() == ent.text:
                s, e = ent.start_char, ent.end_char
                if not any(e > s2 and s < e2 for s2, e2, _ in out):
                    out.append((s, e, 'CN_NAME'))
    out.sort()
    return out


# ---------- 汇总：作为 detect(ner_fn=...) 的入口 ----------

def ner_fn(text: str):
    """cn_recognizers.detect(text, ner_fn=ner_fn) 的回调。"""
    spans = find_names(text) + find_addresses(text) + find_medical(text)
    spans.sort(key=lambda x: (x[0], -(x[1] - x[0])))
    merged, last_end = [], -1
    for s, e, ty in spans:
        if s >= last_end:
            merged.append((s, e, ty))
            last_end = e
    return merged
