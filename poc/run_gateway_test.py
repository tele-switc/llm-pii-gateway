# -*- coding: utf-8 -*-
"""Stage 0 验收门评测（§4.2/§4.3）。

用法：
  python poc/run_gateway_test.py --tool presidio-zh --mode scan-only \
      --corpus corpus/zh_v1.jsonl --report out/presidio-zh.json

- scan-only：不发任何真实请求（§4.3 硬约束 3），仅对语料逐条调用被测工具的检测/脱敏函数，
  统计各类别 FNR、干扰项 FP、对照组放行证明。
- egress 模式：起本地假上游 + 代理抓包（另见 grep_egress.py 对 pcap 做真值命中校验）。

指标口径（唯一，写死）：
  FNR(类别) = 该类别中未被替换的植入项数 / 植入项总数（按类别分报，不报加权均值）
  FP 率     = 干扰项文本中被误替换的 token 数 / 干扰项 token 总数
  对照组    = 无 PII 商业秘密必须 100% 放行（这是设计事实，用来证明"脱敏不解决 D3"）
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# §4.3 锁定阈值（跑之前锁定，禁止事后调整）
THRESHOLDS = {
    'id_card': 0.01, 'mobile': 0.01, 'bank_card': 0.01, 'uscc': 0.01,
    'name': 0.12, 'address': 0.12,
    'health': 0.05,
}
FP_THRESHOLD = 0.03
# 校验位错误负例类别：被替换视为 FP（规则应判为非敏感）
BADCHECK_CATS = {'CN_ID_CARD_BADCHECK', 'CN_USCC_BADCHECK'}
# 真值实体类型 -> 语料类别（FNR 分母归属）
TYPE2CAT = {
    'CN_ID_CARD': 'id_card', 'CN_ID_CARD_FW': 'id_card', 'CN_ID_CARD_SPLIT': 'id_card',
    'CN_MOBILE': 'mobile', 'CN_MOBILE_MASKED': 'mobile',
    'CN_NAME': 'name', 'CN_NAME_COREF': 'name',
    'CN_ADDRESS': 'address', 'CN_ADDRESS_SPLIT': 'address', 'CN_ADDRESS_MIXED': 'address',
    'CN_USCC': 'uscc', 'CN_BANK_CARD': 'bank_card',
    'EMAIL': 'email', 'MEDICAL_RECORD': 'health',
}

PLACEHOLDER = '⟨REDACTED⟩'


# ---------- 被测工具适配层 ----------

def make_tool_presidio_zh():
    """自建 Presidio-zh：强校验规则层 + 本地中文 NER（地址/病历号规则 + spaCy 辅助姓名）。"""
    from recognizers.cn_recognizers import detect
    from recognizers.zh_ner import ner_fn

    def run(text):
        spans = detect(text, ner_fn=ner_fn)
        out, last = [], 0
        for s, e, ty in sorted(spans):
            out.append(text[last:s])
            out.append(PLACEHOLDER)
            last = e
        out.append(text[last:])
        return ''.join(out)

    return run, 'recognizers.cn_recognizers.detect + zh_ner.ner_fn (rules + zh NER)'


TOOLS = {
    'presidio-zh': make_tool_presidio_zh,
}


# ---------- 评测 ----------

def evaluate(redact_fn, corpus):
    fnr = {}          # cat -> [miss, total]
    fp_tokens = 0
    fp_total = 0
    control_leaks = 0
    control_total = 0

    for rec in corpus:
        text = rec['text']
        redacted = redact_fn(text)

        if rec['category'] == 'distractor':
            # FP：干扰项中被替换（出现占位符）的比例，按 token 计
            toks = re.findall(r'\S+', text)
            fp_total += len(toks)
            if PLACEHOLDER in redacted:
                # 被替换的连续片段数近似为占位符数
                fp_tokens += redacted.count(PLACEHOLDER)
            continue

        if rec['category'] == 'trade_secret':
            control_total += 1
            # 对照组：语义必须原样保留（无替换才叫放行）
            if redacted == text:
                control_leaks += 1  # "leak" = 整段原样出门，正是要证明的设计事实
            continue

        for ent in rec['entities']:
            cat = TYPE2CAT.get(ent['type'], ent['type'])
            badcheck = ent['type'] in BADCHECK_CATS
            if badcheck:
                # 校验位错误负例：期望不被替换；被替换计为干扰项 FP
                toks = re.findall(r'\S+', text)
                fp_total += len(toks)
                if redacted != text:
                    fp_tokens += max(1, redacted.count(PLACEHOLDER))
                continue
            fnr.setdefault(cat, [0, 0])
            fnr[cat][1] += 1
            if ent['value'] not in redacted:
                pass  # 已被替换（或被改写）
            else:
                fnr[cat][0] += 1  # 原值仍出现在脱敏输出中 → 漏检

    report = {
        'tool': None,
        'mode': 'scan-only',
        'corpus_size': len(corpus),
        'fnr_by_category': {
            c: {'miss': m, 'total': t, 'fnr': round(m / t, 4) if t else None}
            for c, (m, t) in sorted(fnr.items())
        },
        'fp': {'replaced_tokens': fp_tokens, 'total_tokens': fp_total,
               'rate': round(fp_tokens / fp_total, 4) if fp_total else 0.0},
        'trade_secret_control': {
            'passed_through': control_leaks, 'total': control_total,
            'note': '无 PII 商业秘密 100% 原样放行 = 设计事实，证明脱敏不解决 D3',
        },
        'gate': {},
    }

    # Gate G1 判定
    failed = []
    for cat, thr in THRESHOLDS.items():
        if cat in fnr and fnr[cat][1]:
            if fnr[cat][0] / fnr[cat][1] > thr:
                failed.append({'category': cat,
                               'fnr': round(fnr[cat][0] / fnr[cat][1], 4),
                               'threshold': thr,
                               'action': '该类别降级为不出网（gateway 配 deny）'})
    if fp_total and fp_tokens / fp_total > FP_THRESHOLD:
        failed.append({'category': '_fp', 'rate': round(fp_tokens / fp_total, 4),
                       'threshold': FP_THRESHOLD, 'action': '收紧规则并复测 FNR'})
    report['gate'] = {'G1': 'PASS' if not failed else 'FAIL', 'violations': failed}
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tool', required=True, choices=sorted(TOOLS))
    ap.add_argument('--mode', default='scan-only', choices=['scan-only', 'egress'])
    ap.add_argument('--corpus', required=True)
    ap.add_argument('--capture', default=None, help='egress 模式下的 pcap 输出路径')
    ap.add_argument('--report', required=True)
    args = ap.parse_args()

    with open(args.corpus, encoding='utf-8') as f:
        corpus = [json.loads(l) for l in f if l.strip()]

    redact_fn, impl = TOOLS[args.tool]()
    report = evaluate(redact_fn, corpus)
    report['tool'] = args.tool
    report['impl'] = impl

    os.makedirs(os.path.dirname(args.report) or '.', exist_ok=True)
    with open(args.report, 'w', encoding='utf-8') as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.mode == 'egress':
        print('\n[egress] scan-only 已完成预检；egress 抓包需本地假上游，'
              '真值命中校验请运行 poc/grep_egress.py（硬约束：出口字节零真值命中）')

    sys.exit(0 if report['gate']['G1'] == 'PASS' else 2)


if __name__ == '__main__':
    main()
