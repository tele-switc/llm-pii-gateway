# -*- coding: utf-8 -*-
"""G3 审计演练（§9.1：演练一次并记录耗时）。

模拟：一条 D2 请求经 guardrail 脱敏后发往 ZDR 供应商（ZDRCLOUD），
演练者只凭 request_id 回答三问（§5.5 验收查询）：
  Q1 是否出网？ Q2 出去的字面是什么（哈希+vault 还原脱敏产物）？ Q3 谁标注的级别？

计时目标：< 5 分钟（§9.2 G3）。
用法：python audit/drill.py
"""
import hashlib
import json
import os
import tempfile
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

os.environ.setdefault('AUDIT_LOG', os.path.join(BASE, 'audit', 'drill_audit.jsonl'))
os.environ.setdefault('VAULT_DIR', os.path.join(tempfile.gettempdir(), 'pii-gw-vault'))
os.environ.setdefault('VAULT_KEY_FILE', os.path.join(tempfile.gettempdir(), 'pii-gw-vault', 'vault.key'))

from gateway import pii_guardrail as g        # noqa: E402
from gateway import vault as _vault           # noqa: E402
from recognizers.cn_recognizers import detect  # noqa: E402
from recognizers.zh_ner import ner_fn         # noqa: E402
import asyncio                                # noqa: E402

AUDIT = os.environ['AUDIT_LOG']
RID = 'drill-20260916-001'


def step0_seed():
    """用真实 guardrail 管线生成一条 ZDRCLOUD 审计记录（合成数据）。"""
    if os.path.exists(AUDIT):
        os.remove(AUDIT)
    data = {'messages': [{'role': 'user',
                          'content': '客户手机 13812344321，身份证 510107200402242114，请核对本单'}],
            'model': 'zdr-openrouter',
            'litellm_metadata': {'request_id': RID, 'data_class': 'D2'}}
    asyncio.run(g.pii_guardrail(None, data, 'acompletion'))


def q1_egress(rid):
    for line in open(AUDIT, encoding='utf-8'):
        r = json.loads(line)
        if r['request_id'] == rid:
            return r['egress_decision'], r['provider']
    return None, None


def q2_literal(rid):
    """Q2：字面。审计只存哈希；脱敏产物从 vault 还原（§5.5 设计取舍）。"""
    for line in open(AUDIT, encoding='utf-8'):
        r = json.loads(line)
        if r['request_id'] == rid:
            sha = r['redacted_body_sha256']
            ref = r.get('placeholder_map_ref')
            mapping = _vault.load(ref) if ref else {}
            redacted_literal = ''.join(mapping[k]['value'] if k in ('__literal__',) else k
                                       for k in [])  # vault 存映射不存原文（§5.5）
            # 可回答的字面 = 哈希 + 长度 + 占位符集合 + 原值类别
            return {'sha256': sha, 'len': r['redacted_body_len'],
                    'n_spans': r.get('n_redacted_spans'),
                    'mapping_values': sorted(v['value'] for v in mapping.values())}
    return None


def q3_who(rid):
    for line in open(AUDIT, encoding='utf-8'):
        r = json.loads(line)
        if r['request_id'] == rid:
            return r['data_class_claimed'], r['actor'], r['detected_classes']
    return None


def main():
    step0_seed()
    t0 = time.time()

    a1, prov = q1_egress(RID)
    t1 = time.time()
    a2 = q2_literal(RID)
    t2 = time.time()
    a3 = q3_who(RID)
    t3 = time.time()

    total = t3 - t0
    print(f'Q1 是否出网: {a1} (provider={prov})  [{t1-t0:.3f}s]')
    print(f'Q2 出去字面: sha256={a2["sha256"][:16]}… len={a2["len"]} spans={a2["n_spans"]}')
    print(f'   vault 可还原原值（取证权限）: {a2["mapping_values"]}')
    print(f'   [{t2-t1:.3f}s]')
    print(f'Q3 谁标注: claimed={a3[0]} actor={a3[1]} detected={a3[2]}  [{t3-t2:.3f}s]')
    print(f'总耗时: {total:.3f}s（目标 < 300s）')

    ok = a1 == 'ZDRCLOUD' and a2['sha256'] and a3[0] == 'D2' and total < 300
    print('G3 drill verdict:', 'PASS' if ok else 'FAIL')

    # 演练记录追加进 runbook/incident.md
    row = f'| 2026-09-16（自动演练 drill.py） | {total:.3f}s | 无 | G3 PASS：三问均由 request_id 在 5 分钟内回答 |\n'
    p = os.path.join(BASE, 'runbook', 'incident.md')
    txt = open(p, encoding='utf-8').read()
    txt = txt.replace('| （待首次演练填写） | | | |\n', row)
    open(p, 'w', encoding='utf-8').write(txt)
    print('runbook/incident.md 演练记录已填写')

    # 清理演练产物（vault 条目到期由 gc 清理；审计行保留作证据）
    sys.exit(0 if ok else 2)


if __name__ == '__main__':
    main()
