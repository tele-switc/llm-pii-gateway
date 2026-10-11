# -*- coding: utf-8 -*-
"""guardrail 决策与脱敏单测（§5.3 三条不可协商 + §5.5 审计字段）。"""
import asyncio
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# 测试产物一律落临时目录，绝不写进仓库根
_TMP = tempfile.mkdtemp(prefix="pii-gw-test-")
_VAULT = os.path.join(_TMP, "vault")
os.environ['AUDIT_LOG'] = os.path.join(_TMP, 'audit_test.jsonl')
os.environ['VAULT_DIR'] = _VAULT
os.environ['VAULT_KEY_FILE'] = os.path.join(_VAULT, 'key')

from gateway import pii_guardrail as g  # noqa: E402
from gateway import vault as _vault  # noqa: E402

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


def run_hook(data):
    return asyncio.run(
        g.pii_guardrail(None, data, 'acompletion'))


if os.path.exists(os.environ['AUDIT_LOG']):
    os.remove(os.path.exists(os.environ['AUDIT_LOG']) and os.environ['AUDIT_LOG'])


def audit_lines():
    if not os.path.exists(os.environ['AUDIT_LOG']):
        return []
    import json
    return [json.loads(l) for l in open(os.environ['AUDIT_LOG'], encoding='utf-8')]


print('[决策矩阵]')
d, det, d3 = g._decide(['解释 TCP 三次握手'])
check('干净文本 → local', d == 'local' and not d3)

d, det, d3 = g._decide(['我的身份证是 510107200402242114 请查询'])
check('达标 D2（身份证）→ zdrcLOUD', d == 'zdrcLOUD')

d, det, d3 = g._decide(['联系人：张三丰，请转告'])
check('未达标（姓名）→ zdrcLOUD（仅 ZDR，非免费端点）', d == 'zdrcLOUD')

d, det, d3 = g._decide(['api_key = abc123 帮我调试'])
check('D3 标记（凭据）→ local 不出网', d == 'local' and d3)

d, det, d3 = g._decide(['患者王小明，诊断：2 型糖尿病。住院号 ZY1234567。'])
# 病历语义 → D3（§2.3）
check('病案语义（诊断+住院号）→ local 不出网', d == 'local' and d3)

print('[fail-closed]')
orig = g._decide


def boom(_):
    raise RuntimeError('ner model missing')


g._decide = boom
data = {'messages': [{'role': 'user', 'content': 'hi'}], 'model': 'zdr-openrouter'}
try:
    run_hook(data)
    check('检测层异常 → raise 阻断', False)
except ValueError as e:
    check('检测层异常 → raise 阻断', 'fail-closed' in str(e))
finally:
    g._decide = orig
rows = audit_lines()
check('异常路径审计记 DENY', rows and rows[-1]['egress_decision'] == 'DENY')

print('[脱敏 + vault + 审计]')
if os.path.exists(os.environ['AUDIT_LOG']):
    os.remove(os.environ['AUDIT_LOG'])
data = {'messages': [{'role': 'user', 'content': '客户手机 13812344321，身份证 510107200402242114，请核对'}],
        'model': 'zdr-openrouter', 'litellm_metadata': {'request_id': 't-001', 'data_class': 'D2'}}
out = run_hook(data)
check('zdrcLOUD 路由到 zdr-openrouter', out['model'] == 'zdr-openrouter')
content = out['messages'][0]['content']
check('出口字面不含手机号真值', '13812344321' not in content)
check('出口字面不含身份证真值', '510107200402242114' not in content)
check('占位符已插入', '⟨' in content)
rows = audit_lines()
r = rows[-1]
check('审计：egress_decision=ZDRCLOUD', r['egress_decision'] == 'ZDRCLOUD')
check('审计：placeholder_map_ref 指向 vault', (r.get('placeholder_map_ref') or '').startswith('vault://'))
check('审计：存哈希不存原文', 'redacted_body_sha256' in r and '13812344321' not in str(r))
mp = _vault.load(r['placeholder_map_ref'])
check('vault 可还原原值', any(v['value'] == '13812344321' for v in mp.values()))
check('会话级随机化占位符', any('@' in k for k in mp.keys()))

print('[D0/D1 免费端点放行]')
data = {'messages': [{'role': 'user', 'content': '解释一下 CAP 定理'}], 'model': 'nvidia-free',
        'litellm_metadata': {'request_id': 't-002', 'data_class': 'D1'}}
out = run_hook(data)
check('D1 干净请求保留 nvidia-free', out['model'] == 'nvidia-free')
r = [x for x in audit_lines() if x['request_id'] == 't-002'][0]
check('审计 provider=nvidia-free', r['provider'] == 'nvidia-free')

print('[标签取严]')
data = {'messages': [{'role': 'user', 'content': '普通问题'}], 'model': 'zdr-openrouter',
        'litellm_metadata': {'request_id': 't-003', 'data_class': 'D3'}}
out = run_hook(data)
check('自报 D3 → 强制 local', out['model'] == 'local-default')

# 清理：整个临时目录
shutil.rmtree(_TMP, ignore_errors=True)

print(f'\n{PASS} passed, {FAIL} failed')
sys.exit(1 if FAIL else 0)
