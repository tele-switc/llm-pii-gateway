# -*- coding: utf-8 -*-
"""§6.3 绕过面处置单测：APM 脱敏 / 缓存 key / SSE 还原 / 非扫描字段 DENY。"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# 测试产物一律落临时目录，绝不写进仓库根
_TMP = tempfile.mkdtemp(prefix="pii-gw-test-")
_VAULT = os.path.join(_TMP, "vault")
os.environ['VAULT_DIR'] = _VAULT
os.environ['VAULT_KEY_FILE'] = os.path.join(_VAULT, 'key')

from gateway import bypass as b  # noqa: E402
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


PII = '客户手机 13812344321，身份证 510107200402242114'

print('[APM scrub]')
scrubbed, ref = b.scrub_for_apm({'message': PII, 'tags': {'order': 'ORD-1', 'ip': '10.0.0.1'}})
check('message 中手机号被脱敏', '13812344321' not in scrubbed['message'])
check('message 中身份证被脱敏', '510107200402242114' not in scrubbed['message'])
check('非敏感字段原样保留', scrubbed['tags']['order'] == 'ORD-1' and scrubbed['tags']['ip'] == '10.0.0.1')
check('vault 有映射可溯源', ref is not None and len(_vault.load(ref)) == 2)

print('[cache key]')
k1 = b.cache_key(PII)
k2 = b.cache_key(PII)
k3 = b.cache_key('客户手机 13912344321，身份证 510107200402242115')
check('相同内容 key 稳定', k1 == k2)
check('不同 PII 内容 key 不同', k1 != k3)
check('key 是 64 位 sha256 且不含明文', len(k1) == 64 and '13812344321' not in k1)

print('[SSE 还原]')
mapping = {'⟨CN-aa11bb22cc33@abc12345⟩': '13812344321',
           '⟨ID-dd44ee55ff66@abc12345⟩': '510107200402242114'}
# 正常整块
out = list(b.rehydrate_sse(['手机是⟨CN-aa11bb22cc33@abc12345⟩。'], mapping))
check('整块占位符还原', ''.join(out) == '手机是13812344321。')
# 占位符被切成 3 片
full = '前文⟨CN-aa11bb22cc33@abc12345⟩后文'
chunks = [full[i:i + 5] for i in range(0, len(full), 5)]
out = list(b.rehydrate_sse(chunks, mapping))
check('分片错位（5字节/片）还原完整', ''.join(out) == '前文13812344321后文')
# 两个占位符相邻被切断
adj = '⟨CN-aa11bb22cc33@abc12345⟩⟨ID-dd44ee55ff66@abc12345⟩'
chunks = [adj[i:i + 7] for i in range(0, len(adj), 7)]
out = list(b.rehydrate_sse(chunks, mapping))
check('相邻占位符跨片还原', ''.join(out) == '13812344321' + '510107200402242114')
# 未知占位符不猜值
out = list(b.rehydrate_sse(['x⟨XX-000000000000@ffffffff⟩y'], mapping))
check('未知占位符原样保留（不猜）', out[0] == 'x⟨XX-000000000000@ffffffff⟩y')

print('[非扫描字段 DENY]')
ok = {'messages': [{'role': 'user', 'content': '普通问题', 'name': 'user-1'}]}
check('干净请求通过', b.validate_no_pii_in_unscanned(ok) is None)

bad = {'messages': [{'role': 'user', 'content': '普通问题', 'name': '13812344321'}]}
try:
    b.validate_no_pii_in_unscanned(bad)
    check('messages[].name 含手机号 → DENY', False)
except ValueError as e:
    check('messages[].name 含手机号 → DENY', 'DENY' in str(e))

bad2 = {'messages': [{'role': 'user', 'content': 'hi'}], 'metadata': {'phone': '13812344321'}}
try:
    b.validate_no_pii_in_unscanned(bad2)
    check('metadata 值含手机号 → DENY', False)
except ValueError as e:
    check('metadata 值含手机号 → DENY', 'DENY' in str(e))

bad3 = {'messages': [{'role': 'user', 'content': 'hi'}], 'tools': [{'name': 'lookup', 'description': '查询 13812344321 的订单'}]}
try:
    b.validate_no_pii_in_unscanned(bad3)
    check('tools 定义含手机号 → DENY', False)
except ValueError as e:
    check('tools 定义含手机号 → DENY', 'DENY' in str(e))

bad4 = {'messages': [{'role': 'user', 'content': 'hi'}], 'user': '张三丰经理'}
try:
    b.validate_no_pii_in_unscanned(bad4)
    check('顶层 user 含姓名 → DENY', False)
except ValueError as e:
    check('顶层 user 含姓名 → DENY', 'DENY' in str(e))

bad5 = {'messages': [{'role': 'user', 'content': 'hi', 'phone_number': '13812344321'}]}
try:
    b.validate_no_pii_in_unscanned(bad5)
    check('JSON key/值 含手机号 → DENY', False)
except ValueError as e:
    check('JSON key/值 含手机号 → DENY', 'DENY' in str(e))

# 清理：整个临时目录
shutil.rmtree(_TMP, ignore_errors=True)

print(f'\n{PASS} passed, {FAIL} failed')
sys.exit(1 if FAIL else 0)
