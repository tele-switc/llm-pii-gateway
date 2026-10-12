# -*- coding: utf-8 -*-
"""LiteLLM custom guardrail：检测 → 分级 → 路由/拒绝 + 审计 JSONL（§5.3/§5.5）。

路由规则（三条不可协商，§5.3）：
1. 失败即关闭：检测层任何异常 → 抛异常阻断请求，绝不静默放行到云端。
2. 默认级别 = 最高：请求未标注 data_class 时按 D3 处理（拒绝出网）。
3. 标签与内容检测取严：检测命中任何强规则实体 → 至少 D2；
   D3 特征（凭据/健康/未发布代码标记）→ 一律本地。
"""
import hashlib
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recognizers.cn_recognizers import detect  # noqa: E402
from recognizers.zh_ner import ner_fn  # noqa: E402
from gateway import vault as _vault  # noqa: E402
from gateway import bypass as _bypass  # noqa: E402

AUDIT_PATH = os.environ.get(
    'AUDIT_LOG', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'audit', 'audit.jsonl'))

# D3 特征关键词（凭据 / 健康语义 / 未发布标记）——粗筛层，语义判定交人工与哨兵
D3_MARKERS = ('password', 'secret', 'token=', 'api_key', 'private key',
              'confidential', '内部保密', '未发布', '并购标的',
              '诊断', '处方', '病历', '用药', '住院')

# —— §4.3 实测分类（out/presidio-zh-ner.json，2026-09-16，阈值不变）——
# 达标类别（FNR 0%）：命中即可"脱敏后走 ZDR 云端"
PROVEN_D2_CATS = {'CN_MOBILE', 'EMAIL', 'CN_BANK_CARD', 'CN_ID_CARD',
                  'CN_ID_CARD_FW', 'CN_ID_CARD_SPLIT', 'CN_ID_CARD_MASKED',
                  'CN_USCC', 'CN_ADDRESS', 'CN_ADDRESS_SPLIT', 'CN_ADDRESS_MIXED'}
# 未达标类别（name FNR 72% > 12% 上限）→ 超线动作：仅允许 ZDR 供应商，不允许 NVIDIA 免费端点
UNPROVEN_CATS = {'CN_NAME'}
# 健康语义：规则检出住院号本身达标（0%），但 D3_MARKERS 中的"诊断/病历/处方"
# 触发 D3 语义 → 一律本地（§2.3：病历 = D3）
# 注意：MEDICAL_RECORD（住院号）单独出现归 D2；伴随诊断/用药语义归 D3（D3_MARKERS 判定）。


def _audit(row):
    os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
    with open(AUDIT_PATH, 'a', encoding='utf-8') as f:
        f.write(json.dumps(row, ensure_ascii=False) + '\n')


def _texts(data: dict):
    msgs = data.get('messages') or []
    for m in msgs:
        c = m.get('content')
        if isinstance(c, str):
            yield c
        elif isinstance(c, list):  # multimodal parts
            for p in c:
                if isinstance(p, dict) and p.get('type') == 'text':
                    yield p.get('text', '')


def _decide(texts):
    """返回 (decision, detected, d3_hit)。

    decision ∈ {local, zdrcLOUD, deny}（§3-L2 三选一 + 拒绝，无第四分支）：
    - D3 语义标记（凭据/未发布/并购等，§2.3）→ 不出网：仅本地可用，云端 = deny
    - 检出未达标类别（UNPROVEN_CATS，name 72%）→ 仅 ZDR 供应商，不允许 NVIDIA 免费端点
    - 检出达标 D2 类别（PROVEN_D2_CATS）→ 脱敏后 ZDR 云端
    - 干净（D0/D1）→ 本地；若调用方标注 data_class=D0/D1 且请求目标是免费端点 → 保持免费端点
    标签与检测取严（§5.3-3）。
    """
    detected = set()
    d3_hit = False
    for t in texts:
        for s, e, ty in detect(t, ner_fn=ner_fn):
            detected.add(ty)
        low = t.lower()
        if any(k.lower() in low for k in D3_MARKERS):
            d3_hit = True
    if d3_hit:
        return 'local', detected, d3_hit
    if detected & UNPROVEN_CATS:
        return 'zdrcLOUD', detected, d3_hit
    if detected & PROVEN_D2_CATS:
        return 'zdrcLOUD', detected, d3_hit
    return 'local', detected, d3_hit


def _apply_redaction(data, decision):
    """zdrcLOUD 前对 messages 逐条脱敏，返回 (vault_ref, redacted_body_str, n_spans)。"""
    session_id = str(uuid.uuid4())
    mapping, all_spans_texts = {}, []
    redacted_msgs = []
    for m in data.get('messages') or []:
        c = m.get('content')
        if isinstance(c, str):
            spans = detect(c, ner_fn=ner_fn)
            rc, mp = _vault.redact(c, spans, session_id=session_id)
            mapping.update(mp)
            all_spans_texts.append(rc)
            redacted_msgs.append({**m, 'content': rc})
        elif isinstance(c, list):  # multimodal：只处理 text parts（图像 parts 见 §6.3：未 OCR 前禁止上传）
            new_parts = []
            for p in c:
                if isinstance(p, dict) and p.get('type') == 'text':
                    t = p.get('text', '')
                    spans = detect(t, ner_fn=ner_fn)
                    rt, mp = _vault.redact(t, spans, session_id=session_id)
                    mapping.update(mp)
                    new_parts.append({**p, 'text': rt})
                else:
                    new_parts.append(p)
            redacted_msgs.append({**m, 'content': new_parts})
        else:
            redacted_msgs.append(m)
    data['messages'] = redacted_msgs
    ref = _vault.save(session_id, mapping) if mapping else None
    body = json.dumps(all_spans_texts or [m.get('content') for m in redacted_msgs], ensure_ascii=False)
    # len(mapping)：占位符实体数。旧写法 sum(len(v)) 数的是内层 dict 键数，恒为 2×实体数
    return ref, body, len(mapping)


async def pii_guardrail(user_api_key_dict, data, call_type):
    """LiteLLM custom guardrail 入口（async pre-call hook）。"""
    ts = time.time()
    metadata = data.get('litellm_metadata') or {}
    request_id = metadata.get('request_id', str(uuid.uuid4()))
    texts = list(_texts(data))
    claimed = metadata.get('data_class') or 'UNLABELED(D3)'
    actor = user_api_key_dict.get('key_alias', 'unknown') if user_api_key_dict else 'unknown'
    # §5.3-2 缺标签一律按 D3：只认 D0/D1/D2 前缀，其余（含 UNLABELED、乱标）按 D3 处理（不出网）
    claim_is_d3 = not claimed.startswith(('D0', 'D1', 'D2'))

    try:
        # §6.3 行 2：非扫描字段（tools/name/user/metadata/JSON key）含 PII → 发现即 DENY（fail-closed）
        _bypass.validate_no_pii_in_unscanned(data)
        decision, detected, d3_hit = _decide(texts)
    except Exception as exc:  # fail-closed：检测层/校验层异常一律阻断（§5.3-1）
        _audit({'ts': ts, 'request_id': request_id, 'actor': actor,
                'data_class_claimed': claimed, 'detected_classes': ['<fail-closed>'],
                'egress_decision': 'DENY', 'provider': None, 'model': data.get('model'),
                'error': repr(exc)})
        raise ValueError(f'[pii_guardrail] fail-closed deny: {exc!r}') from exc

    # 标签与检测取严（§5.3-3）：调用方自报 D3（或没标签）时不得被检测"洗白"
    if claim_is_d3:
        decision, d3_hit = 'local', True

    vault_ref, n_redacted = None, 0
    if decision == 'zdrcLOUD':
        # 仅 ZDR 供应商（config: zdr-openrouter；OpenRouter 请求级 provider.zdr=true，§5.4）
        data['model'] = 'zdr-openrouter'
        vault_ref, redacted_body, n_redacted = _apply_redaction(data, decision)
        provider = 'openrouter-zdr'
    elif decision == 'local':
        data['model'] = 'local-default'  # 本地模型不可用 → litellm 直接报错，无 fallback（fail-closed）
        provider = 'local'
        redacted_body = json.dumps(texts, ensure_ascii=False)
    else:
        redacted_body = json.dumps(texts, ensure_ascii=False)
        provider = None

    # D0/D1 干净请求且调用方显式要求免费端点 → 保留其目标（§5.4：免费端点仅 D0/D1）
    if decision == 'local' and not detected and not d3_hit and claimed in ('D0', 'D1'):
        data['model'] = 'nvidia-free' if data.get('model') in ('nvidia-free', 'zdr-openrouter', 'local-default') else data.get('model')
        provider = 'nvidia-free'

    _audit({
        'ts': ts,
        'request_id': request_id,
        'actor': actor,
        'data_class_claimed': claimed,
        'detected_classes': sorted(detected),
        'egress_decision': decision.upper(),
        'provider': provider,
        'model': data.get('model'),
        'redacted_body_sha256': hashlib.sha256(redacted_body.encode('utf-8')).hexdigest(),
        'redacted_body_len': len(redacted_body),
        'placeholder_map_ref': vault_ref,   # vault 条目指针（§5.5：不存映射本身）
        'n_redacted_spans': n_redacted,
        'fnr_sentinel_hits': 0,             # 生产哨兵注入计数（§6.1）
    })

    # zdrcLOUD/local 均已完成路由改写，放行；deny 仅由 detector 异常触发（上方已 raise）
    return data


# —— LiteLLM 挂接层 ——
# litellm proxy 的 pre-call 钩子只执行 CustomGuardrail / 覆写了 async_pre_call_hook 的
# CustomLogger 实例；把裸函数路径写进 litellm_settings.callbacks 会被静默跳过（fail-open）。
# 因此对外暴露 proxy_handler_instance 实例，config.yaml 的 callbacks 指向该实例。
# litellm 未安装（纯跑单测/评测的环境，见 README）时退化为普通对象，不影响本模块导入。
try:
    from litellm.integrations.custom_guardrail import CustomGuardrail as _BaseGuardrail
    _HAS_LITELLM = True
except Exception:  # pragma: no cover - 无 litellm 环境
    _BaseGuardrail = object
    _HAS_LITELLM = False


class PIIGuardrail(_BaseGuardrail):
    """把上方 async 函数包装成 litellm 可派发的前置调用护栏。"""

    def __init__(self, **kwargs):
        kwargs.setdefault('guardrail_name', 'pii-guardrail')
        kwargs.setdefault('event_hook', 'pre_call')
        if _HAS_LITELLM:
            super().__init__(**kwargs)
        else:  # pragma: no cover - 无 litellm 环境
            self.guardrail_name = kwargs['guardrail_name']

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        return await pii_guardrail(user_api_key_dict, data, call_type)


proxy_handler_instance = PIIGuardrail()
