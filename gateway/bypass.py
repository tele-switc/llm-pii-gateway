# -*- coding: utf-8 -*-
"""§6.3 绕过面处置：APM 脱敏 / 缓存 key / 流式 SSE 还原 / 非扫描字段校验。

每个函数对应 §6.3 表中的一行处置结论（g2/bypass_review.md 逐项引用）：
1. APM/错误上报：出网前统一走 scrub_for_apm（同一脱敏函数，§6.3 行 1）。
2. 缓存/去重 key：cache_key() = 脱敏后文本的 sha256，禁止明文 key（§6.3 行 5）。
3. 流式 SSE：rehydrate_sse() 缓冲跨分片占位符再还原，防分片错位（§6.3 行 4）。
4. 工具调用 JSON key / tools 定义 / messages[].name / 顶层 user/metadata：
   PrivAiTe 类工具明确不扫（§1.5）→ validate_no_pii_in_unscanned() 发现即 DENY（§6.3 行 2）。
"""
import hashlib
import json
import os
import re
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recognizers.cn_recognizers import detect  # noqa: E402
from recognizers.zh_ner import ner_fn  # noqa: E402
from gateway import vault as _vault  # noqa: E402

PH_RE = re.compile(r'⟨[A-Z]{2,12}-[0-9a-f]{12}@[0-9a-f]{8}⟩')


def _has_pii(text: str) -> bool:
    return bool(detect(text, ner_fn=ner_fn))


def scrub_for_apm(obj):
    """递归脱敏任意可 JSON 化对象（Sentry event / OTel attributes / 日志 dict）。

    与主出口同一检测函数（§6.3 行 1："出网前统一走同一脱敏函数"）。
    映射写入 vault（会话级 TTL），占位符保留可溯源性。
    """
    session_id = str(uuid.uuid4())
    mapping = {}

    def walk(o):
        if isinstance(o, str):
            spans = detect(o, ner_fn=ner_fn)
            if spans:
                rc, mp = _vault.redact(o, spans, session_id=session_id)
                mapping.update(mp)
                return rc
            return o
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [walk(v) for v in o]
        return o

    scrubbed = walk(obj)
    ref = _vault.save(session_id, mapping) if mapping else None
    return scrubbed, ref


def cache_key(text: str) -> str:
    """缓存/去重 key（§6.3 行 5）：先脱敏再哈希，禁止明文 key。

    用固定 session_id 保证占位符确定性 → 相同内容 key 稳定（否则会话级
    随机化占位符会让同一请求的 key 每次都变，缓存完全失效）。
    明文 key 会让敏感内容进入 Redis 键空间（可被 KEYS/SCAN 枚举、进慢查询日志）。
    """
    spans = detect(text, ner_fn=ner_fn)
    redacted, _ = _vault.redact(text, spans, session_id='cache-key-deterministic')
    return hashlib.sha256(redacted.encode('utf-8')).hexdigest()


def rehydrate_sse(chunks, mapping: dict):
    """流式响应还原（§6.3 行 4：SSE 分片错位）。

    云端 token 流里占位符可能被切到多个 chunk。逐 chunk 直接替换会漏。
    算法：chunk 追加进缓冲区；循环在缓冲区里找完整占位符（已知→还原，
    未知→原样），替换后从头重扫剩余部分；找不到完整占位符时把最后一个
    '⟨' 之后的内容留在缓冲区等下个 chunk。
    未知占位符不猜值；流结束残留原样透出。
    返回还原后的 chunk 生成器。
    """
    buf = ''
    for chunk in chunks:
        buf += chunk
        out = []
        while True:
            k = buf.find('⟨')
            if k == -1:
                out.append(buf)
                buf = ''
                break
            out.append(buf[:k])
            m = PH_RE.match(buf, k)
            if m:
                ph = m.group(0)
                out.append(mapping.get(ph, ph))
                buf = buf[m.end():]
                continue
            # 不完整的 ⟨… 尾片：留缓冲区
            buf = buf[k:]
            break
        yield ''.join(out)
    if buf:
        # 流结束仍有残留（占位符被截断 = 云端异常）：原样透出，不猜值
        yield buf


def _walk_strings(o, path, hits):
    """收集对象中所有字符串（含 dict key）及其路径，供 PII 校验。"""
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(k, str):
                hits.append((f'{path}.{k}', k))
            _walk_strings(v, f'{path}.{k}', hits)
    elif isinstance(o, (list, tuple)):
        for idx, v in enumerate(o):
            _walk_strings(v, f'{path}[{idx}]', hits)
    elif isinstance(o, str):
        hits.append((path, o))


def validate_no_pii_in_unscanned(data: dict):
    """§6.3 行 2：脱敏器明确不扫的字段里禁止业务值，发现即 DENY。

    检查面（PrivAiTe 明确不扫清单，§1.5）：
      - 任意 JSON key（key 里的 PII 同样外发）
      - messages[].name
      - 顶层 user / metadata 的全部字符串值与 key
      - tools 定义的全部字符串值
    注：messages[].content 属于扫描面（主出口已脱敏），不在此重复检查；
    但 content 之外的兄弟字段（如 messages[].tool_calls）属于非扫描面，照查。
    返回 None 通过；抛 ValueError 阻断（fail-closed）。
    """
    # 1) JSON key
    all_strings = []
    _walk_strings(data, 'req', all_strings)
    for path, s in all_strings:
        if s in ('user', 'system', 'assistant', 'tool') or not s.strip():
            continue  # 常规角色名/空串
        if _has_pii(s):
            raise ValueError(f'[pii_guardrail] DENY: PII in unscanned field -> {path} = {s[:40]!r}')
    # 2) messages：只查 content 之外的字段
    for i, m in enumerate(data.get('messages') or []):
        for k, v in m.items():
            if k == 'content':
                continue
            hits = []
            _walk_strings(v, f'messages[{i}].{k}', hits)
            for path, s in hits:
                if s in ('user', 'system', 'assistant', 'tool') or not s.strip():
                    continue
                if _has_pii(s):
                    raise ValueError(f'[pii_guardrail] DENY: PII in unscanned messages field -> {path} = {s[:40]!r}')
    # 3) tools 定义
    for i, t in enumerate(data.get('tools') or []):
        hits = []
        _walk_strings(t, f'tools[{i}]', hits)
        for path, s in hits:
            if not s.strip():
                continue
            if _has_pii(s):
                raise ValueError(f'[pii_guardrail] DENY: PII in tools definition -> {path} = {s[:40]!r}')
    return None
