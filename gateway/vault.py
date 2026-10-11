# -*- coding: utf-8 -*-
"""占位符 vault（§6.2）：映射表加密存储、密钥独立存放、会话级随机化、保留期管理。

- 映射表 = 可重识别密钥：泄露它则脱敏全部作废（§5.6）。
- 密钥来源（优先级）：环境变量 VAULT_KEY（独立存放，不与 vault 同备份）→
  OS 派生文件 vault.key（0600，单独位置）。
- 会话级随机化映射：同实体跨会话不同 token（§6.2）。
- 保留期 ≤ 审计日志保留期；会话结束即删最安全（§6.2）。
"""
import base64
import hashlib
import json
import os
import secrets
import time
import uuid

from cryptography.fernet import Fernet

VAULT_DIR = os.environ.get(
    'VAULT_DIR', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vault'))
KEY_PATH = os.environ.get('VAULT_KEY_FILE', os.path.join(VAULT_DIR, 'vault.key'))
VAULT_TTL_SEC = int(os.environ.get('VAULT_TTL_SEC', '3600'))  # 默认会话级 1h


def _fernet():
    if 'VAULT_KEY' in os.environ:
        return Fernet(os.environ['VAULT_KEY'].encode())
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, 'rb') as f:
            return Fernet(f.read())
    os.makedirs(VAULT_DIR, exist_ok=True)
    key = Fernet.generate_key()
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(key)
    return Fernet(key)


def redact(text: str, spans, session_id=None) -> tuple:
    """把 spans [(start,end,type)] 替换为占位符。返回 (redacted_text, mapping)。
    mapping: {placeholder: {'value':..., 'type':...}} —— 只在内存与 vault 密文中存在。

    占位符 token 由 hash(value+type+session) 派生：
    - 同一会话内同一实体 → 同一占位符（共指一致、cache_key 确定性）
    - 跨会话 → 不同 token（§6.2 会话级随机化，防跨请求关联）
    """
    session_id = session_id or uuid.uuid4().hex
    out, last, mapping = [], 0, {}

    def _token(value, ty):
        seed = f'{value}|{ty}|{session_id}'.encode('utf-8')
        return hashlib.sha256(seed).hexdigest()[:12]

    for s, e, ty in sorted(spans):
        ph = f'⟨{ty[:2].upper()}-{_token(text[s:e], ty)}@{session_id[:8]}⟩'
        out.append(text[last:s])
        out.append(ph)
        mapping[ph] = {'value': text[s:e], 'type': ty}
        last = e
    out.append(text[last:])
    return ''.join(out), mapping


def save(session_id, mapping) -> str:
    """加密写入 vault，返回条目引用（vault://<文件名>）。"""
    os.makedirs(VAULT_DIR, exist_ok=True)
    blob = _fernet().encrypt(json.dumps(mapping, ensure_ascii=False).encode('utf-8'))
    name = f'session-{session_id[:8]}.enc'
    with open(os.path.join(VAULT_DIR, name), 'wb') as f:
        f.write(blob)
    return f'vault://{name}'


def load(ref: str) -> dict:
    name = ref.split('/')[-1]
    with open(os.path.join(VAULT_DIR, name), 'rb') as f:
        return json.loads(_fernet().decrypt(f.read()))


def delete(ref: str):
    name = ref.split('/')[-1]
    p = os.path.join(VAULT_DIR, name)
    if os.path.exists(p):
        os.remove(p)


def gc(now=None, ttl=None):
    """到期即删（§6.2 保留期）。返回删除条数。"""
    now = now or time.time()
    ttl = ttl if ttl is not None else VAULT_TTL_SEC
    n = 0
    if os.path.isdir(VAULT_DIR):
        for name in os.listdir(VAULT_DIR):
            if name.endswith('.enc'):
                p = os.path.join(VAULT_DIR, name)
                if now - os.path.getmtime(p) > ttl:
                    os.remove(p)
                    n += 1
    return n
