# 审计查询手册（G3 验收：5 分钟内回答"是否出网/出的字面/谁标注"）

日志文件：`audit/audit.jsonl`（每请求一行 JSONL，schema 见 `audit/schema.jsonl`）。

## Q1. 这条请求是否离开本机？

```bash
grep '"request_id": "<RID>"' audit/audit.jsonl | python -c "import sys,json; r=json.loads(sys.stdin.readline()); print(r['egress_decision'], r['provider'])"
# 输出 LOCAL / ZDRCLOUD / DENY 之一
```

- `DENY` → 未出网（guardrail 拦截）。
- `LOCAL` → 只到本地模型（ollama/vLLM），无外部端点。
- `ZDRCLOUD` → 出网到 ZDR 供应商，出网字面 = 脱敏后 body（用 Q2 还原哈希）。

## Q2. 离开的字面是什么？

审计只存 `redacted_body_sha256` 与长度（§5.5：不存原文）。

1. 用 `request_id` 反查当次脱敏产物缓存（网关进程内 ring buffer 或 vault 条目，保留期 ≤ 审计保留期）：

```bash
# vault 条目（加密存储；密钥独立存放，§6.2）
vault get "audit:<RID>"   # 需网关进程权限；无权限走人工审批
```

2. 若 vault 条目已过期：只能回答"出过、哈希为 X、长度 N、类别集合为 Y"，字面不可还原——这是设计取舍（§6.2：映射表保留期 ≤ 审计保留期）。

## Q3. 谁标注的级别？

```bash
grep '"request_id": "<RID>"' audit/audit.jsonl | python -c "import sys,json; r=json.loads(sys.stdin.readline()); print('claimed:', r['data_class_claimed'], '| actor:', r['actor'], '| detected:', r['detected_classes'])"
```

- `data_class_claimed` = 调用方自报标签（缺失为 `UNLABELED(D3)`）。
- 实际决策取"标签与内容检测之严"（§5.3-3），`detected_classes` 是检测侧证据。

## 生产哨兵核查（§6.1 P1 线）

```bash
python -c "
import json
hits=[json.loads(l) for l in open('audit/audit.jsonl',encoding='utf-8')
      if int(json.loads(l).get('fnr_sentinel_hits',0))>0]
print('sentinel hits:', len(hits))   # 期望 0；>0 即 P1
"
```

## 演练记录要求（§9.1 runbook/incident.md 验收）

- 每次演练记录：开始时间 → 回答时间（目标 < 5 分钟）→ 三条答案 → 阻塞点。
- 季度回归时（§6.4）连同 §4 重跑一并执行。
