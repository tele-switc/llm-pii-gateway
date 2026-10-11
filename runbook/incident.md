# 泄露事件响应 Runbook（§6.5）

> 目标：泄露已发生时，15 分钟内完成 1–4 步；步骤 5 在 48 小时内完成。

## 前置

- 权限：网关管理员（可读 `audit/audit.jsonl`、可切 `local_only`）。
- 工具：`poc/grep_egress.py`（出口字节真值核查）。

## 步骤

### 1. 判定实际外发了什么（< 5 分钟）

```bash
# 拉出事件时间窗内的全部出网请求
awk -v t1="$T1" -v t2="$T2" '{print}' audit/audit.jsonl | python -c "
import sys,json
for l in sys.stdin:
    r=json.loads(l)
    if t1<=r['ts']<=t2 and r['egress_decision']=='ZDRCLOUD':
        print(r['request_id'], r['detected_classes'], r['redacted_body_sha256'])
"
```

- 对每条 `ZDRCLOUD` 记录，用 `audit/queries.md` Q2 还原脱敏后字面。
- **判定"哪些字段"**：用 `poc/grep_egress.py --pcap <该窗口出口抓包> --truth <事件相关语料/哨兵>` 做真值命中核查，而不是只看"发过一条请求"。

### 2. 停云端分支，保留现场（< 5 分钟）

```bash
# 网关切 local_only（config.yaml: router_settings.fallbacks 已为空，
# 直接禁用 zdr-openrouter / nvidia-free 两个 model_list 条目或加 allowed_models 白名单只留 local-default）
# 注意：只停分支，不清理日志/抓包 —— 现场是取证材料
```

### 3. 判定映射表是否同时外泄（< 5 分钟）

- 检查 vault 访问日志与备份链：`vault get` 调用、对象存储生命周期策略里有无 vault 备份条目。
- 结论二选一：
  - **占位符泄露**（映射表安全）：级别 = 部分 PII 结构外发，可重识别性受限。
  - **原值泄露**（映射表同泄）：级别上移一档，直接按原值泄露上报评估。
- 两者级别差一档，不要混报。

### 4. 法定上报评估（交法务，不自判）

- 输入：步骤 1 的字段清单 + 步骤 3 的级别判定 + 涉及自然人数量（估算口径写清楚）。
- **禁止**自行以"脱敏过"为由跳过上报评估（§6.5-4 / §2.4：本地映射表的存在意味着可重识别性 ≠ 匿名化）。
- 输出：法务的上报/不上报结论 + 理由，存档到事件目录。

### 5. 复盘 → 语料库变大（48 小时内）

- 每个事件必须在 `corpus/zh_v1.jsonl` 增加 ≥1 条植入用例（复现该事件的植入形态，用合成值，**不得用真实泄露值**——用真实值写语料本身就是第二次泄露）。
- 重跑 `python tests/test_recognizers.py && python poc/run_gateway_test.py --tool presidio-zh --mode scan-only --corpus corpus/zh_v1.jsonl --report out/presidio-zh.json`。
- 若新增用例暴露漏检 → 按 Gate G1 流程降级对应类别（改 `gateway/pii_guardrail.py` 的 UNPROVEN_CATS），不是调低阈值。

## 演练

- 频率：随季度回归（§6.4）。
- 方法：用合成哨兵构造一次模拟泄露（注入已知值 → 查审计 → 切 local_only → 走查步骤 3/4 的判定）。
- 记录：每步耗时、总耗时、卡点，写回本文件底部"演练记录"。

## 演练记录

| 日期 | 总耗时 | 卡点 | 结论 |
|---|---|---|---|
| 2026-09-16（自动演练 drill.py） | 0.023s | 无 | G3 PASS：三问均由 request_id 在 5 分钟内回答 |
