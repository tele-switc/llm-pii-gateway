# state-2026-09-30.md 补遗（P6 复算与未读文件核验）· 2026-09-30

- 本文是 `docs/state-2026-09-30.md`「未能核实」一节的闭环补遗，为**新增文件**；未改动、未删除任何既有文件，无 git 操作（该目录不是 git 仓）。
- 所有数字均为当日真实运行输出；密钥零明文。

## ① FNR 真实复算（2026-09-30）

命令（与主报告建议一致，--report 用新文件名，未覆盖 out/ 下任何既有文件）：

```
C:/Python314/python.exe E:/Projects/nvidia-leak-protection/poc/run_gateway_test.py \
  --tool presidio-zh --mode scan-only \
  --corpus E:/Projects/nvidia-leak-protection/corpus/zh_v1.jsonl \
  --report E:/Projects/nvidia-leak-protection/out/presidio-zh-recomputed-20260930.json
```

- 退出码 **2** = 脚本约定 `sys.exit(0 if G1=='PASS' else 2)`（run_gateway_test.py:177），即 G1 FAIL，**属预期而非脚本报错**。
- 复算报告落盘：`out/presidio-zh-recomputed-20260930.json`（新增）。

### 复算表（REPORT.md §2「终版」行逐格 vs 复算）

| 格 | REPORT.md §2 终版声称 | 复算值（2026-09-30） | 结论 |
|---|---|---|---|
| 身份证 FNR | 0% (0/18) | 0.0 (0/18) | 一致 |
| 手机 FNR | 0% (0/20) | 0.0 (0/20) | 一致 |
| 姓名 FNR | **72% (18/25)** | 0.72 (18/25) | 一致 |
| 地址 FNR | 0% (0/20) | 0.0 (0/20) | 一致 |
| 信用代码 FNR | 0% (0/14) | 0.0 (0/14) | 一致 |
| 银行卡 FNR | 0% (0/15) | 0.0 (0/15) | 一致 |
| 健康 FNR | 0% (0/20) | 0.0 (0/20) | 一致 |
| （邮箱，§1 正文） | 0% (0/15) | 0.0 (0/15) | 一致 |
| FP | 0% (0/148 token) | 0.0 (0/148) | 一致 |
| 对照组 | 25/25 原样放行 | 25/25 | 一致 |
| Gate | FAIL → 仅 name 超线（12% 上限） | G1=FAIL，violations 仅 name（0.72 > 0.12） | 一致 |

**结论：11/11 格全部一致，0 处不一致。** REPORT.md §2 终版行的数字今日可复现。

### 新发现 A：REPORT.md:50 所称「终版报告」与复算不一致

REPORT.md:50 写「终版报告：`out/presidio-zh-ner.json`」，但该**存档文件内容**与 REPORT.md §2 及今日复算均不符：

| 格 | 存档 presidio-zh-ner.json | 复算 / REPORT.md §2 |
|---|---|---|
| name | 52% (13/25) | 72% (18/25) |
| FP | 1.35% (2/148) | 0% (0/148) |
| 对照组 | 22/25（3 条对照文本被误脱敏） | 25/25 |
| impl | 同 | 同 |

即：REPORT.md 的数字**不是**来自它自己引用的这份存档文件——出处链断裂（该文件要么是更早一轮运行的残留，要么被后续覆盖）。引用该文件时需注明此矛盾。

## ② spaCy 实测

- `C:/Python314/python.exe -c "import spacy; print(spacy.__version__)"` → **失败**：`ModuleNotFoundError: No module named 'spacy'`。**当前环境未安装 spaCy。**
- 推论（重要）：今日复算的 name FNR 72%（检出 7/25）**完全由语境规则兜底产生，不含任何 spaCy 贡献**。REPORT.md:44 终版行标注「+ spaCy 姓名」在当前环境下不成立——72% 是"规则 only"值。
- zh_ner.py 兜底逻辑核实（`E:\Projects\nvidia-leak-protection\recognizers\zh_ner.py`）：
  - `_nlp()`（:85-93）对 import/load `zh_core_web_sm` 全部 try/except，任何异常置 `_spaCy=False` 并返回 None，**不会抛出**；
  - `find_names()`（:105-126）步骤 1-2 为纯正则语境规则（「联系人/经手人/负责人/经办人/医生/护士/患者/病人/患者家属：X」及「患者X，诊断…」无分隔符形态），步骤 3 spaCy PERSON 仅在 `nlp is not None` 时执行；
  - 地址 `find_addresses`（:45-59）与病历号 `find_medical`（:64-77）为纯规则，**零 spaCy 依赖**。
  - 结论：与测试声称「spaCy 不可用时由语境规则兜底」**一致** ✅，且本次复算本身就是兜底路径的实证。
- 顺带：存档 presidio-zh-ner.json 的 name 检出 12/25 高于今日规则 only 的 7/25，提示该存档运行时环境里 spaCy **可能**在位（待考，不作结论）。

## ③ 三个此前未读文件的要点

### poc/grep_egress.py（71 行）

- 对 pcap/任意字节流做「宁多报不漏报」的宽松真值匹配：同时搜 UTF-8 与 UTF-16LE 两种编码（:46-48），**不做协议重组**；真值来自 `corpus/zh_v1.labels.jsonl` 的 entities.value（:18-26）。
- 命中分两类：real PII（**必须为 0**）与 TRADE_SECRET_CONTROL（对照组允许整段命中，:54-55）；verdict=PASS 仅当 real=0（:64-66），exit 2=FAIL。
- **实测复核**（本日，对未脱敏语料 zh_v1.jsonl 本体做字节流）：truth=150、hits=150/150（real 150、control 0），与 REPORT.md:59「grep_egress 对未脱敏语料复算命中 150/150」**一致** ✅（exit 2 属预期——正证明脚本对在场真值敏感）。
- 局限：纯字节扫描，压缩/分块/其他编码的流可能漏报（自述宽松匹配只覆盖原文与 UTF-16LE）。

### runbook/incident.md（67 行）

- 五步事件响应：①判定外发内容（<5min，要求用 grep_egress.py 做**出口字节真值核查**而非只看"发过请求"）→ ②停云端分支、保留现场 → ③判定映射表是否同泄（占位符泄露 vs 原值泄露**级别差一档，不要混报**）→ ④法定上报评估交法务、**禁止以"已脱敏"自判跳过** → ⑤48h 内复盘并向语料植入 ≥1 条合成复现用例（禁用真实泄露值），重跑 run_gateway_test，按 G1 降级类别而非调阈值。
- 底部「演练记录」**已填**：2026-09-16（自动演练 drill.py）、总耗时 0.023s、无卡点、G3 PASS——证实 REPORT.md:71「记录已填」属实，同时坐实 REPORT.md:62-63 §3 表「首次演练未做 / 演练记录待首填」为陈旧表述（主报告②已指出的文档自相矛盾，此处为其提供 incident.md 侧证据）。

### g2/bypass_review.md（35 行）

- 7 个绕过面逐项处置+签字：#1 APM/日志=覆盖（scrub_for_apm）、#2 非扫描字段=覆盖（DENY）、#3 图像/OCR=**接受+条件**（禁上传）、#4 SSE 分片=覆盖（rehydrate_sse）、#5 缓存 key=覆盖（cache_key）、#6 raw tokens=**架构排除**、#7 agent 捞料=**接受+条件**（唯一出口+哨兵）。
- 遗留项现状：**R1**（image part 硬拒绝待补）——已核实 `gateway/pii_guardrail.py:109-110` 非 text part 仍原样放行、无 raise，**R1 至今未补**，与文件自述一致；**R2**（agent 可读路径白名单）以管理控制形式接受、季度审查，非网关代码。
- 注意其 :4 声称「tests/test_bypass.py **17/17** 通过（2026-09-16）」，而主报告当日实跑为 **16/17**（1 FAIL：顶层 user 含姓名未 DENY）——该签字文件的佐证数字与当前代码行为不符，未随代码状态更新。

## ④ G2 核对（REPORT.md:70 vs bypass_review.md）

- REPORT.md:70：「5 覆盖 + 1 架构排除 + 2 接受带条件」。
- bypass_review.md 实际：**4 覆盖**（#1/#2/#4/#5）+ 1 架构排除（#6）+ 2 接受带条件（#3/#7）= 7 项。
- 「5+1+2」合计 8，与 7 项对不上；**「覆盖」多计 1 项，REPORT.md:70 该计数不准确**。
- 其余表述核对：遗留「R1：image part 硬拒绝待补；R2：agent 可读路径白名单属管理控制」与文件**一致** ✅；「逐项签字见 g2/bypass_review.md」属实（签字表在 :24-32）✅。
- 小瑕疵（bypass_review.md 内部）：:3 判据写「六个绕过面」，:5 又按文档 §6.3 表 **7** 行逐项——同一文件内"六/七"表述不一致。

## ⑤ 主报告 state-2026-09-30.md 需要修订的条目（只列事实，未改它）

1. 「未能核实」第 1 条（REPORT 百分比未复算）→ **已闭环**：§2 终版行 11/11 格复算一致（见本文①）；可改写为"已复算，见 state-addendum-20260930.md"。
2. 「未能核实」第 3 条（spaCy 是否安装）→ **已闭环**：未安装（ModuleNotFoundError）；72% 为语境规则兜底值；zh_ner.py 兜底逻辑与测试声称一致（见本文②）。
3. 「未能核实」第 2、4 条（grep_egress.py / runbook/incident.md / g2/bypass_review.md 未通读）→ **已闭环**：要点见本文③。
4. **新发现 A**：`out/presidio-zh-ner.json`（REPORT.md:50 所称"终版报告"）与 REPORT.md §2 及复算均不一致（name 52% vs 72%、FP 1.35% vs 0%、对照组 22/25 vs 25/25）——出处链断裂，主报告如引用该文件需注明（见本文①）。
5. **新发现 B**：REPORT.md:70 的 G2 计数「5 覆盖」应为「4 覆盖」（bypass_review.md 实为 4+1+2=7）（见本文④）。
6. **新发现 C**：g2/bypass_review.md:4 声称 test_bypass 17/17，与主报告实跑 16/17（1 红测试）不符——主报告②的"绕过面红测试未被执行方记录"判断再获一处书证（见本文③）。
7. 补强证据：grep_egress「150/150」（REPORT.md:59）本日独立复算属实；incident.md 演练记录已填属实——主报告②中相应两行判断获得直接证据。
