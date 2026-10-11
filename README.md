# llm-pii-gateway

把云端 LLM API 当成唯一出口管起来：**先识别中文 PII，再决定这段文本能不能出网**。

一个挂在 LiteLLM 网关上的 guardrail + 中文 recognizer + 加密占位符保险箱 + 每请求审计日志。
敏感文本要么脱敏后才走云端，要么直接失败（fail-closed），不静默降级。

> **命名说明**：本仓库原工作目录名是 `nvidia-leak-protection`，指的是"用 NVIDIA 等云端 LLM API 时
> 防止数据泄露"，**与显卡显存残留数据、或任何 NVIDIA 未公开漏洞无关**。合同条款分析全部基于公开的
> Trial Terms / Privacy Policy。改名 `llm-pii-gateway` 是为了不再引起这种误会。

## 它解决什么

开发者把公司数据丢给云端模型时，通常会犯三个错：以为"供应商说不训练"就够了；以为
"这段里没有身份证号"就不用处理；以及把整段 prompt 原样上报给 APM/Sentry。

本项目的立场是：**把出网当成一个需要每请求决策的动作**。

- **分级**：D0 公开 / D1 普通内部 / D2 含 PII / D3 凭据·病案·未发布内容。缺标签一律按 D3 处理。
- **决策**：D3 直接 `deny` 不出网；D2 只有在**实测检出率达标的类别**上，才允许脱敏后发往
  已确认 ZDR（zero data retention）的供应商；D0/D1 可自由路由。
- **失败即关闭**：detector 抛异常、超时、模型不可用 → 阻断请求，不 fallback 到云端。
  配置里 `fallbacks: []`、`num_retries: 0` 是刻意的。

## 组件

| 路径 | 作用 |
|---|---|
| `gateway/pii_guardrail.py` | LiteLLM 回调：检测 → 分级 → 路由/拒绝；`UNPROVEN_CATS` 是"实测未达标类别"的黑名单 |
| `recognizers/cn_recognizers.py` | 中文强规则识别：身份证（含校验位反例）、手机、银行卡、统一社会信用代码、邮箱、全角、跨行 |
| `recognizers/zh_ner.py` | 姓名/地址/病历号检测；spaCy 可用时辅助姓名，不可用时自动降级为纯规则 |
| `gateway/vault.py` | 占位符↔原值映射，Fernet 加密存放，密钥与 vault 不同目录备份 |
| `gateway/bypass.py` | 绕过面处置：APM 脱敏、缓存 key 哈希、SSE 分片还原、非扫描字段 DENY |
| `gateway/config.yaml` | 网关配置样例（凭据全部 `os.environ/...`，仓库内不含任何真实 key） |
| `audit/` | 每请求 JSONL 审计（存脱敏后哈希与长度，不存原文）+ 5 分钟还原演练脚本 |
| `corpus/` | 240 条**合成**评测语料（`generate_corpus.py` 固定 seed 生成，禁止使用真实数据） |
| `poc/` | 评测跑分与出网 grep 复核 |
| `out/` | 实测结果 JSON（本报告所有百分比的来源） |
| `REPORT.md` | 决策报告：条款结论 + 实测数字 + Gate 状态 |

## 快速开始

```bash
pip install cryptography            # 必需
pip install spacy && python -m spacy download zh_core_web_sm   # 可选：姓名 NER 增强
pip install litellm                 # 只在真要起网关时需要

# 1. 跑单测（无需网关、无需网络）
python tests/test_recognizers.py
python tests/test_guardrail.py
python tests/test_zh_ner.py
python tests/test_bypass.py

# 2. 复现评测数字（scan-only，不需要 API key）
python poc/run_gateway_test.py --tool presidio-zh --mode scan-only \
    --corpus corpus/zh_v1.jsonl --report out/presidio-zh.json

# 3. 起网关（凭据自己给，仓库里一个都没有）
export NVIDIA_API_KEY=...  OPENROUTER_API_KEY=...  LITELLM_MASTER_KEY=...
litellm --config gateway/config.yaml --port 4000
```

> `--tool presidio-zh` 里的 **presidio-zh 是本仓库自建中文规则层的代号，不是
> `microsoft/presidio` 那个库**，装了 presidio 也不会被这段代码用到。

## 实测数字（中英混合，n=240，scan-only）

| 类别 | FNR | 判定 |
|---|---|---|
| 身份证 | 0% (0/18) | 达标 |
| 手机 | 0% (0/20) | 达标 |
| 银行卡 | 0% (0/15) | 达标 |
| 统一社会信用代码 | 0% (0/14) | 达标 |
| 邮箱 | 0% (0/15) | 达标 |
| 地址 | 0% (0/20) | 达标（规则层） |
| 病历号 | 0% (0/20) | 达标（规则层） |
| **姓名** | **72% (18/25)** | **未达标**（阈值 12%）→ 已按策略降级为仅 ZDR 供应商 |
| 无 PII 对照组（商业秘密 25 条） | — | **25/25 整段放行**：脱敏根本不解决 D3 |

> 上面这张表是**未安装 spaCy 的纯规则层**在本机复跑出来的（`out/presidio-zh-recomputed-20260930.json`）。
> 装了 `zh_core_web_sm` 的历史基线姓名 FNR 是 **52%**（`out/presidio-zh-ner.json`，spaCy 负责 PERSON）。
> 两个数都对，只是环境不同——引用前请先确认自己环境里 `_nlp()` 是否可用。
>
> 对照组同理，并且有个坑要提醒：无 NER 环境下是 **25/25 原样放行**（当前代码重跑实测一致），
> 而 `out/presidio-zh-ner.json` 记的是 **22/25**——装了 spaCy 之后有 3 条商业秘密被误判成姓名。
> 该文件自身的 `note` 字段仍写着"100% 原样放行"，与它自己的数字不符；
> `docs/state-addendum-20260930.md` 把这条列为"出处链断裂"，属已知问题，读那份 JSON 时按数字为准。

单测复跑（2026-10-11）：`test_recognizers` 23/23、`test_guardrail` 19/19、`test_zh_ner` 15/15、
`test_bypass` 17/17。

结论最重要的一条：**脱敏是概率性控制**。它把"可识别泄露"降成"部分漏检 + 不可识别内容外发"，
对不含 PII 的商业机密无效——所以数据分级（L0）不能省，D3 只能靠不出网。

## 已知缺口（如实列出）

1. ~~`test_bypass.py` 有一条真实失败~~ **已修复（2026-10-11）**：`validate_no_pii_in_unscanned()`
   其实一直在递归扫顶层 `user`，真正的洞在检测端——`find_names()` 认不出「张三丰经理」这种
   **前面没有语境词、姓名后面直接跟职务称谓**的写法，于是那层扫描对这类值是空转。
   补了一条以常见姓氏表收敛的「姓名+职务称谓」规则后，`test_bypass.py` 17/17。
   两点要说清：① 这条规则**不改变**下面语料表里的姓名 FNR——语料 25 条姓名样本没有一条
   是这个结构（实测 0/25），它补的是非扫描字段那条路径；② 残留未覆盖 `张总`、`王董`
   这类单字简称谓，要再往上走得靠真正的中文 NER。
2. **中文姓名检出 72% FNR**：需要更强的中文 NER（微调模型或更大语料）。达标前姓名类别不出免费端点。
3. **不扫多模态**：图片内文字、PDF OCR 均未实现。当前处置是**禁止任何图像上传**。
4. `_apply_redaction` 对 image part 的直接 raise 仍待补（`g2/bypass_review.md` 遗留 R1）。
5. 条款/合同层（DPA、跨境、供应商书面授权）不是技术问题，本仓库不回答。

## 凭据政策

仓库内**不含任何真实 API key、token、私钥或加密密钥文件**。配置里凭据一律写成
`os.environ/...`。运行期产生的 `vault/*.key`、`*.enc`、审计日志都在 `.gitignore` 里，
测试产物落系统临时目录并自动清理，不会留在仓库。

## 许可

MIT。见 `LICENSE`。
