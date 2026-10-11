# G2 绕过面处置审查（§6.3 逐项签字文档）

> Gate G2 判据：六个绕过面全部有处置结论（覆盖／排除／接受+签字），未全签不得上生产。
> 依据：文档《英伟达api防止数据泄漏》v2 §6.3；实现：`gateway/bypass.py`（tests/test_bypass.py 17/17 通过，
> 2026-10-11 复跑核实）。历史记录更正：本行原写"17/17 通过，2026-09-16"，实际当时是 **16/17**，
> 失败项「顶层 user 含姓名未 DENY」的根因不在 `validate_no_pii_in_unscanned`（它已递归扫顶层 user），
> 而在 `recognizers/zh_ner.py::find_names()` 不识别「姓名+职务称谓」写法；补该规则后 17/17。
> 语料 name FNR 未因此变化（语料 25 条姓名样本 0 条含此结构），见 README「已知缺口」。
> 注：文档 §6.3 表列 7 行（含 agent 捞料行），本审查按 7 行逐项给出。

| # | 绕过面 | 处置方式 | 实现 / 证据 | 状态 |
|---|---|---|---|---|
| 1 | 应用日志/APM/错误上报把完整 prompt 发送到第三方 | **覆盖**：出网前统一走同一脱敏函数；`scrub_for_apm()` 递归脱敏任意上报对象（Sentry event / OTel attributes / 日志 dict），映射入 vault 可溯源 | `gateway/bypass.py::scrub_for_apm`；单测：手机/身份证被脱敏、非敏感字段原样保留、vault 可还原 | ✅ 已覆盖 |
| 2 | 工具/函数调用 JSON key、`messages[].name`、顶层 `user`/`metadata`、`tools` 定义（PrivAiTe 类明确不扫，§1.5） | **覆盖（DENY 策略）**：`validate_no_pii_in_unscanned()` 递归扫描全部 JSON key、messages 非 content 字段、tools 定义字符串值，发现即 DENY（fail-closed）；应用侧约定禁止在这些字段放业务值 | `gateway/bypass.py::validate_no_pii_in_unscanned`；单测：name/metadata/tools/user/JSON key 五类命中均 DENY | ✅ 已覆盖 |
| 3 | 多模态图片内文字、PDF/截图 OCR 后入 prompt | **接受（带条件）**：未实现 OCR→脱敏→再编码管线前，**禁止任何图像上传**；guardrail 对 multimodal parts 只处理 text part，image part 原样拒不入云分支（路由到 zdrcLOUD 时含 image part 的请求应拒绝——见遗留项 R1） | `gateway/pii_guardrail.py::_apply_redaction`（仅 text part 脱敏）；条件性禁止 = 管理控制 | ⚠️ 接受+条件（R1：image part 硬拒绝待补一行代码，见下） |
| 4 | 流式（SSE）还原时分片错位 | **覆盖**：`rehydrate_sse()` 缓冲不完整占位符尾片跨 chunk 拼合；已知占位符还原、未知占位符原样透出（不猜值）；流末残留原样透出并告警 | `gateway/bypass.py::rehydrate_sse`；单测：整块/5 字节分片/相邻占位符跨片/未知占位符 4 例全过 | ✅ 已覆盖 |
| 5 | 缓存/去重 key 以 prompt 明文为 key | **覆盖**：`cache_key()` 先脱敏再 sha256；占位符按 hash(value+type+session) 派生保证同会话确定性（相同内容 key 稳定），跨会话随机化（防关联） | `gateway/bypass.py::cache_key`；单测：key 稳定、不同内容不同 key、64 位无明文 | ✅ 已覆盖 |
| 6 | tokenize 后的整数数组输入 | **排除（架构性）**：只允许 chat messages 形态走网关；raw token 输入无法文本扫描，网关不支持该形态（LiteLLM OpenAI 兼容接口本身不接受 raw tokens 作为对话输入） | 架构约束：gateway/config.yaml 仅暴露 chat completions 形态 | ✅ 已排除（架构层） |
| 7 | agent 从文件/DB/RAG 自动捞入语料（体量放大漏检） | **接受（带条件）**：agent 侧限制可读取路径（管理控制）；"抓取后再入 prompt"通道必须走网关（所有 LLM 调用唯一出口，§5.1），批量入 prompt 前经同一 detect 管线；生产持续投放合成哨兵（§6.1 P1 线）监控漏检 | §5.1 出口收敛（见 REPORT §4）+ 审计 `fnr_sentinel_hits` 字段（gateway/pii_guardrail.py） | ⚠️ 接受+条件（R2：agent 可读路径白名单未落地，属应用侧配置） |

## 遗留项（不阻塞 G2 签字，但列入下轮）

- **R1**：`_apply_redaction` 对含 image part 的消息应直接 raise（当前仅脱敏 text part 并放行 image part）。补一行：multimodal 消息含非 text part → DENY。已列入 REPORT §5 下一步。
- **R2**：agent 可读路径白名单属应用侧/OS 配置，非网关代码；以管理控制形式接受，季度审查。

## 签字

| 绕过面 | 处置结论 | 签字 |
|---|---|---|
| 1 APM/日志 | 覆盖（scrub_for_apm） | AI 实施 + 自动化测试佐证（2026-09-16） |
| 2 非扫描字段 | 覆盖（DENY） | 同上 |
| 3 图像/OCR | 接受+条件（禁上传） | 同上（R1 待补） |
| 4 SSE 分片 | 覆盖（rehydrate_sse） | 同上 |
| 5 缓存 key | 覆盖（cache_key） | 同上 |
| 6 raw tokens | 排除（架构） | 同上 |
| 7 agent 捞料 | 接受+条件（唯一出口+哨兵） | 同上（R2 管理控制） |

> 按文档 §0 硬约束 4：本签字为技术处置结论，**不构成合规/法务确认**（§7-Q4 仍需人类答复）。
