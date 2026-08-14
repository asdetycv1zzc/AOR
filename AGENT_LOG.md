# AOR Agent 协作日志

> 时间均为 UTC；主开发会话为 `019fc579-4a9f-7471-91f5-1f763a975069`。
>
> 全程模型：`gpt-5.6-sol`，用户指定 reasoning effort `max`。
>
> Superpowers：全程未使用。下文的 subagent/review 均为 Codex 原生协作，不应被解释为 Superpowers 过程证据。
>
> Git 提交树是权威实现记录；本日志只列关键转折，不复写全部 589 个提交。

## 2026-08-02 18:43:29 - DESIGN-01 初始构想

- **Prompt / context**：用户提出目标、计划、执行、审计、智库五层组织器，要求执行与审计分离、磁盘知识引用、固定审计顺序和跨模型协议。
- **Skill**：未使用 Superpowers；外部 ChatGPT brainstorming 对话。
- **Agent 输出**：建议把五层作为逻辑角色，由确定性 Orchestrator 控制状态、预算、权限和 Agent 生命周期；提出 A2A/MCP、版本化 Artifact 和非 LLM 验证。
- **人工干预**：用户要求逐项讨论，未直接接受完整建议。
- **证据**：`ChatGPT-Agent组织器设计可行性.json` messages 0-1。
- **教训**：层级角色能表达职责，但可靠性必须由代码状态机和验证器提供。

## 2026-08-02 18:52:08 - DESIGN-02 用户取舍

- **Prompt / context**：用户逐项接受或否决第一轮建议。
- **Skill**：未使用。
- **Agent 输出**：形成 Proposer/Challenger、全局并发 8、三次失败、Knowledge Service/Curator、revision+hash 引用和跨平台能力分级。
- **人工干预**：用户否决目标协商最大轮次；指定第 3 次失败直接交用户而非 Planner；部分保留本地路径/行号。
- **证据**：brainstorming messages 2-3。
- **教训**：AI 的通用“有界循环”建议不能覆盖产品所有者明确的“不一致就不开发”。

## 2026-08-02 18:57:23 - DESIGN-03 生产基线 SPEC

- **Prompt / context**：要求生成可供其他智能体从零实施的完整 SPEC。
- **Skill**：未使用。
- **Agent 输出**：生成 49 章生产基线、15 个工作包和 100 项验收；采用 Go、PostgreSQL、Temporal、NATS、S3、OPA 和 OpenTelemetry 参考栈。
- **人工干预**：无逐章签署；签署区保持 `null`。
- **证据**：brainstorming messages 4-5；`SPEC.md`。
- **教训**：完整不等于合适。生产平台范围后来显著超过课程核心 harness 范围。

## 2026-08-03 02:34:51 - WP-00/01 开发启动

- **Prompt / context**：`/goal 请严格遵守AGENTS.md的规范，完成SPEC.md中的项目。`
- **Skill**：未使用；Codex 原生主会话。
- **Agent 输出**：建立仓库基线、工作包结构、AOP/Schema 和跨语言协议合同。
- **Subagent / review**：启动 `coverage_audit`、`test_audit` 和 `wp02_review`。
- **人工干预**：要求严格按 AGENTS.md 原子提交，不把用户的 `SPEC.md`/`AGENTS.md` 混入实现提交。
- **提交**：`cb80311`、`5d95669`、`89d0a77`。
- **教训**：允许路径和交接文档可以降低并行冲突，但不是 worktree/PR 的替代证据。

## 2026-08-03 02:42:48 - REVIEW-01 状态与租户边界

- **Prompt / context**：对 WP-02 状态/投影实现做独立审查。
- **Skill**：未使用。
- **Subagent 输出**：发现跨租户投影、跨项目任务授权和 PostgreSQL 约束缺陷。
- **人工干预**：无；主 Agent 接受 findings，先补失败场景再提交。
- **提交**：`d8e4997` 及后续 WP-02 修复提交。
- **教训**：内存状态机通过不代表数据库租户边界完整，必须检查持久化和授权交点。

## 2026-08-03 03:37:12 - REVIEW-02 工具、身份与平台证明

- **Prompt / context**：WP-03 至 WP-06 并行实现和复核。
- **Skill**：未使用。
- **Subagent 输出**：`wp06_review` 指出配置期望值不能冒充已验证 runtime attestation，且最初只有测试替身而无可部署后端。
- **人工干预**：接受实际证明与 fail-closed 要求。
- **提交**：`4c9fa9c`、`53e6948`、`8f345ff`、`e948a27`。
- **教训**：安全元数据必须描述真实能力；“配置了隔离”不等于“隔离已经生效”。

## 2026-08-03 04:49:53 - REVIEW-03 Agent Runtime 提交边界

- **Prompt / context**：WP-07 Agent 生命周期、Lease 和结果提交审查。
- **Skill**：未使用。
- **Subagent 输出**：发现授权失败会卡 `STARTING`、校验到写入间存在 Lease 竞态、结果未携带 fencing token。
- **人工干预**：主 Agent 修正测试夹具后保留真实回滚语义。
- **提交**：`f0d54b7`。
- **教训**：长模型调用结束后的 commit-time revalidation 与启动授权同样重要。

## 2026-08-03 05:09:15 - WP-08..15 主体完成

- **Prompt / context**：按工作包 DAG 继续 Goal/Plan、Repository、Audit、Knowledge、Integration、Deployment、Conformance。
- **Skill**：未使用。
- **Subagent / review**：发现跳过的 Windows 测试、第三次 attempt trace、CLI 零退出码和 merge 并发双副作用等问题。
- **人工干预**：用户没有对内部拆分逐项修改；AGENTS.md 继续要求独立小提交。
- **提交**：`5bfd815`、`97f7d2b`、`e883094`、`85226f4`、`d19df46`、`0c1bef7`、`f73169f`、`363d0bd`。
- **教训**：工作包“主体代码存在”不能直接提升为端到端 implemented，conformance 状态必须随证据降级或升级。

## 2026-08-04 02:15:34 - AUDIT-01 用户质疑完成度

- **Prompt / context**：用户问“确定 SPEC 要求对应代码已经全部完成了吗”。
- **Skill**：未使用。
- **Agent 输出**：停止声称全部完成，重新核对验收矩阵、迁移、服务接线和真实进程路径；发现大量 `planned` 及只有测试调用方的服务。
- **人工干预**：用户要求以实际可运行功能而不是测试数量判断进度。
- **提交**：随后多批 control API、eventing、workflow、servicebootstrap 和数据库修复。
- **教训**：代码覆盖局部原语不等于部署后业务闭环，完成度必须从用户入口追到持久副作用。

## 2026-08-06 至 2026-08-07 - SCOPE-01 从生产外围回到核心链路

- **Prompt / context**：用户追问灾备、复杂度、实际流程，并指出 Worker 应共享项目目录、审计应针对 Git 分支；随后质疑“代码未完成时在跑什么测试”。
- **Skill**：未使用。
- **Agent 输出**：承认把通用“先跑测试”置于用户“先完成核心链路”之上，区分课程 TEST 链路与 Production 扩展。
- **人工干预**：用户明确要求减少过度设计，优先 Goal -> Plan -> Execution -> Audit。
- **提交**：TEST profile、共享项目路径、核心执行与审计链相关提交；代表 `7750edf`。
- **教训**：测试不能替代进度；安全外围也不能在核心用户路径不可用时占据全部资源。

## 2026-08-08 至 2026-08-09 - E2E-01 真实数据库与 WebUI 闭环

- **Prompt / context**：用户授权修改 AOR 测试数据库并要求在局域网启动；随后要求 WebUI 配置 OpenAI、DeepSeek、Claude、Grok 的 Base URL、API Key 和连接测试。
- **Skill**：未使用。
- **Agent / review 输出**：真实项目暴露 Submission schema、未拥有变更、LLM audit 失败恢复、投影读取 503 等接线缺口；逐项修复并部署验证。
- **人工干预**：用户决定供应商配置不得只存在 Compose，也不得进入 Git。
- **提交**：`2c4593e`、`2129614` 及 provider/WebUI 相关提交。
- **教训**：真实上游、数据库和浏览器测试能发现 mock/单元测试覆盖不到的契约漂移。

## 2026-08-10 至 2026-08-11 - E2E-02 流式体验与模型能力

- **Prompt / context**：用户报告重复消息、首 token 2 秒但页面 10 秒才显示、Goal 未决事项流程，并追问同步/流式路径和模型输出限制。
- **Skill**：未使用。
- **Agent / review 输出**：修复活动幂等、SSE 立即首帧、reasoning/content 分流、异步持久化、真实流式连接测试、模型 output/thinking 配置。
- **人工干预**：用户要求连接测试必须反映实际流式能力，而非仅同步成功。
- **提交**：`c161912`、`45d436c`、`73ed266`、`e40aad2`、`75465b5` 等。
- **教训**：供应商首 token 指标与用户可见首字符是两条链，必须从上游 SSE 一直测到浏览器渲染。

## 2026-08-12 06:41:08 - TOOLCHAIN-01 用户修正安装策略

- **Prompt / context**：用户指定 GCC 使用 crosstool-ng 构建的路径无关工具链；其他工具链要求 GoalSpec 向用户索取官方链接，不允许 Agent 自行搜索下载。
- **Skill**：未使用。
- **Agent 输出**：实现 URL/SHA/授权绑定、归档安全解压、隔离探测、持久队列和 Goal 自动恢复；GCC 改为用户上传 relocatable archive。
- **Subagent / review**：发现 URL 未绑定字节、下载期间 Lease 不续期、恢复 SQL 漏掉上传类型、发布前第二次探测挂载缺失。
- **人工干预**：否决自动构建 crosstool-ng，固定用户提供制品。
- **提交**：`17ce6cd` 至 `10624fa`，代表 `4c88cda`、`f980561`、`7d2167c`。
- **教训**：Agent 可以提出需求，可信来源和字节授权必须由用户/确定性 Provisioner 固化。

## 2026-08-13 04:24:38 - CONTEXT-01 长协商上下文压缩

- **Prompt / context**：用户提出 GoalSpec 长期反复确认后超过模型窗口，询问是否有窗口参数和 WebUI 配置。
- **Skill**：未使用。
- **Agent / review 输出**：实现 model route context window、90% compaction threshold、95% effective budget、Manifest-bound checkpoint、工具/Schema overhead 预算和伪造引用回归测试。
- **人工干预**：用户要求临时原始上下文容量扩大至 256 MiB，并确认 OpenAI MaxInput 258K、ContextWindow 400K；强调核对每模型原值。
- **提交**：`a816cd0`、`7d2c882`、`9cf01a4`。
- **教训**：窗口总量、最大输入、最大输出和本地 byte cap 是不同概念；压缩首先是信任问题，其次才是摘要问题。

## 2026-08-13 至 2026-08-14 - DEPLOY-01 单人 TEST 默认链路

- **Prompt / context**：用户要求重建镜像、列出部署方法、确认 clone 后一键启动，并要求 TEST 直接作为默认，不改动 Production 代码路径。
- **Skill**：未使用。
- **Agent / review 输出**：修复 Compose 路由环境与 NATS payload 配置，添加极简教程；所有 AOR readiness endpoint 验证为 ready。
- **人工干预**：明确只默认启用 TEST，反对继续增加“沙箱套沙箱”式设计。
- **提交**：`9a64c29`、`b15fc43`。
- **教训**：默认路径应匹配实际单人用户，Production 设计不能增加 TEST 启动前提。

## 2026-08-14 - COURSE-01 Harness 缺口审查与最小功能补充

- **Prompt / context**：两份课程要求进入工作区，用户询问符合度并要求后续避免过度设计。
- **Skill**：未使用。
- **Agent / review 输出**：审查确认自实现主循环、可注入 ModelGateway、工具分发、反馈与 Context/Knowledge 已存在；发现显式领域机制章节、统一 mock 演示和课程过程文档缺失。
- **人工干预**：用户拒绝新增独立命令沙箱，要求复用已有 Worker/审批边界并保持 TEST 默认。
- **提交**：`4167ec8`、`3a16877`、`d1378b9`、`8cfbe44`。
- **教训**：课程机制需要最小、可离线证明的组合测试；安全 review 不能自动授权扩大用户要求的架构范围。

## 2026-08-14 - COURSE-DOC-01 课程文档重建

- **Prompt / context**：完善 `SPEC.md` 和除 `REFLECTION.md` 外的文档；brainstorming 使用导出 JSON；过程以 Git 树和历史 review 为证；不得启动 subagent。
- **Skill**：未使用；本任务也未启动 subagent。
- **Agent 输出**：补充用户故事、课程 TEST 范围、领域与机制设计、上下文压缩 main contribution、Key 生命周期；创建 PLAN、SPEC_PROCESS、AGENT_LOG；重写 README。
- **人工干预**：用户明确要求写明不使用 Superpowers，原因是 `gpt-5.6-sol max` 后续训练已覆盖大部分方法，再叠加会降低效率；同时禁止 AI 创建反思报告。
- **提交**：将在本轮文档提交后回填。
- **教训**：过程文档的价值在于暴露偏差，不在于把缺失步骤事后包装成已完成。

## 当前未闭环事项

1. `COURSE-DEMO-01`：仍缺一个统一 mock-LLM 测试同时证明危险动作拦截、失败后动作改变和 Manifest 压缩行为。
2. 实现前陌生 Agent 冷启动、worktree/PR 和逐 task 红-绿-重构没有历史证据，不能补造。
3. 最终远端 CI pass、助教仓库访问和公网 WebUI 需要仓库所有者/部署者执行。
4. 课程 §4.8 要 GitHub Actions，而最终清单字面写 `.gitlab-ci.yml`；当前仓库按用户要求使用 GitHub Actions `unit-test`，需确认课程最终口径。
5. `REFLECTION.md` 必须由学生本人撰写，本轮不创建。
