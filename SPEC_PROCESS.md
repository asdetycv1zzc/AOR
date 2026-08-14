# AOR 规约与计划形成过程

> 本文件记录真实过程，不将课程建议流程事后改写为已执行事实。
>
> brainstorming 原始记录：`ChatGPT-Agent组织器设计可行性.json`
>
> 主开发会话：`019fc579-4a9f-7471-91f5-1f763a975069`
>
> 实现证据：Git 提交树；截至课程文档整理前为 589 个提交，HEAD `8cfbe44`

## 1. 证据来源与可复核性

1. `ChatGPT-Agent组织器设计可行性.json`：2026-08-02 创建、2026-08-14 导出，共 6 条 Prompt/Response，保存最初构想、第一轮可行性审查、用户逐项取舍和完整 SPEC 生成请求。
2. Codex 主会话 `019fc579-4a9f-7471-91f5-1f763a975069`：2026-08-03 以“严格遵守 AGENTS.md，完成 SPEC.md 中的项目”启动。会话包含实现、部署、用户测试、review 和修复记录。
3. Git 历史：`0817bad` 至 `8cfbe44` 共 589 个提交；97 个提交含 `[WP-*]`，80 个提交含 `[AOR-*]`。提交树是代码过程的首要证据。
4. `work-packages/wp-00` 至 `wp-15`：保存每个模块的规格、设计、接口、威胁模型、测试计划、迁移和交接记录。

会话日志不提交到仓库，因为它包含运行器元数据和大量工具输出；本文件只记录可由源文件、提交和测试交叉验证的节点。

## 2. 工具与方法声明

开发全程使用 `gpt-5.6-sol`，推理强度由用户指定为 `max`。没有使用 Superpowers，也没有触发 `brainstorming`、`writing-plans`、`using-git-worktrees`、`test-driven-development`、`requesting-code-review` 或 `finishing-a-development-branch` skill。

这是明确的方法偏差，不声称“模型表现类似 Superpowers”就等同于使用了课程指定技能。选择原因是：后续模型训练已经学习了先前 Superpowers 的大部分方法内容，在本项目规模下再叠加该 skill 的固定流程会重复规划、增加上下文和降低推进效率。这个取舍提高了短期实现速度，但也直接造成三个过程证据缺口：没有实现前的课程格式 PLAN、没有 worktree/PR 轨迹、没有可审计的逐 task 红-绿-重构序列。

项目确实使用了并行 subagent 和独立 review agent，但它们是 Codex 原生协作能力，不是 Superpowers。课程要求的“陌生且类型不同的 Agent 冷启动”也没有在实现前执行。

## 3. Brainstorming 三轮关键迭代

### 3.1 第一轮：从五层构想到确定性控制平面

用户提出了目标、计划、执行、审计、智库五层模型，并强调：执行者不能自证完成、审计者使用干净上下文、智库以磁盘引用节省 token、跨供应商 Agent 需要通信协议。

AI 提出的关键问题包括：

- 随机选择两个目标 Agent 是否有价值；
- 无限协商、无限返工和按模块创建 Agent 是否会失控；
- 行号引用在内容变化后如何保持稳定；
- Prompt 禁止工具调用能否形成安全边界；
- LLM 审计能否替代编译、测试和静态检查；
- 是否应该从零发明通信协议。

首轮建议把五层定义为逻辑职责，并把状态迁移、Agent 生命周期、并发、预算、Git、权限和完成判定交给非 LLM 的确定性 Orchestrator。用户保留五层产品模型，采纳确定性控制平面、稳定角色、只读知识服务、自动化验证和 A2A/MCP 分工。

### 3.2 第二轮：用户逐项接受、否决和修正

用户没有全盘接受 AI 建议，而是给出明确决策：

| 议题 | AI 建议 | 用户决定 | 最终规约 |
|---|---|---|---|
| 目标 Agent 随机接收输入 | 固定 Proposer / Challenger | 接受 | 两个角色职责固定，记录独立 |
| 目标协商轮次 | 设置最大轮次 | 否决 | 没有轮次上限；未达成一致就不开发，只有用户批准能推进 |
| Plan Supervisor 拆分后休眠 | 持续维护 DAG | 接受 | Supervisor 可低资源等待，但不退出 |
| 每模块创建 Agent | 加全局并发 | 接受并指定上限 8 | 模块可排队，活跃 Agent 总数不超过 8 |
| API Key 作为 token 限额 | 增加内部硬预算 | 部分修正 | Key 用于供应商/配额隔离，Model Gateway 负责预留和结算 |
| 每次提交新 Auditor | 先跑确定性检查再创建 | 接受 | 每个通过基础门禁的 Submission 使用新 Auditor |
| 审计无限返工 | 限制次数并升级 | 接受，指定 3 次后直接交用户 | 决策交用户；Planner 仅同步阻塞状态，不作决定 |
| 智库固定 Agent | 服务与 Curator 分离 | 接受 | 读取由 Knowledge Service 完成，唯一 Curator 经审批写入 |
| 只返回路径和行号 | 增加 URI/version/hash | 部分接受 | 保留本地路径/行号，同时绑定 revision 和 SHA-256 |
| Prompt 禁止工具 | 代码权限边界 | 接受但指出跨平台困难 | Linux 和 Windows 明确不同能力，无法隔离时 fail closed |

这一轮最重要的用户修正是“无限目标协商”和“三次失败直接交用户”。AI 原本偏向通用工程默认值，用户用产品意图覆盖了这些默认建议。SPEC 随后把两者写成 `AOR-INV-003`、`AOR-INV-007` 和 `AOR-INV-008`。

### 3.3 第三轮：从收敛架构生成实施规格

用户要求产出“可供其他智能体从 0 开始开发”的完整 `SPEC.md`。AI 将已确认决策扩展为 49 章生产基线，加入：

- AOP/A2A/MCP/CloudEvents 协议边界；
- 状态机、幂等、Lease、事务 Outbox 和预算账本；
- Repository、Artifact、Knowledge、Audit 和 Policy 服务；
- Linux/Windows 能力差异、凭据威胁模型、SLO 和灾难恢复；
- 15 个初始工作包、100 项生产验收和 Definition of Done。

原始生成物偏向生产平台，而课程题目强调“机制深度优先、避免大而全”。这个范围错配直到真实实现和用户测试阶段才充分暴露。课程版 SPEC 因此新增 §1.5，把默认单人 TEST 链路与 Production 扩展严格分开，并把上下文/记忆机制选为 main contribution。

## 4. 从 SPEC 到实现的实际过程

### 4.1 初始工作包

2026-08-03，主会话先建立 `WP-00` 至 `WP-15` 的接口和依赖，再提交状态、身份、模型、工具、运行时、Goal/Plan、Repository、Audit、Knowledge、Integration、Deployment 和 Conformance。早期代表提交：

| 范围 | 提交 |
|---|---|
| Bootstrap 与协议 | `cb80311`、`89d0a77` |
| 状态与身份 | `d8e4997`、`e948a27` |
| Model / Tool / Sandbox | `4c9fa9c`、`53e6948`、`8f345ff` |
| Agent Runtime 与 Goal/Plan | `f0d54b7`、`5bfd815` |
| Repository / Audit / Knowledge | `97f7d2b`、`e883094`、`85226f4` |
| Integration / Observability / Deploy / Conformance | `d19df46`、`0c1bef7`、`f73169f`、`363d0bd` |

这些提交体现细分和小步演进，但不是每个 task 一个 worktree/PR。仓库只有 `master`、一个 worktree 和零 merge commit。

### 4.2 Review 如何改变实现

主会话中 review 不是只在末尾执行。可复核的例子包括：

1. 2026-08-03 `wp02_review` 发现跨租户投影、跨项目任务授权和 PostgreSQL 租户约束缺陷；修复进入 WP-02。
2. `wp06_review` 指出“期望的容器配置”不能冒充运行时证明，并发现只有测试替身、没有部署后端；实现改为核对实际 attestation。
3. WP-07 审核发现启动授权失败会卡在 `STARTING`、结果提交窗口缺少再次 Lease 校验且缺 fence；对应修复进入 `f0d54b7` 前的工作树。
4. 集成审查发现相同 merge 请求并发时可能执行两次；提交边界被串行化并增加并发回归测试。
5. 需求审查发现一批 `implemented` 只覆盖局部原语；状态被降回 `planned`，避免用文档宣称替代端到端证据。
6. 2026-08-04 用户追问“是否全部完成”，触发对 100 项验收、数据库迁移和生产接线的重新核对，并暴露“代码存在但部署后不会运行”的问题。

后期 review 继续来自真实 WebUI/Compose 测试：重复聊天消息、SSE 首字符延迟、供应商超时、工具链恢复、长 Goal 对话超窗、模型窗口配置和 API Key 生命周期。这些问题以大量小 commit 修复，而不是压成一次“最终实现”。

### 4.3 人工干预改变方向的节点

- 用户拒绝目标协商轮次上限，形成“未批准就不开发”的核心产品语义。
- 用户将第三次失败的决策权固定给自己，否决 Planner 自动接管。
- 用户在 2026-08-07 指出项目过度复杂且核心流程未完成，要求停止用大量测试替代主链实现；此后重点转为 TEST 核心链和真实部署验证。
- 用户要求模型供应商、Base URL、API Key 和测试按钮全部进入 WebUI，禁止把真实配置写进 Compose/Git。
- 用户明确 GCC 使用用户提供的可重定位 crosstool-ng 归档，否决系统自行构建 GCC。
- 用户提出长 GoalSpec 超窗场景，促成 `a816cd0` 的 Manifest-bound context compaction。
- 用户将 OpenAI 能力固定为 258K MaxInput / 400K ContextWindow，并将 Compose TEST 作为默认单人链路。

## 5. 冷启动验证

课程要求在实现前使用不同类型、全新会话的陌生 Agent，仅凭 `SPEC.md + PLAN.md` 实现 1 至 2 个任务。本项目没有执行该步骤：

- 最初没有课程格式的 `PLAN.md`；
- 实现从同一 Codex 主会话和其原生 subagent 展开；
- 现有 subagent 继承了主任务上下文或工作包边界，不能冒充陌生 Agent；
- 当前再运行只能成为“实现后文档可读性审查”，不能补回实现前证据；本轮又被用户明确要求不得启动 subagent。

因此该项在 `PLAN.md` 标为 `DEVIATION`。后续完成的 `COURSE-DEMO-01` 是实现后的组合机制测试，并已按发生时间记录在 `AGENT_LOG.md`；它提高了验收证据强度，但不能补回“实现前陌生 Agent 冷启动”的历史要求。

## 6. TDD、worktree 与 PR 证据边界

代码库有大量单元、竞态、Schema、跨语言和部署测试，`work-packages/*/TEST_PLAN.md` 也记录期望失败场景；会话中多次出现“先补失败测试再修复”的记录。但 Git 提交常把测试和实现放在同一原子 commit，无法从提交树稳定证明每个 task 都经历了可观察的红、绿、重构三个阶段。

同样，97 个 `[WP-*]` 和 80 个 `[AOR-*]` 提交能证明需求拆分，却不能证明 worktree/PR 流程。`git log --merges` 为空，当前只有 `master` 和一个 worktree；最近一批提交也没有持续标注 subagent 名称。以上均作为偏差保留，不重写历史。

## 7. Brainstorming 做得好与不足

做得好的部分：

- 迅速识别“五层对话”不能承担状态与安全控制，促成自实现 deterministic harness；
- 追问随机角色、无限循环、预算、引用稳定性、审计偏差和跨平台能力，帮助把概念变为可编码不变量；
- 用户可以逐条接受、否决或部分接受，最终设计不是 AI 单方面决定；
- 早期建立版本、hash、Evidence 和 fail-closed 语言，为后续 review 提供了明确判据。

不足：

- 过早把“生产级”展开成完整平台，远超课程需要，导致实现范围、测试量和基础设施复杂度膨胀；
- 没有先询问课程交付的时间、主要贡献维度和最低可演示链路；
- 生成的 49 章 SPEC 缺少显式 INVEST 用户故事、课程“领域与机制设计”和实际前端设计声明；
- 没有同步生成课程格式 PLAN、过程日志和冷启动验证任务；
- 对“能否生产化”的安全建议有价值，但多次压过用户要求的单人 TEST 使用场景。

## 8. 本次课程文档修订

2026-08-14 的文档整理只做事实补全，不改写实现历史：

- `SPEC.md` 新增 8 个用户故事、课程范围、前端设计声明、四类机制、main contribution、压缩规范和完整 Key 生命周期；
- 新建 `PLAN.md`，将历史工作包、后期演进、课程文档任务和未完成要求分开；
- 新建 `AGENT_LOG.md`，按时间记录模型、prompt/context、review、人工干预和提交；
- 扩展根 `README.md`，加入安装、运行、分发、目录、安全、机制证据和限制；
- 原始 brainstorming 和两份课程要求纳入 Git；
- 按用户要求不创建 `REFLECTION.md`，该报告必须由学生本人完成。
