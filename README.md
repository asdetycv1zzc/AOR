# Agent Organization Runtime (AOR)

## 项目简介

AOR 是一个面向软件开发的多 Agent Harness。它用确定性状态机组织 Goal、Plan、Execution、Audit 和 Knowledge 五类职责，自行实现“组装上下文 -> 调用 LLM -> 解析动作 -> 分发工具 -> 回灌结果 -> 停机判断”循环，并把模型输出视为不受信任数据。

课程默认交付是 Linux 单机、单人部署的 `TEST` 链路：目标协商、模块规划、仓库执行、确定性模块验证、盲审和 WebUI。Production Integration、Global Audit、HA 与完整发布认证不属于默认链路。

## 极简启动

准备 Docker Engine、Docker Compose v2、GNU Make 和 OpenSSL，然后执行：

```bash
git clone https://github.com/asdetycv1zzc/AOR.git
cd AOR
make compose-up
```

命令会生成本地基础设施 Secret、拉取固定版本依赖、执行迁移、构建 AOR 镜像并等待全部服务健康。完成后打开：

```text
http://127.0.0.1:8090/ui/
```

不需要在本机编译 AOR 时，可将最后一条命令替换为 `make compose-prebuilt-up`，直接拉取公开 Docker Hub 镜像。

更短的中文说明见 [`deploy/compose/QUICKSTART.zh-CN.md`](deploy/compose/QUICKSTART.zh-CN.md)，完整 Compose 说明见 [`deploy/compose/README.md`](deploy/compose/README.md)。

## 安装

### 容器运行前提

- Linux amd64；Linux arm64 由 CI 交叉构建检查覆盖，但应在目标主机另做运行验证
- Docker Engine 与支持 `--wait` / `--wait-timeout` 的 Compose v2 plugin
- GNU Make
- OpenSSL
- 首次拉取依赖和调用真实模型供应商时需要网络
- 建议至少 16 GiB RAM 和 20 GiB 可用磁盘；实际占用取决于镜像、项目仓库和 Artifact

### 本地源码验证前提

- Go `1.26.5`，并设置可写的 Go cache
- Node.js `22.19.0`
- pnpm `11.20.0`
- Python 3
- GNU Make

精确版本由 `go.mod`、根 `package.json`、lockfile 和固定摘要容器镜像定义。

## 运行

查看状态：

```bash
make compose-ps
```

就绪检查：

```bash
curl -fsS http://127.0.0.1:8090/health/ready
curl -fsS http://127.0.0.1:8091/health/ready
curl -fsS http://127.0.0.1:8092/health/ready
curl -fsS http://127.0.0.1:8093/health/ready
curl -fsS http://127.0.0.1:8094/health/ready
```

停止并保留命名卷数据：

```bash
docker compose --parallel 1 -f deploy/compose/docker-compose.yml --profile aor down
```

只把 WebUI/API 暴露到局域网时使用 `deploy/compose/docker-compose.lan.yml` 覆盖文件；不要直接暴露 PostgreSQL、NATS、MinIO、OPA、Temporal 或内部 AOR 端口。

## 模型与 Key 安全配置

1. 启动后进入 WebUI 的 **模型设置**。
2. 为 OpenAI、DeepSeek、Claude、Grok 或自定义供应商填写 Base URL、协议和 API Key。
3. 使用每个供应商的 **测试连接**，再保存设置。
4. 更新配置时，API Key 留空会保留现有 Key；点击清除并保存会发送 `clearApiKey=true`，原子清除凭据并禁用供应商。

供应商 URL 和 Key 不存在于 Compose，也不应提交到 Git。WebUI/API 读取设置只返回 `apiKeyConfigured`，不回显明文；保存后的 Key 由 Model Gateway 加密写入 PostgreSQL。基础设施 Secret 由 `make compose-init-secrets` 生成在被忽略的 `deploy/compose/secrets/`，权限和长度由启动门禁检查。

不要在 `.env`、Goal、Prompt、项目仓库、日志或截图中保存真实凭据。需要轮换时先保存新 Key并测试；需要撤销时使用清除操作并在供应商控制台吊销旧 Key。

## 分发命令

本项目选择容器作为主要分发形态。公开镜像均为 Linux amd64，`0.1.0-test` 对应提交 `223f771`；`latest` 当前指向同一构建，但部署时建议固定版本标签。

| 组件 | Docker Hub 镜像 |
|---|---|
| Server / API / Curator | [`akimisaka/aor-server:0.1.0-test`](https://hub.docker.com/r/akimisaka/aor-server) |
| Model Gateway | [`akimisaka/aor-model-gateway:0.1.0-test`](https://hub.docker.com/r/akimisaka/aor-model-gateway) |
| Tool Broker | [`akimisaka/aor-tool-broker:0.1.0-test`](https://hub.docker.com/r/akimisaka/aor-tool-broker) |
| Worker | [`akimisaka/aor-worker:0.1.0-test`](https://hub.docker.com/r/akimisaka/aor-worker) |
| Toolchain Provisioner | [`akimisaka/aor-toolchain-provisioner:0.1.0-test`](https://hub.docker.com/r/akimisaka/aor-toolchain-provisioner) |
| Toolchain Prober | [`akimisaka/aor-toolchain-prober:0.1.0-test`](https://hub.docker.com/r/akimisaka/aor-toolchain-prober) |

克隆仓库后直接使用预构建镜像启动默认 TEST 链路：

```bash
make compose-prebuilt-up
```

`make compose-up` 仍会从当前源码构建全部运行镜像；单个服务也可直接构建：

```bash
docker build -f deploy/compose/Dockerfile --target final --build-arg AOR_COMPONENT=aor-server -t aor/aor-server:local .
docker build -f deploy/compose/Dockerfile --target worker-runtime --build-arg AOR_COMPONENT=aor-worker -t aor/aor-worker:local .
docker build -f deploy/compose/Dockerfile --target tool-broker-runtime --build-arg AOR_COMPONENT=aor-tool-broker -t aor/aor-tool-broker:local .
```

GitHub CI 在宿主 runner 上直接执行 Go 测试、源码检查、PostgreSQL reconciliation 和 Web build；只有运行制品构建与漏洞扫描使用 Docker，不会把整个 CI 过程塞进一个镜像。

## 测试与机制证据

一键运行核心测试：

```bash
make test
```

运行完整源码门禁：

```bash
make verify
```

Harness 分项机制可离线复现：

```bash
go test ./internal/agentruntime -run TestMockLLMUnifiedMechanismDemo -count=1 -v
go test ./internal/agentruntime -run 'TestRunToolLoop|TestCompactMessages|TestRuntimeCompacts'
go test ./internal/commandapproval -run TestLayerGuardrailsEscalateBeforeReviewer
go test ./internal/execution -run TestExecutorRetryReceivesStructuredPriorAuditFeedback
```

- `mechanism_demo_test.go` 是课程 A.6 的统一演示：同一个确定性 mock LLM 先提出 `rm -rf /` 并被零执行拦截，再接收注入的测试失败后改为文件修复，期间验证 Manifest 绑定压缩保留最新不受信任输入但不提升伪造引用；测试连续运行两次并比较完整证据。
- `tool_loop_test.go` 使用 scripted gateway，证明工具结果进入下一次模型请求并改变终态动作。
- `approval_test.go` 证明提权、递归删除、push、网络、解释器 eval、数据库破坏、路径逃逸和凭据参数在执行前被确定性拦截。
- `rework_feedback_test.go` 证明前一次失败 Evidence 被绑定并注入下一 attempt。
- `compaction_test.go` 证明长上下文压缩保留权威规范和最新用户输入，同时拒绝伪造、跨 Manifest 和递归 checkpoint。

## 目录结构

```text
api/                    OpenAPI、AsyncAPI、A2A 和错误合同
cmd/                    Server、Worker、CLI、Conformance 等入口
internal/agentruntime/  自实现 Agent 循环、Prompt、Context 与压缩
internal/commandapproval/  危险命令确定性护栏和审核层
internal/modelgateway/  模型请求、预算、流式、重放与审计
internal/toolbroker/    MCP/工具声明、授权、调用和结果边界
internal/goalplan/      Goal 协商、Plan 和 Module 规划
internal/execution/     Executor 准备、反馈和任务生命周期
internal/audit/         确定性验证、盲审和 Evidence
internal/knowledge/     项目知识、revision、继承和 Curator
internal/repository/    Git 工作区、路径所有权和 Submission
web/control/            React/TypeScript 控制台
deploy/compose/         默认 TEST 部署、Dockerfile 和运行说明
migrations/postgres/    版本化数据库迁移与摘要清单
work-packages/          WP-00..15 的设计、接口和测试计划
conformance/            需求追踪、跨语言合同和发布证据
adr/                    架构决策记录
runbooks/               运维、恢复、密钥和事故流程
```

## 安全边界说明

- LLM、用户文本、仓库内容、网页内容和工具输出都不受信任；只有经过 Schema、语义和权限校验的命令才能改变状态。
- Agent 不持有供应商 Key、数据库管理员凭据或知识写权限。Model Gateway 和 Tool Broker 是强制执行点。
- Goal/Plan/Module/Knowledge 上下文使用 Manifest、revision 和 SHA-256 绑定；压缩不会把模型伪造引用提升为系统事实。
- Executor 只写其 ModuleSpec 拥有的路径，Submission 是不可变 Git commit；Auditor 不接收 Executor 的自然语言自述。
- 默认 Compose Worker 没有 Docker socket。`TEST` 链路在 Worker 容器和共享项目目录内运行，适合单人可信测试，但不构成对敌对代码或多租户工作负载的强安全隔离。
- Compose 使用 host network 以简化单机依赖接线，但默认只绑定 loopback。局域网覆盖仅应开放 8090。
- Prompt 和模型命令审核是纵深措施，不是权限边界；确定性 guardrail、Lease、OPA、路径校验和提交时重验才是代码边界。

完整威胁模型见 [`SPEC.md`](SPEC.md) §23，各工作包威胁模型见 `work-packages/*/THREAT_MODEL.md`。

## 已知限制

- 截至 `8cfbe44`，需求追踪为 85 项 `implemented`、41 项 `planned`；仓库不得标记为 Production Ready。
- 默认 TEST profile 关闭 Integration 和 Global Audit，不用于敌对多租户或生产数据。
- 目前没有托管 SaaS 或截止期公网 WebUI URL；README 中的地址是本机或显式局域网地址。
- Windows 原生 Worker 设计报告 `isolationLevel=NONE`，不能运行不受信任生产代码；默认一键部署只面向 Linux。
- OpenAI 内置能力区分 258K MaxInput 与 400K ContextWindow；本地 256 MiB Context Manifest 上限不会扩大模型 token 窗口。
- 课程实现前冷启动、worktree/PR 和逐 task 红-绿-重构没有可补造的历史证据；详见 [`SPEC_PROCESS.md`](SPEC_PROCESS.md)。
- 两份课程文档对 CI 平台表述冲突：§4.8 要 GitHub Actions，最终清单字面要求 `.gitlab-ci.yml`。仓库当前按用户要求提供 GitHub `unit-test` job，提交前应向课程方确认是否还需 GitLab 文件。

## CI/CD

GitHub workflow 位于 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)，在每次 push 和 pull request 运行：

- `unit-test`：`make verify`
- WebUI TypeScript build
- PostgreSQL migration 与 reconciliation
- Linux/Windows 跨平台构建和发布合同检查
- Go 依赖漏洞检查
- 四个运行镜像的构建与 High/Critical 漏洞门禁

最后一次远端 CI 必须在课程截止前为 pass；本地测试结果不能替代 GitHub 执行记录。

## 课程与项目文档

- [`SPEC.md`](SPEC.md)：产品、架构、四类机制、main contribution 和验收
- [`PLAN.md`](PLAN.md)：历史工作包、依赖、课程任务与剩余工作
- [`SPEC_PROCESS.md`](SPEC_PROCESS.md)：三轮 brainstorming、开发过程和方法偏差
- [`AGENT_LOG.md`](AGENT_LOG.md)：模型、prompt/context、review、人工干预和 commit 时间线
- [`ChatGPT-Agent组织器设计可行性.json`](ChatGPT-Agent组织器设计可行性.json)：原始 brainstorming 记录
- [`AI4SE_Final_Project_A_Coding_Agent_Harness.md`](AI4SE_Final_Project_A_Coding_Agent_Harness.md)：课程 A 题要求
- [`AI4SE_Final_Project_通用要求.md`](AI4SE_Final_Project_通用要求.md)：课程通用要求

按用户要求，本仓库当前不创建 `REFLECTION.md`。该 1500 至 2500 字报告必须由学生本人完成，不能由 AI 代写。

第三方依赖及精确版本由 `go.mod`、`go.sum`、`package.json`、`pnpm-lock.yaml` 和固定摘要镜像声明；许可证与来源检查由 `make verify` 的 supply-chain/license gate 执行。
