import {
  ArrowLeft,
  ChatCircleText,
  CheckCircle,
  Clock,
  FileArchive,
  GearSix,
  PaperPlaneTilt,
  Pulse,
  Robot,
  Tray,
  UploadSimple,
  UserCircle,
  WarningCircle,
} from "@phosphor-icons/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { AorClient, ApiError } from "./api";
import type {
  ModelRole,
  GoalSpec,
  GoalToolchainTool,
  Project,
  ProjectActivityAgent,
  ProjectActivityFlow,
  ProjectActivityMessage,
  ProjectActivitySnapshot,
  ToolchainArchiveUpload,
} from "./types";
import { Button, Spinner, Textarea } from "./ui";
import "./project-workbench.css";

const roleLabels: Record<string, string> = {
  GOAL_PROPOSER: "目标提案",
  GOAL_CHALLENGER: "目标审议",
  PLAN_SUPERVISOR: "计划总控",
  MODULE_PLANNER: "模块规划",
  EXECUTOR: "代码执行",
  MODULE_AUDITOR: "模块审计",
  GLOBAL_AUDITOR: "全局审计",
  KNOWLEDGE_CURATOR: "知识管理",
};

const layerLabels: Record<string, string> = {
  GOAL_PROPOSER: "目标层",
  GOAL_CHALLENGER: "目标层",
  PLAN_SUPERVISOR: "计划层",
  MODULE_PLANNER: "计划层",
  EXECUTOR: "执行层",
  MODULE_AUDITOR: "审计层",
  GLOBAL_AUDITOR: "审计层",
  KNOWLEDGE_CURATOR: "智库层",
};

const fallbackFlows: ProjectActivityFlow[] = ["GOAL", "PLAN", "EXECUTION", "AUDIT", "KNOWLEDGE"];

const flowLabels: Record<ProjectActivityFlow, string> = {
  GOAL: "目标层",
  PLAN: "计划层",
  EXECUTION: "执行层",
  AUDIT: "审计层",
  KNOWLEDGE: "智库层",
};

const crosstoolToolNames = new Set([
  "gcc", "g++", "gnu gcc", "gnu g++", "gnu c++",
  "gcc compiler", "g++ compiler", "gnu gcc compiler", "gnu g++ compiler", "gnu c++ compiler",
  "gnu c compiler", "gnu compiler collection", "gnu compiler collection gcc", "gnu compiler collection g++",
  "gnu compiler collection c compiler", "gnu compiler collection c++ compiler",
  "gnu compiler collection c compiler gcc", "gnu compiler collection c++ compiler g++",
]);
const maximumToolchainArchiveSize = 4 * 1024 * 1024 * 1024;
const supportedToolchainArchiveExtensions = [".tar", ".tar.xz", ".tar.gz", ".zip", ".7z"];
const toolchainArchiveAccept = [
  ...supportedToolchainArchiveExtensions,
  "application/x-tar",
  "application/x-xz",
  "application/gzip",
  "application/x-gzip",
  "application/zip",
  "application/x-7z-compressed",
].join(",");

function isSupportedToolchainArchive(fileName: string): boolean {
  const lower = fileName.toLowerCase();
  return supportedToolchainArchiveExtensions.some((extension) => lower.endsWith(extension));
}

function normalizeCrosstoolToolName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[()[\]{}\\/\-_:,]/g, " ")
    .split(/\s+/)
    .filter(Boolean)
    .join(" ");
}

function latestGoalSpec(items: GoalSpec[]): GoalSpec | undefined {
  return items.reduce<GoalSpec | undefined>((latest, item) => (
    !latest || item.content.version > latest.content.version ? item : latest
  ), undefined);
}

function pendingCrosstoolTool(goal: GoalSpec | undefined): GoalToolchainTool | undefined {
  return goal?.content.toolchain?.tools.find((tool) => (
    tool.source === "INSTALL_REQUIRED"
    && crosstoolToolNames.has(normalizeCrosstoolToolName(tool.name))
    && (!tool.install || tool.install.authorized !== true)
  ));
}

function toolIdentity(tool: Pick<GoalToolchainTool, "name" | "version" | "architecture">): string {
  return `${tool.name}\u0000${tool.version}\u0000${tool.architecture}`;
}

function archiveAuthorizationMessage(upload: ToolchainArchiveUpload): string {
  return [
    "我明确授权安装以下由我上传的预构建、路径无关的 crosstool-ng C/C++ 工具链归档。",
    "请在下一版 GoalSpec 中保持工具名称、版本和架构完全一致，将该工具设置为 source=INSTALL_REQUIRED、install.method=CROSSTOOL_NG_ARCHIVE、install.authorized=true，并原样绑定以下不可变产物；install.evidenceRef 必须引用本条用户消息。",
    JSON.stringify({
      toolName: upload.toolName,
      toolVersion: upload.toolVersion,
      architecture: upload.architecture,
      artifactId: upload.id,
      artifactRef: upload.artifactRef,
      sourceSha256: upload.sourceSha256,
    }, null, 2),
  ].join("\n\n");
}

function formatArchiveSize(bytes: number): string {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${Math.max(1, Math.ceil(bytes / 1024))} KiB`;
}

function defaultFlow(project: Project): ProjectActivityFlow {
  if (["CREATED", "GOAL_NEGOTIATING", "GOAL_SUSPENDED"].includes(project.state)) return "GOAL";
  if (project.state === "PLANNING") return "PLAN";
  if (project.state === "EXECUTING") return "EXECUTION";
  if (project.state === "INTEGRATING" || project.state === "GLOBAL_AUDIT") return "AUDIT";
  return "GOAL";
}

function activeRoles(project: Project): Set<string> {
  switch (project.state) {
  case "CREATED":
  case "GOAL_NEGOTIATING":
  case "GOAL_SUSPENDED":
    return new Set(["GOAL_PROPOSER", "GOAL_CHALLENGER"]);
  case "PLANNING":
    return new Set(["PLAN_SUPERVISOR", "MODULE_PLANNER"]);
  case "EXECUTING":
    return new Set(["EXECUTOR", "MODULE_AUDITOR", "KNOWLEDGE_CURATOR"]);
  case "INTEGRATING":
  case "GLOBAL_AUDIT":
    return new Set(["PLAN_SUPERVISOR", "GLOBAL_AUDITOR"]);
  default:
    return new Set();
  }
}

function fallbackAgents(project: Project): ProjectActivityAgent[] {
  if (!project.modelRoutes) return [];
  const active = activeRoles(project);
  const completed = project.state === "COMPLETED";
  return Object.keys(project.modelRoutes).map((role) => ({
    id: role.toLowerCase().replaceAll("_", "-"),
    role,
    state: completed ? "COMPLETED" : active.has(role) ? "RUNNING" : "IDLE",
    flow: role === "GOAL_PROPOSER" || role === "GOAL_CHALLENGER"
      ? "GOAL"
      : role === "PLAN_SUPERVISOR" || role === "MODULE_PLANNER"
        ? "PLAN"
        : role === "EXECUTOR"
          ? "EXECUTION"
          : role === "KNOWLEDGE_CURATOR" ? "KNOWLEDGE" : "AUDIT",
    lastActiveAt: "",
  }));
}

function formatActivityTime(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(date);
}

function activityError(cause: unknown): string {
  if (cause instanceof ApiError) return cause.code ? `${cause.message} · ${cause.code}` : cause.message;
  return cause instanceof Error ? cause.message : "请求失败";
}

function stateTone(state: string): string {
  const normalized = state.toLowerCase();
  if (normalized.includes("fail") || normalized.includes("block") || normalized.includes("expire")) return "danger";
  if (normalized.includes("complete") || normalized.includes("answer") || normalized.includes("pass")) return "success";
  if (normalized.includes("active") || normalized.includes("running") || normalized.includes("stream")) return "active";
  return "neutral";
}

function WorkbenchState({ state }: { state: string }) {
  return <span className={`workbench-state is-${stateTone(state)}`}>{state}</span>;
}

function messageSender(message: ProjectActivityMessage): string {
  if (message.sender === "USER") return "你";
  if (message.role) return roleLabels[message.role] || message.role;
  if (message.provider || message.model) return [message.provider, message.model].filter(Boolean).join(" / ");
  return message.sender === "SYSTEM" ? "系统" : "Agent";
}

function messageAvatar(sender: ProjectActivityMessage["sender"]) {
  if (sender === "USER") return <UserCircle weight="duotone" aria-hidden="true" />;
  if (sender === "SYSTEM") return <GearSix weight="duotone" aria-hidden="true" />;
  return <Robot weight="duotone" aria-hidden="true" />;
}

function messageContent(message: ProjectActivityMessage) {
  const content = message.content || (message.state === "FAILED" ? "处理失败，详情见错误码。" : "");
  const hasTrace = Boolean(message.inputPrompt || message.reasoningContent || message.reasoningSummary);
  const output = <p>{content}{message.state === "STREAMING" && <span className="typing-indicator" aria-label={content ? undefined : "Agent 正在响应"} aria-hidden={content ? "true" : undefined}><i /><i /><i /></span>}</p>;
  return <>
    {message.inputPrompt && <section className="message-trace is-input"><strong>输入提示词</strong><pre>{message.inputPrompt}</pre></section>}
    {message.reasoningContent && <section className="message-trace is-reasoning"><strong>思考链</strong><pre>{message.reasoningContent}</pre></section>}
    {message.reasoningSummary && <section className="message-trace is-summary"><strong>思考摘要</strong><pre>{message.reasoningSummary}</pre></section>}
    {hasTrace ? <section className="message-output"><strong>输出文本</strong>{output}</section> : output}
  </>;
}

function flowState(flow: ProjectActivityFlow, agents: ProjectActivityAgent[], messages: ProjectActivityMessage[]): string {
  if (agents.some((agent) => agent.flow === flow && (agent.state === "RUNNING" || agent.state === "STREAMING"))) return "STREAMING";
  const related = messages.filter((message) => message.flow === flow);
  const latest = related.at(-1);
  if (latest?.state === "STREAMING") return "STREAMING";
  if (latest?.state === "FAILED") return "FAILED";
  if (latest?.state === "COMPLETED") return "COMPLETED";
  return "QUEUED";
}

function messageBelongsToConversation(message: ProjectActivityMessage, flow: ProjectActivityFlow, agentID: string): boolean {
  if (message.flow !== flow) return false;
  return !agentID || message.agentId === agentID;
}

function activityStateRank(state: ProjectActivityMessage["state"]): number {
  if (state === "COMPLETED" || state === "FAILED") return 2;
  if (state === "STREAMING" || state === "RUNNING") return 1;
  return 0;
}

function newerActivityMessage(current: ProjectActivityMessage | undefined, candidate: ProjectActivityMessage): ProjectActivityMessage {
  if (!current) return candidate;
  const currentTime = new Date(current.updatedAt || current.createdAt).getTime();
  const candidateTime = new Date(candidate.updatedAt || candidate.createdAt).getTime();
  if (candidateTime > currentTime || candidateTime === currentTime && activityStateRank(candidate.state) >= activityStateRank(current.state)) {
    return candidate;
  }
  return current;
}

function mergeActivitySnapshot(current: ProjectActivitySnapshot | undefined, candidate: ProjectActivitySnapshot): ProjectActivitySnapshot {
  if (!current) return candidate;
  const currentMessages = new Map(current.messages.map((message) => [message.id, message]));
  return {
    ...candidate,
    messages: candidate.messages
      .map((message) => newerActivityMessage(currentMessages.get(message.id), message))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id)),
  };
}

export function ProjectWorkbench({ project, client, onBack, onReload, onNotice }: {
  project: Project;
  client: AorClient;
  onBack: () => void;
  onReload: () => void;
  onNotice: (message: string) => void;
}) {
  const [activity, setActivity] = useState<ProjectActivitySnapshot>();
  const [activityAvailable, setActivityAvailable] = useState<boolean>();
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [activeFlow, setActiveFlow] = useState<ProjectActivityFlow>(() => defaultFlow(project));
  const [selectedAgent, setSelectedAgent] = useState("");
  const [sending, setSending] = useState(false);
  const [goalSpec, setGoalSpec] = useState<GoalSpec>();
  const [goalSpecLoaded, setGoalSpecLoaded] = useState(false);
  const [archiveFile, setArchiveFile] = useState<File>();
  const [archiveUpload, setArchiveUpload] = useState<ToolchainArchiveUpload>();
  const [archiveBusy, setArchiveBusy] = useState<"" | "upload" | "authorize">("");
  const [archiveError, setArchiveError] = useState("");
  const [authorizationSent, setAuthorizationSent] = useState(false);
  const archiveSubmitting = useRef(false);
  const refreshTimer = useRef<number | undefined>(undefined);
  const knownMessageIDs = useRef(new Set<string>());
  const messagesRef = useRef<HTMLDivElement | null>(null);
  const followLatest = useRef(true);

  const refreshActivity = useCallback(async () => {
    try {
      const next = await client.getProjectActivity(project.id);
      knownMessageIDs.current = new Set(next.messages.map((message) => message.id));
      setActivity((current) => mergeActivitySnapshot(current, next));
      setActivityAvailable(true);
      setError("");
    } catch (cause) {
      if (cause instanceof ApiError && (cause.status === 404 || cause.status === 405)) {
        setActivityAvailable(false);
        return;
      }
      setError(activityError(cause));
    }
  }, [client, project.id]);

  const refreshGoalSpec = useCallback(async () => {
    try {
      const specs = await client.getGoalSpecs(project.id);
      setGoalSpec(latestGoalSpec(specs.items));
      setGoalSpecLoaded(true);
    } catch (cause) {
      setGoalSpecLoaded(true);
      if (!(cause instanceof ApiError && cause.status === 404)) setError(activityError(cause));
    }
  }, [client, project.id]);

  useEffect(() => {
    setActivity(undefined);
    setActivityAvailable(undefined);
    setError("");
    setMessage("");
    setActiveFlow(defaultFlow(project));
    setSelectedAgent("");
    setGoalSpec(undefined);
    setGoalSpecLoaded(false);
    setArchiveFile(undefined);
    setArchiveUpload(undefined);
    setArchiveBusy("");
    setArchiveError("");
    setAuthorizationSent(false);
    archiveSubmitting.current = false;
    knownMessageIDs.current.clear();
    void Promise.allSettled([refreshActivity(), refreshGoalSpec()]);
  }, [project.id, refreshActivity, refreshGoalSpec]);

  useEffect(() => {
    const interval = activityAvailable === false ? 15_000 : 4_000;
    const timer = window.setInterval(() => void Promise.allSettled([refreshActivity(), refreshGoalSpec()]), interval);
    return () => window.clearInterval(timer);
  }, [activityAvailable, refreshActivity, refreshGoalSpec]);

  useEffect(() => {
    if (activityAvailable !== true) return;
    const stop = client.subscribeProjectEvents(project.id, {
      onEvent: (event) => {
        const isNewMessage = !knownMessageIDs.current.has(event.id);
        knownMessageIDs.current.add(event.id);
        setActivity((current) => {
          if (!current) return current;
          const existing = current.messages.findIndex((item) => item.id === event.id);
          const messages = [...current.messages];
          if (existing >= 0) messages[existing] = newerActivityMessage(messages[existing], event); else messages.push(event);
          return { ...current, messages, cursor: event.cursor };
        });
        const shouldRefresh = (isNewMessage && event.id.startsWith("model:")) || event.state === "COMPLETED" || event.state === "FAILED";
        if (!shouldRefresh || refreshTimer.current !== undefined) return;
        refreshTimer.current = window.setTimeout(() => {
          refreshTimer.current = undefined;
          void Promise.allSettled([refreshActivity(), refreshGoalSpec()]);
          onReload();
        }, isNewMessage ? 50 : 250);
      },
      onError: (cause) => {
        if (cause instanceof ApiError && (cause.status === 404 || cause.status === 405)) setActivityAvailable(false);
      },
    });
    return () => {
      stop();
      if (refreshTimer.current !== undefined) window.clearTimeout(refreshTimer.current);
      refreshTimer.current = undefined;
    };
  }, [activityAvailable, client, onReload, project.id, refreshActivity, refreshGoalSpec]);

  const agents = activity?.agents?.length ? activity.agents : fallbackAgents(project);
  const messages = activity?.messages || [];
  const queuedInputs = messages.filter((item) => item.sender === "USER" && (item.state === "QUEUED" || item.state === "STREAMING"));
  const flows = activity?.flows?.length ? activity.flows : fallbackFlows;
  const visibleAgents = agents.filter((agent) => agent.flow === activeFlow);
  const visibleMessages = messages.filter((item) => messageBelongsToConversation(item, activeFlow, selectedAgent));
  const visibleMessageVersion = visibleMessages.map((item) => `${item.id}:${item.updatedAt || item.createdAt}:${item.content.length}:${item.inputPrompt?.length || 0}:${item.reasoningContent?.length || 0}:${item.reasoningSummary?.length || 0}`).join("|");
  const crosstoolTool = pendingCrosstoolTool(goalSpec);
  const goalProcessing = activity?.goalProcessing ?? project.goalProcessing;
  const showArchiveUpload = activeFlow === "GOAL"
    && (project.state === "GOAL_NEGOTIATING" || project.state === "GOAL_SUSPENDED")
    && Boolean(crosstoolTool);

  useEffect(() => {
    if (!goalSpecLoaded || !archiveUpload) return;
    if (!crosstoolTool || toolIdentity(crosstoolTool) !== toolIdentity({
      name: archiveUpload.toolName,
      version: archiveUpload.toolVersion,
      architecture: archiveUpload.architecture,
    })) {
      setArchiveFile(undefined);
      setArchiveUpload(undefined);
      setArchiveError("");
      setAuthorizationSent(false);
    }
  }, [archiveUpload, crosstoolTool, goalSpecLoaded]);

  useEffect(() => {
    const container = messagesRef.current;
    if (!container || !followLatest.current) return;
    container.scrollTop = container.scrollHeight;
  }, [activeFlow, visibleMessageVersion]);

  const sendMessage = async () => {
    const content = message.trim();
    if (!content || sending || archiveSubmitting.current) return;
    setSending(true);
    setError("");
    try {
      const selected = activity?.agents?.find((agent) => agent.id === selectedAgent && agent.flow === activeFlow);
      const targetFlow = selected?.flow || activeFlow;
      const targetAgent = selected?.id || "";
      await client.sendProjectActivityMessage({ id: project.id, version: activity?.projectVersion || project.version }, targetFlow, content, targetAgent);
      setMessage("");
      onNotice("消息已进入项目队列");
      await refreshActivity();
      onReload();
    } catch (cause) {
      setError(activityError(cause));
    } finally {
      setSending(false);
    }
  };

  const authorizeArchive = async (upload: ToolchainArchiveUpload) => {
    if (archiveSubmitting.current || authorizationSent) return;
    archiveSubmitting.current = true;
    setArchiveBusy("authorize");
    setArchiveError("");
    try {
      await client.sendProjectActivityMessage(
        { id: project.id, version: activity?.projectVersion || project.version },
        "GOAL",
        archiveAuthorizationMessage(upload),
      );
      setAuthorizationSent(true);
      onNotice("工具链归档已上传，安装授权正在处理中");
      await Promise.allSettled([refreshActivity(), refreshGoalSpec()]);
      onReload();
    } catch (cause) {
      setArchiveError(`归档已保存，但授权消息发送失败：${activityError(cause)}`);
    } finally {
      archiveSubmitting.current = false;
      setArchiveBusy("");
    }
  };

  const uploadArchive = async () => {
    if (!crosstoolTool || !archiveFile || archiveSubmitting.current || sending || goalProcessing) return;
    if (!isSupportedToolchainArchive(archiveFile.name)) {
      setArchiveError("请选择 .tar、.tar.xz、.tar.gz、.zip 或 .7z 格式的 crosstool-ng 产物");
      return;
    }
    if (archiveFile.size < 1 || archiveFile.size > maximumToolchainArchiveSize) {
      setArchiveError("归档必须非空且不超过 4 GiB");
      return;
    }
    archiveSubmitting.current = true;
    setArchiveBusy("upload");
    setArchiveError("");
    try {
      const upload = await client.uploadToolchainArchive(project.id, {
        file: archiveFile,
        toolName: crosstoolTool.name,
        toolVersion: crosstoolTool.version,
        architecture: crosstoolTool.architecture,
      });
      setArchiveUpload(upload);
      archiveSubmitting.current = false;
      setArchiveBusy("");
      await authorizeArchive(upload);
    } catch (cause) {
      setArchiveError(activityError(cause));
      archiveSubmitting.current = false;
      setArchiveBusy("");
    }
  };

  return (
    <main className="project-workbench">
      <Button
        className="workbench-back"
        appearance="subtle"
        size="small"
        icon={<ArrowLeft />}
        onClick={onBack}
        aria-label="返回阶段详情"
        title="返回阶段详情"
      />

      {error && <div className="workbench-error" role="alert"><WarningCircle weight="fill" /><span>{error}</span><button onClick={() => setError("")} aria-label="关闭">×</button></div>}

      <div className="workbench-grid">
        <aside className="workbench-flow-rail" aria-label="项目流程">
          <header className="workbench-panel-heading"><Pulse /><div><h2>流程</h2><span>{flows.length} 个阶段</span></div></header>
          <nav className="workbench-flow-list">
            {flows.map((flow, index) => {
              const state = flowState(flow, agents, messages);
              return <button key={flow} className={`workbench-flow-item${activeFlow === flow ? " is-selected" : ""}`} onClick={() => { setActiveFlow(flow); setSelectedAgent(""); }}>
                <span className="flow-index">{String(index + 1).padStart(2, "0")}</span>
                <span><strong>{flowLabels[flow]}</strong><small>{state === "STREAMING" ? "实时处理中" : state === "COMPLETED" ? "已完成" : state === "FAILED" ? "发生错误" : "等待中"}</small></span>
                <WorkbenchState state={state} />
              </button>;
            })}
          </nav>
        </aside>

        <aside className="workbench-agent-rail">
          <section className="workbench-agents" aria-labelledby="workbench-agents-title">
            <header className="workbench-panel-heading"><Robot /><div><h2 id="workbench-agents-title">Agent</h2><span>{visibleAgents.length} 个</span></div></header>
            <div className="workbench-agent-list">
              {visibleAgents.length ? visibleAgents.map((agent) => (
                <button className={`workbench-agent${selectedAgent === agent.id ? " is-selected" : ""}`} key={agent.id} aria-pressed={selectedAgent === agent.id} onClick={() => { setSelectedAgent(agent.id); setActiveFlow(agent.flow); }}>
                  <span className={`agent-signal is-${stateTone(agent.state)}`}><Pulse weight="bold" /></span>
                  <span><strong>{roleLabels[agent.role] || agent.role}</strong><small>{layerLabels[agent.role] || flowLabels[agent.flow]}</small></span>
                  <span className="agent-model"><strong>{project.modelRoutes?.[agent.role as ModelRole]?.provider || "-"}</strong><small>{project.modelRoutes?.[agent.role as ModelRole]?.model || formatActivityTime(agent.lastActiveAt)}</small></span>
                  <WorkbenchState state={agent.state} />
                </button>
              )) : <div className="workbench-empty"><Robot /><span>暂无 Agent 活动</span></div>}
            </div>
          </section>

          <section className="workbench-inputs" aria-labelledby="workbench-inputs-title">
            <header className="workbench-panel-heading"><Tray /><div><h2 id="workbench-inputs-title">输入队列</h2><span>{queuedInputs.length} 项</span></div></header>
            <div className="workbench-input-list">
              {queuedInputs.length ? queuedInputs.map((input) => (
                <article className="workbench-input" key={input.id}>
                  <header><strong>{flowLabels[input.flow]}</strong><WorkbenchState state={input.state} /></header>
                  <p>{input.content}</p>
                  <small><Clock />{formatActivityTime(input.updatedAt || input.createdAt)}</small>
                </article>
              )) : <div className="workbench-empty"><Tray /><span>没有待处理输入</span></div>}
            </div>
          </section>
        </aside>

        <section className="workbench-thread" aria-labelledby="workbench-chat-title">
          <header className="workbench-panel-heading"><ChatCircleText /><div><h2 id="workbench-chat-title">{flowLabels[activeFlow]}对话</h2><span>{visibleMessages.length} 条</span></div></header>
          <div
            className="workbench-messages"
            aria-live="polite"
            ref={messagesRef}
            onScroll={(event) => {
              const container = event.currentTarget;
              followLatest.current = container.scrollHeight - container.scrollTop - container.clientHeight < 80;
            }}
          >
            {visibleMessages.length ? visibleMessages.map((item) => (
              <article className={`workbench-message is-${item.sender.toLowerCase()} is-${item.state.toLowerCase()}${item.id.startsWith("model-attempt:") ? " is-model-attempt" : ""}`} key={item.id}>
                <div className="message-avatar">{messageAvatar(item.sender)}</div>
                <div className="message-bubble"><header><strong>{messageSender(item)}</strong><span>{flowLabels[item.flow]}</span><time>{formatActivityTime(item.createdAt)}</time></header>
                <div className="message-content">{messageContent(item)}</div>
                <footer><WorkbenchState state={item.state} />{item.latencyMs !== undefined && <small>{item.latencyMs} ms</small>}{item.errorCode && <small>{item.errorCode}</small>}</footer>
                </div>
              </article>
            )) : <div className="workbench-empty"><ChatCircleText /><span>暂无对话记录</span></div>}
          </div>
          {showArchiveUpload && crosstoolTool && (
            <section className="workbench-toolchain-upload" aria-labelledby="toolchain-upload-title">
              <header>
                <FileArchive weight="duotone" />
                <div><strong id="toolchain-upload-title">上传 C/C++ 工具链</strong><span>支持 tar、tar.xz、tar.gz、zip、7z，最大 4 GiB</span></div>
              </header>
              <dl>
                <div><dt>工具</dt><dd>{crosstoolTool.name} {crosstoolTool.version}</dd></div>
                <div><dt>架构</dt><dd>{crosstoolTool.architecture}</dd></div>
              </dl>
              {archiveUpload ? (
                <div className="toolchain-upload-result">
                  <CheckCircle weight="fill" />
                  <span><strong>{authorizationSent ? "授权已提交" : "归档已保存"}</strong><small>{formatArchiveSize(archiveUpload.sizeBytes)} · {archiveUpload.sourceSha256}</small></span>
                  {!authorizationSent && <Button appearance="primary" size="small" icon={archiveBusy === "authorize" ? <Spinner size="tiny" /> : <PaperPlaneTilt />} disabled={Boolean(archiveBusy) || sending} onClick={() => void authorizeArchive(archiveUpload)}>{archiveBusy === "authorize" ? "发送中" : "重试授权"}</Button>}
                </div>
              ) : (
                <div className="toolchain-upload-actions">
                  <label className={`toolchain-file-picker${archiveFile ? " has-file" : ""}`}>
                    <input
                      type="file"
                      accept={toolchainArchiveAccept}
                      disabled={Boolean(archiveBusy) || sending || goalProcessing}
                      onChange={(event) => {
                        setArchiveFile(event.currentTarget.files?.[0]);
                        setArchiveError("");
                      }}
                    />
                    <UploadSimple />
                    <span>{archiveFile ? archiveFile.name : "选择工具链归档"}</span>
                  </label>
                  <Button appearance="primary" size="small" icon={archiveBusy === "upload" ? <Spinner size="tiny" /> : <UploadSimple />} disabled={!archiveFile || Boolean(archiveBusy) || sending || goalProcessing} onClick={() => void uploadArchive()}>{archiveBusy === "upload" ? "上传中" : goalProcessing ? "Goal 处理中" : "上传并授权"}</Button>
                </div>
              )}
              {archiveError && <p className="toolchain-upload-error" role="alert"><WarningCircle weight="fill" />{archiveError}</p>}
            </section>
          )}
          <div className="workbench-composer">
            <Textarea value={message} resize="vertical" placeholder={`向${selectedAgent ? "当前 Agent" : flowLabels[activeFlow]}发送消息`} onChange={(_, data) => setMessage(data.value)} disabled={sending || Boolean(archiveBusy)} />
            <Button appearance="primary" icon={sending ? <Spinner size="tiny" /> : <PaperPlaneTilt />} disabled={!message.trim() || sending || Boolean(archiveBusy)} onClick={() => void sendMessage()}>{sending ? "发送中" : "发送"}</Button>
          </div>
        </section>
      </div>
    </main>
  );
}
