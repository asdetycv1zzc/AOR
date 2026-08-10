import {
  ArrowLeft,
  ArrowClockwise,
  ChatCircleText,
  Clock,
  GearSix,
  PaperPlaneTilt,
  Pulse,
  Robot,
  Tray,
  UserCircle,
  WarningCircle,
} from "@phosphor-icons/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { AorClient, ApiError } from "./api";
import type {
  ModelRole,
  ModuleTask,
  Project,
  ProjectActivityAgent,
  ProjectActivityFlow,
  ProjectActivityMessage,
  ProjectActivitySnapshot,
  ProjectResult,
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
  if (message.state === "STREAMING" && !message.content) {
    return <span className="typing-indicator" aria-label="Agent 正在响应"><i /><i /><i /></span>;
  }
  return <>{message.content || (message.state === "FAILED" ? "处理失败，详情见错误码。" : "")}{message.state === "STREAMING" && <span className="typing-indicator" aria-hidden="true"><i /><i /><i /></span>}</>;
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

export function ProjectWorkbench({ project, tasks, result, client, onBack, onReload, onNotice }: {
  project: Project;
  tasks: ModuleTask[];
  result?: ProjectResult;
  client: AorClient;
  onBack: () => void;
  onReload: () => void;
  onNotice: (message: string) => void;
}) {
  const [activity, setActivity] = useState<ProjectActivitySnapshot>();
  const [activityAvailable, setActivityAvailable] = useState<boolean>();
  const [streaming, setStreaming] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [messageFlow, setMessageFlow] = useState<ProjectActivityFlow>(() => defaultFlow(project));
  const [activeFlow, setActiveFlow] = useState<ProjectActivityFlow>(() => defaultFlow(project));
  const [selectedAgent, setSelectedAgent] = useState("");
  const [sending, setSending] = useState(false);
  const refreshTimer = useRef<number | undefined>(undefined);

  const refreshActivity = useCallback(async () => {
    try {
      const next = await client.getProjectActivity(project.id);
      setActivity(next);
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

  useEffect(() => {
    setActivity(undefined);
    setActivityAvailable(undefined);
    setError("");
    setMessage("");
    setMessageFlow(defaultFlow(project));
    setActiveFlow(defaultFlow(project));
    setSelectedAgent("");
    void refreshActivity();
  }, [project.id, refreshActivity]);

  useEffect(() => {
    if (activityAvailable === false) return;
    const timer = window.setInterval(() => void refreshActivity(), 4_000);
    return () => window.clearInterval(timer);
  }, [activityAvailable, refreshActivity]);

  useEffect(() => {
    const stop = client.subscribeProjectEvents(project.id, {
      onOpen: () => setStreaming(true),
      onClose: () => setStreaming(false),
      onEvent: (event) => {
        setActivity((current) => {
          if (!current) return current;
          const existing = current.messages.findIndex((item) => item.id === event.id);
          const messages = [...current.messages];
          if (existing >= 0) messages[existing] = event; else messages.push(event);
          return { ...current, messages, cursor: event.cursor };
        });
        if (refreshTimer.current !== undefined) return;
        refreshTimer.current = window.setTimeout(() => {
          refreshTimer.current = undefined;
          if (activityAvailable !== false) void refreshActivity();
          onReload();
        }, 250);
      },
      onError: () => setStreaming(false),
    });
    return () => {
      stop();
      if (refreshTimer.current !== undefined) window.clearTimeout(refreshTimer.current);
      refreshTimer.current = undefined;
    };
  }, [activityAvailable, client, onReload, project.id, refreshActivity]);

  const agents = activity?.agents?.length ? activity.agents : fallbackAgents(project);
  const messages = activity?.messages || [];
  const queuedInputs = messages.filter((item) => item.sender === "USER" && (item.state === "QUEUED" || item.state === "STREAMING"));
  const flows = activity?.flows?.length ? activity.flows : fallbackFlows;
  const visibleAgents = agents.filter((agent) => agent.flow === activeFlow);
  const visibleMessages = messages.filter((item) => item.flow === activeFlow);
  const completedTasks = tasks.filter((task) => task.state === "PASSED" || task.state === "INTEGRATED").length;
  const latestActivityAt = messages.at(-1)?.updatedAt || messages.at(-1)?.createdAt;

  const sendMessage = async () => {
    const content = message.trim();
    if (!content || sending) return;
    setSending(true);
    setError("");
    try {
      const targetAgent = activity?.agents?.some((agent) => agent.id === selectedAgent && agent.flow === messageFlow) ? selectedAgent : "";
      await client.sendProjectActivityMessage({ id: project.id, version: activity?.projectVersion || project.version }, messageFlow, content, targetAgent);
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

  return (
    <main className="project-workbench">
      <header className="workbench-header">
        <div className="workbench-heading-group">
          <Button appearance="subtle" size="small" icon={<ArrowLeft />} onClick={onBack} aria-label="返回项目总览" title="返回项目总览" />
          <span className="workbench-kicker">PROJECT WORKBENCH</span>
          <h1>{project.name}</h1>
        </div>
        <div className="workbench-live" aria-live="polite">
          <span className={streaming ? "is-live" : ""} />
          <strong>{streaming ? "实时" : "轮询"}</strong>
          <small>{formatActivityTime(latestActivityAt)}</small>
          <Button appearance="subtle" size="small" icon={<ArrowClockwise />} onClick={() => void refreshActivity()} aria-label="刷新活动" />
        </div>
      </header>

      {error && <div className="workbench-error" role="alert"><WarningCircle weight="fill" /><span>{error}</span><button onClick={() => setError("")} aria-label="关闭">×</button></div>}

      <div className="workbench-grid">
        <aside className="workbench-flow-rail" aria-label="项目流程">
          <header className="workbench-panel-heading"><Pulse /><div><h2>流程</h2><span>{flows.length} 个阶段</span></div></header>
          <nav className="workbench-flow-list">
            {flows.map((flow, index) => {
              const state = flowState(flow, agents, messages);
              return <button key={flow} className={`workbench-flow-item${activeFlow === flow ? " is-selected" : ""}`} onClick={() => { setActiveFlow(flow); setMessageFlow(flow); setSelectedAgent(""); }}>
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
                <button className={`workbench-agent${selectedAgent === agent.id ? " is-selected" : ""}`} key={agent.id} aria-pressed={selectedAgent === agent.id} onClick={() => { setSelectedAgent(agent.id); setMessageFlow(agent.flow); }}>
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
          <div className="workbench-messages" aria-live="polite">
            {visibleMessages.length ? visibleMessages.map((item) => (
              <article className={`workbench-message is-${item.sender.toLowerCase()}`} key={item.id}>
                <div className="message-avatar">{messageAvatar(item.sender)}</div>
                <div className="message-bubble"><header><strong>{messageSender(item)}</strong><span>{flowLabels[item.flow]}</span><time>{formatActivityTime(item.createdAt)}</time></header>
                <p>{messageContent(item)}</p>
                <footer><WorkbenchState state={item.state} />{item.latencyMs !== undefined && <small>{item.latencyMs} ms</small>}{item.errorCode && <small>{item.errorCode}</small>}</footer>
                </div>
              </article>
            )) : <div className="workbench-empty"><ChatCircleText /><span>暂无对话记录</span></div>}
          </div>
          <div className="workbench-composer">
            <select className="native-select" value={messageFlow} onChange={(event) => { const flow = event.target.value as ProjectActivityFlow; setMessageFlow(flow); setActiveFlow(flow); setSelectedAgent(""); }} aria-label="消息目标层">
              {flows.map((flow) => <option value={flow} key={flow}>{flowLabels[flow]}</option>)}
            </select>
            <Textarea value={message} resize="vertical" placeholder="向项目 Agent 发送消息" onChange={(_, data) => setMessage(data.value)} disabled={sending} />
            <Button appearance="primary" icon={sending ? <Spinner size="tiny" /> : <PaperPlaneTilt />} disabled={!message.trim() || sending} onClick={() => void sendMessage()}>{sending ? "发送中" : "发送"}</Button>
          </div>
        </section>
      </div>

      <section className="workbench-overview" aria-labelledby="workbench-overview-title">
        <header className="workbench-panel-heading"><Pulse /><div><h2 id="workbench-overview-title">返回总览</h2><span>{result?.status || project.state}</span></div></header>
        <div className="workbench-overview-body">
          <div className="overview-metrics">
            <span><strong>{completedTasks}</strong><small>已完成模块</small></span>
            <span><strong>{tasks.length}</strong><small>模块总数</small></span>
            <span><strong>{result?.artifactRef ? 1 : 0}</strong><small>返回产物</small></span>
          </div>
          <p>{result?.planSupervisorSummary?.overview || "项目完成后在此显示计划层返回。"}</p>
        </div>
      </section>
    </main>
  );
}
