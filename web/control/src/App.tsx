import {
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Field,
  Input,
  Spinner,
  Textarea,
  Tooltip,
} from "./ui";
import {
  ArrowClockwise,
  ArrowRight,
  CaretDown,
  CaretRight,
  Check,
  CheckCircle,
  ClipboardText,
  Code,
  Copy,
  FilePlus,
  FlagCheckered,
  FolderOpen,
  GearSix,
  ListChecks,
  Plus,
  ShieldCheck,
  Sparkle,
  Target,
  TreeStructure,
  WarningCircle,
  X,
} from "@phosphor-icons/react";
import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import {
  FormEvent,
  ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { AorClient, ApiError } from "./api";
import { modelRoles } from "./types";
import type {
  AuditRun,
  GoalSpec,
  ModelProvider,
  ModelProviderSettings,
  ModelProviderSettingsInput,
  ModelProviderTestInput,
  ModelProviderTestResult,
  ModelRole,
  ModelRouteSettings,
  ModelRoutes,
  ModelSamplingSettings,
  ModelSamplingSettingsInput,
  ModuleTask,
  PlanSpec,
  Project,
  ProjectCreateInput,
  ProjectResult,
  ProjectState,
  RecentProject,
} from "./types";

gsap.registerPlugin(ScrollTrigger, useGSAP);

const recentProjectsKey = "aor.recent-projects.v1";
const activeProjectKey = "aor.active-project.v1";

const projectStateLabels: Record<ProjectState, string> = {
  CREATED: "已创建",
  GOAL_NEGOTIATING: "目标协商",
  GOAL_SUSPENDED: "目标待处理",
  PLANNING: "规划中",
  EXECUTING: "执行中",
  INTEGRATING: "集成中",
  GLOBAL_AUDIT: "全局审计",
  BLOCKED_USER_DECISION: "等待决策",
  PAUSED: "已暂停",
  COMPLETED: "已完成",
  ABORTED: "已终止",
  FAILED_SYSTEM: "系统失败",
  ARCHIVED: "已归档",
};

const taskStateLabels: Record<string, string> = {
  DEFINED: "已定义",
  PLANNING: "模块规划",
  READY: "等待执行",
  EXECUTING: "编码中",
  SUBMITTED: "已提交",
  DETERMINISTIC_AUDIT: "自动审计",
  LLM_AUDIT: "模型审计",
  REWORK: "返工",
  PASSED: "通过",
  INTEGRATED: "已集成",
  BLOCKED: "已阻塞",
  FAILED: "失败",
  SUPERSEDED: "已替换",
};

const terminalProjectStates = new Set<ProjectState>([
  "COMPLETED",
  "ABORTED",
  "FAILED_SYSTEM",
  "ARCHIVED",
]);

const modelRoleLabels: Record<ModelRole, string> = {
  GOAL_PROPOSER: "目标提案",
  GOAL_CHALLENGER: "目标审议",
  PLAN_SUPERVISOR: "计划总控",
  MODULE_PLANNER: "模块规划",
  EXECUTOR: "代码执行",
  MODULE_AUDITOR: "模块审计",
  GLOBAL_AUDITOR: "全局审计",
  KNOWLEDGE_CURATOR: "知识管理",
};

const modelProviderRows = [
  { key: "openai", label: "OpenAI" },
  { key: "deepseek", label: "DeepSeek" },
  { key: "claude", label: "Claude" },
  { key: "grok", label: "Grok" },
] as const;

type ModelProviderKey = (typeof modelProviderRows)[number]["key"];

type ModelProviderDraft = ModelProviderSettings & {
  apiKey: string;
  testModel: string;
};

type ModelProviderDrafts = Record<ModelProviderKey, ModelProviderDraft | undefined>;

type ProviderTestState = {
  status: "idle" | "testing" | "success" | "error";
  message?: string;
  latencyMs?: number;
};

type ModelProviderUpdate = {
  id: string;
  input: ModelProviderSettingsInput;
};

function emptyModelProviderDrafts(): ModelProviderDrafts {
  return { openai: undefined, deepseek: undefined, claude: undefined, grok: undefined };
}

function modelProviderSetting(settings: ModelProviderSettings[], key: ModelProviderKey): ModelProviderSettings | undefined {
  return settings.find((item) => item.provider.toLowerCase() === key || item.id.toLowerCase() === key);
}

function cloneModelProviderDrafts(settings: ModelProviderSettings[]): ModelProviderDrafts {
  const drafts = emptyModelProviderDrafts();
  for (const { key } of modelProviderRows) {
    const setting = modelProviderSetting(settings, key);
    if (!setting) continue;
    drafts[key] = {
      ...setting,
      protocols: setting.protocols ? [...setting.protocols] : undefined,
      models: [...setting.models],
      apiKey: "",
      testModel: setting.models[0] || "",
    };
  }
  return drafts;
}

function cloneModelRoutes(routes?: ModelRoutes): ModelRoutes | undefined {
  if (!routes) return undefined;
  return Object.fromEntries(modelRoles.map((role) => [role, { ...routes[role] }])) as ModelRoutes;
}

function readRecentProjects(): RecentProject[] {
  try {
    const parsed = JSON.parse(localStorage.getItem(recentProjectsKey) || "[]") as RecentProject[];
    return parsed.filter((item) => item.id && item.name).slice(0, 8);
  } catch {
    return [];
  }
}

function rememberProject(project: Project): RecentProject[] {
  const item: RecentProject = {
    id: project.id,
    name: project.name,
    state: project.state,
    touchedAt: new Date().toISOString(),
  };
  const next = [item, ...readRecentProjects().filter((recent) => recent.id !== project.id)].slice(0, 8);
  localStorage.setItem(recentProjectsKey, JSON.stringify(next));
  localStorage.setItem(activeProjectKey, project.id);
  return next;
}

function shortId(value: string, length = 8): string {
  if (!value) return "-";
  return value.length <= length ? value : value.slice(0, length);
}

function formatTime(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError && error.code) {
    return `${error.message} · ${error.code}`;
  }
  return error instanceof Error ? error.message : "请求失败";
}

function findingText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    for (const key of ["message", "summary", "description", "detail"]) {
      if (typeof record[key] === "string") return record[key];
    }
  }
  return JSON.stringify(value);
}

function latestByVersion<T>(items: T[], version: (item: T) => number): T | undefined {
  return [...items].sort((left, right) => version(right) - version(left))[0];
}

function IconButton({ label, icon, onClick, disabled }: {
  label: string;
  icon: ReactNode;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <Tooltip content={label} relationship="label">
      <Button
        appearance="subtle"
        className="icon-button"
        aria-label={label}
        icon={icon}
        onClick={onClick}
        disabled={disabled}
      />
    </Tooltip>
  );
}

function StatusMark({ state }: { state: string }) {
  const lower = state.toLowerCase();
  const tone = lower.includes("fail") || lower.includes("abort") || lower.includes("block")
    ? "danger"
    : lower.includes("pass") || lower.includes("complete") || lower.includes("approve") || lower.includes("integrated")
      ? "success"
      : "neutral";
  return <span className={`status-mark status-${tone}`}>{taskStateLabels[state] || projectStateLabels[state as ProjectState] || state}</span>;
}

export function App() {
  const client = useMemo(() => new AorClient(), []);
  return <ControlConsole client={client} />;
}

interface ProjectBundle {
  project?: Project;
  goalSpecs: GoalSpec[];
  plans: PlanSpec[];
  tasks: ModuleTask[];
  result?: ProjectResult;
}

function ControlConsole({ client }: { client: AorClient }) {
  const [bundle, setBundle] = useState<ProjectBundle>({ goalSpecs: [], plans: [], tasks: [] });
  const [recent, setRecent] = useState(readRecentProjects);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [newOpen, setNewOpen] = useState(false);
  const [openOpen, setOpenOpen] = useState(false);
  const [resultOpen, setResultOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [modelProviders, setModelProviders] = useState<ModelProvider[]>([]);
  const [providerSettings, setProviderSettings] = useState<ModelProviderSettings[]>([]);
  const [routeSettings, setRouteSettings] = useState<ModelRouteSettings>();
  const [samplingSettings, setSamplingSettings] = useState<ModelSamplingSettings>();
  const [selectedTask, setSelectedTask] = useState("");
  const [audits, setAudits] = useState<Record<string, AuditRun[]>>({});
  const [auditLoading, setAuditLoading] = useState("");
  const mainRef = useRef<HTMLDivElement>(null);
  const project = bundle.project;

  const loadProject = useCallback(async (projectId: string, silent = false) => {
    if (!projectId) return;
    if (silent) setRefreshing(true); else setLoading(true);
    if (!silent) setError("");
    try {
      const current = await client.getProject(projectId);
      const tasksRequest = current.plan
        ? client.getTasks(projectId)
        : Promise.resolve({ items: [] as ModuleTask[] });
      const [goals, plans, tasks, result] = await Promise.allSettled([
        client.getGoalSpecs(projectId),
        client.getPlans(projectId),
        tasksRequest,
        client.getResult(projectId),
      ]);
      setBundle({
        project: current,
        goalSpecs: goals.status === "fulfilled" ? goals.value.items : [],
        plans: plans.status === "fulfilled" ? plans.value.items : [],
        tasks: tasks.status === "fulfilled" ? tasks.value.items : [],
        result: result.status === "fulfilled" ? result.value : undefined,
      });
      setRecent(rememberProject(current));
    } catch (cause) {
      if (!silent) setError(errorMessage(cause));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [client]);

  useEffect(() => {
    const active = localStorage.getItem(activeProjectKey);
    if (active) void loadProject(active);
  }, [loadProject]);

  useEffect(() => {
    let active = true;
    void Promise.all([client.getModelProviders(), client.getModelProviderSettings(), client.getModelRouteSettings(), client.getModelSamplingSettings()])
      .then(([providers, configuredProviders, settings, sampling]) => {
        if (!active) return;
        setModelProviders(providers.items);
        setProviderSettings(configuredProviders.items);
        setRouteSettings(settings);
        setSamplingSettings(sampling);
      })
      .catch((cause) => active && setError(errorMessage(cause)));
    return () => { active = false; };
  }, [client]);

  useEffect(() => {
    if (!project || terminalProjectStates.has(project.state)) return;
    const timer = window.setInterval(() => void loadProject(project.id, true), 5_000);
    return () => window.clearInterval(timer);
  }, [loadProject, project?.id, project?.state]);

  useEffect(() => {
    if (!notice) return;
    const timer = window.setTimeout(() => setNotice(""), 4_000);
    return () => window.clearTimeout(timer);
  }, [notice]);

  useGSAP(() => {
    if (!project || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    gsap.fromTo(
      ".stage-section",
      { y: 22, autoAlpha: 0 },
      {
        y: 0,
        autoAlpha: 1,
        duration: 0.48,
        stagger: 0.06,
        ease: "power2.out",
        scrollTrigger: { trigger: ".workspace-content", start: "top 88%", once: true },
      },
    );
    const media = gsap.matchMedia();
    media.add("(min-width: 1080px) and (prefers-reduced-motion: no-preference)", () => {
      ScrollTrigger.create({
        trigger: ".console-layout",
        start: "top 78px",
        end: "bottom bottom",
        pin: ".context-rail-inner",
        pinSpacing: false,
      });
    });
    return () => media.revert();
  }, { scope: mainRef, dependencies: [project?.id], revertOnUpdate: true });

  const selectTask = useCallback(async (taskId: string) => {
    const next = selectedTask === taskId ? "" : taskId;
    setSelectedTask(next);
    if (!next || !project || audits[next]) return;
    setAuditLoading(next);
    try {
      const page = await client.getAudits(project.id, next);
      setAudits((current) => ({ ...current, [next]: page.items }));
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setAuditLoading("");
    }
  }, [audits, client, project, selectedTask]);

  const createProject = useCallback(async (input: ProjectCreateInput) => {
    setLoading(true);
    setError("");
    try {
      const created = await client.createProject(input);
      setNewOpen(false);
      setNotice("项目已创建");
      await loadProject(created.id);
    } catch (cause) {
      setError(errorMessage(cause));
      setLoading(false);
    }
  }, [client, loadProject]);

  const saveModelSettings = useCallback(async (updates: ModelProviderUpdate[], modelRoutes: ModelRoutes, sampling: ModelSamplingSettingsInput) => {
    setSettingsBusy(true);
    setError("");
    try {
      const [savedSampling, saved, savedProviders] = await Promise.all([
        client.putModelSamplingSettings(sampling),
        client.putModelRouteSettings(modelRoutes),
        Promise.all(updates.map((update) => client.putModelProviderSettings(update.id, update.input))),
      ]);
      if (savedProviders.length > 0) {
        setProviderSettings((current) => {
          const next = [...current];
          for (const provider of savedProviders) {
            const index = next.findIndex((item) => item.id === provider.id);
            if (index >= 0) next[index] = provider;
            else next.push(provider);
          }
          return next;
        });
      }
      setRouteSettings(saved);
      setSamplingSettings(savedSampling);
      setSettingsOpen(false);
      setNotice("模型设置已更新");
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setSettingsBusy(false);
    }
  }, [client]);

  const testModelProvider = useCallback((providerId: string, input: ModelProviderTestInput): Promise<ModelProviderTestResult> => {
    return client.testModelProvider(providerId, input);
  }, [client]);

  return (
    <div className="console-shell" ref={mainRef}>
      <header className="topbar">
        <button className="brand-button" onClick={() => project && window.scrollTo({ top: 0, behavior: "smooth" })}>
          <span className="brand-glyph">A</span><span>AOR</span><small>CONTROL</small>
        </button>
        <div className="topbar-context">
          {project ? <><strong>{project.name}</strong><StatusMark state={project.state} /></> : <span>未选择项目</span>}
        </div>
        <div className="topbar-actions">
          <IconButton label="刷新" icon={<ArrowClockwise className={refreshing ? "spin" : ""} />} onClick={() => project && void loadProject(project.id)} disabled={!project || refreshing} />
          <IconButton label="模型设置" icon={<GearSix />} onClick={() => setSettingsOpen(true)} disabled={!routeSettings || !samplingSettings || modelProviders.length === 0} />
          <Button appearance="subtle" icon={<FolderOpen />} onClick={() => setOpenOpen(true)}>打开</Button>
          <Button appearance="primary" icon={<Plus weight="bold" />} onClick={() => setNewOpen(true)}>新建项目</Button>
        </div>
      </header>

      {notice && <div className="toast" role="status"><CheckCircle weight="fill" />{notice}</div>}
      {error && <div className="error-banner" role="alert"><WarningCircle weight="fill" /><span>{error}</span><button aria-label="关闭" onClick={() => setError("")}><X /></button></div>}

      {loading && !project ? (
        <div className="workspace-loading"><Spinner label="正在读取项目" /></div>
      ) : project ? (
        <div className="console-layout">
          <ContextRail
            project={project}
            result={bundle.result}
            recent={recent}
            onSelect={(id) => void loadProject(id)}
            onResult={() => setResultOpen(true)}
          />
          <Workspace
            bundle={bundle}
            selectedTask={selectedTask}
            audits={audits}
            auditLoading={auditLoading}
            onSelectTask={(id) => void selectTask(id)}
            onProjectChanged={(next) => {
              setBundle((current) => ({ ...current, project: next }));
              setRecent(rememberProject(next));
            }}
            onReload={() => void loadProject(project.id)}
            onNotice={setNotice}
            onError={(cause) => setError(errorMessage(cause))}
            client={client}
          />
        </div>
      ) : (
        <EmptyWorkspace onCreate={() => setNewOpen(true)} onOpen={() => setOpenOpen(true)} recent={recent} onSelect={(id) => void loadProject(id)} />
      )}

      <NewProjectDialog open={newOpen} busy={loading} providers={modelProviders} defaults={routeSettings} onClose={() => setNewOpen(false)} onSubmit={createProject} />
      <OpenProjectDialog open={openOpen} onClose={() => setOpenOpen(false)} onSubmit={(id) => { setOpenOpen(false); void loadProject(id); }} />
      <ModelSettingsDialog
        open={settingsOpen}
        busy={settingsBusy}
        providers={modelProviders}
        providerSettings={providerSettings}
        settings={routeSettings}
        samplingSettings={samplingSettings}
        onClose={() => setSettingsOpen(false)}
        onTestProvider={testModelProvider}
        onSubmit={saveModelSettings}
      />
      <ResultDrawer result={bundle.result} project={project} open={resultOpen} onClose={() => setResultOpen(false)} />
    </div>
  );
}

function EmptyWorkspace({ onCreate, onOpen, recent, onSelect }: {
  onCreate: () => void;
  onOpen: () => void;
  recent: RecentProject[];
  onSelect: (id: string) => void;
}) {
  return (
    <main className="empty-workspace">
      <div className="empty-copy">
        <span className="eyebrow">AOR 项目控制台</span>
        <h1>选择一个项目开始</h1>
        <div className="empty-actions">
          <Button appearance="primary" size="large" icon={<FilePlus />} onClick={onCreate}>新建项目</Button>
          <Button size="large" icon={<FolderOpen />} onClick={onOpen}>按 ID 打开</Button>
        </div>
      </div>
      {recent.length > 0 && (
        <div className="recent-grid">
          {recent.map((item) => (
            <button key={item.id} onClick={() => onSelect(item.id)}>
              <span><StatusMark state={item.state} /></span>
              <strong>{item.name}</strong>
              <small>{shortId(item.id, 12)}</small>
              <ArrowRight />
            </button>
          ))}
        </div>
      )}
    </main>
  );
}

function ContextRail({ project, result, recent, onSelect, onResult }: {
  project: Project;
  result?: ProjectResult;
  recent: RecentProject[];
  onSelect: (id: string) => void;
  onResult: () => void;
}) {
  const stages = [
    { name: "目标", icon: <Target />, states: ["CREATED", "GOAL_NEGOTIATING", "GOAL_SUSPENDED"] },
    { name: "计划", icon: <TreeStructure />, states: ["PLANNING"] },
    { name: "执行", icon: <Code />, states: ["EXECUTING"] },
    { name: "审计", icon: <ShieldCheck />, states: ["INTEGRATING", "GLOBAL_AUDIT"] },
    { name: "结果", icon: <FlagCheckered />, states: ["COMPLETED"] },
  ];
  const active = result?.status === "COMPLETED" ? 4 : Math.max(0, stages.findIndex((stage) => stage.states.includes(project.state)));
  return (
    <aside className="context-rail">
      <div className="context-rail-inner">
        <div className="project-index">
          <span className="eyebrow">当前项目</span>
          <strong>{project.name}</strong>
          <button className="copy-id" onClick={() => void navigator.clipboard.writeText(project.id)} title="复制项目 ID">
            <span>{shortId(project.id, 18)}</span><Copy />
          </button>
        </div>
        <nav className="workflow-rail" aria-label="项目流程">
          {stages.map((stage, index) => (
            <div className={`workflow-step ${index < active ? "is-done" : index === active ? "is-active" : ""}`} key={stage.name}>
              <span className="workflow-icon">{index < active ? <Check weight="bold" /> : stage.icon}</span>
              <span><small>0{index + 1}</small><strong>{stage.name}</strong></span>
            </div>
          ))}
        </nav>
        <Button appearance="outline" icon={<ClipboardText />} onClick={onResult} disabled={!result}>查看项目结果</Button>
        {recent.length > 1 && (
          <div className="recent-list">
            <span className="rail-label">最近项目</span>
            {recent.filter((item) => item.id !== project.id).slice(0, 4).map((item) => (
              <button key={item.id} onClick={() => onSelect(item.id)}><span>{item.name}</span><ArrowRight /></button>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}

function Workspace({ bundle, selectedTask, audits, auditLoading, onSelectTask, onProjectChanged, onReload, onNotice, onError, client }: {
  bundle: ProjectBundle;
  selectedTask: string;
  audits: Record<string, AuditRun[]>;
  auditLoading: string;
  onSelectTask: (id: string) => void;
  onProjectChanged: (project: Project) => void;
  onReload: () => void;
  onNotice: (notice: string) => void;
  onError: (error: unknown) => void;
  client: AorClient;
}) {
  const project = bundle.project!;
  const goal = latestByVersion(bundle.goalSpecs, (item) => item.content.version);
  const plan = latestByVersion(bundle.plans, (item) => item.planSpecVersion || 0);
  const [goalMessage, setGoalMessage] = useState("");
  const [action, setAction] = useState("");

  const sendGoal = async () => {
    const message = goalMessage.trim();
    if (!message) return;
    setAction("goal");
    try {
      const next = await client.sendGoal(project, message);
      onProjectChanged(next);
      setGoalMessage("");
      onNotice("目标已提交，正在生成 GoalSpec");
      onReload();
    } catch (cause) {
      onError(cause);
    } finally {
      setAction("");
    }
  };

  const approveGoal = async () => {
    if (!goal) return;
    setAction("approve");
    try {
      const next = await client.approveGoal(project, goal);
      onProjectChanged(next);
      onNotice("GoalSpec 已批准，规划已启动");
      onReload();
    } catch (cause) {
      onError(cause);
    } finally {
      setAction("");
    }
  };

  return (
    <main className="workspace-content">
      <header className="workspace-header">
        <div>
          <span className="eyebrow">PROJECT / {shortId(project.id)}</span>
          <h1>{project.name}</h1>
        </div>
        <dl className="project-facts">
          <div><dt>状态</dt><dd><StatusMark state={project.state} /></dd></div>
          <div><dt>版本</dt><dd>v{project.version}</dd></div>
          <div><dt>目标 Agent</dt><dd>{project.goalAgentCount}</dd></div>
          <div><dt>数据级别</dt><dd>{project.dataClassification}</dd></div>
        </dl>
      </header>

      <section className="stage-section goal-section" id="goal">
        <SectionHeading number="01" title="目标" icon={<Target />} meta={goal ? `GoalSpec v${goal.content.version}` : "等待输入"} />
        <div className="goal-layout">
          <div className="goal-primary">
            {goal ? (
              <div className="goal-spec">
                <div className="goal-title-line"><h2>{goal.content.title}</h2><StatusMark state={goal.status} /></div>
                <p>{goal.content.summary}</p>
                <div className="metric-strip">
                  <div><strong>{goal.content.functionalRequirements?.length || 0}</strong><span>功能需求</span></div>
                  <div><strong>{goal.content.acceptanceCriteria?.length || 0}</strong><span>验收标准</span></div>
                  <div className={goal.content.unresolvedItems?.length ? "metric-alert" : ""}><strong>{goal.content.unresolvedItems?.length || 0}</strong><span>未决事项</span></div>
                </div>
                {goal.content.acceptanceCriteria?.length > 0 && (
                  <div className="criteria-list">
                    <span className="rail-label">验收标准</span>
                    {goal.content.acceptanceCriteria.slice(0, 5).map((criterion) => (
                      <div key={criterion.id}><CheckCircle /><span>{criterion.statement}</span></div>
                    ))}
                  </div>
                )}
                {goal.status === "DRAFT" && (
                  <Button
                    appearance="primary"
                    icon={action === "approve" ? <Spinner size="tiny" /> : <Check />}
                    onClick={() => void approveGoal()}
                    disabled={action !== "" || goal.content.unresolvedItems.length > 0}
                  >
                    批准 GoalSpec
                  </Button>
                )}
              </div>
            ) : (
              <div className="stage-empty"><Sparkle /><strong>尚未生成 GoalSpec</strong><span>提交目标后，目标层会整理范围与验收标准。</span></div>
            )}
          </div>
          {(project.state === "CREATED" || project.state === "GOAL_NEGOTIATING" || project.state === "GOAL_SUSPENDED") && (
            <div className="goal-composer">
              <Field label="项目目标">
                <Textarea
                  resize="vertical"
                  value={goalMessage}
                  onChange={(_, data) => setGoalMessage(data.value)}
                  placeholder="例如：实现一个支持四则运算、包含 README 和测试的 Go 计算器。"
                />
              </Field>
              <Button
                appearance="primary"
                icon={action === "goal" ? <Spinner size="tiny" /> : <ArrowRight />}
                iconPosition="after"
                disabled={!goalMessage.trim() || action !== ""}
                onClick={() => void sendGoal()}
              >
                提交目标
              </Button>
            </div>
          )}
        </div>
      </section>

      <section className="stage-section" id="plan">
        <SectionHeading number="02" title="计划" icon={<TreeStructure />} meta={plan ? `${plan.modules?.length || 0} 个模块` : "尚未发布"} />
        {plan ? (
          <div className="plan-grid">
            {(plan.modules || []).map((module, index) => (
              <article className="plan-module" key={module.moduleId || module.name || index}>
                <span>0{index + 1}</span>
                <div><h3>{module.name || module.moduleId || `模块 ${index + 1}`}</h3>{module.summary && <p>{module.summary}</p>}</div>
              </article>
            ))}
          </div>
        ) : (
          <PendingLine label={project.state === "PLANNING" ? "计划 Agent 正在拆分模块" : "GoalSpec 批准后开始规划"} active={project.state === "PLANNING"} />
        )}
      </section>

      <section className="stage-section" id="execution">
        <SectionHeading
          number="03"
          title="执行与审计"
          icon={<Code />}
          meta={bundle.tasks.length ? `${bundle.tasks.filter((task) => task.state === "PASSED" || task.state === "INTEGRATED").length}/${bundle.tasks.length} 通过` : "无任务"}
        />
        {bundle.tasks.length ? (
          <TaskTable tasks={bundle.tasks} selectedTask={selectedTask} audits={audits} auditLoading={auditLoading} onSelect={onSelectTask} />
        ) : (
          <PendingLine label="计划发布后显示模块任务" active={false} />
        )}
      </section>

      <section className="stage-section result-band" id="result">
        <SectionHeading number="04" title="结果" icon={<FlagCheckered />} meta={bundle.result?.status || "PENDING"} />
        {bundle.result?.planSupervisorSummary ? (
          <div className="result-preview">
            <CheckCircle weight="fill" />
            <div><strong>核心链路已完成</strong><p>{bundle.result.planSupervisorSummary.overview}</p></div>
          </div>
        ) : (
          <PendingLine label={bundle.result?.status === "SUMMARIZING" ? "计划层正在汇总结果" : "所有模块通过后生成结果"} active={bundle.result?.status === "SUMMARIZING"} />
        )}
      </section>
    </main>
  );
}

function SectionHeading({ number, title, icon, meta }: { number: string; title: string; icon: ReactNode; meta: string }) {
  return (
    <header className="section-heading">
      <span className="section-number">{number}</span>
      <span className="section-icon">{icon}</span>
      <h2>{title}</h2>
      <span className="section-meta">{meta}</span>
    </header>
  );
}

function PendingLine({ label, active }: { label: string; active: boolean }) {
  return (
    <div className={`pending-line ${active ? "is-active" : ""}`}>
      {active ? <Spinner size="tiny" /> : <span className="pending-dot" />}
      <span>{label}</span>
    </div>
  );
}

function TaskTable({ tasks, selectedTask, audits, auditLoading, onSelect }: {
  tasks: ModuleTask[];
  selectedTask: string;
  audits: Record<string, AuditRun[]>;
  auditLoading: string;
  onSelect: (taskId: string) => void;
}) {
  return (
    <div className="task-table">
      <div className="task-table-head"><span>模块</span><span>状态</span><span>尝试</span><span>依赖</span><span /></div>
      {tasks.map((task) => {
        const expanded = selectedTask === task.id;
        return (
          <div className={`task-item ${expanded ? "is-expanded" : ""}`} key={task.id}>
            <button className="task-row" onClick={() => onSelect(task.id)} aria-expanded={expanded}>
              <span className="task-name"><Code /><span><strong>{task.moduleId || shortId(task.id)}</strong><small>{shortId(task.id, 12)}</small></span></span>
              <StatusMark state={task.state} />
              <span>{task.attempt || 0} / 3</span>
              <span>{task.dependentTaskIds?.length || 0}</span>
              <span className="task-expand">{expanded ? <CaretDown /> : <CaretRight />}</span>
            </button>
            {expanded && (
              <div className="task-detail">
                <div className="task-facts">
                  <span><small>Task version</small><strong>v{task.version}</strong></span>
                  <span><small>Fence</small><strong>{task.fencingToken || "-"}</strong></span>
                  <span><small>Spec</small><strong>v{task.moduleSpecRef?.version || "-"}</strong></span>
                </div>
                {auditLoading === task.id ? <Spinner size="tiny" label="读取审计记录" /> : <AuditList runs={audits[task.id] || []} />}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function AuditList({ runs }: { runs: AuditRun[] }) {
  if (!runs.length) {
    return <div className="audit-empty"><ShieldCheck /><span>暂无审计记录</span></div>;
  }
  return (
    <div className="audit-list">
      {runs.map((run) => (
        <article className="audit-run" key={run.id}>
          <div className="audit-run-head">
            <span className="audit-phase">{run.phase}</span>
            <StatusMark state={run.verdict || run.state} />
            <time>{formatTime(run.completedAt || run.startedAt)}</time>
          </div>
          {run.findings.length > 0 ? (
            <div className="finding-list">
              {run.findings.map((finding) => (
                <div className="finding" key={finding.id}>
                  <span className={`severity severity-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                  <div><strong>{finding.ruleId}</strong><p>{findingText(finding.content)}</p>{finding.filePath && <small>{finding.filePath}{finding.lineStart ? `:${finding.lineStart}` : ""}</small>}</div>
                </div>
              ))}
            </div>
          ) : <span className="no-findings"><CheckCircle />未发现问题</span>}
        </article>
      ))}
    </div>
  );
}

function NewProjectDialog({ open, busy, providers, defaults, onClose, onSubmit }: {
  open: boolean;
  busy: boolean;
  providers: ModelProvider[];
  defaults?: ModelRouteSettings;
  onClose: () => void;
  onSubmit: (input: ProjectCreateInput) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [agents, setAgents] = useState<1 | 2>(1);
  const [classification, setClassification] = useState<ProjectCreateInput["dataClassification"]>("INTERNAL");
  const [target, setTarget] = useState("test");
  const [hard, setHard] = useState("100000");
  const [soft, setSoft] = useState("80000");
  const [routes, setRoutes] = useState<ModelRoutes>();
  useEffect(() => {
    if (open) setRoutes(cloneModelRoutes(defaults?.modelRoutes));
  }, [defaults?.version, open]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void onSubmit({
      name: name.trim(),
      goalAgentCount: agents,
      dataClassification: classification,
      deploymentTargets: target.split(",").map((item) => item.trim()).filter(Boolean),
      budget: { hardLimitMinor: Number(hard), softLimitMinor: Number(soft), currency: "USD" },
      modelRoutes: cloneModelRoutes(routes),
    });
  };
  return (
    <Dialog open={open} onOpenChange={(_, data) => !data.open && onClose()}>
      <DialogSurface className="form-dialog project-form-dialog">
        <form onSubmit={submit}>
          <DialogBody>
            <DialogTitle>新建项目</DialogTitle>
            <DialogContent className="dialog-form">
              <Field label="项目名称" required><Input value={name} onChange={(_, data) => setName(data.value)} autoFocus /></Field>
              <Field label="目标层 Agent 数量">
                <div className="segment-control">
                  <button type="button" className={agents === 1 ? "is-active" : ""} onClick={() => setAgents(1)}>1 个</button>
                  <button type="button" className={agents === 2 ? "is-active" : ""} onClick={() => setAgents(2)}>2 个</button>
                </div>
              </Field>
              <Field label="数据级别">
                <select className="native-select" value={classification} onChange={(event) => setClassification(event.target.value as ProjectCreateInput["dataClassification"])}>
                  <option value="PUBLIC">PUBLIC</option><option value="INTERNAL">INTERNAL</option><option value="CONFIDENTIAL">CONFIDENTIAL</option><option value="RESTRICTED">RESTRICTED</option>
                </select>
              </Field>
              <Field label="部署目标"><Input value={target} onChange={(_, data) => setTarget(data.value)} /></Field>
              <div className="field-pair">
                <Field label="预算上限（美分）"><Input type="number" min={1} value={hard} onChange={(_, data) => setHard(data.value)} /></Field>
                <Field label="软预警（美分）"><Input type="number" min={0} value={soft} onChange={(_, data) => setSoft(data.value)} /></Field>
              </div>
              {routes && providers.length > 0 && <ModelRouteEditor routes={routes} providers={providers} onChange={setRoutes} />}
            </DialogContent>
            <DialogActions><Button appearance="secondary" onClick={onClose}>取消</Button><Button appearance="primary" type="submit" disabled={busy || !name.trim() || !target.trim() || Number(hard) <= 0 || Number(soft) > Number(hard)}>{busy ? "创建中" : "创建项目"}</Button></DialogActions>
          </DialogBody>
        </form>
      </DialogSurface>
    </Dialog>
  );
}

function ModelSettingsDialog({ open, busy, providers, providerSettings, settings, samplingSettings, onClose, onTestProvider, onSubmit }: {
  open: boolean;
  busy: boolean;
  providers: ModelProvider[];
  providerSettings: ModelProviderSettings[];
  settings?: ModelRouteSettings;
  samplingSettings?: ModelSamplingSettings;
  onClose: () => void;
  onTestProvider: (providerId: string, input: ModelProviderTestInput) => Promise<ModelProviderTestResult>;
  onSubmit: (updates: ModelProviderUpdate[], routes: ModelRoutes, sampling: ModelSamplingSettingsInput) => Promise<void>;
}) {
  const [routes, setRoutes] = useState<ModelRoutes>();
  const [sampling, setSampling] = useState<ModelSamplingSettingsInput>();
  const [drafts, setDrafts] = useState<ModelProviderDrafts>(emptyModelProviderDrafts);
  const [testStates, setTestStates] = useState<Partial<Record<ModelProviderKey, ProviderTestState>>>({});
  const samplingValid = Boolean(
    sampling &&
    Number.isFinite(sampling.temperature) && sampling.temperature >= 0 && sampling.temperature <= 2 &&
    Number.isFinite(sampling.topP) && sampling.topP >= 0 && sampling.topP <= 1 &&
    Number.isInteger(sampling.topK) && sampling.topK >= 0 && sampling.topK <= 500,
  );

  useEffect(() => {
    if (!open) return;
    setRoutes(cloneModelRoutes(settings?.modelRoutes));
    setSampling(samplingSettings ? {
      temperature: samplingSettings.temperature,
      topP: samplingSettings.topP,
      topK: samplingSettings.topK,
      reasoningEffort: samplingSettings.reasoningEffort,
    } : undefined);
    setDrafts(cloneModelProviderDrafts(providerSettings));
    setTestStates({});
  }, [open, providerSettings, samplingSettings?.version, settings?.version]);

  const updateDraft = (key: ModelProviderKey, patch: Partial<ModelProviderDraft>) => {
    setDrafts((current) => {
      const draft = current[key];
      return draft ? { ...current, [key]: { ...draft, ...patch } } : current;
    });
  };

  const testProvider = async (key: ModelProviderKey) => {
    const draft = drafts[key];
    if (!draft || !draft.baseUrl.trim() || !draft.testModel || busy) return;
    setTestStates((current) => ({ ...current, [key]: { status: "testing" } }));
    try {
      const input: ModelProviderTestInput = {
        baseUrl: draft.baseUrl.trim(),
        protocol: draft.protocol,
        model: draft.testModel,
      };
      if (draft.apiKey.trim()) input.apiKey = draft.apiKey.trim();
      const result = await onTestProvider(draft.id, input);
      setTestStates((current) => ({
        ...current,
        [key]: {
          status: result.ok ? "success" : "error",
          message: result.detail || (result.ok ? "连接成功" : "连接失败"),
          latencyMs: result.latencyMs,
        },
      }));
    } catch (cause) {
      setTestStates((current) => ({ ...current, [key]: { status: "error", message: errorMessage(cause) } }));
    }
  };

  const submit = () => {
    if (!routes || !sampling || !samplingValid) return;
    const updates: ModelProviderUpdate[] = [];
    for (const { key } of modelProviderRows) {
      const draft = drafts[key];
      if (!draft) continue;
      const input: ModelProviderSettingsInput = {
        baseUrl: draft.baseUrl.trim(),
        protocol: draft.protocol,
        enabled: draft.enabled,
      };
      if (draft.apiKey.trim()) input.apiKey = draft.apiKey.trim();
      updates.push({ id: draft.id, input });
    }
    void onSubmit(updates, routes, sampling);
  };

  return (
    <Dialog open={open} onOpenChange={(_, data) => !data.open && onClose()}>
      <DialogSurface className="form-dialog model-settings-dialog">
        <DialogBody>
          <DialogTitle>模型设置</DialogTitle>
          <DialogContent className="dialog-form">
            <ModelProviderSettingsEditor drafts={drafts} testStates={testStates} busy={busy} onChange={updateDraft} onTest={(key) => void testProvider(key)} />
            {sampling ? <ModelSamplingSettingsEditor settings={sampling} onChange={setSampling} /> : <Spinner label="正在读取采样参数" />}
            {routes ? <ModelRouteEditor routes={routes} providers={providers} onChange={setRoutes} /> : <Spinner label="正在读取模型目录" />}
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={onClose}>取消</Button>
            <Button appearance="primary" disabled={busy || !routes || !samplingValid} onClick={submit}>{busy ? "保存中" : "保存"}</Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}

function ModelSamplingSettingsEditor({ settings, onChange }: {
  settings: ModelSamplingSettingsInput;
  onChange: (settings: ModelSamplingSettingsInput) => void;
}) {
  return (
    <fieldset className="model-sampling-editor">
      <legend>生成参数</legend>
      <div className="model-sampling-grid">
        <Field label="温度">
          <Input type="number" min={0} max={2} step={0.1} value={settings.temperature} onChange={(_, data) => onChange({ ...settings, temperature: Number(data.value) })} />
        </Field>
        <Field label="Top P">
          <Input type="number" min={0} max={1} step={0.05} value={settings.topP} onChange={(_, data) => onChange({ ...settings, topP: Number(data.value) })} />
        </Field>
        <Field label="Top K（0 使用默认值）">
          <Input type="number" min={0} max={500} step={1} value={settings.topK} onChange={(_, data) => onChange({ ...settings, topK: Number(data.value) })} />
        </Field>
        <Field label="推理深度">
          <select className="native-select" value={settings.reasoningEffort} onChange={(event) => onChange({ ...settings, reasoningEffort: event.target.value as ModelSamplingSettingsInput["reasoningEffort"] })}>
            <option value="none">关闭</option>
            <option value="minimal">最小</option>
            <option value="low">低</option>
            <option value="medium">中</option>
            <option value="high">高</option>
            <option value="xhigh">极高</option>
            <option value="max">最大</option>
          </select>
        </Field>
      </div>
    </fieldset>
  );
}

function ModelProviderSettingsEditor({ drafts, testStates, busy, onChange, onTest }: {
  drafts: ModelProviderDrafts;
  testStates: Partial<Record<ModelProviderKey, ProviderTestState>>;
  busy: boolean;
  onChange: (key: ModelProviderKey, patch: Partial<ModelProviderDraft>) => void;
  onTest: (key: ModelProviderKey) => void;
}) {
  return (
    <fieldset className="provider-settings-editor">
      <legend>供应商</legend>
      <div className="provider-settings-list">
        {modelProviderRows.map(({ key, label }) => {
          const draft = drafts[key];
          const testState = testStates[key];
          if (!draft) {
            return (
              <div className="provider-settings-row provider-settings-missing" key={key}>
                <strong>{label}</strong><span>未提供配置</span>
              </div>
            );
          }
          const protocols = draft.protocols?.length ? draft.protocols : draft.protocol ? [draft.protocol] : [];
          return (
            <div className="provider-settings-row" key={key}>
              <div className="provider-settings-heading">
                <strong>{draft.displayName || label}</strong>
                <span className={`provider-config-state ${draft.apiKeyConfigured ? "is-configured" : ""}`}>
                  {draft.apiKeyConfigured ? "已配置" : "未配置"}
                </span>
              </div>
              <Field label="Base URL">
                <Input type="url" value={draft.baseUrl} onChange={(_, data) => onChange(key, { baseUrl: data.value })} />
              </Field>
              <Field label="API Key">
                <Input type="password" autoComplete="new-password" value={draft.apiKey} placeholder={draft.apiKeyConfigured ? "留空保持不变" : "输入 API Key"} onChange={(_, data) => onChange(key, { apiKey: data.value })} />
              </Field>
              <Field label="协议">
                {protocols.length > 1 ? (
                  <select className="native-select" value={draft.protocol} onChange={(event) => onChange(key, { protocol: event.target.value })}>
                    {protocols.map((protocol) => <option value={protocol} key={protocol}>{protocol}</option>)}
                  </select>
                ) : <span className="provider-protocol">{draft.protocol || "未指定"}</span>}
              </Field>
              <Field label="测试模型">
                <select className="native-select" value={draft.testModel} disabled={draft.models.length === 0} onChange={(event) => onChange(key, { testModel: event.target.value })}>
                  {draft.models.map((model) => <option value={model} key={model}>{model}</option>)}
                </select>
              </Field>
              <label className="provider-enabled"><input type="checkbox" checked={draft.enabled} onChange={(event) => onChange(key, { enabled: event.target.checked })} /><span>启用</span></label>
              <div className="provider-test-line">
                <Button appearance="outline" size="small" icon={testState?.status === "testing" ? <Spinner size="tiny" /> : <ArrowClockwise />} disabled={busy || testState?.status === "testing" || !draft.baseUrl.trim() || !draft.testModel} onClick={() => onTest(key)}>测试连接</Button>
                {testState?.status === "success" && <span className="provider-test-status is-success"><CheckCircle />{testState.message}{testState.latencyMs ? ` · ${testState.latencyMs} ms` : ""}</span>}
                {testState?.status === "error" && <span className="provider-test-status is-error"><WarningCircle />{testState.message}</span>}
              </div>
            </div>
          );
        })}
      </div>
    </fieldset>
  );
}

function ModelRouteEditor({ routes, providers, onChange }: {
  routes: ModelRoutes;
  providers: ModelProvider[];
  onChange: (routes: ModelRoutes) => void;
}) {
  const providersForRole = (role: ModelRole) => providers.filter((provider) =>
    provider.supportsJsonSchema &&
    (!["EXECUTOR", "MODULE_AUDITOR", "GLOBAL_AUDITOR"].includes(role) || provider.supportsToolCalls),
  );
  const updateProvider = (role: ModelRole, providerId: string) => {
    const provider = providers.find((item) => item.id === providerId);
    if (!provider || provider.models.length === 0) return;
    const current = routes[role];
    onChange({
      ...routes,
      [role]: {
        ...current,
        provider: provider.id,
        model: provider.models.includes(current.model) ? current.model : provider.models[0],
        maxOutputTokens: Math.min(current.maxOutputTokens, provider.maxOutputTokens),
        seed: provider.supportsSeed ? current.seed : undefined,
      },
    });
  };
  const updateModel = (role: ModelRole, model: string) => {
    onChange({ ...routes, [role]: { ...routes[role], model } });
  };
  return (
    <fieldset className="model-route-editor">
      <legend>模型组合</legend>
      <div className="model-route-head"><span>角色</span><span>供应商</span><span>模型</span></div>
      {modelRoles.map((role) => {
        const route = routes[role];
        const eligibleProviders = providersForRole(role);
        const provider = eligibleProviders.find((item) => item.id === route.provider) || eligibleProviders[0];
        return (
          <div className="model-route-row" key={role}>
            <label htmlFor={`provider-${role}`}>{modelRoleLabels[role]}</label>
            <select id={`provider-${role}`} className="native-select" value={route.provider} onChange={(event) => updateProvider(role, event.target.value)}>
              {eligibleProviders.map((item) => <option value={item.id} key={item.id}>{item.id}</option>)}
            </select>
            <select aria-label={`${modelRoleLabels[role]}模型`} className="native-select" value={route.model} onChange={(event) => updateModel(role, event.target.value)}>
              {(provider?.models || []).map((model) => <option value={model} key={model}>{model}</option>)}
            </select>
          </div>
        );
      })}
    </fieldset>
  );
}

function OpenProjectDialog({ open, onClose, onSubmit }: { open: boolean; onClose: () => void; onSubmit: (id: string) => void }) {
  const [projectId, setProjectId] = useState("");
  return (
    <Dialog open={open} onOpenChange={(_, data) => !data.open && onClose()}>
      <DialogSurface className="form-dialog compact-dialog">
        <form onSubmit={(event) => { event.preventDefault(); onSubmit(projectId.trim()); }}>
          <DialogBody>
            <DialogTitle>打开项目</DialogTitle>
            <DialogContent><Field label="Project ID" required><Input value={projectId} onChange={(_, data) => setProjectId(data.value)} autoFocus /></Field></DialogContent>
            <DialogActions><Button onClick={onClose}>取消</Button><Button appearance="primary" type="submit" disabled={!projectId.trim()}>打开</Button></DialogActions>
          </DialogBody>
        </form>
      </DialogSurface>
    </Dialog>
  );
}

function ResultDrawer({ result, project, open, onClose }: { result?: ProjectResult; project?: Project; open: boolean; onClose: () => void }) {
  const drawerRef = useRef<HTMLElement>(null);
  useGSAP(() => {
    if (!open || !drawerRef.current || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    gsap.fromTo(drawerRef.current, { xPercent: 100 }, { xPercent: 0, duration: 0.35, ease: "power3.out" });
  }, { dependencies: [open] });
  if (!open) return null;
  const summary = result?.planSupervisorSummary;
  return (
    <div className="drawer-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside className="result-drawer" ref={drawerRef} role="dialog" aria-modal="true" aria-labelledby="result-title">
        <header><div><span className="eyebrow">PROJECT RESULT</span><h2 id="result-title">{project?.name || "项目结果"}</h2></div><IconButton label="关闭" icon={<X />} onClick={onClose} /></header>
        <div className="drawer-status"><FlagCheckered weight="fill" /><span><small>结果状态</small><strong>{result?.status || "PENDING"}</strong></span></div>
        {summary ? (
          <div className="drawer-content">
            <section><h3>概要</h3><p className="overview-copy">{summary.overview}</p></section>
            <section><h3>模块</h3><div className="result-modules">{summary.modules.map((module) => <div key={module.taskId}><CheckCircle weight="fill" /><span><strong>{module.moduleId}</strong><small>{module.summary}</small></span></div>)}</div></section>
            {summary.crossModuleFindings.length > 0 && <section><h3>跨模块结论</h3><ul>{summary.crossModuleFindings.map((item) => <li key={item}>{item}</li>)}</ul></section>}
            {summary.recommendedNextActions.length > 0 && <section><h3>后续行动</h3><ol>{summary.recommendedNextActions.map((item) => <li key={item}>{item}</li>)}</ol></section>}
            {result?.artifactRef && <div className="artifact-ref"><ClipboardText /><span>{result.artifactRef}</span></div>}
          </div>
        ) : (
          <div className="drawer-empty"><ListChecks /><strong>结果尚未生成</strong><span>所有模块通过后，计划层会在这里发布最终汇总。</span></div>
        )}
      </aside>
    </div>
  );
}
