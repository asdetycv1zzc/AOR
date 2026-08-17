import type {
  AuditRun,
  CommandAccepted,
  GoalSpec,
  ModelProvider,
  ModelProviderSettings,
  ModelProviderSettingsInput,
  ModelProviderSettingsPage,
  ModelProviderTestInput,
  ModelProviderTestResult,
  ModelRouteSettings,
  ModelRoutes,
  ModelSamplingSettings,
  ModelSamplingSettingsInput,
  ModuleTask,
  Page,
  PlanSpec,
  Project,
  ProjectActivityFlow,
  ProjectActivityMessage,
  ProjectActivitySnapshot,
  ProjectCreateInput,
  ProjectResult,
  ToolchainArchiveUpload,
  ToolchainInstallationBatch,
  ToolchainInventory,
  TaskDecision,
  TaskDecisionReport,
} from "./types";

interface ProblemResponse {
  detail?: string;
  title?: string;
  error?: { code?: string; message?: string; retryable?: boolean; correlationId?: string };
}

type ProjectResponse = Omit<Project, "budgetHardLimitDollars" | "budgetSoftLimitDollars"> & {
  budgetHardLimitMinor?: number;
  budgetSoftLimitMinor?: number;
};

type ProjectCreateRequest = Omit<ProjectCreateInput, "budget"> & {
  budget: {
    hardLimitMinor: number;
    softLimitMinor: number;
    currency: "USD";
  };
};

function dollarsToMinor(value: number): number {
  const scaled = value * 100;
  const rounded = Math.round(scaled);
  const tolerance = Number.EPSILON * Math.max(1, Math.abs(scaled)) * 8;
  if (!Number.isFinite(value) || value < 0 || !Number.isSafeInteger(rounded) || Math.abs(scaled - rounded) > tolerance) {
    throw new Error("美元金额必须是非负数，且最多保留两位小数");
  }
  return rounded;
}

function idempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  const bytes = globalThis.crypto?.getRandomValues(new Uint8Array(24));
  if (!bytes) {
    throw new Error("当前浏览器无法生成安全的请求标识");
  }
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function projectFromResponse(response: ProjectResponse): Project {
  const { budgetHardLimitMinor, budgetSoftLimitMinor, ...project } = response;
  return {
    ...project,
    budgetHardLimitDollars: budgetHardLimitMinor === undefined ? undefined : budgetHardLimitMinor / 100,
    budgetSoftLimitDollars: budgetSoftLimitMinor === undefined ? undefined : budgetSoftLimitMinor / 100,
  };
}

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly retryable: boolean;

  constructor(status: number, problem: ProblemResponse) {
    super(problem.error?.message || problem.detail || problem.title || `请求失败 (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.code = problem.error?.code;
    this.retryable = Boolean(problem.error?.retryable);
  }
}

export type TokenProvider = () => Promise<string | undefined>;

const eventStreamInitialRetryDelay = 500;
const eventStreamMaximumRetryDelay = 8_000;
const eventStreamStableConnectionTime = 10_000;

async function parseProblem(response: Response): Promise<ProblemResponse> {
  try {
    return (await response.json()) as ProblemResponse;
  } catch {
    return { title: response.statusText };
  }
}

export class AorClient {
  constructor(private readonly token: TokenProvider = async () => undefined) {}

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers = new Headers(init.headers);
    const token = await this.token();
    if (token) headers.set("Authorization", `Bearer ${token}`);
    headers.set("Accept", "application/json");
    if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(path, { ...init, headers, cache: "no-store" });
    if (!response.ok) {
      throw new ApiError(response.status, await parseProblem(response));
    }
    return (await response.json()) as T;
  }

  async createProject(input: ProjectCreateInput): Promise<Project> {
    const request: ProjectCreateRequest = {
      ...input,
      budget: {
        hardLimitMinor: dollarsToMinor(input.budget.hardLimitDollars),
        softLimitMinor: dollarsToMinor(input.budget.softLimitDollars),
        currency: input.budget.currency,
      },
    };
    const response = await this.request<ProjectResponse>("/v1/projects", {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey() },
      body: JSON.stringify(request),
    });
    return projectFromResponse(response);
  }

  async getProjects(): Promise<Project[]> {
    const projects: Project[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    do {
      const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : "";
      const page = await this.request<Page<ProjectResponse>>(`/v1/projects${query}`);
      projects.push(...page.items.map(projectFromResponse));
      if (!page.nextCursor) break;
      if (seenCursors.has(page.nextCursor)) throw new Error("项目列表返回了重复的游标");
      seenCursors.add(page.nextCursor);
      cursor = page.nextCursor;
    } while (cursor);
    return projects;
  }

  getModelProviders(): Promise<Page<ModelProvider>> {
    return this.request("/v1/model-providers");
  }

  getToolchains(): Promise<ToolchainInventory> {
    return this.request("/v1/toolchains");
  }

  getToolchainInstallations(projectId: string): Promise<Page<ToolchainInstallationBatch>> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/toolchain-installations`);
  }

  uploadToolchainArchive(projectId: string, input: {
    file: File;
    toolName: string;
    toolVersion: string;
    architecture: string;
  }): Promise<ToolchainArchiveUpload> {
    const body = new FormData();
    body.append("toolName", input.toolName);
    body.append("toolVersion", input.toolVersion);
    body.append("architecture", input.architecture);
    body.append("file", input.file, input.file.name);
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/toolchain-archives`, {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey() },
      body,
    });
  }

  getModelProviderSettings(): Promise<ModelProviderSettingsPage> {
    return this.request("/v1/settings/model-providers");
  }

  putModelProviderSettings(providerId: string, input: ModelProviderSettingsInput): Promise<ModelProviderSettings> {
    return this.request(`/v1/settings/model-providers/${encodeURIComponent(providerId)}`, {
      method: "PUT",
      body: JSON.stringify(input),
    });
  }

  testModelProvider(providerId: string, input: ModelProviderTestInput): Promise<ModelProviderTestResult> {
    return this.request(`/v1/settings/model-providers/${encodeURIComponent(providerId)}:test`, {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  getModelRouteSettings(): Promise<ModelRouteSettings> {
    return this.request("/v1/settings/model-routes");
  }

  putModelRouteSettings(modelRoutes: ModelRoutes): Promise<ModelRouteSettings> {
    return this.request("/v1/settings/model-routes", {
      method: "PUT",
      body: JSON.stringify({ modelRoutes }),
    });
  }

  getModelSamplingSettings(): Promise<ModelSamplingSettings> {
    return this.request("/v1/settings/model-sampling");
  }

  putModelSamplingSettings(input: ModelSamplingSettingsInput): Promise<ModelSamplingSettings> {
    return this.request("/v1/settings/model-sampling", {
      method: "PUT",
      body: JSON.stringify(input),
    });
  }

  async getProject(projectId: string): Promise<Project> {
    const response = await this.request<ProjectResponse>(`/v1/projects/${encodeURIComponent(projectId)}`);
    return projectFromResponse(response);
  }

  getGoalSpecs(projectId: string): Promise<Page<GoalSpec>> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/goal/specs`);
  }

  sendGoal(project: Project, message: string): Promise<Project> {
    return this.request(`/v1/projects/${encodeURIComponent(project.id)}/goal/messages`, {
      method: "POST",
      headers: {
        "Idempotency-Key": idempotencyKey(),
        "If-Match": `"v${project.version}"`,
      },
      body: JSON.stringify({ expectedVersion: project.version, message }),
    });
  }

  approveGoal(project: Project, spec: GoalSpec): Promise<Project> {
    return this.request(
      `/v1/projects/${encodeURIComponent(project.id)}/goal/specs/${spec.content.version}:approve`,
      {
        method: "POST",
        headers: {
          "Idempotency-Key": idempotencyKey(),
          "If-Match": `"v${project.version}"`,
        },
        body: JSON.stringify({
          expectedVersion: project.version,
          sha256: spec.contentSha256,
          decision: "APPROVE",
        }),
      },
    );
  }

  getPlans(projectId: string): Promise<Page<PlanSpec>> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/plans`);
  }

  getTasks(projectId: string): Promise<Page<ModuleTask>> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/tasks`);
  }

  getAudits(projectId: string, taskId: string): Promise<Page<AuditRun>> {
    return this.request(
      `/v1/projects/${encodeURIComponent(projectId)}/tasks/${encodeURIComponent(taskId)}/audits`,
    );
  }

  getTaskDecisionReport(projectId: string, taskId: string): Promise<TaskDecisionReport> {
    return this.request(
      `/v1/projects/${encodeURIComponent(projectId)}/tasks/${encodeURIComponent(taskId)}/decision-report`,
    );
  }

  decideTask(task: Pick<ModuleTask, "projectId" | "id" | "version">, decision: TaskDecision): Promise<CommandAccepted> {
    return this.request(
      `/v1/projects/${encodeURIComponent(task.projectId)}/tasks/${encodeURIComponent(task.id)}/decisions`,
      {
        method: "POST",
        headers: {
          "Idempotency-Key": idempotencyKey(),
          "If-Match": `"v${task.version}"`,
        },
        body: JSON.stringify({ decision, expectedVersion: task.version }),
      },
    );
  }

  getResult(projectId: string): Promise<ProjectResult> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/result`);
  }

  getProjectActivity(projectId: string): Promise<ProjectActivitySnapshot> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/activity`);
  }

  sendProjectActivityMessage(project: Pick<Project, "id" | "version">, flow: ProjectActivityFlow, message: string, agentId = ""): Promise<ProjectActivityMessage> {
    return this.request(`/v1/projects/${encodeURIComponent(project.id)}/activity/messages`, {
      method: "POST",
      headers: {
        "Idempotency-Key": idempotencyKey(),
        "If-Match": `"v${project.version}"`,
      },
      body: JSON.stringify({ expectedVersion: project.version, flow, agentId, message }),
    });
  }

  subscribeProjectEvents(projectId: string, callbacks: {
    onOpen?: () => void;
    onEvent: (event: ProjectActivityMessage) => void;
    onClose?: () => void;
    onError?: (error: unknown) => void;
  }, after = ""): () => void {
    const controller = new AbortController();
    void this.reconnectProjectEvents(projectId, callbacks, after, controller.signal);
    return () => controller.abort();
  }

  private async reconnectProjectEvents(projectId: string, callbacks: {
    onOpen?: () => void;
    onEvent: (event: ProjectActivityMessage) => void;
    onClose?: () => void;
    onError?: (error: unknown) => void;
  }, after: string, signal: AbortSignal): Promise<void> {
    let cursor = after;
    let delay = eventStreamInitialRetryDelay;
    while (!signal.aborted) {
      let openedAt = 0;
      try {
        await this.consumeProjectEvents(projectId, {
          onOpen: () => {
            openedAt = Date.now();
            callbacks.onOpen?.();
          },
          onEvent: (event) => {
            cursor = event.cursor || cursor;
            callbacks.onEvent(event);
          },
        }, cursor, signal);
        if (signal.aborted) return;
        callbacks.onClose?.();
      } catch (cause) {
        if (signal.aborted) return;
        callbacks.onError?.(cause);
        if (cause instanceof ApiError && cause.status >= 400 && cause.status < 500 && cause.status !== 408 && cause.status !== 429 && !cause.retryable) return;
      }
      if (openedAt && Date.now() - openedAt >= eventStreamStableConnectionTime) delay = eventStreamInitialRetryDelay;
      await reconnectDelay(delay, signal);
      delay = Math.min(delay * 2, eventStreamMaximumRetryDelay);
    }
  }

  private async consumeProjectEvents(projectId: string, callbacks: {
    onOpen?: () => void;
    onEvent: (event: ProjectActivityMessage) => void;
  }, after: string, signal: AbortSignal): Promise<void> {
    const token = await this.token();
    const headers = new Headers({ Accept: "text/event-stream" });
    if (token) headers.set("Authorization", `Bearer ${token}`);
    if (after) headers.set("Last-Event-ID", after);
    const query = new URLSearchParams({ follow: "true" });
    if (after) query.set("after", after);
    const response = await fetch(`/v1/projects/${encodeURIComponent(projectId)}/activity/events?${query}`, { headers, cache: "no-store", signal });
    if (!response.ok) throw new ApiError(response.status, await parseProblem(response));
    if (!response.body) throw new Error("事件流不可用");
    callbacks.onOpen?.();
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (!signal.aborted) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const lines = frame.split("\n");
        const data = lines.filter((line) => line.startsWith("data:")).map((line) => line.slice(5).trimStart()).join("\n");
        if (data) {
          const event = JSON.parse(data) as ProjectActivityMessage;
          if (!event.cursor) {
            const id = lines.find((line) => line.startsWith("id:"))?.slice(3).trimStart();
            if (id) event.cursor = id;
          }
          callbacks.onEvent(event);
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
  }
}

function reconnectDelay(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = window.setTimeout(done, milliseconds);
    function done() {
      signal.removeEventListener("abort", done);
      window.clearTimeout(timer);
      resolve();
    }
    signal.addEventListener("abort", done, { once: true });
  });
}
