import type {
  AuditRun,
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
  ProjectCreateInput,
  ProjectResult,
} from "./types";

interface ProblemResponse {
  detail?: string;
  title?: string;
  error?: { code?: string; message?: string; retryable?: boolean; correlationId?: string };
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
    if (init.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(path, { ...init, headers, cache: "no-store" });
    if (!response.ok) {
      throw new ApiError(response.status, await parseProblem(response));
    }
    return (await response.json()) as T;
  }

  createProject(input: ProjectCreateInput): Promise<Project> {
    return this.request("/v1/projects", {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify(input),
    });
  }

  getModelProviders(): Promise<Page<ModelProvider>> {
    return this.request("/v1/model-providers");
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

  getProject(projectId: string): Promise<Project> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}`);
  }

  getGoalSpecs(projectId: string): Promise<Page<GoalSpec>> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/goal/specs`);
  }

  sendGoal(project: Project, message: string): Promise<Project> {
    return this.request(`/v1/projects/${encodeURIComponent(project.id)}/goal/messages`, {
      method: "POST",
      headers: {
        "Idempotency-Key": crypto.randomUUID(),
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
          "Idempotency-Key": crypto.randomUUID(),
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

  getResult(projectId: string): Promise<ProjectResult> {
    return this.request(`/v1/projects/${encodeURIComponent(projectId)}/result`);
  }
}
