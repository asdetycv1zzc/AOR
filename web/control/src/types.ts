export type ProjectState =
  | "CREATED"
  | "GOAL_NEGOTIATING"
  | "GOAL_SUSPENDED"
  | "PLANNING"
  | "EXECUTING"
  | "INTEGRATING"
  | "GLOBAL_AUDIT"
  | "BLOCKED_USER_DECISION"
  | "PAUSED"
  | "COMPLETED"
  | "ABORTED"
  | "FAILED_SYSTEM"
  | "ARCHIVED";

export type DataClassification = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED";

export const modelRoles = [
  "GOAL_PROPOSER",
  "GOAL_CHALLENGER",
  "PLAN_SUPERVISOR",
  "MODULE_PLANNER",
  "EXECUTOR",
  "MODULE_AUDITOR",
  "GLOBAL_AUDITOR",
  "KNOWLEDGE_CURATOR",
] as const;

export type ModelRole = (typeof modelRoles)[number];

export interface ProjectModelRoute {
  provider: string;
  model: string;
  maxOutputTokens: number;
  temperature: number;
  seed?: number;
  providerPolicy: string;
  cachePolicy: string;
  worstCaseCostMicros: number;
  maxAttempts: number;
}

export type ModelRoutes = Record<ModelRole, ProjectModelRoute>;

export interface ModelProvider {
  id: string;
  provider: string;
  models: string[];
  reasoningEffort?: string;
  inputMicrosPerToken: number;
  outputMicrosPerToken: number;
  supportsStreaming: boolean;
  supportsToolCalls: boolean;
  supportsJsonSchema: boolean;
  supportsSeed: boolean;
  supportsPromptCaching: boolean;
  maxInputTokens: number;
  maxOutputTokens: number;
  allowedDataClassifications: string[];
  dataResidency: string[];
  retentionPolicy: string;
  modalities: string[];
}

export interface ModelProviderSettings {
  id: string;
  provider: string;
  displayName?: string;
  baseUrl: string;
  protocol: string;
  protocols?: string[];
  models: string[];
  apiKeyConfigured: boolean;
  enabled: boolean;
  version: number;
}

export interface ModelProviderSettingsPage {
  items: ModelProviderSettings[];
}

export interface ModelProviderSettingsInput {
  baseUrl: string;
  protocol: string;
  apiKey?: string;
  enabled: boolean;
}

export interface ModelProviderTestInput {
  baseUrl: string;
  protocol: string;
  apiKey?: string;
  model: string;
}

export interface ModelProviderTestResult {
  ok: boolean;
  model: string;
  latencyMs?: number;
  detail?: string;
}

export interface ModelRouteSettings {
  modelRoutes: ModelRoutes;
  version: number;
}

export type ReasoningEffort = "none" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max";

export interface ModelSamplingSettingsInput {
  temperature: number;
  topP: number;
  topK: number;
  reasoningEffort: ReasoningEffort;
}

export interface ModelSamplingSettings extends ModelSamplingSettingsInput {
  version: number;
}

export interface SpecReference {
  version: number;
  sha256: string;
}

export interface CoreModuleOutcome {
  taskId: string;
  moduleId: string;
  state: string;
  version: number;
  moduleSpecRef: SpecReference;
  attempt: number;
  attemptSeriesId: string;
}

export interface CoreSummary {
  summaryVersion: number;
  tenantId: string;
  projectId: string;
  status: "COMPLETED";
  goalSpecRef: SpecReference;
  planSpecRef: SpecReference;
  modules: CoreModuleOutcome[];
  summarySha256: string;
  createdAt: string;
}

export interface Project {
  tenantId: string;
  id: string;
  name: string;
  createdBy: string;
  dataClassification: DataClassification;
  deploymentTargets?: string[];
  budgetCurrency?: string;
  budgetHardLimitDollars?: number;
  budgetSoftLimitDollars?: number;
  promptBundleVersion?: string;
  riskTolerance: "LOW" | "MEDIUM" | "HIGH";
  state: ProjectState;
  version: number;
  goalAgentCount: 1 | 2;
  modelRoutes?: ModelRoutes;
  goal?: { id?: string; version?: number; sha256?: string };
  plan?: SpecReference;
  coreSummary?: CoreSummary;
}

export interface GoalCriterion {
  id: string;
  statement: string;
  evidenceType: string;
}

export interface GoalSpecContent {
  goalSpecVersion: number;
  projectId: string;
  version: number;
  title: string;
  summary: string;
  problemStatement: string;
  functionalRequirements: string[];
  constraints: string[];
  decisions: string[];
  unresolvedItems: string[];
  acceptanceCriteria: GoalCriterion[];
  riskTolerance: string;
  dataClassification: string;
  deploymentTargets: string[];
  createdAt: string;
}

export interface GoalSpec {
  content: GoalSpecContent;
  status: "DRAFT" | "APPROVED" | "SUPERSEDED" | "REJECTED";
  contentSha256: string;
  approvedBy?: { actorId: string; approvedAt: string };
}

export interface PlanModule {
  moduleId?: string;
  name?: string;
  summary?: string;
  responsibilities?: string[];
  [key: string]: unknown;
}

export interface PlanSpec {
  planSpecVersion?: number;
  projectId?: string;
  architecture?: string | Record<string, unknown>;
  modules?: PlanModule[];
  testStrategy?: unknown;
  sha256?: string;
  [key: string]: unknown;
}

export interface ModuleTask {
  tenantId: string;
  projectId: string;
  id: string;
  moduleId?: string;
  state: string;
  version: number;
  planningSpecRef?: SpecReference;
  moduleSpecRef: SpecReference;
  attemptSeriesId: string;
  attemptSeriesIds: string[];
  attempt: number;
  fencingToken: number;
  dependentTaskIds: string[];
  frozenDependentIds: string[];
  blockingTaskIds: string[];
  blockedFromState?: string;
}

export interface AuditFinding {
  id: string;
  stableFingerprint: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  category: string;
  ruleId: string;
  filePath?: string;
  lineStart?: number;
  lineEnd?: number;
  status: string;
  content: unknown;
  evidenceRefs: string[];
  createdAt: string;
}

export interface AuditRun {
  id: string;
  projectId: string;
  taskId: string;
  submissionId: string;
  phase: string;
  state: string;
  pipelineVersion: string;
  executionPlatform: string;
  isolationLevel: string;
  startedAt: string;
  completedAt?: string;
  verdict?: "PASS" | "FAIL" | "INCONCLUSIVE";
  evidenceBundleRef?: string;
  findings: AuditFinding[];
}

export interface PlanCompletionModule {
  taskId: string;
  moduleId: string;
  state: string;
  moduleSpecRef: SpecReference;
  attempt: number;
  attemptSeriesId: string;
  summary: string;
}

export interface PlanCompletionSummary {
  overview: string;
  modules: PlanCompletionModule[];
  crossModuleFindings: string[];
  recommendedNextActions: string[];
  createdAt: string;
  summarySha256: string;
}

export interface ProjectResult {
  status: "PENDING" | "SUMMARIZING" | "COMPLETED";
  coreSummary?: CoreSummary;
  planSupervisorSummary?: PlanCompletionSummary;
  artifactRef?: string;
}

export interface Page<T> {
  items: T[];
  nextCursor?: string;
}

export interface RecentProject {
  id: string;
  name: string;
  state: ProjectState;
  touchedAt: string;
}

export interface ProjectCreateInput {
  name: string;
  goalAgentCount: 1 | 2;
  dataClassification: Project["dataClassification"];
  deploymentTargets: string[];
  budget: {
    hardLimitDollars: number;
    softLimitDollars: number;
    currency: "USD";
  };
  modelRoutes?: ModelRoutes;
}
