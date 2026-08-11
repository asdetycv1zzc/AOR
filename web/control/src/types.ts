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
  reasoningEffort: ReasoningEffort;
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
  custom: boolean;
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
  displayName?: string;
  protocol: string;
  apiKey?: string;
  models?: string[];
  enabled: boolean;
}

export interface ModelProviderTestInput {
  baseUrl: string;
  protocol: string;
  apiKey?: string;
  model: string;
  reasoningEffort: ReasoningEffort;
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

export type ReasoningEffort = "" | "none" | "low" | "medium" | "high" | "xhigh" | "max";

export interface ModelSamplingSettingsInput {
  temperature: number;
  topP: number;
  topK: number;
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
  goalProcessing: boolean;
  modelRoutes?: ModelRoutes;
  goal?: { id?: string; version?: number; sha256?: string };
  plan?: SpecReference;
  coreSummary?: CoreSummary;
}

export type ProjectActivityFlow = "GOAL" | "PLAN" | "EXECUTION" | "AUDIT" | "KNOWLEDGE";

export type ProjectActivityState = "QUEUED" | "STREAMING" | "COMPLETED" | "FAILED" | "IDLE" | "RUNNING";

export interface ProjectActivityAgent {
  id: string;
  role: string;
  flow: ProjectActivityFlow;
  state: ProjectActivityState;
  lastActiveAt: string;
}

export interface ProjectActivityMessage {
  id: string;
  cursor: string;
  projectId: string;
  taskId?: string;
  flow: ProjectActivityFlow;
  agentId?: string;
  role?: string;
  sender: "USER" | "AGENT" | "SYSTEM" | string;
  state: ProjectActivityState;
  content: string;
  reasoningSummary?: string;
  errorCode?: string;
  provider?: string;
  model?: string;
  inputTokens?: number;
  outputTokens?: number;
  latencyMs?: number;
  outputSha256?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface ProjectActivitySnapshot {
  projectId: string;
  projectVersion: number;
  goalProcessing: boolean;
  flows: ProjectActivityFlow[];
  agents: ProjectActivityAgent[];
  messages: ProjectActivityMessage[];
  cursor?: string;
}

export interface GoalCriterion {
  id: string;
  statement: string;
  evidenceType: string;
}

export interface ToolchainExecutable {
  name: string;
  path: string;
}

export interface ToolchainInventoryTool {
  schemaVersion: number;
  id: string;
  kind: string;
  name: string;
  version: string;
  platform: string;
  architecture: string;
  languages: string[];
  binDirs: string[];
  executables: ToolchainExecutable[];
}

export interface ToolchainInventory {
  tools: ToolchainInventoryTool[];
}

export interface GoalToolchainLanguage {
  name: string;
  version: string;
}

export interface GoalToolchainTool {
  inventoryId?: string;
  kind: string;
  name: string;
  version: string;
  platform: string;
  architecture: string;
  source: "INSTALLED" | "INSTALL_REQUIRED";
}

export interface GoalToolchain {
  languages: GoalToolchainLanguage[];
  tools: GoalToolchainTool[];
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
  toolchain?: GoalToolchain;
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
  budget: {
    hardLimitDollars: number;
    softLimitDollars: number;
    currency: "USD";
  };
  modelRoutes?: ModelRoutes;
}
