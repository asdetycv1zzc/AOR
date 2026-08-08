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
  dataClassification: "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED";
  deploymentTargets?: string[];
  budgetCurrency?: string;
  budgetHardLimitMinor?: number;
  budgetSoftLimitMinor?: number;
  promptBundleVersion?: string;
  riskTolerance: "LOW" | "MEDIUM" | "HIGH";
  state: ProjectState;
  version: number;
  goalAgentCount: 1 | 2;
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
    hardLimitMinor: number;
    softLimitMinor: number;
    currency: "USD";
  };
}
