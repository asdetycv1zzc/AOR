package state

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type Project struct {
	TenantID                string                       `json:"tenantId"`
	ID                      string                       `json:"id"`
	Name                    string                       `json:"name"`
	CreatedBy               string                       `json:"createdBy"`
	DataClassification      string                       `json:"dataClassification"`
	DeploymentTargets       []string                     `json:"deploymentTargets,omitempty"`
	BudgetCurrency          string                       `json:"budgetCurrency,omitempty"`
	BudgetHardLimitMinor    int64                        `json:"budgetHardLimitMinor,omitempty"`
	BudgetSoftLimitMinor    int64                        `json:"budgetSoftLimitMinor,omitempty"`
	PromptBundleVersion     string                       `json:"promptBundleVersion,omitempty"`
	RiskTolerance           string                       `json:"riskTolerance"`
	State                   contracts.ProjectState       `json:"state"`
	Version                 int64                        `json:"version"`
	GoalAgentCount          int                          `json:"goalAgentCount"`
	GoalProcessing          bool                         `json:"goalProcessing"`
	ModelRoutes             map[string]ProjectModelRoute `json:"modelRoutes,omitempty"`
	Goal                    *GoalRecord                  `json:"goal,omitempty"`
	Plan                    *contracts.SpecRef           `json:"plan,omitempty"`
	CoreSummary             *CoreSummary                 `json:"coreSummary,omitempty"`
	ReleaseApprovalRecordID string                       `json:"releaseApprovalRecordId,omitempty"`
	PausedFromState         contracts.ProjectState       `json:"pausedFromState,omitempty"`
	Deletion                *ProjectDeletion             `json:"deletion,omitempty"`
	LegalHolds              []ProjectLegalHold           `json:"legalHolds,omitempty"`
}

type ProjectModelRoute struct {
	Provider            string  `json:"provider"`
	Model               string  `json:"model"`
	ReasoningEffort     string  `json:"reasoningEffort"`
	MaxOutputTokens     int     `json:"maxOutputTokens"`
	ThinkingBudget      int     `json:"thinkingBudget"`
	Temperature         float64 `json:"temperature"`
	Seed                *int64  `json:"seed,omitempty"`
	ProviderPolicy      string  `json:"providerPolicy"`
	CachePolicy         string  `json:"cachePolicy"`
	WorstCaseCostMicros int64   `json:"worstCaseCostMicros"`
	MaxAttempts         int     `json:"maxAttempts"`
}

var requiredProjectModelRoles = [...]string{
	"GOAL_PROPOSER",
	"GOAL_CHALLENGER",
	"PLAN_SUPERVISOR",
	"MODULE_PLANNER",
	"EXECUTOR",
	"MODULE_AUDITOR",
	"GLOBAL_AUDITOR",
	"KNOWLEDGE_CURATOR",
}

func ValidateProjectModelRoutes(routes map[string]ProjectModelRoute) error {
	if len(routes) != len(requiredProjectModelRoles) {
		return fmt.Errorf("project model routes must define all roles")
	}
	for _, role := range requiredProjectModelRoles {
		route, found := routes[role]
		if !found || !validProjectModelRoute(route) {
			return fmt.Errorf("invalid project model route for %s", role)
		}
	}
	return nil
}

func validProjectModelRoute(route ProjectModelRoute) bool {
	return validProjectModelIdentity(route.Provider, 128) && validProjectModelIdentity(route.Model, 256) && route.Model != "*" &&
		ValidModelReasoningEffort(route.Provider, route.ReasoningEffort) &&
		route.MaxOutputTokens >= 1 && route.MaxOutputTokens <= 1_000_000 &&
		route.ThinkingBudget >= 0 && route.ThinkingBudget < route.MaxOutputTokens &&
		!math.IsNaN(route.Temperature) && !math.IsInf(route.Temperature, 0) && route.Temperature >= 0 && route.Temperature <= 2 &&
		validProjectModelIdentity(route.ProviderPolicy, 256) && validProjectModelIdentity(route.CachePolicy, 128) &&
		route.WorstCaseCostMicros >= 0 && route.MaxAttempts >= 1 && route.MaxAttempts <= 5
}

func ValidModelReasoningEffort(provider, effort string) bool {
	switch strings.ToLower(provider) {
	case "openai", "openai-primary":
		return effort == "none" || effort == "low" || effort == "medium" || effort == "high" || effort == "xhigh" || effort == "max"
	case "claude":
		return effort == "low" || effort == "medium" || effort == "high" || effort == "xhigh" || effort == "max"
	case "deepseek", "deepseek-audit":
		return effort == "high" || effort == "max"
	case "grok":
		return effort == ""
	default:
		return effort == "" || effort == "none" || effort == "low" || effort == "medium" || effort == "high" || effort == "xhigh" || effort == "max"
	}
}

func DefaultModelReasoningEffort(provider string) string {
	switch strings.ToLower(provider) {
	case "openai", "openai-primary", "claude":
		return "medium"
	case "deepseek", "deepseek-audit":
		return "high"
	default:
		return ""
	}
}

func validProjectModelIdentity(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

type CoreSummary struct {
	SummaryVersion int                 `json:"summaryVersion"`
	TenantID       string              `json:"tenantId"`
	ProjectID      string              `json:"projectId"`
	Status         string              `json:"status"`
	GoalSpecRef    contracts.SpecRef   `json:"goalSpecRef"`
	PlanSpecRef    contracts.SpecRef   `json:"planSpecRef"`
	Modules        []CoreModuleOutcome `json:"modules"`
	SummarySHA256  string              `json:"summarySha256"`
	CreatedAt      time.Time           `json:"createdAt"`
}

type CoreModuleOutcome struct {
	TaskID          string                    `json:"taskId"`
	ModuleID        string                    `json:"moduleId"`
	State           contracts.ModuleTaskState `json:"state"`
	Version         int64                     `json:"version"`
	ModuleSpecRef   contracts.SpecRef         `json:"moduleSpecRef"`
	Attempt         int                       `json:"attempt"`
	AttemptSeriesID string                    `json:"attemptSeriesId"`
}

func (summary CoreSummary) validFor(project Project) bool {
	if summary.SummaryVersion != 1 || summary.TenantID != project.TenantID || summary.ProjectID != project.ID || summary.Status != "COMPLETED" || project.Goal == nil || project.Plan == nil || summary.GoalSpecRef != (contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}) || summary.PlanSpecRef != *project.Plan || !validDigest(summary.SummarySHA256) || summary.CreatedAt.IsZero() || len(summary.Modules) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(summary.Modules))
	for _, module := range summary.Modules {
		if module.TaskID == "" || module.ModuleID == "" || module.State != contracts.TaskPassed || module.Version < 1 || module.Attempt < 1 || module.Attempt > 3 || module.AttemptSeriesID == "" || module.ModuleSpecRef.Validate() != nil {
			return false
		}
		if _, duplicate := seen[module.TaskID]; duplicate {
			return false
		}
		seen[module.TaskID] = struct{}{}
	}
	return true
}

type ProjectDeletionStatus string

const (
	ProjectDeletionBlocked   ProjectDeletionStatus = "BLOCKED_LEGAL_HOLD"
	ProjectDeletionReady     ProjectDeletionStatus = "READY"
	ProjectDeletionErasing   ProjectDeletionStatus = "ERASING"
	ProjectDeletionCompleted ProjectDeletionStatus = "COMPLETED"
)

// ProjectDeletion contains only lifecycle metadata. A completed record is the
// content-free proof index retained after project data has been erased.
type ProjectDeletion struct {
	ID                  string                `json:"id"`
	Status              ProjectDeletionStatus `json:"status"`
	RequestedBy         string                `json:"requestedBy"`
	RequestedAt         time.Time             `json:"requestedAt"`
	EarliestExecutionAt time.Time             `json:"earliestExecutionAt"`
	StartedAt           *time.Time            `json:"startedAt,omitempty"`
	CompletedAt         *time.Time            `json:"completedAt,omitempty"`
	ProofSHA256         string                `json:"proofSha256,omitempty"`
	ProofArtifactURI    string                `json:"proofArtifactUri,omitempty"`
	BackupExpiresAt     *time.Time            `json:"backupExpiresAt,omitempty"`
}

type ProjectLegalHold struct {
	ID            string     `json:"id"`
	Reason        string     `json:"reason"`
	PlacedBy      string     `json:"placedBy"`
	PlacedAt      time.Time  `json:"placedAt"`
	ReleasedBy    string     `json:"releasedBy,omitempty"`
	ReleasedAt    *time.Time `json:"releasedAt,omitempty"`
	ReleaseReason string     `json:"releaseReason,omitempty"`
}

type GoalRecord struct {
	ID               string               `json:"id"`
	Version          int                  `json:"version"`
	SHA256           string               `json:"sha256"`
	UnresolvedItems  []string             `json:"unresolvedItems"`
	Status           contracts.GoalStatus `json:"status"`
	ApprovedBy       string               `json:"approvedBy,omitempty"`
	ApprovalRecordID string               `json:"approvalRecordId,omitempty"`
}

type GoalMessageKind string

const (
	GoalMessageUser          GoalMessageKind = "USER"
	GoalMessageRejection     GoalMessageKind = "REJECTION"
	GoalMessageChangeRequest GoalMessageKind = "CHANGE_REQUEST"
)

// GoalMessage is an immutable, content-addressed user input artifact.
type GoalMessage struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenantId"`
	ProjectID     string          `json:"projectId"`
	Kind          GoalMessageKind `json:"kind"`
	Message       string          `json:"message"`
	ContentSHA256 string          `json:"contentSha256"`
	ArtifactURI   string          `json:"artifactUri"`
	CreatedAt     time.Time       `json:"createdAt"`
	CreatedBy     string          `json:"createdBy"`
}

type CompletionFacts struct {
	AllTasksIntegrated             bool   `json:"allTasksIntegrated"`
	AllIntegrationTasksDone        bool   `json:"allIntegrationTasksDone"`
	IntegrationAuditPassed         bool   `json:"integrationAuditPassed"`
	GoalCriteriaSatisfied          bool   `json:"goalCriteriaSatisfied"`
	GlobalAuditPassed              bool   `json:"globalAuditPassed"`
	ReleaseGatesPassed             bool   `json:"releaseGatesPassed"`
	ReleaseArtifactsSigned         bool   `json:"releaseArtifactsSigned"`
	SBOMGenerated                  bool   `json:"sbomGenerated"`
	ProvenanceGenerated            bool   `json:"provenanceGenerated"`
	NoBlockedOrRework              bool   `json:"noBlockedOrRework"`
	NoBlockingFindings             bool   `json:"noBlockingFindings"`
	RiskAcceptancesValid           bool   `json:"riskAcceptancesValid"`
	OperationalSummariesGenerated  bool   `json:"operationalSummariesGenerated"`
	PlanSupervisorSummaryGenerated bool   `json:"planSupervisorSummaryGenerated"`
	GoalSummaryVerified            bool   `json:"goalSummaryVerified"`
	FinalResultDelivered           bool   `json:"finalResultDelivered"`
	EvidenceSHA256                 string `json:"evidenceSha256"`
}

type ProjectGuardFacts struct {
	AllTasksPassed         bool   `json:"allTasksPassed"`
	AllTasksIntegrated     bool   `json:"allTasksIntegrated"`
	IntegrationAuditPassed bool   `json:"integrationAuditPassed"`
	EvidenceSHA256         string `json:"evidenceSha256"`
}

type ProjectCommandType string

const (
	ProjectCommandCreate               ProjectCommandType = "CREATE_PROJECT"
	ProjectCommandStartGoalNegotiation ProjectCommandType = "START_GOAL_NEGOTIATION"
	ProjectCommandResumeToolchainGoal  ProjectCommandType = "RESUME_TOOLCHAIN_GOAL"
	ProjectCommandSubmitGoalMessage    ProjectCommandType = "SUBMIT_GOAL_MESSAGE"
	ProjectCommandProposeGoal          ProjectCommandType = "PROPOSE_GOAL"
	ProjectCommandApproveGoal          ProjectCommandType = "APPROVE_GOAL"
	ProjectCommandRejectGoal           ProjectCommandType = "REJECT_GOAL"
	ProjectCommandRequestGoalChange    ProjectCommandType = "REQUEST_GOAL_CHANGE"
	ProjectCommandSupersedeGoal        ProjectCommandType = "SUPERSEDE_GOAL"
	ProjectCommandPublishPlan          ProjectCommandType = "PUBLISH_PLAN"
	ProjectCommandRecordCoreProgress   ProjectCommandType = "RECORD_CORE_PROGRESS"
	ProjectCommandPublishCoreSummary   ProjectCommandType = "PUBLISH_CORE_SUMMARY"
	ProjectCommandBeginIntegration     ProjectCommandType = "BEGIN_INTEGRATION"
	ProjectCommandBeginGlobalAudit     ProjectCommandType = "BEGIN_GLOBAL_AUDIT"
	ProjectCommandReopenExecution      ProjectCommandType = "REOPEN_EXECUTION"
	ProjectCommandReopenIntegration    ProjectCommandType = "REOPEN_INTEGRATION"
	ProjectCommandApproveRelease       ProjectCommandType = "APPROVE_RELEASE"
	ProjectCommandComplete             ProjectCommandType = "COMPLETE_PROJECT"
	ProjectCommandPause                ProjectCommandType = "PAUSE_PROJECT"
	ProjectCommandResume               ProjectCommandType = "RESUME_PROJECT"
	ProjectCommandAbort                ProjectCommandType = "ABORT_PROJECT"
	ProjectCommandArchive              ProjectCommandType = "ARCHIVE_PROJECT"
	ProjectCommandRequestDeletion      ProjectCommandType = "REQUEST_PROJECT_DELETION"
	ProjectCommandPlaceLegalHold       ProjectCommandType = "PLACE_PROJECT_LEGAL_HOLD"
	ProjectCommandReleaseLegalHold     ProjectCommandType = "RELEASE_PROJECT_LEGAL_HOLD"
	ProjectCommandBeginDeletion        ProjectCommandType = "BEGIN_PROJECT_DELETION"
	ProjectCommandCompleteDeletion     ProjectCommandType = "COMPLETE_PROJECT_DELETION"
)

type ProjectCommand struct {
	Type                 ProjectCommandType
	TenantID             string
	ProjectID            string
	ActorID              string
	GoalAgentCount       int
	AsyncGoalProcessing  bool
	StartGoalNegotiation bool
	Goal                 *GoalRecord
	GoalSpec             *contracts.GoalSpec
	GoalMessage          *GoalMessage
	Plan                 *contracts.SpecRef
	CoreSummary          *CoreSummary
	GoalSpecRef          *contracts.SpecRef
	DAG                  map[string][]string
	Approval             *ApprovalBinding
	Completion           *CompletionFacts
	Guard                *ProjectGuardFacts
	ImpactedTaskIDs      []string
	Name                 string
	DataClassification   string
	DeploymentTargets    []string
	BudgetCurrency       string
	BudgetHardLimitMinor int64
	BudgetSoftLimitMinor int64
	PromptBundleVersion  string
	RiskTolerance        string
	ModelRoutes          map[string]ProjectModelRoute
	Deletion             *ProjectDeletion
	LegalHold            *ProjectLegalHold
	LegalHoldID          string
	ReleaseReason        string
	At                   time.Time
}

type ProjectEvent struct {
	Type             string    `json:"type"`
	AggregateVersion int64     `json:"aggregateVersion"`
	OccurredAt       time.Time `json:"occurredAt"`
	Projection       Project   `json:"projection"`
}

func DecideProject(current Project, command ProjectCommand) (ProjectEvent, *aorerrors.Error) {
	if command.At.IsZero() || command.ActorID == "" {
		return ProjectEvent{}, invalidProject(command, "actor and trusted time are required")
	}
	next := cloneProject(current)
	eventType := ""
	if current.Deletion != nil && current.Deletion.Status != ProjectDeletionCompleted && !projectLifecycleCommand(command.Type) {
		return ProjectEvent{}, transitionProject(command, current.State)
	}
	switch command.Type {
	case ProjectCommandCreate:
		if current.Version != 0 || current.ID != "" || command.TenantID == "" || command.ProjectID == "" || command.GoalAgentCount < 1 || command.GoalAgentCount > 2 || command.ModelRoutes != nil && ValidateProjectModelRoutes(command.ModelRoutes) != nil {
			return ProjectEvent{}, invalidProject(command, "project creation guard")
		}
		name := command.Name
		if name == "" {
			name = command.ProjectID
		}
		dataClassification := command.DataClassification
		if dataClassification == "" {
			dataClassification = "INTERNAL"
		}
		riskTolerance := command.RiskTolerance
		if riskTolerance == "" {
			riskTolerance = "MEDIUM"
		}
		if command.BudgetCurrency == "" {
			command.BudgetCurrency = "USD"
		}
		if command.BudgetHardLimitMinor < 0 || command.BudgetSoftLimitMinor < 0 || command.BudgetSoftLimitMinor > command.BudgetHardLimitMinor || !validProjectCurrency(command.BudgetCurrency) || command.StartGoalNegotiation && command.PromptBundleVersion == "" {
			return ProjectEvent{}, invalidProject(command, "project budget")
		}
		deploymentTargets := append([]string(nil), command.DeploymentTargets...)
		if len(deploymentTargets) != 0 {
			seenTargets := make(map[string]struct{}, len(deploymentTargets))
			for _, target := range deploymentTargets {
				_, duplicate := seenTargets[target]
				if target == "" || len(target) > 128 || strings.TrimSpace(target) != target || strings.ContainsAny(target, "\r\n\x00") || duplicate {
					return ProjectEvent{}, invalidProject(command, "deployment target")
				}
				seenTargets[target] = struct{}{}
			}
		}
		stateValue := contracts.ProjectCreated
		if command.StartGoalNegotiation {
			stateValue = contracts.ProjectGoalNegotiating
			eventType = "io.aor.goal.negotiation-started.v1"
		} else {
			eventType = "io.aor.project.created.v1"
		}
		next = Project{TenantID: command.TenantID, ID: command.ProjectID, Name: name, CreatedBy: command.ActorID, DataClassification: dataClassification, DeploymentTargets: deploymentTargets, BudgetCurrency: command.BudgetCurrency, BudgetHardLimitMinor: command.BudgetHardLimitMinor, BudgetSoftLimitMinor: command.BudgetSoftLimitMinor, PromptBundleVersion: command.PromptBundleVersion, RiskTolerance: riskTolerance, State: stateValue, GoalAgentCount: command.GoalAgentCount, ModelRoutes: cloneProjectModelRoutes(command.ModelRoutes)}
	case ProjectCommandStartGoalNegotiation:
		if current.State != contracts.ProjectCreated {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectGoalNegotiating
		eventType = "io.aor.goal.negotiation-started.v1"
	case ProjectCommandResumeToolchainGoal:
		if current.State != contracts.ProjectGoalNegotiating || current.GoalProcessing || current.Goal == nil || command.Goal == nil ||
			current.Goal.ID != command.Goal.ID || current.Goal.Version != command.Goal.Version || current.Goal.SHA256 != command.Goal.SHA256 || current.Goal.ApprovedBy != "" {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.GoalProcessing = true
		eventType = "io.aor.goal.toolchain-ready.v1"
	case ProjectCommandSubmitGoalMessage:
		if current.State != contracts.ProjectCreated && current.State != contracts.ProjectGoalNegotiating && current.State != contracts.ProjectGoalSuspended {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.GoalProcessing {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "goal processing"})
		}
		if !validGoalMessage(command.GoalMessage, current, command) {
			return ProjectEvent{}, invalidProject(command, "goal message artifact")
		}
		next.State = contracts.ProjectGoalNegotiating
		next.GoalProcessing = command.AsyncGoalProcessing
		eventType = "io.aor.goal.message-received.v1"
	case ProjectCommandProposeGoal:
		if current.State != contracts.ProjectGoalNegotiating || command.Goal == nil || command.Goal.ID == "" || command.Goal.Version < 1 || command.Goal.SHA256 == "" {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.Goal != nil && command.Goal.Version <= current.Goal.Version {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeSpecSuperseded, "", nil)
		}
		goal := *command.Goal
		goal.UnresolvedItems = append([]string(nil), command.Goal.UnresolvedItems...)
		goal.Status = contracts.GoalDraft
		goal.ApprovedBy = ""
		goal.ApprovalRecordID = ""
		next.Goal = &goal
		next.GoalProcessing = false
		eventType = "io.aor.goal.proposed.v1"
	case ProjectCommandApproveGoal:
		if current.State != contracts.ProjectGoalNegotiating || current.Goal == nil || command.Goal == nil || command.Approval == nil {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.Goal.ID != command.Goal.ID || current.Goal.Version != command.Goal.Version || current.Goal.SHA256 != command.Goal.SHA256 {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil)
		}
		if len(current.Goal.UnresolvedItems) != 0 || len(command.Goal.UnresolvedItems) != 0 {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeGoalNotApproved, "", nil)
		}
		if !command.Approval.validAt(command.At, command.ActorID, "GOAL_APPROVAL", "GOAL_SPEC", current.Goal.ID, current.Goal.Version, current.Goal.SHA256) {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
		}
		next.Goal.ApprovedBy = command.ActorID
		next.Goal.ApprovalRecordID = command.Approval.RecordID
		next.Goal.Status = contracts.GoalApproved
		next.State = contracts.ProjectPlanning
		eventType = "io.aor.goal.approved.v1"
	case ProjectCommandRejectGoal:
		if current.State != contracts.ProjectGoalNegotiating || current.Goal == nil || command.Goal == nil || current.Goal.ApprovedBy != "" {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.Goal.ID != command.Goal.ID || current.Goal.Version != command.Goal.Version || current.Goal.SHA256 != command.Goal.SHA256 {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil)
		}
		if command.GoalMessage != nil && !validGoalMessage(command.GoalMessage, current, command) {
			return ProjectEvent{}, invalidProject(command, "goal rejection message artifact")
		}
		next.Goal.Status = contracts.GoalRejected
		eventType = "io.aor.goal.rejected.v1"
	case ProjectCommandRequestGoalChange:
		if !goalChangeAllowedState(current.State) || current.Goal == nil || current.Goal.ApprovedBy == "" || command.Goal == nil {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.Goal.ID != command.Goal.ID || current.Goal.Version != command.Goal.Version || current.Goal.SHA256 != command.Goal.SHA256 {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil)
		}
		if hasDuplicateStrings(command.ImpactedTaskIDs) || !validGoalMessage(command.GoalMessage, current, command) {
			return ProjectEvent{}, invalidProject(command, "goal change request")
		}
		next.Goal.Status = contracts.GoalSuperseded
		next.Plan = nil
		next.CoreSummary = nil
		next.ReleaseApprovalRecordID = ""
		next.State = contracts.ProjectGoalNegotiating
		eventType = "io.aor.goal.change-requested.v1"
	case ProjectCommandSupersedeGoal:
		if terminalProjectState(current.State) || current.Goal == nil || current.Goal.ApprovedBy == "" || command.Goal == nil || command.Goal.Version <= current.Goal.Version || command.Goal.SHA256 == "" {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if hasDuplicateStrings(command.ImpactedTaskIDs) {
			return ProjectEvent{}, invalidProject(command, "duplicate impacted task")
		}
		goal := *command.Goal
		goal.UnresolvedItems = append([]string(nil), command.Goal.UnresolvedItems...)
		goal.Status = contracts.GoalDraft
		goal.ApprovedBy = ""
		goal.ApprovalRecordID = ""
		next.Goal = &goal
		next.GoalProcessing = false
		next.Plan = nil
		next.CoreSummary = nil
		next.ReleaseApprovalRecordID = ""
		next.State = contracts.ProjectGoalNegotiating
		eventType = "io.aor.goal.superseded.v1"
	case ProjectCommandPublishPlan:
		if current.State != contracts.ProjectPlanning || current.Goal == nil || current.Goal.ApprovedBy == "" || command.Plan == nil || command.GoalSpecRef == nil {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if !ValidateDAG(command.DAG) {
			return ProjectEvent{}, invalidProject(command, "plan dependency graph is not a DAG")
		}
		if command.GoalSpecRef.Version != current.Goal.Version || command.GoalSpecRef.SHA256 != current.Goal.SHA256 {
			return ProjectEvent{}, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil)
		}
		if err := command.Plan.Validate(); err != nil {
			return ProjectEvent{}, invalidProject(command, err.Error())
		}
		plan := *command.Plan
		next.Plan = &plan
		next.CoreSummary = nil
		next.State = contracts.ProjectExecuting
		eventType = "io.aor.plan.published.v1"
	case ProjectCommandRecordCoreProgress:
		if current.State != contracts.ProjectExecuting || current.CoreSummary != nil {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		eventType = "io.aor.plan.core-progress-recorded.v1"
	case ProjectCommandPublishCoreSummary:
		if current.State != contracts.ProjectExecuting || current.CoreSummary != nil || command.CoreSummary == nil || !command.CoreSummary.validFor(current) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.CoreSummary = cloneCoreSummary(command.CoreSummary)
		eventType = "io.aor.plan.core-summary-published.v1"
	case ProjectCommandBeginIntegration:
		if current.State != contracts.ProjectExecuting || command.Guard == nil || !command.Guard.AllTasksPassed || !validDigest(command.Guard.EvidenceSHA256) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectIntegrating
		eventType = "io.aor.project.integration-started.v1"
	case ProjectCommandBeginGlobalAudit:
		if current.State != contracts.ProjectIntegrating || command.Guard == nil || !command.Guard.AllTasksIntegrated || !command.Guard.IntegrationAuditPassed || !validDigest(command.Guard.EvidenceSHA256) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectGlobalAudit
		eventType = "io.aor.project.global-audit-started.v1"
	case ProjectCommandReopenExecution:
		if current.State != contracts.ProjectGlobalAudit || command.Guard == nil || !validDigest(command.Guard.EvidenceSHA256) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectExecuting
		next.ReleaseApprovalRecordID = ""
		eventType = "io.aor.project.global-audit-remediation-started.v1"
	case ProjectCommandReopenIntegration:
		if current.State != contracts.ProjectGlobalAudit || command.Guard == nil || !validDigest(command.Guard.EvidenceSHA256) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectIntegrating
		next.ReleaseApprovalRecordID = ""
		eventType = "io.aor.project.global-audit-remediation-started.v1"
	case ProjectCommandApproveRelease:
		if current.State != contracts.ProjectGlobalAudit || current.Plan == nil || command.Approval == nil || !command.Approval.validAt(command.At, command.ActorID, "RELEASE_APPROVAL", "PROJECT", current.ID, int(current.Version), current.Plan.SHA256) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.ReleaseApprovalRecordID = command.Approval.RecordID
		eventType = "io.aor.approval.committed.v1"
	case ProjectCommandComplete:
		if current.State != contracts.ProjectGlobalAudit || current.Goal == nil || current.Goal.Status != contracts.GoalApproved || current.Goal.ApprovedBy == "" || current.Goal.ApprovalRecordID == "" || current.Plan == nil || current.ReleaseApprovalRecordID == "" || command.Completion == nil || !command.Completion.allSatisfied() {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectCompleted
		eventType = "io.aor.project.completed.v1"
	case ProjectCommandPause:
		if terminalProjectState(current.State) || current.State == contracts.ProjectPaused {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.PausedFromState = current.State
		if current.State == contracts.ProjectGoalNegotiating {
			next.State = contracts.ProjectGoalSuspended
		} else {
			next.State = contracts.ProjectPaused
		}
		next.GoalProcessing = false
		eventType = "io.aor.project.paused.v1"
	case ProjectCommandResume:
		if current.State != contracts.ProjectPaused && current.State != contracts.ProjectGoalSuspended {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		if current.State == contracts.ProjectGoalSuspended {
			next.State = contracts.ProjectGoalNegotiating
		} else if current.PausedFromState != "" {
			next.State = current.PausedFromState
		} else if current.Goal == nil || current.Goal.ApprovedBy == "" {
			next.State = contracts.ProjectGoalNegotiating
		} else if current.Plan == nil {
			next.State = contracts.ProjectPlanning
		} else {
			next.State = contracts.ProjectExecuting
		}
		next.PausedFromState = ""
		eventType = "io.aor.project.resumed.v1"
	case ProjectCommandAbort:
		if terminalProjectState(current.State) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectAborted
		eventType = "io.aor.project.aborted.v1"
	case ProjectCommandArchive:
		if current.State != contracts.ProjectCompleted && current.State != contracts.ProjectAborted {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		next.State = contracts.ProjectArchived
		eventType = "io.aor.project.archived.v1"
	case ProjectCommandRequestDeletion:
		if current.ID == "" || current.Deletion != nil || command.Deletion == nil || !validDeletionRequest(command.Deletion, command) {
			return ProjectEvent{}, invalidProject(command, "deletion request")
		}
		deletion := *command.Deletion
		deletion.Status = ProjectDeletionReady
		if hasActiveLegalHold(current.LegalHolds) {
			deletion.Status = ProjectDeletionBlocked
		}
		next.Deletion = &deletion
		if !terminalProjectState(current.State) {
			next.PausedFromState = current.State
			next.State = contracts.ProjectPaused
		} else if current.State != contracts.ProjectArchived {
			next.State = contracts.ProjectArchived
		}
		eventType = "io.aor.project.deletion-requested.v1"
	case ProjectCommandPlaceLegalHold:
		if current.ID == "" || command.LegalHold == nil || !validLegalHold(command.LegalHold, command) || legalHoldIndex(current.LegalHolds, command.LegalHold.ID) >= 0 {
			return ProjectEvent{}, invalidProject(command, "legal hold")
		}
		hold := *command.LegalHold
		next.LegalHolds = append(next.LegalHolds, hold)
		if next.Deletion != nil && next.Deletion.Status == ProjectDeletionReady {
			next.Deletion.Status = ProjectDeletionBlocked
		}
		eventType = "io.aor.project.legal-hold-placed.v1"
	case ProjectCommandReleaseLegalHold:
		index := legalHoldIndex(current.LegalHolds, command.LegalHoldID)
		if index < 0 || current.LegalHolds[index].ReleasedAt != nil || !safeLifecycleText(command.ReleaseReason, 1024) {
			return ProjectEvent{}, invalidProject(command, "legal hold release")
		}
		releasedAt := command.At.UTC()
		next.LegalHolds[index].ReleasedAt = &releasedAt
		next.LegalHolds[index].ReleasedBy = command.ActorID
		next.LegalHolds[index].ReleaseReason = command.ReleaseReason
		if next.Deletion != nil && next.Deletion.Status == ProjectDeletionBlocked && !hasActiveLegalHold(next.LegalHolds) {
			next.Deletion.Status = ProjectDeletionReady
		}
		eventType = "io.aor.project.legal-hold-released.v1"
	case ProjectCommandBeginDeletion:
		if current.Deletion == nil || current.Deletion.Status != ProjectDeletionReady || hasActiveLegalHold(current.LegalHolds) || command.At.Before(current.Deletion.EarliestExecutionAt) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		startedAt := command.At.UTC()
		next.Deletion.Status = ProjectDeletionErasing
		next.Deletion.StartedAt = &startedAt
		eventType = "io.aor.project.deletion-started.v1"
	case ProjectCommandCompleteDeletion:
		if current.Deletion == nil || current.Deletion.Status != ProjectDeletionErasing || command.Deletion == nil || !validDeletionCompletion(command.Deletion, command.At) {
			return ProjectEvent{}, transitionProject(command, current.State)
		}
		completedAt := command.At.UTC()
		next.Deletion.Status = ProjectDeletionCompleted
		next.Deletion.CompletedAt = &completedAt
		next.Deletion.ProofSHA256 = command.Deletion.ProofSHA256
		next.Deletion.ProofArtifactURI = command.Deletion.ProofArtifactURI
		if command.Deletion.BackupExpiresAt != nil {
			value := command.Deletion.BackupExpiresAt.UTC()
			next.Deletion.BackupExpiresAt = &value
		}
		next.State = contracts.ProjectArchived
		next.PausedFromState = ""
		next.Goal = nil
		next.Plan = nil
		next.DeploymentTargets = nil
		next.ModelRoutes = nil
		next.PromptBundleVersion = ""
		next.ReleaseApprovalRecordID = ""
		eventType = "io.aor.project.deletion-completed.v1"
	default:
		return ProjectEvent{}, invalidProject(command, "unknown command")
	}
	next.Version = current.Version + 1
	return ProjectEvent{Type: eventType, AggregateVersion: next.Version, OccurredAt: command.At.UTC(), Projection: next}, nil
}

func ValidateDAG(graph map[string][]string) bool {
	if len(graph) == 0 {
		return false
	}
	indegree := make(map[string]int, len(graph))
	reverse := make(map[string][]string, len(graph))
	for node := range graph {
		indegree[node] = 0
	}
	for node, dependencies := range graph {
		seen := make(map[string]bool, len(dependencies))
		for _, dependency := range dependencies {
			if dependency == node || seen[dependency] {
				return false
			}
			if _, exists := graph[dependency]; !exists {
				return false
			}
			seen[dependency] = true
			indegree[node]++
			reverse[dependency] = append(reverse[dependency], node)
		}
	}
	queue := make([]string, 0, len(graph))
	for node, degree := range indegree {
		if degree == 0 {
			queue = append(queue, node)
		}
	}
	visited := 0
	for len(queue) != 0 {
		node := queue[0]
		queue = queue[1:]
		visited++
		for _, dependent := range reverse[node] {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				queue = append(queue, dependent)
			}
		}
	}
	return visited == len(graph)
}

func hasDuplicateStrings(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

func validGoalMessage(message *GoalMessage, current Project, command ProjectCommand) bool {
	if message == nil || message.ID == "" || message.TenantID != current.TenantID || message.ProjectID != current.ID || message.CreatedBy != command.ActorID || message.CreatedAt.IsZero() || !message.CreatedAt.Equal(command.At) || message.Message == "" || message.ContentSHA256 == "" || message.ArtifactURI == "" {
		return false
	}
	switch message.Kind {
	case GoalMessageUser, GoalMessageRejection, GoalMessageChangeRequest:
		return validDigest(message.ContentSHA256) && message.ArtifactURI == "artifact://sha256/"+message.ContentSHA256[len("sha256:"):]
	default:
		return false
	}
}

func ApplyProject(current Project, event ProjectEvent) (Project, error) {
	if event.AggregateVersion != current.Version+1 || event.Projection.Version != event.AggregateVersion || event.Projection.ID == "" || event.OccurredAt.IsZero() {
		return Project{}, fmt.Errorf("project event version or projection is invalid")
	}
	return cloneProject(event.Projection), nil
}

func cloneProject(project Project) Project {
	next := project
	next.DeploymentTargets = append([]string(nil), project.DeploymentTargets...)
	next.ModelRoutes = cloneProjectModelRoutes(project.ModelRoutes)
	if project.Goal != nil {
		goal := *project.Goal
		goal.UnresolvedItems = append([]string(nil), project.Goal.UnresolvedItems...)
		next.Goal = &goal
	}
	if project.Plan != nil {
		plan := *project.Plan
		next.Plan = &plan
	}
	if project.CoreSummary != nil {
		next.CoreSummary = cloneCoreSummary(project.CoreSummary)
	}
	if project.Deletion != nil {
		deletion := *project.Deletion
		deletion.StartedAt = cloneTimePointer(project.Deletion.StartedAt)
		deletion.CompletedAt = cloneTimePointer(project.Deletion.CompletedAt)
		deletion.BackupExpiresAt = cloneTimePointer(project.Deletion.BackupExpiresAt)
		next.Deletion = &deletion
	}
	next.LegalHolds = append([]ProjectLegalHold(nil), project.LegalHolds...)
	for index := range next.LegalHolds {
		next.LegalHolds[index].ReleasedAt = cloneTimePointer(next.LegalHolds[index].ReleasedAt)
	}
	return next
}

func cloneProjectModelRoutes(routes map[string]ProjectModelRoute) map[string]ProjectModelRoute {
	if routes == nil {
		return nil
	}
	cloned := make(map[string]ProjectModelRoute, len(routes))
	for role, route := range routes {
		if route.Seed != nil {
			seed := *route.Seed
			route.Seed = &seed
		}
		cloned[role] = route
	}
	return cloned
}

func cloneCoreSummary(value *CoreSummary) *CoreSummary {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Modules = append([]CoreModuleOutcome(nil), value.Modules...)
	return &cloned
}

func projectLifecycleCommand(command ProjectCommandType) bool {
	switch command {
	case ProjectCommandPlaceLegalHold, ProjectCommandReleaseLegalHold, ProjectCommandBeginDeletion, ProjectCommandCompleteDeletion:
		return true
	default:
		return false
	}
}

func validDeletionRequest(deletion *ProjectDeletion, command ProjectCommand) bool {
	return deletion != nil && safeLifecycleText(deletion.ID, 128) && deletion.RequestedBy == command.ActorID && deletion.RequestedAt.Equal(command.At) && !deletion.EarliestExecutionAt.IsZero() && !deletion.EarliestExecutionAt.Before(command.At) && deletion.Status == "" && deletion.StartedAt == nil && deletion.CompletedAt == nil && deletion.ProofSHA256 == "" && deletion.ProofArtifactURI == ""
}

func validDeletionCompletion(deletion *ProjectDeletion, at time.Time) bool {
	if deletion == nil || !validDigest(deletion.ProofSHA256) || deletion.ProofArtifactURI != "artifact://sha256/"+strings.TrimPrefix(deletion.ProofSHA256, "sha256:") {
		return false
	}
	return deletion.BackupExpiresAt == nil || !deletion.BackupExpiresAt.Before(at)
}

func validLegalHold(hold *ProjectLegalHold, command ProjectCommand) bool {
	return hold != nil && safeLifecycleText(hold.ID, 128) && safeLifecycleText(hold.Reason, 1024) && hold.PlacedBy == command.ActorID && hold.PlacedAt.Equal(command.At) && hold.ReleasedBy == "" && hold.ReleasedAt == nil && hold.ReleaseReason == ""
}

func legalHoldIndex(holds []ProjectLegalHold, id string) int {
	for index := range holds {
		if holds[index].ID == id {
			return index
		}
	}
	return -1
}

func hasActiveLegalHold(holds []ProjectLegalHold) bool {
	for index := range holds {
		if holds[index].ReleasedAt == nil {
			return true
		}
	}
	return false
}

func safeLifecycleText(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func validProjectCurrency(value string) bool {
	if len(value) != 3 {
		return false
	}
	for _, character := range value {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func (f CompletionFacts) allSatisfied() bool {
	return f.AllTasksIntegrated && f.AllIntegrationTasksDone && f.IntegrationAuditPassed && f.GoalCriteriaSatisfied && f.GlobalAuditPassed &&
		f.ReleaseGatesPassed && f.ReleaseArtifactsSigned && f.SBOMGenerated && f.ProvenanceGenerated && f.NoBlockedOrRework &&
		(f.NoBlockingFindings || f.RiskAcceptancesValid) && f.OperationalSummariesGenerated && f.PlanSupervisorSummaryGenerated &&
		f.GoalSummaryVerified && f.FinalResultDelivered && validDigest(f.EvidenceSHA256)
}

func validDigest(value string) bool {
	return contracts.SpecRef{Version: 1, SHA256: value}.Validate() == nil
}

func terminalProjectState(state contracts.ProjectState) bool {
	return state == contracts.ProjectCompleted || state == contracts.ProjectAborted || state == contracts.ProjectArchived
}

func goalChangeAllowedState(value contracts.ProjectState) bool {
	switch value {
	case contracts.ProjectPlanning, contracts.ProjectExecuting, contracts.ProjectIntegrating, contracts.ProjectGlobalAudit, contracts.ProjectBlockedUserDecision:
		return true
	default:
		return false
	}
}

func invalidProject(command ProjectCommand, reason string) *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": string(command.Type) + ": " + reason})
}

func transitionProject(command ProjectCommand, current contracts.ProjectState) *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": string(command.Type), "actualVersion": current})
}
