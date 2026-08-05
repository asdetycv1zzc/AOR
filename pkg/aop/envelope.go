// Package aop implements the AOR A2A extension `urn:aor:aop:v1`.
package aop

import (
	"fmt"
	"regexp"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const (
	Version      = "1.0"
	ExtensionURI = "urn:aor:aop:v1"
)

type Intent string

const (
	IntentProposeGoal              Intent = "PROPOSE_GOAL"
	IntentChallengeGoal            Intent = "CHALLENGE_GOAL"
	IntentRequestUserReview        Intent = "REQUEST_USER_REVIEW"
	IntentApproveGoalRequested     Intent = "APPROVE_GOAL_REQUESTED"
	IntentProposePlan              Intent = "PROPOSE_PLAN"
	IntentDefineModule             Intent = "DEFINE_MODULE"
	IntentRequestAgent             Intent = "REQUEST_AGENT"
	IntentAssignModule             Intent = "ASSIGN_MODULE"
	IntentRequestKnowledge         Intent = "REQUEST_KNOWLEDGE"
	IntentReturnKnowledgeRefs      Intent = "RETURN_KNOWLEDGE_REFS"
	IntentRequestTool              Intent = "REQUEST_TOOL"
	IntentSubmitImplementation     Intent = "SUBMIT_IMPLEMENTATION"
	IntentReportDeterministicAudit Intent = "REPORT_DETERMINISTIC_AUDIT"
	IntentReportLLMAudit           Intent = "REPORT_LLM_AUDIT"
	IntentRequestRework            Intent = "REQUEST_REWORK"
	IntentReportModuleComplete     Intent = "REPORT_MODULE_COMPLETE"
	IntentReportModuleBlocked      Intent = "REPORT_MODULE_BLOCKED"
	IntentReportPlanComplete       Intent = "REPORT_PLAN_COMPLETE"
	IntentRequestGlobalAudit       Intent = "REQUEST_GLOBAL_AUDIT"
	IntentReportGlobalAudit        Intent = "REPORT_GLOBAL_AUDIT"
	IntentRequestUserDecision      Intent = "REQUEST_USER_DECISION"
	IntentCancelTask               Intent = "CANCEL_TASK"
	IntentPauseProject             Intent = "PAUSE_PROJECT"
	IntentResumeProject            Intent = "RESUME_PROJECT"
)

type Scope string

const (
	ScopeProject Scope = "PROJECT"
	ScopeTask    Scope = "TASK"
)

type SpecRef = contracts.SpecRef

type Sender struct {
	AgentInstanceID string `json:"agentInstanceId"`
	Role            string `json:"role"`
	Provider        string `json:"provider,omitempty"`
	Model           string `json:"model,omitempty"`
	LeaseID         string `json:"leaseId"`
}

type BudgetContext struct {
	AccountID     string `json:"accountId"`
	ReservationID string `json:"reservationId,omitempty"`
}

type TraceContext struct {
	Traceparent string `json:"traceparent"`
	Tracestate  string `json:"tracestate,omitempty"`
}

type Envelope struct {
	AOPVersion               string         `json:"aopVersion"`
	MessageID                string         `json:"messageId"`
	IdempotencyKey           string         `json:"idempotencyKey"`
	CorrelationID            string         `json:"correlationId"`
	CausationID              string         `json:"causationId,omitempty"`
	ProjectID                string         `json:"projectId"`
	GoalSpec                 *SpecRef       `json:"goalSpec,omitempty"`
	PlanSpec                 *SpecRef       `json:"planSpec,omitempty"`
	ModuleSpec               *SpecRef       `json:"moduleSpec,omitempty"`
	TaskID                   string         `json:"taskId,omitempty"`
	AttemptSeriesID          string         `json:"attemptSeriesId,omitempty"`
	Attempt                  int            `json:"attempt,omitempty"`
	Sender                   Sender         `json:"sender"`
	Scope                    Scope          `json:"scope"`
	Intent                   Intent         `json:"intent"`
	ExpectedAggregateVersion int64          `json:"expectedAggregateVersion"`
	ArtifactRefs             []string       `json:"artifactRefs"`
	KnowledgeRefs            []string       `json:"knowledgeRefs"`
	BudgetContext            *BudgetContext `json:"budgetContext,omitempty"`
	TraceContext             *TraceContext  `json:"traceContext,omitempty"`
	CreatedAt                time.Time      `json:"createdAt"`
	ExpiresAt                time.Time      `json:"expiresAt"`
	Signature                string         `json:"signature,omitempty"`
}

type referenceRequirements struct {
	goal    bool
	plan    bool
	module  bool
	task    bool
	attempt bool
	global  bool
	dynamic bool
}

var intentRequirements = map[Intent]referenceRequirements{
	IntentProposeGoal:              {},
	IntentChallengeGoal:            {goal: true},
	IntentRequestUserReview:        {goal: true},
	IntentApproveGoalRequested:     {goal: true},
	IntentProposePlan:              {goal: true},
	IntentDefineModule:             {goal: true, plan: true, task: true},
	IntentRequestAgent:             {goal: true, dynamic: true},
	IntentAssignModule:             {goal: true, plan: true, module: true},
	IntentRequestKnowledge:         {goal: true, dynamic: true},
	IntentReturnKnowledgeRefs:      {goal: true, dynamic: true},
	IntentRequestTool:              {goal: true, dynamic: true},
	IntentSubmitImplementation:     {goal: true, plan: true, module: true, attempt: true},
	IntentReportDeterministicAudit: {goal: true, plan: true, module: true, attempt: true},
	IntentReportLLMAudit:           {goal: true, plan: true, module: true, attempt: true},
	IntentRequestRework:            {goal: true, plan: true, module: true, attempt: true},
	IntentReportModuleComplete:     {goal: true, plan: true, module: true, attempt: true},
	IntentReportModuleBlocked:      {goal: true, plan: true, module: true, attempt: true},
	IntentReportPlanComplete:       {goal: true, plan: true, global: true},
	IntentRequestGlobalAudit:       {goal: true, plan: true, global: true},
	IntentReportGlobalAudit:        {goal: true, plan: true, global: true},
	IntentRequestUserDecision:      {goal: true, plan: true, module: true, attempt: true},
	IntentCancelTask:               {goal: true, plan: true, module: true},
	IntentPauseProject:             {goal: true},
	IntentResumeProject:            {goal: true},
}

var traceparentPattern = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

func Intents() []Intent {
	result := make([]Intent, 0, len(intentRequirements))
	for _, intent := range []Intent{
		IntentProposeGoal, IntentChallengeGoal, IntentRequestUserReview, IntentApproveGoalRequested, IntentProposePlan, IntentDefineModule,
		IntentRequestAgent, IntentAssignModule, IntentRequestKnowledge, IntentReturnKnowledgeRefs, IntentRequestTool, IntentSubmitImplementation,
		IntentReportDeterministicAudit, IntentReportLLMAudit, IntentRequestRework, IntentReportModuleComplete, IntentReportModuleBlocked,
		IntentReportPlanComplete, IntentRequestGlobalAudit, IntentReportGlobalAudit, IntentRequestUserDecision, IntentCancelTask, IntentPauseProject, IntentResumeProject,
	} {
		result = append(result, intent)
	}
	return result
}

func (e Envelope) Validate(now time.Time) *aorerrors.Error {
	invalid := func(message string) *aorerrors.Error {
		return aorerrors.New(aorerrors.CodeInvalidArgument, e.CorrelationID, map[string]any{"scope": message})
	}
	if e.AOPVersion != Version || e.MessageID == "" || e.IdempotencyKey == "" || e.CorrelationID == "" || e.ProjectID == "" {
		return invalid("envelope identity")
	}
	requirements, known := intentRequirements[e.Intent]
	if !known {
		return invalid("intent")
	}
	if e.ExpectedAggregateVersion < 0 || e.Sender.AgentInstanceID == "" || e.Sender.Role == "" || e.Sender.LeaseID == "" {
		return invalid("sender or aggregate version")
	}
	curatorKnowledgeDraft := e.Sender.Role == "KNOWLEDGE_CURATOR" && e.Intent == IntentReturnKnowledgeRefs && e.Scope == ScopeProject
	if requirements.goal && !curatorKnowledgeDraft && e.GoalSpec == nil || e.GoalSpec != nil && e.GoalSpec.Validate() != nil {
		return invalid("goalSpec")
	}
	if e.CreatedAt.IsZero() || e.ExpiresAt.IsZero() || !e.CreatedAt.Before(e.ExpiresAt) || !now.Before(e.ExpiresAt) {
		return invalid("message time window")
	}
	if e.TraceContext != nil && !traceparentPattern.MatchString(e.TraceContext.Traceparent) {
		return invalid("traceparent")
	}
	if requirements.dynamic {
		if err := e.validateDynamicReferences(); err != nil {
			return invalid(err.Error())
		}
		return nil
	}
	if requirements.plan != (e.PlanSpec != nil) || requirements.module != (e.ModuleSpec != nil) {
		return invalid("spec reference stage")
	}
	if e.PlanSpec != nil && e.PlanSpec.Validate() != nil || e.ModuleSpec != nil && e.ModuleSpec.Validate() != nil {
		return invalid("spec reference digest")
	}
	if requirements.module || requirements.task {
		if e.TaskID == "" || e.Scope != ScopeTask {
			return invalid("task scope")
		}
	} else if e.TaskID != "" || e.Scope != ScopeProject {
		return invalid("project scope")
	}
	if requirements.attempt {
		if e.AttemptSeriesID == "" || e.Attempt < 1 || e.Attempt > 3 {
			return invalid("attempt")
		}
	} else if e.AttemptSeriesID != "" || e.Attempt != 0 {
		return invalid("unexpected attempt")
	}
	if e.Intent == IntentRequestUserDecision && e.Attempt != 3 {
		return invalid("third attempt decision")
	}
	return nil
}

func (e Envelope) validateDynamicReferences() error {
	switch e.Scope {
	case ScopeProject:
		if e.ModuleSpec != nil || e.TaskID != "" || e.AttemptSeriesID != "" || e.Attempt != 0 {
			return fmt.Errorf("project scope contains task references")
		}
		if e.PlanSpec != nil && e.PlanSpec.Validate() != nil {
			return fmt.Errorf("project scope contains an invalid PlanSpec")
		}
	case ScopeTask:
		if e.PlanSpec == nil || e.ModuleSpec == nil || e.TaskID == "" || e.PlanSpec.Validate() != nil || e.ModuleSpec.Validate() != nil {
			return fmt.Errorf("task scope is missing immutable references")
		}
		if (e.AttemptSeriesID == "") != (e.Attempt == 0) || e.Attempt < 0 || e.Attempt > 3 {
			return fmt.Errorf("task scope attempt is inconsistent")
		}
	default:
		return fmt.Errorf("unknown scope")
	}
	return nil
}
