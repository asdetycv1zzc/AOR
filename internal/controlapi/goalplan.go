package controlapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type GoalNegotiationService interface {
	Negotiate(context.Context, goalplan.NegotiationRequest) (goalplan.NegotiationResult, error)
	Approve(context.Context, goalplan.ApprovalRequest) (orchestrator.ProjectOutcome, error)
}

type GoalPlanningService interface {
	BuildAndPublishAutomatic(context.Context, goalplan.PlanningRequest) (goalplan.PlanningResult, error)
}

type GoalPlanServices struct {
	Negotiator GoalNegotiationService
	Planner    GoalPlanningService
}

func (handler *Handler) negotiateGoal(ctx context.Context, principal authn.Principal, projectID string, body goalMessageBody, idempotencyKey string) (state.Project, error) {
	project, found, err := handler.orchestrator.Project(ctx, principal.TenantID, projectID)
	if err != nil {
		return state.Project{}, err
	}
	if !found {
		return state.Project{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := authorizeRead(ctx, handler.authorizer, principal, projectID, authz.ActionProjectCommand, "project", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		return state.Project{}, err
	}

	goalSpecID := goalPlanUUID("goal-spec", principal.TenantID, projectID)
	var previousRef *contracts.SpecRef
	supersede := false
	if project.Goal != nil {
		goalSpecID = project.Goal.ID
		ref := contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}
		previousRef = &ref
		supersede = project.Goal.ApprovedBy != ""
	}
	result, err := handler.goalPlan.Negotiator.Negotiate(ctx, goalplan.NegotiationRequest{
		TenantID: principal.TenantID, ProjectID: projectID, GoalSpecID: goalSpecID,
		MessageID:       goalPlanUUID("goal-message", principal.TenantID, projectID, principal.ID, idempotencyKey),
		UserPrincipalID: principal.ID, UserInput: []byte(body.Message), GoalAgentCount: project.GoalAgentCount,
		PreviousRef: previousRef, SupersedeApprovedGoal: supersede, ExpectedProjectVersion: body.ExpectedVersion,
		IdempotencyKey: goalPlanKey("negotiate", principal.TenantID, projectID, principal.ID, idempotencyKey),
	})
	if err != nil {
		return state.Project{}, err
	}
	outcome := result.Project.Project
	if outcome.TenantID != principal.TenantID || outcome.ID != projectID || outcome.Version != body.ExpectedVersion+1 || outcome.State != contracts.ProjectGoalNegotiating || outcome.Goal == nil || outcome.Goal.ID != goalSpecID || outcome.Goal.Version != result.Goal.Content.Version || outcome.Goal.SHA256 != result.Goal.ContentSHA256 || result.Goal.Status != contracts.GoalDraft || result.Artifact.TenantID != principal.TenantID || result.Artifact.ProjectID != projectID || result.Artifact.Kind != goalplan.ArtifactGoalDraft || result.Artifact.SpecID != goalSpecID || result.Artifact.Version != result.Goal.Content.Version || result.Artifact.ContentSHA256 != result.Goal.ContentSHA256 {
		return state.Project{}, goalplan.ErrAgentOutput
	}
	return outcome, nil
}

func (handler *Handler) approveGoalAndPlan(ctx context.Context, principal authn.Principal, projectID string, projection orchestrator.GoalSpecProjection, body goalDecisionBody, idempotencyKey, reason string) (state.Project, error) {
	project, found, err := handler.orchestrator.Project(ctx, principal.TenantID, projectID)
	if err != nil {
		return state.Project{}, err
	}
	if !found {
		return state.Project{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := authorizeRead(ctx, handler.authorizer, principal, projectID, authz.ActionProjectCommand, "project", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		return state.Project{}, err
	}
	issuedAt := handler.clock().UTC()
	if projection.Spec.Status == contracts.GoalApproved {
		if projection.Spec.ApprovedBy == nil || projection.Spec.ApprovedBy.ActorID != principal.ID {
			return state.Project{}, goalplan.ErrInvalidRequest
		}
		approvedAt, err := time.Parse(time.RFC3339Nano, projection.Spec.ApprovedBy.ApprovedAt)
		if err != nil {
			return state.Project{}, goalplan.ErrAgentOutput
		}
		issuedAt = approvedAt.UTC()
	}
	goalRef := contracts.SpecRef{Version: projection.Spec.Content.Version, SHA256: body.SHA256}
	approval, err := handler.goalPlan.Negotiator.Approve(ctx, goalplan.ApprovalRequest{
		TenantID: principal.TenantID, ProjectID: projectID, GoalSpecID: projection.GoalSpecID, GoalRef: goalRef,
		UserPrincipalID: principal.ID, ExpectedProjectVersion: body.ExpectedVersion, IdempotencyKey: idempotencyKey,
		Approval: goalplan.ApprovalBinding{
			RecordID:     approvalRecordID(principal.TenantID, principal.ID, idempotencyKey),
			ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: projection.GoalSpecID,
			SubjectVersion: goalRef.Version, SubjectSHA256: goalRef.SHA256, PrincipalID: principal.ID,
			Reason: reason, IssuedAt: issuedAt,
			Signature: goalApprovalSignature(principal.TenantID, projectID, projection.GoalSpecID, goalRef.Version, goalRef.SHA256, principal.ID, reason, idempotencyKey),
		},
	})
	if err != nil {
		return state.Project{}, err
	}
	if approval.Project.TenantID != principal.TenantID || approval.Project.ID != projectID || approval.Project.Version != body.ExpectedVersion+1 || approval.Project.State != contracts.ProjectPlanning || approval.Project.Goal == nil || approval.Project.Goal.ID != projection.GoalSpecID || approval.Project.Goal.Version != goalRef.Version || approval.Project.Goal.SHA256 != goalRef.SHA256 || approval.Project.Goal.ApprovedBy != principal.ID {
		return state.Project{}, goalplan.ErrAgentOutput
	}

	plan, err := handler.goalPlan.Planner.BuildAndPublishAutomatic(ctx, goalplan.PlanningRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
		GoalSpecID: projection.GoalSpecID, GoalRef: goalRef,
		PlanSpecID: goalPlanUUID("plan-spec", principal.TenantID, projectID), PlanVersion: 1,
		ExpectedProjectVersion: approval.Project.Version,
		IdempotencyKey:         goalPlanKey("initial-plan", principal.TenantID, projectID, principal.ID, idempotencyKey),
	})
	if err != nil {
		return state.Project{}, err
	}
	outcome := plan.Publication.Project
	if outcome.TenantID != principal.TenantID || outcome.ID != projectID || outcome.Version != approval.Project.Version+1 || outcome.State != contracts.ProjectExecuting || outcome.Plan == nil || outcome.Plan.Version != plan.Plan.PlanSpecVersion || outcome.Plan.SHA256 != plan.Plan.SHA256 || plan.PlanArtifact.Kind != goalplan.ArtifactPlanSpec || plan.PlanArtifact.SpecID != goalPlanUUID("plan-spec", principal.TenantID, projectID) {
		return state.Project{}, goalplan.ErrAgentOutput
	}
	return outcome, nil
}

func goalPlanUUID(parts ...string) string {
	digest := sha256.Sum256([]byte(joinGoalPlanParts(parts)))
	digest[6] = digest[6]&0x0f | 0x50
	digest[8] = digest[8]&0x3f | 0x80
	value := hex.EncodeToString(digest[:16])
	return value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]
}

func goalPlanKey(kind string, parts ...string) string {
	digest := sha256.Sum256([]byte(joinGoalPlanParts(append([]string{kind}, parts...))))
	return "goalplan:" + kind + ":" + hex.EncodeToString(digest[:])
}

func joinGoalPlanParts(parts []string) string {
	return strings.Join(parts, "\x00")
}

func normalizeGoalPlanError(err error) error {
	var typed *aorerrors.Error
	if errors.As(err, &typed) {
		return typed
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return aorerrors.New(aorerrors.CodeTimeout, "", nil)
	case errors.Is(err, goalplan.ErrArtifactConflict), errors.Is(err, modelgateway.ErrRequestConflict):
		return aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
	case errors.Is(err, goalplan.ErrArtifactNotFound):
		return aorerrors.New(aorerrors.CodeArtifactNotAvailable, "", nil)
	case errors.Is(err, goalplan.ErrAgentOutput), errors.Is(err, goalplan.ErrOwnershipConflict), errors.Is(err, modelgateway.ErrOutputSchema), errors.Is(err, agentruntime.ErrOutputInvalid):
		return aorerrors.New(aorerrors.CodeModelOutputSchemaInvalid, "", nil)
	case errors.Is(err, goalplan.ErrInvalidRequest), errors.Is(err, agentruntime.ErrInvalidDeclaration), errors.Is(err, agentruntime.ErrInvalidTransition):
		return aorerrors.New(aorerrors.CodeInvalidStateTransition, "", nil)
	case errors.Is(err, modelgateway.ErrBudgetExceeded):
		return aorerrors.New(aorerrors.CodeBudgetExceeded, "", nil)
	case errors.Is(err, modelgateway.ErrProviderNotAllowed):
		return aorerrors.New(aorerrors.CodeModelNotAllowed, "", nil)
	case errors.Is(err, agentruntime.ErrLeaseExpired):
		return aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
	case errors.Is(err, agentruntime.ErrLeaseInvalid), errors.Is(err, agentruntime.ErrLeaseBinding), errors.Is(err, agentruntime.ErrCapabilityDenied), errors.Is(err, agentruntime.ErrIntentDenied):
		return aorerrors.New(aorerrors.CodePolicyDenied, "", nil)
	case errors.Is(err, modelgateway.ErrProviderUnavailable), errors.Is(err, agentruntime.ErrProviderUnavailable):
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "goal plan runtime"})
	default:
		return normalizeError(err)
	}
}

var _ GoalNegotiationService = (*goalplan.Negotiator)(nil)
var _ GoalPlanningService = (*goalplan.Planner)(nil)
