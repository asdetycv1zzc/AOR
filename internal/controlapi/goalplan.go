package controlapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/internal/toolchain"
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

type GoalPlanningRecovery interface {
	Schedule(context.Context, goalplan.PlanningRequest) error
}

type GoalPlanServices struct {
	Negotiator GoalNegotiationService
	Planner    GoalPlanningService
	Recovery   GoalPlanningRecovery
}

func (handler *Handler) acceptGoalNegotiation(ctx context.Context, principal authn.Principal, projectID string, body goalMessageBody, idempotencyKey string) (state.Project, *goalplan.NegotiationRequest, error) {
	project, found, err := handler.orchestrator.Project(ctx, principal.TenantID, projectID)
	if err != nil {
		return state.Project{}, nil, err
	}
	if !found {
		return state.Project{}, nil, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := authorizeRead(ctx, handler.authorizer, principal, projectID, authz.ActionProjectCommand, "project", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		return state.Project{}, nil, err
	}

	outcome, err := handler.orchestrator.HandleProject(ctx, orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID, IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion,
		Command: state.ProjectCommand{Type: state.ProjectCommandSubmitGoalMessage, AsyncGoalProcessing: true, GoalMessage: &state.GoalMessage{Kind: state.GoalMessageUser, Message: body.Message}},
	})
	if err != nil {
		return state.Project{}, nil, err
	}
	if outcome.Duplicate {
		if project.Version != outcome.Project.Version || !project.GoalProcessing {
			return project, nil, nil
		}
		outcome.Project = project
	}
	if outcome.Project.Version != body.ExpectedVersion+1 || !outcome.Project.GoalProcessing {
		return state.Project{}, nil, goalplan.ErrAgentOutput
	}
	messages, err := handler.orchestrator.GoalMessages(ctx, principal.TenantID, projectID)
	if err != nil {
		return state.Project{}, nil, err
	}
	message, found := acceptedGoalMessage(messages, principal.ID, body.Message)
	if !found {
		return state.Project{}, nil, goalplan.ErrArtifactNotFound
	}
	negotiation, err := goalNegotiationRequest(outcome.Project, message)
	if err != nil {
		return state.Project{}, nil, err
	}
	return outcome.Project, negotiation, nil
}

func acceptedGoalMessage(messages []state.GoalMessage, principalID, content string) (state.GoalMessage, bool) {
	for index := len(messages) - 1; index >= 0; index-- {
		message := messages[index]
		if message.Kind == state.GoalMessageUser && message.CreatedBy == principalID && message.Message == content {
			return message, true
		}
	}
	return state.GoalMessage{}, false
}

func goalNegotiationRequest(project state.Project, message state.GoalMessage) (*goalplan.NegotiationRequest, error) {
	return goalNegotiationRequestWithKey(project, message, goalPlanKey("negotiate", project.TenantID, project.ID, message.CreatedBy, message.ID))
}

func goalNegotiationRequestWithKey(project state.Project, message state.GoalMessage, idempotencyKey string) (*goalplan.NegotiationRequest, error) {
	if !project.GoalProcessing || project.State != contracts.ProjectGoalNegotiating || message.TenantID != project.TenantID || message.ProjectID != project.ID || message.CreatedBy == "" || message.Message == "" || idempotencyKey == "" {
		return nil, goalplan.ErrInvalidRequest
	}
	goalSpecID := ""
	var previousRef *contracts.SpecRef
	supersede := false
	if project.Goal != nil {
		goalSpecID = project.Goal.ID
		ref := contracts.SpecRef{Version: project.Goal.Version, SHA256: project.Goal.SHA256}
		previousRef = &ref
		supersede = project.Goal.ApprovedBy != ""
	} else {
		var err error
		goalSpecID, err = newRecordUUIDv7()
		if err != nil {
			return nil, err
		}
	}
	return &goalplan.NegotiationRequest{
		TenantID: project.TenantID, ProjectID: project.ID, GoalSpecID: goalSpecID, MessageID: message.ID,
		UserPrincipalID: message.CreatedBy, UserInput: []byte(message.Message), GoalAgentCount: project.GoalAgentCount,
		PreviousRef: previousRef, SupersedeApprovedGoal: supersede, ExpectedProjectVersion: project.Version,
		IdempotencyKey:  idempotencyKey,
		MessageAccepted: true,
	}, nil
}

func (handler *Handler) resumeGoalNegotiation(ctx context.Context, principal authn.Principal, project state.Project) {
	if handler.goalPlan.Negotiator == nil || !project.GoalProcessing {
		return
	}
	messages, err := handler.orchestrator.GoalMessages(ctx, project.TenantID, project.ID)
	if err != nil {
		return
	}
	for index := len(messages) - 1; index >= 0; index-- {
		message := messages[index]
		if message.Kind != state.GoalMessageUser || message.CreatedBy != principal.ID {
			continue
		}
		request, requestErr := goalNegotiationRequest(project, message)
		if requestErr == nil {
			handler.startGoalNegotiation(ctx, principal, *request)
		}
		return
	}
}

func (handler *Handler) startGoalNegotiation(ctx context.Context, principal authn.Principal, request goalplan.NegotiationRequest) {
	if _, running := handler.goalNegotiations.LoadOrStore(request.IdempotencyKey, struct{}{}); running {
		return
	}
	go func() {
		defer handler.goalNegotiations.Delete(request.IdempotencyKey)
		handler.runGoalNegotiation(ctx, principal, request)
	}()
}

func (handler *Handler) runGoalNegotiation(ctx context.Context, principal authn.Principal, request goalplan.NegotiationRequest) {
	_, _ = handler.executeGoalNegotiation(ctx, principal, request)
}

func (handler *Handler) executeGoalNegotiation(ctx context.Context, principal authn.Principal, request goalplan.NegotiationRequest) (goalplan.NegotiationResult, error) {
	goalContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
	defer cancel()
	activityID := handler.beginGoalActivity(goalContext, request)
	result, err := handler.goalPlan.Negotiator.Negotiate(goalContext, request)
	if err == nil {
		outcome := result.Project.Project
		if outcome.TenantID != principal.TenantID || outcome.ID != request.ProjectID || outcome.Version != request.ExpectedProjectVersion+1 || outcome.State != contracts.ProjectGoalNegotiating || outcome.Goal == nil || outcome.Goal.ID != request.GoalSpecID || outcome.Goal.Version != result.Goal.Content.Version || outcome.Goal.SHA256 != result.Goal.ContentSHA256 || outcome.GoalProcessing || result.Goal.Status != contracts.GoalDraft || result.Artifact.TenantID != principal.TenantID || result.Artifact.ProjectID != request.ProjectID || result.Artifact.Kind != goalplan.ArtifactGoalDraft || result.Artifact.SpecID != request.GoalSpecID || result.Artifact.Version != result.Goal.Content.Version || result.Artifact.ContentSHA256 != result.Goal.ContentSHA256 {
			err = goalplan.ErrAgentOutput
		}
	}
	if err == nil {
		err = handler.scheduleToolchainInstallations(goalContext, principal, request, result)
	}
	if err != nil {
		handler.suspendFailedGoalNegotiation(goalContext, principal, request)
	}
	handler.completeGoalActivity(goalContext, request, activityID, result, err)
	handler.startNextGoalIntervention(goalContext, request.TenantID, request.ProjectID)
	return result, err
}

func (handler *Handler) scheduleToolchainInstallations(ctx context.Context, principal authn.Principal, request goalplan.NegotiationRequest, result goalplan.NegotiationResult) error {
	selection := result.Goal.Content.Toolchain
	if selection == nil {
		return nil
	}
	ready := false
	for _, tool := range selection.Tools {
		ready = ready || tool.ReadyToProvision()
	}
	if !ready {
		return nil
	}
	if handler.toolchainInstalls == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "toolchain installation queue"})
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		_, err = handler.toolchainInstalls.Schedule(ctx, request.TenantID, request.ProjectID, request.GoalSpecID, result.Goal.Content.Version, request.MessageID, principal, selection.Tools, handler.clock().UTC())
		if err == nil {
			return nil
		}
		if attempt < 2 {
			timer := time.NewTimer(time.Duration(attempt+1) * time.Second)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "toolchain installation queue"})
}

func (handler *Handler) suspendFailedGoalNegotiation(ctx context.Context, principal authn.Principal, request goalplan.NegotiationRequest) {
	failureContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	project, found, err := handler.orchestrator.Project(failureContext, request.TenantID, request.ProjectID)
	if err != nil || !found || project.Version != request.ExpectedProjectVersion || !project.GoalProcessing {
		return
	}
	_, _ = handler.orchestrator.HandleProject(failureContext, orchestrator.ProjectRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: principal.ID,
		IdempotencyKey:  goalPlanKey("negotiation-failed", request.TenantID, request.ProjectID, principal.ID, request.IdempotencyKey),
		ExpectedVersion: request.ExpectedProjectVersion,
		Command:         state.ProjectCommand{Type: state.ProjectCommandPause},
	})
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
	goalRef := contracts.SpecRef{Version: projection.Spec.Content.Version, SHA256: body.SHA256}
	approvedProjectVersion := body.ExpectedVersion + 1
	approvalCommitted := project.Version == approvedProjectVersion || project.Version == approvedProjectVersion+1
	if approvalCommitted {
		if projection.Spec.Status != contracts.GoalApproved || project.Goal == nil || project.Goal.ID != projection.GoalSpecID || project.Goal.Version != goalRef.Version || project.Goal.SHA256 != goalRef.SHA256 || project.Goal.ApprovedBy != principal.ID {
			return state.Project{}, goalplan.ErrInvalidRequest
		}
		if project.Version == approvedProjectVersion && project.State != contracts.ProjectPlanning {
			return state.Project{}, goalplan.ErrInvalidRequest
		}
		if project.Version == approvedProjectVersion+1 && (project.State != contracts.ProjectExecuting || project.Plan == nil) {
			return state.Project{}, goalplan.ErrInvalidRequest
		}
	} else {
		if project.Version != body.ExpectedVersion {
			return state.Project{}, goalplan.ErrInvalidRequest
		}
		if projection.Spec.Content.GoalSpecVersion != 2 || projection.Spec.Content.Toolchain == nil || handler.toolchains == nil {
			return state.Project{}, goalplan.ErrInvalidRequest
		}
		inventory, inventoryErr := handler.toolchains.Snapshot(ctx)
		if inventoryErr != nil {
			return state.Project{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", inventoryErr, map[string]any{"scope": "toolchain inventory"})
		}
		if toolchain.ValidateSelection(inventory, *projection.Spec.Content.Toolchain) != nil || projection.Spec.Content.Toolchain.RequiresInstallation() {
			return state.Project{}, goalplan.ErrInvalidRequest
		}
		issuedAt := handler.clock().UTC()
		if projection.Spec.Status == contracts.GoalApproved {
			if projection.Spec.ApprovedBy == nil || projection.Spec.ApprovedBy.ActorID != principal.ID {
				return state.Project{}, goalplan.ErrInvalidRequest
			}
			approvedAt, parseErr := time.Parse(time.RFC3339Nano, projection.Spec.ApprovedBy.ApprovedAt)
			if parseErr != nil {
				return state.Project{}, goalplan.ErrAgentOutput
			}
			issuedAt = approvedAt.UTC()
		}
		approvalID, idErr := newRecordUUIDv7()
		if idErr != nil {
			return state.Project{}, idErr
		}
		approval, approveErr := handler.goalPlan.Negotiator.Approve(ctx, goalplan.ApprovalRequest{
			TenantID: principal.TenantID, ProjectID: projectID, GoalSpecID: projection.GoalSpecID, GoalRef: goalRef,
			UserPrincipalID: principal.ID, ExpectedProjectVersion: body.ExpectedVersion, IdempotencyKey: idempotencyKey,
			Approval: goalplan.ApprovalBinding{
				RecordID:     approvalID,
				ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC", SubjectID: projection.GoalSpecID,
				SubjectVersion: goalRef.Version, SubjectSHA256: goalRef.SHA256, PrincipalID: principal.ID,
				Reason: reason, IssuedAt: issuedAt,
				Signature: goalApprovalSignature(principal.TenantID, projectID, projection.GoalSpecID, goalRef.Version, goalRef.SHA256, principal.ID, reason, idempotencyKey),
			},
		})
		if approveErr != nil {
			return state.Project{}, approveErr
		}
		if approval.Project.TenantID != principal.TenantID || approval.Project.ID != projectID || approval.Project.Version != approvedProjectVersion || approval.Project.State != contracts.ProjectPlanning || approval.Project.Goal == nil || approval.Project.Goal.ID != projection.GoalSpecID || approval.Project.Goal.Version != goalRef.Version || approval.Project.Goal.SHA256 != goalRef.SHA256 || approval.Project.Goal.ApprovedBy != principal.ID {
			return state.Project{}, goalplan.ErrAgentOutput
		}
	}

	planSpecID, _, err := handler.findGoalPlanArtifactSpecID(ctx, principal.TenantID, projectID, goalplan.ArtifactPlanSpec, 1, func(artifact goalplan.SpecArtifact) bool {
		var stored contracts.PlanSpec
		return json.Unmarshal(artifact.Content, &stored) == nil && stored.ProjectID == projectID && stored.GoalSpecRef == goalRef
	})
	if err != nil {
		return state.Project{}, err
	}
	if planSpecID == "" {
		planSpecID, err = newRecordUUIDv7()
		if err != nil {
			return state.Project{}, err
		}
	}
	planningRequest := goalplan.PlanningRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
		GoalSpecID: projection.GoalSpecID, GoalRef: goalRef,
		PlanSpecID: planSpecID, PlanVersion: 1,
		ExpectedProjectVersion: approvedProjectVersion,
		IdempotencyKey:         goalPlanKey("initial-plan", principal.TenantID, projectID, principal.ID, idempotencyKey),
	}
	activityID := handler.beginPlanActivity(ctx, planningRequest)
	plan, err := handler.goalPlan.Planner.BuildAndPublishAutomatic(ctx, planningRequest)
	handler.completePlanActivity(ctx, planningRequest, activityID, plan, err)
	if err != nil {
		if handler.goalPlan.Recovery != nil {
			recoveryContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if recoveryErr := handler.goalPlan.Recovery.Schedule(recoveryContext, planningRequest); recoveryErr != nil {
				return state.Project{}, errors.Join(err, recoveryErr)
			}
		}
		return state.Project{}, err
	}
	outcome := plan.Publication.Project
	if outcome.TenantID != principal.TenantID || outcome.ID != projectID || outcome.Version != approvedProjectVersion+1 || outcome.State != contracts.ProjectExecuting || outcome.Plan == nil || outcome.Plan.Version != plan.Plan.PlanSpecVersion || outcome.Plan.SHA256 != plan.Plan.SHA256 || plan.PlanArtifact.Kind != goalplan.ArtifactPlanSpec || plan.PlanArtifact.SpecID != planSpecID {
		return state.Project{}, goalplan.ErrAgentOutput
	}
	return outcome, nil
}

func (handler *Handler) findGoalPlanArtifactSpecID(ctx context.Context, tenantID, projectID string, kind goalplan.ArtifactKind, version int, matches func(goalplan.SpecArtifact) bool) (string, bool, error) {
	lister, ok := handler.store.(eventing.ProjectionList)
	if !ok {
		return "", false, nil
	}
	projections, err := lister.ListProjections(ctx, tenantID, projectID, "spec_artifact")
	if err != nil {
		return "", false, err
	}
	result := ""
	for _, projection := range projections {
		var artifact goalplan.SpecArtifact
		if json.Unmarshal(projection.State, &artifact) != nil || artifact.Kind != kind || artifact.Version != version {
			continue
		}
		if artifact.TenantID != tenantID || artifact.ProjectID != projectID || artifact.SpecID == "" {
			return "", false, goalplan.ErrAgentOutput
		}
		if matches != nil && !matches(artifact) {
			continue
		}
		if result != "" && result != artifact.SpecID {
			return "", false, goalplan.ErrArtifactConflict
		}
		result = artifact.SpecID
	}
	return result, result != "", nil
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
var _ GoalPlanningRecovery = (*goalplan.PostgresPlanningRecoverySource)(nil)
