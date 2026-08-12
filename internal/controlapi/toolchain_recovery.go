package controlapi

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/internal/toolchain"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

var (
	ErrToolchainRecoveryUnavailable = errors.New("toolchain recovery unavailable")
	ErrToolchainRecoveryRunning     = errors.New("toolchain recovery already running")
)

type ToolchainRecoveryScheduler struct {
	handler      *Handler
	store        *toolchain.InstallStore
	running      atomic.Bool
	lastSuccess  atomic.Int64
	failingSince atomic.Int64
}

func NewToolchainRecoveryScheduler(handler *Handler, store *toolchain.InstallStore) (*ToolchainRecoveryScheduler, error) {
	if handler == nil || handler.goalPlan.Negotiator == nil || store == nil {
		return nil, ErrToolchainRecoveryUnavailable
	}
	return &ToolchainRecoveryScheduler{handler: handler, store: store}, nil
}

func (scheduler *ToolchainRecoveryScheduler) Ready() error {
	if scheduler == nil || !scheduler.running.Load() {
		return ErrToolchainRecoveryUnavailable
	}
	if failingSince := scheduler.failingSince.Load(); failingSince > 0 && scheduler.handler.clock().UTC().Sub(time.Unix(0, failingSince)) > 30*time.Second {
		return ErrToolchainRecoveryUnavailable
	}
	return nil
}

func (scheduler *ToolchainRecoveryScheduler) Run(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return ErrToolchainRecoveryUnavailable
	}
	if !scheduler.running.CompareAndSwap(false, true) {
		return ErrToolchainRecoveryRunning
	}
	defer scheduler.running.Store(false)
	for {
		dispatchErr := scheduler.DispatchOnce(ctx)
		now := scheduler.handler.clock().UTC()
		if dispatchErr == nil {
			scheduler.lastSuccess.Store(now.UnixNano())
			scheduler.failingSince.Store(0)
		} else {
			scheduler.failingSince.CompareAndSwap(0, now.UnixNano())
		}
		timer := time.NewTimer(time.Second)
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

func (scheduler *ToolchainRecoveryScheduler) DispatchOnce(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return ErrToolchainRecoveryUnavailable
	}
	if err := scheduler.reconcileMissingBatch(ctx); err != nil {
		return err
	}
	leaseID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	batches, err := scheduler.store.ClaimReadyBatches(ctx, 1, leaseID.String(), 35*time.Minute)
	if err != nil || len(batches) == 0 {
		return err
	}
	batch := batches[0]
	recoveryErr := scheduler.handler.recoverToolchainGoal(ctx, batch)
	if recoveryErr == nil {
		return scheduler.store.CompleteBatch(ctx, batch.ID, leaseID.String(), batch.RecoveryAttempt)
	}
	normalized := normalizeGoalPlanError(recoveryErr)
	code := string(aorerrors.CodeInternalError)
	message := aorerrors.MetadataFor(aorerrors.CodeInternalError).Message
	retry := true
	var typed *aorerrors.Error
	if errors.As(normalized, &typed) {
		code = string(typed.Code)
		message = aorerrors.MetadataFor(typed.Code).Message
		retry = aorerrors.MetadataFor(typed.Code).Retryable
		switch typed.Code {
		case aorerrors.CodeModelOutputSchemaInvalid, aorerrors.CodeTimeout, aorerrors.CodeDependencyUnavailable, aorerrors.CodeProviderRateLimited:
			retry = true
		}
	}
	finishErr := scheduler.store.FailBatch(ctx, batch.ID, leaseID.String(), batch.RecoveryAttempt, retry, code, message)
	return errors.Join(recoveryErr, finishErr)
}

func (scheduler *ToolchainRecoveryScheduler) reconcileMissingBatch(ctx context.Context) error {
	tenantIDs, err := scheduler.store.ReconciliationTenants(ctx, 100)
	if err != nil {
		return err
	}
	for _, tenantID := range tenantIDs {
		projects, err := scheduler.handler.orchestrator.Projects(ctx, tenantID)
		if err != nil {
			return err
		}
		for _, project := range projects {
			if project.Goal == nil || project.Goal.ApprovedBy != "" ||
				project.State != contracts.ProjectGoalNegotiating && project.State != contracts.ProjectGoalSuspended {
				continue
			}
			projection, found, loadErr := scheduler.handler.orchestrator.GoalSpec(ctx, project.TenantID, project.ID, project.Goal.Version)
			if loadErr != nil {
				return loadErr
			}
			if !found || projection.GoalSpecID != project.Goal.ID || projection.Spec.ContentSHA256 != project.Goal.SHA256 ||
				projection.Spec.Status != contracts.GoalDraft || projection.Spec.Content.Toolchain == nil || !hasProvisionableTool(projection.Spec.Content.Toolchain.Tools) {
				continue
			}
			batches, listErr := scheduler.store.ListProjectBatches(ctx, project.TenantID, project.ID)
			if listErr != nil {
				return listErr
			}
			matched := false
			for _, batch := range batches {
				matched = matched || batch.GoalSpecID == project.Goal.ID && batch.GoalVersion == project.Goal.Version
			}
			if matched {
				continue
			}
			messages, messagesErr := scheduler.handler.orchestrator.GoalMessages(ctx, project.TenantID, project.ID)
			if messagesErr != nil {
				return messagesErr
			}
			message, principal, messageFound := recoveryGoalMessage(project, projection.Spec, messages)
			if !messageFound {
				return aorerrors.New(aorerrors.CodeArtifactNotAvailable, "", map[string]any{"scope": "toolchain installation authorization"})
			}
			if _, scheduleErr := scheduler.store.Schedule(ctx, project.TenantID, project.ID, project.Goal.ID, project.Goal.Version, message.ID, principal, projection.Spec.Content.Toolchain.Tools, scheduler.handler.clock().UTC()); scheduleErr != nil {
				return scheduleErr
			}
			return nil
		}
	}
	return nil
}

func hasProvisionableTool(tools []contracts.VersionedTool) bool {
	for _, tool := range tools {
		if tool.ReadyToProvision() && toolchain.SupportsProvisionableArchive(tool) {
			return true
		}
	}
	return false
}

func recoveryGoalMessage(project state.Project, spec contracts.GoalSpec, messages []state.GoalMessage) (state.GoalMessage, authn.Principal, bool) {
	evidence := make(map[string]struct{})
	for _, tool := range spec.Content.Toolchain.Tools {
		if tool.ReadyToProvision() && tool.Install != nil {
			evidence[tool.Install.EvidenceRef] = struct{}{}
		}
	}
	for index := len(messages) - 1; index >= 0; index-- {
		message := messages[index]
		if message.Kind != state.GoalMessageUser || message.CreatedBy == "" {
			continue
		}
		if _, found := evidence[message.ArtifactURI]; !found {
			continue
		}
		principal := authn.Principal{ID: message.CreatedBy, Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: project.TenantID, ProjectID: project.ID}
		if principal.Validate() == nil {
			return message, principal, true
		}
	}
	return state.GoalMessage{}, authn.Principal{}, false
}

func (handler *Handler) recoverToolchainGoal(ctx context.Context, batch toolchain.InstallationBatch) error {
	bound, err := authn.ContextWithPrincipal(ctx, batch.Principal)
	if err != nil {
		return err
	}
	project, found, err := handler.orchestrator.Project(bound, batch.TenantID, batch.ProjectID)
	if err != nil {
		return err
	}
	if !found {
		return aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if project.Goal != nil && project.Goal.ID == batch.GoalSpecID && project.Goal.Version > batch.GoalVersion {
		return nil
	}
	if project.State == contracts.ProjectGoalSuspended && !project.GoalProcessing && project.Goal != nil && project.Goal.ID == batch.GoalSpecID && project.Goal.Version == batch.GoalVersion {
		outcome, resumeErr := handler.orchestrator.HandleProject(bound, orchestrator.ProjectRequest{
			TenantID: batch.TenantID, ProjectID: batch.ProjectID, PrincipalID: batch.Principal.ID,
			IdempotencyKey: goalPlanKey("toolchain-unsuspend", batch.ID, strconv.Itoa(batch.RecoveryAttempt)), ExpectedVersion: project.Version,
			Command: state.ProjectCommand{Type: state.ProjectCommandResume},
		})
		if resumeErr != nil {
			return resumeErr
		}
		project = outcome.Project
	}
	if project.State != contracts.ProjectGoalNegotiating || project.GoalProcessing || project.Goal == nil ||
		project.Goal.ID != batch.GoalSpecID || project.Goal.Version != batch.GoalVersion || project.Goal.ApprovedBy != "" {
		return aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "toolchain goal recovery"})
	}
	messages, err := handler.orchestrator.GoalMessages(bound, batch.TenantID, batch.ProjectID)
	if err != nil {
		return err
	}
	var message state.GoalMessage
	for _, candidate := range messages {
		if candidate.ID == batch.MessageID && candidate.Kind == state.GoalMessageUser && candidate.CreatedBy == batch.Principal.ID {
			message = candidate
			break
		}
	}
	if message.ID == "" {
		return aorerrors.New(aorerrors.CodeArtifactNotAvailable, "", nil)
	}
	outcome, err := handler.orchestrator.HandleProject(bound, orchestrator.ProjectRequest{
		TenantID: batch.TenantID, ProjectID: batch.ProjectID, PrincipalID: batch.Principal.ID,
		IdempotencyKey: goalPlanKey("toolchain-ready", batch.ID, strconv.Itoa(batch.RecoveryAttempt)), ExpectedVersion: project.Version,
		Command: state.ProjectCommand{Type: state.ProjectCommandResumeToolchainGoal, Goal: project.Goal},
	})
	if err != nil {
		return err
	}
	request, err := goalNegotiationRequestWithKey(outcome.Project, message, goalPlanKey("toolchain-negotiate", batch.ID, batch.MessageID, strconv.Itoa(batch.RecoveryAttempt)))
	if err != nil {
		return err
	}
	_, err = handler.executeGoalNegotiation(bound, batch.Principal, *request)
	return err
}
