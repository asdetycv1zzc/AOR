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
	handler *Handler
	store   *toolchain.InstallStore
	running atomic.Bool
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
		_ = scheduler.DispatchOnce(ctx)
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
	}
	finishErr := scheduler.store.FailBatch(ctx, batch.ID, leaseID.String(), batch.RecoveryAttempt, retry, code, message)
	return errors.Join(recoveryErr, finishErr)
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
