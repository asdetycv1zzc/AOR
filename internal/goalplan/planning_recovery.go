package goalplan

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akimisaka/aor/internal/authn"
)

const (
	planningRecoveryBatchSize      = 1
	planningRecoveryPollInterval   = time.Second
	planningRecoveryFailureBackoff = 5 * time.Second
)

var (
	ErrInvalidPlanningRecovery    = errors.New("invalid planning recovery configuration")
	ErrPlanningRecoveryRunning    = errors.New("planning recovery is already running")
	ErrPlanningRecoveryNotRunning = errors.New("planning recovery is not running")
)

type PlanningRecoveryCandidate struct {
	Request   PlanningRequest
	Principal authn.Principal
	Attempt   int64
}

type PlanningRecoverySource interface {
	Schedule(context.Context, PlanningRequest) error
	Claim(context.Context, int) ([]PlanningRecoveryCandidate, error)
	Finish(context.Context, PlanningRecoveryCandidate, bool) error
}

type PostgresPlanningRecoverySource struct {
	database *sql.DB
}

func NewPostgresPlanningRecoverySource(database *sql.DB) (*PostgresPlanningRecoverySource, error) {
	if database == nil {
		return nil, ErrInvalidPlanningRecovery
	}
	return &PostgresPlanningRecoverySource{database: database}, nil
}

func (source *PostgresPlanningRecoverySource) Schedule(ctx context.Context, request PlanningRequest) error {
	if source == nil || source.database == nil || ctx == nil || !validPlanningRecoveryRequest(request) {
		return ErrInvalidPlanningRecovery
	}
	principal, found := authn.PrincipalFromContext(ctx)
	if !found || principal.ID != request.PrincipalID || principal.TenantID != request.TenantID ||
		principal.Type != authn.PrincipalUser && principal.Type != authn.PrincipalBreakGlassAdmin || principal.Role == "" {
		return ErrInvalidPlanningRecovery
	}
	var scheduled bool
	err := source.database.QueryRowContext(ctx, `
SELECT aor_schedule_planning_recovery(
  $1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11
)`, request.TenantID, request.ProjectID, request.ExpectedProjectVersion,
		request.PrincipalID, string(principal.Type), principal.Role,
		request.GoalSpecID, request.GoalRef.Version,
		request.GoalRef.SHA256, request.PlanSpecID, request.IdempotencyKey,
	).Scan(&scheduled)
	return err
}

func (source *PostgresPlanningRecoverySource) Claim(ctx context.Context, limit int) ([]PlanningRecoveryCandidate, error) {
	if source == nil || source.database == nil || ctx == nil || limit < 1 || limit > 8 {
		return nil, ErrInvalidPlanningRecovery
	}
	rows, err := source.database.QueryContext(ctx, `
SELECT tenant_id::text, project_id::text, project_version, principal_id,
       principal_type, principal_role, goal_spec_id, goal_version, goal_sha256,
       plan_spec_id, idempotency_key, attempt
FROM aor_claim_planning_recoveries($1)`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]PlanningRecoveryCandidate, 0, limit)
	for rows.Next() {
		var candidate PlanningRecoveryCandidate
		request := &candidate.Request
		if err := rows.Scan(
			&request.TenantID, &request.ProjectID, &request.ExpectedProjectVersion,
			&request.PrincipalID, &candidate.Principal.Type, &candidate.Principal.Role,
			&request.GoalSpecID, &request.GoalRef.Version,
			&request.GoalRef.SHA256, &request.PlanSpecID, &request.IdempotencyKey,
			&candidate.Attempt,
		); err != nil {
			return nil, err
		}
		candidate.Principal.ID = request.PrincipalID
		candidate.Principal.TenantID = request.TenantID
		request.PlanVersion = 1
		if !validPlanningRecoveryCandidate(candidate) {
			return nil, ErrInvalidPlanningRecovery
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return candidates, nil
}

func (source *PostgresPlanningRecoverySource) Finish(ctx context.Context, candidate PlanningRecoveryCandidate, retry bool) error {
	if source == nil || source.database == nil || ctx == nil || !validPlanningRecoveryCandidate(candidate) {
		return ErrInvalidPlanningRecovery
	}
	var finished bool
	err := source.database.QueryRowContext(ctx, `
SELECT aor_finish_planning_recovery($1::uuid, $2::uuid, $3, $4, $5)`,
		candidate.Request.TenantID, candidate.Request.ProjectID,
		candidate.Request.ExpectedProjectVersion, candidate.Attempt, retry,
	).Scan(&finished)
	if err != nil {
		return err
	}
	if !finished {
		return ErrInvalidPlanningRecovery
	}
	return nil
}

type automaticPlanningService interface {
	BuildAndPublishAutomatic(context.Context, PlanningRequest) (PlanningResult, error)
}

type PlanningRecoveryScheduler struct {
	source  PlanningRecoverySource
	planner automaticPlanningService
	running atomic.Bool
	status  sync.RWMutex
	lastErr error
}

func NewPlanningRecoveryScheduler(source PlanningRecoverySource, planner automaticPlanningService) (*PlanningRecoveryScheduler, error) {
	if source == nil || planner == nil {
		return nil, ErrInvalidPlanningRecovery
	}
	return &PlanningRecoveryScheduler{source: source, planner: planner}, nil
}

func (scheduler *PlanningRecoveryScheduler) DispatchOnce(ctx context.Context) error {
	if scheduler == nil || scheduler.source == nil || scheduler.planner == nil || ctx == nil {
		return ErrInvalidPlanningRecovery
	}
	candidates, err := scheduler.source.Claim(ctx, planningRecoveryBatchSize)
	if err != nil {
		return err
	}
	var dispatchErr error
	for _, candidate := range candidates {
		planningContext, bindErr := authn.ContextWithPrincipal(ctx, candidate.Principal)
		if bindErr == nil {
			_, bindErr = scheduler.planner.BuildAndPublishAutomatic(planningContext, candidate.Request)
		}
		retry := bindErr != nil
		finishErr := scheduler.source.Finish(ctx, candidate, retry)
		dispatchErr = errors.Join(dispatchErr, bindErr, finishErr)
	}
	return dispatchErr
}

func (scheduler *PlanningRecoveryScheduler) Run(ctx context.Context) error {
	if scheduler == nil || ctx == nil {
		return ErrInvalidPlanningRecovery
	}
	if !scheduler.running.CompareAndSwap(false, true) {
		return ErrPlanningRecoveryRunning
	}
	defer scheduler.running.Store(false)
	for {
		dispatchErr := scheduler.DispatchOnce(ctx)
		scheduler.status.Lock()
		scheduler.lastErr = dispatchErr
		scheduler.status.Unlock()
		wait := planningRecoveryPollInterval
		if dispatchErr != nil {
			wait = planningRecoveryFailureBackoff
		}
		timer := time.NewTimer(wait)
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

func (scheduler *PlanningRecoveryScheduler) Ready() error {
	if scheduler == nil || !scheduler.running.Load() {
		return ErrPlanningRecoveryNotRunning
	}
	scheduler.status.RLock()
	defer scheduler.status.RUnlock()
	return scheduler.lastErr
}

func validPlanningRecoveryCandidate(candidate PlanningRecoveryCandidate) bool {
	request := candidate.Request
	return candidate.Attempt > 0 && validPlanningRecoveryRequest(request) &&
		candidate.Principal.ID == request.PrincipalID && candidate.Principal.TenantID == request.TenantID &&
		(candidate.Principal.Type == authn.PrincipalUser || candidate.Principal.Type == authn.PrincipalBreakGlassAdmin) &&
		candidate.Principal.Role != ""
}

func validPlanningRecoveryRequest(request PlanningRequest) bool {
	return request.TenantID != "" && request.ProjectID != "" &&
		request.PrincipalID != "" && request.GoalSpecID != "" && request.GoalRef.Validate() == nil &&
		request.PlanSpecID != "" && request.PlanVersion == 1 && request.ExpectedProjectVersion > 0 && request.IdempotencyKey != "" &&
		len(request.ModuleTaskIDs) == 0 && len(request.AttemptSeriesIDs) == 0 &&
		len(request.ModuleSpecVersions) == 0 && len(request.RetainedModules) == 0
}

var _ PlanningRecoverySource = (*PostgresPlanningRecoverySource)(nil)
var _ automaticPlanningService = (*Planner)(nil)
