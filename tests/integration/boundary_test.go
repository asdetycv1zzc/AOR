package integration_test

import (
	"context"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/orchestrator"
)

type integrationCommitBoundary struct{}

func (integrationCommitBoundary) Validate(_ context.Context, validation orchestrator.CommitValidation) error {
	if validation.TenantID == "" || validation.ProjectID == "" || validation.PrincipalID == "" || validation.Action == "" || validation.ParameterDigest == "" || validation.CommitAt.IsZero() {
		return orchestrator.ErrCommitBoundary
	}
	return nil
}

func newIntegrationOrchestrator(store eventing.Store) *orchestrator.Service {
	return orchestrator.NewWithBoundary(store, replayClock, integrationCommitBoundary{})
}
