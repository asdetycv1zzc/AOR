package integration

import (
	"context"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

type authorityProjectSource struct{ project state.Project }

func (source authorityProjectSource) Project(context.Context, string, string) (state.Project, bool, error) {
	return source.project, true, nil
}

func TestGlobalAuditConflictAuthorityRequiresGlobalAuditState(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7()).String()
	projectID := uuid.Must(uuid.NewV7()).String()
	integrationID := uuid.Must(uuid.NewV7()).String()
	ownerTaskID := uuid.Must(uuid.NewV7()).String()
	principal := authn.Principal{ID: "aor-global-audit-service", Type: authn.PrincipalService, Role: authn.RoleService}
	store := NewMemoryStore()
	authority, err := NewGlobalAuditConflictAuthority(store, authorityProjectSource{project: state.Project{
		TenantID: tenantID, ID: projectID, State: contracts.ProjectGlobalAudit, Version: 4,
	}}, principal)
	if err != nil {
		t.Fatal(err)
	}
	evidence := digest("global-audit")
	result := MergeResult{
		TenantID: tenantID, ProjectID: projectID, IntegrationID: integrationID, OwnerTaskID: ownerTaskID,
		Audit: Audit{
			IntegrationID: integrationID, ProjectID: projectID, Findings: []Finding{{ID: "finding-1", Severity: "BLOCKING", Category: "SECURITY", Summary: "remediate", Tasks: []string{ownerTaskID}}},
			Checks:         []CheckResult{{Kind: CheckIntegration, Status: CheckError, EvidenceSHA256: evidence, OwnerTaskID: ownerTaskID, Tasks: []string{ownerTaskID}, StartedAt: time.Now().UTC(), CompletedAt: time.Now().UTC()}},
			EvidenceSHA256: evidence, CreatedAt: time.Now().UTC(),
		},
	}
	ctx, err := authn.ContextWithPrincipal(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	stored, created, err := authority.CreateGlobalAuditConflict(ctx, result)
	if err != nil || !created || stored.IntegrationID != integrationID {
		t.Fatalf("created conflict = %#v created=%t err=%v", stored, created, err)
	}
	found, exists, err := store.FindConflictByEvidence(ctx, tenantID, projectID, evidence)
	if err != nil || !exists || found.ID != integrationID {
		t.Fatalf("conflict lookup = %#v found=%t err=%v", found, exists, err)
	}
	authority.projects = authorityProjectSource{project: state.Project{TenantID: tenantID, ID: projectID, State: contracts.ProjectIntegrating, Version: 5}}
	if _, _, err := authority.CreateGlobalAuditConflict(ctx, result); err != ErrNotAudited {
		t.Fatalf("non-global-audit state error = %v", err)
	}
}
