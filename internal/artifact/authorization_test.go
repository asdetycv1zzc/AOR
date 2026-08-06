package artifact

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
)

type publicationPolicy struct {
	version string
	input   authz.PolicyInput
}

func (policy *publicationPolicy) Evaluate(_ context.Context, input authz.PolicyInput) (authz.PolicyDecision, error) {
	policy.input = input
	return authz.PolicyDecision{Decision: authz.DecisionAllow, PolicyVersion: policy.version, ReasonCodes: []string{"ARTIFACT_ALLOWED"}}, nil
}

func TestCapabilityPublicationValidatorRevalidatesRevocationAndExactBindings(t *testing.T) {
	now := time.Date(2030, 2, 3, 4, 5, 6, 0, time.UTC)
	manager, err := publicationLeaseManager(func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	publication, authorization, scope, lease, err := publicationCommitFixture(manager, now)
	if err != nil {
		t.Fatal(err)
	}
	policy := &publicationPolicy{version: lease.PolicyVersion}
	validator, err := newCapabilityPublicationValidator(capabilityPublicationValidatorConfig{
		Leases: manager, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	commitContext, err := authn.ContextWithPrincipal(context.Background(), scope.Principal)
	if err != nil {
		t.Fatal(err)
	}
	commitContext = context.WithValue(commitContext, publicationOriginContextKey{}, authorization.origin)
	if err := validator.validateCommit(commitContext, publication, authorization, scope); err != nil {
		t.Fatalf("valid publication rejected: %v", err)
	}
	if policy.input.Resource.Type != "artifact" || policy.input.Resource.ID == "" || policy.input.ParameterDigest == "" || policy.input.Project.StateVersion != scope.Project.StateVersion {
		t.Fatalf("policy input did not contain exact commit facts: %#v", policy.input)
	}

	tampered := publication
	tampered.Metadata = map[string]any{"kind": "different"}
	if err := validator.validateCommit(commitContext, tampered, authorization, scope); !errors.Is(err, ErrCommitAuthorization) {
		t.Fatalf("tampered publication error = %v", err)
	}
	stale := scope
	stale.Project.StateVersion++
	if err := validator.validateCommit(commitContext, publication, authorization, stale); !errors.Is(err, ErrCommitAuthorization) {
		t.Fatalf("stale project version error = %v", err)
	}
	noBudget := scope
	noBudget.Budget.Available = false
	if err := validator.validateCommit(commitContext, publication, authorization, noBudget); !errors.Is(err, ErrCommitAuthorization) {
		t.Fatalf("unavailable budget error = %v", err)
	}
	wrongApproval := authorization
	wrongApproval.ApprovalID = "11111111-1111-4111-8111-111111111118"
	if err := validator.validateCommit(commitContext, publication, wrongApproval, scope); !errors.Is(err, ErrCommitAuthorization) {
		t.Fatalf("wrong approval error = %v", err)
	}

	revokeDigest := "sha256:" + strings.Repeat("c", 64)
	if err := manager.Revoke(context.Background(), authz.LeaseRevokeRequest{
		LeaseID: lease.ID, ProjectID: lease.ProjectID, Actor: scope.Principal,
		Reason: "publication canceled", RequestDigest: revokeDigest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := validator.validateCommit(commitContext, publication, authorization, scope); !errors.Is(err, ErrCommitAuthorization) {
		t.Fatalf("revoked lease error = %v", err)
	}
}

func TestPublicationAuthorizationBindingIsCanonicalAndComplete(t *testing.T) {
	publication := publicationFixture()
	leftResource, leftDigest, err := PublicationAuthorizationBinding(publication)
	if err != nil {
		t.Fatal(err)
	}
	reordered := publication
	reordered.Metadata = map[string]any{"ordinal": 1, "kind": "evidence"}
	rightResource, rightDigest, err := PublicationAuthorizationBinding(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftResource, rightResource) || leftDigest != rightDigest {
		t.Fatalf("map order changed binding: left=%#v %s right=%#v %s", leftResource, leftDigest, rightResource, rightDigest)
	}
	retention := time.Date(2031, 4, 5, 6, 7, 8, 0, time.UTC)
	for name, mutate := range map[string]func(*Publication){
		"tenant":      func(candidate *Publication) { candidate.TenantID = "33333333-3333-4333-8333-333333333333" },
		"project":     func(candidate *Publication) { candidate.ProjectID = "44444444-4444-4444-8444-444444444444" },
		"task":        func(candidate *Publication) { candidate.TaskID = "55555555-5555-4555-8555-555555555555" },
		"artifact":    func(candidate *Publication) { candidate.ArtifactID = "66666666-6666-4666-8666-666666666666" },
		"idempotency": func(candidate *Publication) { candidate.IdempotencyKey = "publish-evidence-2" },
		"creator":     func(candidate *Publication) { candidate.CreatedByPrincipal = "audit_service_2" },
		"contentType": func(candidate *Publication) { candidate.ContentType = "application/octet-stream" },
		"metadata":    func(candidate *Publication) { candidate.Metadata = map[string]any{"kind": "different"} },
		"retention":   func(candidate *Publication) { candidate.RetentionUntil = &retention },
		"content":     func(candidate *Publication) { candidate.Data = []byte("different") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := publication
			mutate(&candidate)
			resource, digest, bindingErr := PublicationAuthorizationBinding(candidate)
			if bindingErr != nil {
				t.Fatal(bindingErr)
			}
			if digest == leftDigest || name == "content" && reflect.DeepEqual(resource, leftResource) {
				t.Fatalf("%s was not bound", name)
			}
		})
	}
}

func publicationLeaseManager(clock func() time.Time) (*authz.LeaseManager, error) {
	signer, err := authz.NewHMACSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		return nil, err
	}
	return authz.NewLeaseManager(authz.LeaseManagerConfig{
		Store: authz.NewMemoryLeaseStore(), Signer: signer, Clock: clock,
		DefaultTTL: 5 * time.Minute, MaxTTL: 10 * time.Minute, HeartbeatInterval: 30 * time.Second,
	})
}

func publicationCommitFixture(manager *authz.LeaseManager, now time.Time) (Publication, PublicationAuthorization, publicationCommitScope, authz.CapabilityLease, error) {
	publication := publicationFixture()
	publication.ApprovalID = "11111111-1111-4111-8111-111111111119"
	resource, parameterDigest, err := PublicationAuthorizationBinding(publication)
	if err != nil {
		return Publication{}, PublicationAuthorization{}, publicationCommitScope{}, authz.CapabilityLease{}, err
	}
	principal := authn.Principal{
		ID: "artifact_service", Type: authn.PrincipalService, Role: authn.RoleService,
		TenantID: publication.TenantID, ProjectID: publication.ProjectID,
	}
	project := authz.ProjectScope{
		TenantID: publication.TenantID, ID: publication.ProjectID,
		State: "EXECUTING", StateVersion: 7, Classification: "INTERNAL",
	}
	budget := authz.BudgetScope{AccountID: publication.ProjectID, Available: true}
	approval := &authz.Approval{
		ID: publication.ApprovalID, TenantID: publication.TenantID,
		ProjectID: publication.ProjectID, PrincipalID: "release_approver",
		SubjectType: authz.ActionArtifactPublish, SubjectID: resource.ID,
		SubjectVersion: project.StateVersion, SubjectDigest: parameterDigest,
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Signature: "signed-approval",
	}
	binding := &authz.DecisionBinding{
		PrincipalID: principal.ID, TenantID: publication.TenantID, ProjectID: publication.ProjectID,
		ProjectVersion: project.StateVersion, Role: principal.Role,
		Action: authz.ActionArtifactPublish, Resource: resource,
		ParameterDigest: parameterDigest, BudgetAccountID: budget.AccountID,
	}
	policyVersion := "sha256:" + strings.Repeat("1", 64)
	grant := authz.PolicyDecision{
		Decision: authz.DecisionAllow, PolicyVersion: policyVersion,
		ReasonCodes: []string{"ARTIFACT_ALLOWED"}, RuleID: "aor.artifact.publish",
		Binding: binding, Constraints: authz.Constraints{ExpiresAt: now.Add(5 * time.Minute)},
	}
	lease, err := manager.Issue(context.Background(), authz.LeaseRequest{
		Principal: principal, TenantID: publication.TenantID, ProjectID: publication.ProjectID,
		ProjectVersion: project.StateVersion, Role: principal.Role,
		Action: authz.ActionArtifactPublish, Resource: resource, ParameterDigest: parameterDigest,
		Capabilities: []string{authz.ActionArtifactPublish}, PolicyVersion: policyVersion,
		BudgetAccountID: budget.AccountID, Grant: grant,
	})
	if err != nil {
		return Publication{}, PublicationAuthorization{}, publicationCommitScope{}, authz.CapabilityLease{}, err
	}
	return publication, PublicationAuthorization{
			Lease: lease.Reference(), BudgetAccountID: budget.AccountID, ApprovalID: approval.ID,
			origin: principal,
		}, publicationCommitScope{
			Principal: principal, Project: project, Budget: budget, Approval: approval,
			AuthorizationTime: now,
		}, lease, nil
}

func publicationFixture() Publication {
	retention := time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)
	return Publication{
		TenantID:           "11111111-1111-4111-8111-111111111111",
		ProjectID:          "22222222-2222-4222-8222-222222222222",
		ArtifactID:         "33333333-3333-4333-8333-333333333333",
		CreatedByPrincipal: "audit_service", ContentType: "application/json",
		Metadata: map[string]any{"kind": "evidence", "ordinal": 1}, RetentionUntil: &retention,
		Data: []byte(`{"status":"PASS"}`),
	}
}
