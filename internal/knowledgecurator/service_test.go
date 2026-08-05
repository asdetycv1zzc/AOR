package knowledgecurator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

var curatorTestNow = time.Date(2038, 5, 6, 7, 8, 9, 0, time.UTC)

const (
	curatorTenantID  = "11111111-1111-4111-8111-111111111111"
	curatorProjectID = "22222222-2222-4222-8222-222222222222"
	curatorPolicy    = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type curatorProjectReader struct{ project state.Project }

func (reader curatorProjectReader) Project(_ context.Context, tenantID, projectID string) (state.Project, bool, error) {
	return reader.project, reader.project.TenantID == tenantID && reader.project.ID == projectID, nil
}

type curatorScopeResolver struct{ project authz.ProjectScope }

func (resolver curatorScopeResolver) ResolveProject(_ context.Context, tenantID, projectID string) (authz.ProjectScope, error) {
	if resolver.project.TenantID != tenantID || resolver.project.ID != projectID {
		return authz.ProjectScope{}, context.Canceled
	}
	return resolver.project, nil
}

type curatorAllowPolicy struct{}

func (curatorAllowPolicy) Evaluate(context.Context, authz.PolicyInput) (authz.PolicyDecision, error) {
	return authz.PolicyDecision{
		Decision: authz.DecisionAllow, PolicyVersion: curatorPolicy,
		ReasonCodes: []string{"TEST_ALLOWED"}, RuleID: "aor.test.allow",
	}, nil
}

type curatorInvoker struct{ output draftOutput }

func (invoker curatorInvoker) Invoke(_ context.Context, request goalplan.AgentInvocation) (goalplan.AgentRecord, error) {
	payload, err := json.Marshal(invoker.output)
	if err != nil {
		return goalplan.AgentRecord{}, err
	}
	return goalplan.AgentRecord{
		RunID: request.InvocationID, AgentInstanceID: request.ProjectID + ":" + authn.RoleKnowledgeCurator,
		Role: agentruntime.RoleKnowledgeCurator, Payload: payload,
	}, nil
}

type curatorLeaseIssuer struct {
	now   time.Time
	calls int
}

func (issuer *curatorLeaseIssuer) Issue(_ context.Context, principal authn.Principal, request leaseauthority.GrantRequest) (authz.CapabilityLease, error) {
	issuer.calls++
	return authz.CapabilityLease{
		ID: "33333333-3333-4333-8333-333333333333", AgentInstanceID: principal.ID,
		PrincipalID: principal.ID, PrincipalType: principal.Type, TenantID: request.TenantID, ProjectID: request.ProjectID,
		ProjectVersion: 7, Role: principal.Role, Action: request.Action, Resource: request.Resource,
		ParameterDigest: request.ParameterDigest, Capabilities: []string{request.Action}, PolicyVersion: curatorPolicy,
		BudgetAccountID: request.BudgetAccountID, IssuedAt: issuer.now, ExpiresAt: issuer.now.Add(5 * time.Minute),
		LastHeartbeatAt: issuer.now, HeartbeatIntervalSeconds: agentruntime.DefaultHeartbeatSeconds,
		Nonce:        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		FencingToken: 1, State: authz.LeaseActive, Signature: "hmac-sha256:test",
	}, nil
}

func TestCuratorDraftApprovalAndApplyAreExactAndIdempotent(t *testing.T) {
	ctx := context.Background()
	store := eventing.NewMemoryStore()
	repository, err := knowledge.NewFileRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := repository.Initialize(ctx, curatorTenantID, curatorProjectID, curatorTestNow)
	if err != nil {
		t.Fatal(err)
	}
	scope := authz.ProjectScope{
		TenantID: curatorTenantID, ID: curatorProjectID, State: string(contracts.ProjectExecuting),
		StateVersion: 7, Classification: "INTERNAL",
	}
	signer, err := knowledge.NewHMACKnowledgeUpdatedSigner([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := knowledge.NewEventKnowledgeUpdatedPublisher(store, signer, func() time.Time { return curatorTestNow })
	if err != nil {
		t.Fatal(err)
	}
	knowledgeService, err := knowledge.NewService(knowledge.ServiceConfig{
		Repository: repository, Authorizer: curatorAllowPolicy{}, Scopes: curatorScopeResolver{project: scope},
		Events: publisher, Clock: func() time.Time { return curatorTestNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := goalplan.NewEventArtifactStore(store, func() time.Time { return curatorTestNow })
	if err != nil {
		t.Fatal(err)
	}
	proposal := Proposal{
		BaseRevision: baseline.Revision, Parents: []knowledge.ParentSnapshot{}, Overrides: []string{},
		Documents: []Document{{
			Path: "architecture/authentication.md", Title: "Authentication", Tags: []string{"security"},
			TrustLevel: knowledge.TrustCurated, ContentType: "text/markdown", Content: "# Authentication\n\nDeny by default.\n",
			Source: &knowledge.SourceReference{URI: "https://docs.example/authentication", Revision: "git:0123456789abcdef0123456789abcdef01234567", SHA256: "sha256:" + strings.Repeat("a", 64), TrustLevel: knowledge.TrustCurated},
		}}, DeletePaths: []string{},
	}
	leases := &curatorLeaseIssuer{now: curatorTestNow}
	project := state.Project{
		TenantID: curatorTenantID, ID: curatorProjectID, Version: 7, State: contracts.ProjectExecuting,
		DataClassification: "INTERNAL",
	}
	service, err := New(Config{
		Store: store, Updates: publisher, Artifacts: artifacts, Projects: curatorProjectReader{project: project},
		Knowledge: knowledgeService, Invoker: curatorInvoker{output: draftOutput{Proposal: proposal, ChangeSummary: "Add the authentication architecture."}},
		Leases: leases, Clock: func() time.Time { return curatorTestNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	user := authn.Principal{ID: "user_1", Type: authn.PrincipalUser, Role: "USER", TenantID: curatorTenantID}
	agent := authn.Principal{
		ID: curatorProjectID + ":" + authn.RoleKnowledgeCurator, Type: authn.PrincipalKnowledgeCurator,
		Role: authn.RoleKnowledgeCurator, TenantID: curatorTenantID, ProjectID: curatorProjectID,
	}
	if _, err := service.Draft(ctx, DraftRequest{
		Principal: agent, TenantID: curatorTenantID, ProjectID: curatorProjectID,
		ExpectedProjectVersion: 7, IdempotencyKey: "agent-draft", Instruction: "Write directly.", Proposal: proposal,
	}); err == nil {
		t.Fatal("knowledge curator bypassed the human command boundary")
	}
	draft, err := service.Draft(ctx, DraftRequest{
		Principal: user, TenantID: curatorTenantID, ProjectID: curatorProjectID,
		ExpectedProjectVersion: 7, IdempotencyKey: "draft-1", Instruction: "Add the approved authentication architecture.",
		Proposal: proposal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if draft.Status != StatusDraft || draft.ProposalDigest == "" || draft.Proposal.Documents[0].Content != proposal.Documents[0].Content || !draft.Validation.Passed || knowledge.ValidateValidationReport(draft.Validation) != nil {
		t.Fatalf("draft = %#v", draft)
	}
	loaded, err := service.Get(ctx, user, curatorTenantID, curatorProjectID, draft.UpdateID)
	if err != nil || loaded.Status != StatusDraft {
		t.Fatalf("loaded draft = %#v err=%v", loaded, err)
	}
	boundElsewhere := user
	boundElsewhere.ProjectID = "44444444-4444-4444-8444-444444444444"
	if _, err := service.Get(ctx, boundElsewhere, curatorTenantID, curatorProjectID, draft.UpdateID); err == nil {
		t.Fatal("project-bound principal read a different project's draft")
	}
	applied, err := service.Approve(ctx, ApprovalRequest{
		Principal: user, TenantID: curatorTenantID, ProjectID: curatorProjectID, UpdateID: draft.UpdateID,
		ExpectedProjectVersion: 7, ProposalDigest: draft.ProposalDigest,
		Reason: "Reviewed exact content and approve publication.", IdempotencyKey: "approve-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != StatusApplied || applied.ApprovalID != draft.UpdateID || applied.Revision == "" || leases.calls != 1 {
		t.Fatalf("applied = %#v lease calls=%d", applied, leases.calls)
	}
	if stats := store.Stats(); stats.Approvals != 1 {
		t.Fatalf("approval stats = %#v", stats)
	}
	events, err := store.ListEvents(ctx, curatorTenantID)
	if err != nil {
		t.Fatal(err)
	}
	approvalExternalized := false
	for _, event := range events {
		if event.Type != approvalEventType {
			continue
		}
		external, externalErr := eventing.Externalize(event, eventing.CloudEventOptions{Source: "https://aor.test/control"})
		if externalErr != nil {
			t.Fatal(externalErr)
		}
		if external.Subject != "projects/"+curatorProjectID+"/approvals/"+draft.UpdateID {
			t.Fatalf("approval subject = %q", external.Subject)
		}
		approvalExternalized = true
	}
	if !approvalExternalized {
		t.Fatal("approval event was not persisted")
	}
	replayed, err := service.Approve(ctx, ApprovalRequest{
		Principal: user, TenantID: curatorTenantID, ProjectID: curatorProjectID, UpdateID: draft.UpdateID,
		ExpectedProjectVersion: 7, ProposalDigest: draft.ProposalDigest,
		Reason: "Reviewed exact content and approve publication.", IdempotencyKey: "approve-1",
	})
	if err != nil || replayed.Status != StatusApplied || replayed.Revision != applied.Revision || leases.calls != 1 {
		t.Fatalf("replayed = %#v err=%v lease calls=%d", replayed, err, leases.calls)
	}
	_, err = service.Approve(ctx, ApprovalRequest{
		Principal: user, TenantID: curatorTenantID, ProjectID: curatorProjectID, UpdateID: draft.UpdateID,
		ExpectedProjectVersion: 7, ProposalDigest: draft.ProposalDigest,
		Reason: "A different approval command.", IdempotencyKey: "approve-1",
	})
	var conflict *aorerrors.Error
	if !errors.As(err, &conflict) || conflict.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("changed approval replay error = %v", err)
	}
	_, err = service.Approve(ctx, ApprovalRequest{
		Principal: user, TenantID: curatorTenantID, ProjectID: curatorProjectID, UpdateID: draft.UpdateID,
		ExpectedProjectVersion: 7, ProposalDigest: draft.ProposalDigest,
		Reason: "Reviewed exact content and approve publication.", IdempotencyKey: "approve-2",
	})
	if !errors.As(err, &conflict) || conflict.Code != aorerrors.CodeIdempotencyConflict {
		t.Fatalf("new approval command error = %v", err)
	}
	manifest, err := knowledgeService.Manifest(ctx, knowledge.Access{Principal: user, TenantID: curatorTenantID, ProjectID: curatorProjectID}, "")
	if err != nil || manifest.Revision != applied.Revision || len(manifest.Documents) != 1 {
		t.Fatalf("manifest = %#v err=%v", manifest, err)
	}
}

var _ authz.PolicyEvaluator = curatorAllowPolicy{}
var _ knowledge.ScopeResolver = curatorScopeResolver{}
var _ AgentInvoker = curatorInvoker{}
var _ LeaseIssuer = (*curatorLeaseIssuer)(nil)
