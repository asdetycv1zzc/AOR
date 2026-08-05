package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/knowledgecurator"
)

const controlKnowledgeUpdateID = "33333333-3333-5333-8333-333333333333"

type recordingKnowledgeCurator struct {
	draftRequest    knowledgecurator.DraftRequest
	approvalRequest knowledgecurator.ApprovalRequest
	record          knowledgecurator.Record
}

func (service *recordingKnowledgeCurator) Draft(_ context.Context, request knowledgecurator.DraftRequest) (knowledgecurator.Record, error) {
	service.draftRequest = request
	record := service.record
	record.UpdateID, record.TenantID, record.ProjectID = controlKnowledgeUpdateID, request.TenantID, request.ProjectID
	record.ProjectVersion, record.Status = request.ExpectedProjectVersion, knowledgecurator.StatusDraft
	return record, nil
}

func (service *recordingKnowledgeCurator) Get(_ context.Context, _ authn.Principal, tenantID, projectID, updateID string) (knowledgecurator.Record, error) {
	record := service.record
	record.UpdateID, record.TenantID, record.ProjectID = updateID, tenantID, projectID
	record.Status = knowledgecurator.StatusDraft
	return record, nil
}

func (service *recordingKnowledgeCurator) Approve(_ context.Context, request knowledgecurator.ApprovalRequest) (knowledgecurator.Record, error) {
	service.approvalRequest = request
	record := service.record
	record.UpdateID, record.TenantID, record.ProjectID = request.UpdateID, request.TenantID, request.ProjectID
	record.ProjectVersion, record.ProposalDigest = request.ExpectedProjectVersion, request.ProposalDigest
	record.Status, record.ApprovalID = knowledgecurator.StatusApplied, request.UpdateID
	record.Revision = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	return record, nil
}

func TestKnowledgeUpdateAPIBindsDraftAndApproval(t *testing.T) {
	handler, _, authorizer := newTestHandler(t)
	project := createTestProject(t, handler)
	proposalDigest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	curator := &recordingKnowledgeCurator{record: knowledgecurator.Record{
		ProposalDigest: proposalDigest, ChangeSummary: "Add architecture guidance.",
		Proposal: knowledgecurator.Proposal{
			BaseRevision: proposalDigest, Parents: []knowledge.ParentSnapshot{}, Overrides: []string{},
			Documents: []knowledgecurator.Document{{
				Path: "architecture/auth.md", Title: "Authentication", Tags: []string{},
				TrustLevel: knowledge.TrustCurated, ContentType: "text/markdown", Content: "# Authentication\n",
			}}, DeletePaths: []string{},
		},
		DraftURI:    "artifact://sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DraftSHA256: proposalDigest, SourceRunID: "curator_run", CreatedAt: controlAPITestTime,
	}}
	handler.knowledgeCurator = curator
	draftBody, err := json.Marshal(knowledgeUpdateDraftBody{
		ExpectedVersion: project.Version, Instruction: "Add authentication guidance.", Proposal: curator.record.Proposal,
	})
	if err != nil {
		t.Fatal(err)
	}
	drafted := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/knowledge:propose-update", draftBody, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "knowledge-draft-1",
	})
	if drafted.Code != http.StatusCreated || drafted.Header().Get("Location") != "/v1/projects/"+project.ID+"/knowledge/updates/"+controlKnowledgeUpdateID || drafted.Header().Get("ETag") == "" {
		t.Fatalf("draft status=%d headers=%v body=%s", drafted.Code, drafted.Header(), drafted.Body.String())
	}
	if curator.draftRequest.ProjectID != project.ID || curator.draftRequest.ExpectedProjectVersion != project.Version || curator.draftRequest.IdempotencyKey != "knowledge-draft-1" {
		t.Fatalf("draft request = %#v", curator.draftRequest)
	}
	read := performRequest(handler, http.MethodGet, "/v1/projects/"+project.ID+"/knowledge/updates/"+controlKnowledgeUpdateID, nil, map[string]string{
		"Authorization": "Bearer " + testBearer,
	})
	if read.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", read.Code, read.Body.String())
	}
	approvalBody, err := json.Marshal(knowledgeUpdateApprovalBody{
		ExpectedVersion: project.Version, ProposalDigest: proposalDigest, Reason: "Reviewed the exact draft.",
	})
	if err != nil {
		t.Fatal(err)
	}
	approved := performRequest(handler, http.MethodPost, "/v1/projects/"+project.ID+"/knowledge/updates/"+controlKnowledgeUpdateID+":approve", approvalBody, map[string]string{
		"Authorization": "Bearer " + testBearer, "Content-Type": "application/json", "Idempotency-Key": "knowledge-approve-1",
	})
	if approved.Code != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", approved.Code, approved.Body.String())
	}
	if curator.approvalRequest.UpdateID != controlKnowledgeUpdateID || curator.approvalRequest.ProposalDigest != proposalDigest || curator.approvalRequest.IdempotencyKey != "knowledge-approve-1" {
		t.Fatalf("approval request = %#v", curator.approvalRequest)
	}
	foundCommand, foundRead := false, false
	for _, input := range authorizer.inputs {
		foundCommand = foundCommand || input.Action == "project.command" && input.Resource.Type == "KNOWLEDGE_CHANGE"
		foundRead = foundRead || input.Action == "knowledge.read" && input.Resource.ID == controlKnowledgeUpdateID
	}
	if !foundCommand || !foundRead {
		t.Fatalf("authorization inputs = %#v", authorizer.inputs)
	}
}

var _ KnowledgeCuratorService = (*recordingKnowledgeCurator)(nil)
