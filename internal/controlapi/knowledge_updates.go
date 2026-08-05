package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/knowledgecurator"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type KnowledgeCuratorService interface {
	Draft(context.Context, knowledgecurator.DraftRequest) (knowledgecurator.Record, error)
	Get(context.Context, authn.Principal, string, string, string) (knowledgecurator.Record, error)
	Approve(context.Context, knowledgecurator.ApprovalRequest) (knowledgecurator.Record, error)
}

type knowledgeUpdateDraftBody struct {
	ExpectedVersion int64                     `json:"expectedVersion"`
	Instruction     string                    `json:"instruction"`
	Proposal        knowledgecurator.Proposal `json:"proposal"`
}

type knowledgeUpdateApprovalBody struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	ProposalDigest  string `json:"proposalDigest"`
	Reason          string `json:"reason"`
}

func (handler *Handler) proposeKnowledgeUpdate(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if handler.knowledgeCurator == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge curator"}))
		return
	}
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge update query"}))
		return
	}
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectCommand, "KNOWLEDGE_CHANGE", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body knowledgeUpdateDraftBody
	if err := decodeJSON(request, &body); err != nil || body.ExpectedVersion < 1 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge update draft"}))
		return
	}
	if body.ExpectedVersion != project.Version {
		writeError(response, request, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil))
		return
	}
	record, err := handler.knowledgeCurator.Draft(request.Context(), knowledgecurator.DraftRequest{
		Principal: principal, TenantID: principal.TenantID, ProjectID: projectID,
		ExpectedProjectVersion: body.ExpectedVersion, IdempotencyKey: idempotencyKey,
		Instruction: body.Instruction, Proposal: body.Proposal,
	})
	if err != nil {
		writeError(response, request, normalizeKnowledgeUpdateError(err))
		return
	}
	if record.TenantID != principal.TenantID || record.ProjectID != projectID || record.ProjectVersion != body.ExpectedVersion ||
		record.Status != knowledgecurator.StatusDraft || record.UpdateID == "" || record.ProposalDigest == "" || record.DraftSHA256 == "" {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "knowledge curator result"}))
		return
	}
	response.Header().Set("Location", "/v1/projects/"+projectID+"/knowledge/updates/"+record.UpdateID)
	writeKnowledgeUpdate(response, http.StatusCreated, record)
}

func (handler *Handler) getKnowledgeUpdate(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, updateID string) {
	if handler.knowledgeCurator == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge curator"}))
		return
	}
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge update query"}))
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionKnowledgeRead, "knowledge.update", updateID); err != nil {
		writeError(response, request, err)
		return
	}
	record, err := handler.knowledgeCurator.Get(request.Context(), principal, principal.TenantID, projectID, updateID)
	if err != nil {
		writeError(response, request, normalizeKnowledgeUpdateError(err))
		return
	}
	if record.TenantID != principal.TenantID || record.ProjectID != projectID || record.UpdateID != updateID || record.ProposalDigest == "" {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "knowledge curator result"}))
		return
	}
	writeKnowledgeUpdate(response, http.StatusOK, record)
}

func (handler *Handler) approveKnowledgeUpdate(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, updateID string) {
	if handler.knowledgeCurator == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge curator"}))
		return
	}
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge update query"}))
		return
	}
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectCommand, "KNOWLEDGE_CHANGE", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body knowledgeUpdateApprovalBody
	if err := decodeJSON(request, &body); err != nil || body.ExpectedVersion < 1 || body.ProposalDigest == "" || body.Reason == "" {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge update approval"}))
		return
	}
	if body.ExpectedVersion != project.Version {
		writeError(response, request, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil))
		return
	}
	record, err := handler.knowledgeCurator.Approve(request.Context(), knowledgecurator.ApprovalRequest{
		Principal: principal, TenantID: principal.TenantID, ProjectID: projectID, UpdateID: updateID,
		ExpectedProjectVersion: body.ExpectedVersion, ProposalDigest: body.ProposalDigest,
		Reason: body.Reason, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		writeError(response, request, normalizeKnowledgeUpdateError(err))
		return
	}
	if record.TenantID != principal.TenantID || record.ProjectID != projectID || record.UpdateID != updateID ||
		record.ProjectVersion != body.ExpectedVersion || record.ProposalDigest != body.ProposalDigest ||
		record.Status != knowledgecurator.StatusApplied || record.ApprovalID == "" || record.Revision == "" {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "knowledge curator result"}))
		return
	}
	writeKnowledgeUpdate(response, http.StatusOK, record)
}

func writeKnowledgeUpdate(response http.ResponseWriter, status int, record knowledgecurator.Record) {
	encoded, err := json.Marshal(record)
	if err == nil {
		if digest, digestErr := canonicaljson.Digest(encoded); digestErr == nil {
			response.Header().Set("ETag", `"`+digest+`"`)
		}
	}
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, status, record)
}

func normalizeKnowledgeUpdateError(err error) error {
	var typed *aorerrors.Error
	if errors.As(err, &typed) {
		return typed
	}
	return normalizeGoalPlanError(err)
}

var _ KnowledgeCuratorService = (*knowledgecurator.Service)(nil)
