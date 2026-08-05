package knowledgecurator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

const (
	approvalAggregateType = "approval"
	approvalEventType     = "io.aor.knowledge.update-approved.v1"
	maximumInstruction    = 16 << 10
	approvalLifetime      = 15 * time.Minute
)

var allowedPathRoots = map[string]struct{}{
	"inherited": {}, "requirements": {}, "architecture": {}, "modules": {},
	"interfaces": {}, "decisions": {}, "prompts": {}, "workflows": {},
	"tools": {}, "security": {}, "operations": {}, "lessons": {},
}

type Config struct {
	Store     eventing.Store
	Updates   knowledge.KnowledgeUpdatedLookup
	Artifacts goalplan.ArtifactStore
	Projects  ProjectReader
	Knowledge KnowledgeService
	Invoker   AgentInvoker
	Leases    LeaseIssuer
	Clock     func() time.Time
	LeaseTTL  time.Duration
}

type Service struct {
	store     eventing.Store
	updates   knowledge.KnowledgeUpdatedLookup
	artifacts goalplan.ArtifactStore
	projects  ProjectReader
	knowledge KnowledgeService
	invoker   AgentInvoker
	leases    LeaseIssuer
	clock     func() time.Time
	leaseTTL  time.Duration
}

type draftOutput struct {
	Proposal
	ChangeSummary string `json:"changeSummary"`
}

type storedDraft struct {
	KnowledgeUpdateDraftVersion int                        `json:"knowledgeUpdateDraftVersion"`
	UpdateID                    string                     `json:"updateId"`
	TenantID                    string                     `json:"tenantId"`
	ProjectID                   string                     `json:"projectId"`
	ProjectVersion              int64                      `json:"projectVersion"`
	CurrentRevision             string                     `json:"currentRevision"`
	Proposal                    Proposal                   `json:"proposal"`
	ProposalDigest              string                     `json:"proposalDigest"`
	ChangeSummary               string                     `json:"changeSummary"`
	Validation                  knowledge.ValidationReport `json:"validationReport"`
	RequestURI                  string                     `json:"requestUri"`
	RequestSHA256               string                     `json:"requestSha256"`
	AgentInstanceID             string                     `json:"agentInstanceId"`
	SourceRunID                 string                     `json:"sourceRunId"`
}

type approvalState struct {
	KnowledgeApprovalVersion int            `json:"knowledgeApprovalVersion"`
	UpdateID                 string         `json:"updateId"`
	TenantID                 string         `json:"tenantId"`
	ProjectID                string         `json:"projectId"`
	ProjectVersion           int64          `json:"projectVersion"`
	ProposalDigest           string         `json:"proposalDigest"`
	DraftURI                 string         `json:"draftUri"`
	DraftSHA256              string         `json:"draftSha256"`
	Approval                 authz.Approval `json:"approval"`
}

type approvalEvent struct {
	ApprovalVersion  int            `json:"approvalVersion"`
	AggregateVersion int64          `json:"aggregateVersion"`
	ApprovalID       string         `json:"approvalId"`
	TenantID         string         `json:"tenantId"`
	ProjectID        string         `json:"projectId"`
	ApprovalType     string         `json:"approvalType"`
	SubjectType      string         `json:"subjectType"`
	SubjectID        string         `json:"subjectId"`
	SubjectVersion   int64          `json:"subjectVersion"`
	SubjectSHA256    string         `json:"subjectSha256"`
	PrincipalID      string         `json:"principalId"`
	Reason           string         `json:"reason"`
	Constraints      map[string]any `json:"constraints"`
	IssuedAt         time.Time      `json:"issuedAt"`
	ExpiresAt        time.Time      `json:"expiresAt"`
	Signature        string         `json:"signature"`
}

func New(config Config) (*Service, error) {
	if config.Store == nil || config.Updates == nil || config.Artifacts == nil || config.Projects == nil || config.Knowledge == nil || config.Invoker == nil || config.Leases == nil {
		return nil, invalid("knowledge curator configuration")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.LeaseTTL == 0 {
		config.LeaseTTL = 5 * time.Minute
	}
	if config.LeaseTTL < time.Minute || config.LeaseTTL > approvalLifetime {
		return nil, invalid("knowledge curator lease ttl")
	}
	return &Service{
		store: config.Store, updates: config.Updates, artifacts: config.Artifacts, projects: config.Projects,
		knowledge: config.Knowledge, invoker: config.Invoker, leases: config.Leases,
		clock: config.Clock, leaseTTL: config.LeaseTTL,
	}, nil
}

func (service *Service) Draft(ctx context.Context, request DraftRequest) (Record, error) {
	if service == nil || ctx == nil || !validCaller(request.Principal, request.TenantID, request.ProjectID) ||
		request.ExpectedProjectVersion < 1 || !validIdempotencyKey(request.IdempotencyKey) ||
		request.Instruction == "" || strings.TrimSpace(request.Instruction) != request.Instruction || len(request.Instruction) > maximumInstruction || strings.ContainsAny(request.Instruction, "\r\x00") {
		return Record{}, invalid("knowledge update draft")
	}
	project, found, err := service.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return Record{}, err
	}
	if !found {
		return Record{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if project.TenantID != request.TenantID || project.ID != request.ProjectID || project.Version != request.ExpectedProjectVersion {
		return Record{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
	}
	access := readAccess(request.Principal, request.TenantID, request.ProjectID)
	manifest, err := service.knowledge.Manifest(ctx, access, "")
	if err != nil {
		return Record{}, err
	}
	if manifest.TenantID != request.TenantID || manifest.ProjectID != request.ProjectID || request.Proposal.BaseRevision != manifest.Revision {
		return Record{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
	}
	if !sameParentConfiguration(request.Proposal, manifest) {
		return Record{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"scope": "knowledge inheritance"})
	}
	candidate, err := toKnowledgeProposal(request.Proposal)
	if err != nil || !proposalChangesManifest(request.Proposal, manifest) {
		if err != nil {
			return Record{}, err
		}
		return Record{}, invalid("empty knowledge update")
	}
	if _, err := service.knowledge.ValidateProposal(ctx, access, candidate); err != nil {
		return Record{}, err
	}
	updateID := stableUpdateID(request)
	requestContent, err := json.Marshal(struct {
		KnowledgeUpdateRequestVersion int                `json:"knowledgeUpdateRequestVersion"`
		ProjectID                     string             `json:"projectId"`
		ProjectVersion                int64              `json:"projectVersion"`
		Instruction                   string             `json:"instruction"`
		CurrentManifest               knowledge.Manifest `json:"currentManifest"`
		Proposal                      Proposal           `json:"proposal"`
	}{1, request.ProjectID, project.Version, request.Instruction, manifest, cloneProposal(request.Proposal)})
	if err != nil {
		return Record{}, err
	}
	requestArtifact, err := service.artifacts.Put(ctx, goalplan.SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: goalplan.ArtifactKnowledgeUpdateRequest,
		SpecID: updateID, Version: 1, MediaType: "application/json", Content: requestContent,
		CreatedBy: request.Principal.ID,
	})
	if err != nil {
		return Record{}, normalizeArtifactConflict(err)
	}
	runID := stableRunID(updateID)
	agent, err := service.invoker.Invoke(ctx, goalplan.AgentInvocation{
		InvocationID: runID, TenantID: request.TenantID, ProjectID: request.ProjectID,
		Role: agentruntime.RoleKnowledgeCurator, Stage: "KNOWLEDGE_UPDATE_DRAFT",
		Inputs: []goalplan.ArtifactPointer{{
			Kind: requestArtifact.Kind, SpecID: requestArtifact.SpecID, Version: requestArtifact.Version,
			URI: requestArtifact.URI, ContentSHA256: requestArtifact.ContentSHA256,
		}},
	})
	if err != nil {
		return Record{}, err
	}
	if agent.RunID != runID || agent.Role != agentruntime.RoleKnowledgeCurator || agent.AgentInstanceID != request.ProjectID+":"+authn.RoleKnowledgeCurator {
		return Record{}, goalplan.ErrAgentOutput
	}
	var output draftOutput
	if err := decodeStrict(agent.Payload, &output); err != nil || output.ChangeSummary == "" || strings.TrimSpace(output.ChangeSummary) != output.ChangeSummary || len(output.ChangeSummary) > 8192 || strings.ContainsAny(output.ChangeSummary, "\r\x00") || output.BaseRevision != manifest.Revision || !sameParentConfiguration(output.Proposal, manifest) || !sameSourceAttribution(request.Proposal, output.Proposal) {
		return Record{}, goalplan.ErrAgentOutput
	}
	draftProposal, err := toKnowledgeProposal(output.Proposal)
	if err != nil || !proposalChangesManifest(output.Proposal, manifest) {
		return Record{}, goalplan.ErrAgentOutput
	}
	validation, err := service.knowledge.ValidateProposal(ctx, access, draftProposal)
	if err != nil {
		return Record{}, err
	}
	stored := storedDraft{
		KnowledgeUpdateDraftVersion: 1, UpdateID: updateID, TenantID: request.TenantID,
		ProjectID: request.ProjectID, ProjectVersion: project.Version, CurrentRevision: manifest.Revision,
		Proposal: cloneProposal(output.Proposal), ProposalDigest: validation.Digest, ChangeSummary: output.ChangeSummary, Validation: validation.Report,
		RequestURI: requestArtifact.URI, RequestSHA256: requestArtifact.ArtifactSHA256,
		AgentInstanceID: agent.AgentInstanceID, SourceRunID: agent.RunID,
	}
	draftContent, err := json.Marshal(stored)
	if err != nil {
		return Record{}, err
	}
	draftArtifact, err := service.artifacts.Put(ctx, goalplan.SpecArtifact{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Kind: goalplan.ArtifactKnowledgeUpdateDraft,
		SpecID: updateID, Version: 1, MediaType: "application/json", Content: draftContent,
		CreatedBy: agent.AgentInstanceID, SourceRunID: agent.RunID,
	})
	if err != nil {
		return Record{}, normalizeArtifactConflict(err)
	}
	return recordForDraft(stored, draftArtifact), nil
}

func (service *Service) Get(ctx context.Context, principal authn.Principal, tenantID, projectID, updateID string) (Record, error) {
	if service == nil || ctx == nil || !validCaller(principal, tenantID, projectID) || !validUpdateID(updateID) {
		return Record{}, invalid("knowledge update lookup")
	}
	draft, artifact, err := service.loadDraft(ctx, tenantID, projectID, updateID)
	if err != nil {
		return Record{}, err
	}
	return service.recordState(ctx, draft, artifact)
}

func (service *Service) Approve(ctx context.Context, request ApprovalRequest) (Record, error) {
	if service == nil || ctx == nil || !validCaller(request.Principal, request.TenantID, request.ProjectID) ||
		!validUpdateID(request.UpdateID) || request.ExpectedProjectVersion < 1 || request.ProposalDigest == "" ||
		request.Reason == "" || strings.TrimSpace(request.Reason) != request.Reason || len(request.Reason) > 4096 || strings.ContainsAny(request.Reason, "\r\x00") || !validIdempotencyKey(request.IdempotencyKey) {
		return Record{}, invalid("knowledge update approval")
	}
	draft, artifact, err := service.loadDraft(ctx, request.TenantID, request.ProjectID, request.UpdateID)
	if err != nil {
		return Record{}, err
	}
	if draft.ProjectVersion != request.ExpectedProjectVersion || draft.ProposalDigest != request.ProposalDigest {
		return Record{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
	}
	project, found, err := service.projects.Project(ctx, request.TenantID, request.ProjectID)
	if err != nil {
		return Record{}, err
	}
	if !found {
		return Record{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if project.TenantID != request.TenantID || project.ID != request.ProjectID || project.Version != draft.ProjectVersion {
		return Record{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
	}
	requestDigest, err := approvalRequestDigest(request, draft)
	if err != nil {
		return Record{}, err
	}
	approval, replayed, err := service.lookupApprovalCommand(ctx, request, draft, requestDigest)
	if err != nil {
		return Record{}, err
	}
	if !replayed {
		if _, found, loadErr := service.loadApproval(ctx, draft); loadErr != nil {
			return Record{}, loadErr
		} else if found {
			return Record{}, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", map[string]any{"scope": "knowledge approval"})
		}
		approval, err = service.commitApproval(ctx, request, draft, artifact, requestDigest)
		if err != nil {
			return Record{}, err
		}
	}
	if applied, found, err := service.appliedEvent(ctx, draft); err != nil {
		return Record{}, err
	} else if found {
		return appliedRecord(draft, artifact, applied), nil
	}
	if !service.clock().UTC().Before(approval.Approval.ExpiresAt) {
		return Record{}, aorerrors.New(aorerrors.CodeApprovalRequired, "", nil)
	}
	proposal, err := toKnowledgeProposal(draft.Proposal)
	if err != nil {
		return Record{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	curator := authn.Principal{
		ID: request.ProjectID + ":" + authn.RoleKnowledgeCurator, Type: authn.PrincipalKnowledgeCurator,
		Role: authn.RoleKnowledgeCurator, TenantID: request.TenantID, ProjectID: request.ProjectID,
	}
	leaseContext, err := authn.ContextWithPrincipal(ctx, curator)
	if err != nil {
		return Record{}, err
	}
	resource := authz.Resource{Type: "KNOWLEDGE_CHANGE", ID: request.ProjectID}
	lease, err := service.leases.Issue(leaseContext, curator, leaseauthority.GrantRequest{
		TenantID: request.TenantID, ProjectID: request.ProjectID, Action: authz.ActionKnowledgeWrite,
		Resource: resource, ParameterDigest: draft.ProposalDigest, BudgetAccountID: request.ProjectID,
		ApprovalID: approval.Approval.ID, IdempotencyKey: "knowledge-write:" + request.UpdateID,
		TTL: service.leaseTTL, NotAfter: approval.Approval.ExpiresAt,
	})
	if err != nil {
		return Record{}, err
	}
	if lease.ValidateShape() != nil || lease.PrincipalID != curator.ID || lease.PrincipalType != curator.Type || lease.Role != curator.Role ||
		lease.TenantID != request.TenantID || lease.ProjectID != request.ProjectID || lease.ProjectVersion != project.Version ||
		lease.TaskID != "" || lease.Action != authz.ActionKnowledgeWrite || !reflect.DeepEqual(lease.Resource, resource) ||
		lease.ParameterDigest != draft.ProposalDigest || !service.clock().UTC().Before(lease.ExpiresAt) {
		return Record{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "knowledge write lease"})
	}
	result, err := service.knowledge.Update(leaseContext, knowledge.Access{
		Principal: curator, TenantID: request.TenantID, ProjectID: request.ProjectID,
		Lease:    &authz.LeaseReference{ID: lease.ID, ExpiresAt: lease.ExpiresAt, PolicyVersion: lease.PolicyVersion, FencingToken: lease.FencingToken},
		Approval: &approval.Approval, ParameterDigest: draft.ProposalDigest,
		BudgetAccountID: request.ProjectID, PolicyVersion: lease.PolicyVersion,
	}, proposal)
	if err != nil {
		if applied, found, loadErr := service.appliedEvent(ctx, draft); loadErr == nil && found {
			return appliedRecord(draft, artifact, applied), nil
		}
		return Record{}, err
	}
	if result.Digest != draft.ProposalDigest || result.Manifest.TenantID != request.TenantID || result.Manifest.ProjectID != request.ProjectID || result.Manifest.Revision == "" {
		return Record{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge update result"})
	}
	applied, found, err := service.appliedEvent(ctx, draft)
	if err != nil {
		return Record{}, err
	}
	if !found || applied.Revision != result.Manifest.Revision {
		return Record{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge update event"})
	}
	return appliedRecord(draft, artifact, applied), nil
}

func (service *Service) commitApproval(ctx context.Context, request ApprovalRequest, draft storedDraft, artifact goalplan.SpecArtifact, requestDigest string) (approvalState, error) {
	now := service.clock().UTC()
	approvalID := draft.UpdateID
	signature := approvalSignature(request, draft, now)
	approval := authz.Approval{
		ID: approvalID, TenantID: request.TenantID, ProjectID: request.ProjectID, PrincipalID: request.Principal.ID,
		SubjectType: "KNOWLEDGE_CHANGE", SubjectID: request.ProjectID, SubjectVersion: draft.ProjectVersion,
		SubjectDigest: draft.ProposalDigest, IssuedAt: now, ExpiresAt: now.Add(approvalLifetime), Signature: signature,
	}
	state := approvalState{
		KnowledgeApprovalVersion: 1, UpdateID: draft.UpdateID, TenantID: request.TenantID,
		ProjectID: request.ProjectID, ProjectVersion: draft.ProjectVersion, ProposalDigest: draft.ProposalDigest,
		DraftURI: artifact.URI, DraftSHA256: artifact.ArtifactSHA256, Approval: approval,
	}
	stateJSON, err := json.Marshal(state)
	if err != nil {
		return approvalState{}, err
	}
	eventPayload, err := json.Marshal(approvalEvent{
		ApprovalVersion: 1, AggregateVersion: 1, ApprovalID: approval.ID, TenantID: approval.TenantID, ProjectID: approval.ProjectID,
		ApprovalType: "PERMANENT_SIDE_EFFECT", SubjectType: approval.SubjectType, SubjectID: approval.SubjectID,
		SubjectVersion: approval.SubjectVersion, SubjectSHA256: approval.SubjectDigest, PrincipalID: approval.PrincipalID,
		Reason: request.Reason, Constraints: map[string]any{"draftUri": artifact.URI, "proposalDigest": draft.ProposalDigest},
		IssuedAt: approval.IssuedAt, ExpiresAt: approval.ExpiresAt, Signature: approval.Signature,
	})
	if err != nil {
		return approvalState{}, err
	}
	stateDigest, err := canonicaljson.Digest(stateJSON)
	if err != nil {
		return approvalState{}, err
	}
	eventDigest, err := canonicaljson.Digest(eventPayload)
	if err != nil {
		return approvalState{}, err
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return approvalState{}, err
	}
	traceparent, tracestate, err := eventTrace(ctx)
	if err != nil {
		return approvalState{}, err
	}
	expiresAt := approval.ExpiresAt
	transaction, err := service.store.Execute(ctx, eventing.TransactionRequest{
		TenantID: request.TenantID, PrincipalID: request.Principal.ID,
		IdempotencyKey: approvalCommandKey(request.IdempotencyKey), RequestSHA256: requestDigest,
		Updates: []eventing.ProjectionUpdate{{
			TenantID: request.TenantID, ProjectID: request.ProjectID, AggregateType: approvalAggregateType,
			AggregateID: draft.UpdateID, ExpectedVersion: 0, NextVersion: 1, State: stateJSON,
		}},
		Events: []eventing.DomainEvent{{
			EventID: eventID.String(), TenantID: request.TenantID, ProjectID: request.ProjectID,
			AggregateType: approvalAggregateType, AggregateID: draft.UpdateID, AggregateVersion: 1,
			Type: approvalEventType, Payload: eventPayload, PayloadSHA256: eventDigest, OccurredAt: now,
			CorrelationID: "corr_" + strings.ReplaceAll(draft.UpdateID, "-", ""), CausationID: draft.SourceRunID,
			Traceparent: traceparent, Tracestate: tracestate, TaskIDReason: "NOT_APPLICABLE", AgentRunReason: "NOT_APPLICABLE",
		}},
		Approvals: []eventing.ApprovalRecord{{
			ID: approval.ID, TenantID: approval.TenantID, ProjectID: approval.ProjectID,
			ApprovalType: "PERMANENT_SIDE_EFFECT", SubjectType: approval.SubjectType, SubjectID: approval.SubjectID,
			SubjectVersion: int(approval.SubjectVersion), SubjectSHA256: approval.SubjectDigest,
			PrincipalID: approval.PrincipalID, Reason: request.Reason, IssuedAt: approval.IssuedAt,
			ExpiresAt: &expiresAt, Signature: approval.Signature,
		}},
		Result: stateJSON, ResultSHA256: stateDigest,
	})
	if err != nil {
		if recovered, found, loadErr := service.lookupApprovalCommand(ctx, request, draft, requestDigest); loadErr == nil && found {
			return recovered, nil
		}
		return approvalState{}, err
	}
	var committed approvalState
	if err := decodeStrict(transaction.Result, &committed); err != nil || !sameApprovalState(committed, state) {
		return approvalState{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge approval result"})
	}
	return committed, nil
}

func (service *Service) lookupApprovalCommand(ctx context.Context, request ApprovalRequest, draft storedDraft, requestDigest string) (approvalState, bool, error) {
	result, found, err := service.store.Lookup(ctx, request.TenantID, request.Principal.ID, approvalCommandKey(request.IdempotencyKey), requestDigest)
	if err != nil || !found {
		return approvalState{}, found, err
	}
	var state approvalState
	if decodeStrict(result.Result, &state) != nil || validateApprovalState(state, draft) != nil || state.Approval.PrincipalID != request.Principal.ID {
		return approvalState{}, false, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge approval replay"})
	}
	return state, true, nil
}

func (service *Service) loadDraft(ctx context.Context, tenantID, projectID, updateID string) (storedDraft, goalplan.SpecArtifact, error) {
	artifact, found, err := service.artifacts.Get(ctx, tenantID, projectID, goalplan.ArtifactKnowledgeUpdateDraft, updateID, 1)
	if err != nil {
		return storedDraft{}, goalplan.SpecArtifact{}, err
	}
	if !found {
		return storedDraft{}, goalplan.SpecArtifact{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	var draft storedDraft
	if err := decodeStrict(artifact.Content, &draft); err != nil || draft.KnowledgeUpdateDraftVersion != 1 ||
		draft.UpdateID != updateID || draft.TenantID != tenantID || draft.ProjectID != projectID || draft.ProjectVersion < 1 ||
		draft.CurrentRevision != draft.Proposal.BaseRevision || draft.ProposalDigest == "" || draft.ChangeSummary == "" ||
		draft.AgentInstanceID != projectID+":"+authn.RoleKnowledgeCurator || draft.SourceRunID == "" {
		return storedDraft{}, goalplan.SpecArtifact{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge update draft"})
	}
	proposal, err := toKnowledgeProposal(draft.Proposal)
	if err != nil {
		return storedDraft{}, goalplan.SpecArtifact{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge update proposal"})
	}
	digest, err := knowledge.ProposalDigest(proposal)
	if err != nil || digest != draft.ProposalDigest {
		return storedDraft{}, goalplan.SpecArtifact{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge update proposal"})
	}
	if draft.Validation.ProposalDigest != draft.ProposalDigest || !draft.Validation.Passed || knowledge.ValidateValidationReport(draft.Validation) != nil {
		return storedDraft{}, goalplan.SpecArtifact{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge validation report"})
	}
	return draft, artifact, nil
}

func (service *Service) loadApproval(ctx context.Context, draft storedDraft) (approvalState, bool, error) {
	projection, found, err := service.store.Load(ctx, draft.TenantID, approvalAggregateType, draft.UpdateID)
	if err != nil || !found {
		return approvalState{}, found, err
	}
	var state approvalState
	if projection.TenantID != draft.TenantID || projection.ProjectID != draft.ProjectID || projection.AggregateType != approvalAggregateType ||
		projection.AggregateID != draft.UpdateID || projection.Version != 1 || decodeStrict(projection.State, &state) != nil || validateApprovalState(state, draft) != nil {
		return approvalState{}, false, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge approval projection"})
	}
	return state, true, nil
}

func validateApprovalState(state approvalState, draft storedDraft) error {
	if state.KnowledgeApprovalVersion != 1 || state.UpdateID != draft.UpdateID || state.TenantID != draft.TenantID ||
		state.ProjectID != draft.ProjectID || state.ProjectVersion != draft.ProjectVersion || state.ProposalDigest != draft.ProposalDigest ||
		state.DraftURI == "" || state.DraftSHA256 == "" || state.Approval.ID != draft.UpdateID ||
		state.Approval.TenantID != draft.TenantID || state.Approval.ProjectID != draft.ProjectID || state.Approval.PrincipalID == "" ||
		state.Approval.SubjectType != "KNOWLEDGE_CHANGE" || state.Approval.SubjectID != draft.ProjectID ||
		state.Approval.SubjectVersion != draft.ProjectVersion || state.Approval.SubjectDigest != draft.ProposalDigest ||
		state.Approval.IssuedAt.IsZero() || !state.Approval.ExpiresAt.After(state.Approval.IssuedAt) || state.Approval.Signature == "" {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge approval state"})
	}
	return nil
}

func (service *Service) appliedEvent(ctx context.Context, draft storedDraft) (knowledge.KnowledgeUpdatedEvent, bool, error) {
	return service.updates.Find(ctx, draft.TenantID, draft.ProjectID, draft.ProposalDigest, draft.UpdateID)
}

func (service *Service) recordState(ctx context.Context, draft storedDraft, artifact goalplan.SpecArtifact) (Record, error) {
	if applied, found, err := service.appliedEvent(ctx, draft); err != nil {
		return Record{}, err
	} else if found {
		return appliedRecord(draft, artifact, applied), nil
	}
	approval, found, err := service.loadApproval(ctx, draft)
	if err != nil {
		return Record{}, err
	}
	record := recordForDraft(draft, artifact)
	if found {
		record.Status = StatusApproved
		record.ApprovalID = approval.Approval.ID
		approvedAt := approval.Approval.IssuedAt
		record.ApprovedAt = &approvedAt
	}
	return record, nil
}

func recordForDraft(draft storedDraft, artifact goalplan.SpecArtifact) Record {
	return Record{
		UpdateID: draft.UpdateID, TenantID: draft.TenantID, ProjectID: draft.ProjectID,
		ProjectVersion: draft.ProjectVersion, Status: StatusDraft, ProposalDigest: draft.ProposalDigest,
		ChangeSummary: draft.ChangeSummary, Validation: draft.Validation, Proposal: cloneProposal(draft.Proposal), DraftURI: artifact.URI, DraftSHA256: artifact.ArtifactSHA256,
		SourceRunID: draft.SourceRunID, CreatedAt: artifact.CreatedAt,
	}
}

func appliedRecord(draft storedDraft, artifact goalplan.SpecArtifact, event knowledge.KnowledgeUpdatedEvent) Record {
	record := recordForDraft(draft, artifact)
	record.Status, record.ApprovalID, record.Revision = StatusApplied, event.ApprovalID, event.Revision
	appliedAt := event.OccurredAt
	record.AppliedAt = &appliedAt
	return record
}

func toKnowledgeProposal(input Proposal) (knowledge.UpdateProposal, error) {
	output := knowledge.UpdateProposal{
		BaseRevision: input.BaseRevision, ParentOrderExplicit: input.ParentOrderExplicit,
		Parents:   append([]knowledge.ParentSnapshot(nil), input.Parents...),
		Overrides: append([]string(nil), input.Overrides...), DeletePaths: append([]string(nil), input.DeletePaths...),
		Documents: make([]knowledge.DocumentInput, len(input.Documents)),
	}
	for _, candidate := range append(append([]string(nil), input.Overrides...), input.DeletePaths...) {
		if !validKnowledgePath(candidate) {
			return knowledge.UpdateProposal{}, invalid("knowledge path")
		}
	}
	for index, document := range input.Documents {
		if !validKnowledgePath(document.Path) || !document.TrustLevel.Valid() || document.TrustLevel == knowledge.TrustSignedPolicy {
			return knowledge.UpdateProposal{}, invalid("knowledge document")
		}
		if document.Source != nil {
			if err := document.Source.Validate(); err != nil {
				return knowledge.UpdateProposal{}, invalid("knowledge source")
			}
		}
		if document.TrustLevel == knowledge.TrustCurated && (document.Source == nil || !document.Source.VerifiedFor(document.TrustLevel)) {
			return knowledge.UpdateProposal{}, invalid("curated knowledge source")
		}
		output.Documents[index] = knowledge.DocumentInput{
			Path: document.Path, Title: document.Title, Tags: append([]string(nil), document.Tags...),
			TrustLevel: document.TrustLevel, ContentType: document.ContentType, Content: []byte(document.Content), Source: cloneSource(document.Source),
		}
	}
	return output, nil
}

func proposalChangesManifest(proposal Proposal, manifest knowledge.Manifest) bool {
	if len(proposal.Documents) != 0 || len(proposal.DeletePaths) != 0 || proposal.ParentOrderExplicit != manifest.ParentOrderExplicit {
		return true
	}
	return !reflect.DeepEqual(proposal.Parents, manifest.Parents) || !reflect.DeepEqual(proposal.Overrides, manifest.Overrides)
}

func sameParentConfiguration(proposal Proposal, manifest knowledge.Manifest) bool {
	if proposal.ParentOrderExplicit != manifest.ParentOrderExplicit || len(proposal.Parents) != len(manifest.Parents) {
		return false
	}
	for index := range proposal.Parents {
		if proposal.Parents[index] != manifest.Parents[index] {
			return false
		}
	}
	return true
}

func sameSourceAttribution(input, output Proposal) bool {
	provided := make(map[string]*knowledge.SourceReference, len(input.Documents))
	for _, document := range input.Documents {
		provided[document.Path] = document.Source
	}
	for _, document := range output.Documents {
		source, exists := provided[document.Path]
		if !exists || !sameSourceReference(source, document.Source) {
			return false
		}
	}
	return true
}

func sameSourceReference(left, right *knowledge.SourceReference) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validKnowledgePath(value string) bool {
	if value == "" || strings.ContainsRune(value, '\x00') || strings.ContainsRune(value, '\\') || path.Clean(value) != value || strings.HasPrefix(value, "/") {
		return false
	}
	root, remainder, found := strings.Cut(value, "/")
	_, allowed := allowedPathRoots[root]
	return found && allowed && remainder != ""
}

func cloneProposal(input Proposal) Proposal {
	output := input
	output.Parents = append([]knowledge.ParentSnapshot(nil), input.Parents...)
	output.Overrides = append([]string(nil), input.Overrides...)
	output.DeletePaths = append([]string(nil), input.DeletePaths...)
	output.Documents = make([]Document, len(input.Documents))
	for index, document := range input.Documents {
		document.Tags = append([]string(nil), document.Tags...)
		document.Source = cloneSource(document.Source)
		output.Documents[index] = document
	}
	return output
}

func cloneSource(input *knowledge.SourceReference) *knowledge.SourceReference {
	if input == nil {
		return nil
	}
	copySource := *input
	return &copySource
}

func stableUpdateID(request DraftRequest) string {
	value := strings.Join([]string{request.TenantID, request.ProjectID, request.Principal.ID, request.IdempotencyKey}, "\x00")
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(value)).String()
}

func stableRunID(updateID string) string {
	return "curator_" + strings.ReplaceAll(updateID, "-", "")
}

func approvalSignature(request ApprovalRequest, draft storedDraft, issuedAt time.Time) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{
		request.TenantID, request.ProjectID, draft.UpdateID, request.ProposalDigest,
		request.Principal.ID, request.Reason, request.IdempotencyKey, issuedAt.Format(time.RFC3339Nano),
	}, "\x00")))
	return "oidc-sha256:" + hex.EncodeToString(digest[:])
}

func approvalRequestDigest(request ApprovalRequest, draft storedDraft) (string, error) {
	encoded, err := json.Marshal(struct {
		TenantID               string `json:"tenantId"`
		ProjectID              string `json:"projectId"`
		UpdateID               string `json:"updateId"`
		ExpectedProjectVersion int64  `json:"expectedProjectVersion"`
		ProposalDigest         string `json:"proposalDigest"`
		PrincipalID            string `json:"principalId"`
		Reason                 string `json:"reason"`
	}{
		TenantID: request.TenantID, ProjectID: request.ProjectID, UpdateID: draft.UpdateID,
		ExpectedProjectVersion: request.ExpectedProjectVersion, ProposalDigest: draft.ProposalDigest,
		PrincipalID: request.Principal.ID, Reason: request.Reason,
	})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func approvalCommandKey(idempotencyKey string) string {
	return "knowledge-approval:" + idempotencyKey
}

func readAccess(principal authn.Principal, tenantID, projectID string) knowledge.Access {
	return knowledge.Access{Principal: principal, TenantID: tenantID, ProjectID: projectID}
}

func eventTrace(ctx context.Context) (string, string, error) {
	trace, ok := observability.TraceFromContext(ctx)
	if !ok {
		var err error
		trace, err = observability.NewRootTraceContext(false)
		if err != nil {
			return "", "", err
		}
	}
	traceparent, err := trace.TraceParent()
	return traceparent, trace.TraceState, err
}

func decodeStrict(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return invalid("trailing json")
	}
	return nil
}

func validCaller(principal authn.Principal, tenantID, projectID string) bool {
	return principal.Validate() == nil && (principal.Type == authn.PrincipalUser || principal.Type == authn.PrincipalBreakGlassAdmin) &&
		tenantID != "" && projectID != "" &&
		(principal.TenantID == "" || principal.TenantID == tenantID) &&
		(principal.ProjectID == "" || principal.ProjectID == projectID)
}

func validIdempotencyKey(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func validUpdateID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}

func sameApprovalState(left, right approvalState) bool {
	return reflect.DeepEqual(left, right)
}

func normalizeArtifactConflict(err error) error {
	if errors.Is(err, goalplan.ErrArtifactConflict) {
		return aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
	}
	return err
}

func invalid(scope string) error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": scope})
}
