package goalplan

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

type knowledgeDraftDocument struct {
	Path        string   `json:"path"`
	Title       string   `json:"title"`
	Tags        []string `json:"tags"`
	TrustLevel  string   `json:"trustLevel"`
	ContentType string   `json:"contentType"`
	Content     string   `json:"content"`
}

type knowledgeDraftProposal struct {
	BaseRevision        string                     `json:"baseRevision"`
	ParentOrderExplicit bool                       `json:"parentOrderExplicit"`
	Parents             []knowledge.ParentSnapshot `json:"parents"`
	Overrides           []string                   `json:"overrides"`
	Documents           []knowledgeDraftDocument   `json:"documents"`
	DeletePaths         []string                   `json:"deletePaths"`
}

type knowledgeDraftOutput struct {
	knowledgeDraftProposal
	ChangeSummary string `json:"changeSummary"`
}

func goalDraftSemanticValidator(request AgentInvocation) func(json.RawMessage) error {
	return func(content json.RawMessage) error {
		_, _, err := normalizeGoalRecord(responseAgentRecord(request, content), request.ProjectID, 1, time.Unix(0, 0).UTC())
		return err
	}
}

func challengeSemanticValidator(request AgentInvocation, goalRef contracts.SpecRef) func(json.RawMessage) error {
	return func(content json.RawMessage) error {
		_, _, err := normalizeChallenge(responseAgentRecord(request, content), request.ProjectID, goalRef, time.Unix(0, 0).UTC())
		return err
	}
}

func planDraftSemanticValidator(request AgentInvocation, goalRef contracts.SpecRef) func(json.RawMessage) error {
	return func(content json.RawMessage) error {
		_, _, err := normalizePlanRecord(responseAgentRecord(request, content), request.ProjectID, goalRef, 1)
		return err
	}
}

func planCompletionSemanticValidator(core state.CoreSummary) func(json.RawMessage) error {
	return func(content json.RawMessage) error {
		var draft PlanCompletionDraft
		if err := decodeStrict(content, &draft); err != nil || !validPlanCompletionDraft(draft, core) {
			return ErrAgentOutput
		}
		return nil
	}
}

func moduleDraftSemanticValidator(request AgentInvocation, plan contracts.PlanSpec, planned contracts.PlanModule) func(json.RawMessage) error {
	return func(content json.RawMessage) error {
		_, _, err := normalizeModuleRecord(responseAgentRecord(request, content), request.ProjectID, plan, planned, 1)
		return err
	}
}

func responseAgentRecord(request AgentInvocation, content json.RawMessage) AgentRecord {
	return AgentRecord{
		RunID: request.InvocationID, AgentInstanceID: runtimeAgentID(request), Role: request.Role,
		Payload: append([]byte(nil), content...),
	}
}

func knowledgeDraftSemanticValidator(projectID string) func(json.RawMessage) error {
	return func(content json.RawMessage) error {
		var output knowledgeDraftOutput
		if err := decodeStrict(content, &output); err != nil || !validKnowledgeDraftOutput(output, projectID) {
			return ErrAgentOutput
		}
		return nil
	}
}

func validKnowledgeDraftOutput(output knowledgeDraftOutput, projectID string) bool {
	if strings.TrimSpace(output.ChangeSummary) != output.ChangeSummary || output.ChangeSummary == "" || strings.ContainsAny(output.ChangeSummary, "\r\x00") ||
		len(output.Parents) > 1 && !output.ParentOrderExplicit {
		return false
	}
	seenParents := make(map[string]struct{}, len(output.Parents))
	for index, parent := range output.Parents {
		if parent.ProjectID == projectID || parent.Order != index {
			return false
		}
		if _, duplicate := seenParents[parent.ProjectID]; duplicate {
			return false
		}
		seenParents[parent.ProjectID] = struct{}{}
	}
	if !uniqueKnowledgePaths(output.Overrides) || !uniqueKnowledgePaths(output.DeletePaths) {
		return false
	}
	deletedPaths := make(map[string]struct{}, len(output.DeletePaths))
	for _, candidate := range output.DeletePaths {
		deletedPaths[candidate] = struct{}{}
	}
	changedPaths := make(map[string]struct{}, len(output.Documents))
	for _, document := range output.Documents {
		if _, deleted := deletedPaths[document.Path]; deleted {
			return false
		}
		if _, duplicate := changedPaths[document.Path]; duplicate {
			return false
		}
		changedPaths[document.Path] = struct{}{}
	}
	return true
}

func uniqueKnowledgePaths(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
