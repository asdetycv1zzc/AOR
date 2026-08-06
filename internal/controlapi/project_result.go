package controlapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/state"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const (
	projectResultPending     = "PENDING"
	projectResultSummarizing = "SUMMARIZING"
	projectResultCompleted   = "COMPLETED"
)

type projectResultResource struct {
	Status                string                          `json:"status"`
	CoreSummary           *state.CoreSummary              `json:"coreSummary,omitempty"`
	PlanSupervisorSummary *goalplan.PlanCompletionSummary `json:"planSupervisorSummary,omitempty"`
	ArtifactRef           string                          `json:"artifactRef,omitempty"`
}

func (handler *Handler) getProjectResult(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectRead, "project-result", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	result := projectResultResource{Status: projectResultPending}
	if project.CoreSummary == nil {
		writeJSON(response, http.StatusOK, result)
		return
	}
	coreSummary := *project.CoreSummary
	coreSummary.Modules = append([]state.CoreModuleOutcome(nil), project.CoreSummary.Modules...)
	result.Status = projectResultSummarizing
	result.CoreSummary = &coreSummary

	artifact, summary, found, err := handler.findPlanCompletion(request.Context(), principal.TenantID, project)
	if err != nil {
		writeError(response, request, err)
		return
	}
	if !found {
		writeJSON(response, http.StatusOK, result)
		return
	}
	result.Status = projectResultCompleted
	result.PlanSupervisorSummary = &summary
	result.ArtifactRef = artifact.URI
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) findPlanCompletion(ctx context.Context, tenantID string, project state.Project) (goalplan.SpecArtifact, goalplan.PlanCompletionSummary, bool, error) {
	lister, ok := handler.store.(eventing.ProjectionList)
	if !ok {
		return goalplan.SpecArtifact{}, goalplan.PlanCompletionSummary{}, false, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "project result projection"})
	}
	if project.Plan == nil || project.CoreSummary == nil {
		return goalplan.SpecArtifact{}, goalplan.PlanCompletionSummary{}, false, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "project result state"})
	}
	projections, err := lister.ListProjections(ctx, tenantID, project.ID, "spec_artifact")
	if err != nil {
		return goalplan.SpecArtifact{}, goalplan.PlanCompletionSummary{}, false, normalizeError(err)
	}

	var result goalplan.SpecArtifact
	var summary goalplan.PlanCompletionSummary
	found := false
	for _, projection := range projections {
		var artifact goalplan.SpecArtifact
		if json.Unmarshal(projection.State, &artifact) != nil || artifact.Kind != goalplan.ArtifactPlanCompletion {
			continue
		}
		if artifact.TenantID != tenantID || artifact.ProjectID != project.ID {
			return goalplan.SpecArtifact{}, goalplan.PlanCompletionSummary{}, false, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "plan completion projection"})
		}
		if artifact.SpecID != goalplan.PlanCompletionSpecID(project.ID) || artifact.Version != project.Plan.Version {
			continue
		}
		var candidate goalplan.PlanCompletionSummary
		if json.Unmarshal(artifact.Content, &candidate) != nil || !validPlanCompletionResult(artifact, candidate, project) || found {
			return goalplan.SpecArtifact{}, goalplan.PlanCompletionSummary{}, false, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "plan completion projection"})
		}
		result, summary, found = artifact, candidate, true
	}
	return result, summary, found, nil
}

func validPlanCompletionResult(artifact goalplan.SpecArtifact, summary goalplan.PlanCompletionSummary, project state.Project) bool {
	core := project.CoreSummary
	return core != nil && artifact.URI != "" && summary.TenantID == project.TenantID && summary.ProjectID == project.ID && summary.Status == projectResultCompleted && summary.GoalSpecRef == core.GoalSpecRef && summary.PlanSpecRef == core.PlanSpecRef && summary.CoreSummarySHA256 == core.SummarySHA256 && summary.SummarySHA256 == artifact.ContentSHA256
}
