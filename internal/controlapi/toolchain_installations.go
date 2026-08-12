package controlapi

import (
	"net/http"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/toolchain"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type toolchainInstallationPage struct {
	Items []toolchainInstallationBatchResource `json:"items"`
}

type toolchainInstallationBatchResource struct {
	ID              string                          `json:"id"`
	GoalSpecID      string                          `json:"goalSpecId"`
	GoalVersion     int                             `json:"goalVersion"`
	State           string                          `json:"state"`
	RecoveryAttempt int                             `json:"recoveryAttempt"`
	Installations   []toolchainInstallationResource `json:"installations"`
}

type toolchainInstallationResource struct {
	ID               string                      `json:"id"`
	Name             string                      `json:"name"`
	Version          string                      `json:"version"`
	Kind             string                      `json:"kind"`
	Platform         string                      `json:"platform"`
	Architecture     string                      `json:"architecture"`
	State            toolchain.InstallationState `json:"state"`
	Attempt          int                         `json:"attempt"`
	InventoryID      string                      `json:"inventoryId,omitempty"`
	LastErrorCode    string                      `json:"lastErrorCode,omitempty"`
	LastErrorMessage string                      `json:"lastErrorMessage,omitempty"`
	CreatedAt        time.Time                   `json:"createdAt"`
	UpdatedAt        time.Time                   `json:"updatedAt"`
}

func (handler *Handler) listToolchainInstallations(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "toolchain installation query"}))
		return
	}
	project, found, err := handler.orchestrator.Project(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if !found {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	if err := authorizeRead(request.Context(), handler.authorizer, principal, projectID, "project.read", "project", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	if handler.toolchainInstalls == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "toolchain installation queue"}))
		return
	}
	batches, err := handler.toolchainInstalls.ListProjectBatches(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "toolchain installation queue"}))
		return
	}
	page := toolchainInstallationPage{Items: make([]toolchainInstallationBatchResource, 0, len(batches))}
	for _, batch := range batches {
		installations, _, loadErr := handler.toolchainInstalls.ForGoal(request.Context(), principal.TenantID, projectID, batch.GoalSpecID, batch.GoalVersion)
		if loadErr != nil {
			writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", loadErr, map[string]any{"scope": "toolchain installation queue"}))
			return
		}
		item := toolchainInstallationBatchResource{
			ID: batch.ID, GoalSpecID: batch.GoalSpecID, GoalVersion: batch.GoalVersion,
			State: batch.State, RecoveryAttempt: batch.RecoveryAttempt,
			Installations: make([]toolchainInstallationResource, 0, len(installations)),
		}
		for _, installation := range installations {
			item.Installations = append(item.Installations, toolchainInstallationResource{
				ID: installation.ID, Name: installation.Tool.Name, Version: installation.Tool.Version,
				Kind: string(installation.Tool.Kind), Platform: string(installation.Tool.Platform), Architecture: installation.Tool.Architecture,
				State: installation.State, Attempt: installation.Attempt, InventoryID: installation.InventoryID,
				LastErrorCode: installation.LastErrorCode, LastErrorMessage: installation.LastErrorMessage,
				CreatedAt: installation.CreatedAt, UpdatedAt: installation.UpdatedAt,
			})
		}
		page.Items = append(page.Items, item)
	}
	writeVersionedPage(response, request, page)
}
