package controlapi

import (
	"encoding/json"
	"net/http"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type modelSamplingSettingsBody struct {
	Temperature     float64 `json:"temperature"`
	TopP            float64 `json:"topP"`
	TopK            int     `json:"topK"`
	ReasoningEffort string  `json:"reasoningEffort"`
}

func (body modelSamplingSettingsBody) settings() modelgateway.SamplingSettings {
	return modelgateway.SamplingSettings{
		Temperature: body.Temperature, TopP: body.TopP, TopK: body.TopK, ReasoningEffort: body.ReasoningEffort,
	}
}

func (handler *Handler) getModelSamplingSettings(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, invalidModelSamplingSettings())
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsRead, "model-sampling-settings", ""); err != nil {
		writeError(response, request, err)
		return
	}
	settings, found, err := handler.modelSamplingSettings.Get(request.Context(), principal.TenantID)
	if err != nil {
		writeError(response, request, unavailableModelSamplingSettings(err))
		return
	}
	if !found {
		settings = modelgateway.DefaultSamplingSettings()
	}
	writeModelSamplingSettings(response, http.StatusOK, settings)
}

func (handler *Handler) putModelSamplingSettings(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, invalidModelSamplingSettings())
		return
	}
	var body modelSamplingSettingsBody
	if decodeJSON(request, &body) != nil {
		writeError(response, request, invalidModelSamplingSettings())
		return
	}
	settings := body.settings()
	if modelgateway.ValidateSamplingSettings(settings) != nil {
		writeError(response, request, invalidModelSamplingSettings())
		return
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "model sampling settings"}))
		return
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		writeError(response, request, invalidModelSamplingSettings())
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsWrite, "model-sampling-settings", digest); err != nil {
		writeError(response, request, err)
		return
	}
	if err := handler.ensureTenant(request.Context(), principal.TenantID); err != nil {
		writeError(response, request, err)
		return
	}
	settings, err = handler.modelSamplingSettings.Put(request.Context(), principal.TenantID, settings)
	if err != nil {
		writeError(response, request, unavailableModelSamplingSettings(err))
		return
	}
	writeModelSamplingSettings(response, http.StatusOK, settings)
}

func writeModelSamplingSettings(response http.ResponseWriter, status int, settings modelgateway.SamplingSettings) {
	response.Header().Set("ETag", entityTag(settings.Version))
	writeJSON(response, status, settings)
}

func invalidModelSamplingSettings() error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "model sampling settings"})
}

func unavailableModelSamplingSettings(cause error) error {
	return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", cause, map[string]any{"scope": "model sampling settings"})
}
