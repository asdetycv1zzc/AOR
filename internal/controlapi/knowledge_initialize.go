package controlapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/state"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func (handler *Handler) initializeProjectKnowledge(request *http.Request, project state.Project) error {
	if handler == nil || request == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge initializer"})
	}
	if handler.knowledgeCuratorURL == "" {
		initializer, ok := handler.knowledge.(KnowledgeInitializer)
		if !ok {
			return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge initializer"})
		}
		if _, err := initializer.Initialize(request.Context(), project.TenantID, project.ID, handler.clock().UTC()); err != nil {
			return normalizeKnowledgeError(err)
		}
		return nil
	}

	target := handler.knowledgeCuratorURL + "/v1/projects/" + project.ID + "/knowledge:initialize"
	forward, err := http.NewRequestWithContext(request.Context(), http.MethodPost, target, http.NoBody)
	if err != nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge initializer"})
	}
	for _, name := range []string{"Authorization", "Traceparent", "Tracestate", "X-Request-ID"} {
		for _, value := range request.Header.Values(name) {
			forward.Header.Add(name, value)
		}
	}
	forward.Header.Set("Idempotency-Key", "knowledge-init-"+project.ID)
	forward.Header.Set(curatorForwardedHeader, "aor-api")
	client := handler.knowledgeCuratorHTTP
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(forward)
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "knowledge initializer"})
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumCuratorResponseBytes+1))
	if err != nil || len(body) > maximumCuratorResponseBytes || response.StatusCode != http.StatusOK {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge initializer"})
	}
	var manifest knowledge.Manifest
	if json.Unmarshal(body, &manifest) != nil || manifest.TenantID != project.TenantID || manifest.ProjectID != project.ID || manifest.Version != 1 || manifest.Revision == "" {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge initializer"})
	}
	return nil
}

func (handler *Handler) initializeKnowledge(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if request.Header.Get(curatorForwardedHeader) != "aor-api" || len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	if _, err := requiredIdempotencyKey(request); err != nil {
		writeError(response, request, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1))
	if err != nil || len(body) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge initializer"}))
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
	if err := authorizeRead(request.Context(), handler.authorizer, principal, project.ID, authz.ActionKnowledgeRead, "knowledge", project.ID, string(project.State), project.Version, project.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	initializer, ok := handler.knowledge.(KnowledgeInitializer)
	if !ok {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge initializer"}))
		return
	}
	manifest, err := initializer.Initialize(request.Context(), project.TenantID, project.ID, handler.clock().UTC())
	if err != nil {
		writeError(response, request, normalizeKnowledgeError(err))
		return
	}
	writeJSON(response, http.StatusOK, manifest)
}
