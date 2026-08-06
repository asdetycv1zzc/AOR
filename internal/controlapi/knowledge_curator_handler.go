package controlapi

import (
	"net/http"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type knowledgeCuratorHandler struct {
	domain *Handler
}

// NewKnowledgeCuratorHandler exposes only the approved knowledge mutation
// surface. The underlying handler retains the same authentication and project
// authorization path as the control API.
func NewKnowledgeCuratorHandler(config Config) (http.Handler, error) {
	if config.KnowledgeCurator == nil || config.KnowledgeCuratorURL != "" {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge curator api configuration"})
	}
	if _, ok := config.Knowledge.(KnowledgeInitializer); !ok {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge curator api configuration"})
	}
	domain, err := New(config)
	if err != nil {
		return nil, err
	}
	return &knowledgeCuratorHandler{domain: domain}, nil
}

func (handler *knowledgeCuratorHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request == nil {
		response.WriteHeader(http.StatusNotFound)
		return
	}
	if handler == nil || handler.domain == nil || !isKnowledgeCuratorRequest(request) {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	handler.domain.ServeHTTP(response, request)
}
