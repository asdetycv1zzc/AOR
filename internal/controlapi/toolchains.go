package controlapi

import (
	"net/http"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func (handler *Handler) listToolchains(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "toolchain inventory query"}))
		return
	}
	if err := handler.authorizeTenantModelResource(request.Context(), principal, authz.ActionSettingsRead, "toolchain-inventory", ""); err != nil {
		writeError(response, request, err)
		return
	}
	if handler.toolchains == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "toolchain inventory"}))
		return
	}
	inventory, err := handler.toolchains.Snapshot(request.Context())
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "toolchain inventory"}))
		return
	}
	writeVersionedPage(response, request, inventory)
}
