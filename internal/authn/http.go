package authn

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type HTTPMiddleware struct {
	authenticator Authenticator
	next          http.Handler
}

func NewHTTPMiddleware(authenticator Authenticator, next http.Handler) (*HTTPMiddleware, error) {
	if nilInterface(authenticator) || nilInterface(next) {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "authentication middleware"})
	}
	return &HTTPMiddleware{authenticator: authenticator, next: next}, nil
}

func (middleware *HTTPMiddleware) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	principal, err := AuthenticateHTTPRequest(request, middleware.authenticator)
	if err != nil {
		writeHTTPAuthenticationError(response, request)
		return
	}
	ctx, err := ContextWithPrincipal(request.Context(), principal)
	if err != nil {
		writeHTTPAuthenticationError(response, request)
		return
	}
	clone := request.Clone(ctx)
	clone.Header = request.Header.Clone()
	clone.Header.Del("Authorization")
	middleware.next.ServeHTTP(response, clone)
}

func AuthenticateHTTPRequest(request *http.Request, authenticator Authenticator) (Principal, error) {
	if request == nil || nilInterface(authenticator) {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || strings.Count(authorization, " ") != 1 {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	token := strings.TrimPrefix(authorization, "Bearer ")
	if token == "" || len(token) > maximumOIDCTokenBytes || strings.ContainsAny(token, "\r\n\x00") {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	principal, err := authenticator.Authenticate(request.Context(), BearerCredential(token))
	if err != nil || principal.Validate() != nil {
		return Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	return principal, nil
}

func writeHTTPAuthenticationError(response http.ResponseWriter, request *http.Request) {
	correlationID := ""
	instance := ""
	if request != nil {
		correlationID = request.Header.Get("X-Request-ID")
		instance = request.URL.Path
	}
	problem := aorerrors.New(aorerrors.CodeUnauthorized, correlationID, nil).Problem()
	problem.Instance = instance
	response.Header().Set("Content-Type", "application/problem+json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("WWW-Authenticate", `Bearer realm="aor"`)
	response.WriteHeader(problem.Status)
	_ = json.NewEncoder(response).Encode(problem)
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ http.Handler = (*HTTPMiddleware)(nil)
