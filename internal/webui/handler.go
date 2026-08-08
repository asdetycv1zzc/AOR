package webui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

const (
	configPath           = "/ui/config"
	redirectPath         = "/ui/callback"
	tokenProxyPath       = "/ui/oauth/token"
	maximumTokenRequest  = 64 << 10
	maximumTokenResponse = 1 << 20
	maximumAuthorization = 16 << 10
	maximumRefreshToken  = 32 << 10
	maximumRedirectURI   = 2048
	tokenRequestTimeout  = 8 * time.Second
	staticContentPolicy  = "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'"
)

var errInvalidConfig = errors.New("invalid web UI configuration")

type Config struct {
	Next          http.Handler
	Root          string
	Issuer        string
	ClientID      string
	TokenEndpoint string
}

type Handler struct {
	next                  http.Handler
	root                  fs.FS
	issuer                string
	authorizationEndpoint string
	clientID              string
	tokenEndpoint         string
	client                *http.Client
}

func New(config Config) (*Handler, error) {
	if config.Next == nil || strings.TrimSpace(config.Root) == "" || !validClientID(config.ClientID) {
		return nil, errInvalidConfig
	}
	issuer, err := validEndpoint(config.Issuer)
	if err != nil {
		return nil, errInvalidConfig
	}
	tokenEndpoint, err := validEndpoint(config.TokenEndpoint)
	if err != nil {
		return nil, errInvalidConfig
	}
	info, err := os.Stat(config.Root)
	if err != nil || !info.IsDir() {
		return nil, errInvalidConfig
	}
	root := os.DirFS(config.Root)
	index, err := fs.Stat(root, "index.html")
	if err != nil || index.IsDir() {
		return nil, errInvalidConfig
	}
	return &Handler{
		next:                  config.Next,
		root:                  root,
		issuer:                issuer,
		authorizationEndpoint: strings.TrimRight(issuer, "/") + "/auth",
		clientID:              config.ClientID,
		tokenEndpoint:         tokenEndpoint,
		client: &http.Client{
			Timeout: tokenRequestTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/":
		http.Redirect(response, request, "/ui/", http.StatusTemporaryRedirect)
	case request.URL.Path == configPath:
		handler.serveConfig(response, request)
	case request.URL.Path == tokenProxyPath:
		handler.proxyToken(response, request)
	case request.URL.Path == "/ui":
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			methodNotAllowed(response, http.MethodGet, http.MethodHead)
			return
		}
		http.Redirect(response, request, "/ui/", http.StatusTemporaryRedirect)
	case strings.HasPrefix(request.URL.Path, "/ui/"):
		handler.serveStatic(response, request)
	default:
		handler.next.ServeHTTP(response, request)
	}
}

func (handler *Handler) serveConfig(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"issuer":                handler.issuer,
		"authorizationEndpoint": handler.authorizationEndpoint,
		"clientId":              handler.clientID,
		"redirectPath":          redirectPath,
		"tokenEndpoint":         tokenProxyPath,
		"scopes":                []string{"openid", "profile", "email", "offline_access"},
	})
}

func (handler *Handler) proxyToken(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Pragma", "no-cache")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodPost {
		methodNotAllowed(response, http.MethodPost)
		return
	}
	if !sameOriginRequest(request) {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumTokenRequest)
	if err := request.ParseForm(); err != nil || request.PostForm == nil {
		writeOAuthError(response, http.StatusBadRequest, "invalid_request")
		return
	}

	form := make(url.Values)
	form.Set("client_id", handler.clientID)
	switch grantType := singleValue(request.PostForm, "grant_type"); grantType {
	case "authorization_code":
		code := singleValue(request.PostForm, "code")
		verifier := singleValue(request.PostForm, "code_verifier")
		redirectURI := singleValue(request.PostForm, "redirect_uri")
		if !validOpaqueValue(code, maximumAuthorization) || !validCodeVerifier(verifier) || !validRedirectURI(request, redirectURI) {
			writeOAuthError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		form.Set("grant_type", grantType)
		form.Set("code", code)
		form.Set("code_verifier", verifier)
		form.Set("redirect_uri", redirectURI)
	case "refresh_token":
		refreshToken := singleValue(request.PostForm, "refresh_token")
		if !validOpaqueValue(refreshToken, maximumRefreshToken) {
			writeOAuthError(response, http.StatusBadRequest, "invalid_request")
			return
		}
		form.Set("grant_type", grantType)
		form.Set("refresh_token", refreshToken)
	default:
		writeOAuthError(response, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), tokenRequestTimeout)
	defer cancel()
	upstreamRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, handler.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		writeOAuthError(response, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	upstreamRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	upstreamRequest.Header.Set("Accept", "application/json")
	upstreamResponse, err := handler.client.Do(upstreamRequest)
	if err != nil {
		writeOAuthError(response, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	defer upstreamResponse.Body.Close()
	body, err := io.ReadAll(io.LimitReader(upstreamResponse.Body, maximumTokenResponse+1))
	if err != nil || len(body) > maximumTokenResponse {
		writeOAuthError(response, http.StatusBadGateway, "temporarily_unavailable")
		return
	}
	contentType := upstreamResponse.Header.Get("Content-Type")
	if !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		contentType = "application/json"
	}
	response.Header().Set("Content-Type", contentType)
	response.WriteHeader(upstreamResponse.StatusCode)
	_, _ = response.Write(body)
}

func (handler *Handler) serveStatic(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		methodNotAllowed(response, http.MethodGet, http.MethodHead)
		return
	}
	setStaticHeaders(response)
	name := strings.TrimPrefix(request.URL.Path, "/ui/")
	if name == "" {
		handler.serveFile(response, request, "index.html", false)
		return
	}
	clean := path.Clean(name)
	if clean == "." || !fs.ValidPath(clean) {
		http.NotFound(response, request)
		return
	}
	info, err := fs.Stat(handler.root, clean)
	if err == nil && !info.IsDir() {
		handler.serveFile(response, request, clean, strings.HasPrefix(clean, "assets/"))
		return
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	handler.serveFile(response, request, "index.html", false)
}

func (handler *Handler) serveFile(response http.ResponseWriter, request *http.Request, name string, immutable bool) {
	file, err := handler.root.Open(name)
	if err != nil {
		http.NotFound(response, request)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(response, request)
		return
	}
	content, ok := file.(io.ReadSeeker)
	if !ok {
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if immutable {
		response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		response.Header().Set("Cache-Control", "no-cache")
	}
	http.ServeContent(response, request, path.Base(name), info.ModTime(), content)
}

func validEndpoint(raw string) (string, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || !endpoint.IsAbs() || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return "", errInvalidConfig
	}
	return endpoint.String(), nil
}

func validClientID(clientID string) bool {
	return clientID != "" && len(clientID) <= 512 && !strings.ContainsAny(clientID, "\r\n\x00")
}

func validRedirectURI(request *http.Request, raw string) bool {
	if len(raw) == 0 || len(raw) > maximumRedirectURI {
		return false
	}
	redirect, err := url.Parse(raw)
	if err != nil || !redirect.IsAbs() || redirect.User != nil || redirect.RawQuery != "" || redirect.Fragment != "" || redirect.Path != redirectPath {
		return false
	}
	return strings.EqualFold(redirect.Scheme, requestScheme(request)) && strings.EqualFold(redirect.Host, request.Host)
}

func sameOriginRequest(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.User == nil && parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && strings.EqualFold(parsed.Scheme, requestScheme(request)) && strings.EqualFold(parsed.Host, request.Host)
}

func requestScheme(request *http.Request) string {
	if request.TLS != nil {
		return "https"
	}
	return "http"
}

func singleValue(values url.Values, key string) string {
	items := values[key]
	if len(items) != 1 {
		return ""
	}
	return items[0]
}

func validOpaqueValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func validCodeVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~", character) {
			continue
		}
		return false
	}
	return true
}

func setStaticHeaders(response http.ResponseWriter) {
	response.Header().Set("Content-Security-Policy", staticContentPolicy)
	response.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
}

func methodNotAllowed(response http.ResponseWriter, methods ...string) {
	response.Header().Set("Allow", strings.Join(methods, ", "))
	response.WriteHeader(http.StatusMethodNotAllowed)
}

func writeOAuthError(response http.ResponseWriter, status int, code string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(map[string]string{"error": code})
}

var _ http.Handler = (*Handler)(nil)
