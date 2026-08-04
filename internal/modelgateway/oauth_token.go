package modelgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	defaultOAuthTokenTimeout = 10 * time.Second
	maximumOAuthTokenTimeout = 30 * time.Second
	maximumOAuthTokenBody    = 64 << 10
	oauthTokenRefreshMargin  = 30 * time.Second
)

type OAuthClientCredentialsConfig struct {
	TokenEndpoint string
	ClientID      string
	ClientSecret  []byte
	Scopes        []string
	Audience      string
	AllowHTTP     bool
	Transport     http.RoundTripper
	Timeout       time.Duration
	Clock         func() time.Time
}

type OAuthClientCredentialsTokenSource struct {
	endpoint     string
	clientID     string
	clientSecret []byte
	scopes       string
	audience     string
	client       *http.Client
	timeout      time.Duration
	clock        func() time.Time

	mu     sync.Mutex
	cached BearerToken
}

func NewOAuthClientCredentialsTokenSource(config OAuthClientCredentialsConfig) (*OAuthClientCredentialsTokenSource, error) {
	endpoint, err := validateOAuthTokenEndpoint(config.TokenEndpoint, config.AllowHTTP)
	if err != nil || !validOAuthClientID(config.ClientID) || !validOAuthSecret(config.ClientSecret) ||
		!validOAuthAudience(config.Audience) || nilHTTPClientTransport(config.Transport) {
		return nil, ErrInvalidRequest
	}
	scopes, err := normalizeOAuthScopes(config.Scopes)
	if err != nil {
		return nil, err
	}
	if config.Timeout == 0 {
		config.Timeout = defaultOAuthTokenTimeout
	}
	if config.Timeout <= 0 || config.Timeout > maximumOAuthTokenTimeout {
		return nil, ErrInvalidRequest
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	transport := config.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &OAuthClientCredentialsTokenSource{
		endpoint: endpoint, clientID: config.ClientID, clientSecret: append([]byte(nil), config.ClientSecret...),
		scopes: scopes, audience: config.Audience, timeout: config.Timeout, clock: config.Clock,
		client: &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (source *OAuthClientCredentialsTokenSource) Token(ctx context.Context) (BearerToken, error) {
	if source == nil || source.client == nil || ctx == nil {
		return BearerToken{}, ErrAuthorizationDenied
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	now := source.clock().UTC()
	if validHTTPBearerToken(source.cached, now.Add(oauthTokenRefreshMargin-minimumHTTPBearerTokenValidity)) {
		return source.cached, nil
	}
	token, err := source.fetch(ctx, now)
	if err != nil {
		return BearerToken{}, err
	}
	source.cached = token
	return token, nil
}

func (source *OAuthClientCredentialsTokenSource) fetch(ctx context.Context, now time.Time) (BearerToken, error) {
	requestContext, cancel := context.WithTimeout(ctx, source.timeout)
	defer cancel()
	form := url.Values{"grant_type": []string{"client_credentials"}}
	if source.scopes != "" {
		form.Set("scope", source.scopes)
	}
	if source.audience != "" {
		form.Set("audience", source.audience)
	}
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, source.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return BearerToken{}, ErrAuthorizationDenied
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(source.clientID, string(source.clientSecret))
	response, err := source.client.Do(request)
	if err != nil {
		if requestContext.Err() != nil {
			return BearerToken{}, requestContext.Err()
		}
		return BearerToken{}, ErrAuthorizationDenied
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumOAuthTokenBody+1))
	if err != nil || len(body) > maximumOAuthTokenBody || response.StatusCode != http.StatusOK || !oauthJSONContentType(response.Header.Get("Content-Type")) {
		return BearerToken{}, ErrAuthorizationDenied
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		Scope       string `json:"scope,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || !jsonDecoderAtEOF(decoder) ||
		!strings.EqualFold(payload.TokenType, "Bearer") || payload.ExpiresIn <= int64(minimumHTTPBearerTokenValidity/time.Second) {
		return BearerToken{}, ErrAuthorizationDenied
	}
	token := BearerToken{Value: payload.AccessToken, ExpiresAt: now.Add(time.Duration(payload.ExpiresIn) * time.Second)}
	if !validHTTPBearerToken(token, now) {
		return BearerToken{}, ErrAuthorizationDenied
	}
	return token, nil
}

func validateOAuthTokenEndpoint(raw string, allowHTTP bool) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return "", ErrInvalidRequest
	}
	return parsed.String(), nil
}

func validOAuthClientID(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, ": \t\r\n\x00")
}

func validOAuthSecret(value []byte) bool {
	return len(value) > 0 && len(value) <= maximumHTTPBearerTokenBytes && utf8.Valid(value) && !bytes.ContainsAny(value, "\r\n\x00")
}

func validOAuthAudience(value string) bool {
	return len(value) <= 2048 && !strings.ContainsAny(value, " \t\r\n\x00")
}

func normalizeOAuthScopes(values []string) (string, error) {
	if len(values) > 32 {
		return "", ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || len(value) > 256 || strings.ContainsAny(value, " \t\r\n\x00") {
			return "", ErrInvalidRequest
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return strings.Join(normalized, " "), nil
}

func oauthJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && mediaType == "application/json"
}

func jsonDecoderAtEOF(decoder *json.Decoder) bool {
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}
