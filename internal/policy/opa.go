// Package policy provides fail-closed clients for external policy engines.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
)

const (
	decisionPath    = "/v1/data/aor/authz/decision"
	leaseGrantPath  = "/v1/data/aor/authz/lease_grant"
	healthPath      = "/health"
	maxResponseSize = 64 * 1024
)

var (
	ErrInvalidBaseURL        = errors.New("invalid OPA base URL")
	ErrPolicyUnavailable     = errors.New("policy evaluator unavailable")
	ErrInvalidPolicyResponse = errors.New("invalid policy response")
)

// OPAClient evaluates AOR authorization decisions through OPA's HTTP API.
type OPAClient struct {
	baseURL *url.URL
	client  *http.Client
}

var _ authz.PolicyEvaluator = (*OPAClient)(nil)
var _ authz.LeaseGrantEvaluator = (*OPAClient)(nil)

// NewOPAClient creates a client for an HTTP or HTTPS OPA endpoint.
func NewOPAClient(baseURL string) (*OPAClient, error) {
	parsed, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return &OPAClient{
		baseURL: parsed,
		client:  &http.Client{Timeout: 5 * time.Second},
	}, nil
}

// Evaluate validates the trusted input, evaluates it in OPA, and validates the
// returned decision. Any transport or protocol failure returns a denial.
func (client *OPAClient) Evaluate(ctx context.Context, input authz.PolicyInput) (authz.PolicyDecision, error) {
	return client.evaluate(ctx, input, decisionPath, false)
}

// EvaluateLeaseGrant calls the policy entrypoint that authorizes creation or
// renewal of a capability lease. Issuance uses a separate fail-closed rule.
func (client *OPAClient) EvaluateLeaseGrant(ctx context.Context, input authz.PolicyInput) (authz.PolicyDecision, error) {
	taskLease := (authz.IsSideEffect(input.Action) || input.Action == authz.ActionModelGenerate) && input.Task.ID != "" && input.Task.SpecDigest != ""
	projectModelLease := input.Action == authz.ActionModelGenerate && input.Task.ID == "" && input.Task.StateVersion == 0 && input.Task.SpecDigest == "" && !authz.LeaseRoleRequiresTask(input.Principal.Role)
	projectIntegrationLease := input.Action == authz.ActionIntegrationMerge && input.Principal.Role == authn.RoleService && input.Task.ID == "" && input.Task.StateVersion == 0 && input.Task.SpecDigest == ""
	if (!taskLease && !projectModelLease && !projectIntegrationLease) || input.Lease != nil || input.ParameterDigest == "" || input.Budget.AccountID == "" || !input.Budget.Available {
		return denied("INVALID_LEASE_GRANT_INPUT"), ErrInvalidPolicyResponse
	}
	return client.evaluate(ctx, input, leaseGrantPath, true)
}

func (client *OPAClient) evaluate(ctx context.Context, input authz.PolicyInput, path string, requireBinding bool) (authz.PolicyDecision, error) {
	if err := contextError(ctx); err != nil {
		return denied("REQUEST_CANCELED"), err
	}
	now := time.Now().UTC()
	if err := input.Validate(now); err != nil {
		return denied("INVALID_POLICY_INPUT"), err
	}

	payload, err := json.Marshal(struct {
		Input authz.PolicyInput `json:"input"`
	}{Input: input})
	if err != nil {
		return denied("INVALID_POLICY_INPUT"), ErrPolicyUnavailable
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint(path), bytes.NewReader(payload))
	if err != nil {
		return denied("POLICY_UNAVAILABLE"), ErrPolicyUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.httpClient().Do(request)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return denied("REQUEST_CANCELED"), contextErr
		}
		return denied("POLICY_UNAVAILABLE"), ErrPolicyUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return denied("POLICY_UNAVAILABLE"), ErrPolicyUnavailable
	}

	body, err := readResponse(ctx, response.Body)
	if err != nil {
		return denied("POLICY_UNAVAILABLE"), err
	}
	decision, err := decodeDecision(body)
	if err != nil {
		return denied("INVALID_POLICY_RESULT"), err
	}
	if err := decision.Validate(now); err != nil {
		return denied("INVALID_POLICY_RESULT"), ErrInvalidPolicyResponse
	}
	if requireBinding && decision.Decision == authz.DecisionAllow && decision.Binding == nil {
		return denied("INVALID_POLICY_RESULT"), ErrInvalidPolicyResponse
	}
	return decision, nil
}

// Health reports whether OPA's health endpoint responds successfully.
func (client *OPAClient) Health(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint(healthPath), nil)
	if err != nil {
		return ErrPolicyUnavailable
	}
	response, err := client.httpClient().Do(request)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		return ErrPolicyUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ErrPolicyUnavailable
	}
	return nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return nil, ErrInvalidBaseURL
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawPath != "" {
		return nil, ErrInvalidBaseURL
	}
	return parsed, nil
}

func (client *OPAClient) endpoint(path string) string {
	endpoint := *client.baseURL
	endpoint.Path = path
	endpoint.RawPath = ""
	return endpoint.String()
}

func (client *OPAClient) httpClient() *http.Client {
	if client != nil && client.client != nil {
		return client.client
	}
	return http.DefaultClient
}

func readResponse(ctx context.Context, body io.Reader) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(body, maxResponseSize+1))
	if contextErr := contextError(ctx); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, ErrPolicyUnavailable
	}
	if len(content) > maxResponseSize {
		return nil, ErrInvalidPolicyResponse
	}
	return content, nil
}

func decodeDecision(content []byte) (authz.PolicyDecision, error) {
	var response struct {
		Result *authz.PolicyDecision `json:"result"`
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || response.Result == nil {
		return authz.PolicyDecision{}, ErrInvalidPolicyResponse
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return authz.PolicyDecision{}, ErrInvalidPolicyResponse
	}
	return *response.Result, nil
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrPolicyUnavailable
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func denied(reason string) authz.PolicyDecision {
	return authz.PolicyDecision{
		Decision:      authz.DecisionDeny,
		PolicyVersion: "unavailable",
		ReasonCodes:   []string{reason},
		RuleID:        "aor.default.deny",
	}
}
