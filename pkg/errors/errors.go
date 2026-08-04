// Package errors defines stable, redacted AOR wire errors.
package errors

import "fmt"

type Code string

const (
	CodeInternalError                Code = "AOR_INTERNAL_ERROR"
	CodeInvalidArgument              Code = "AOR_INVALID_ARGUMENT"
	CodeNotFound                     Code = "AOR_NOT_FOUND"
	CodeConflict                     Code = "AOR_CONFLICT"
	CodeUnauthorized                 Code = "AOR_UNAUTHORIZED"
	CodeForbidden                    Code = "AOR_FORBIDDEN"
	CodeRateLimited                  Code = "AOR_RATE_LIMITED"
	CodeTimeout                      Code = "AOR_TIMEOUT"
	CodeDependencyUnavailable        Code = "AOR_DEPENDENCY_UNAVAILABLE"
	CodeStateVersionConflict         Code = "AOR_STATE_VERSION_CONFLICT"
	CodeInvalidStateTransition       Code = "AOR_INVALID_STATE_TRANSITION"
	CodeGoalNotApproved              Code = "AOR_GOAL_NOT_APPROVED"
	CodeGoalHashMismatch             Code = "AOR_GOAL_HASH_MISMATCH"
	CodeSpecSuperseded               Code = "AOR_SPEC_SUPERSEDED"
	CodeTaskBlocked                  Code = "AOR_TASK_BLOCKED"
	CodeAttemptLimitReached          Code = "AOR_ATTEMPT_LIMIT_REACHED"
	CodeLeaseExpired                 Code = "AOR_LEASE_EXPIRED"
	CodeIdempotencyConflict          Code = "AOR_IDEMPOTENCY_CONFLICT"
	CodeBudgetExceeded               Code = "AOR_BUDGET_EXCEEDED"
	CodeBudgetReservationFailed      Code = "AOR_BUDGET_RESERVATION_FAILED"
	CodeModelNotAllowed              Code = "AOR_MODEL_NOT_ALLOWED"
	CodeModelCapabilityMissing       Code = "AOR_MODEL_CAPABILITY_MISSING"
	CodeProviderRateLimited          Code = "AOR_PROVIDER_RATE_LIMITED"
	CodeProviderResultUnknown        Code = "AOR_PROVIDER_RESULT_UNKNOWN"
	CodeModelOutputSchemaInvalid     Code = "AOR_MODEL_OUTPUT_SCHEMA_INVALID"
	CodeToolNotAllowed               Code = "AOR_TOOL_NOT_ALLOWED"
	CodeToolInputInvalid             Code = "AOR_TOOL_INPUT_INVALID"
	CodeToolOutputTooLarge           Code = "AOR_TOOL_OUTPUT_TOO_LARGE"
	CodePolicyDenied                 Code = "AOR_POLICY_DENIED"
	CodeApprovalRequired             Code = "AOR_APPROVAL_REQUIRED"
	CodeSandboxLevelInsufficient     Code = "AOR_SANDBOX_LEVEL_INSUFFICIENT"
	CodeSandboxCreateFailed          Code = "AOR_SANDBOX_CREATE_FAILED"
	CodeSandboxExecTimeout           Code = "AOR_SANDBOX_EXEC_TIMEOUT"
	CodeUnauthorizedPath             Code = "AOR_UNAUTHORIZED_PATH"
	CodeNetworkDestinationDenied     Code = "AOR_NETWORK_DESTINATION_DENIED"
	CodeArtifactHashMismatch         Code = "AOR_ARTIFACT_HASH_MISMATCH"
	CodeArtifactNotAvailable         Code = "AOR_ARTIFACT_NOT_AVAILABLE"
	CodeKnowledgeRevisionUnavailable Code = "AOR_KNOWLEDGE_REVISION_NOT_AVAILABLE"
	CodeKnowledgeWriteForbidden      Code = "AOR_KNOWLEDGE_WRITE_FORBIDDEN"
	CodeAuditEvidenceInvalid         Code = "AOR_AUDIT_EVIDENCE_INVALID"
	CodeAuditorContextViolation      Code = "AOR_AUDITOR_CONTEXT_VIOLATION"
	CodeHiddenTestAccessDenied       Code = "AOR_HIDDEN_TEST_ACCESS_DENIED"
	CodeIntegrationConflict          Code = "AOR_INTEGRATION_CONFLICT"
)

type Metadata struct {
	Message    string
	HTTPStatus int
	Retryable  bool
}

var codes = []Code{
	CodeInternalError, CodeInvalidArgument, CodeNotFound, CodeConflict, CodeUnauthorized, CodeForbidden, CodeRateLimited, CodeTimeout, CodeDependencyUnavailable,
	CodeStateVersionConflict, CodeInvalidStateTransition, CodeGoalNotApproved, CodeGoalHashMismatch, CodeSpecSuperseded, CodeTaskBlocked, CodeAttemptLimitReached, CodeLeaseExpired, CodeIdempotencyConflict,
	CodeBudgetExceeded, CodeBudgetReservationFailed, CodeModelNotAllowed, CodeModelCapabilityMissing, CodeProviderRateLimited, CodeProviderResultUnknown, CodeModelOutputSchemaInvalid,
	CodeToolNotAllowed, CodeToolInputInvalid, CodeToolOutputTooLarge, CodePolicyDenied, CodeApprovalRequired, CodeSandboxLevelInsufficient, CodeSandboxCreateFailed, CodeSandboxExecTimeout, CodeUnauthorizedPath, CodeNetworkDestinationDenied,
	CodeArtifactHashMismatch, CodeArtifactNotAvailable, CodeKnowledgeRevisionUnavailable, CodeKnowledgeWriteForbidden, CodeAuditEvidenceInvalid, CodeAuditorContextViolation, CodeHiddenTestAccessDenied, CodeIntegrationConflict,
}

var metadata = map[Code]Metadata{
	CodeInternalError:                {Message: "Internal error", HTTPStatus: 500},
	CodeInvalidArgument:              {Message: "Invalid argument", HTTPStatus: 400},
	CodeNotFound:                     {Message: "Resource not found", HTTPStatus: 404},
	CodeConflict:                     {Message: "Resource conflict", HTTPStatus: 409},
	CodeUnauthorized:                 {Message: "Authentication required", HTTPStatus: 401},
	CodeForbidden:                    {Message: "Operation forbidden", HTTPStatus: 403},
	CodeRateLimited:                  {Message: "Rate limit exceeded", HTTPStatus: 429, Retryable: true},
	CodeTimeout:                      {Message: "Operation timed out", HTTPStatus: 504, Retryable: true},
	CodeDependencyUnavailable:        {Message: "Dependency unavailable", HTTPStatus: 503, Retryable: true},
	CodeStateVersionConflict:         {Message: "Aggregate version conflict", HTTPStatus: 409},
	CodeInvalidStateTransition:       {Message: "Invalid state transition", HTTPStatus: 409},
	CodeGoalNotApproved:              {Message: "Goal is not approved", HTTPStatus: 409},
	CodeGoalHashMismatch:             {Message: "Goal digest mismatch", HTTPStatus: 409},
	CodeSpecSuperseded:               {Message: "Specification was superseded", HTTPStatus: 409},
	CodeTaskBlocked:                  {Message: "Task is blocked", HTTPStatus: 409},
	CodeAttemptLimitReached:          {Message: "Attempt limit reached", HTTPStatus: 409},
	CodeLeaseExpired:                 {Message: "Capability lease expired", HTTPStatus: 410},
	CodeIdempotencyConflict:          {Message: "Idempotency key conflicts with prior request", HTTPStatus: 409},
	CodeBudgetExceeded:               {Message: "Budget exceeded", HTTPStatus: 402},
	CodeBudgetReservationFailed:      {Message: "Budget reservation failed", HTTPStatus: 409},
	CodeModelNotAllowed:              {Message: "Model is not allowed", HTTPStatus: 403},
	CodeModelCapabilityMissing:       {Message: "Required model capability is missing", HTTPStatus: 422},
	CodeProviderRateLimited:          {Message: "Provider rate limit exceeded", HTTPStatus: 429, Retryable: true},
	CodeProviderResultUnknown:        {Message: "Provider result is unknown", HTTPStatus: 502},
	CodeModelOutputSchemaInvalid:     {Message: "Model output does not match Schema", HTTPStatus: 422},
	CodeToolNotAllowed:               {Message: "Tool is not allowed", HTTPStatus: 403},
	CodeToolInputInvalid:             {Message: "Tool input is invalid", HTTPStatus: 422},
	CodeToolOutputTooLarge:           {Message: "Tool output exceeds the inline limit", HTTPStatus: 413},
	CodePolicyDenied:                 {Message: "Operation denied by policy", HTTPStatus: 403},
	CodeApprovalRequired:             {Message: "Explicit approval is required", HTTPStatus: 428},
	CodeSandboxLevelInsufficient:     {Message: "Sandbox level is insufficient", HTTPStatus: 412},
	CodeSandboxCreateFailed:          {Message: "Sandbox creation failed", HTTPStatus: 500},
	CodeSandboxExecTimeout:           {Message: "Sandbox execution timed out", HTTPStatus: 504, Retryable: true},
	CodeUnauthorizedPath:             {Message: "Path is outside the authorized scope", HTTPStatus: 403},
	CodeNetworkDestinationDenied:     {Message: "Network destination denied", HTTPStatus: 403},
	CodeArtifactHashMismatch:         {Message: "Artifact digest mismatch", HTTPStatus: 409},
	CodeArtifactNotAvailable:         {Message: "Artifact not available", HTTPStatus: 404},
	CodeKnowledgeRevisionUnavailable: {Message: "Knowledge revision not available", HTTPStatus: 410},
	CodeKnowledgeWriteForbidden:      {Message: "Knowledge write forbidden", HTTPStatus: 403},
	CodeAuditEvidenceInvalid:         {Message: "Audit evidence is invalid", HTTPStatus: 422},
	CodeAuditorContextViolation:      {Message: "Auditor context violates blind-review policy", HTTPStatus: 403},
	CodeHiddenTestAccessDenied:       {Message: "Hidden test access denied", HTTPStatus: 403},
	CodeIntegrationConflict:          {Message: "Integration conflict", HTTPStatus: 409},
}

var safeDetailKeys = map[string]struct{}{
	"actualVersion": {}, "expectedVersion": {}, "limit": {}, "policyVersion": {}, "ruleId": {}, "scope": {}, "subjectType": {},
}

func AllCodes() []Code {
	return append([]Code(nil), codes...)
}

func MetadataFor(code Code) Metadata {
	if value, ok := metadata[code]; ok {
		return value
	}
	return metadata[CodeInternalError]
}

type Error struct {
	Code          Code
	CorrelationID string
	Details       map[string]any
	cause         error
}

func New(code Code, correlationID string, details map[string]any) *Error {
	return &Error{Code: code, CorrelationID: correlationID, Details: safeDetails(details)}
}

func Wrap(code Code, correlationID string, cause error, details map[string]any) *Error {
	err := New(code, correlationID, details)
	err.cause = cause
	return err
}

func (e *Error) Error() string {
	return string(e.Code) + ": " + MetadataFor(e.Code).Message
}

func (e *Error) Unwrap() error {
	return e.cause
}

// NonRetryable lets workflow boundaries preserve the retry policy attached to
// the stable wire error code without exposing internal causes.
func (e *Error) NonRetryable() bool {
	return e != nil && !MetadataFor(e.Code).Retryable
}

type Problem struct {
	Type     string      `json:"type"`
	Title    string      `json:"title"`
	Status   int         `json:"status"`
	Detail   string      `json:"detail"`
	Instance string      `json:"instance,omitempty"`
	Error    ProblemBody `json:"error"`
}

type ProblemBody struct {
	Code          Code           `json:"code"`
	Message       string         `json:"message"`
	Retryable     bool           `json:"retryable"`
	Details       map[string]any `json:"details,omitempty"`
	CorrelationID string         `json:"correlationId"`
}

func (e *Error) Problem() Problem {
	meta := MetadataFor(e.Code)
	return Problem{
		Type:   "https://errors.aor.local/" + string(e.Code),
		Title:  meta.Message,
		Status: meta.HTTPStatus,
		Detail: meta.Message,
		Error: ProblemBody{
			Code: e.Code, Message: meta.Message, Retryable: meta.Retryable, Details: safeDetails(e.Details), CorrelationID: e.CorrelationID,
		},
	}
}

func safeDetails(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any)
	for key, value := range input {
		if _, allowed := safeDetailKeys[key]; allowed {
			output[key] = fmt.Sprint(value)
		}
	}
	if len(output) == 0 {
		return nil
	}
	return output
}
