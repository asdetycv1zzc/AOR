package servicebootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/commandapproval"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/modelproviders"
)

const (
	commandReviewModel         = modelgateway.CommandReviewModel
	commandReviewPromptVersion = modelgateway.CommandReviewPromptVersion
	commandReviewMaxOutput     = 2048
	commandReviewContextWindow = 400_000
)

var commandReviewSchema = json.RawMessage(`{
  "type": "object",
  "required": ["decision", "reason", "riskCodes"],
  "additionalProperties": false,
  "properties": {
    "decision": {"enum": ["APPROVE", "ESCALATE"]},
    "reason": {"type": "string", "minLength": 1, "maxLength": 16384},
    "riskCodes": {
      "type": "array",
      "maxItems": 64,
      "items": {"type": "string", "minLength": 1, "maxLength": 128}
    }
  }
}`)

const commandReviewSystemPrompt = `You are AOR's command approval reviewer. Review exactly one argv command that would run in a task-bound repository workspace.

APPROVE only when the command is necessary for repository inspection, building, or testing in a disposable workspace copy; it does not rely on persistent file changes; its arguments stay within the workspace and outside every forbidden path; it does not use a shell or interpreter evaluation; it does not access credentials, other projects, host controls, external networks, package installation, remote Git operations, deployment, publication, or destructive database/filesystem operations.

ESCALATE any ambiguous, destructive, privileged, networked, credential-related, persistence-changing, deployment, publication, or workspace-escaping command. Fail closed when intent cannot be established from the structured input. Return only the response schema.`

type commandReviewGateway interface {
	Generate(context.Context, modelgateway.NormalizedRequest, modelgateway.GenerateOptions) (modelgateway.NormalizedResponse, error)
}

type modelCommandReviewer struct {
	gateway commandReviewGateway
}

func newModelCommandReviewer(gateway commandReviewGateway) (*modelCommandReviewer, error) {
	if gateway == nil {
		return nil, ErrWorkerConfiguration
	}
	return &modelCommandReviewer{gateway: gateway}, nil
}

func (reviewer *modelCommandReviewer) Review(ctx context.Context, request commandapproval.Request) (commandapproval.Result, error) {
	if reviewer == nil || reviewer.gateway == nil || ctx == nil {
		return commandapproval.Result{}, commandapproval.ErrReviewerFailed
	}
	payload, err := json.Marshal(struct {
		Executable     string   `json:"executable"`
		Arguments      []string `json:"arguments"`
		WorkingDir     string   `json:"workingDirectory"`
		AllowedPaths   []string `json:"allowedPaths"`
		ForbiddenPaths []string `json:"forbiddenPaths"`
		TimeoutSeconds int64    `json:"timeoutSeconds"`
	}{
		Executable: request.Executable, Arguments: append([]string(nil), request.Arguments...),
		WorkingDir: request.WorkingDir, AllowedPaths: append([]string(nil), request.AllowedPaths...),
		ForbiddenPaths: append([]string(nil), request.ForbiddenPaths...), TimeoutSeconds: int64(request.Timeout.Seconds()),
	})
	if err != nil {
		return commandapproval.Result{}, err
	}
	promptDigest := digestCommandReview(commandReviewSystemPrompt + "\x00" + string(payload))
	response, err := reviewer.gateway.Generate(ctx, modelgateway.NormalizedRequest{
		RequestID: request.RequestID, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		AgentInstanceID: request.AgentID, Role: authn.RoleExecutor, Model: commandReviewModel,
		PromptBundleVersion: commandReviewPromptVersion,
		Messages: []modelgateway.Message{
			{Role: "system", Content: commandReviewSystemPrompt},
			{Role: "user", Content: string(payload)},
		},
		ResponseSchemaRef: "schema://aor/command-approval/v1", ResponseSchema: append(json.RawMessage(nil), commandReviewSchema...),
		MaxOutputTokens: commandReviewMaxOutput, ContextWindowTokens: commandReviewContextWindow,
		ReasoningEffort: "low", Temperature: 0, ProviderPolicy: "default",
		DataClassification: request.DataClassification, CachePolicy: "NO_STORE",
		PromptDigest: promptDigest, ToolSchemaDigest: agentruntime.DigestToolDefinitions(nil),
		PolicyDigest: digestCommandReview(commandReviewSystemPrompt),
	}, modelgateway.GenerateOptions{
		Provider: modelproviders.ProviderOpenAI, AccountID: request.BudgetAccountID,
		ReservationID: commandReviewReservationID(request), MaxAttempts: 1,
	})
	if err != nil {
		return commandapproval.Result{}, err
	}
	var decoded struct {
		Decision  commandapproval.Decision `json:"decision"`
		Reason    string                   `json:"reason"`
		RiskCodes []string                 `json:"riskCodes"`
	}
	if err := decodeCommandReviewResponse(response.Content, &decoded); err != nil {
		return commandapproval.Result{}, err
	}
	if decoded.Decision != commandapproval.DecisionApprove && decoded.Decision != commandapproval.DecisionEscalate || strings.TrimSpace(decoded.Reason) == "" || len(decoded.Reason) > 16<<10 || len(decoded.RiskCodes) > 64 {
		return commandapproval.Result{}, commandapproval.ErrInvalidDecision
	}
	for _, riskCode := range decoded.RiskCodes {
		if strings.TrimSpace(riskCode) == "" || len(riskCode) > 128 || strings.ContainsAny(riskCode, "\x00\r\n") {
			return commandapproval.Result{}, commandapproval.ErrInvalidDecision
		}
	}
	return commandapproval.Result{Decision: decoded.Decision, Reason: decoded.Reason, RiskCodes: decoded.RiskCodes}, nil
}

func decodeCommandReviewResponse(content json.RawMessage, target any) error {
	if len(content) == 0 {
		return commandapproval.ErrInvalidDecision
	}
	decodedContent := []byte(content)
	var encoded string
	if json.Unmarshal(content, &encoded) == nil {
		decodedContent = []byte(encoded)
	}
	decoder := json.NewDecoder(bytes.NewReader(decodedContent))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return commandapproval.ErrInvalidDecision
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return commandapproval.ErrInvalidDecision
	}
	return nil
}

func commandReviewReservationID(request commandapproval.Request) string {
	digest := sha256.Sum256([]byte(request.TenantID + "\x00" + request.ProjectID + "\x00" + request.RequestID + "\x00" + request.IdempotencyKey))
	return "command-review-reservation-" + hex.EncodeToString(digest[:])
}

func digestCommandReview(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

var _ commandapproval.Reviewer = (*modelCommandReviewer)(nil)
