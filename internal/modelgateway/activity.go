package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/projectactivity"
)

type ActivityRecorder interface {
	Start(context.Context, NormalizedRequest, GenerateOptions, time.Time) error
	AppendDelta(context.Context, NormalizedRequest, string, time.Time) error
	Finish(context.Context, NormalizedRequest, GenerateOptions, NormalizedResponse, error, time.Time, time.Time) error
}

type ActivityIntervention struct {
	ID      string
	Content string
}

type ActivityInterventionSource interface {
	Claim(context.Context, NormalizedRequest, time.Time) ([]ActivityIntervention, error)
	Complete(context.Context, NormalizedRequest, []string, error, time.Time) error
	Pending(context.Context, NormalizedRequest, string) (bool, error)
}

type PostgresActivityRecorder struct {
	store *projectactivity.Store
}

func NewPostgresActivityRecorder(store *projectactivity.Store) (*PostgresActivityRecorder, error) {
	if store == nil {
		return nil, errors.New("project activity store is required")
	}
	return &PostgresActivityRecorder{store: store}, nil
}

func (recorder *PostgresActivityRecorder) Start(ctx context.Context, request NormalizedRequest, options GenerateOptions, startedAt time.Time) error {
	return recorder.store.Upsert(ctx, projectactivity.Message{
		TenantID: request.TenantID, ProjectID: request.ProjectID,
		ID: modelActivityID(request.RequestID), RequestID: request.RequestID,
		TaskID: request.TaskID, Flow: activityFlowForRole(request.Role),
		AgentInstanceID: request.AgentInstanceID, Role: request.Role,
		Sender: projectactivity.SenderAgent, State: projectactivity.StateStreaming,
		Provider: options.Provider, Model: request.Model,
		CreatedAt: startedAt.UTC(), UpdatedAt: startedAt.UTC(),
	})
}

func (recorder *PostgresActivityRecorder) AppendDelta(ctx context.Context, request NormalizedRequest, delta string, updatedAt time.Time) error {
	if delta == "" {
		return nil
	}
	return recorder.store.AppendDelta(ctx, request.TenantID, modelActivityID(request.RequestID), delta, updatedAt.UTC())
}

func (recorder *PostgresActivityRecorder) Finish(ctx context.Context, request NormalizedRequest, options GenerateOptions, response NormalizedResponse, resultErr error, startedAt, completedAt time.Time) error {
	stateValue := projectactivity.StateCompleted
	content := activityResponseContent(response)
	errorCode := ""
	if resultErr != nil {
		stateValue = projectactivity.StateFailed
		content = redactError(resultErr).Error()
		errorCode = activityErrorCode(resultErr)
	}
	outputSHA256 := ""
	if resultErr == nil {
		outputSHA256 = responseOutputDigest(response)
	}
	provider := response.Provider
	if provider == "" {
		provider = options.Provider
	}
	model := request.Model
	if response.ModelVersion != "" {
		model = response.ModelVersion
	}
	return recorder.store.Upsert(ctx, projectactivity.Message{
		TenantID: request.TenantID, ProjectID: request.ProjectID,
		ID: modelActivityID(request.RequestID), RequestID: request.RequestID,
		TaskID: request.TaskID, Flow: activityFlowForRole(request.Role),
		AgentInstanceID: request.AgentInstanceID, Role: request.Role,
		Sender: projectactivity.SenderAgent, State: stateValue,
		Content: content, ErrorCode: errorCode, Provider: provider, Model: model,
		InputTokens: response.Usage.InputTokens, OutputTokens: response.Usage.OutputTokens,
		LatencyMS:    elapsedMilliseconds(startedAt, completedAt),
		OutputSHA256: outputSHA256,
		CreatedAt:    startedAt.UTC(), UpdatedAt: completedAt.UTC(),
	})
}

func (recorder *PostgresActivityRecorder) Claim(ctx context.Context, request NormalizedRequest, now time.Time) ([]ActivityIntervention, error) {
	flow := activityFlowForRole(request.Role)
	if request.TenantID == "" || request.ProjectID == "" || flow == projectactivity.FlowGoal {
		return nil, nil
	}
	messages, err := recorder.store.ClaimQueued(ctx, request.TenantID, request.ProjectID, flow, request.AgentInstanceID, request.RequestID, now)
	if err != nil {
		return nil, err
	}
	result := make([]ActivityIntervention, 0, len(messages))
	for _, message := range messages {
		result = append(result, ActivityIntervention{ID: message.ID, Content: message.Content})
	}
	return result, nil
}

func (recorder *PostgresActivityRecorder) Complete(ctx context.Context, request NormalizedRequest, messages []string, resultErr error, now time.Time) error {
	if request.TenantID == "" || request.ProjectID == "" || len(messages) == 0 {
		return nil
	}
	return recorder.store.CompleteClaimed(ctx, request.TenantID, request.ProjectID, request.RequestID, messages, resultErr != nil, activityInterventionRetryable(resultErr), now)
}

func (recorder *PostgresActivityRecorder) Pending(ctx context.Context, request NormalizedRequest, continuationRequestID string) (bool, error) {
	flow := activityFlowForRole(request.Role)
	if request.TenantID == "" || request.ProjectID == "" || continuationRequestID == "" || flow == projectactivity.FlowGoal {
		return false, nil
	}
	return recorder.store.HasQueuedOrClaimed(ctx, request.TenantID, request.ProjectID, flow, request.AgentInstanceID, continuationRequestID)
}

type activityDeltaContextKey struct{}

func withActivityDeltaRecorder(ctx context.Context, callback func(string)) context.Context {
	if callback == nil {
		return ctx
	}
	return context.WithValue(ctx, activityDeltaContextKey{}, callback)
}

func ReportActivityDelta(ctx context.Context, delta string) {
	if ctx == nil || delta == "" {
		return
	}
	callback, _ := ctx.Value(activityDeltaContextKey{}).(func(string))
	if callback != nil {
		callback(delta)
	}
}

func (g *Gateway) recordActivityStart(ctx context.Context, request NormalizedRequest, options GenerateOptions, startedAt time.Time) {
	if g.activityRecorder == nil {
		return
	}
	recordContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = g.activityRecorder.Start(recordContext, request, options, startedAt)
}

func (g *Gateway) recordActivityDelta(ctx context.Context, request NormalizedRequest, delta string) {
	if g.activityRecorder == nil || delta == "" {
		return
	}
	recordContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = g.activityRecorder.AppendDelta(recordContext, request, delta, g.clock().UTC())
}

func (g *Gateway) recordActivityFinish(ctx context.Context, request NormalizedRequest, options GenerateOptions, response NormalizedResponse, resultErr error, startedAt time.Time) {
	if g.activityRecorder == nil {
		return
	}
	recordContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = g.activityRecorder.Finish(recordContext, request, options, response, resultErr, startedAt, g.clock().UTC())
}

func (g *Gateway) claimActivityInterventions(ctx context.Context, request NormalizedRequest) ([]ActivityIntervention, error) {
	if g.activityInterventions == nil {
		return nil, nil
	}
	claimContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	claimed, err := g.activityInterventions.Claim(claimContext, request, g.clock().UTC())
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

func (g *Gateway) completeActivityInterventions(ctx context.Context, request NormalizedRequest, ids []string, resultErr error) {
	if g.activityInterventions == nil || len(ids) == 0 {
		return
	}
	completeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	_ = g.activityInterventions.Complete(completeContext, request, ids, resultErr, g.clock().UTC())
}

func (g *Gateway) decorateActivityResponse(ctx context.Context, request NormalizedRequest, claimed []ActivityIntervention, response NormalizedResponse) NormalizedResponse {
	response.AppliedInterventions = nil
	response.InterventionRequestID = ""
	for _, intervention := range claimed {
		if intervention.Content != "" {
			response.AppliedInterventions = append(response.AppliedInterventions, intervention.Content)
		}
	}
	if g.activityInterventions == nil || len(response.Content) == 0 {
		return response
	}
	continuationRequestID := activityContinuationRequestID(request.RequestID)
	pendingContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	pending, err := g.activityInterventions.Pending(pendingContext, request, continuationRequestID)
	if err == nil && pending {
		response.InterventionRequestID = continuationRequestID
	}
	return response
}

func claimedInterventionMessages(interventions []ActivityIntervention) []Message {
	result := make([]Message, 0, len(interventions))
	for _, intervention := range interventions {
		if intervention.Content == "" {
			continue
		}
		result = append(result, Message{Role: "user", Content: intervention.Content})
	}
	return result
}

func claimedInterventionIDs(interventions []ActivityIntervention) []string {
	result := make([]string, 0, len(interventions))
	for _, intervention := range interventions {
		if intervention.ID != "" {
			result = append(result, intervention.ID)
		}
	}
	return result
}

func modelActivityID(requestID string) string {
	return "model:" + requestID
}

func activityContinuationRequestID(requestID string) string {
	digest := sha256.Sum256([]byte("activity-intervention\x00" + requestID))
	return "activity-intervention-" + hex.EncodeToString(digest[:])
}

func activityFlowForRole(role string) projectactivity.Flow {
	switch role {
	case "GOAL_PROPOSER", "GOAL_CHALLENGER":
		return projectactivity.FlowGoal
	case "PLAN_SUPERVISOR", "MODULE_PLANNER":
		return projectactivity.FlowPlan
	case "MODULE_AUDITOR", "GLOBAL_AUDITOR":
		return projectactivity.FlowAudit
	case "KNOWLEDGE_CURATOR":
		return projectactivity.FlowKnowledge
	default:
		return projectactivity.FlowExecution
	}
}

func activityResponseContent(response NormalizedResponse) string {
	if len(response.Content) != 0 {
		var text string
		if json.Unmarshal(response.Content, &text) == nil {
			return text
		}
		return string(response.Content)
	}
	if len(response.ToolCalls) == 0 {
		return ""
	}
	names := make([]string, 0, len(response.ToolCalls))
	for _, call := range response.ToolCalls {
		if call.Name != "" {
			names = append(names, call.Name)
		}
	}
	if len(names) == 0 {
		return "Tool call requested"
	}
	return "Tool calls: " + strings.Join(names, ", ")
}

func activityErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return "AOR_REQUEST_CANCELED"
	case errors.Is(err, context.DeadlineExceeded):
		return "AOR_REQUEST_TIMEOUT"
	case errors.Is(err, ErrBudgetExceeded):
		return "AOR_BUDGET_EXCEEDED"
	case errors.Is(err, ErrReconciliationRequired):
		return "AOR_PROVIDER_RESULT_UNKNOWN"
	case errors.Is(err, ErrOutputSchema):
		return "AOR_MODEL_OUTPUT_SCHEMA_INVALID"
	case errors.Is(err, ErrOutputTooLarge):
		return "AOR_TOOL_OUTPUT_TOO_LARGE"
	case errors.Is(err, ErrProviderNotAllowed):
		return "AOR_MODEL_PROVIDER_NOT_ALLOWED"
	case errors.Is(err, ErrCredentialDetected):
		return "AOR_PROVIDER_CREDENTIAL_DETECTED"
	case errors.Is(err, ErrInvalidRequest):
		return "AOR_INVALID_ARGUMENT"
	default:
		var providerFailure *ProviderFailure
		if errors.As(err, &providerFailure) && !providerFailure.OutcomeKnown {
			return "AOR_PROVIDER_RESULT_UNKNOWN"
		}
		return "AOR_DEPENDENCY_UNAVAILABLE"
	}
}

func activityInterventionRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrProviderUnavailable) || errors.Is(err, ErrReconciliationRequired) {
		return true
	}
	var providerFailure *ProviderFailure
	return errors.As(err, &providerFailure) && providerFailure.Retryable
}
