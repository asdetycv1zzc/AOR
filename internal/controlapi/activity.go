package controlapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/projectactivity"
	"github.com/akimisaka/aor/internal/state"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

type activityFlow string

const (
	activityFlowGoal              activityFlow = "GOAL"
	activityFlowPlan              activityFlow = "PLAN"
	activityFlowExecution         activityFlow = "EXECUTION"
	activityFlowAudit             activityFlow = "AUDIT"
	activityFlowKnowledge         activityFlow = "KNOWLEDGE"
	maximumActivityMessageBytes                = 1 << 20
	projectActivityEventInterval               = 100 * time.Millisecond
	projectActivityHeartbeatTicks              = 150
)

type activityState string

const (
	activityQueued    activityState = "QUEUED"
	activityStreaming activityState = "STREAMING"
	activityCompleted activityState = "COMPLETED"
	activityFailed    activityState = "FAILED"
)

type activitySender string

const (
	activitySenderUser   activitySender = "USER"
	activitySenderAgent  activitySender = "AGENT"
	activitySenderSystem activitySender = "SYSTEM"
)

type projectActivityMessage struct {
	ID               string          `json:"id"`
	Cursor           string          `json:"cursor"`
	ProjectID        string          `json:"projectId"`
	TaskID           string          `json:"taskId,omitempty"`
	Flow             activityFlow    `json:"flow"`
	AgentID          string          `json:"agentId,omitempty"`
	Role             string          `json:"role,omitempty"`
	Sender           activitySender  `json:"sender"`
	State            activityState   `json:"state"`
	Content          string          `json:"content"`
	InputPrompt      string          `json:"inputPrompt,omitempty"`
	ReasoningContent string          `json:"reasoningContent,omitempty"`
	ReasoningSummary string          `json:"reasoningSummary,omitempty"`
	ErrorCode        string          `json:"errorCode,omitempty"`
	Provider         string          `json:"provider,omitempty"`
	Model            string          `json:"model,omitempty"`
	InputTokens      int64           `json:"inputTokens,omitempty"`
	OutputTokens     int64           `json:"outputTokens,omitempty"`
	LatencyMS        int64           `json:"latencyMs,omitempty"`
	OutputSHA256     string          `json:"outputSha256,omitempty"`
	CreatedAt        time.Time       `json:"createdAt"`
	UpdatedAt        time.Time       `json:"updatedAt"`
	PrincipalID      string          `json:"-"`
	IdempotencyKey   string          `json:"-"`
	RequestSHA256    string          `json:"-"`
	QueuedPrincipal  authn.Principal `json:"-"`
}

type projectActivityAgent struct {
	ID           string        `json:"id"`
	Role         string        `json:"role"`
	Flow         activityFlow  `json:"flow"`
	State        activityState `json:"state"`
	LastActiveAt time.Time     `json:"lastActiveAt"`
}

type projectActivitySnapshot struct {
	ProjectID      string                   `json:"projectId"`
	ProjectVersion int64                    `json:"projectVersion"`
	GoalProcessing bool                     `json:"goalProcessing"`
	Flows          []activityFlow           `json:"flows"`
	Agents         []projectActivityAgent   `json:"agents"`
	Messages       []projectActivityMessage `json:"messages"`
	Cursor         string                   `json:"cursor,omitempty"`
}

type activityInterventionBody struct {
	ExpectedVersion int64        `json:"expectedVersion"`
	Flow            activityFlow `json:"flow"`
	AgentID         string       `json:"agentId,omitempty"`
	Message         string       `json:"message"`
}

type activityRequestRecord struct {
	RequestSHA256 string
	MessageID     string
}

type projectActivityStore struct {
	mu       sync.RWMutex
	messages map[string][]projectActivityMessage
	requests map[string]activityRequestRecord
}

func newProjectActivityStore() *projectActivityStore {
	return &projectActivityStore{messages: make(map[string][]projectActivityMessage), requests: make(map[string]activityRequestRecord)}
}

func (store *projectActivityStore) appendIntervention(principal authn.Principal, projectID string, body activityInterventionBody, idempotencyKey string, now time.Time) (projectActivityMessage, bool, error) {
	requestSHA256 := activityRequestSHA(projectID, body)
	requestKey := principal.TenantID + "\x00" + principal.ID + "\x00" + idempotencyKey
	projectKey := activityProjectKey(principal.TenantID, projectID)

	store.mu.Lock()
	defer store.mu.Unlock()
	if previous, found := store.requests[requestKey]; found {
		if previous.RequestSHA256 != requestSHA256 {
			return projectActivityMessage{}, false, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
		}
		for _, message := range store.messages[projectKey] {
			if message.ID == previous.MessageID {
				return cloneActivityMessage(message), true, nil
			}
		}
		return projectActivityMessage{}, false, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "activity idempotency"})
	}
	messageID, err := uuid.NewV7()
	if err != nil {
		return projectActivityMessage{}, false, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, map[string]any{"scope": "activity id"})
	}
	message := projectActivityMessage{
		ID: messageID.String(), ProjectID: projectID, Flow: body.Flow, AgentID: body.AgentID,
		Sender: activitySenderUser, State: activityQueued, Content: body.Message,
		CreatedAt: now.UTC(), UpdatedAt: now.UTC(), PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, RequestSHA256: requestSHA256, QueuedPrincipal: principal,
	}
	message.Cursor = activityCursor(message)
	store.messages[projectKey] = append(store.messages[projectKey], message)
	store.requests[requestKey] = activityRequestRecord{RequestSHA256: requestSHA256, MessageID: message.ID}
	return cloneActivityMessage(message), false, nil
}

func activityRequestSHA(projectID string, body activityInterventionBody) string {
	requestDigest := sha256.Sum256([]byte(projectID + "\x00" + string(body.Flow) + "\x00" + body.AgentID + "\x00" + body.Message))
	return "sha256:" + hex.EncodeToString(requestDigest[:])
}

func (store *projectActivityStore) append(message projectActivityMessage, tenantID string) projectActivityMessage {
	store.mu.Lock()
	defer store.mu.Unlock()
	if message.ID == "" {
		message.ID = uuid.New().String()
	}
	if message.CreatedAt.IsZero() {
		message.CreatedAt = time.Now().UTC()
	}
	if message.UpdatedAt.IsZero() {
		message.UpdatedAt = message.CreatedAt
	}
	message.Cursor = activityCursor(message)
	key := activityProjectKey(tenantID, message.ProjectID)
	for index := range store.messages[key] {
		if store.messages[key][index].ID == message.ID {
			if !activityMessageUpdateWins(store.messages[key][index], message) {
				return cloneActivityMessage(store.messages[key][index])
			}
			store.messages[key][index] = message
			return cloneActivityMessage(message)
		}
	}
	store.messages[key] = append(store.messages[key], message)
	return cloneActivityMessage(message)
}

func (store *projectActivityStore) update(tenantID, projectID, messageID string, stateValue activityState, content, errorCode string, now time.Time) (projectActivityMessage, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := activityProjectKey(tenantID, projectID)
	for index := range store.messages[key] {
		message := &store.messages[key][index]
		if message.ID != messageID {
			continue
		}
		candidate := *message
		candidate.State = stateValue
		if content != "" || stateValue == activityCompleted {
			candidate.Content = content
		}
		candidate.ErrorCode = errorCode
		candidate.UpdatedAt = now.UTC()
		candidate.Cursor = activityCursor(candidate)
		if !activityMessageUpdateWins(*message, candidate) {
			return cloneActivityMessage(*message), true
		}
		*message = candidate
		return cloneActivityMessage(candidate), true
	}
	return projectActivityMessage{}, false
}

func activityMessageUpdateWins(current, candidate projectActivityMessage) bool {
	if candidate.UpdatedAt.Before(current.UpdatedAt) {
		return false
	}
	if activityStateTerminal(current.State) {
		return candidate.State == current.State
	}
	return activityStateRank(candidate.State) >= activityStateRank(current.State)
}

func activityStateTerminal(state activityState) bool {
	return state == activityCompleted || state == activityFailed
}

func activityStateRank(state activityState) int {
	switch state {
	case activityQueued:
		return 0
	case activityStreaming:
		return 1
	case activityCompleted, activityFailed:
		return 2
	default:
		return -1
	}
}

func (store *projectActivityStore) list(tenantID, projectID string) []projectActivityMessage {
	store.mu.RLock()
	defer store.mu.RUnlock()
	stored := store.messages[activityProjectKey(tenantID, projectID)]
	result := make([]projectActivityMessage, len(stored))
	for index := range stored {
		result[index] = cloneActivityMessage(stored[index])
	}
	return result
}

func (store *projectActivityStore) claimGoalIntervention(tenantID, projectID string, now time.Time) (projectActivityMessage, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	key := activityProjectKey(tenantID, projectID)
	for index := range store.messages[key] {
		message := &store.messages[key][index]
		if message.Flow != activityFlowGoal || message.Sender != activitySenderUser || message.State != activityQueued {
			continue
		}
		message.State = activityStreaming
		message.UpdatedAt = now.UTC()
		message.Cursor = activityCursor(*message)
		return cloneActivityMessage(*message), true
	}
	return projectActivityMessage{}, false
}

func cloneActivityMessage(message projectActivityMessage) projectActivityMessage {
	message.QueuedPrincipal.Attributes = cloneStringMap(message.QueuedPrincipal.Attributes)
	return message
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func activityProjectKey(tenantID, projectID string) string {
	return tenantID + "\x00" + projectID
}

func activityCursor(message projectActivityMessage) string {
	value := message.ID + "\x00" + string(message.State) + "\x00" + message.UpdatedAt.UTC().Format(time.RFC3339Nano) + "\x00" + message.Content + "\x00" + message.ErrorCode
	if message.InputPrompt != "" {
		value += "\x00" + message.InputPrompt
	}
	if message.ReasoningSummary != "" {
		value += "\x00" + message.ReasoningSummary
	}
	if message.ReasoningContent != "" {
		value += "\x00" + message.ReasoningContent
	}
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func validActivityFlow(flow activityFlow) bool {
	switch flow {
	case activityFlowGoal, activityFlowPlan, activityFlowExecution, activityFlowAudit, activityFlowKnowledge:
		return true
	default:
		return false
	}
}

func activityFlowForRole(role string) activityFlow {
	switch role {
	case "GOAL_PROPOSER", "GOAL_CHALLENGER":
		return activityFlowGoal
	case "PLAN_SUPERVISOR", "MODULE_PLANNER":
		return activityFlowPlan
	case "EXECUTOR":
		return activityFlowExecution
	case "MODULE_AUDITOR", "GLOBAL_AUDITOR":
		return activityFlowAudit
	case "KNOWLEDGE_CURATOR":
		return activityFlowKnowledge
	default:
		return activityFlowExecution
	}
}

func (handler *Handler) projectActivity(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity query"}))
		return
	}
	snapshot, err := handler.activitySnapshot(request.Context(), principal, projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	if handler.goalPlan.Negotiator != nil && !snapshot.GoalProcessing {
		handler.startNextGoalIntervention(request.Context(), principal.TenantID, projectID)
		if refreshed, refreshErr := handler.activitySnapshot(request.Context(), principal, projectID); refreshErr == nil {
			snapshot = refreshed
		}
	}
	response.Header().Set("ETag", entityTag(snapshot.ProjectVersion))
	writeJSON(response, http.StatusOK, snapshot)
}

func (handler *Handler) activitySnapshot(ctx context.Context, principal authn.Principal, projectID string) (projectActivitySnapshot, error) {
	project, err := handler.authorizeProjectResourceRead(ctx, principal, projectID, authz.ActionProjectRead, "project-activity", projectID)
	if err != nil {
		return projectActivitySnapshot{}, err
	}
	messages := handler.activity.list(principal.TenantID, projectID)
	if handler.persistentActivity != nil {
		stored, listErr := handler.persistentActivity.List(ctx, principal.TenantID, projectID)
		if listErr != nil {
			return projectActivitySnapshot{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", listErr, map[string]any{"scope": "project activity"})
		}
		for _, message := range stored {
			messages = append(messages, activityFromStored(message))
		}
	}
	persisted, err := handler.persistedActivityMessages(ctx, principal.TenantID, projectID)
	if err != nil {
		return projectActivitySnapshot{}, err
	}
	messages = mergeActivityMessages(messages, persisted)
	messages = collapseConversationDuplicates(messages)
	sortActivityMessages(messages)
	agents := activityAgents(messages)
	snapshot := projectActivitySnapshot{
		ProjectID: projectID, ProjectVersion: project.Version, GoalProcessing: project.GoalProcessing,
		Flows:  []activityFlow{activityFlowGoal, activityFlowPlan, activityFlowExecution, activityFlowAudit, activityFlowKnowledge},
		Agents: agents, Messages: messages,
	}
	if len(messages) != 0 {
		snapshot.Cursor = messages[len(messages)-1].Cursor
	}
	return snapshot, nil
}

func activityFromStored(message projectactivity.Message) projectActivityMessage {
	result := projectActivityMessage{
		ID: message.ID, ProjectID: message.ProjectID, TaskID: message.TaskID,
		Flow: activityFlow(message.Flow), AgentID: message.AgentInstanceID, Role: message.Role,
		Sender: activitySender(message.Sender), State: activityState(message.State), Content: message.Content,
		InputPrompt: message.InputPrompt, ReasoningContent: message.ReasoningContent,
		ReasoningSummary: message.ReasoningSummary,
		ErrorCode:        message.ErrorCode, Provider: message.Provider, Model: message.Model,
		InputTokens: message.InputTokens, OutputTokens: message.OutputTokens,
		LatencyMS: message.LatencyMS, OutputSHA256: message.OutputSHA256,
		CreatedAt: message.CreatedAt.UTC(), UpdatedAt: message.UpdatedAt.UTC(), PrincipalID: message.PrincipalID,
		IdempotencyKey: message.IdempotencyKey, RequestSHA256: message.RequestSHA256,
	}
	result.Cursor = activityCursor(result)
	return result
}

func activityToStored(tenantID string, message projectActivityMessage) projectactivity.Message {
	return projectactivity.Message{
		TenantID: tenantID, ProjectID: message.ProjectID, ID: message.ID, TaskID: message.TaskID,
		Flow: projectactivity.Flow(message.Flow), AgentInstanceID: message.AgentID, Role: message.Role,
		Sender: projectactivity.Sender(message.Sender), State: projectactivity.State(message.State),
		Content: message.Content, InputPrompt: message.InputPrompt, ReasoningContent: message.ReasoningContent,
		ReasoningSummary: message.ReasoningSummary,
		ErrorCode:        message.ErrorCode, Provider: message.Provider, Model: message.Model,
		InputTokens: message.InputTokens, OutputTokens: message.OutputTokens, LatencyMS: message.LatencyMS,
		OutputSHA256: message.OutputSHA256, PrincipalID: message.PrincipalID,
		IdempotencyKey: message.IdempotencyKey, RequestSHA256: message.RequestSHA256,
		CreatedAt: message.CreatedAt.UTC(), UpdatedAt: message.UpdatedAt.UTC(),
	}
}

func (handler *Handler) persistActivity(ctx context.Context, tenantID string, message projectActivityMessage) error {
	if handler.persistentActivity == nil {
		return nil
	}
	if err := handler.persistentActivity.Upsert(ctx, activityToStored(tenantID, message)); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "project activity"})
	}
	return nil
}

func (handler *Handler) appendActivity(ctx context.Context, tenantID string, message projectActivityMessage) projectActivityMessage {
	message.CreatedAt = activityTimestamp(message.CreatedAt)
	message.UpdatedAt = activityTimestamp(message.UpdatedAt)
	message = handler.activity.append(message, tenantID)
	_ = handler.persistActivity(ctx, tenantID, message)
	return message
}

func (handler *Handler) updateActivity(ctx context.Context, tenantID, projectID, messageID string, stateValue activityState, content, errorCode string, now time.Time) (projectActivityMessage, bool) {
	message, found := handler.activity.update(tenantID, projectID, messageID, stateValue, content, errorCode, activityTimestamp(now))
	if found {
		_ = handler.persistActivity(ctx, tenantID, message)
	}
	return message, found
}

func activityTimestamp(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func (handler *Handler) persistedActivityMessages(ctx context.Context, tenantID, projectID string) ([]projectActivityMessage, error) {
	messages, err := handler.orchestrator.GoalMessages(ctx, tenantID, projectID)
	if err != nil {
		return nil, normalizeError(err)
	}
	result := make([]projectActivityMessage, 0, len(messages))
	for _, message := range messages {
		activity := projectActivityMessage{
			ID: "goal-message-" + message.ID, ProjectID: projectID, Flow: activityFlowGoal,
			Sender: activitySenderUser, State: activityCompleted, Content: message.Message,
			CreatedAt: message.CreatedAt.UTC(), UpdatedAt: message.CreatedAt.UTC(), PrincipalID: message.CreatedBy,
		}
		activity.Cursor = activityCursor(activity)
		result = append(result, activity)
	}
	goalSpecs, err := handler.orchestrator.GoalSpecs(ctx, tenantID, projectID)
	if err != nil {
		return nil, normalizeError(err)
	}
	for _, projection := range goalSpecs {
		content, encodeErr := json.Marshal(projection.Spec.Content)
		if encodeErr != nil {
			return nil, aorerrors.Wrap(aorerrors.CodeInternalError, "", encodeErr, map[string]any{"scope": "goal activity"})
		}
		createdAt, parseErr := time.Parse(time.RFC3339Nano, projection.Spec.Content.CreatedAt)
		if parseErr != nil {
			createdAt = handler.clock().UTC()
		}
		activity := projectActivityMessage{
			ID: "goal-spec-" + projection.RecordID, ProjectID: projectID, Flow: activityFlowGoal,
			AgentID: projection.Spec.Content.CreatedBy.AgentInstanceID, Role: projection.Spec.Content.CreatedBy.Role,
			Sender: activitySenderAgent, State: activityCompleted, Content: string(content),
			OutputSHA256: projection.Spec.ContentSHA256, CreatedAt: createdAt.UTC(), UpdatedAt: createdAt.UTC(),
		}
		activity.Cursor = activityCursor(activity)
		result = append(result, activity)
	}
	if handler.events != nil {
		events, listErr := handler.events.ListEvents(ctx, tenantID)
		if listErr != nil {
			return nil, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", listErr, map[string]any{"scope": "project activity events"})
		}
		for _, event := range events {
			if event.ProjectID != projectID {
				continue
			}
			flow, content, visible := systemActivityForEvent(event.Type)
			if !visible {
				continue
			}
			activity := projectActivityMessage{
				ID: "system-event-" + event.EventID, ProjectID: projectID, TaskID: event.TaskID,
				Flow: flow, Sender: activitySenderSystem, State: activityCompleted, Content: content,
				CreatedAt: event.OccurredAt.UTC(), UpdatedAt: event.OccurredAt.UTC(),
			}
			activity.Cursor = activityCursor(activity)
			result = append(result, activity)
		}
	}
	return result, nil
}

func systemActivityForEvent(eventType string) (activityFlow, string, bool) {
	switch eventType {
	case "io.aor.goal.negotiation-started.v1":
		return activityFlowGoal, "目标协商已开始", true
	case "io.aor.goal.toolchain-ready.v1":
		return activityFlowGoal, "工具链已安装，目标协商正在继续", true
	case "io.aor.goal.message-received.v1":
		return activityFlowGoal, "后端已接收目标", true
	case "io.aor.goal.proposed.v1":
		return activityFlowGoal, "GoalSpec 已生成", true
	case "io.aor.goal.approved.v1":
		return activityFlowGoal, "目标已批准", true
	case "io.aor.goal.rejected.v1":
		return activityFlowGoal, "目标已拒绝", true
	case "io.aor.goal.change-requested.v1":
		return activityFlowGoal, "目标已进入修改流程", true
	case "io.aor.plan.published.v1":
		return activityFlowPlan, "计划已发布", true
	case "io.aor.plan.core-progress-recorded.v1":
		return activityFlowPlan, "计划进度已更新", true
	case "io.aor.plan.core-summary-published.v1":
		return activityFlowPlan, "核心流程摘要已生成", true
	case "io.aor.module.planning-queued.v1":
		return activityFlowPlan, "模块已进入规划队列", true
	case "io.aor.module.planning-started.v1":
		return activityFlowPlan, "模块规划已开始", true
	case "io.aor.module.defined.v1":
		return activityFlowPlan, "模块任务已创建", true
	case "io.aor.module.spec-attached.v1":
		return activityFlowPlan, "模块规格已就绪", true
	case "io.aor.module.execution-ready.v1":
		return activityFlowExecution, "模块已准备执行", true
	case "io.aor.module.execution-leased.v1":
		return activityFlowExecution, "执行 Agent 已接收模块", true
	case "io.aor.module.execution-recovered.v1":
		return activityFlowExecution, "模块执行已恢复", true
	case "io.aor.module.implementation-submitted.v1":
		return activityFlowExecution, "模块实现已提交", true
	case "io.aor.module.integrated.v1":
		return activityFlowExecution, "模块已完成集成", true
	case "io.aor.module.rework-queued.v1":
		return activityFlowExecution, "模块已进入返工队列", true
	case "io.aor.module.blocked-dependency.v1":
		return activityFlowExecution, "模块正在等待依赖", true
	case "io.aor.module.unblocked-dependency.v1":
		return activityFlowExecution, "模块依赖已满足", true
	case "io.aor.module.blocked-user-decision.v1":
		return activityFlowExecution, "模块正在等待用户决策", true
	case "io.aor.module.deterministic-audit-started.v1":
		return activityFlowAudit, "确定性审计已开始", true
	case "io.aor.module.deterministic-audit-passed.v1":
		return activityFlowAudit, "确定性审计已通过", true
	case "io.aor.module.deterministic-audit-failed.v1":
		return activityFlowAudit, "确定性审计未通过", true
	case "io.aor.module.llm-audit-passed.v1":
		return activityFlowAudit, "Agent 审计已通过", true
	case "io.aor.module.llm-audit-failed.v1":
		return activityFlowAudit, "Agent 审计未通过", true
	case "io.aor.project.global-audit-started.v1":
		return activityFlowAudit, "全局审计已开始", true
	case "io.aor.project.global-audit-remediation-started.v1":
		return activityFlowAudit, "全局审计整改已开始", true
	case "io.aor.knowledge.updated.v1", "io.aor.knowledge.update-approved.v1":
		return activityFlowKnowledge, "项目知识已更新", true
	case "io.aor.project.integration-started.v1":
		return activityFlowExecution, "集成流程已开始", true
	case "io.aor.integration.summary-published.v1":
		return activityFlowExecution, "集成摘要已生成", true
	case "io.aor.project.completed.v1":
		return activityFlowExecution, "项目已完成", true
	case "io.aor.project.aborted.v1":
		return activityFlowExecution, "项目已终止", true
	case "io.aor.project.paused.v1":
		return activityFlowExecution, "项目已暂停", true
	case "io.aor.project.resumed.v1":
		return activityFlowExecution, "项目已恢复", true
	default:
		return "", "", false
	}
}

func mergeActivityMessages(live, persisted []projectActivityMessage) []projectActivityMessage {
	result := make([]projectActivityMessage, 0, len(live)+len(persisted))
	byID := make(map[string]int, len(live)+len(persisted))
	for _, message := range append(live, persisted...) {
		if index, found := byID[message.ID]; found {
			if message.UpdatedAt.After(result[index].UpdatedAt) {
				result[index] = cloneActivityMessage(message)
			}
			continue
		}
		byID[message.ID] = len(result)
		result = append(result, cloneActivityMessage(message))
	}
	return result
}

// Activity contains both durable domain projections and runtime telemetry.
// Keep the runtime row for live updates, while suppressing the corresponding
// domain projection when both describe the same conversation turn.
func collapseConversationDuplicates(messages []projectActivityMessage) []projectActivityMessage {
	const matchWindow = 2 * time.Second
	dropped := make(map[string]bool)
	usedUsers := make(map[string]bool)
	modelRows := make([]projectActivityMessage, 0)
	for _, message := range messages {
		if strings.HasPrefix(message.ID, "model:") && message.Sender == activitySenderAgent {
			modelRows = append(modelRows, message)
		}
	}
	for _, message := range messages {
		if !strings.HasPrefix(message.ID, "goal-message-") || message.Sender != activitySenderUser {
			continue
		}
		bestID := ""
		bestDistance := time.Duration(1<<63 - 1)
		for _, candidate := range messages {
			if candidate.Sender != activitySenderUser || strings.HasPrefix(candidate.ID, "goal-message-") || usedUsers[candidate.ID] || candidate.Content != message.Content || candidate.Flow != message.Flow {
				continue
			}
			distance := activityTimeDistance(candidate.CreatedAt, message.CreatedAt)
			if distance <= matchWindow && distance < bestDistance {
				bestID, bestDistance = candidate.ID, distance
			}
		}
		if bestID != "" {
			usedUsers[bestID] = true
			dropped[message.ID] = true
		}
	}
	for _, message := range messages {
		if message.Sender != activitySenderAgent || message.Flow != activityFlowGoal {
			continue
		}
		if strings.HasPrefix(message.ID, "goalplan:") && (strings.HasSuffix(message.ID, ":activity") || strings.HasSuffix(message.ID, ":challenge-activity")) {
			for _, model := range modelRows {
				if model.Flow == message.Flow && model.Role == message.Role && model.AgentID == message.AgentID && model.CreatedAt.Before(message.UpdatedAt.Add(matchWindow)) && !model.UpdatedAt.Before(message.CreatedAt.Add(-matchWindow)) {
					dropped[message.ID] = true
					break
				}
			}
		}
		if strings.HasPrefix(message.ID, "goal-spec-") && message.State == activityCompleted {
			for _, model := range modelRows {
				if model.Flow == message.Flow && model.Role == message.Role && model.AgentID == message.AgentID && activityTimeDistance(model.UpdatedAt, message.CreatedAt) <= matchWindow {
					dropped[message.ID] = true
					break
				}
			}
		}
	}
	result := make([]projectActivityMessage, 0, len(messages)-len(dropped))
	for _, message := range messages {
		if !dropped[message.ID] {
			result = append(result, message)
		}
	}
	return result
}

func activityTimeDistance(left, right time.Time) time.Duration {
	if left.After(right) {
		return left.Sub(right)
	}
	return right.Sub(left)
}

func sortActivityMessages(messages []projectActivityMessage) {
	sort.SliceStable(messages, func(left, right int) bool {
		if messages[left].CreatedAt.Equal(messages[right].CreatedAt) {
			return messages[left].ID < messages[right].ID
		}
		return messages[left].CreatedAt.Before(messages[right].CreatedAt)
	})
}

func activityAgents(messages []projectActivityMessage) []projectActivityAgent {
	agents := make(map[string]projectActivityAgent)
	for _, message := range messages {
		if message.AgentID == "" || message.Role == "" {
			continue
		}
		candidate := projectActivityAgent{ID: message.AgentID, Role: message.Role, Flow: message.Flow, State: message.State, LastActiveAt: message.UpdatedAt}
		if current, found := agents[message.AgentID]; !found || candidate.LastActiveAt.After(current.LastActiveAt) {
			agents[message.AgentID] = candidate
		}
	}
	result := make([]projectActivityAgent, 0, len(agents))
	for _, agent := range agents {
		result = append(result, agent)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Flow != result[right].Flow {
			return result[left].Flow < result[right].Flow
		}
		return result[left].ID < result[right].ID
	})
	return result
}

func (handler *Handler) submitActivityIntervention(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity intervention query"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body activityInterventionBody
	if err := decodeJSON(request, &body); err != nil || body.ExpectedVersion < 1 || !validActivityFlow(body.Flow) || strings.TrimSpace(body.Message) == "" || len(body.Message) > maximumActivityMessageBytes || strings.ContainsRune(body.Message, '\x00') || len(body.AgentID) > 256 || strings.ContainsAny(body.AgentID, "\r\n\x00") {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity intervention"}))
		return
	}
	if err := validateGoalIfMatch(request, body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	project, found, err := handler.orchestrator.Project(request.Context(), principal.TenantID, projectID)
	if err != nil || !found {
		if err == nil {
			err = aorerrors.New(aorerrors.CodeNotFound, "", nil)
		}
		writeError(response, request, normalizeError(err))
		return
	}
	if project.Version != body.ExpectedVersion {
		writeError(response, request, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": body.ExpectedVersion, "actualVersion": project.Version}))
		return
	}
	if err := authorizeRead(request.Context(), handler.authorizer, principal, projectID, authz.ActionProjectCommand, "project-activity-intervention", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	if handler.persistentActivity != nil {
		requestSHA := activityRequestSHA(projectID, body)
		storedMessage, found, lookupErr := handler.persistentActivity.FindByIdempotency(request.Context(), principal.TenantID, principal.ID, idempotencyKey)
		if lookupErr != nil {
			writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", lookupErr, map[string]any{"scope": "project activity idempotency"}))
			return
		}
		if found {
			if storedMessage.RequestSHA256 != requestSHA {
				writeError(response, request, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil))
				return
			}
			if storedMessage.ProjectID != projectID {
				writeError(response, request, aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil))
				return
			}
			message := activityFromStored(storedMessage)
			if message.Sender == activitySenderUser && message.State == activityQueued {
				message.QueuedPrincipal = principal
			}
			handler.activity.append(message, principal.TenantID)
			if message.Flow == activityFlowGoal && message.State == activityQueued && !project.GoalProcessing {
				handler.startNextGoalIntervention(request.Context(), principal.TenantID, projectID)
				if refreshed, found := handler.activityMessage(principal.TenantID, projectID, message.ID); found {
					message = refreshed
				}
			}
			response.Header().Set("ETag", entityTag(project.Version))
			writeJSON(response, http.StatusAccepted, message)
			return
		}
	}
	message, _, err := handler.activity.appendIntervention(principal, projectID, body, idempotencyKey, activityTimestamp(handler.clock()))
	if err != nil {
		writeError(response, request, err)
		return
	}
	if err := handler.persistActivity(request.Context(), principal.TenantID, message); err != nil {
		writeError(response, request, err)
		return
	}
	if body.Flow == activityFlowGoal && !project.GoalProcessing && message.State == activityQueued {
		handler.startNextGoalIntervention(request.Context(), principal.TenantID, projectID)
		message, _ = handler.activityMessage(principal.TenantID, projectID, message.ID)
	}
	response.Header().Set("ETag", entityTag(project.Version))
	writeJSON(response, http.StatusAccepted, message)
}

func (handler *Handler) activityMessage(tenantID, projectID, messageID string) (projectActivityMessage, bool) {
	for _, message := range handler.activity.list(tenantID, projectID) {
		if message.ID == messageID {
			return message, true
		}
	}
	return projectActivityMessage{}, false
}

func (handler *Handler) startNextGoalIntervention(ctx context.Context, tenantID, projectID string) {
	project, projectFound, err := handler.orchestrator.Project(ctx, tenantID, projectID)
	if err != nil || !projectFound || project.GoalProcessing {
		return
	}
	handler.hydrateQueuedInterventions(ctx, tenantID, projectID)
	message, found := handler.activity.claimGoalIntervention(tenantID, projectID, activityTimestamp(handler.clock()))
	if !found {
		return
	}
	_ = handler.persistActivity(ctx, tenantID, message)
	principal := message.QueuedPrincipal
	body := goalMessageBody{ExpectedVersion: project.Version, Message: message.Content}
	if handler.goalPlan.Negotiator == nil {
		_, err := handler.orchestrator.HandleProject(ctx, orchestrator.ProjectRequest{
			TenantID: tenantID, ProjectID: projectID, PrincipalID: principal.ID,
			IdempotencyKey: goalPlanKey("intervention", tenantID, projectID, principal.ID, message.ID), ExpectedVersion: project.Version,
			Command: state.ProjectCommand{Type: state.ProjectCommandSubmitGoalMessage, GoalMessage: &state.GoalMessage{Kind: state.GoalMessageUser, Message: message.Content}},
		})
		if err != nil {
			handler.failClaimedIntervention(ctx, tenantID, projectID, message.ID, normalizeError(err))
			return
		}
		handler.updateActivity(ctx, tenantID, projectID, message.ID, activityCompleted, message.Content, "", handler.clock())
		handler.startNextGoalIntervention(ctx, tenantID, projectID)
		return
	}
	accepted, negotiation, err := handler.acceptGoalNegotiation(ctx, principal, projectID, body, goalPlanKey("intervention", tenantID, projectID, principal.ID, message.ID))
	if err != nil {
		handler.failClaimedIntervention(ctx, tenantID, projectID, message.ID, normalizeGoalPlanError(err))
		return
	}
	handler.updateActivity(ctx, tenantID, projectID, message.ID, activityCompleted, message.Content, "", handler.clock())
	if negotiation != nil {
		handler.startGoalNegotiation(ctx, principal, *negotiation)
	}
	_ = accepted
}

func (handler *Handler) hydrateQueuedInterventions(ctx context.Context, tenantID, projectID string) {
	if handler.persistentActivity == nil {
		return
	}
	stored, err := handler.persistentActivity.List(ctx, tenantID, projectID)
	if err != nil {
		return
	}
	for _, storedMessage := range stored {
		if storedMessage.Sender != projectactivity.SenderUser || storedMessage.State != projectactivity.StateQueued || storedMessage.Flow != projectactivity.FlowGoal {
			continue
		}
		message := activityFromStored(storedMessage)
		message.QueuedPrincipal = authn.Principal{ID: storedMessage.PrincipalID, Type: authn.PrincipalUser, Role: authn.RoleUser, TenantID: tenantID}
		handler.activity.append(message, tenantID)
	}
}

func (handler *Handler) failClaimedIntervention(ctx context.Context, tenantID, projectID, messageID string, err error) {
	code := string(aorerrors.CodeInternalError)
	content := "Intervention could not be applied"
	var typed *aorerrors.Error
	if errors.As(err, &typed) {
		code = string(typed.Code)
		content = aorerrors.MetadataFor(typed.Code).Message
	}
	handler.updateActivity(ctx, tenantID, projectID, messageID, activityFailed, content, code, handler.clock())
}

func (handler *Handler) projectActivityEvents(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	after, err := eventCursor(request)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "activity cursor"}))
		return
	}
	snapshot, err := handler.activitySnapshot(request.Context(), principal, projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Accel-Buffering", "no")
	response.Header().Set("Connection", "keep-alive")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(http.StatusOK)
	lastCursor := after
	if err := writeActivityMessages(response, activityMessagesAfter(snapshot.Messages, lastCursor)); err != nil {
		return
	}
	seen := activityCursorMap(snapshot.Messages)
	if len(snapshot.Messages) != 0 {
		lastCursor = snapshot.Messages[len(snapshot.Messages)-1].Cursor
	}
	if !eventFollowRequested(request) {
		return
	}
	if len(snapshot.Messages) == 0 {
		if _, err := io.WriteString(response, ": connected\n\n"); err != nil {
			return
		}
		if flusher, ok := response.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	ticker := time.NewTicker(projectActivityEventInterval)
	defer ticker.Stop()
	idleTicks := 0
	for {
		select {
		case <-request.Context().Done():
			return
		case <-ticker.C:
			idleTicks++
			latest, snapshotErr := handler.activitySnapshot(request.Context(), principal, projectID)
			if snapshotErr != nil {
				return
			}
			pending := changedActivityMessages(latest.Messages, seen)
			if err := writeActivityMessages(response, pending); err != nil {
				return
			}
			if len(pending) == 0 && idleTicks >= projectActivityHeartbeatTicks {
				if _, err := io.WriteString(response, ": heartbeat\n\n"); err != nil {
					return
				}
				if flusher, ok := response.(http.Flusher); ok {
					flusher.Flush()
				}
				idleTicks = 0
			} else if len(pending) != 0 {
				idleTicks = 0
			}
			seen = activityCursorMap(latest.Messages)
			if len(latest.Messages) != 0 {
				lastCursor = latest.Messages[len(latest.Messages)-1].Cursor
			}
		}
	}
}

func activityCursorMap(messages []projectActivityMessage) map[string]string {
	result := make(map[string]string, len(messages))
	for _, message := range messages {
		result[message.ID] = message.Cursor
	}
	return result
}

func changedActivityMessages(messages []projectActivityMessage, seen map[string]string) []projectActivityMessage {
	result := make([]projectActivityMessage, 0)
	for _, message := range messages {
		if seen[message.ID] != message.Cursor {
			result = append(result, message)
		}
	}
	return result
}

func activityMessagesAfter(messages []projectActivityMessage, cursor string) []projectActivityMessage {
	// Messages are mutable while a model is streaming. A cursor identifies a
	// row version, not an append-only position; replay the snapshot so a
	// reconnect cannot miss an older row's completion update.
	_ = cursor
	return messages
}

func writeActivityMessages(response http.ResponseWriter, messages []projectActivityMessage) error {
	for _, message := range messages {
		if !safeSSEField(message.Cursor) {
			return errors.New("unsafe activity SSE cursor")
		}
		payload, err := json.Marshal(message)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(response, "id: "+message.Cursor+"\n"); err != nil {
			return err
		}
		if _, err := io.WriteString(response, "event: activity\n"); err != nil {
			return err
		}
		if _, err := io.WriteString(response, "data: "+string(payload)+"\n\n"); err != nil {
			return err
		}
		if flusher, ok := response.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	return nil
}

func (handler *Handler) beginGoalActivity(ctx context.Context, request goalplan.NegotiationRequest) string {
	now := handler.clock().UTC()
	message := projectActivityMessage{
		ID: request.IdempotencyKey + ":activity", ProjectID: request.ProjectID, Flow: activityFlowGoal,
		AgentID: request.ProjectID + ":GOAL_PROPOSER", Role: "GOAL_PROPOSER",
		Sender: activitySenderAgent, State: activityStreaming, Content: "", CreatedAt: now, UpdatedAt: now,
	}
	handler.appendActivity(ctx, request.TenantID, message)
	return message.ID
}

func (handler *Handler) completeGoalActivity(ctx context.Context, request goalplan.NegotiationRequest, messageID string, result goalplan.NegotiationResult, err error) {
	now := handler.clock().UTC()
	if err != nil {
		normalized := normalizeGoalPlanError(err)
		code := string(aorerrors.CodeInternalError)
		content := "Goal agent request failed"
		var typed *aorerrors.Error
		if errors.As(normalized, &typed) {
			code = string(typed.Code)
			content = aorerrors.MetadataFor(typed.Code).Message
		}
		handler.updateActivity(ctx, request.TenantID, request.ProjectID, messageID, activityFailed, content, code, now)
		return
	}
	content, encodeErr := json.Marshal(result.Goal.Content)
	if encodeErr != nil {
		handler.updateActivity(ctx, request.TenantID, request.ProjectID, messageID, activityFailed, "Goal result could not be displayed", string(aorerrors.CodeInternalError), now)
		return
	}
	handler.updateActivity(ctx, request.TenantID, request.ProjectID, messageID, activityCompleted, string(content), "", now)
	if result.Challenge != nil {
		challenge, encodeErr := json.Marshal(result.Challenge)
		if encodeErr == nil {
			handler.appendActivity(ctx, request.TenantID, projectActivityMessage{
				ID: request.IdempotencyKey + ":challenge-activity", ProjectID: request.ProjectID, Flow: activityFlowGoal,
				AgentID: request.ProjectID + ":GOAL_CHALLENGER", Role: "GOAL_CHALLENGER",
				Sender: activitySenderAgent, State: activityCompleted, Content: string(challenge), CreatedAt: now, UpdatedAt: now,
			})
		}
	}
}

func (handler *Handler) beginPlanActivity(ctx context.Context, request goalplan.PlanningRequest) string {
	now := handler.clock().UTC()
	message := projectActivityMessage{
		ID: request.IdempotencyKey + ":activity", ProjectID: request.ProjectID, Flow: activityFlowPlan,
		AgentID: request.ProjectID + ":PLAN_SUPERVISOR", Role: "PLAN_SUPERVISOR",
		Sender: activitySenderAgent, State: activityStreaming, Content: "", CreatedAt: now, UpdatedAt: now,
	}
	handler.appendActivity(ctx, request.TenantID, message)
	return message.ID
}

func (handler *Handler) completePlanActivity(ctx context.Context, request goalplan.PlanningRequest, messageID string, result goalplan.PlanningResult, err error) {
	now := handler.clock().UTC()
	if err != nil {
		normalized := normalizeGoalPlanError(err)
		code := string(aorerrors.CodeInternalError)
		content := "Planning agent request failed"
		var typed *aorerrors.Error
		if errors.As(normalized, &typed) {
			code = string(typed.Code)
			content = aorerrors.MetadataFor(typed.Code).Message
		}
		handler.updateActivity(ctx, request.TenantID, request.ProjectID, messageID, activityFailed, content, code, now)
		return
	}
	content, encodeErr := json.Marshal(result.Plan)
	if encodeErr != nil {
		handler.updateActivity(ctx, request.TenantID, request.ProjectID, messageID, activityFailed, "Plan result could not be displayed", string(aorerrors.CodeInternalError), now)
		return
	}
	handler.updateActivity(ctx, request.TenantID, request.ProjectID, messageID, activityCompleted, string(content), "", now)
}
