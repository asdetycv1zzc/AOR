package controlapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/google/uuid"
)

const maximumRequestBytes = 1 << 20

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Config struct {
	Store         eventing.Store
	Authenticator authn.Authenticator
	Authorizer    authz.PolicyEvaluator
	Database      *sql.DB
	Budgets       modelgateway.BudgetAdministration
	Clock         func() time.Time
}

type Handler struct {
	orchestrator  *orchestrator.Service
	store         eventing.Store
	events        eventing.EventLog
	authenticator authn.Authenticator
	authorizer    authz.PolicyEvaluator
	database      *sql.DB
	budgets       modelgateway.BudgetAdministration
	autoBudget    bool
	clock         func() time.Time
}

type projectCreate struct {
	Name               string `json:"name"`
	GoalAgentCount     int    `json:"goalAgentCount"`
	DataClassification string `json:"dataClassification"`
}

type commandBody struct {
	ExpectedVersion int64 `json:"expectedVersion"`
}

type budgetAdjustmentBody struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	HardLimitMinor  int64  `json:"hardLimitMinor"`
	SoftLimitMinor  int64  `json:"softLimitMinor"`
	Currency        string `json:"currency"`
	Reason          string `json:"reason"`
}

type page struct {
	Items      any    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type budgetAccountResource struct {
	ID             string     `json:"id"`
	ScopeType      string     `json:"scopeType"`
	ScopeID        string     `json:"scopeId"`
	Currency       string     `json:"currency"`
	HardLimitMinor int64      `json:"hardLimitMinor"`
	SoftLimitMinor int64      `json:"softLimitMinor"`
	SpentMinor     int64      `json:"spentMinor"`
	ReservedMinor  int64      `json:"reservedMinor"`
	RemainingMinor int64      `json:"remainingMinor"`
	PeriodStart    time.Time  `json:"periodStart"`
	PeriodEnd      *time.Time `json:"periodEnd,omitempty"`
	Version        int64      `json:"version"`
}

type budgetCollection struct {
	ProjectID string                  `json:"projectId"`
	Items     []budgetAccountResource `json:"items"`
	Version   int64                   `json:"version"`
}

type budgetUsageResource struct {
	ProjectID        string `json:"projectId"`
	AccountID        string `json:"accountId"`
	Currency         string `json:"currency"`
	HardLimitMinor   int64  `json:"hardLimitMinor"`
	SoftLimitMinor   int64  `json:"softLimitMinor"`
	SpentMinor       int64  `json:"spentMinor"`
	ReservedMinor    int64  `json:"reservedMinor"`
	RemainingMinor   int64  `json:"remainingMinor"`
	ReservationCount int64  `json:"reservationCount"`
	CallCount        int64  `json:"callCount"`
	InputTokens      int64  `json:"inputTokens"`
	OutputTokens     int64  `json:"outputTokens"`
	CostMinor        int64  `json:"costMinor"`
	Version          int64  `json:"version"`
}

type budgetAdjustmentResource struct {
	ProjectID string                `json:"projectId"`
	Account   budgetAccountResource `json:"account"`
	Usage     budgetUsageResource   `json:"usage"`
}

func New(config Config) (*Handler, error) {
	if config.Store == nil || config.Authenticator == nil || config.Authorizer == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "control api configuration"})
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	autoBudget := false
	if config.Budgets == nil && config.Database != nil {
		ledger, err := modelgateway.NewPostgresBudgetLedger(config.Database, config.Clock, 0)
		if err != nil {
			return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "budget ledger"})
		}
		config.Budgets = ledger
	} else if config.Budgets == nil {
		config.Budgets = modelgateway.NewBudgetLedger(config.Clock)
		autoBudget = true
	}
	boundary, err := NewPolicyCommitBoundary(config.Authorizer)
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		orchestrator:  orchestrator.NewWithBoundary(config.Store, config.Clock, boundary),
		store:         config.Store,
		authenticator: config.Authenticator,
		authorizer:    config.Authorizer,
		database:      config.Database,
		budgets:       config.Budgets,
		autoBudget:    autoBudget,
		clock:         config.Clock,
	}
	handler.events, _ = config.Store.(eventing.EventLog)
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	principal, err := handler.authenticate(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	request = request.WithContext(contextWithPrincipal(request.Context(), principal))

	if request.URL.Path == "/v1/projects" {
		if request.Method == http.MethodPost {
			handler.createProject(response, request, principal)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	parts, ok := splitProjectPath(request.URL.Path)
	if !ok {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	projectID := parts[0]
	if len(parts) == 1 {
		if id, commandName, found := strings.Cut(projectID, ":"); found {
			if !validProjectID(id) {
				writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
				return
			}
			if request.Method == http.MethodPost && validProjectID(id) && commandName != "" {
				handler.commandProject(response, request, principal, id, commandName)
				return
			}
			writeMethodNotAllowed(response, request)
			return
		}
	}
	if len(parts) == 1 {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getProject(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "state" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getProject(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "events" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.projectEvents(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "tasks" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.listTasks(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "budgets" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getBudgets(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if (len(parts) == 2 && parts[1] == "usage") || (len(parts) == 3 && parts[1] == "budgets" && parts[2] == "usage") {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getBudgetUsage(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "budgets:adjust" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodPost {
			handler.adjustBudget(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 3 && parts[1] == "tasks" {
		if !validProjectID(projectID) || !validAPIIdentifier(parts[2]) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getTask(response, request, principal, projectID, parts[2])
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
}

func (handler *Handler) authenticate(request *http.Request) (authn.Principal, error) {
	if handler == nil || handler.authenticator == nil || request == nil {
		return authn.Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	principal, err := authn.AuthenticateHTTPRequest(request, handler.authenticator)
	if err != nil || principal.TenantID == "" || !uuidPattern.MatchString(strings.ToLower(principal.TenantID)) {
		return authn.Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	return principal, nil
}

func (handler *Handler) createProject(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body projectCreate
	if err := decodeJSON(request, &body); err != nil || body.Name == "" || len(body.Name) > 256 || body.GoalAgentCount < 1 || body.GoalAgentCount > 2 || !oneOf(body.DataClassification, "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED") {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project create"}))
		return
	}
	projectUUID, err := uuid.NewV7()
	if err != nil {
		writeError(response, request, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil))
		return
	}
	projectID := projectUUID.String()
	if err := authorizeVirtualProject(request.Context(), handler.authorizer, principal, projectID, "project.create", body.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	if err := handler.ensureTenant(request.Context(), principal.TenantID); err != nil {
		writeError(response, request, err)
		return
	}
	outcome, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: 0,
		Command: state.ProjectCommand{Type: state.ProjectCommandCreate, Name: body.Name, GoalAgentCount: body.GoalAgentCount, DataClassification: body.DataClassification},
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if handler.autoBudget {
		creator, ok := handler.budgets.(interface {
			CreateAccount(context.Context, modelgateway.BudgetAccount) error
		})
		if !ok {
			writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "budget account"}))
			return
		}
		err := creator.CreateAccount(request.Context(), modelgateway.BudgetAccount{
			ID: outcome.Project.ID, TenantID: principal.TenantID, ScopeType: "PROJECT", ScopeID: outcome.Project.ID,
			Currency: "USD", PeriodStart: handler.clock().UTC(), Version: 1,
		})
		if err != nil && !errors.Is(err, modelgateway.ErrReservationConflict) {
			writeError(response, request, normalizeBudgetError(err))
			return
		}
	}
	writeProject(response, http.StatusCreated, outcome.Project)
}

func (handler *Handler) getProject(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	project, found, err := handler.orchestrator.Project(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if !found {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	if err := authorizeRead(request.Context(), handler.authorizer, principal, projectID, "project.read", "project", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	writeProject(response, http.StatusOK, project)
}

func (handler *Handler) commandProject(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, commandName string) {
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body commandBody
	if err := decodeJSON(request, &body); err != nil || body.ExpectedVersion < 1 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project command"}))
		return
	}
	if len(request.Header.Values("If-Match")) != 1 {
		writeError(response, request, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": body.ExpectedVersion}))
		return
	}
	if err := validateIfMatch(request.Header.Get("If-Match"), body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	commandType, ok := mapProjectCommand(commandName)
	if !ok {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "unsupported project command"}))
		return
	}
	outcome, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion,
		Command: state.ProjectCommand{Type: commandType},
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	writeProject(response, http.StatusAccepted, outcome.Project)
}

func (handler *Handler) getTask(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	project, found, err := handler.orchestrator.Project(request.Context(), principal.TenantID, projectID)
	if err != nil || !found {
		if err == nil {
			err = aorerrors.New(aorerrors.CodeNotFound, "", nil)
		}
		writeError(response, request, normalizeError(err))
		return
	}
	task, found, err := handler.orchestrator.Task(request.Context(), principal.TenantID, projectID, taskID)
	if err != nil || !found {
		if err == nil {
			err = aorerrors.New(aorerrors.CodeNotFound, "", nil)
		}
		writeError(response, request, normalizeError(err))
		return
	}
	if err := authorizeTaskRead(request.Context(), handler.authorizer, principal, project, task); err != nil {
		writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", entityTag(task.Version))
	writeJSON(response, http.StatusOK, task)
}

func (handler *Handler) listTasks(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	query := request.URL.Query()
	if len(query) > 1 || len(query) == 1 && len(query["cursor"]) != 1 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "task cursor"}))
		return
	}
	cursor := query.Get("cursor")
	if len(cursor) > 512 || strings.ContainsAny(cursor, "\r\n\x00") {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "task cursor"}))
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
	if err := authorizeRead(request.Context(), handler.authorizer, principal, projectID, authz.ActionTaskRead, "task-list", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	tasks, err := handler.orchestrator.Tasks(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	start := 0
	if cursor != "" {
		foundCursor := false
		for index, task := range tasks {
			if taskPageCursor(projectID, task.ID) == cursor {
				start = index + 1
				foundCursor = true
				break
			}
		}
		if !foundCursor {
			writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "task cursor"}))
			return
		}
	}
	const pageSize = 100
	end := start + pageSize
	if end > len(tasks) {
		end = len(tasks)
	}
	items := make([]state.ModuleTask, 0, end-start)
	for _, task := range tasks[start:end] {
		if err := authorizeTaskRead(request.Context(), handler.authorizer, principal, project, task); err != nil {
			writeError(response, request, err)
			return
		}
		items = append(items, task)
	}
	result := page{Items: items}
	if end < len(tasks) && len(items) != 0 {
		result.NextCursor = taskPageCursor(projectID, items[len(items)-1].ID)
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) getBudgets(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	project, err := handler.authorizeBudgetRead(request, principal, projectID, "budget")
	if err != nil {
		writeError(response, request, err)
		return
	}
	if handler.budgets == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "budget ledger"}))
		return
	}
	accounts, err := handler.budgets.ListAccounts(request.Context(), principal.TenantID, project.ID)
	if err != nil {
		writeError(response, request, normalizeBudgetError(err))
		return
	}
	if len(accounts) == 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	if len(accounts) > 1 {
		writeError(response, request, normalizeBudgetError(modelgateway.ErrBudgetAccountConflict))
		return
	}
	items := make([]budgetAccountResource, 0, len(accounts))
	var version int64
	for _, account := range accounts {
		if account.TenantID != principal.TenantID || account.ScopeType != "PROJECT" || account.ScopeID != project.ID || account.Version < 1 {
			writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "budget account"}))
			return
		}
		items = append(items, budgetAccountView(account))
		if account.Version > version {
			version = account.Version
		}
	}
	response.Header().Set("ETag", entityTag(version))
	writeJSON(response, http.StatusOK, budgetCollection{ProjectID: project.ID, Items: items, Version: version})
}

func (handler *Handler) getBudgetUsage(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	project, err := handler.authorizeBudgetRead(request, principal, projectID, "budget-usage")
	if err != nil {
		writeError(response, request, err)
		return
	}
	if handler.budgets == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "budget ledger"}))
		return
	}
	usage, err := handler.budgets.Usage(request.Context(), principal.TenantID, project.ID)
	if err != nil {
		writeError(response, request, normalizeBudgetError(err))
		return
	}
	if usage.Version < 1 || usage.AccountID == "" {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "budget usage"}))
		return
	}
	response.Header().Set("ETag", entityTag(usage.Version))
	writeJSON(response, http.StatusOK, budgetUsageView(project.ID, usage))
}

func (handler *Handler) adjustBudget(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "budget query"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body budgetAdjustmentBody
	if err := decodeJSON(request, &body); err != nil || !validBudgetAdjustmentBody(body) {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "budget adjustment"}))
		return
	}
	if len(request.Header.Values("If-Match")) != 1 {
		writeError(response, request, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": body.ExpectedVersion}))
		return
	}
	if err := validateIfMatch(request.Header.Get("If-Match"), body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	traceparent, tracestate, err := budgetTraceHeaders(request)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "trace context"}))
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
	if handler.budgets == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "budget ledger"}))
		return
	}
	accounts, err := handler.budgets.ListAccounts(request.Context(), principal.TenantID, project.ID)
	if err != nil {
		writeError(response, request, normalizeBudgetError(err))
		return
	}
	if len(accounts) == 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	if len(accounts) != 1 || accounts[0].ID == "" {
		writeError(response, request, normalizeBudgetError(modelgateway.ErrBudgetAccountConflict))
		return
	}
	digest, err := budgetAdjustmentDigest(body)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "budget adjustment"}))
		return
	}
	policyDecision, err := authorizeBudgetAdjustment(request.Context(), handler.authorizer, principal, project, accounts[0].ID, digest)
	if err != nil {
		writeError(response, request, err)
		return
	}
	result, err := handler.budgets.Adjust(request.Context(), modelgateway.BudgetAdjustment{
		TenantID: principal.TenantID, ProjectID: project.ID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, Traceparent: traceparent, Tracestate: tracestate,
		PolicyVersion: policyDecision.PolicyVersion, PolicyRuleID: policyDecision.RuleID,
		PolicyDecision: string(policyDecision.Decision), PolicyReasons: append([]string(nil), policyDecision.ReasonCodes...),
		ParameterDigest: digest,
		ProjectState:    string(project.State), ProjectVersion: project.Version,
		ExpectedVersion: body.ExpectedVersion,
		HardLimitMicros: body.HardLimitMinor, SoftLimitMicros: body.SoftLimitMinor,
		Currency: body.Currency, Reason: body.Reason,
	})
	if err != nil {
		writeError(response, request, normalizeBudgetError(err))
		return
	}
	if result.Account.TenantID != principal.TenantID || result.Account.ScopeType != "PROJECT" || result.Account.ScopeID != project.ID || result.Account.Version < 1 || result.Usage.AccountID != result.Account.ID || result.Usage.Version != result.Account.Version {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "budget adjustment result"}))
		return
	}
	response.Header().Set("ETag", entityTag(result.Account.Version))
	writeJSON(response, http.StatusAccepted, budgetAdjustmentResource{ProjectID: project.ID, Account: budgetAccountView(result.Account), Usage: budgetUsageView(project.ID, result.Usage)})
}

func (handler *Handler) authorizeBudgetRead(request *http.Request, principal authn.Principal, projectID, resourceType string) (state.Project, error) {
	if len(request.URL.Query()) != 0 {
		return state.Project{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "budget query"})
	}
	project, found, err := handler.orchestrator.Project(request.Context(), principal.TenantID, projectID)
	if err != nil {
		return state.Project{}, normalizeError(err)
	}
	if !found {
		return state.Project{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := authorizeRead(request.Context(), handler.authorizer, principal, projectID, authz.ActionProjectRead, resourceType, projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		return state.Project{}, err
	}
	return project, nil
}

func authorizeBudgetAdjustment(ctx context.Context, authorizer authz.PolicyEvaluator, principal authn.Principal, project state.Project, accountID, parameterDigest string) (authz.PolicyDecision, error) {
	if authorizer == nil || parameterDigest == "" {
		return authz.PolicyDecision{}, aorerrors.New(aorerrors.CodePolicyDenied, "", nil)
	}
	input := authz.PolicyInput{
		Principal:       principal,
		Project:         authz.ProjectScope{TenantID: project.TenantID, ID: project.ID, State: string(project.State), StateVersion: project.Version, Classification: project.DataClassification},
		Action:          authz.ActionProjectCommand,
		Resource:        authz.Resource{Type: "budget", ID: project.ID},
		ParameterDigest: parameterDigest,
		Budget:          authz.BudgetScope{AccountID: accountID, Available: true},
	}
	decision, err := authorizer.Evaluate(ctx, input)
	if err != nil {
		return authz.PolicyDecision{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if !decision.Decision.Allowed() {
		return decision, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": decision.PolicyVersion, "ruleId": decision.RuleID})
	}
	return decision, nil
}

func validBudgetAdjustmentBody(body budgetAdjustmentBody) bool {
	return body.ExpectedVersion >= 1 && body.HardLimitMinor >= 0 && body.SoftLimitMinor >= 0 && body.SoftLimitMinor <= body.HardLimitMinor && validCurrency(body.Currency) && body.Reason != "" && len(body.Reason) <= 2048 && strings.TrimSpace(body.Reason) == body.Reason && !strings.ContainsAny(body.Reason, "\r\n\x00")
}

func budgetAdjustmentDigest(body budgetAdjustmentBody) (string, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func validCurrency(value string) bool {
	return len(value) == 3 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z' && value[2] >= 'A' && value[2] <= 'Z'
}

func budgetTraceHeaders(request *http.Request) (string, string, error) {
	traceparents := request.Header.Values("traceparent")
	tracestates := request.Header.Values("tracestate")
	if len(traceparents) > 1 || len(tracestates) > 1 || len(traceparents) == 0 && len(tracestates) != 0 {
		return "", "", errors.New("invalid trace headers")
	}
	if len(traceparents) == 0 {
		return "", "", nil
	}
	traceparent := traceparents[0]
	tracestate := ""
	if len(tracestates) == 1 {
		tracestate = tracestates[0]
	}
	if _, err := observability.ParseTraceParent(traceparent, tracestate); err != nil {
		return "", "", err
	}
	return traceparent, tracestate, nil
}

func budgetAccountView(account modelgateway.BudgetAccount) budgetAccountResource {
	remaining := account.LimitMicros - account.SpentMicros - account.ReservedMicros
	if remaining < 0 {
		remaining = 0
	}
	return budgetAccountResource{
		ID: account.ID, ScopeType: account.ScopeType, ScopeID: account.ScopeID, Currency: account.Currency,
		HardLimitMinor: account.LimitMicros, SoftLimitMinor: account.SoftLimitMicros,
		SpentMinor: account.SpentMicros, ReservedMinor: account.ReservedMicros, RemainingMinor: remaining,
		PeriodStart: account.PeriodStart, PeriodEnd: account.PeriodEnd, Version: account.Version,
	}
}

func budgetUsageView(projectID string, usage modelgateway.BudgetUsage) budgetUsageResource {
	return budgetUsageResource{
		ProjectID: projectID, AccountID: usage.AccountID, Currency: usage.Currency,
		HardLimitMinor: usage.HardLimitMicros, SoftLimitMinor: usage.SoftLimitMicros,
		SpentMinor: usage.SpentMicros, ReservedMinor: usage.ReservedMicros, RemainingMinor: usage.RemainingMicros,
		ReservationCount: usage.ReservationCount, CallCount: usage.CallCount,
		InputTokens: usage.InputTokens, OutputTokens: usage.OutputTokens, CostMinor: usage.CostMicros, Version: usage.Version,
	}
}

func normalizeBudgetError(err error) error {
	switch {
	case errors.Is(err, modelgateway.ErrInvalidRequest):
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "budget"})
	case errors.Is(err, modelgateway.ErrBudgetAccountNotFound):
		return aorerrors.New(aorerrors.CodeNotFound, "", nil)
	case errors.Is(err, modelgateway.ErrBudgetAccountConflict):
		return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "budget account"})
	case errors.Is(err, modelgateway.ErrBudgetVersionConflict):
		return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"scope": "budget"})
	case errors.Is(err, modelgateway.ErrBudgetProjectConflict):
		return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"scope": "project"})
	case errors.Is(err, modelgateway.ErrBudgetIdempotencyConflict):
		return aorerrors.New(aorerrors.CodeIdempotencyConflict, "", nil)
	case errors.Is(err, modelgateway.ErrBudgetCurrencyConflict), errors.Is(err, modelgateway.ErrBudgetLimitConflict):
		return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "budget"})
	case errors.Is(err, modelgateway.ErrBudgetPeriodClosed):
		return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "budget period"})
	default:
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "budget ledger"})
	}
}

func (handler *Handler) projectEvents(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if handler.events == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil))
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
	if err := authorizeRead(request.Context(), handler.authorizer, principal, projectID, "project.read", "project-events", projectID, string(project.State), project.Version, project.DataClassification); err != nil {
		writeError(response, request, err)
		return
	}
	events, err := handler.events.ListEvents(request.Context(), principal.TenantID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	after := request.URL.Query().Get("after")
	if len(after) > 512 || strings.ContainsAny(after, "\r\n\x00") {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "event cursor"}))
		return
	}
	projectEvents := make([]eventing.DomainEvent, 0, len(events))
	for _, event := range events {
		if event.ProjectID == projectID {
			projectEvents = append(projectEvents, event)
		}
	}
	start := 0
	if after != "" {
		foundCursor := false
		for index, event := range projectEvents {
			if event.EventID == after {
				start = index + 1
				foundCursor = true
				break
			}
		}
		if !foundCursor {
			writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "event cursor"}))
			return
		}
	}
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Accel-Buffering", "no")
	response.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(response)
	for _, event := range projectEvents[start:] {
		if !safeSSEField(event.EventID) || !safeSSEField(event.Type) {
			return
		}
		_, _ = io.WriteString(response, "id: "+event.EventID+"\n")
		_, _ = io.WriteString(response, "event: "+event.Type+"\n")
		_, _ = io.WriteString(response, "data: ")
		if err := encoder.Encode(event); err != nil {
			return
		}
		_, _ = io.WriteString(response, "\n")
		if flusher, ok := response.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

func (handler *Handler) ensureTenant(ctx context.Context, tenantID string) error {
	if handler.database == nil {
		return nil
	}
	tx, err := handler.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenants (id, name) VALUES ($1::uuid, $2) ON CONFLICT (id) DO NOTHING`, tenantID, "tenant-"+tenantID); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if err := tx.Commit(); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	return nil
}

func authorizeVirtualProject(ctx context.Context, authorizer authz.PolicyEvaluator, principal authn.Principal, projectID, action, classification string) error {
	return authorizeRead(ctx, authorizer, principal, projectID, action, "project", projectID, "CREATED", 0, classification)
}

func authorizeTaskRead(ctx context.Context, authorizer authz.PolicyEvaluator, principal authn.Principal, project state.Project, task state.ModuleTask) error {
	input := authz.PolicyInput{
		Principal: principal,
		Project:   authz.ProjectScope{TenantID: project.TenantID, ID: project.ID, State: string(project.State), StateVersion: project.Version, Classification: project.DataClassification},
		Task:      authz.TaskScope{TenantID: task.TenantID, ProjectID: task.ProjectID, ID: task.ID, State: string(task.State), StateVersion: task.Version, SpecDigest: task.ModuleSpecRef.SHA256},
		Action:    authz.ActionTaskRead,
		Resource:  authz.Resource{Type: "task", ID: task.ID},
		Budget:    authz.BudgetScope{AccountID: "control-plane", Available: true},
	}
	decision, err := authorizer.Evaluate(ctx, input)
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if !decision.Decision.Allowed() {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": decision.PolicyVersion, "ruleId": decision.RuleID})
	}
	return nil
}

func splitProjectPath(path string) ([]string, bool) {
	if !strings.HasPrefix(path, "/v1/projects/") || strings.Contains(path, "//") {
		return nil, false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/v1/projects/"), "/")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, false
	}
	for _, part := range parts {
		if part == "" || strings.ContainsAny(part, "\r\n\x00") {
			return nil, false
		}
	}
	return parts, true
}

func decodeJSON(request *http.Request, target any) error {
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	content, err := io.ReadAll(io.LimitReader(request.Body, maximumRequestBytes+1))
	if err != nil || len(content) == 0 || len(content) > maximumRequestBytes || rejectDuplicateJSONMembers(content) != nil {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	return nil
}

func rejectDuplicateJSONMembers(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		members := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, keyOK := keyToken.(string)
			if keyErr != nil || !keyOK {
				return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
			}
			if _, duplicate := members[key]; duplicate {
				return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
			}
			members[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil || end != json.Delim('}') {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil || end != json.Delim(']') {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
		}
	default:
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	return nil
}

func requiredIdempotencyKey(request *http.Request) (string, error) {
	if len(request.Header.Values("Idempotency-Key")) != 1 {
		return "", aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "idempotency key"})
	}
	value := request.Header.Get("Idempotency-Key")
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return "", aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "idempotency key"})
	}
	return value, nil
}

func validateIfMatch(value string, version int64) error {
	if value != entityTag(version) {
		return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": version})
	}
	return nil
}

func entityTag(version int64) string {
	return `"v` + strconv.FormatInt(version, 10) + `"`
}

func mapProjectCommand(name string) (state.ProjectCommandType, bool) {
	switch name {
	case "pause":
		return state.ProjectCommandPause, true
	case "resume":
		return state.ProjectCommandResume, true
	case "abort":
		return state.ProjectCommandAbort, true
	case "archive":
		return state.ProjectCommandArchive, true
	case "request-deletion", "approve-release":
		return "", false
	default:
		return "", false
	}
}

func oneOf(value string, options ...string) bool {
	for _, option := range options {
		if value == option {
			return true
		}
	}
	return false
}

func taskPageCursor(projectID, taskID string) string {
	digest := sha256.Sum256([]byte(projectID + "\x00" + taskID))
	return hex.EncodeToString(digest[:])
}

func writeProject(response http.ResponseWriter, status int, project state.Project) {
	response.Header().Set("ETag", entityTag(project.Version))
	writeJSON(response, status, project)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeMethodNotAllowed(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Allow", "GET, POST")
	problem := aorerrors.New(aorerrors.CodeInvalidArgument, request.Header.Get("X-Request-ID"), map[string]any{"scope": "http method"}).Problem()
	problem.Status = http.StatusMethodNotAllowed
	problem.Instance = request.URL.Path
	writeJSON(response, http.StatusMethodNotAllowed, problem)
}

func validProjectID(value string) bool {
	return uuidPattern.MatchString(value)
}

func validAPIIdentifier(value string) bool {
	if len(value) < 3 || len(value) > 128 || value[0] < 'A' || value[0] > 'z' || value[0] > 'Z' && value[0] < 'a' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func safeSSEField(value string) bool {
	return value != "" && !strings.ContainsAny(value, "\r\n\x00")
}

func writeError(response http.ResponseWriter, request *http.Request, err error) {
	correlationID := request.Header.Get("X-Request-ID")
	var typed *aorerrors.Error
	if !errors.As(err, &typed) {
		typed = aorerrors.New(aorerrors.CodeInternalError, correlationID, nil)
	} else if typed.CorrelationID == "" {
		typed = aorerrors.New(typed.Code, correlationID, typed.Details)
	}
	problem := typed.Problem()
	problem.Instance = request.URL.Path
	writeJSON(response, problem.Status, problem)
}

func normalizeError(err error) error {
	var typed *aorerrors.Error
	if errors.As(err, &typed) {
		return typed
	}
	if isCommitBoundaryError(err) {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", nil)
	}
	return aorerrors.New(aorerrors.CodeInternalError, "", nil)
}
