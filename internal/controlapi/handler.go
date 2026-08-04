package controlapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const maximumRequestBytes = 1 << 20

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Config struct {
	Store         eventing.Store
	Authenticator authn.Authenticator
	Authorizer    authz.PolicyEvaluator
	Database      *sql.DB
	Clock         func() time.Time
}

type Handler struct {
	orchestrator  *orchestrator.Service
	store         eventing.Store
	events        eventing.EventLog
	authenticator authn.Authenticator
	authorizer    authz.PolicyEvaluator
	database      *sql.DB
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

func New(config Config) (*Handler, error) {
	if config.Store == nil || config.Authenticator == nil || config.Authorizer == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "control api configuration"})
	}
	if config.Clock == nil {
		config.Clock = time.Now
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
	projectID := projectIDFor(principal.TenantID, principal.ID, idempotencyKey)
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
	reader := http.MaxBytesReader(nil, request.Body, maximumRequestBytes)
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	return nil
}

func requiredIdempotencyKey(request *http.Request) (string, error) {
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
	case "archive", "request-deletion", "approve-release":
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

func projectIDFor(tenantID, principalID, idempotencyKey string) string {
	value := sha256.Sum256([]byte(tenantID + "\x00" + principalID + "\x00" + idempotencyKey))
	value[0] = value[0]&0x0f | 0xa0
	value[6] = value[6]&0x0f | 0x50
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
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
