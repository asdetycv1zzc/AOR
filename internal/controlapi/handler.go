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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/agentruntime"
	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/modelproviders"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/orchestrator"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
	"github.com/akimisaka/aor/prompts"
	"github.com/google/uuid"
)

const maximumRequestBytes = 1 << 20

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Config struct {
	Store                eventing.Store
	Authenticator        authn.Authenticator
	AnonymousPrincipal   *authn.Principal
	Authorizer           authz.PolicyEvaluator
	Database             *sql.DB
	Budgets              modelgateway.BudgetAdministration
	Artifacts            artifact.Catalog
	Knowledge            KnowledgeReader
	KnowledgeCurator     KnowledgeCuratorService
	KnowledgeCuratorURL  string
	TaskHistory          TaskHistoryReader
	DecisionReports      TaskDecisionReportReader
	DecisionReportSigner TaskDecisionReportSigner
	Eraser               ProjectEraser
	Leases               LeaseAuthority
	GoalPlan             GoalPlanServices
	ClassroomCore        bool
	DefaultModelRoutes   map[string]state.ProjectModelRoute
	ModelProviders       []ModelProvider
	ProviderSettings     modelproviders.SettingsStore
	ProviderAdapter      modelproviders.AdapterFactory
	Clock                func() time.Time
}

type ErasureReport struct {
	Scopes       []string `json:"scopes"`
	Records      int64    `json:"records"`
	Objects      int64    `json:"objects"`
	CacheEntries int64    `json:"cacheEntries"`
}

type ProjectEraser interface {
	EraseProject(context.Context, string, string, string) (ErasureReport, error)
}

type projectAuthorizationEraser interface {
	FinalizeProjectAuthorizationErasure(context.Context, string, string, string) error
}

type KnowledgeReader interface {
	Search(context.Context, knowledge.SearchRequest) (knowledge.SearchResponse, error)
	ReadRange(context.Context, knowledge.ReadRangeRequest) (knowledge.ReadRangeResponse, error)
	Manifest(context.Context, knowledge.Access, string) (knowledge.Manifest, error)
}

type KnowledgeInitializer interface {
	Initialize(context.Context, string, string, time.Time) (knowledge.Manifest, error)
}

type Handler struct {
	orchestrator         *orchestrator.Service
	store                eventing.Store
	events               eventing.EventLog
	authenticator        authn.Authenticator
	anonymousPrincipal   *authn.Principal
	authorizer           authz.PolicyEvaluator
	database             *sql.DB
	budgets              modelgateway.BudgetAdministration
	artifacts            artifact.Catalog
	publisher            artifact.Publisher
	knowledge            KnowledgeReader
	knowledgeCurator     KnowledgeCuratorService
	knowledgeCuratorURL  string
	knowledgeCuratorHTTP *http.Client
	taskHistory          TaskHistoryReader
	decisionReports      TaskDecisionReportReader
	decisionVerifier     TaskDecisionReportVerifier
	eraser               ProjectEraser
	leases               LeaseAuthority
	goalPlan             GoalPlanServices
	defaultModelRoutes   map[string]state.ProjectModelRoute
	modelProviders       []ModelProvider
	providerSettings     modelproviders.SettingsStore
	providerAdapter      modelproviders.AdapterFactory
	modelRouteSettings   modelRouteSettingsStore
	autoBudget           bool
	clock                func() time.Time
}

type projectCreate struct {
	Name               string                             `json:"name"`
	GoalAgentCount     int                                `json:"goalAgentCount"`
	DataClassification string                             `json:"dataClassification"`
	DeploymentTargets  []string                           `json:"deploymentTargets,omitempty"`
	Budget             projectBudgetSelection             `json:"budget,omitempty"`
	ModelRoutes        map[string]state.ProjectModelRoute `json:"modelRoutes,omitempty"`
}

type projectBudgetSelection struct {
	HardLimitMinor int64  `json:"hardLimitMinor"`
	SoftLimitMinor int64  `json:"softLimitMinor"`
	Currency       string `json:"currency"`
}

type commandBody struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	SHA256          string `json:"sha256,omitempty"`
}

type legalHoldBody struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	Reason          string `json:"reason"`
}

type legalHoldReleaseBody struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	Reason          string `json:"reason"`
}

type projectExportManifest struct {
	SchemaVersion string                 `json:"schemaVersion"`
	Project       state.Project          `json:"project"`
	Events        []eventing.DomainEvent `json:"events"`
	Artifacts     []artifact.Record      `json:"artifacts"`
	GeneratedAt   time.Time              `json:"generatedAt"`
}

type projectExportResource struct {
	ProjectID      string    `json:"projectId"`
	ProjectVersion int64     `json:"projectVersion"`
	ArtifactID     string    `json:"artifactId"`
	URI            string    `json:"uri"`
	SHA256         string    `json:"sha256"`
	SizeBytes      int64     `json:"sizeBytes"`
	CreatedAt      time.Time `json:"createdAt"`
}

type budgetAdjustmentBody struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	HardLimitMinor  int64  `json:"hardLimitMinor"`
	SoftLimitMinor  int64  `json:"softLimitMinor"`
	Currency        string `json:"currency"`
	Reason          string `json:"reason"`
}

type goalMessageBody struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	Message         string `json:"message"`
}

type goalDecisionBody struct {
	ExpectedVersion int64  `json:"expectedVersion"`
	SHA256          string `json:"sha256"`
	Decision        string `json:"decision,omitempty"`
	Comment         string `json:"comment,omitempty"`
	IdempotencyKey  string `json:"idempotencyKey,omitempty"`
}

type goalChangeBody struct {
	ExpectedVersion int64    `json:"expectedVersion"`
	Version         int      `json:"version"`
	SHA256          string   `json:"sha256"`
	Message         string   `json:"message"`
	ImpactedTaskIDs []string `json:"impactedTaskIds"`
}

type knowledgeSearchBody struct {
	Path  string   `json:"path,omitempty"`
	Title string   `json:"title,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	Text  string   `json:"text,omitempty"`
	Limit int      `json:"limit,omitempty"`
}

type knowledgeReadRangeBody struct {
	Reference knowledge.Reference `json:"reference"`
	LineStart int                 `json:"lineStart,omitempty"`
	LineEnd   int                 `json:"lineEnd,omitempty"`
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
	if config.AnonymousPrincipal != nil {
		principal := *config.AnonymousPrincipal
		if principal.Validate() != nil || principal.Type != authn.PrincipalUser || principal.Role != authn.RoleUser || principal.TenantID == "" || !uuidPattern.MatchString(strings.ToLower(principal.TenantID)) {
			return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "anonymous principal"})
		}
		config.AnonymousPrincipal = &principal
	}
	if config.GoalPlan.Negotiator == nil != (config.GoalPlan.Planner == nil) {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal plan configuration"})
	}
	providers, defaultRoutes, err := validatedModelConfiguration(config.ModelProviders, config.DefaultModelRoutes)
	if err != nil {
		return nil, err
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.KnowledgeCuratorURL != "" {
		if err := validateKnowledgeCuratorURL(config.KnowledgeCuratorURL); err != nil {
			return nil, err
		}
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
	if config.TaskHistory == nil && config.Database != nil {
		reader, err := NewPostgresTaskHistoryReader(config.Database)
		if err != nil {
			return nil, err
		}
		config.TaskHistory = reader
	}
	if config.DecisionReports == nil && config.Database != nil && config.DecisionReportSigner != nil {
		reader, err := NewPostgresTaskDecisionReportReader(config.Database, config.DecisionReportSigner)
		if err != nil {
			return nil, err
		}
		config.DecisionReports = reader
	}
	decisionVerifier, _ := config.DecisionReportSigner.(TaskDecisionReportVerifier)
	boundary, err := NewPolicyCommitBoundary(config.Authorizer)
	if err != nil {
		return nil, err
	}
	handler := &Handler{
		orchestrator:         orchestrator.NewWithBoundaryAndMode(config.Store, config.Clock, boundary, config.ClassroomCore),
		store:                config.Store,
		authenticator:        config.Authenticator,
		anonymousPrincipal:   config.AnonymousPrincipal,
		authorizer:           config.Authorizer,
		database:             config.Database,
		budgets:              config.Budgets,
		artifacts:            config.Artifacts,
		knowledge:            config.Knowledge,
		knowledgeCurator:     config.KnowledgeCurator,
		knowledgeCuratorURL:  strings.TrimRight(config.KnowledgeCuratorURL, "/"),
		knowledgeCuratorHTTP: newKnowledgeCuratorHTTPClient(),
		taskHistory:          config.TaskHistory,
		decisionReports:      config.DecisionReports,
		decisionVerifier:     decisionVerifier,
		eraser:               config.Eraser,
		leases:               config.Leases,
		goalPlan:             config.GoalPlan,
		defaultModelRoutes:   defaultRoutes,
		modelProviders:       providers,
		providerSettings:     config.ProviderSettings,
		providerAdapter:      config.ProviderAdapter,
		modelRouteSettings:   newModelRouteSettingsStore(config.Database),
		autoBudget:           autoBudget,
		clock:                config.Clock,
	}
	handler.publisher, _ = config.Artifacts.(artifact.Publisher)
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
	if handler.knowledgeCuratorURL != "" && isKnowledgeCuratorRequest(request) {
		handler.proxyKnowledgeCurator(response, request)
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/admin/") {
		switch request.URL.Path {
		case "/v1/admin/doctor":
			handler.admin(response, request, principal, "doctor")
		case "/v1/admin/policies:test":
			handler.admin(response, request, principal, "policy-test")
		case "/v1/admin/sandboxes:probe":
			handler.admin(response, request, principal, "sandbox-probe")
		case "/v1/admin/backup:verify":
			handler.admin(response, request, principal, "backup-verify")
		default:
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		}
		return
	}
	if request.URL.Path == "/v1/model-providers" {
		if request.Method == http.MethodGet {
			handler.listModelProviders(response, request, principal)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if request.URL.Path == "/v1/settings/model-providers" {
		if request.Method == http.MethodGet {
			handler.getModelProviderSettings(response, request, principal)
			return
		}
		writeMethodNotAllowedWith(response, request, "GET")
		return
	}
	if providerID, test, ok := modelProviderSettingsPath(request.URL.Path); ok {
		if test && request.Method == http.MethodPost {
			handler.testModelProvider(response, request, principal, providerID)
			return
		}
		if !test && request.Method == http.MethodPut {
			handler.putModelProviderSettings(response, request, principal, providerID)
			return
		}
		if test {
			writeMethodNotAllowedWith(response, request, "POST")
		} else {
			writeMethodNotAllowedWith(response, request, "PUT")
		}
		return
	}
	if request.URL.Path == "/v1/settings/model-routes" {
		switch request.Method {
		case http.MethodGet:
			handler.getModelRouteSettings(response, request, principal)
		case http.MethodPut:
			handler.putModelRouteSettings(response, request, principal)
		default:
			writeMethodNotAllowedWith(response, request, "GET, PUT")
		}
		return
	}

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
			if request.Method == http.MethodPost && validProjectID(id) && commandName == "execute-deletion" {
				handler.executeProjectDeletion(response, request, principal, id)
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
	if len(parts) == 2 && parts[1] == "result" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getProjectResult(response, request, principal, projectID)
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
	if len(parts) == 2 && parts[1] == "export" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.exportProject(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 1 {
		if id, commandName, found := strings.Cut(projectID, ":"); found && commandName == "execute-deletion" {
			if !validProjectID(id) {
				writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
				return
			}
			if request.Method == http.MethodPost {
				handler.executeProjectDeletion(response, request, principal, id)
				return
			}
			writeMethodNotAllowed(response, request)
			return
		}
	}
	if len(parts) == 2 && parts[1] == "legal-holds" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		switch request.Method {
		case http.MethodGet:
			handler.listLegalHolds(response, request, principal, projectID)
		case http.MethodPost:
			handler.placeLegalHold(response, request, principal, projectID)
		default:
			writeMethodNotAllowed(response, request)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "legal-holds" {
		holdID, action, found := strings.Cut(parts[2], ":")
		if !validProjectID(projectID) || !found || action != "release" || (!validProjectID(holdID) && !validAPIIdentifier(holdID)) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodPost {
			handler.releaseLegalHold(response, request, principal, projectID, holdID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "goal:change" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodPost {
			handler.requestGoalChange(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 3 && parts[1] == "goal" && parts[2] == "messages" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		switch request.Method {
		case http.MethodGet:
			handler.listGoalMessages(response, request, principal, projectID)
		case http.MethodPost:
			handler.submitGoalMessage(response, request, principal, projectID)
		default:
			writeMethodNotAllowed(response, request)
		}
		return
	}
	if len(parts) == 3 && parts[1] == "goal" && parts[2] == "specs" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.listGoalSpecs(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 4 && parts[1] == "goal" && parts[2] == "specs" {
		versionPart, action, hasAction := strings.Cut(parts[3], ":")
		version, versionErr := strconv.Atoi(versionPart)
		if !validProjectID(projectID) || versionErr != nil || version < 1 {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if !hasAction && request.Method == http.MethodGet {
			handler.getGoalSpec(response, request, principal, projectID, version)
			return
		}
		if hasAction && request.Method == http.MethodPost && (action == "approve" || action == "reject") {
			handler.decideGoalSpec(response, request, principal, projectID, version, action)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "artifacts" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.listArtifacts(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 3 && parts[1] == "artifacts" {
		if !validProjectID(projectID) || !validArtifactID(parts[2]) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getArtifact(response, request, principal, projectID, parts[2])
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "knowledge:initialize" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodPost {
			handler.initializeKnowledge(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "knowledge:search" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodPost {
			handler.searchKnowledge(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "knowledge:read-range" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodPost {
			handler.readKnowledgeRange(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 3 && parts[1] == "knowledge" && parts[2] == "manifest" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getKnowledgeManifest(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 2 && parts[1] == "knowledge:propose-update" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodPost {
			handler.proposeKnowledgeUpdate(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 4 && parts[1] == "knowledge" && parts[2] == "updates" {
		updateID, action, hasAction := strings.Cut(parts[3], ":")
		if !validProjectID(projectID) || !validArtifactID(updateID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if !hasAction && request.Method == http.MethodGet {
			handler.getKnowledgeUpdate(response, request, principal, projectID, updateID)
			return
		}
		if hasAction && action == "approve" && request.Method == http.MethodPost {
			handler.approveKnowledgeUpdate(response, request, principal, projectID, updateID)
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
	if len(parts) == 2 && parts[1] == "plans" {
		if !validProjectID(projectID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.listPlans(response, request, principal, projectID)
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 3 && parts[1] == "plans" {
		version, versionErr := strconv.Atoi(parts[2])
		if !validProjectID(projectID) || versionErr != nil || version < 1 {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			handler.getPlan(response, request, principal, projectID, version)
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
	if len(parts) == 4 && parts[1] == "tasks" && strings.HasPrefix(parts[3], "leases") {
		if !validProjectID(projectID) || !validAPIIdentifier(parts[2]) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		handler.manageTaskLease(response, request, principal, projectID, parts[2], parts[3])
		return
	}
	if len(parts) == 4 && parts[1] == "tasks" && (parts[3] == "submissions" || parts[3] == "audits") {
		if !validProjectID(projectID) || !validAPIIdentifier(parts[2]) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if request.Method == http.MethodGet {
			if parts[3] == "submissions" {
				handler.listTaskSubmissions(response, request, principal, projectID, parts[2])
			} else {
				handler.listTaskAudits(response, request, principal, projectID, parts[2])
			}
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	if len(parts) == 4 && parts[1] == "tasks" && (parts[3] == "decisions" || parts[3] == "decision-report") {
		if !validProjectID(projectID) || !validAPIIdentifier(parts[2]) {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if parts[3] == "decision-report" && request.Method == http.MethodGet {
			handler.getTaskDecisionReport(response, request, principal, projectID, parts[2])
			return
		}
		if parts[3] == "decisions" && request.Method == http.MethodPost {
			handler.decideTask(response, request, principal, projectID, parts[2])
			return
		}
		writeMethodNotAllowed(response, request)
		return
	}
	writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
}

func (handler *Handler) authenticate(request *http.Request) (authn.Principal, error) {
	if handler == nil || request == nil {
		return authn.Principal{}, aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	if handler.anonymousPrincipal != nil && request.Header.Get("Authorization") == "" {
		return *handler.anonymousPrincipal, nil
	}
	if handler.authenticator == nil {
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
	if err := decodeJSON(request, &body); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project create"}))
		return
	}
	if err := validateProjectCreate(body); err != nil {
		writeError(response, request, err)
		return
	}
	modelRoutes, err := handler.resolveProjectModelRoutes(request.Context(), principal.TenantID, body.ModelRoutes)
	if err != nil {
		writeError(response, request, err)
		return
	}
	bundles := make([]agentruntime.PromptBundle, 0, body.GoalAgentCount)
	promptVersion := ""
	roles := []agentruntime.Role{agentruntime.RoleGoalProposer}
	if body.GoalAgentCount == 2 {
		roles = append(roles, agentruntime.RoleGoalChallenger)
	}
	for _, role := range roles {
		bundle, loadErr := prompts.LoadBaseline(role)
		if loadErr != nil {
			writeError(response, request, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", loadErr, map[string]any{"scope": "initial prompt bundle"}))
			return
		}
		if promptVersion != "" && promptVersion != bundle.Version {
			writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "prompt bundle version"}))
			return
		}
		promptVersion = bundle.Version
		bundles = append(bundles, bundle)
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
		Command: state.ProjectCommand{
			Type: state.ProjectCommandCreate, Name: body.Name, GoalAgentCount: body.GoalAgentCount,
			DataClassification: body.DataClassification, DeploymentTargets: append([]string(nil), body.DeploymentTargets...),
			BudgetCurrency: body.Budget.Currency, BudgetHardLimitMinor: body.Budget.HardLimitMinor,
			BudgetSoftLimitMinor: body.Budget.SoftLimitMinor, PromptBundleVersion: promptVersion,
			StartGoalNegotiation: true, ModelRoutes: modelRoutes,
		},
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if err := handler.ensureProjectBudget(request.Context(), principal.TenantID, outcome.Project, body.Budget); err != nil {
		writeError(response, request, normalizeBudgetError(err))
		return
	}
	if err := handler.initializeProjectResources(request, principal, outcome.Project, bundles); err != nil {
		writeError(response, request, err)
		return
	}
	writeProject(response, http.StatusCreated, outcome.Project)
}

func validateProjectCreate(body projectCreate) error {
	if body.Name == "" || len(body.Name) > 256 || strings.TrimSpace(body.Name) != body.Name || strings.ContainsAny(body.Name, "\r\n\x00") || body.GoalAgentCount < 1 || body.GoalAgentCount > 2 || !oneOf(body.DataClassification, "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED") {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project create"})
	}
	if len(body.DeploymentTargets) == 0 || len(body.DeploymentTargets) > 16 || body.Budget.HardLimitMinor <= 0 || body.Budget.SoftLimitMinor < 0 || body.Budget.SoftLimitMinor > body.Budget.HardLimitMinor || !validCurrency(body.Budget.Currency) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project initialization selection"})
	}
	seen := make(map[string]struct{}, len(body.DeploymentTargets))
	for _, target := range body.DeploymentTargets {
		if target == "" || len(target) > 128 || strings.TrimSpace(target) != target || strings.ContainsAny(target, "\r\n\x00") {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "deployment target"})
		}
		if _, duplicate := seen[target]; duplicate {
			return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "deployment target"})
		}
		seen[target] = struct{}{}
	}
	return nil
}

func (handler *Handler) ensureProjectBudget(ctx context.Context, tenantID string, project state.Project, selection projectBudgetSelection) error {
	if !handler.autoBudget {
		return nil
	}
	creator, ok := handler.budgets.(interface {
		CreateAccount(context.Context, modelgateway.BudgetAccount) error
	})
	if !ok {
		return aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "budget account"})
	}
	currency := selection.Currency
	if currency == "" {
		currency = "USD"
	}
	account := modelgateway.BudgetAccount{
		ID: project.ID, TenantID: tenantID, ScopeType: "PROJECT", ScopeID: project.ID,
		Currency: currency, LimitMicros: selection.HardLimitMinor, SoftLimitMicros: selection.SoftLimitMinor,
		PeriodStart: handler.clock().UTC(), Version: 1,
	}
	if err := creator.CreateAccount(ctx, account); err == nil {
		return nil
	} else if !errors.Is(err, modelgateway.ErrReservationConflict) {
		return err
	}
	existing, err := handler.budgets.ListAccounts(ctx, tenantID, project.ID)
	if err != nil {
		return err
	}
	if len(existing) != 1 || existing[0].ID != account.ID || existing[0].Currency != account.Currency || existing[0].LimitMicros != account.LimitMicros || existing[0].SoftLimitMicros != account.SoftLimitMicros {
		return modelgateway.ErrReservationConflict
	}
	return nil
}

func (handler *Handler) initializeProjectResources(request *http.Request, principal authn.Principal, project state.Project, bundles []agentruntime.PromptBundle) error {
	if err := handler.initializeProjectKnowledge(request, project); err != nil {
		return err
	}
	ctx := request.Context()
	publisher, ok := handler.artifacts.(artifact.Publisher)
	if !ok {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "prompt artifact publisher"})
	}
	for _, bundle := range bundles {
		content, err := json.Marshal(bundle)
		if err != nil {
			return aorerrors.Wrap(aorerrors.CodeInternalError, "", err, map[string]any{"scope": "prompt bundle serialization"})
		}
		_, err = publisher.Publish(ctx, artifact.Publication{
			TenantID: principal.TenantID, ProjectID: project.ID, CreatedByPrincipal: principal.ID,
			ContentType: "application/json", Data: content,
			Metadata: map[string]any{
				"artifactKind": "PROMPT_BUNDLE", "role": string(bundle.Role),
				"promptBundleVersion": bundle.Version, "promptBundleSha256": bundle.SHA256,
			},
		})
		if err != nil {
			return normalizeArtifactError(err)
		}
	}
	return nil
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
	command := state.ProjectCommand{Type: commandType}
	if commandType == state.ProjectCommandRequestDeletion {
		command.Deletion = &state.ProjectDeletion{}
	}
	if commandType == state.ProjectCommandApproveRelease {
		project, found, projectErr := handler.orchestrator.Project(request.Context(), principal.TenantID, projectID)
		if projectErr != nil {
			writeError(response, request, normalizeError(projectErr))
			return
		}
		if !found {
			writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
			return
		}
		if project.Version != body.ExpectedVersion {
			writeError(response, request, aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": body.ExpectedVersion, "actualVersion": project.Version}))
			return
		}
		if project.State != contracts.ProjectGlobalAudit || project.Plan == nil || body.SHA256 != project.Plan.SHA256 {
			writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "release approval"}))
			return
		}
		issuedAt := handler.clock().UTC()
		approvalID, allocationErr := newRecordUUIDv7()
		if allocationErr != nil {
			writeError(response, request, aorerrors.Wrap(aorerrors.CodeInternalError, "", allocationErr, nil))
			return
		}
		command.Approval = &state.ApprovalBinding{
			RecordID: approvalID, ApprovalType: "RELEASE_APPROVAL", SubjectType: "PROJECT",
			SubjectID: project.ID, SubjectVersion: int(project.Version), SubjectSHA256: project.Plan.SHA256, PrincipalID: principal.ID,
			Reason: "explicit release approval", IssuedAt: issuedAt,
			Signature: releaseApprovalSignature(principal.TenantID, project.ID, project.Version, project.Plan.SHA256, principal.ID, idempotencyKey),
		}
	}
	outcome, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion,
		Command: command,
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	writeProject(response, http.StatusAccepted, outcome.Project)
}

func (handler *Handler) listLegalHolds(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "legal hold query"}))
		return
	}
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectRead, "project-legal-holds", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	response.Header().Set("ETag", entityTag(project.Version))
	writeJSON(response, http.StatusOK, page{Items: project.LegalHolds})
}

func (handler *Handler) placeLegalHold(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body legalHoldBody
	if err := decodeJSON(request, &body); err != nil || body.ExpectedVersion < 1 || !safeAPIText(body.Reason, 1024) {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "legal hold"}))
		return
	}
	if err := requireProjectVersionHeader(request, body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	outcome, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion,
		Command: state.ProjectCommand{Type: state.ProjectCommandPlaceLegalHold, LegalHold: &state.ProjectLegalHold{Reason: body.Reason}},
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	writeProject(response, http.StatusAccepted, outcome.Project)
}

func (handler *Handler) releaseLegalHold(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, holdID string) {
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body legalHoldReleaseBody
	if err := decodeJSON(request, &body); err != nil || body.ExpectedVersion < 1 || !safeAPIText(body.Reason, 1024) {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "legal hold release"}))
		return
	}
	if err := requireProjectVersionHeader(request, body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	outcome, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion,
		Command: state.ProjectCommand{Type: state.ProjectCommandReleaseLegalHold, LegalHoldID: holdID, ReleaseReason: body.Reason},
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	writeProject(response, http.StatusAccepted, outcome.Project)
}

func (handler *Handler) exportProject(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project export query"}))
		return
	}
	if handler.events == nil || handler.artifacts == nil || handler.publisher == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "project export"}))
		return
	}
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectRead, "project-export", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	events, err := handler.projectEventHistory(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	artifacts, err := handler.projectArtifactHistory(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeArtifactError(err))
		return
	}
	generatedAt := handler.clock().UTC()
	if len(events) != 0 {
		generatedAt = events[len(events)-1].OccurredAt.UTC()
	}
	manifest := projectExportManifest{SchemaVersion: "1.0", Project: project, Events: events, Artifacts: artifacts, GeneratedAt: generatedAt}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "project export encoding"}))
		return
	}
	content, err := canonicaljson.Canonicalize(encoded)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "project export canonicalization"}))
		return
	}
	digest, err := canonicaljson.Digest(content)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "project export digest"}))
		return
	}
	record, err := handler.publisher.Publish(request.Context(), artifact.Publication{
		TenantID: principal.TenantID, ProjectID: projectID, CreatedByPrincipal: principal.ID,
		ContentType: "application/vnd.aor.project-export.v1+json", Data: content,
		Metadata: map[string]any{"kind": "project-export", "schemaVersion": "1.0", "projectVersion": project.Version},
	})
	if err != nil {
		writeError(response, request, normalizeArtifactError(err))
		return
	}
	if record.SHA256 != digest || record.URI != "artifact://sha256/"+strings.TrimPrefix(digest, "sha256:") || record.ProjectID != projectID {
		writeError(response, request, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "project export"}))
		return
	}
	response.Header().Set("ETag", `"`+digest+`"`)
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, projectExportResource{
		ProjectID: projectID, ProjectVersion: project.Version, ArtifactID: record.ID, URI: record.URI,
		SHA256: record.SHA256, SizeBytes: record.SizeBytes, CreatedAt: record.CreatedAt,
	})
}

func (handler *Handler) executeProjectDeletion(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if handler.erasureUnavailable() {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "project eraser"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body commandBody
	if err := decodeJSON(request, &body); err != nil || body.ExpectedVersion < 1 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project deletion execution"}))
		return
	}
	if err := requireProjectVersionHeader(request, body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectCommand, "project-deletion", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	if project.Deletion == nil || project.Deletion.Status == state.ProjectDeletionBlocked {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "project deletion"}))
		return
	}
	if project.Deletion.Status == state.ProjectDeletionCompleted {
		if err := handler.finalizeProjectAuthorizationErasure(request.Context(), principal.TenantID, projectID, project.Deletion.ID); err != nil {
			writeError(response, request, normalizeProjectErasureError(err))
			return
		}
		writeProject(response, http.StatusAccepted, project)
		return
	}
	if project.Deletion.Status == state.ProjectDeletionReady {
		begun, beginErr := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
			TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
			IdempotencyKey: idempotencyKey + ":begin", ExpectedVersion: project.Version,
			Command: state.ProjectCommand{Type: state.ProjectCommandBeginDeletion},
		})
		if beginErr != nil {
			writeError(response, request, normalizeError(beginErr))
			return
		}
		project = begun.Project
	}
	if project.Deletion == nil || project.Deletion.Status != state.ProjectDeletionErasing {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "project deletion execution"}))
		return
	}
	report, err := handler.eraser.EraseProject(request.Context(), principal.TenantID, projectID, project.Deletion.ID)
	if err != nil {
		writeError(response, request, normalizeProjectErasureError(err))
		return
	}
	proof := struct {
		SchemaVersion string    `json:"schemaVersion"`
		DeletionID    string    `json:"deletionId"`
		ProjectID     string    `json:"projectId"`
		CompletedAt   time.Time `json:"completedAt"`
		Scopes        []string  `json:"scopes"`
		Records       int64     `json:"records"`
		Objects       int64     `json:"objects"`
		CacheEntries  int64     `json:"cacheEntries"`
	}{SchemaVersion: "1.0", DeletionID: project.Deletion.ID, ProjectID: projectID, CompletedAt: handler.clock().UTC(), Scopes: append([]string(nil), report.Scopes...), Records: report.Records, Objects: report.Objects, CacheEntries: report.CacheEntries}
	encoded, err := json.Marshal(proof)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "deletion proof"}))
		return
	}
	content, err := canonicaljson.Canonicalize(encoded)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "deletion proof"}))
		return
	}
	digest, err := canonicaljson.Digest(content)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "deletion proof"}))
		return
	}
	retention := handler.clock().UTC().AddDate(7, 0, 0)
	record, err := handler.publisher.Publish(request.Context(), artifact.Publication{
		TenantID: principal.TenantID, ProjectID: projectID, CreatedByPrincipal: principal.ID,
		ContentType: "application/vnd.aor.deletion-proof.v1+json", RetentionUntil: &retention, Data: content,
		Metadata: map[string]any{"kind": "deletion-proof", "deletionId": project.Deletion.ID, "schemaVersion": "1.0"},
	})
	if err != nil || record.SHA256 != digest {
		if err == nil {
			err = aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "deletion proof"})
		}
		writeError(response, request, normalizeArtifactError(err))
		return
	}
	completed, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID,
		IdempotencyKey: idempotencyKey + ":complete", ExpectedVersion: project.Version,
		Command: state.ProjectCommand{Type: state.ProjectCommandCompleteDeletion, Deletion: &state.ProjectDeletion{
			ProofSHA256: digest, ProofArtifactURI: record.URI, BackupExpiresAt: &retention,
		}},
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if err := handler.finalizeProjectAuthorizationErasure(request.Context(), principal.TenantID, projectID, project.Deletion.ID); err != nil {
		writeError(response, request, normalizeProjectErasureError(err))
		return
	}
	writeProject(response, http.StatusAccepted, completed.Project)
}

func (handler *Handler) finalizeProjectAuthorizationErasure(ctx context.Context, tenantID, projectID, deletionID string) error {
	finalizer, ok := handler.eraser.(projectAuthorizationEraser)
	if !ok {
		return nil
	}
	return finalizer.FinalizeProjectAuthorizationErasure(ctx, tenantID, projectID, deletionID)
}

func (handler *Handler) erasureUnavailable() bool {
	return handler == nil || handler.eraser == nil || handler.publisher == nil
}

func normalizeProjectErasureError(err error) error {
	if err == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "project eraser"})
	}
	if errors.Is(err, artifact.ErrInvalidRequest) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project eraser"})
	}
	if errors.Is(err, artifact.ErrConflict) {
		return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "project eraser"})
	}
	return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "project eraser"})
}

func (handler *Handler) projectEventHistory(ctx context.Context, tenantID, projectID string) ([]eventing.DomainEvent, error) {
	events, err := handler.events.ListEvents(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	result := make([]eventing.DomainEvent, 0, len(events))
	for _, event := range events {
		if event.ProjectID == projectID {
			result = append(result, event)
		}
	}
	return result, nil
}

func (handler *Handler) projectArtifactHistory(ctx context.Context, tenantID, projectID string) ([]artifact.Record, error) {
	result := make([]artifact.Record, 0, 100)
	cursor := ""
	seen := make(map[string]struct{})
	for {
		page, err := handler.artifacts.List(ctx, tenantID, projectID, cursor, 100)
		if err != nil {
			return nil, err
		}
		for _, record := range page.Items {
			if record.Metadata["kind"] != "project-export" {
				result = append(result, record)
			}
		}
		if page.NextCursor == "" {
			return result, nil
		}
		if _, duplicate := seen[page.NextCursor]; duplicate || len(seen) >= 10000 {
			return nil, artifact.ErrIntegrity
		}
		seen[page.NextCursor] = struct{}{}
		cursor = page.NextCursor
	}
}

func requireProjectVersionHeader(request *http.Request, expectedVersion int64) error {
	if len(request.Header.Values("If-Match")) != 1 {
		return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": expectedVersion})
	}
	return validateIfMatch(request.Header.Get("If-Match"), expectedVersion)
}

func safeAPIText(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
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

func (handler *Handler) listTaskSubmissions(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	cursor, err := goalCursor(request, "submission")
	if err != nil {
		writeError(response, request, err)
		return
	}
	if handler.taskHistory == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "task history"}))
		return
	}
	if err := handler.authorizeTaskHistoryRead(request.Context(), principal, projectID, taskID, "task-submissions"); err != nil {
		writeError(response, request, err)
		return
	}
	result, err := handler.taskHistory.ListSubmissions(request.Context(), principal.TenantID, projectID, taskID, cursor)
	if err != nil {
		writeError(response, request, normalizeTaskHistoryError(err))
		return
	}
	writeVersionedPage(response, request, result)
}

func (handler *Handler) listTaskAudits(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, taskID string) {
	cursor, err := goalCursor(request, "audit")
	if err != nil {
		writeError(response, request, err)
		return
	}
	if handler.taskHistory == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "task history"}))
		return
	}
	if err := handler.authorizeTaskHistoryRead(request.Context(), principal, projectID, taskID, "task-audits"); err != nil {
		writeError(response, request, err)
		return
	}
	result, err := handler.taskHistory.ListAudits(request.Context(), principal.TenantID, projectID, taskID, cursor)
	if err != nil {
		writeError(response, request, normalizeTaskHistoryError(err))
		return
	}
	writeVersionedPage(response, request, result)
}

func (handler *Handler) authorizeTaskHistoryRead(ctx context.Context, principal authn.Principal, projectID, taskID, resourceType string) error {
	project, found, err := handler.orchestrator.Project(ctx, principal.TenantID, projectID)
	if err != nil || !found {
		if err == nil {
			err = aorerrors.New(aorerrors.CodeNotFound, "", nil)
		}
		return normalizeError(err)
	}
	task, found, err := handler.orchestrator.Task(ctx, principal.TenantID, projectID, taskID)
	if err != nil || !found {
		if err == nil {
			err = aorerrors.New(aorerrors.CodeNotFound, "", nil)
		}
		return normalizeError(err)
	}
	if err := authorizeTaskRead(ctx, handler.authorizer, principal, project, task); err != nil {
		return err
	}
	return authorizeRead(ctx, handler.authorizer, principal, projectID, authz.ActionTaskRead, resourceType, taskID, string(project.State), project.Version, project.DataClassification)
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

type storedPlan struct {
	Version       int
	ContentSHA256 string
	Content       json.RawMessage
}

func (handler *Handler) listPlans(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	cursor, err := goalCursor(request, "plan")
	if err != nil {
		writeError(response, request, err)
		return
	}
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectRead, "plan-list", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	plans, err := handler.storedPlans(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	start := 0
	if cursor != "" {
		found := false
		for index := range plans {
			if planCursor(projectID, plans[index].Version, plans[index].ContentSHA256) == cursor {
				start = index + 1
				found = true
				break
			}
		}
		if !found {
			writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "plan cursor"}))
			return
		}
	}
	const pageSize = 100
	end := start + pageSize
	if end > len(plans) {
		end = len(plans)
	}
	items := make([]json.RawMessage, 0, end-start)
	for _, plan := range plans[start:end] {
		items = append(items, append(json.RawMessage(nil), plan.Content...))
	}
	result := page{Items: items}
	if end < len(plans) {
		last := plans[end-1]
		result.NextCursor = planCursor(projectID, last.Version, last.ContentSHA256)
	}
	response.Header().Set("ETag", entityTag(project.Version))
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) getPlan(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string, version int) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "plan query"}))
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectRead, "plan", strconv.Itoa(version)); err != nil {
		writeError(response, request, err)
		return
	}
	plans, err := handler.storedPlans(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	for _, plan := range plans {
		if plan.Version != version {
			continue
		}
		response.Header().Set("ETag", `"`+plan.ContentSHA256+`"`)
		response.Header().Set("Cache-Control", "private, no-store")
		writeJSON(response, http.StatusOK, plan.Content)
		return
	}
	writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
}

func (handler *Handler) storedPlans(ctx context.Context, tenantID, projectID string) ([]storedPlan, error) {
	lister, ok := handler.store.(eventing.ProjectionList)
	if !ok {
		return nil, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "plan projection list"})
	}
	projections, err := lister.ListProjections(ctx, tenantID, projectID, "spec_artifact")
	if err != nil {
		return nil, err
	}
	plans := make([]storedPlan, 0)
	seenVersions := make(map[int]struct{})
	for _, projection := range projections {
		var artifact struct {
			TenantID      string `json:"tenantId"`
			ProjectID     string `json:"projectId"`
			Kind          string `json:"kind"`
			Version       int    `json:"version"`
			ContentSHA256 string `json:"contentSha256"`
			Content       []byte `json:"content"`
		}
		if err := json.Unmarshal(projection.State, &artifact); err != nil {
			return nil, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, map[string]any{"scope": "plan projection"})
		}
		if artifact.Kind != "PLAN_SPEC" {
			continue
		}
		var plan contracts.PlanSpec
		if artifact.TenantID != tenantID || artifact.ProjectID != projectID || artifact.Version < 1 || len(artifact.Content) == 0 || contracts.ValidatePlanJSON(artifact.Content) != nil || json.Unmarshal(artifact.Content, &plan) != nil || plan.ProjectID != projectID || plan.PlanSpecVersion != artifact.Version || plan.SHA256 != artifact.ContentSHA256 {
			return nil, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "plan projection integrity"})
		}
		if _, duplicate := seenVersions[artifact.Version]; duplicate {
			return nil, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "plan version"})
		}
		seenVersions[artifact.Version] = struct{}{}
		plans = append(plans, storedPlan{Version: artifact.Version, ContentSHA256: artifact.ContentSHA256, Content: append(json.RawMessage(nil), artifact.Content...)})
	}
	sort.Slice(plans, func(left, right int) bool { return plans[left].Version < plans[right].Version })
	return plans, nil
}

func (handler *Handler) submitGoalMessage(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal message query"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body goalMessageBody
	if err := decodeJSON(request, &body); err != nil || body.ExpectedVersion < 1 || strings.TrimSpace(body.Message) == "" || len(body.Message) > maximumRequestBytes || strings.ContainsRune(body.Message, '\x00') {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal message"}))
		return
	}
	if err := validateGoalIfMatch(request, body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	if handler.goalPlan.Negotiator != nil {
		project, negotiateErr := handler.negotiateGoal(request.Context(), principal, projectID, body, idempotencyKey)
		if negotiateErr != nil {
			writeError(response, request, normalizeGoalPlanError(negotiateErr))
			return
		}
		writeProject(response, http.StatusAccepted, project)
		return
	}
	outcome, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID, IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion,
		Command: state.ProjectCommand{Type: state.ProjectCommandSubmitGoalMessage, GoalMessage: &state.GoalMessage{Kind: state.GoalMessageUser, Message: body.Message}},
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	writeProject(response, http.StatusAccepted, outcome.Project)
}

func (handler *Handler) listGoalMessages(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	cursor, err := goalCursor(request, "goal message")
	if err != nil {
		writeError(response, request, err)
		return
	}
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionGoalRead, "goal-message-list", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	messages, err := handler.orchestrator.GoalMessages(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	start := 0
	if cursor != "" {
		found := false
		for index := range messages {
			if goalMessageCursor(projectID, messages[index].ID) == cursor {
				start = index + 1
				found = true
				break
			}
		}
		if !found {
			writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal message cursor"}))
			return
		}
	}
	const pageSize = 100
	end := start + pageSize
	if end > len(messages) {
		end = len(messages)
	}
	items := append([]state.GoalMessage(nil), messages[start:end]...)
	result := page{Items: items}
	if end < len(messages) {
		result.NextCursor = goalMessageCursor(projectID, items[len(items)-1].ID)
	}
	response.Header().Set("ETag", entityTag(project.Version))
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) listGoalSpecs(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	cursor, err := goalCursor(request, "goal spec")
	if err != nil {
		writeError(response, request, err)
		return
	}
	project, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionGoalRead, "goal-spec-list", projectID)
	if err != nil {
		writeError(response, request, err)
		return
	}
	projections, err := handler.orchestrator.GoalSpecs(request.Context(), principal.TenantID, projectID)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	start := 0
	if cursor != "" {
		found := false
		for index := range projections {
			if goalSpecCursor(projectID, projections[index].Spec.Content.Version) == cursor {
				start = index + 1
				found = true
				break
			}
		}
		if !found {
			writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal spec cursor"}))
			return
		}
	}
	const pageSize = 100
	end := start + pageSize
	if end > len(projections) {
		end = len(projections)
	}
	items := make([]contracts.GoalSpec, 0, end-start)
	for _, projection := range projections[start:end] {
		items = append(items, projection.Spec)
	}
	result := page{Items: items}
	if end < len(projections) {
		result.NextCursor = goalSpecCursor(projectID, items[len(items)-1].Content.Version)
	}
	response.Header().Set("ETag", entityTag(project.Version))
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) getGoalSpec(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string, version int) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal spec query"}))
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionGoalRead, "goal-spec", strconv.Itoa(version)); err != nil {
		writeError(response, request, err)
		return
	}
	projection, found, err := handler.orchestrator.GoalSpec(request.Context(), principal.TenantID, projectID, version)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if !found {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	response.Header().Set("ETag", goalSpecETag(version, projection.Revision))
	writeJSON(response, http.StatusOK, projection.Spec)
}

func (handler *Handler) decideGoalSpec(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string, version int, action string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal decision query"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body goalDecisionBody
	if err := decodeJSON(request, &body); err != nil || !validGoalDecisionBody(body, version, action, idempotencyKey) {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal decision"}))
		return
	}
	if err := validateGoalIfMatch(request, body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionGoalRead, "goal-spec", strconv.Itoa(version)); err != nil {
		writeError(response, request, err)
		return
	}
	projection, found, err := handler.orchestrator.GoalSpec(request.Context(), principal.TenantID, projectID, version)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if !found {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	if projection.Spec.ContentSHA256 != body.SHA256 {
		writeError(response, request, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil))
		return
	}
	goal := &state.GoalRecord{ID: projection.GoalSpecID, Version: version, SHA256: body.SHA256, UnresolvedItems: append([]string(nil), projection.Spec.Content.UnresolvedItems...)}
	command := state.ProjectCommand{Goal: goal}
	if action == "approve" {
		if projection.Spec.Status != contracts.GoalDraft && !(projection.Spec.Status == contracts.GoalApproved && projection.Spec.ApprovedBy != nil && projection.Spec.ApprovedBy.ActorID == principal.ID) {
			writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "goal approval"}))
			return
		}
		if len(projection.Spec.Content.UnresolvedItems) != 0 {
			writeError(response, request, aorerrors.New(aorerrors.CodeGoalNotApproved, "", nil))
			return
		}
		reason := body.Comment
		if reason == "" {
			reason = "explicit GoalSpec approval"
		}
		if handler.goalPlan.Negotiator != nil {
			project, approveErr := handler.approveGoalAndPlan(request.Context(), principal, projectID, projection, body, idempotencyKey, reason)
			if approveErr != nil {
				writeError(response, request, normalizeGoalPlanError(approveErr))
				return
			}
			writeProject(response, http.StatusAccepted, project)
			return
		}
		issuedAt := handler.clock().UTC()
		approvalID, allocationErr := newRecordUUIDv7()
		if allocationErr != nil {
			writeError(response, request, aorerrors.Wrap(aorerrors.CodeInternalError, "", allocationErr, nil))
			return
		}
		command.Type = state.ProjectCommandApproveGoal
		command.Approval = &state.ApprovalBinding{
			RecordID: approvalID, ApprovalType: "GOAL_APPROVAL", SubjectType: "GOAL_SPEC",
			SubjectID: projection.GoalSpecID, SubjectVersion: version, SubjectSHA256: body.SHA256, PrincipalID: principal.ID,
			Reason: reason, IssuedAt: issuedAt, Signature: goalApprovalSignature(principal.TenantID, projectID, projection.GoalSpecID, version, body.SHA256, principal.ID, reason, idempotencyKey),
		}
	} else {
		if projection.Spec.Status != contracts.GoalDraft && projection.Spec.Status != contracts.GoalRejected {
			writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "goal rejection"}))
			return
		}
		command.Type = state.ProjectCommandRejectGoal
		command.GoalMessage = &state.GoalMessage{Kind: state.GoalMessageRejection, Message: body.Comment}
	}
	outcome, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID, IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion, Command: command,
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	writeProject(response, http.StatusAccepted, outcome.Project)
}

func (handler *Handler) requestGoalChange(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal change query"}))
		return
	}
	idempotencyKey, err := requiredIdempotencyKey(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	var body goalChangeBody
	if err := decodeJSON(request, &body); err != nil || !validGoalChangeBody(body) {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "goal change"}))
		return
	}
	if err := validateGoalIfMatch(request, body.ExpectedVersion); err != nil {
		writeError(response, request, err)
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionGoalRead, "goal-spec", strconv.Itoa(body.Version)); err != nil {
		writeError(response, request, err)
		return
	}
	projection, found, err := handler.orchestrator.GoalSpec(request.Context(), principal.TenantID, projectID, body.Version)
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	if !found {
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
		return
	}
	if projection.Spec.ContentSHA256 != body.SHA256 {
		writeError(response, request, aorerrors.New(aorerrors.CodeGoalHashMismatch, "", nil))
		return
	}
	if projection.Spec.Status != contracts.GoalApproved && projection.Spec.Status != contracts.GoalSuperseded {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidStateTransition, "", map[string]any{"scope": "goal change"}))
		return
	}
	goal := &state.GoalRecord{ID: projection.GoalSpecID, Version: body.Version, SHA256: body.SHA256, UnresolvedItems: append([]string(nil), projection.Spec.Content.UnresolvedItems...)}
	outcome, err := handler.orchestrator.HandleProject(request.Context(), orchestrator.ProjectRequest{
		TenantID: principal.TenantID, ProjectID: projectID, PrincipalID: principal.ID, IdempotencyKey: idempotencyKey, ExpectedVersion: body.ExpectedVersion,
		Command: state.ProjectCommand{Type: state.ProjectCommandRequestGoalChange, Goal: goal, GoalMessage: &state.GoalMessage{Kind: state.GoalMessageChangeRequest, Message: body.Message}, ImpactedTaskIDs: append([]string(nil), body.ImpactedTaskIDs...)},
	})
	if err != nil {
		writeError(response, request, normalizeError(err))
		return
	}
	writeProject(response, http.StatusAccepted, outcome.Project)
}

func validGoalDecisionBody(body goalDecisionBody, version int, action, headerKey string) bool {
	if body.ExpectedVersion < 1 || (contracts.SpecRef{Version: version, SHA256: body.SHA256}).Validate() != nil || body.IdempotencyKey != "" && body.IdempotencyKey != headerKey || len(body.Comment) > 2048 || strings.ContainsRune(body.Comment, '\x00') {
		return false
	}
	if action == "approve" {
		return body.Decision == "" || body.Decision == "APPROVE"
	}
	return (body.Decision == "" || body.Decision == "REJECT") && strings.TrimSpace(body.Comment) != ""
}

func validGoalChangeBody(body goalChangeBody) bool {
	if body.ExpectedVersion < 1 || body.Version < 1 || (contracts.SpecRef{Version: body.Version, SHA256: body.SHA256}).Validate() != nil || strings.TrimSpace(body.Message) == "" || len(body.Message) > maximumRequestBytes || strings.ContainsRune(body.Message, '\x00') || body.ImpactedTaskIDs == nil {
		return false
	}
	seen := make(map[string]bool, len(body.ImpactedTaskIDs))
	for _, taskID := range body.ImpactedTaskIDs {
		if seen[taskID] || !validAPIIdentifier(taskID) && !validProjectID(taskID) {
			return false
		}
		seen[taskID] = true
	}
	return true
}

func validateGoalIfMatch(request *http.Request, expectedVersion int64) error {
	if len(request.Header.Values("If-Match")) != 1 {
		return aorerrors.New(aorerrors.CodeStateVersionConflict, "", map[string]any{"expectedVersion": expectedVersion})
	}
	return validateIfMatch(request.Header.Get("If-Match"), expectedVersion)
}

func goalCursor(request *http.Request, scope string) (string, error) {
	query := request.URL.Query()
	if len(query) > 1 || len(query) == 1 && len(query["cursor"]) != 1 {
		return "", aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": scope + " cursor"})
	}
	cursor := query.Get("cursor")
	if len(cursor) > 512 || strings.ContainsAny(cursor, "\r\n\x00") {
		return "", aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": scope + " cursor"})
	}
	return cursor, nil
}

func goalMessageCursor(projectID, messageID string) string {
	digest := sha256.Sum256([]byte(projectID + "\x00message\x00" + messageID))
	return hex.EncodeToString(digest[:])
}

func goalSpecCursor(projectID string, version int) string {
	digest := sha256.Sum256([]byte(projectID + "\x00spec\x00" + strconv.Itoa(version)))
	return hex.EncodeToString(digest[:])
}

func goalSpecETag(version int, revision int64) string {
	return `"goal-v` + strconv.Itoa(version) + `-r` + strconv.FormatInt(revision, 10) + `"`
}

func newRecordUUIDv7() (string, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	return value.String(), nil
}

func releaseApprovalSignature(tenantID, projectID string, version int64, digest, principalID, idempotencyKey string) string {
	value := sha256.Sum256([]byte(tenantID + "\x00" + projectID + "\x00" + strconv.FormatInt(version, 10) + "\x00" + digest + "\x00" + principalID + "\x00explicit release approval\x00" + idempotencyKey))
	return "oidc-sha256:" + hex.EncodeToString(value[:])
}

func goalApprovalSignature(tenantID, projectID, goalSpecID string, version int, digest, principalID, reason, idempotencyKey string) string {
	value := sha256.Sum256([]byte(tenantID + "\x00" + projectID + "\x00" + goalSpecID + "\x00" + strconv.Itoa(version) + "\x00" + digest + "\x00" + principalID + "\x00" + reason + "\x00" + idempotencyKey))
	return "oidc-sha256:" + hex.EncodeToString(value[:])
}

func (handler *Handler) authorizeProjectResourceRead(ctx context.Context, principal authn.Principal, projectID, action, resourceType, resourceID string) (state.Project, error) {
	project, found, err := handler.orchestrator.Project(ctx, principal.TenantID, projectID)
	if err != nil {
		return state.Project{}, normalizeError(err)
	}
	if !found {
		return state.Project{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := authorizeRead(ctx, handler.authorizer, principal, projectID, action, resourceType, resourceID, string(project.State), project.Version, project.DataClassification); err != nil {
		return state.Project{}, err
	}
	return project, nil
}

func (handler *Handler) listArtifacts(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if handler.artifacts == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "artifact catalog"}))
		return
	}
	query := request.URL.Query()
	if len(query) > 1 || len(query) == 1 && len(query["cursor"]) != 1 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "artifact cursor"}))
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectRead, "artifact-list", projectID); err != nil {
		writeError(response, request, err)
		return
	}
	result, err := handler.artifacts.List(request.Context(), principal.TenantID, projectID, query.Get("cursor"), 100)
	if err != nil {
		writeError(response, request, normalizeArtifactError(err))
		return
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "artifact page"}))
		return
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "artifact page"}))
		return
	}
	response.Header().Set("ETag", `"`+digest+`"`)
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) getArtifact(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID, artifactID string) {
	if handler.artifacts == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "artifact catalog"}))
		return
	}
	download, err := artifactDownloadQuery(request)
	if err != nil {
		writeError(response, request, err)
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionProjectRead, "artifact", artifactID); err != nil {
		writeError(response, request, err)
		return
	}
	if !download {
		record, err := handler.artifacts.Get(request.Context(), principal.TenantID, projectID, artifactID)
		if err != nil {
			writeError(response, request, normalizeArtifactError(err))
			return
		}
		response.Header().Set("ETag", `"`+record.SHA256+`"`)
		response.Header().Set("Cache-Control", "private, no-store")
		writeJSON(response, http.StatusOK, record)
		return
	}
	record, reader, err := handler.artifacts.Open(request.Context(), principal.TenantID, projectID, artifactID)
	if err != nil {
		writeError(response, request, normalizeArtifactError(err))
		return
	}
	defer reader.Close()
	response.Header().Set("Content-Type", record.ContentType)
	response.Header().Set("Content-Disposition", `attachment; filename="`+record.ID+`"`)
	response.Header().Set("Content-Length", strconv.FormatInt(record.SizeBytes, 10))
	response.Header().Set("ETag", `"`+record.SHA256+`"`)
	response.Header().Set("X-AOR-Artifact-URI", record.URI)
	response.Header().Set("Cache-Control", "private, no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = io.Copy(response, reader)
}

func (handler *Handler) searchKnowledge(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if handler.knowledge == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge service"}))
		return
	}
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge query"}))
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionKnowledgeRead, "knowledge.snapshot", projectID); err != nil {
		writeError(response, request, err)
		return
	}
	var body knowledgeSearchBody
	if err := decodeJSON(request, &body); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge search"}))
		return
	}
	result, err := handler.knowledge.Search(request.Context(), knowledge.SearchRequest{Access: knowledgeAccess(principal, projectID), Path: body.Path, Title: body.Title, Tags: append([]string(nil), body.Tags...), Text: body.Text, Limit: body.Limit})
	if err != nil {
		writeError(response, request, normalizeKnowledgeError(err))
		return
	}
	response.Header().Set("ETag", `"`+result.Revision+`"`)
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) readKnowledgeRange(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if handler.knowledge == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge service"}))
		return
	}
	if len(request.URL.Query()) != 0 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge query"}))
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionKnowledgeRead, "knowledge.reference", projectID); err != nil {
		writeError(response, request, err)
		return
	}
	var body knowledgeReadRangeBody
	if err := decodeJSON(request, &body); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge read range"}))
		return
	}
	result, err := handler.knowledge.ReadRange(request.Context(), knowledge.ReadRangeRequest{Access: knowledgeAccess(principal, projectID), Reference: body.Reference, LineStart: body.LineStart, LineEnd: body.LineEnd})
	if err != nil {
		writeError(response, request, normalizeKnowledgeError(err))
		return
	}
	response.Header().Set("ETag", `"`+result.Reference.SHA256+`"`)
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) getKnowledgeManifest(response http.ResponseWriter, request *http.Request, principal authn.Principal, projectID string) {
	if handler.knowledge == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge service"}))
		return
	}
	query := request.URL.Query()
	if len(query) > 1 || len(query) == 1 && len(query["revision"]) != 1 {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge revision"}))
		return
	}
	if _, err := handler.authorizeProjectResourceRead(request.Context(), principal, projectID, authz.ActionKnowledgeRead, "knowledge.manifest", projectID); err != nil {
		writeError(response, request, err)
		return
	}
	manifest, err := handler.knowledge.Manifest(request.Context(), knowledgeAccess(principal, projectID), query.Get("revision"))
	if err != nil {
		writeError(response, request, normalizeKnowledgeError(err))
		return
	}
	response.Header().Set("ETag", `"`+manifest.Revision+`"`)
	response.Header().Set("Cache-Control", "private, no-store")
	writeJSON(response, http.StatusOK, manifest)
}

func artifactDownloadQuery(request *http.Request) (bool, error) {
	query := request.URL.Query()
	if len(query) == 0 {
		return false, nil
	}
	values, found := query["download"]
	if len(query) != 1 || !found || len(values) != 1 || values[0] != "true" && values[0] != "false" {
		return false, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "artifact download"})
	}
	return values[0] == "true", nil
}

func knowledgeAccess(principal authn.Principal, projectID string) knowledge.Access {
	return knowledge.Access{Principal: principal, TenantID: principal.TenantID, ProjectID: projectID}
}

func normalizeArtifactError(err error) error {
	switch {
	case errors.Is(err, artifact.ErrInvalidRequest):
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "artifact"})
	case errors.Is(err, artifact.ErrNotFound):
		return aorerrors.New(aorerrors.CodeArtifactNotAvailable, "", nil)
	case errors.Is(err, artifact.ErrIntegrity):
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	case errors.Is(err, artifact.ErrConflict):
		return aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "artifact"})
	default:
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "artifact catalog"})
	}
}

func normalizeKnowledgeError(err error) error {
	var typed *aorerrors.Error
	if errors.As(err, &typed) {
		return typed
	}
	return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "knowledge service"})
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
	after, err := eventCursor(request)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "event cursor"}))
		return
	}
	projectEvents := sortProjectEvents(events, projectID)
	start, foundCursor := eventStart(projectEvents, after)
	if after != "" && !foundCursor {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "event cursor"}))
		return
	}
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Accel-Buffering", "no")
	response.Header().Set("Connection", "keep-alive")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	lastCursor := after
	frames, preparedCursor, prepareErr := handler.prepareProjectEventBatch(request, principal, project, projectEvents[start:], lastCursor)
	if prepareErr != nil {
		writeError(response, request, prepareErr)
		return
	}
	lastCursor = preparedCursor
	response.WriteHeader(http.StatusOK)
	if writeErr := writeProjectEventFrames(response, frames); writeErr != nil {
		return
	}
	if !eventFollowRequested(request) {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case <-ticker.C:
			latest, listErr := handler.events.ListEvents(request.Context(), principal.TenantID)
			if listErr != nil {
				return
			}
			latest = sortProjectEvents(latest, projectID)
			frames, nextCursor, prepareErr := handler.prepareProjectEventBatch(request, principal, project, eventsAfterCursor(latest, lastCursor), lastCursor)
			if prepareErr != nil {
				return
			}
			if writeErr := writeProjectEventFrames(response, frames); writeErr != nil {
				return
			}
			lastCursor = nextCursor
		}
	}
}

func eventCursor(request *http.Request) (string, error) {
	if request == nil {
		return "", errors.New("nil event request")
	}
	queryCursor := request.URL.Query().Get("after")
	headerCursor := request.Header.Get("Last-Event-ID")
	if queryCursor != "" && headerCursor != "" && queryCursor != headerCursor {
		return "", errors.New("conflicting event cursors")
	}
	cursor := queryCursor
	if cursor == "" {
		cursor = headerCursor
	}
	if len(cursor) > 512 || strings.ContainsAny(cursor, "\r\n\x00") {
		return "", errors.New("invalid event cursor")
	}
	return cursor, nil
}

func sortProjectEvents(events []eventing.DomainEvent, projectID string) []eventing.DomainEvent {
	result := make([]eventing.DomainEvent, 0, len(events))
	for _, event := range events {
		if event.ProjectID == projectID {
			result = append(result, event)
		}
	}
	sort.SliceStable(result, func(left, right int) bool {
		if result[left].OccurredAt.Equal(result[right].OccurredAt) {
			if result[left].AggregateVersion != result[right].AggregateVersion {
				return result[left].AggregateVersion < result[right].AggregateVersion
			}
			return result[left].EventID < result[right].EventID
		}
		return result[left].OccurredAt.Before(result[right].OccurredAt)
	})
	return result
}

func eventStart(events []eventing.DomainEvent, cursor string) (int, bool) {
	if cursor == "" {
		return 0, true
	}
	for index, event := range events {
		if event.EventID == cursor {
			return index + 1, true
		}
	}
	return 0, false
}

func eventsAfterCursor(events []eventing.DomainEvent, cursor string) []eventing.DomainEvent {
	if cursor == "" {
		return events
	}
	start, found := eventStart(events, cursor)
	if !found {
		return events
	}
	return events[start:]
}

func eventFollowRequested(request *http.Request) bool {
	if request == nil {
		return false
	}
	if strings.EqualFold(request.URL.Query().Get("follow"), "true") {
		return true
	}
	return strings.Contains(strings.ToLower(request.Header.Get("Accept")), "text/event-stream")
}

type projectEventFrame struct {
	id      string
	event   string
	payload []byte
}

func (handler *Handler) prepareProjectEventBatch(request *http.Request, principal authn.Principal, project state.Project, events []eventing.DomainEvent, cursor string) ([]projectEventFrame, string, error) {
	frames := make([]projectEventFrame, 0, len(events))
	lastCursor := cursor
	for _, event := range events {
		if lastCursor == event.EventID {
			continue
		}
		resourceType, resourceID := "project-event", event.EventID
		switch event.AggregateType {
		case "task":
			resourceType, resourceID = "task", event.AggregateID
		case "audit":
			resourceType, resourceID = "audit", event.AggregateID
		}
		if err := authorizeRead(request.Context(), handler.authorizer, principal, project.ID, "project.read", resourceType, resourceID, string(project.State), project.Version, project.DataClassification); err != nil {
			var typed *aorerrors.Error
			if errors.As(err, &typed) && typed.Code == aorerrors.CodePolicyDenied {
				lastCursor = event.EventID
				continue
			}
			return nil, lastCursor, err
		}
		external, err := eventing.Externalize(event, eventing.CloudEventOptions{Source: "urn:aor:service:orchestrator"})
		if err != nil {
			return nil, lastCursor, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, map[string]any{"scope": "external event"})
		}
		if !safeSSEField(external.ID) || !safeSSEField(external.Type) {
			return nil, lastCursor, errors.New("unsafe SSE field")
		}
		payload, err := json.Marshal(external)
		if err != nil {
			return nil, lastCursor, err
		}
		frames = append(frames, projectEventFrame{id: external.ID, event: external.Type, payload: payload})
		lastCursor = event.EventID
	}
	return frames, lastCursor, nil
}

func writeProjectEventFrames(response http.ResponseWriter, frames []projectEventFrame) error {
	for _, frame := range frames {
		if _, err := io.WriteString(response, "id: "+frame.id+"\n"); err != nil {
			return err
		}
		if _, err := io.WriteString(response, "event: "+frame.event+"\n"); err != nil {
			return err
		}
		if _, err := io.WriteString(response, "data: "+string(frame.payload)+"\n\n"); err != nil {
			return err
		}
		if flusher, ok := response.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	return nil
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
	case "request-deletion":
		return state.ProjectCommandRequestDeletion, true
	case "approve-release":
		return state.ProjectCommandApproveRelease, true
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

func planCursor(projectID string, version int, contentSHA256 string) string {
	digest := sha256.Sum256([]byte(projectID + "\x00" + strconv.Itoa(version) + "\x00" + contentSHA256))
	return hex.EncodeToString(digest[:])
}

func writeProject(response http.ResponseWriter, status int, project state.Project) {
	response.Header().Set("ETag", entityTag(project.Version))
	writeJSON(response, status, project)
}

func writeVersionedPage(response http.ResponseWriter, request *http.Request, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "history page"}))
		return
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "history page"}))
		return
	}
	response.Header().Set("ETag", `"`+digest+`"`)
	writeJSON(response, http.StatusOK, value)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeMethodNotAllowed(response http.ResponseWriter, request *http.Request) {
	writeMethodNotAllowedWith(response, request, "GET, POST")
}

func writeMethodNotAllowedWith(response http.ResponseWriter, request *http.Request, allowed string) {
	response.Header().Set("Allow", allowed)
	problem := aorerrors.New(aorerrors.CodeInvalidArgument, request.Header.Get("X-Request-ID"), map[string]any{"scope": "http method"}).Problem()
	problem.Status = http.StatusMethodNotAllowed
	problem.Instance = request.URL.Path
	writeJSON(response, http.StatusMethodNotAllowed, problem)
}

func validProjectID(value string) bool {
	return uuidPattern.MatchString(value)
}

func validArtifactID(value string) bool {
	return uuidPattern.MatchString(value)
}

func validAPIIdentifier(value string) bool {
	if uuidPattern.MatchString(value) {
		return true
	}
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

func normalizeTaskHistoryError(err error) error {
	var typed *aorerrors.Error
	if errors.As(err, &typed) {
		return typed
	}
	return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "task history"})
}
