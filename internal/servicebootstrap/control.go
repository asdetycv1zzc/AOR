package servicebootstrap

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/controlapi"
	"github.com/akimisaka/aor/internal/credentials"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/internal/modelproviders"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/webui"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
)

type controlHandler struct {
	http.Handler
	dispatcher           *eventing.OutboxDispatcher
	retention            *artifact.RetentionWorker
	scheduler            *aorworkflow.ReadyExecutionScheduler
	moduleAuditScheduler *aorworkflow.ModuleAuditScheduler
	integrationScheduler *aorworkflow.IntegrationScheduler
	globalAuditScheduler *aorworkflow.GlobalAuditScheduler
	planningRecovery     *goalplan.PlanningRecoveryScheduler
	cancel               context.CancelFunc
	dispatchDone         <-chan error
	retentionDone        <-chan error
	schedulerDone        <-chan error
	moduleAuditDone      <-chan error
	integrationDone      <-chan error
	globalAuditDone      <-chan error
	planningRecoveryDone <-chan error
	close                sync.Once
	closeErr             error
}

type artifactProjectEraser struct {
	catalog *artifact.PostgresS3Catalog
}

func (eraser artifactProjectEraser) EraseProject(ctx context.Context, tenantID, projectID, deletionID string) (controlapi.ErasureReport, error) {
	report, err := eraser.catalog.EraseProject(ctx, tenantID, projectID, deletionID)
	if err != nil {
		return controlapi.ErasureReport{}, err
	}
	return controlapi.ErasureReport{
		Scopes: append([]string(nil), report.Scopes...), Records: report.Records,
		Objects: report.Objects, CacheEntries: report.CacheEntries,
	}, nil
}

func (eraser artifactProjectEraser) FinalizeProjectAuthorizationErasure(ctx context.Context, tenantID, projectID, deletionID string) error {
	return eraser.catalog.FinalizeProjectAuthorizationErasure(ctx, tenantID, projectID, deletionID)
}

func (handler *controlHandler) Ready() error {
	if handler == nil || handler.dispatcher == nil || handler.retention == nil || handler.scheduler == nil || handler.moduleAuditScheduler == nil || handler.planningRecovery == nil {
		return runtimeclient.ErrDependencyUnavailable
	}
	if err := handler.dispatcher.Ready(); err != nil {
		return err
	}
	if err := handler.retention.Ready(); err != nil {
		return err
	}
	if err := handler.scheduler.Ready(); err != nil {
		return err
	}
	if err := handler.moduleAuditScheduler.Ready(); err != nil {
		return err
	}
	if err := handler.planningRecovery.Ready(); err != nil {
		return err
	}
	if handler.integrationScheduler != nil {
		if err := handler.integrationScheduler.Ready(); err != nil {
			return err
		}
	}
	if handler.globalAuditScheduler != nil {
		return handler.globalAuditScheduler.Ready()
	}
	return nil
}

func (handler *controlHandler) Close() error {
	if handler == nil {
		return nil
	}
	handler.close.Do(func() {
		if handler.cancel != nil {
			handler.cancel()
		}
		if handler.dispatchDone != nil {
			err := <-handler.dispatchDone
			if err != nil && !errors.Is(err, context.Canceled) {
				handler.closeErr = err
			}
		}
		if handler.retentionDone != nil {
			err := <-handler.retentionDone
			if err != nil && !errors.Is(err, context.Canceled) {
				handler.closeErr = errors.Join(handler.closeErr, err)
			}
		}
		if handler.planningRecoveryDone != nil {
			err := <-handler.planningRecoveryDone
			if err != nil && !errors.Is(err, context.Canceled) {
				handler.closeErr = errors.Join(handler.closeErr, err)
			}
		}
		if handler.schedulerDone != nil {
			err := <-handler.schedulerDone
			if err != nil && !errors.Is(err, context.Canceled) {
				handler.closeErr = errors.Join(handler.closeErr, err)
			}
		}
		if handler.moduleAuditDone != nil {
			err := <-handler.moduleAuditDone
			if err != nil && !errors.Is(err, context.Canceled) {
				handler.closeErr = errors.Join(handler.closeErr, err)
			}
		}
		if handler.integrationDone != nil {
			err := <-handler.integrationDone
			if err != nil && !errors.Is(err, context.Canceled) {
				handler.closeErr = errors.Join(handler.closeErr, err)
			}
		}
		if handler.globalAuditDone != nil {
			err := <-handler.globalAuditDone
			if err != nil && !errors.Is(err, context.Canceled) {
				handler.closeErr = errors.Join(handler.closeErr, err)
			}
		}
	})
	return handler.closeErr
}

func ControlAPI(config runtimeconfig.Config, clients *runtimeclient.Clients) (http.Handler, error) {
	if clients == nil || clients.Database() == nil || clients.JetStream() == nil || clients.S3() == nil || clients.Temporal() == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	authenticator, err := oidcAuthenticator(config)
	if err != nil {
		return nil, err
	}
	authorizer, err := policy.NewOPAClient(config.OPA.URL)
	if err != nil {
		return nil, err
	}
	store := eventing.NewPostgresStore(clients.Database())
	lifecycleStore, err := aorworkflow.NewProjectLifecycleStore(store, clients.Temporal(), config.Temporal.TaskQueue)
	if err != nil {
		return nil, err
	}
	artifactCatalog, err := artifact.NewPostgresS3Catalog(clients.Database(), clients.S3(), config.S3.Bucket, time.Now)
	if err != nil {
		return nil, err
	}
	retentionWorker, err := artifact.NewRetentionWorker(artifactCatalog, artifact.RetentionWorkerConfig{})
	if err != nil {
		return nil, err
	}
	knowledgeRepository, err := knowledge.NewFileRepository(config.KnowledgeRoot)
	if err != nil {
		return nil, err
	}
	knowledgeScopes, err := knowledge.NewEventingScopeResolver(store)
	if err != nil {
		return nil, err
	}
	knowledgeEvents, err := controlKnowledgeUpdatedPublisher(config, store)
	if err != nil {
		return nil, err
	}
	knowledgeService, err := knowledge.NewService(knowledge.ServiceConfig{Repository: knowledgeRepository, Authorizer: authorizer, Scopes: knowledgeScopes, Events: knowledgeEvents, Clock: time.Now})
	if err != nil {
		return nil, err
	}
	leaseService, err := controlLeaseAuthority(config, clients.Database(), authorizer)
	if err != nil {
		return nil, err
	}
	artifactPublisher, err := controlArtifactPublisher(config, clients.Database(), artifactCatalog, authorizer)
	if err != nil {
		return nil, err
	}
	decisionReportSigner, err := controlDecisionReportSigner(config)
	if err != nil {
		return nil, err
	}
	modelProviders, defaultModelRoutes, err := configuredControlModelConfiguration(config)
	if err != nil {
		return nil, err
	}
	providerSettings, err := configuredControlProviderSettings(config, clients.Database())
	if err != nil {
		return nil, err
	}
	samplingSettings, err := modelgateway.NewPostgresSamplingSettingsStore(clients.Database())
	if err != nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	projectAgents, err := configuredGoalPlanServices(config, lifecycleStore, leaseService, authorizer, knowledgeService, knowledgeEvents)
	if err != nil {
		return nil, err
	}
	planningRecoveries, err := goalplan.NewPostgresPlanningRecoverySource(clients.Database())
	if err != nil {
		return nil, err
	}
	planningRecovery, err := goalplan.NewPlanningRecoveryScheduler(planningRecoveries, projectAgents.goalPlan.Planner)
	if err != nil {
		return nil, err
	}
	projectAgents.goalPlan.Recovery = planningRecoveries
	knowledgeCurator := controlapi.KnowledgeCuratorService(projectAgents.curator)
	if config.KnowledgeCuratorURL != "" {
		// The API process keeps the project-scoped read service, but all Curator
		// mutations are routed to the writer process with the configured URL.
		knowledgeCurator = nil
	}
	var anonymousPrincipal *authn.Principal
	if config.AllowAnonymousControlAPI {
		principal := authn.Principal{
			ID: "local-user", Type: authn.PrincipalUser, Role: config.Identity.DefaultRole,
			TenantID: config.Identity.DefaultTenantID, Issuer: config.Identity.Issuer, Subject: "local-user",
		}
		anonymousPrincipal = &principal
	}
	domain, err := controlapi.New(controlapi.Config{
		Store: lifecycleStore, Authenticator: authenticator, AnonymousPrincipal: anonymousPrincipal, Authorizer: authorizer,
		Database: clients.Database(), Artifacts: artifactPublisher, Knowledge: knowledgeService,
		KnowledgeCurator: knowledgeCurator, KnowledgeCuratorURL: config.KnowledgeCuratorURL,
		DecisionReportSigner: decisionReportSigner,
		Eraser:               artifactProjectEraser{catalog: artifactCatalog}, Leases: leaseService,
		GoalPlan: projectAgents.goalPlan, ClassroomCore: config.DeploymentProfile == "TEST",
		ModelProviders: modelProviders, DefaultModelRoutes: defaultModelRoutes, Clock: time.Now,
		ProviderSettings: providerSettings, ProviderAdapter: modelproviders.AdapterFactory{},
		SamplingSettings: samplingSettings,
	})
	if err != nil {
		return nil, err
	}
	domainHandler := http.Handler(domain)
	if root := os.Getenv("AOR_WEB_ROOT"); root != "" {
		domainHandler, err = webui.New(webui.Config{
			Next: domainHandler, Root: root, Issuer: config.Identity.Issuer,
			ClientID: config.Identity.Audience, TokenEndpoint: config.ModelGatewayClient.TokenEndpoint,
		})
		if err != nil {
			return nil, runtimeconfig.ErrInvalidConfiguration
		}
	}
	domainHandler = withRequestTrace(domainHandler)
	bus, err := eventing.NewJetStreamEventBus(clients.JetStream(), eventing.JetStreamEventBusConfig{
		Stream: config.NATS.Stream, Source: "urn:aor:service:orchestrator",
	})
	if err != nil {
		return nil, err
	}
	publisher, err := eventing.NewOutboxPublisher(store, bus, eventing.OutboxPublisherConfig{})
	if err != nil {
		return nil, err
	}
	dispatcher, err := eventing.NewOutboxDispatcher(store, publisher, eventing.OutboxDispatcherConfig{})
	if err != nil {
		return nil, err
	}
	readyExecutions, err := aorworkflow.NewPostgresReadyExecutionSource(clients.Database())
	if err != nil {
		return nil, err
	}
	executionStarter, err := aorworkflow.NewProjectExecutionStarter(clients.Temporal(), config.Temporal.TaskQueue)
	if err != nil {
		return nil, err
	}
	scheduler, err := aorworkflow.NewReadyExecutionScheduler(readyExecutions, executionStarter)
	if err != nil {
		return nil, err
	}
	moduleAuditRequests, err := aorworkflow.NewPostgresModuleAuditRequests(clients.Database())
	if err != nil {
		return nil, err
	}
	moduleAuditStarter, err := aorworkflow.NewModuleAuditStarter(clients.Temporal(), moduleAuditRequests, config.Temporal.TaskQueue)
	if err != nil {
		return nil, err
	}
	moduleAuditScheduler, err := aorworkflow.NewModuleAuditScheduler(moduleAuditRequests, moduleAuditStarter)
	if err != nil {
		return nil, err
	}
	var integrationScheduler *aorworkflow.IntegrationScheduler
	var globalAuditScheduler *aorworkflow.GlobalAuditScheduler
	if config.DeploymentProfile != "TEST" {
		integrationRequests, err := aorworkflow.NewPostgresIntegrationRequests(clients.Database())
		if err != nil {
			return nil, err
		}
		integrationStarter, err := aorworkflow.NewIntegrationStarter(clients.Temporal(), integrationRequests, config.Temporal.TaskQueue)
		if err != nil {
			return nil, err
		}
		integrationScheduler, err = aorworkflow.NewIntegrationScheduler(integrationRequests, integrationStarter)
		if err != nil {
			return nil, err
		}
		globalAuditRequests, err := aorworkflow.NewPostgresGlobalAuditRequests(clients.Database())
		if err != nil {
			return nil, err
		}
		globalAuditStarter, err := aorworkflow.NewGlobalAuditStarter(clients.Temporal(), globalAuditRequests, config.Temporal.TaskQueue)
		if err != nil {
			return nil, err
		}
		globalAuditScheduler, err = aorworkflow.NewGlobalAuditScheduler(globalAuditRequests, globalAuditStarter)
		if err != nil {
			return nil, err
		}
	}
	dispatchContext, cancel := context.WithCancel(context.Background())
	dispatchDone := make(chan error, 1)
	retentionDone := make(chan error, 1)
	schedulerDone := make(chan error, 1)
	moduleAuditDone := make(chan error, 1)
	planningRecoveryDone := make(chan error, 1)
	var integrationDone chan error
	var globalAuditDone chan error
	go func() { dispatchDone <- dispatcher.Run(dispatchContext) }()
	go func() { retentionDone <- retentionWorker.Run(dispatchContext) }()
	go func() { schedulerDone <- scheduler.Run(dispatchContext) }()
	go func() { moduleAuditDone <- moduleAuditScheduler.Run(dispatchContext) }()
	go func() { planningRecoveryDone <- planningRecovery.Run(dispatchContext) }()
	if integrationScheduler != nil {
		integrationDone = make(chan error, 1)
		go func() { integrationDone <- integrationScheduler.Run(dispatchContext) }()
	}
	if globalAuditScheduler != nil {
		globalAuditDone = make(chan error, 1)
		go func() { globalAuditDone <- globalAuditScheduler.Run(dispatchContext) }()
	}
	return &controlHandler{
		Handler: domainHandler, dispatcher: dispatcher, retention: retentionWorker, scheduler: scheduler,
		moduleAuditScheduler: moduleAuditScheduler, integrationScheduler: integrationScheduler,
		globalAuditScheduler: globalAuditScheduler, planningRecovery: planningRecovery, cancel: cancel,
		dispatchDone: dispatchDone, retentionDone: retentionDone, schedulerDone: schedulerDone, moduleAuditDone: moduleAuditDone,
		integrationDone: integrationDone, globalAuditDone: globalAuditDone, planningRecoveryDone: planningRecoveryDone,
	}, nil
}

func configuredControlProviderSettings(config runtimeconfig.Config, database *sql.DB) (modelproviders.SettingsStore, error) {
	if database == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	resolveContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	replayKey, err := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT")).Resolve(resolveContext, config.ModelGateway.ReplayKeyRef)
	cancel()
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	settings, err := modelproviders.NewPostgresStore(database, replayKey)
	clearBytes(replayKey)
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	return settings, nil
}

func controlDecisionReportSigner(config runtimeconfig.Config) (controlapi.TaskDecisionReportSigner, error) {
	resolveContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	leaseKey, err := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT")).Resolve(resolveContext, config.LeaseSigningKeyRef)
	cancel()
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	derived := deriveDecisionReportSigningKey(leaseKey)
	clearBytes(leaseKey)
	signer, err := controlapi.NewHMACTaskDecisionReportSigner(derived)
	clearBytes(derived)
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	return signer, nil
}

func controlKnowledgeUpdatedPublisher(config runtimeconfig.Config, store eventing.Store) (*knowledge.EventKnowledgeUpdatedPublisher, error) {
	if store == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	resolveContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	leaseKey, err := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT")).Resolve(resolveContext, config.LeaseSigningKeyRef)
	cancel()
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	derived := deriveKnowledgeUpdatedSigningKey(leaseKey)
	clearBytes(leaseKey)
	signer, err := knowledge.NewHMACKnowledgeUpdatedSigner(derived)
	clearBytes(derived)
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	publisher, err := knowledge.NewEventKnowledgeUpdatedPublisher(store, signer, time.Now)
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	return publisher, nil
}

func controlLeaseAuthority(config runtimeconfig.Config, database *sql.DB, authorizer authz.LeaseGrantEvaluator) (*leaseauthority.Service, error) {
	if database == nil || authorizer == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	leaseManager, _, err := controlLeaseManager(config, database)
	if err != nil {
		return nil, err
	}
	leaseScopes, err := leaseauthority.NewPostgresScopeResolver(database, config.DeploymentProfile)
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	service, err := leaseauthority.New(leaseauthority.Config{Manager: leaseManager, Policy: authorizer, Scopes: leaseScopes, Clock: time.Now})
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	return service, nil
}

func controlArtifactPublisher(config runtimeconfig.Config, database *sql.DB, catalog *artifact.PostgresS3Catalog, policyClient publicationPolicyClient) (*artifact.CapabilityPublisher, error) {
	if database == nil || catalog == nil || policyClient == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	leaseManager, _, err := controlLeaseManager(config, database)
	if err != nil {
		return nil, err
	}
	publisher, err := artifact.NewCapabilityPublisher(artifact.CapabilityPublisherConfig{
		Catalog: catalog, Leases: leaseManager, Policy: policyClient,
		ServiceID: "aor-control-artifact-service", DeploymentProfile: config.DeploymentProfile,
	})
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	return publisher, nil
}

type publicationPolicyClient interface {
	authz.PolicyEvaluator
	authz.LeaseGrantEvaluator
}

func controlLeaseManager(config runtimeconfig.Config, database *sql.DB) (*authz.LeaseManager, authz.Signer, error) {
	if database == nil {
		return nil, nil, runtimeclient.ErrInvalidClientConfig
	}
	resolveContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	leaseKey, err := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT")).Resolve(resolveContext, config.LeaseSigningKeyRef)
	cancel()
	if err != nil {
		return nil, nil, runtimeconfig.ErrInvalidConfiguration
	}
	leaseSigner, err := authz.NewHMACSigner(leaseKey)
	clearBytes(leaseKey)
	if err != nil {
		return nil, nil, runtimeconfig.ErrInvalidConfiguration
	}
	leaseStore, err := authz.NewPostgresLeaseStore(database)
	if err != nil {
		return nil, nil, runtimeconfig.ErrInvalidConfiguration
	}
	leaseManager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{
		Store: leaseStore, Signer: leaseSigner,
		DefaultTTL: 5 * time.Minute, MaxTTL: 15 * time.Minute, HeartbeatInterval: 30 * time.Second,
	})
	if err != nil {
		return nil, nil, runtimeconfig.ErrInvalidConfiguration
	}
	return leaseManager, leaseSigner, nil
}

func withRequestTrace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if next == nil || request == nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		trace, found := observability.TraceFromContext(request.Context())
		var err error
		if !found {
			trace, err = requestTrace(request)
		}
		if err != nil {
			trace, err = observability.NewRootTraceContext(false)
			if err != nil {
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		ctx, err := observability.ContextWithTrace(request.Context(), trace)
		if err != nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(response, request.WithContext(ctx))
	})
}

func requestTrace(request *http.Request) (observability.TraceContext, error) {
	traceparent := request.Header.Get(observability.TraceParentHeader)
	if traceparent == "" {
		return observability.NewRootTraceContext(false)
	}
	return observability.ParseTraceParent(traceparent, request.Header.Get(observability.TraceStateHeader))
}

func oidcAuthenticator(config runtimeconfig.Config) (authn.Authenticator, error) {
	allowHTTP := config.Environment == runtimeconfig.EnvironmentDevelopment || config.Environment == runtimeconfig.EnvironmentTest
	remoteVerifier, err := authn.NewRemoteJWKSVerifier(authn.RemoteJWKSConfig{
		Issuer: config.Identity.Issuer, JWKSURL: config.Identity.JWKSURL, AllowHTTP: allowHTTP,
	})
	if err != nil {
		return nil, err
	}
	var verifier authn.OIDCVerifier = remoteVerifier
	if len(config.Identity.ServiceSubjects) > 0 {
		mappings := make(map[string]string, len(config.Identity.ServiceSubjects))
		for _, mapping := range config.Identity.ServiceSubjects {
			mappings[mapping.Subject] = mapping.TenantID
		}
		verifier = &serviceSubjectClaimsVerifier{inner: verifier, tenantBySubject: mappings}
	}
	authenticator := authn.NewOIDCAuthenticator(verifier, []string{config.Identity.Issuer}, config.Identity.Audience)
	authenticator.ClockSkew = 30 * time.Second
	if config.Identity.DefaultTenantID != "" {
		return authn.NewDefaultClaimsAuthenticator(authenticator, config.Identity.DefaultTenantID, config.Identity.DefaultRole)
	}
	return authenticator, nil
}
