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
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/observability"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
)

type controlHandler struct {
	http.Handler
	dispatcher *eventing.OutboxDispatcher
	cancel     context.CancelFunc
	done       <-chan error
	close      sync.Once
	closeErr   error
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

func (handler *controlHandler) Ready() error {
	if handler == nil || handler.dispatcher == nil {
		return runtimeclient.ErrDependencyUnavailable
	}
	return handler.dispatcher.Ready()
}

func (handler *controlHandler) Close() error {
	if handler == nil {
		return nil
	}
	handler.close.Do(func() {
		if handler.cancel != nil {
			handler.cancel()
		}
		if handler.done != nil {
			err := <-handler.done
			if err != nil && !errors.Is(err, context.Canceled) {
				handler.closeErr = err
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
	knowledgeRepository, err := knowledge.NewFileRepository(config.KnowledgeRoot)
	if err != nil {
		return nil, err
	}
	knowledgeScopes, err := knowledge.NewEventingScopeResolver(store)
	if err != nil {
		return nil, err
	}
	knowledgeService, err := knowledge.NewService(knowledge.ServiceConfig{Repository: knowledgeRepository, Authorizer: authorizer, Scopes: knowledgeScopes, Clock: time.Now})
	if err != nil {
		return nil, err
	}
	leaseService, err := controlLeaseAuthority(config, clients.Database(), authorizer)
	if err != nil {
		return nil, err
	}
	domain, err := controlapi.New(controlapi.Config{
		Store: lifecycleStore, Authenticator: authenticator, Authorizer: authorizer,
		Database: clients.Database(), Artifacts: artifactCatalog, Knowledge: knowledgeService,
		Eraser: artifactProjectEraser{catalog: artifactCatalog}, Leases: leaseService, Clock: time.Now,
	})
	if err != nil {
		return nil, err
	}
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
	dispatchContext, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- dispatcher.Run(dispatchContext) }()
	return &controlHandler{Handler: withRequestTrace(domain), dispatcher: dispatcher, cancel: cancel, done: done}, nil
}

func controlLeaseAuthority(config runtimeconfig.Config, database *sql.DB, authorizer authz.LeaseGrantEvaluator) (*leaseauthority.Service, error) {
	if database == nil || authorizer == nil {
		return nil, runtimeclient.ErrInvalidClientConfig
	}
	resolveContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	leaseKey, err := credentials.NewSecretResolver(os.Getenv("AOR_SECRET_ROOT")).Resolve(resolveContext, config.LeaseSigningKeyRef)
	cancel()
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	leaseSigner, err := authz.NewHMACSigner(leaseKey)
	clearBytes(leaseKey)
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	leaseStore, err := authz.NewPostgresLeaseStore(database)
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
	}
	leaseManager, err := authz.NewLeaseManager(authz.LeaseManagerConfig{
		Store: leaseStore, Signer: leaseSigner, Clock: time.Now,
		DefaultTTL: 5 * time.Minute, MaxTTL: 15 * time.Minute, HeartbeatInterval: 30 * time.Second,
	})
	if err != nil {
		return nil, runtimeconfig.ErrInvalidConfiguration
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

func withRequestTrace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if next == nil || request == nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		trace, err := requestTrace(request)
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
