package servicebootstrap

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/controlapi"
	"github.com/akimisaka/aor/internal/eventing"
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
	if clients == nil || clients.Database() == nil || clients.JetStream() == nil || clients.Temporal() == nil {
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
	domain, err := controlapi.New(controlapi.Config{
		Store: lifecycleStore, Authenticator: authenticator, Authorizer: authorizer,
		Database: clients.Database(), Clock: time.Now,
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
	return &controlHandler{Handler: domain, dispatcher: dispatcher, cancel: cancel, done: done}, nil
}

func oidcAuthenticator(config runtimeconfig.Config) (authn.Authenticator, error) {
	allowHTTP := config.Environment == runtimeconfig.EnvironmentDevelopment || config.Environment == runtimeconfig.EnvironmentTest
	verifier, err := authn.NewRemoteJWKSVerifier(authn.RemoteJWKSConfig{
		Issuer: config.Identity.Issuer, JWKSURL: config.Identity.JWKSURL, AllowHTTP: allowHTTP,
	})
	if err != nil {
		return nil, err
	}
	authenticator := authn.NewOIDCAuthenticator(verifier, []string{config.Identity.Issuer}, config.Identity.Audience)
	authenticator.ClockSkew = 30 * time.Second
	if config.Identity.DefaultTenantID != "" {
		return authn.NewDefaultClaimsAuthenticator(authenticator, config.Identity.DefaultTenantID, config.Identity.DefaultRole)
	}
	return authenticator, nil
}
