package servicebootstrap

import (
	"net/http"
	"time"

	"github.com/akimisaka/aor/internal/controlapi"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/knowledge"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	aorworkflow "github.com/akimisaka/aor/internal/workflow"
)

// KnowledgeCuratorAPI constructs the writer-only process. It deliberately
// does not start control-plane schedulers, outbox dispatch, or retention work.
func KnowledgeCuratorAPI(config runtimeconfig.Config, clients *runtimeclient.Clients) (http.Handler, error) {
	if clients == nil || clients.Database() == nil || clients.Temporal() == nil {
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
	repository, err := knowledge.NewFileRepository(config.KnowledgeRoot)
	if err != nil {
		return nil, err
	}
	scopes, err := knowledge.NewEventingScopeResolver(store)
	if err != nil {
		return nil, err
	}
	updates, err := controlKnowledgeUpdatedPublisher(config, store)
	if err != nil {
		return nil, err
	}
	service, err := knowledge.NewService(knowledge.ServiceConfig{
		Repository: repository, Authorizer: authorizer, Scopes: scopes, Events: updates, Clock: time.Now,
	})
	if err != nil {
		return nil, err
	}
	leases, err := controlLeaseAuthority(config, clients.Database(), authorizer)
	if err != nil {
		return nil, err
	}
	agents, err := configuredGoalPlanServices(config, lifecycleStore, leases, authorizer, service, updates)
	if err != nil {
		return nil, err
	}
	domain, err := controlapi.NewKnowledgeCuratorHandler(controlapi.Config{
		Store: store, Authenticator: authenticator, Authorizer: authorizer,
		Knowledge: service, KnowledgeCurator: agents.curator, Clock: time.Now,
	})
	if err != nil {
		return nil, err
	}
	return withRequestTrace(domain), nil
}
