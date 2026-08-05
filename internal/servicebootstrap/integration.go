package servicebootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/akimisaka/aor/internal/audit"
	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/goalplan"
	"github.com/akimisaka/aor/internal/integration"
	"github.com/akimisaka/aor/internal/leaseauthority"
	"github.com/akimisaka/aor/internal/policy"
	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

const integrationServicePrincipalID = "aor-integration-service"

type integrationActivity struct {
	store          *integration.PostgresStore
	authority      *integration.OrchestratorAuthority
	events         eventing.Store
	repositories   repository.ProjectRepositoryStore
	repositoryRoot string
	submissions    integration.RepositorySubmissionSource
	evidenceStore  audit.EvidenceStore
	evidence       integration.SignedEvidenceSource
	modules        integration.ArtifactModuleSource
	summaries      *integration.EventSummaryStore
	leases         *leaseauthority.Service
	leaseManager   *authz.LeaseManager
	policy         authz.PolicyEvaluator
	provider       sandbox.SandboxProvider
	imageDigest    string
	profile        sandbox.DeploymentProfile
	workRoot       string
	commands       []integration.CheckCommand
	principal      authn.Principal
}

type integrationSnapshot struct {
	repository repository.ProjectRepository
	candidates []integration.Candidate
	policy     string
}

func configuredIntegration(config runtimeconfig.Config, clients *runtimeclient.Clients, provider sandbox.SandboxProvider, services *workerExecutionServices, leaseManager *authz.LeaseManager, repositorySigner repository.Signer, evidenceSigner audit.Signer) (*integrationActivity, error) {
	if clients == nil || provider == nil || services == nil || services.leaseService == nil || services.artifactCatalog == nil || leaseManager == nil || repositorySigner == nil || evidenceSigner == nil {
		return nil, ErrWorkerConfiguration
	}
	if err := os.MkdirAll(config.Integration.WorkRoot, 0o700); err != nil {
		return nil, ErrWorkerConfiguration
	}
	policyClient, err := policy.NewOPAClient(config.OPA.URL)
	if err != nil {
		return nil, err
	}
	events := eventing.NewPostgresStore(clients.Database())
	principal := authn.Principal{ID: integrationServicePrincipalID, Type: authn.PrincipalService, Role: authn.RoleService}
	authority, err := integration.NewOrchestratorAuthority(events, policyClient, principal, time.Now)
	if err != nil {
		return nil, err
	}
	store, err := integration.NewPostgresStore(clients.Database())
	if err != nil {
		return nil, err
	}
	repositories, err := repository.NewPostgresRegistryStore(clients.Database())
	if err != nil {
		return nil, err
	}
	submissionStore, err := repository.NewPostgresSubmissionStore(clients.Database())
	if err != nil {
		return nil, err
	}
	artifacts, err := goalplan.NewEventArtifactStore(events, time.Now)
	if err != nil {
		return nil, err
	}
	evidenceStore, err := audit.NewArtifactEvidenceStore(services.artifactCatalog, services.artifactCatalog)
	if err != nil {
		return nil, err
	}
	summaries, err := integration.NewEventSummaryStore(events, time.Now)
	if err != nil {
		return nil, err
	}
	commands, err := configuredIntegrationChecks(config.Integration.Checks)
	if err != nil {
		return nil, err
	}
	profile := sandbox.ProfileLocal
	if config.DeploymentProfile == "PREPRODUCTION" || config.DeploymentProfile == "PRODUCTION" {
		profile = sandbox.ProfileProduction
	}
	return &integrationActivity{
		store: store, authority: authority, events: events, repositories: repositories,
		repositoryRoot: config.RepositoryRoot,
		submissions:    integration.RepositorySubmissionSource{Store: submissionStore, Signer: repositorySigner},
		evidenceStore:  evidenceStore,
		evidence:       integration.SignedEvidenceSource{Store: evidenceStore, Signer: evidenceSigner},
		modules:        integration.ArtifactModuleSource{Store: artifacts}, summaries: summaries,
		leases: services.leaseService, leaseManager: leaseManager, policy: policyClient,
		provider: provider, imageDigest: configuredImageDigest(config.Sandbox.ImageReference),
		profile: profile, workRoot: config.Integration.WorkRoot, commands: commands, principal: principal,
	}, nil
}

func configuredIntegrationChecks(configs []runtimeconfig.IntegrationCheckConfig) ([]integration.CheckCommand, error) {
	commands := make([]integration.CheckCommand, 0, len(configs))
	for _, configured := range configs {
		if len(configured.Argv) == 0 {
			return nil, ErrWorkerConfiguration
		}
		kind := integration.CheckKind(configured.Kind)
		switch kind {
		case integration.CheckCompile, integration.CheckContract, integration.CheckIntegration, integration.CheckE2E, integration.CheckMigration:
		default:
			return nil, ErrWorkerConfiguration
		}
		commands = append(commands, integration.CheckCommand{
			Kind: kind, Executable: configured.Argv[0], Arguments: append([]string(nil), configured.Argv[1:]...),
			Timeout: time.Duration(configured.TimeoutSeconds) * time.Second,
		})
	}
	return commands, nil
}

func (activity *integrationActivity) Run(ctx context.Context, tenantID, projectID, integrationID string) (result integration.WorkflowResult, resultErr error) {
	parsedID, parseErr := uuid.Parse(integrationID)
	principal, principalFound := authn.PrincipalFromContext(ctx)
	if activity == nil || activity.store == nil || activity.authority == nil || activity.repositories == nil || activity.leases == nil || activity.leaseManager == nil || activity.policy == nil || activity.provider == nil || ctx == nil || ctx.Err() != nil || parseErr != nil || parsedID == uuid.Nil || parsedID.String() != integrationID || tenantID == "" || projectID == "" || !principalFound || principal.ID != integrationServicePrincipalID || principal.Type != authn.PrincipalService || principal.Role != authn.RoleService || principal.TenantID != tenantID || principal.ProjectID != projectID {
		return integration.WorkflowResult{}, ErrWorkerUnavailable
	}
	var lease authz.CapabilityLease
	leaseIssued := false
	defer func() {
		if !leaseIssued {
			return
		}
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		revokeErr := activity.leases.Revoke(cleanupContext, principal, leaseauthority.RevokeRequest{
			TenantID: tenantID, ProjectID: projectID, LeaseID: lease.ID,
			Reason: "integration activity complete", IdempotencyKey: "integration-revoke:" + integrationID,
		})
		cancel()
		if revokeErr != nil {
			resultErr = errors.Join(resultErr, revokeErr)
		}
	}()
	durable, found, err := activity.store.Request(ctx, tenantID, integrationID)
	if err != nil || !found || durable.ProjectID != projectID {
		if err != nil {
			return integration.WorkflowResult{}, err
		}
		return integration.WorkflowResult{}, integration.ErrInvalidRequest
	}
	project, found, err := activity.authority.Project(ctx, tenantID, projectID)
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	if !found {
		return integration.WorkflowResult{}, integration.ErrInvalidRequest
	}
	snapshot, err := activity.snapshot(ctx, tenantID, projectID)
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	if project.State == contracts.ProjectExecuting {
		evidenceSHA256, digestErr := integrationStartEvidence(integrationID, project.Version, snapshot)
		if digestErr != nil {
			return integration.WorkflowResult{}, digestErr
		}
		project, _, err = activity.authority.BeginIntegration(ctx, integrationID, tenantID, projectID, project.Version, snapshot.policy, evidenceSHA256)
		if err != nil {
			return integration.WorkflowResult{}, err
		}
		snapshot, err = activity.snapshot(ctx, tenantID, projectID)
		if err != nil {
			return integration.WorkflowResult{}, err
		}
	}
	if project.State != contracts.ProjectIntegrating {
		return integration.WorkflowResult{}, integration.ErrModulesNotReady
	}

	ownerTaskID, attempt, err := activity.attemptBinding(ctx, tenantID, integrationID)
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	authorizationRequest := integration.AuthorizationRequest{
		TenantID: tenantID, ProjectID: projectID, IntegrationID: integrationID,
		PrincipalID: principal.ID, PolicyDigest: snapshot.policy, ExpectedVersion: project.Version,
		BaseCommit: snapshot.repository.BaselineCommit, Candidates: append([]integration.Candidate(nil), snapshot.candidates...),
		OwnerTaskID: ownerTaskID, Attempt: attempt,
	}
	parameterDigest, err := integration.AuthorizationParameterDigest(authorizationRequest)
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	leaseKey, err := uuid.NewV7()
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	lease, err = activity.leases.Issue(ctx, principal, leaseauthority.GrantRequest{
		TenantID: tenantID, ProjectID: projectID, Action: authz.ActionIntegrationMerge,
		Resource: integration.IntegrationResource(integrationID), ParameterDigest: parameterDigest,
		BudgetAccountID: projectID, IdempotencyKey: "integration-merge-" + leaseKey.String(), TTL: 30 * time.Minute,
	})
	if err != nil || lease.PolicyVersion != snapshot.policy {
		if err != nil {
			return integration.WorkflowResult{}, err
		}
		return integration.WorkflowResult{}, integration.ErrNotAudited
	}
	leaseIssued = true
	authorizationRequest.LeaseID = lease.ID
	authorizationRequest.FencingToken = lease.FencingToken
	authorizer, err := integration.NewLeaseAuthorizer(activity.leaseManager, activity.policy, activity.authority, time.Now)
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	projectFacts := integrationActivityProjectFacts{
		store: activity.store, authority: activity.authority, repositories: activity.repositories,
		repositoryRoot: activity.repositoryRoot, policyDigest: snapshot.policy,
	}
	gate, err := integration.NewAuthoritativeGate(
		projectFacts, integration.EventTaskSource{Store: activity.events}, activity.submissions,
		activity.evidence, activity.modules, authorizer,
	)
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	merger, err := integration.NewGitMerger(snapshot.repository.Path)
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	commands := activity.boundCommands(snapshot.candidates, ownerTaskID)
	verifier, err := integration.NewSandboxVerifier(integration.SandboxVerifierConfig{
		RepositoryPath: snapshot.repository.Path, WorkRoot: activity.workRoot, Provider: activity.provider,
		ImageDigest: activity.imageDigest, DeploymentProfile: activity.profile, Commands: commands, Clock: time.Now,
	})
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	queue, err := integration.NewVerifiedQueue(activity.store, merger, gate, time.Now)
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	workflow, err := integration.NewWorkflow(integration.WorkflowConfig{
		Queue: queue, Tasks: activity.authority, Checks: verifier, Summaries: activity.summaries, Clock: time.Now,
	})
	if err != nil {
		return integration.WorkflowResult{}, err
	}
	result, err = workflow.Run(ctx, integration.Request{
		TenantID: tenantID, ProjectID: projectID, IntegrationID: integrationID,
		IdempotencyKey: "integration:" + integrationID, BaseCommit: snapshot.repository.BaselineCommit,
		Candidates: append([]integration.Candidate(nil), snapshot.candidates...), PolicyDigest: snapshot.policy,
		ExpectedVersion: project.Version, CreatedAt: durable.CreatedAt, PrincipalID: principal.ID,
		LeaseID: lease.ID, FencingToken: lease.FencingToken, OwnerTaskID: ownerTaskID, Attempt: attempt,
	})
	if err != nil {
		return result, err
	}
	if result.Summary.State != integration.SummaryReleaseCandidate || !result.Merge.Audit.Passed || result.Merge.Pending {
		return result, integration.ErrChecksFailed
	}
	if err := activity.integrateTasks(ctx, integrationID, tenantID, projectID, snapshot.policy, result.Summary.SummarySHA256); err != nil {
		return result, err
	}
	project, found, err = activity.authority.Project(ctx, tenantID, projectID)
	if err != nil {
		return result, err
	}
	if !found {
		return result, integration.ErrInvalidRequest
	}
	_, _, err = activity.authority.BeginGlobalAudit(ctx, integrationID, tenantID, projectID, project.Version, snapshot.policy, result.Summary.SummarySHA256)
	return result, err
}

func (activity *integrationActivity) snapshot(ctx context.Context, tenantID, projectID string) (integrationSnapshot, error) {
	repositoryRecord, found, err := activity.repositories.LoadProjectRepository(ctx, tenantID, projectID)
	if err != nil || !found {
		if err != nil {
			return integrationSnapshot{}, err
		}
		return integrationSnapshot{}, integration.ErrInvalidRequest
	}
	expectedPath, err := repository.ProjectRepositoryPath(activity.repositoryRoot, tenantID, projectID)
	if err != nil || repositoryRecord.Path != expectedPath {
		return integrationSnapshot{}, integration.ErrInvalidRequest
	}
	tasks, err := activity.authority.Tasks(ctx, tenantID, projectID)
	if err != nil || len(tasks) == 0 {
		return integrationSnapshot{}, integration.ErrModulesNotReady
	}
	candidates := make([]integration.Candidate, 0, len(tasks))
	policyDigest := ""
	for _, task := range tasks {
		switch task.State {
		case contracts.TaskCanceled, contracts.TaskSuperseded:
			continue
		case contracts.TaskPassed, contracts.TaskIntegrated:
		default:
			return integrationSnapshot{}, integration.ErrModulesNotReady
		}
		submission, err := activity.submissions.Current(ctx, task)
		if err != nil {
			return integrationSnapshot{}, err
		}
		bundle, found, err := activity.evidenceStore.Get(ctx, tenantID, projectID, task.ID, task.AttemptSeriesID, task.Attempt)
		if err != nil || !found {
			if err != nil {
				return integrationSnapshot{}, err
			}
			return integrationSnapshot{}, integration.ErrNotAudited
		}
		record, err := activity.evidence.Verified(ctx, task, submission, bundle.ManifestSHA256)
		if err != nil || !record.Passed {
			return integrationSnapshot{}, integration.ErrNotAudited
		}
		if policyDigest == "" {
			policyDigest = record.PolicyDigest
		}
		if record.PolicyDigest != policyDigest {
			return integrationSnapshot{}, integration.ErrNotAudited
		}
		module, err := activity.modules.Current(ctx, tenantID, projectID, task.ModuleID, task.ModuleSpecRef)
		if err != nil {
			return integrationSnapshot{}, err
		}
		candidates = append(candidates, integration.Candidate{
			TaskID: task.ID, ModuleID: task.ModuleID, SubmissionCommit: submission.Manifest.HeadCommit,
			ModuleSpecRef: task.ModuleSpecRef, OwnedPaths: append([]string(nil), module.OwnedPaths...),
			PublicInterfaces: append([]string(nil), module.PublicInterfaces...), EvidenceSHA256: record.SHA256, AuditPassed: true,
		})
	}
	if len(candidates) == 0 || policyDigest == "" {
		return integrationSnapshot{}, integration.ErrModulesNotReady
	}
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].TaskID < candidates[right].TaskID })
	return integrationSnapshot{repository: repositoryRecord, candidates: candidates, policy: policyDigest}, nil
}

func (activity *integrationActivity) attemptBinding(ctx context.Context, tenantID, integrationID string) (string, int, error) {
	task, found, err := activity.store.GetTask(ctx, tenantID, integrationID)
	if err != nil || !found {
		return "", 0, err
	}
	switch task.State {
	case integration.TaskReworkRequired:
		if task.Attempt >= 3 {
			return task.OwnerTaskID, task.Attempt, integration.ErrAttemptsExhausted
		}
		return task.OwnerTaskID, task.Attempt + 1, nil
	case integration.TaskExecuting, integration.TaskMergeReserved, integration.TaskBlockedUserDecision:
		return task.OwnerTaskID, task.Attempt, nil
	case integration.TaskDone:
		if task.Attempt == 0 {
			return "", 0, nil
		}
		return task.OwnerTaskID, task.Attempt, nil
	default:
		return "", 0, integration.ErrAttemptState
	}
}

func (activity *integrationActivity) boundCommands(candidates []integration.Candidate, ownerTaskID string) []integration.CheckCommand {
	taskIDs := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		taskIDs = append(taskIDs, candidate.TaskID)
	}
	commands := make([]integration.CheckCommand, len(activity.commands))
	for index, command := range activity.commands {
		command.Arguments = append([]string(nil), command.Arguments...)
		command.Environment = append([]string(nil), command.Environment...)
		command.Tasks = append([]string(nil), taskIDs...)
		command.OwnerTaskID = ownerTaskID
		commands[index] = command
	}
	return commands
}

func (activity *integrationActivity) integrateTasks(ctx context.Context, integrationID, tenantID, projectID, policyDigest, evidenceSHA256 string) error {
	for {
		tasks, err := activity.authority.Tasks(ctx, tenantID, projectID)
		if err != nil {
			return err
		}
		passed := make([]state.ModuleTask, 0, len(tasks))
		for _, task := range tasks {
			if task.State == contracts.TaskPassed {
				passed = append(passed, task)
			}
		}
		if len(passed) == 0 {
			return nil
		}
		sort.Slice(passed, func(left, right int) bool { return passed[left].ID < passed[right].ID })
		progressed := false
		for _, task := range passed {
			_, _, err := activity.authority.IntegrateTask(ctx, integrationID, tenantID, projectID, task.ID, task.Version, policyDigest, evidenceSHA256)
			if errors.Is(err, integration.ErrModulesNotReady) {
				continue
			}
			if err != nil {
				return err
			}
			progressed = true
		}
		if !progressed {
			return integration.ErrModulesNotReady
		}
	}
}

func integrationStartEvidence(integrationID string, projectVersion int64, snapshot integrationSnapshot) (string, error) {
	encoded, err := json.Marshal(struct {
		IntegrationID  string                  `json:"integrationId"`
		ProjectVersion int64                   `json:"projectVersion"`
		BaseCommit     string                  `json:"baseCommit"`
		PolicyDigest   string                  `json:"policyDigest"`
		Candidates     []integration.Candidate `json:"candidates"`
	}{integrationID, projectVersion, snapshot.repository.BaselineCommit, snapshot.policy, snapshot.candidates})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

type integrationActivityProjectFacts struct {
	store          *integration.PostgresStore
	authority      *integration.OrchestratorAuthority
	repositories   repository.ProjectRepositoryStore
	repositoryRoot string
	policyDigest   string
}

func (source integrationActivityProjectFacts) Current(ctx context.Context, tenantID, projectID, integrationID string) (integration.ProjectFacts, error) {
	request, found, err := source.store.Request(ctx, tenantID, integrationID)
	if err != nil || !found || request.ProjectID != projectID {
		return integration.ProjectFacts{}, integration.ErrNotAudited
	}
	project, found, err := source.authority.Project(ctx, tenantID, projectID)
	if err != nil || !found || project.State != contracts.ProjectIntegrating {
		return integration.ProjectFacts{}, integration.ErrNotAudited
	}
	repositoryRecord, found, err := source.repositories.LoadProjectRepository(ctx, tenantID, projectID)
	if err != nil || !found {
		return integration.ProjectFacts{}, integration.ErrNotAudited
	}
	expectedPath, err := repository.ProjectRepositoryPath(source.repositoryRoot, tenantID, projectID)
	if err != nil || repositoryRecord.Path != expectedPath {
		return integration.ProjectFacts{}, integration.ErrNotAudited
	}
	return integration.ProjectFacts{
		TenantID: tenantID, ProjectID: projectID, IntegrationID: integrationID,
		BaseCommit: repositoryRecord.BaselineCommit, PolicyDigest: source.policyDigest, StateVersion: project.Version,
	}, nil
}

var _ integration.ProjectFactsSource = integrationActivityProjectFacts{}
