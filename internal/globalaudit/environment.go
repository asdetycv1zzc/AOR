package globalaudit

import (
	"context"
	"errors"
	"time"

	"github.com/akimisaka/aor/internal/sandbox"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/contracts"
)

// EnvironmentSession identifies one clean, attested environment held for the
// lifetime of a GlobalAuditor model run. Its facts are copied from the
// provider's Create attestation; callers cannot substitute configuration
// values as evidence.
type EnvironmentSession struct {
	ID    string
	Facts EnvironmentFacts
}

// EnvironmentSource owns the lifecycle of the clean audit environment.
type EnvironmentSource interface {
	Acquire(context.Context, Request, state.Project, string) (EnvironmentSession, error)
	Release(context.Context, EnvironmentSession) error
}

type SandboxEnvironmentConfig struct {
	Provider          sandbox.SandboxProvider
	ImageDigest       string
	DeploymentProfile sandbox.DeploymentProfile
}

// SandboxEnvironment creates a fresh Linux Auditor container for each run.
// The provider remains the sole authority for the actual isolation and image
// attestation.
type SandboxEnvironment struct {
	provider          sandbox.SandboxProvider
	imageDigest       string
	deploymentProfile sandbox.DeploymentProfile
}

func NewSandboxEnvironment(config SandboxEnvironmentConfig) (*SandboxEnvironment, error) {
	if config.Provider == nil || !digestPattern.MatchString(config.ImageDigest) ||
		(config.DeploymentProfile != sandbox.ProfileLocal && config.DeploymentProfile != sandbox.ProfileProduction) {
		return nil, ErrRuntimeUnavailable
	}
	return &SandboxEnvironment{
		provider:          config.Provider,
		imageDigest:       config.ImageDigest,
		deploymentProfile: config.DeploymentProfile,
	}, nil
}

func (environment *SandboxEnvironment) Acquire(ctx context.Context, request Request, project state.Project, releaseCommit string) (EnvironmentSession, error) {
	if environment == nil || environment.provider == nil || ctx == nil || ctx.Err() != nil ||
		!uuidV7(request.RunID) || !canonicalUUID(request.TenantID) || !canonicalUUID(request.ProjectID) ||
		!validProject(project, request) || !commitPattern.MatchString(releaseCommit) {
		return EnvironmentSession{}, ErrInvalidRequest
	}
	sandboxID := stableGlobalAuditID("global-audit-sandbox-", request.TenantID, request.ProjectID, request.RunID, releaseCommit)
	spec := sandbox.SandboxSpec{
		SandboxID:                sandboxID,
		TenantID:                 request.TenantID,
		ProjectID:                request.ProjectID,
		TaskID:                   request.RunID,
		Role:                     sandbox.RoleAuditor,
		Platform:                 sandbox.PlatformLinux,
		IsolationLevel:           sandbox.IsolationContainer,
		ImageDigest:              environment.imageDigest,
		CPULimit:                 "1",
		MemoryBytes:              512 * 1024 * 1024,
		PIDsLimit:                128,
		DiskBytes:                1024 * 1024 * 1024,
		WallTimeSeconds:          1800,
		NetworkPolicy:            sandbox.NetworkPolicy{Mode: "DENY_ALL"},
		AllowedExecutables:       []string{},
		EnvironmentAllowlist:     []string{},
		WorkloadTrust:            sandbox.TrustUntrusted,
		DeploymentProfile:        environment.deploymentProfile,
		RequiresHiddenTests:      true,
		RequiresNetworkIsolation: true,
		HostileMultiTenant:       false,
	}
	if err := spec.Validate(); err != nil {
		return EnvironmentSession{}, ErrRuntimeUnavailable
	}
	handle, err := environment.provider.Create(ctx, spec)
	if err != nil {
		return EnvironmentSession{}, err
	}
	facts := EnvironmentFacts{
		ExecutionPlatform:  contracts.PlatformLinux,
		IsolationLevel:     contracts.IsolationContainer,
		SandboxImageDigest: handle.Attestation.ImageDigest,
	}
	if handle.ID != sandboxID || handle.Platform != sandbox.PlatformLinux || handle.IsolationLevel != sandbox.IsolationContainer ||
		handle.Attestation.ImageDigest != environment.imageDigest || !validEnvironmentFacts(facts) {
		cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		cleanupErr := environment.provider.Destroy(cleanupContext, handle.ID)
		cancel()
		if cleanupErr != nil {
			return EnvironmentSession{}, errors.Join(ErrRuntimeUnavailable, cleanupErr)
		}
		return EnvironmentSession{}, ErrRuntimeUnavailable
	}
	return EnvironmentSession{ID: handle.ID, Facts: facts}, nil
}

func (environment *SandboxEnvironment) Release(ctx context.Context, session EnvironmentSession) error {
	if environment == nil || environment.provider == nil || ctx == nil || ctx.Err() != nil ||
		!safeText(session.ID, 128) || !validEnvironmentFacts(session.Facts) {
		return ErrInvalidRequest
	}
	return environment.provider.Destroy(ctx, session.ID)
}

func validEnvironmentFacts(facts EnvironmentFacts) bool {
	return facts.ExecutionPlatform == contracts.PlatformLinux && facts.IsolationLevel == contracts.IsolationContainer &&
		digestPattern.MatchString(facts.SandboxImageDigest)
}

func validEnvironmentSession(session EnvironmentSession) bool {
	return safeText(session.ID, 128) && validEnvironmentFacts(session.Facts)
}

var _ EnvironmentSource = (*SandboxEnvironment)(nil)
