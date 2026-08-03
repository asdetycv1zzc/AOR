package sandbox

import (
	"context"
	"time"
)

type Platform string
type IsolationLevel string
type Role string
type WorkloadTrust string
type DeploymentProfile string

const (
	PlatformLinux      Platform          = "LINUX"
	PlatformWindows    Platform          = "WINDOWS"
	IsolationContainer IsolationLevel    = "CONTAINER"
	IsolationNone      IsolationLevel    = "NONE"
	RoleExecutor       Role              = "EXECUTOR"
	RoleAuditor        Role              = "AUDITOR"
	TrustTrusted       WorkloadTrust     = "TRUSTED"
	TrustUntrusted     WorkloadTrust     = "UNTRUSTED"
	ProfileLocal       DeploymentProfile = "LOCAL"
	ProfileProduction  DeploymentProfile = "PRODUCTION"
)

type NetworkPolicy struct {
	Mode         string   `json:"mode"`
	Destinations []string `json:"destinations"`
}

type Mount struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Mode   string `json:"mode"`
}

type SandboxSpec struct {
	SandboxID                string
	TenantID                 string
	ProjectID                string
	TaskID                   string
	Role                     Role
	Platform                 Platform
	IsolationLevel           IsolationLevel
	ImageDigest              string
	CPULimit                 string
	MemoryBytes              int64
	PIDsLimit                int
	DiskBytes                int64
	WallTimeSeconds          int
	NetworkPolicy            NetworkPolicy
	Mounts                   []Mount
	AllowedExecutables       []string
	EnvironmentAllowlist     []string
	WorkloadTrust            WorkloadTrust
	DeploymentProfile        DeploymentProfile
	RequiresHiddenTests      bool
	RequiresNetworkIsolation bool
	TrustedSingleTenant      bool
	HostileMultiTenant       bool
	RiskAcceptanceApprovalID string
}

type SandboxHandle struct {
	ID             string
	Platform       Platform
	IsolationLevel IsolationLevel
	Attestation    Attestation
	CreatedAt      time.Time
}

type Attestation struct {
	SecurityProfileSHA256 string
	ImageDigest           string
	Runtime               string
	NonRoot               bool
	UserNamespace         bool
	Rootless              bool
	ReadOnlyRootFS        bool
	CapabilitiesDropped   bool
	SeccompEnabled        bool
	MandatoryPolicy       bool
	CgroupsV2             bool
	Tmpfs                 bool
	WorkdirReadWrite      bool
	HostDevices           bool
	HostPID               bool
	HostNetwork           bool
	Privileged            bool
	RuntimeSocket         bool
	RiskDisclosure        string
}

type ExecRequest struct {
	Executable string
	Arguments  []string
	WorkingDir string
	Timeout    time.Duration
}

type ExecResult struct {
	ExitCode   int
	Stdout     []byte
	Stderr     []byte
	StartedAt  time.Time
	FinishedAt time.Time
}

type ArtifactRef struct {
	Path   string
	URI    string
	SHA256 string
	Size   int64
}

type SnapshotRef struct {
	URI            string
	SHA256         string
	IsolationLevel IsolationLevel
	Attestation    Attestation
}

type SandboxProvider interface {
	Create(ctx context.Context, spec SandboxSpec) (SandboxHandle, error)
	Exec(ctx context.Context, id string, req ExecRequest) (ExecResult, error)
	Export(ctx context.Context, id string, paths []string) ([]ArtifactRef, error)
	Snapshot(ctx context.Context, id string) (SnapshotRef, error)
	Terminate(ctx context.Context, id string, reason string) error
	Destroy(ctx context.Context, id string) error
}

type Backend interface {
	Create(ctx context.Context, spec SandboxSpec) (Attestation, error)
	Exec(ctx context.Context, id string, req ExecRequest) (ExecResult, error)
	Export(ctx context.Context, id string, paths []string) ([]ArtifactRef, error)
	Snapshot(ctx context.Context, id string) (SnapshotRef, error)
	Terminate(ctx context.Context, id string, reason string) error
	Destroy(ctx context.Context, id string) error
}

type LinuxProviderOptions struct {
	RuntimeName       string
	AllowedMountRoots []string
}
