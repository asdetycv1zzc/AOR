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
	SandboxID                string            `json:"sandboxId"`
	TenantID                 string            `json:"tenantId"`
	ProjectID                string            `json:"projectId"`
	TaskID                   string            `json:"taskId"`
	Role                     Role              `json:"role"`
	Platform                 Platform          `json:"platform"`
	IsolationLevel           IsolationLevel    `json:"isolationLevel"`
	ImageDigest              string            `json:"imageDigest,omitempty"`
	CPULimit                 string            `json:"cpuLimit"`
	MemoryBytes              int64             `json:"memoryBytes"`
	PIDsLimit                int               `json:"pidsLimit"`
	DiskBytes                int64             `json:"diskBytes"`
	WallTimeSeconds          int               `json:"wallTimeSeconds"`
	NetworkPolicy            NetworkPolicy     `json:"networkPolicy"`
	Mounts                   []Mount           `json:"mounts,omitempty"`
	AllowedExecutables       []string          `json:"allowedExecutables"`
	EnvironmentAllowlist     []string          `json:"environmentAllowlist,omitempty"`
	WorkloadTrust            WorkloadTrust     `json:"workloadTrust"`
	DeploymentProfile        DeploymentProfile `json:"deploymentProfile"`
	RequiresHiddenTests      bool              `json:"requiresHiddenTests,omitempty"`
	RequiresNetworkIsolation bool              `json:"requiresNetworkIsolation,omitempty"`
	TrustedSingleTenant      bool              `json:"trustedSingleTenant,omitempty"`
	HostileMultiTenant       bool              `json:"hostileMultiTenant,omitempty"`
	RiskAcceptanceApprovalID string            `json:"riskAcceptanceApprovalId,omitempty"`
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
