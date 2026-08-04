package servicebootstrap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/repository"
	"github.com/akimisaka/aor/internal/toolbroker"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/akimisaka/aor/pkg/mcp"
)

const (
	repositoryMCPServerID = "aor-repository"
	repositoryMCPVersion  = "1.0.0"
	repositoryReadTool    = "repository.file.read"
)

type repositoryExecutionAuthority struct {
	database *sql.DB
	leases   toolbroker.LeaseChecker
	root     string
	clock    func() time.Time
}

type repositoryExecutionScope struct {
	module   contracts.ModuleSpec
	provider string
	model    string
}

type repositoryMCPClient struct {
	service   *repository.Service
	authority *repositoryExecutionAuthority
}

type repositoryCreateArguments struct {
	AttemptSeriesID string `json:"attemptSeriesId"`
	Attempt         int    `json:"attempt"`
}

type repositoryWriteArguments struct {
	WorkspaceID   string `json:"workspaceId"`
	Path          string `json:"path"`
	ContentBase64 string `json:"contentBase64"`
}

type repositoryPathArguments struct {
	WorkspaceID string `json:"workspaceId"`
	Path        string `json:"path"`
}

type repositorySubmitArguments struct {
	WorkspaceID           string   `json:"workspaceId"`
	Attempt               int      `json:"attempt"`
	ClaimedCriteria       []string `json:"claimedCriteria"`
	LocalTestEvidenceRefs []string `json:"localTestEvidenceRefs"`
}

func deriveRepositorySigningKey(leaseKey []byte) []byte {
	mac := hmac.New(sha256.New, leaseKey)
	_, _ = mac.Write([]byte("aor/repository/submission-signing/v1"))
	return mac.Sum(nil)
}

func newRepositoryMCPClient(root string, database *sql.DB, leases toolbroker.LeaseChecker, signer repository.Signer, clock func() time.Time) (*repositoryMCPClient, error) {
	if database == nil || leases == nil || signer == nil || root == "" {
		return nil, repository.ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	store, err := repository.NewPostgresSubmissionStore(database)
	if err != nil {
		return nil, err
	}
	registry, err := repository.NewPostgresRegistryStore(database)
	if err != nil {
		return nil, err
	}
	authority := &repositoryExecutionAuthority{database: database, leases: leases, root: root, clock: clock}
	service, err := repository.NewServiceWithConfig(repository.ServiceConfig{
		Root: root, Leases: authority, Submissions: store, Workspaces: registry,
		ProjectRepositories: registry, Signer: signer, Clock: clock,
	})
	if err != nil {
		return nil, err
	}
	return &repositoryMCPClient{service: service, authority: authority}, nil
}

func (client *repositoryMCPClient) Initialize(ctx context.Context) (mcp.InitializeResponse, error) {
	if client == nil || client.service == nil || client.authority == nil || ctx == nil {
		return mcp.InitializeResponse{}, repository.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return mcp.InitializeResponse{}, err
	}
	return mcp.InitializeResponse{
		ProtocolVersion: mcp.BaselineProtocolVersion,
		Capabilities:    map[string]any{"tools": map[string]any{"listChanged": false}},
		ServerInfo:      mcp.Implementation{Name: repositoryMCPServerID, Version: repositoryMCPVersion, Description: "AOR repository service"},
	}, nil
}

func (client *repositoryMCPClient) ListTools(ctx context.Context, cursor string) (mcp.ToolListResult, error) {
	if client == nil || client.service == nil || client.authority == nil || ctx == nil || cursor != "" {
		return mcp.ToolListResult{}, repository.ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return mcp.ToolListResult{}, err
	}
	return mcp.ToolListResult{Tools: repositoryMCPTools()}, nil
}

func (client *repositoryMCPClient) CallTool(ctx context.Context, name string, arguments map[string]any) (mcp.ToolCallResult, error) {
	if client == nil || client.service == nil || client.authority == nil || ctx == nil {
		return mcp.ToolCallResult{}, repository.ErrInvalidRequest
	}
	switch name {
	case string(repository.LeaseActionCreateWorkspace):
		var input repositoryCreateArguments
		if err := decodeRepositoryArguments(arguments, &input); err != nil {
			return mcp.ToolCallResult{}, err
		}
		request, err := client.authority.workspaceRequest(ctx, input)
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		request.BaseCommit, err = client.service.ResolveWorkspaceBaseCommit(ctx, request.TenantID, request.ProjectID, request.TaskID, request.AttemptSeriesID, request.Attempt)
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		workspace, err := client.service.CreateWorkspace(ctx, request)
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		return repositoryToolResult(map[string]any{
			"workspaceId":   workspace.ID,
			"branch":        workspace.Branch,
			"baseCommit":    workspace.BaseCommit,
			"moduleSpecRef": workspace.ModuleSpecRef,
		}), nil
	case string(repository.LeaseActionWriteFile):
		var input repositoryWriteArguments
		if err := decodeRepositoryArguments(arguments, &input); err != nil {
			return mcp.ToolCallResult{}, err
		}
		content, err := base64.StdEncoding.DecodeString(input.ContentBase64)
		if err != nil || len(content) > 4<<20 {
			return mcp.ToolCallResult{}, repository.ErrInvalidRequest
		}
		proof, err := client.authority.proof(ctx, name)
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		if err := client.service.WriteFile(ctx, repository.WriteRequest{WorkspaceID: input.WorkspaceID, Path: input.Path, Content: content, Lease: proof}); err != nil {
			return mcp.ToolCallResult{}, err
		}
		return repositoryToolResult(map[string]any{"ok": true}), nil
	case string(repository.LeaseActionDeleteFile):
		var input repositoryPathArguments
		if err := decodeRepositoryArguments(arguments, &input); err != nil {
			return mcp.ToolCallResult{}, err
		}
		proof, err := client.authority.proof(ctx, name)
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		if err := client.service.DeleteFile(ctx, repository.DeleteRequest{WorkspaceID: input.WorkspaceID, Path: input.Path, Lease: proof}); err != nil {
			return mcp.ToolCallResult{}, err
		}
		return repositoryToolResult(map[string]any{"ok": true}), nil
	case repositoryReadTool:
		var input repositoryPathArguments
		if err := decodeRepositoryArguments(arguments, &input); err != nil {
			return mcp.ToolCallResult{}, err
		}
		workspace, found, err := client.service.WorkspaceContext(ctx, input.WorkspaceID)
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		if !found {
			return mcp.ToolCallResult{}, repository.ErrWorkspaceNotFound
		}
		if err := client.authority.validateRead(ctx, workspace); err != nil {
			return mcp.ToolCallResult{}, err
		}
		content, err := client.service.ReadFile(ctx, input.WorkspaceID, input.Path)
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		return repositoryToolResult(map[string]any{
			"workspaceId":   input.WorkspaceID,
			"path":          input.Path,
			"contentBase64": base64.StdEncoding.EncodeToString(content),
			"sha256":        repository.DigestBytes(content),
			"size":          len(content),
		}), nil
	case string(repository.LeaseActionSubmit):
		var input repositorySubmitArguments
		if err := decodeRepositoryArguments(arguments, &input); err != nil {
			return mcp.ToolCallResult{}, err
		}
		proof, err := client.authority.proof(ctx, name)
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		requestID, ok := toolbroker.InvocationRequestIDFromContext(ctx)
		if !ok || strings.TrimSpace(requestID) == "" {
			return mcp.ToolCallResult{}, repository.ErrInvalidRequest
		}
		submission, err := client.service.Submit(ctx, repository.SubmissionRequest{
			WorkspaceID:           input.WorkspaceID,
			Attempt:               input.Attempt,
			ClaimedCriteria:       append([]string(nil), input.ClaimedCriteria...),
			LocalTestEvidenceRefs: append([]string(nil), input.LocalTestEvidenceRefs...),
			Lease:                 proof,
			IdempotencyKey:        requestID,
		})
		if err != nil {
			return mcp.ToolCallResult{}, err
		}
		encoded, err := json.Marshal(submission.Manifest)
		if err != nil {
			return mcp.ToolCallResult{}, repository.ErrInvalidRequest
		}
		var manifest map[string]any
		if json.Unmarshal(encoded, &manifest) != nil {
			return mcp.ToolCallResult{}, repository.ErrInvalidRequest
		}
		return repositoryToolResult(map[string]any{"manifest": manifest}), nil
	default:
		return mcp.ToolCallResult{}, toolbroker.ErrUnknownTool
	}
}

func (client *repositoryMCPClient) Close() error { return nil }

func (authority *repositoryExecutionAuthority) workspaceRequest(ctx context.Context, input repositoryCreateArguments) (repository.WorkspaceRequest, error) {
	claim, proof, err := authority.claim(ctx, string(repository.LeaseActionCreateWorkspace))
	if err != nil {
		return repository.WorkspaceRequest{}, err
	}
	scope, err := authority.loadScope(ctx, claim, input.AttemptSeriesID, input.Attempt)
	if err != nil {
		return repository.WorkspaceRequest{}, err
	}
	repositoryPath, err := repository.ProjectRepositoryPath(authority.root, claim.TenantID, claim.ProjectID)
	if err != nil {
		return repository.WorkspaceRequest{}, err
	}
	return repository.WorkspaceRequest{
		RepositoryPath:  repositoryPath,
		TenantID:        claim.TenantID,
		ProjectID:       claim.ProjectID,
		TaskID:          claim.TaskID,
		Attempt:         input.Attempt,
		AttemptSeriesID: input.AttemptSeriesID,
		ModuleSpec:      scope.module,
		AgentIdentity: contracts.AgentIdentity{
			AgentInstanceID: claim.Principal.ID,
			Role:            claim.Principal.Role,
			Provider:        scope.provider,
			Model:           scope.model,
			LeaseID:         claim.Lease.ID,
		},
		Lease: proof,
	}, nil
}

func (authority *repositoryExecutionAuthority) proof(ctx context.Context, toolID string) (repository.LeaseProof, error) {
	_, proof, err := authority.claim(ctx, toolID)
	return proof, err
}

func (authority *repositoryExecutionAuthority) claim(ctx context.Context, toolID string) (toolbroker.LeaseValidation, repository.LeaseProof, error) {
	if authority == nil || authority.database == nil || authority.leases == nil || authority.clock == nil || ctx == nil {
		return toolbroker.LeaseValidation{}, repository.LeaseProof{}, repository.ErrLeaseStale
	}
	claim, ok := toolbroker.ExecutionAuthorizationFromContext(ctx)
	if !ok || claim.MCPServerID != repositoryMCPServerID || claim.ToolVersion != repositoryMCPVersion || claim.ToolID != toolID || claim.Principal.Type != "AGENT_INSTANCE" || claim.Principal.Role != "EXECUTOR" || claim.Principal.ID == "" {
		return toolbroker.LeaseValidation{}, repository.LeaseProof{}, repository.ErrLeaseStale
	}
	expiresAt, err := time.Parse(time.RFC3339, claim.Lease.ExpiresAt)
	now := authority.clock().UTC()
	if err != nil || claim.Lease.ID == "" || claim.Lease.FencingToken < 1 || !now.Before(expiresAt) {
		return toolbroker.LeaseValidation{}, repository.LeaseProof{}, repository.ErrLeaseStale
	}
	claim.At = now
	if err := authority.leases.Validate(ctx, claim); err != nil {
		return toolbroker.LeaseValidation{}, repository.LeaseProof{}, repository.ErrLeaseStale
	}
	return claim, repository.LeaseProof{ID: claim.Lease.ID, FencingToken: claim.Lease.FencingToken, ExpiresAt: expiresAt.UTC()}, nil
}

func (authority *repositoryExecutionAuthority) Validate(ctx context.Context, validation repository.LeaseValidation) error {
	claim, proof, err := authority.claim(ctx, string(validation.Action))
	if err != nil {
		return err
	}
	if validation.Proof.ID != proof.ID || validation.Proof.FencingToken != proof.FencingToken || !validation.Proof.ExpiresAt.Equal(proof.ExpiresAt) || validation.TenantID != claim.TenantID || validation.ProjectID != claim.ProjectID || validation.TaskID != claim.TaskID || validation.AgentInstanceID != claim.Principal.ID || validation.Role != claim.Principal.Role {
		return repository.ErrLeaseStale
	}
	scope, err := authority.loadScope(ctx, claim, validation.AttemptSeriesID, validation.Attempt)
	if err != nil || scope.module.ModuleSpecVersion != validation.ModuleSpecRef.Version || scope.module.SHA256 != validation.ModuleSpecRef.SHA256 {
		return repository.ErrLeaseStale
	}
	return nil
}

func (authority *repositoryExecutionAuthority) validateRead(ctx context.Context, workspace repository.Workspace) error {
	claim, _, err := authority.claim(ctx, repositoryReadTool)
	if err != nil {
		return err
	}
	if workspace.TenantID != claim.TenantID || workspace.ProjectID != claim.ProjectID || workspace.TaskID != claim.TaskID || workspace.AgentIdentity.AgentInstanceID != claim.Principal.ID || workspace.AgentIdentity.LeaseID != claim.Lease.ID {
		return repository.ErrLeaseStale
	}
	scope, err := authority.loadScope(ctx, claim, workspace.AttemptSeriesID, workspace.Attempt)
	if err != nil || scope.module.ModuleSpecVersion != workspace.ModuleSpecRef.Version || scope.module.SHA256 != workspace.ModuleSpecRef.SHA256 {
		return repository.ErrLeaseStale
	}
	return nil
}

func (authority *repositoryExecutionAuthority) loadScope(ctx context.Context, claim toolbroker.LeaseValidation, attemptSeriesID string, attempt int) (repositoryExecutionScope, error) {
	if attemptSeriesID == "" || attempt < 1 || attempt > 3 {
		return repositoryExecutionScope{}, repository.ErrLeaseStale
	}
	tx, err := authority.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return repositoryExecutionScope{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var superuser, bypassRLS bool
	if err := tx.QueryRowContext(ctx, `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil || superuser || bypassRLS {
		return repositoryExecutionScope{}, repository.ErrLeaseStale
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, claim.TenantID); err != nil {
		return repositoryExecutionScope{}, err
	}
	var projectState, taskState, activeSeriesID, agentRole, agentState string
	var attemptCount, moduleVersion int
	var latestFencing int64
	var moduleDigest, provider, model string
	var moduleJSON []byte
	err = tx.QueryRowContext(ctx, `
SELECT p.state, t.state, t.active_attempt_series_id::text, t.attempt_count,
       t.latest_fencing_token, ms.version, ms.content_sha256, ms.content_jsonb,
       ai.role, ai.provider, ai.logical_model, ai.state
FROM projects p
JOIN module_tasks t ON t.tenant_id = p.tenant_id AND t.project_id = p.id
JOIN module_specs ms ON ms.tenant_id = t.tenant_id AND ms.id = t.module_spec_id
JOIN attempt_series ats ON ats.tenant_id = t.tenant_id
  AND ats.id = t.active_attempt_series_id AND ats.module_task_id = t.id
  AND ats.module_spec_id = ms.id AND ats.closed_at IS NULL
JOIN agent_instances ai ON ai.tenant_id = p.tenant_id AND ai.project_id = p.id
  AND ai.id = $4
WHERE p.tenant_id = $1::uuid AND p.id = $2::uuid AND t.id = $3::uuid`,
		claim.TenantID, claim.ProjectID, claim.TaskID, claim.Principal.ID).Scan(
		&projectState, &taskState, &activeSeriesID, &attemptCount, &latestFencing,
		&moduleVersion, &moduleDigest, &moduleJSON, &agentRole, &provider, &model, &agentState,
	)
	if err != nil {
		return repositoryExecutionScope{}, repository.ErrLeaseStale
	}
	var module contracts.ModuleSpec
	if json.Unmarshal(moduleJSON, &module) != nil || module.Validate() != nil || module.ProjectID != claim.ProjectID || module.ModuleSpecVersion != moduleVersion || module.SHA256 != moduleDigest || projectState != "EXECUTING" || taskState != "EXECUTING" || activeSeriesID != attemptSeriesID || attemptCount != attempt || latestFencing != claim.Lease.FencingToken || agentRole != "EXECUTOR" || !activeRepositoryAgentState(agentState) {
		return repositoryExecutionScope{}, repository.ErrLeaseStale
	}
	if err := tx.Commit(); err != nil {
		return repositoryExecutionScope{}, err
	}
	return repositoryExecutionScope{module: module, provider: provider, model: model}, nil
}

func activeRepositoryAgentState(state string) bool {
	switch state {
	case "LEASED", "STARTING", "RUNNING", "WAITING_INPUT", "WAITING_TOOL", "WAITING_DEPENDENCY":
		return true
	default:
		return false
	}
}

func decodeRepositoryArguments(arguments map[string]any, target any) error {
	encoded, err := json.Marshal(arguments)
	if err != nil {
		return repository.ErrInvalidRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return repository.ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return repository.ErrInvalidRequest
	}
	return nil
}

func repositoryToolResult(structured map[string]any) mcp.ToolCallResult {
	return mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: "repository operation completed"}}, StructuredContent: structured}
}

func repositoryMCPTools() []mcp.Tool {
	stringProperty := func(maxLength int) map[string]any {
		return map[string]any{"type": "string", "minLength": 1, "maxLength": maxLength}
	}
	integerProperty := map[string]any{"type": "integer", "minimum": 1, "maximum": 3}
	arrayProperty := map[string]any{"type": "array", "maxItems": 256, "items": stringProperty(4096), "uniqueItems": true}
	objectSchema := func(required []any, properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "required": required, "properties": properties, "additionalProperties": false}
	}
	return []mcp.Tool{
		{Name: string(repository.LeaseActionCreateWorkspace), Description: "Create a lease-bound repository workspace", InputSchema: objectSchema([]any{"attemptSeriesId", "attempt"}, map[string]any{"attemptSeriesId": stringProperty(128), "attempt": integerProperty}), OutputSchema: objectSchema([]any{"workspaceId", "branch", "baseCommit", "moduleSpecRef"}, map[string]any{"workspaceId": stringProperty(512), "branch": stringProperty(512), "baseCommit": stringProperty(40), "moduleSpecRef": map[string]any{"type": "object"}})},
		{Name: string(repository.LeaseActionWriteFile), Description: "Write one module-owned file", InputSchema: objectSchema([]any{"workspaceId", "path", "contentBase64"}, map[string]any{"workspaceId": stringProperty(512), "path": stringProperty(4096), "contentBase64": stringProperty(6 << 20)}), OutputSchema: objectSchema([]any{"ok"}, map[string]any{"ok": map[string]any{"type": "boolean"}})},
		{Name: string(repository.LeaseActionDeleteFile), Description: "Delete one module-owned file", InputSchema: objectSchema([]any{"workspaceId", "path"}, map[string]any{"workspaceId": stringProperty(512), "path": stringProperty(4096)}), OutputSchema: objectSchema([]any{"ok"}, map[string]any{"ok": map[string]any{"type": "boolean"}})},
		{Name: repositoryReadTool, Description: "Read one module-owned file", InputSchema: objectSchema([]any{"workspaceId", "path"}, map[string]any{"workspaceId": stringProperty(512), "path": stringProperty(4096)}), OutputSchema: objectSchema([]any{"workspaceId", "path", "contentBase64", "sha256", "size"}, map[string]any{"workspaceId": stringProperty(512), "path": stringProperty(4096), "contentBase64": map[string]any{"type": "string"}, "sha256": stringProperty(71), "size": map[string]any{"type": "integer", "minimum": 0}})},
		{Name: string(repository.LeaseActionSubmit), Description: "Create an immutable signed submission commit", InputSchema: objectSchema([]any{"workspaceId", "attempt", "claimedCriteria", "localTestEvidenceRefs"}, map[string]any{"workspaceId": stringProperty(512), "attempt": integerProperty, "claimedCriteria": arrayProperty, "localTestEvidenceRefs": arrayProperty}), OutputSchema: objectSchema([]any{"manifest"}, map[string]any{"manifest": map[string]any{"type": "object"}})},
	}
}

func repositoryMCPPolicies() map[string]toolbroker.MCPToolPolicy {
	executor := []string{"EXECUTOR"}
	return map[string]toolbroker.MCPToolPolicy{
		string(repository.LeaseActionCreateWorkspace): {Risk: toolbroker.RiskMedium, SideEffect: toolbroker.SideEffectReversible, NetworkAccess: toolbroker.NetworkNone, FilesystemAccess: toolbroker.FilesystemScopedWrite, RequiresApproval: toolbroker.ApprovalNever, AllowedRoles: executor, RateLimit: "5/s", TimeoutSeconds: 60, MaxOutputBytes: 64 << 10},
		string(repository.LeaseActionWriteFile):       {Risk: toolbroker.RiskMedium, SideEffect: toolbroker.SideEffectReversible, NetworkAccess: toolbroker.NetworkNone, FilesystemAccess: toolbroker.FilesystemScopedWrite, RequiresApproval: toolbroker.ApprovalNever, AllowedRoles: executor, RateLimit: "20/s", TimeoutSeconds: 30, MaxOutputBytes: 64 << 10},
		string(repository.LeaseActionDeleteFile):      {Risk: toolbroker.RiskMedium, SideEffect: toolbroker.SideEffectReversible, NetworkAccess: toolbroker.NetworkNone, FilesystemAccess: toolbroker.FilesystemScopedWrite, RequiresApproval: toolbroker.ApprovalNever, AllowedRoles: executor, RateLimit: "20/s", TimeoutSeconds: 30, MaxOutputBytes: 64 << 10},
		repositoryReadTool:                            {Risk: toolbroker.RiskLow, SideEffect: toolbroker.SideEffectNone, NetworkAccess: toolbroker.NetworkNone, FilesystemAccess: toolbroker.FilesystemRead, RequiresApproval: toolbroker.ApprovalNever, AllowedRoles: executor, RateLimit: "20/s", TimeoutSeconds: 30, MaxOutputBytes: 1 << 20},
		string(repository.LeaseActionSubmit):          {Risk: toolbroker.RiskHigh, SideEffect: toolbroker.SideEffectIrreversible, NetworkAccess: toolbroker.NetworkNone, FilesystemAccess: toolbroker.FilesystemScopedWrite, RequiresApproval: toolbroker.ApprovalPolicy, AllowedRoles: executor, RateLimit: "2/s", TimeoutSeconds: 60, MaxOutputBytes: 256 << 10},
	}
}

var _ repository.LeaseValidator = (*repositoryExecutionAuthority)(nil)
var _ toolbroker.MCPToolClient = (*repositoryMCPClient)(nil)
