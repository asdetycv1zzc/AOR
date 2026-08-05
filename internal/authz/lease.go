package authz

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type LeaseState string

const (
	LeaseActive  LeaseState = "ACTIVE"
	LeaseRevoked LeaseState = "REVOKED"
	LeaseExpired LeaseState = "EXPIRED"
)

// CapabilityLease is the signed, short-lived proof for one runtime capability scope.
// It is safe to serialize as metadata; the signing key is never part of it.
type CapabilityLease struct {
	ID                       string              `json:"id"`
	AgentInstanceID          string              `json:"agentInstanceId"`
	PrincipalID              string              `json:"principalId"`
	PrincipalType            authn.PrincipalType `json:"principalType"`
	TenantID                 string              `json:"tenantId"`
	ProjectID                string              `json:"projectId"`
	ProjectVersion           int64               `json:"projectVersion"`
	TaskID                   string              `json:"taskId"`
	TaskVersion              int64               `json:"taskVersion"`
	SpecDigest               string              `json:"specDigest"`
	Role                     string              `json:"role"`
	Action                   string              `json:"action"`
	Resource                 Resource            `json:"resource"`
	ParameterDigest          string              `json:"parameterDigest"`
	Capabilities             []string            `json:"capabilities"`
	IssuedAt                 time.Time           `json:"issuedAt"`
	ExpiresAt                time.Time           `json:"expiresAt"`
	LastHeartbeatAt          time.Time           `json:"lastHeartbeatAt"`
	HeartbeatIntervalSeconds int64               `json:"heartbeatIntervalSeconds"`
	PolicyVersion            string              `json:"policyVersion"`
	BudgetAccountID          string              `json:"budgetAccountId"`
	Nonce                    string              `json:"nonce"`
	FencingToken             int64               `json:"fencingToken"`
	State                    LeaseState          `json:"state"`
	RevokedAt                *time.Time          `json:"revokedAt,omitempty"`
	Signature                string              `json:"signature"`
}

func (lease CapabilityLease) Reference() LeaseReference {
	return LeaseReference{ID: lease.ID, ExpiresAt: lease.ExpiresAt, PolicyVersion: lease.PolicyVersion, FencingToken: lease.FencingToken}
}

func (lease CapabilityLease) IsExpired(now time.Time) bool {
	if lease.ExpiresAt.IsZero() || !now.Before(lease.ExpiresAt) {
		return true
	}
	if lease.HeartbeatIntervalSeconds > 0 && !lease.LastHeartbeatAt.IsZero() && !now.Before(lease.LastHeartbeatAt.Add(3*time.Duration(lease.HeartbeatIntervalSeconds)*time.Second)) {
		return true
	}
	return false
}

func (lease CapabilityLease) ValidateShape() *aorerrors.Error {
	if lease.ID == "" || lease.AgentInstanceID == "" || lease.PrincipalID == "" || lease.TenantID == "" || lease.ProjectID == "" || lease.ProjectVersion < 0 || !validLeaseTaskBinding(lease.Role, lease.TaskID, lease.TaskVersion, lease.SpecDigest) || lease.Role == "" || !leaseActionAllowed(lease.Action, lease.Role, lease.TaskID) || resourceEmpty(lease.Resource) || lease.ParameterDigest == "" || lease.PolicyVersion == "" || lease.BudgetAccountID == "" || lease.Nonce == "" || lease.FencingToken < 1 || lease.State == "" || lease.IssuedAt.IsZero() || lease.ExpiresAt.IsZero() || lease.LastHeartbeatAt.IsZero() || lease.HeartbeatIntervalSeconds <= 0 || lease.HeartbeatIntervalSeconds > 300 || len(lease.Capabilities) == 0 || len(lease.Capabilities) > 64 || !containsString(lease.Capabilities, lease.Action) {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease"})
	}
	if lease.PrincipalType == "" || !lease.ExpiresAt.After(lease.IssuedAt) || lease.LastHeartbeatAt.Before(lease.IssuedAt) || lease.LastHeartbeatAt.After(lease.ExpiresAt) {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease"})
	}
	if !digestPattern.MatchString(lease.ParameterDigest) || !digestPattern.MatchString(lease.Nonce) {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease digest"})
	}
	for _, capability := range lease.Capabilities {
		if !safeOpaque(capability, 128) {
			return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease capabilities"})
		}
	}
	if lease.Resource.Path != "" {
		if _, err := normalizeRelativePath(lease.Resource.Path); err != nil {
			return aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
		}
	}
	if lease.State != LeaseActive && lease.State != LeaseRevoked && lease.State != LeaseExpired {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease"})
	}
	if strings.ContainsAny(lease.ID+lease.AgentInstanceID+lease.PrincipalID+lease.ProjectID+lease.TaskID+lease.Role+lease.Action+lease.ParameterDigest+lease.PolicyVersion+lease.BudgetAccountID+lease.Nonce, "\r\n\x00") {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease"})
	}
	return nil
}

// Signer abstracts the lease proof key. Verify must compare in constant time.
type Signer interface {
	Sign(payload []byte) (string, error)
	Verify(payload []byte, signature string) error
}

// HMACSigner is a small reference signer. Production should inject a KMS/HSM
// implementation through Signer rather than exporting the key.
type HMACSigner struct{ key []byte }

func NewHMACSigner(key []byte) (*HMACSigner, error) {
	if len(key) < 32 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "signing key"})
	}
	copyKey := append([]byte(nil), key...)
	return &HMACSigner{key: copyKey}, nil
}

func (s *HMACSigner) Sign(payload []byte) (string, error) {
	if s == nil || len(s.key) < 32 {
		return "", aorerrors.New(aorerrors.CodeInternalError, "", nil)
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func (s *HMACSigner) Verify(payload []byte, signature string) error {
	if s == nil || len(s.key) < 32 || !strings.HasPrefix(signature, "hmac-sha256:") {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(signature, "hmac-sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), decoded) {
		return aorerrors.New(aorerrors.CodeUnauthorized, "", nil)
	}
	return nil
}

// LeaseStore is the persistence seam. Implementations must atomically compare
// the expected fencing token in CompareAndSwap.
type LeaseStore interface {
	Put(context.Context, CapabilityLease) error
	Get(context.Context, string) (CapabilityLease, bool, error)
	CompareAndSwap(context.Context, string, int64, CapabilityLease) (bool, error)
}

type MemoryLeaseStore struct {
	mu     sync.RWMutex
	leases map[string]CapabilityLease
}

func NewMemoryLeaseStore() *MemoryLeaseStore {
	return &MemoryLeaseStore{leases: make(map[string]CapabilityLease)}
}

func (s *MemoryLeaseStore) Put(ctx context.Context, lease CapabilityLease) error {
	if s == nil {
		return aorerrors.New(aorerrors.CodeInternalError, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.leases[lease.ID]; exists {
		return aorerrors.New(aorerrors.CodeConflict, "", nil)
	}
	s.leases[lease.ID] = cloneLease(lease)
	return nil
}

func (s *MemoryLeaseStore) Get(ctx context.Context, id string) (CapabilityLease, bool, error) {
	if s == nil {
		return CapabilityLease{}, false, aorerrors.New(aorerrors.CodeInternalError, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, false, err
	}
	s.mu.RLock()
	lease, ok := s.leases[id]
	s.mu.RUnlock()
	if !ok || leaseTenantID(ctx) != "" && lease.TenantID != leaseTenantID(ctx) {
		return CapabilityLease{}, false, nil
	}
	return cloneLease(lease), true, nil
}

func (s *MemoryLeaseStore) CompareAndSwap(ctx context.Context, id string, expected int64, replacement CapabilityLease) (bool, error) {
	if s == nil {
		return false, aorerrors.New(aorerrors.CodeInternalError, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.leases[id]
	if !ok || current.FencingToken != expected || current.TenantID != replacement.TenantID || current.ID != replacement.ID {
		return false, nil
	}
	s.leases[id] = cloneLease(replacement)
	return true, nil
}

type LeaseRequest struct {
	ID                string
	AgentInstanceID   string
	Principal         authn.Principal
	TenantID          string
	ProjectID         string
	ProjectVersion    int64
	TaskID            string
	TaskVersion       int64
	SpecDigest        string
	Role              string
	Action            string
	Resource          Resource
	ParameterDigest   string
	Capabilities      []string
	PolicyVersion     string
	BudgetAccountID   string
	TTL               time.Duration
	HeartbeatInterval time.Duration
	Grant             PolicyDecision
	RequestDigest     string
	FencingToken      int64
	NotAfter          time.Time
	Now               time.Time
}

type LeaseRenewalRequest struct {
	LeaseID       string
	TenantID      string
	FencingToken  int64
	PrincipalID   string
	PrincipalType authn.PrincipalType
	Role          string
	PolicyVersion string
	TTL           time.Duration
	Grant         PolicyDecision
	RequestDigest string
	Now           time.Time
}

type LeaseHeartbeatRequest struct {
	LeaseID      string
	TenantID     string
	ProjectID    string
	TaskID       string
	PrincipalID  string
	FencingToken int64
	Now          time.Time
}

type LeaseRevokeRequest struct {
	LeaseID       string
	ProjectID     string
	TaskID        string
	Actor         authn.Principal
	Reason        string
	RequestDigest string
	Now           time.Time
}

type LeaseCheck struct {
	LeaseID         string
	AgentInstanceID string
	PrincipalID     string
	PrincipalType   authn.PrincipalType
	TenantID        string
	ProjectID       string
	ProjectVersion  int64
	TaskID          string
	TaskVersion     int64
	SpecDigest      string
	Role            string
	Action          string
	Resource        Resource
	ParameterDigest string
	PolicyVersion   string
	BudgetAccountID string
	Capability      string
	FencingToken    int64
	At              time.Time
}

type LeaseManagerConfig struct {
	Store             LeaseStore
	Signer            Signer
	Clock             func() time.Time
	DefaultTTL        time.Duration
	MaxTTL            time.Duration
	HeartbeatInterval time.Duration
}

type LeaseManager struct {
	store             LeaseStore
	signer            Signer
	clock             func() time.Time
	defaultTTL        time.Duration
	maxTTL            time.Duration
	heartbeatInterval time.Duration
}

func NewLeaseManager(config LeaseManagerConfig) (*LeaseManager, error) {
	store := config.Store
	if store == nil {
		store = NewMemoryLeaseStore()
	}
	signer := config.Signer
	if signer == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil)
		}
		var err error
		signer, err = NewHMACSigner(key)
		if err != nil {
			return nil, err
		}
	}
	if config.DefaultTTL <= 0 {
		config.DefaultTTL = 5 * time.Minute
	}
	if config.MaxTTL <= 0 {
		config.MaxTTL = 15 * time.Minute
	}
	if config.DefaultTTL > config.MaxTTL || config.HeartbeatInterval <= 0 {
		if config.HeartbeatInterval <= 0 {
			config.HeartbeatInterval = 30 * time.Second
		}
		if config.DefaultTTL > config.MaxTTL {
			return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease ttl"})
		}
	}
	return &LeaseManager{store: store, signer: signer, clock: config.Clock, defaultTTL: config.DefaultTTL, maxTTL: config.MaxTTL, heartbeatInterval: config.HeartbeatInterval}, nil
}

func (m *LeaseManager) now() time.Time {
	if m != nil && m.clock != nil {
		return m.clock().UTC()
	}
	return time.Now().UTC()
}

func (m *LeaseManager) Issue(ctx context.Context, request LeaseRequest) (CapabilityLease, error) {
	if m == nil || m.store == nil || m.signer == nil {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if err := request.Principal.Validate(); err != nil {
		return CapabilityLease{}, err
	}
	if request.AgentInstanceID == "" {
		request.AgentInstanceID = request.Principal.ID
	}
	if request.Principal.ID != request.AgentInstanceID {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "agent"})
	}
	if request.TenantID == "" || request.ProjectID == "" || request.ProjectVersion < 0 || !validLeaseTaskBinding(request.Role, request.TaskID, request.TaskVersion, request.SpecDigest) || request.Role == "" || request.Action == "" || resourceEmpty(request.Resource) || !digestPattern.MatchString(request.ParameterDigest) || request.PolicyVersion == "" || request.BudgetAccountID == "" || len(request.Capabilities) == 0 || len(request.Capabilities) > 64 || !containsString(request.Capabilities, request.Action) || request.RequestDigest != "" && !digestPattern.MatchString(request.RequestDigest) || request.FencingToken < 0 {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease"})
	}
	if request.Principal.TenantID != "" && request.Principal.TenantID != request.TenantID {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "tenant"})
	}
	if request.Principal.ProjectID != "" && request.Principal.ProjectID != request.ProjectID {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "project"})
	}
	if request.Principal.Role != "" && request.Principal.Role != request.Role {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "role"})
	}
	if !leaseActionAllowed(request.Action, request.Role, request.TaskID) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "action"})
	}
	now := m.now()
	binding := DecisionBinding{PrincipalID: request.Principal.ID, TenantID: request.TenantID, ProjectID: request.ProjectID, ProjectVersion: request.ProjectVersion, TaskID: request.TaskID, TaskVersion: request.TaskVersion, SpecDigest: request.SpecDigest, Role: request.Role, Action: request.Action, Resource: cloneResource(request.Resource), ParameterDigest: request.ParameterDigest, BudgetAccountID: request.BudgetAccountID}
	if err := validateLeaseGrant(request.Grant, request.PolicyVersion, binding, now); err != nil {
		return CapabilityLease{}, err
	}
	ttl := request.TTL
	if ttl <= 0 {
		ttl = m.defaultTTL
	}
	if ttl > m.maxTTL {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"limit": m.maxTTL})
	}
	if !request.Grant.Constraints.ExpiresAt.IsZero() {
		grantTTL := request.Grant.Constraints.ExpiresAt.Sub(now)
		if grantTTL <= 0 {
			return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": request.PolicyVersion})
		}
		if ttl > grantTTL {
			ttl = grantTTL
		}
	}
	if !request.NotAfter.IsZero() {
		remaining := request.NotAfter.Sub(now)
		if remaining <= 0 {
			return CapabilityLease{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
		}
		if ttl > remaining {
			ttl = remaining
		}
	}
	heartbeat := request.HeartbeatInterval
	if heartbeat <= 0 {
		heartbeat = m.heartbeatInterval
	}
	if heartbeat <= 0 || heartbeat%time.Second != 0 || heartbeat > 5*time.Minute || heartbeat > ttl/3 {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "heartbeat"})
	}
	id := request.ID
	if id == "" {
		var idErr error
		id, idErr = randomID("lease_")
		if idErr != nil {
			return CapabilityLease{}, idErr
		}
	}
	nonce := request.RequestDigest
	if nonce == "" {
		rawNonce, err := randomID("nonce_")
		if err != nil {
			return CapabilityLease{}, err
		}
		nonceSum := sha256.Sum256([]byte(rawNonce))
		nonce = "sha256:" + hex.EncodeToString(nonceSum[:])
	}
	fencingToken := request.FencingToken
	if fencingToken == 0 {
		fencingToken = 1
	}
	lease := CapabilityLease{ID: id, AgentInstanceID: request.AgentInstanceID, PrincipalID: request.Principal.ID, PrincipalType: request.Principal.Type, TenantID: request.TenantID, ProjectID: request.ProjectID, ProjectVersion: request.ProjectVersion, TaskID: request.TaskID, TaskVersion: request.TaskVersion, SpecDigest: request.SpecDigest, Role: request.Role, Action: request.Action, Resource: cloneResource(request.Resource), ParameterDigest: request.ParameterDigest, Capabilities: append([]string(nil), request.Capabilities...), IssuedAt: now, ExpiresAt: now.Add(ttl), LastHeartbeatAt: now, HeartbeatIntervalSeconds: int64(heartbeat / time.Second), PolicyVersion: request.PolicyVersion, BudgetAccountID: request.BudgetAccountID, Nonce: nonce, FencingToken: fencingToken, State: LeaseActive}
	if err := lease.ValidateShape(); err != nil {
		return CapabilityLease{}, err
	}
	if err := m.sign(&lease); err != nil {
		return CapabilityLease{}, err
	}
	if err := m.store.Put(ctx, lease); err != nil {
		return CapabilityLease{}, err
	}
	return cloneLease(lease), nil
}

func leaseActionAllowed(action, role, taskID string) bool {
	if taskID == "" {
		return action == ActionModelGenerate && !LeaseRoleRequiresTask(role)
	}
	return IsSideEffect(action) || action == ActionModelGenerate && taskModelLeaseRole(role)
}

func (m *LeaseManager) Renew(ctx context.Context, request LeaseRenewalRequest) (CapabilityLease, error) {
	if m == nil || m.store == nil {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if request.RequestDigest != "" && !digestPattern.MatchString(request.RequestDigest) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease request digest"})
	}
	now := m.now()
	current, found, err := m.store.Get(withLeaseTenant(ctx, request.TenantID), request.LeaseID)
	if err != nil {
		return CapabilityLease{}, err
	}
	if !found {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := m.verify(current); err != nil {
		return CapabilityLease{}, err
	}
	if current.State != LeaseActive || current.IsExpired(now) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
	}
	if request.FencingToken < 1 || request.FencingToken != current.FencingToken {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeConflict, "", map[string]any{"scope": "lease fencing"})
	}
	if request.PrincipalID == "" || request.PrincipalID != current.PrincipalID || (request.PrincipalType != "" && request.PrincipalType != current.PrincipalType) || (request.Role != "" && request.Role != current.Role) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease principal"})
	}
	if request.PolicyVersion == "" || request.PolicyVersion != current.PolicyVersion {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": current.PolicyVersion})
	}
	binding := DecisionBinding{PrincipalID: current.PrincipalID, TenantID: current.TenantID, ProjectID: current.ProjectID, ProjectVersion: current.ProjectVersion, TaskID: current.TaskID, TaskVersion: current.TaskVersion, SpecDigest: current.SpecDigest, Role: current.Role, Action: current.Action, Resource: cloneResource(current.Resource), ParameterDigest: current.ParameterDigest, BudgetAccountID: current.BudgetAccountID}
	if err := validateLeaseGrant(request.Grant, current.PolicyVersion, binding, now); err != nil {
		return CapabilityLease{}, err
	}
	ttl := request.TTL
	if ttl <= 0 {
		ttl = m.defaultTTL
	}
	if ttl > m.maxTTL {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"limit": m.maxTTL})
	}
	if !request.Grant.Constraints.ExpiresAt.IsZero() {
		grantTTL := request.Grant.Constraints.ExpiresAt.Sub(now)
		if grantTTL <= 0 {
			return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": current.PolicyVersion})
		}
		if ttl > grantTTL {
			ttl = grantTTL
		}
	}
	updated := cloneLease(current)
	updated.ExpiresAt = now.Add(ttl)
	updated.LastHeartbeatAt = now
	updated.FencingToken++
	if request.RequestDigest != "" {
		updated.Nonce = request.RequestDigest
	}
	if updated.ExpiresAt.Before(updated.IssuedAt) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease time"})
	}
	if err := m.sign(&updated); err != nil {
		return CapabilityLease{}, err
	}
	updatedOK, err := m.store.CompareAndSwap(ctx, current.ID, current.FencingToken, updated)
	if err != nil {
		return CapabilityLease{}, err
	}
	if !updatedOK {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeConflict, "", nil)
	}
	return updated, nil
}

func (m *LeaseManager) Heartbeat(ctx context.Context, request LeaseHeartbeatRequest) (CapabilityLease, error) {
	if m == nil || m.store == nil {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	now := m.now()
	current, found, err := m.store.Get(withLeaseTenant(ctx, request.TenantID), request.LeaseID)
	if err != nil {
		return CapabilityLease{}, err
	}
	if !found {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := m.verify(current); err != nil {
		return CapabilityLease{}, err
	}
	if current.State != LeaseActive || current.IsExpired(now) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
	}
	if request.ProjectID == "" || request.ProjectID != current.ProjectID || request.TaskID != current.TaskID || request.PrincipalID == "" || request.PrincipalID != current.PrincipalID || request.FencingToken != current.FencingToken {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease fencing"})
	}
	if now.Before(current.LastHeartbeatAt) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "heartbeat time"})
	}
	updated := cloneLease(current)
	updated.LastHeartbeatAt = now
	if err := m.sign(&updated); err != nil {
		return CapabilityLease{}, err
	}
	ok, err := m.store.CompareAndSwap(ctx, current.ID, current.FencingToken, updated)
	if err != nil {
		return CapabilityLease{}, err
	}
	if !ok {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeConflict, "", nil)
	}
	return updated, nil
}

func (m *LeaseManager) Revoke(ctx context.Context, request LeaseRevokeRequest) error {
	if m == nil || m.store == nil {
		return aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if err := request.Actor.Validate(); err != nil {
		return err
	}
	if request.ProjectID == "" || request.Reason == "" || len(request.Reason) > 256 || strings.ContainsAny(request.Reason, "\r\n\x00") || !digestPattern.MatchString(request.RequestDigest) {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "revoke reason"})
	}
	now := m.now()
	current, found, err := m.store.Get(withLeaseTenant(ctx, request.Actor.TenantID), request.LeaseID)
	if err != nil {
		return err
	}
	if !found {
		return aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err := m.verify(current); err != nil {
		return err
	}
	if current.ProjectID != request.ProjectID || current.TaskID != request.TaskID {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease revoke binding"})
	}
	if request.Actor.ID != current.PrincipalID && request.Actor.Type != authn.PrincipalBreakGlassAdmin && request.Actor.Role != authn.RoleBreakGlassAdmin {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease revoke"})
	}
	if current.State != LeaseActive {
		if current.State == LeaseRevoked && current.Nonce == request.RequestDigest {
			return nil
		}
		return aorerrors.New(aorerrors.CodeIdempotencyConflict, "", map[string]any{"scope": "lease revoke"})
	}
	updated := cloneLease(current)
	updated.State = LeaseRevoked
	updated.RevokedAt = &now
	updated.FencingToken++
	updated.Nonce = request.RequestDigest
	if err := m.sign(&updated); err != nil {
		return err
	}
	ok, err := m.store.CompareAndSwap(ctx, current.ID, current.FencingToken, updated)
	if err != nil {
		return err
	}
	if !ok {
		latest, found, lookupErr := m.store.Get(withLeaseTenant(ctx, request.Actor.TenantID), request.LeaseID)
		if lookupErr == nil && found && latest.State == LeaseRevoked && latest.Nonce == request.RequestDigest {
			return nil
		}
		return aorerrors.New(aorerrors.CodeConflict, "", nil)
	}
	return nil
}

func (m *LeaseManager) Validate(ctx context.Context, check LeaseCheck) (CapabilityLease, error) {
	if m == nil || m.store == nil {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	now := m.now()
	current, found, err := m.store.Get(withLeaseTenant(ctx, check.TenantID), check.LeaseID)
	if err != nil {
		return CapabilityLease{}, err
	}
	if !found {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
	}
	if err := m.verify(current); err != nil {
		return CapabilityLease{}, err
	}
	if current.State != LeaseActive || current.IsExpired(now) {
		if current.State == LeaseActive && current.IsExpired(now) {
			m.expire(ctx, current)
		}
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
	}
	if check.AgentInstanceID == "" || check.AgentInstanceID != current.AgentInstanceID || check.PrincipalID == "" || check.PrincipalID != current.PrincipalID || check.PrincipalType == "" || check.PrincipalType != current.PrincipalType || check.TenantID == "" || check.TenantID != current.TenantID || check.ProjectID == "" || check.ProjectID != current.ProjectID || check.ProjectVersion != current.ProjectVersion || check.TaskID != current.TaskID || check.TaskVersion != current.TaskVersion || check.SpecDigest != current.SpecDigest || check.Role == "" || check.Role != current.Role || check.Action == "" || check.Action != current.Action || check.PolicyVersion == "" || check.PolicyVersion != current.PolicyVersion || check.BudgetAccountID == "" || check.BudgetAccountID != current.BudgetAccountID || check.Capability == "" || !containsString(current.Capabilities, check.Capability) || check.FencingToken < 1 || check.FencingToken != current.FencingToken {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "lease binding"})
	}
	if !digestPattern.MatchString(check.ParameterDigest) || check.ParameterDigest != current.ParameterDigest {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "lease parameters"})
	}
	if resourceEmpty(check.Resource) || !resourcesEqual(check.Resource, current.Resource) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
	}
	return current, nil
}

// ValidateActive checks only the signed lifecycle state. It must not be used
// as authorization for a side effect; Validate performs the exact binding
// checks required at commit time.
func (m *LeaseManager) ValidateActive(ctx context.Context, leaseID string, _ time.Time) (CapabilityLease, error) {
	if m == nil || m.store == nil {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	current, found, err := m.store.Get(ctx, leaseID)
	if err != nil {
		return CapabilityLease{}, err
	}
	if !found {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
	}
	if err := m.verify(current); err != nil {
		return CapabilityLease{}, err
	}
	now := m.now()
	if current.State != LeaseActive || current.IsExpired(now) {
		return CapabilityLease{}, aorerrors.New(aorerrors.CodeLeaseExpired, "", nil)
	}
	return current, nil
}

func (m *LeaseManager) Get(ctx context.Context, id string) (CapabilityLease, bool, error) {
	if m == nil || m.store == nil {
		return CapabilityLease{}, false, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return CapabilityLease{}, false, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	lease, found, err := m.store.Get(ctx, id)
	if err != nil || !found {
		return CapabilityLease{}, found, err
	}
	if err := m.verify(lease); err != nil {
		return CapabilityLease{}, false, err
	}
	return lease, true, nil
}

// GetForTenant rehydrates and verifies a lease under the caller's explicit
// tenant scope. It is intended for idempotency replay checks, not authorization
// of a side effect; Validate performs the exact commit-time binding checks.
func (m *LeaseManager) GetForTenant(ctx context.Context, tenantID, id string) (CapabilityLease, bool, error) {
	if tenantID == "" {
		return CapabilityLease{}, false, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "lease tenant"})
	}
	return m.Get(withLeaseTenant(ctx, tenantID), id)
}

func (m *LeaseManager) verify(lease CapabilityLease) error {
	if err := lease.ValidateShape(); err != nil {
		return err
	}
	return m.signer.Verify(leaseSigningPayload(lease), lease.Signature)
}

func (m *LeaseManager) sign(lease *CapabilityLease) error {
	if lease == nil {
		return aorerrors.New(aorerrors.CodeInvalidArgument, "", nil)
	}
	signature, err := m.signer.Sign(leaseSigningPayload(*lease))
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil)
	}
	lease.Signature = signature
	return nil
}

func (m *LeaseManager) expire(ctx context.Context, current CapabilityLease) {
	updated := cloneLease(current)
	updated.State = LeaseExpired
	updated.FencingToken++
	if err := m.sign(&updated); err != nil {
		return
	}
	_, _ = m.store.CompareAndSwap(ctx, current.ID, current.FencingToken, updated)
}

type leaseSigningView struct {
	ID                       string              `json:"id"`
	AgentInstanceID          string              `json:"agentInstanceId"`
	PrincipalID              string              `json:"principalId"`
	PrincipalType            authn.PrincipalType `json:"principalType"`
	TenantID                 string              `json:"tenantId"`
	ProjectID                string              `json:"projectId"`
	ProjectVersion           int64               `json:"projectVersion"`
	TaskID                   string              `json:"taskId"`
	TaskVersion              int64               `json:"taskVersion"`
	SpecDigest               string              `json:"specDigest"`
	Role                     string              `json:"role"`
	Action                   string              `json:"action"`
	Resource                 Resource            `json:"resource"`
	ParameterDigest          string              `json:"parameterDigest"`
	Capabilities             []string            `json:"capabilities"`
	IssuedAt                 time.Time           `json:"issuedAt"`
	ExpiresAt                time.Time           `json:"expiresAt"`
	LastHeartbeatAt          time.Time           `json:"lastHeartbeatAt"`
	HeartbeatIntervalSeconds int64               `json:"heartbeatIntervalSeconds"`
	PolicyVersion            string              `json:"policyVersion"`
	BudgetAccountID          string              `json:"budgetAccountId"`
	Nonce                    string              `json:"nonce"`
	FencingToken             int64               `json:"fencingToken"`
	State                    LeaseState          `json:"state"`
	RevokedAt                *time.Time          `json:"revokedAt,omitempty"`
}

func leaseSigningPayload(lease CapabilityLease) []byte {
	view := leaseSigningView{ID: lease.ID, AgentInstanceID: lease.AgentInstanceID, PrincipalID: lease.PrincipalID, PrincipalType: lease.PrincipalType, TenantID: lease.TenantID, ProjectID: lease.ProjectID, ProjectVersion: lease.ProjectVersion, TaskID: lease.TaskID, TaskVersion: lease.TaskVersion, SpecDigest: lease.SpecDigest, Role: lease.Role, Action: lease.Action, Resource: cloneResource(lease.Resource), ParameterDigest: lease.ParameterDigest, Capabilities: append([]string(nil), lease.Capabilities...), IssuedAt: lease.IssuedAt.UTC(), ExpiresAt: lease.ExpiresAt.UTC(), LastHeartbeatAt: lease.LastHeartbeatAt.UTC(), HeartbeatIntervalSeconds: lease.HeartbeatIntervalSeconds, PolicyVersion: lease.PolicyVersion, BudgetAccountID: lease.BudgetAccountID, Nonce: lease.Nonce, FencingToken: lease.FencingToken, State: lease.State, RevokedAt: lease.RevokedAt}
	payload, _ := json.Marshal(view)
	return payload
}

func randomID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil)
	}
	return prefix + hex.EncodeToString(value), nil
}

func cloneResource(resource Resource) Resource {
	resource.Attributes = cloneStringMap(resource.Attributes)
	return resource
}

func cloneLease(lease CapabilityLease) CapabilityLease {
	lease.Capabilities = append([]string(nil), lease.Capabilities...)
	lease.Resource = cloneResource(lease.Resource)
	if lease.RevokedAt != nil {
		value := *lease.RevokedAt
		lease.RevokedAt = &value
	}
	return lease
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func validateLeaseGrant(grant PolicyDecision, policyVersion string, expected DecisionBinding, now time.Time) error {
	if err := grant.Validate(now); err != nil {
		return err
	}
	if grant.Decision != DecisionAllow || grant.PolicyVersion != policyVersion || grant.Binding == nil || !decisionBindingsEqual(*grant.Binding, expected) {
		return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"policyVersion": policyVersion})
	}
	return nil
}

func decisionBindingsEqual(left, right DecisionBinding) bool {
	return left.PrincipalID == right.PrincipalID && left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.ProjectVersion == right.ProjectVersion && left.TaskID == right.TaskID && left.TaskVersion == right.TaskVersion && left.SpecDigest == right.SpecDigest && left.Role == right.Role && left.Action == right.Action && resourcesEqual(left.Resource, right.Resource) && left.ParameterDigest == right.ParameterDigest && left.BudgetAccountID == right.BudgetAccountID
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func resourceEmpty(resource Resource) bool {
	return resource.Type == "" && resource.ID == "" && resource.Path == "" && len(resource.Attributes) == 0
}

func resourcesEqual(left, right Resource) bool {
	if left.Type != right.Type || left.ID != right.ID || left.Path != right.Path || len(left.Attributes) != len(right.Attributes) {
		return false
	}
	for key, value := range left.Attributes {
		if right.Attributes[key] != value {
			return false
		}
	}
	return true
}
