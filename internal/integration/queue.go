package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type Queue struct {
	store    Store
	executor MergeExecutor
	gate     Gate
	clock    func() time.Time
	mu       sync.Mutex
}

func NewQueue(store Store, executor MergeExecutor, clock func() time.Time) (*Queue, error) {
	gate, ok := executor.(Gate)
	if !ok {
		return nil, ErrNotAudited
	}
	return NewVerifiedQueue(store, executor, gate, clock)
}

func NewVerifiedQueue(store Store, executor MergeExecutor, gate Gate, clock func() time.Time) (*Queue, error) {
	if store == nil || executor == nil || gate == nil {
		return nil, ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	return &Queue{store: store, executor: executor, gate: gate, clock: clock}, nil
}

func (q *Queue) Audit(ctx context.Context, request Request) (Audit, error) {
	verified, err := q.verify(ctx, request)
	if err != nil {
		return Audit{}, err
	}
	return q.auditVerified(verified)
}

func (q *Queue) Task(ctx context.Context, tenantID, integrationID string) (IntegrationTask, bool, error) {
	return q.store.GetTask(ctx, tenantID, integrationID)
}

func (q *Queue) StartAttempt(ctx context.Context, request StartAttemptRequest) (IntegrationTask, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.store.StartAttempt(ctx, request)
}

func (q *Queue) auditVerified(request VerifiedRequest) (Audit, error) {
	candidates := cloneCandidates(request.Candidates)
	sort.Slice(candidates, func(left, right int) bool { return candidates[left].TaskID < candidates[right].TaskID })
	findings := []Finding{}
	paths := make(map[string]string)
	interfaces := make(map[string]string)
	for _, candidate := range candidates {
		if !candidate.AuditPassed || candidate.EvidenceSHA256 == "" {
			findings = append(findings, Finding{ID: "audit-evidence-" + candidate.TaskID, Severity: "BLOCKING", Category: "EVIDENCE", Summary: "candidate has no passing immutable audit evidence", Tasks: []string{candidate.TaskID}})
		}
		for _, raw := range candidate.OwnedPaths {
			clean, ok := cleanPath(raw)
			if !ok {
				findings = append(findings, Finding{ID: "path-invalid-" + candidate.TaskID, Severity: "BLOCKING", Category: "OWNERSHIP", Summary: "candidate path is invalid", Tasks: []string{candidate.TaskID}})
				continue
			}
			for priorPath, priorTask := range paths {
				if priorTask != candidate.TaskID && (containsPath(priorPath, clean) || containsPath(clean, priorPath)) {
					findings = append(findings, Finding{ID: "path-overlap-" + priorTask + "-" + candidate.TaskID, Severity: "BLOCKING", Category: "OWNERSHIP", Summary: "module ownership overlaps", Tasks: []string{priorTask, candidate.TaskID}})
				}
			}
			paths[clean] = candidate.TaskID
		}
		for _, publicInterface := range candidate.PublicInterfaces {
			key := strings.ToLower(strings.TrimSpace(publicInterface))
			if key == "" {
				continue
			}
			if prior, exists := interfaces[key]; exists && prior != candidate.TaskID {
				findings = append(findings, Finding{ID: "interface-conflict-" + prior + "-" + candidate.TaskID, Severity: "BLOCKING", Category: "INTERFACE", Summary: "public interface is owned by multiple modules", Tasks: []string{prior, candidate.TaskID}})
			}
			interfaces[key] = candidate.TaskID
		}
	}
	findings = deduplicateFindings(findings)
	request.Candidates = candidates
	digest, err := auditDigest(request, findings)
	if err != nil {
		return Audit{}, err
	}
	return Audit{IntegrationID: request.IntegrationID, ProjectID: request.ProjectID, Findings: findings, EvidenceSHA256: digest, Passed: len(findings) == 0, CreatedAt: q.clock().UTC()}, nil
}

func (q *Queue) Merge(ctx context.Context, request Request) (MergeResult, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	verified, err := q.verify(ctx, request)
	if err != nil {
		return MergeResult{}, err
	}
	audit, err := q.auditVerified(verified)
	if err != nil {
		return MergeResult{}, err
	}
	if !audit.Passed {
		return q.recordConflict(ctx, verified, audit)
	}
	requestDigest, err := requestDigest(request, verified)
	if err != nil {
		return MergeResult{}, err
	}
	reservation := MergeResult{TenantID: verified.TenantID, IntegrationID: verified.IntegrationID, ProjectID: verified.ProjectID, OwnerTaskID: verified.OwnerTaskID, Attempt: verified.Attempt, RequestDigest: requestDigest, Audit: audit, Pending: true}
	prior, owner, err := q.store.Reserve(ctx, reservation)
	if err != nil {
		return MergeResult{}, err
	}
	if !owner && !prior.Pending {
		prior.Duplicate = true
		return prior, nil
	}
	if !owner {
		reservation.Duplicate = true
		if recovered, found, lookupErr := q.executor.Lookup(ctx, verified.IntegrationID); lookupErr != nil {
			return MergeResult{}, lookupErr
		} else if found {
			if _, verifyErr := q.reverifyReservation(ctx, request, reservation); verifyErr != nil {
				return reservation, verifyErr
			}
			return q.completeRecovered(ctx, reservation, recovered)
		}
	}
	verified, err = q.reverifyReservation(ctx, request, reservation)
	if err != nil {
		return reservation, err
	}
	commits := make([]string, 0, len(verified.Candidates))
	for _, candidate := range verified.Candidates {
		commits = append(commits, candidate.SubmissionCommit)
	}
	sort.Strings(commits)
	commit, err := q.executor.Merge(ctx, verified.BaseCommit, commits, verified.IntegrationID)
	if err != nil {
		if recovered, found, lookupErr := q.executor.Lookup(ctx, verified.IntegrationID); lookupErr != nil {
			return reservation, errors.Join(ErrMergePending, err, lookupErr)
		} else if found {
			if _, verifyErr := q.reverifyReservation(ctx, request, reservation); verifyErr != nil {
				return reservation, verifyErr
			}
			return q.completeRecovered(ctx, reservation, recovered)
		}
		if !errors.Is(err, ErrMergeConflict) {
			return reservation, errors.Join(ErrMergePending, err)
		}
		failure, failureErr := q.mergeFailureAudit(verified)
		if failureErr != nil {
			return reservation, failureErr
		}
		return q.recordConflict(ctx, verified, failure)
	}
	if _, err := q.reverifyReservation(ctx, request, reservation); err != nil {
		return reservation, err
	}
	return q.completeRecovered(ctx, reservation, commit)
}

func (q *Queue) recordConflict(ctx context.Context, request VerifiedRequest, audit Audit) (MergeResult, error) {
	owner := request.OwnerTaskID
	if owner == "" {
		owner = conflictOwner(audit, request.Candidates)
	}
	conflict := MergeResult{
		TenantID: request.TenantID, IntegrationID: request.IntegrationID, ProjectID: request.ProjectID,
		OwnerTaskID: owner, Attempt: request.Attempt, Audit: audit,
	}
	if owner == "" {
		return conflict, ErrInvalidRequest
	}
	stored, changed, err := q.store.RecordConflict(ctx, conflict)
	if err != nil {
		return conflict, err
	}
	stored.Duplicate = !changed
	task, found, err := q.store.GetTask(ctx, request.TenantID, request.IntegrationID)
	if err != nil {
		return stored, err
	}
	if !found {
		return stored, ErrAttemptState
	}
	if task.State == TaskBlockedUserDecision {
		return stored, errors.Join(ErrConflict, ErrAttemptsExhausted)
	}
	return stored, ErrConflict
}

func (q *Queue) mergeFailureAudit(request VerifiedRequest) (Audit, error) {
	tasks := make([]string, 0, len(request.Candidates))
	for _, candidate := range canonicalCandidates(request.Candidates) {
		tasks = append(tasks, candidate.TaskID)
	}
	finding := Finding{
		ID: "merge-conflict", Severity: "BLOCKING", Category: "MERGE",
		Summary: "repository merge could not create an integration commit", Tasks: tasks,
	}
	digest, err := auditDigest(request, []Finding{finding})
	if err != nil {
		return Audit{}, err
	}
	return Audit{
		IntegrationID: request.IntegrationID, ProjectID: request.ProjectID,
		Findings: []Finding{finding}, EvidenceSHA256: digest, CreatedAt: q.clock().UTC(),
	}, nil
}

func (q *Queue) reverifyReservation(ctx context.Context, request Request, reservation MergeResult) (VerifiedRequest, error) {
	verified, err := q.verify(ctx, request)
	if err != nil {
		return VerifiedRequest{}, err
	}
	digest, err := requestDigest(request, verified)
	if err != nil || digest != reservation.RequestDigest {
		return VerifiedRequest{}, ErrNotAudited
	}
	return verified, nil
}

func (q *Queue) completeRecovered(ctx context.Context, reservation MergeResult, commit string) (MergeResult, error) {
	if !commitID(commit) {
		return MergeResult{}, ErrMergeConflict
	}
	result := reservation
	result.Commit = commit
	result.Pending = false
	if err := q.store.Complete(ctx, result); err != nil {
		return MergeResult{}, err
	}
	return result, nil
}

func (q *Queue) verify(ctx context.Context, request Request) (VerifiedRequest, error) {
	if err := validateRequest(request); err != nil || request.CreatedAt.After(q.clock().UTC().Add(time.Minute)) {
		return VerifiedRequest{}, ErrInvalidRequest
	}
	verified, err := q.gate.Validate(ctx, cloneRequest(request))
	if err != nil {
		return VerifiedRequest{}, ErrNotAudited
	}
	if err := validateVerifiedRequest(verified); err != nil || !requestMatchesVerified(request, verified) {
		return VerifiedRequest{}, ErrNotAudited
	}
	return cloneVerifiedRequest(verified), nil
}

func validateRequest(request Request) error {
	if request.TenantID == "" || request.ProjectID == "" || request.IntegrationID == "" || request.IdempotencyKey == "" || strings.ContainsAny(request.IdempotencyKey, "\r\n\x00") || !commitID(request.BaseCommit) || len(request.Candidates) == 0 || !digestPattern(request.PolicyDigest) || request.ExpectedVersion < 1 || request.CreatedAt.IsZero() || request.PrincipalID == "" || request.LeaseID == "" || request.FencingToken < 1 || !validAttemptBinding(request.OwnerTaskID, request.Attempt) {
		return ErrInvalidRequest
	}
	seenTasks := make(map[string]bool, len(request.Candidates))
	for _, candidate := range request.Candidates {
		if candidate.TaskID == "" || candidate.ModuleID == "" || seenTasks[candidate.TaskID] || !commitID(candidate.SubmissionCommit) || candidate.ModuleSpecRef.Validate() != nil || !digestPattern(candidate.EvidenceSHA256) {
			return ErrInvalidRequest
		}
		seenTasks[candidate.TaskID] = true
	}
	if request.Attempt > 0 && !seenTasks[request.OwnerTaskID] {
		return ErrInvalidRequest
	}
	return nil
}

func validateVerifiedRequest(request VerifiedRequest) error {
	if request.TenantID == "" || request.ProjectID == "" || request.IntegrationID == "" || !commitID(request.BaseCommit) || len(request.Candidates) == 0 || !digestPattern(request.PolicyDigest) || request.ExpectedVersion < 1 || request.PrincipalID == "" || request.LeaseID == "" || request.FencingToken < 1 || !digestPattern(request.Authorization) || !validAttemptBinding(request.OwnerTaskID, request.Attempt) {
		return ErrInvalidRequest
	}
	seenTasks := make(map[string]bool, len(request.Candidates))
	for _, candidate := range request.Candidates {
		if candidate.TaskID == "" || candidate.ModuleID == "" || seenTasks[candidate.TaskID] || !commitID(candidate.SubmissionCommit) || candidate.ModuleSpecRef.Validate() != nil || !digestPattern(candidate.EvidenceSHA256) || !candidate.AuditPassed {
			return ErrInvalidRequest
		}
		seenTasks[candidate.TaskID] = true
	}
	if request.Attempt > 0 && !seenTasks[request.OwnerTaskID] {
		return ErrInvalidRequest
	}
	return nil
}

func auditDigest(request VerifiedRequest, findings []Finding) (string, error) {
	value, err := json.Marshal(struct {
		TenantID      string      `json:"tenantId"`
		IntegrationID string      `json:"integrationId"`
		ProjectID     string      `json:"projectId"`
		BaseCommit    string      `json:"baseCommit"`
		Candidates    []Candidate `json:"candidates"`
		Findings      []Finding   `json:"findings"`
		PolicyDigest  string      `json:"policyDigest"`
		StateVersion  int64       `json:"stateVersion"`
		Authorization string      `json:"authorization"`
		OwnerTaskID   string      `json:"ownerTaskId,omitempty"`
		Attempt       int         `json:"attempt"`
	}{request.TenantID, request.IntegrationID, request.ProjectID, request.BaseCommit, request.Candidates, findings, request.PolicyDigest, request.ExpectedVersion, request.Authorization, request.OwnerTaskID, request.Attempt})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(value)
}

func requestDigest(request Request, verified VerifiedRequest) (string, error) {
	candidates := canonicalCandidates(verified.Candidates)
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].TaskID != candidates[right].TaskID {
			return candidates[left].TaskID < candidates[right].TaskID
		}
		return candidates[left].ModuleID < candidates[right].ModuleID
	})
	value, err := json.Marshal(struct {
		TenantID        string      `json:"tenantId"`
		ProjectID       string      `json:"projectId"`
		IntegrationID   string      `json:"integrationId"`
		IdempotencyKey  string      `json:"idempotencyKey"`
		BaseCommit      string      `json:"baseCommit"`
		Candidates      []Candidate `json:"candidates"`
		PolicyDigest    string      `json:"policyDigest"`
		ExpectedVersion int64       `json:"expectedVersion"`
		CreatedAt       string      `json:"createdAt"`
		PrincipalID     string      `json:"principalId"`
		LeaseID         string      `json:"leaseId"`
		FencingToken    int64       `json:"fencingToken"`
		Authorization   string      `json:"authorization"`
		OwnerTaskID     string      `json:"ownerTaskId,omitempty"`
		Attempt         int         `json:"attempt"`
	}{verified.TenantID, verified.ProjectID, verified.IntegrationID, request.IdempotencyKey, verified.BaseCommit, candidates, verified.PolicyDigest, verified.ExpectedVersion, request.CreatedAt.UTC().Format(time.RFC3339Nano), verified.PrincipalID, verified.LeaseID, verified.FencingToken, verified.Authorization, verified.OwnerTaskID, verified.Attempt})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(value)
}

func requestMatchesVerified(request Request, verified VerifiedRequest) bool {
	return request.TenantID == verified.TenantID && request.ProjectID == verified.ProjectID && request.IntegrationID == verified.IntegrationID && request.BaseCommit == verified.BaseCommit && request.PolicyDigest == verified.PolicyDigest && request.ExpectedVersion == verified.ExpectedVersion && request.PrincipalID == verified.PrincipalID && request.LeaseID == verified.LeaseID && request.FencingToken == verified.FencingToken && request.OwnerTaskID == verified.OwnerTaskID && request.Attempt == verified.Attempt && reflect.DeepEqual(canonicalCandidates(request.Candidates), canonicalCandidates(verified.Candidates))
}

func validAttemptBinding(ownerTaskID string, attempt int) bool {
	return attempt == 0 && ownerTaskID == "" || attempt >= 1 && attempt <= 3 && ownerTaskID != ""
}

func conflictOwner(audit Audit, candidates []Candidate) string {
	allowed := make(map[string]bool, len(candidates))
	for _, candidate := range candidates {
		allowed[candidate.TaskID] = true
	}
	for _, finding := range audit.Findings {
		for index := len(finding.Tasks) - 1; index >= 0; index-- {
			if allowed[finding.Tasks[index]] {
				return finding.Tasks[index]
			}
		}
	}
	return ""
}

func canonicalCandidates(input []Candidate) []Candidate {
	result := cloneCandidates(input)
	for index := range result {
		sort.Strings(result[index].OwnedPaths)
		sort.Strings(result[index].PublicInterfaces)
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].TaskID != result[right].TaskID {
			return result[left].TaskID < result[right].TaskID
		}
		return result[left].ModuleID < result[right].ModuleID
	})
	return result
}

func cloneCandidates(input []Candidate) []Candidate {
	result := append([]Candidate(nil), input...)
	for index := range result {
		result[index].OwnedPaths = append([]string(nil), input[index].OwnedPaths...)
		result[index].PublicInterfaces = append([]string(nil), input[index].PublicInterfaces...)
	}
	return result
}

func cloneRequest(request Request) Request {
	request.Candidates = cloneCandidates(request.Candidates)
	return request
}

func cloneVerifiedRequest(request VerifiedRequest) VerifiedRequest {
	request.Candidates = cloneCandidates(request.Candidates)
	return request
}

func deduplicateFindings(input []Finding) []Finding {
	seen := make(map[string]bool, len(input))
	result := make([]Finding, 0, len(input))
	for _, finding := range input {
		if seen[finding.ID] {
			continue
		}
		seen[finding.ID] = true
		result = append(result, finding)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

func cleanPath(value string) (string, bool) {
	clean := path.Clean(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || clean != value || clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") || clean == ".git" || strings.HasPrefix(clean, ".git/") {
		return "", false
	}
	return clean, true
}

func containsPath(parent, child string) bool {
	return parent == child || strings.HasPrefix(child, parent+"/")
}

func commitID(value string) bool {
	if len(value) != 40 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestPattern(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
