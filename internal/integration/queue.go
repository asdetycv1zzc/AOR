package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type Queue struct {
	store    Store
	executor MergeExecutor
	clock    func() time.Time
}

func NewQueue(store Store, executor MergeExecutor, clock func() time.Time) (*Queue, error) {
	if store == nil || executor == nil {
		return nil, ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	return &Queue{store: store, executor: executor, clock: clock}, nil
}

func (q *Queue) Audit(ctx context.Context, request Request) (Audit, error) {
	if err := validateRequest(request); err != nil {
		return Audit{}, err
	}
	candidates := append([]Candidate(nil), request.Candidates...)
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
	if err := validateRequest(request); err != nil {
		return MergeResult{}, err
	}
	requestDigest, err := requestDigest(request)
	if err != nil {
		return MergeResult{}, err
	}
	if prior, found, err := q.store.Get(ctx, request.TenantID, request.IntegrationID); err != nil {
		return MergeResult{}, err
	} else if found {
		if prior.RequestDigest != requestDigest {
			return MergeResult{}, ErrImmutable
		}
		return MergeResult{TenantID: prior.TenantID, IntegrationID: prior.IntegrationID, ProjectID: prior.ProjectID, Commit: prior.Commit, RequestDigest: prior.RequestDigest, Audit: prior.Audit, Duplicate: true}, nil
	}
	audit, err := q.Audit(ctx, request)
	if err != nil {
		return MergeResult{}, err
	}
	if !audit.Passed {
		return MergeResult{TenantID: request.TenantID, IntegrationID: request.IntegrationID, ProjectID: request.ProjectID, Audit: audit}, ErrConflict
	}
	commits := make([]string, 0, len(request.Candidates))
	for _, candidate := range request.Candidates {
		commits = append(commits, candidate.SubmissionCommit)
	}
	sort.Strings(commits)
	commit, err := q.executor.Merge(ctx, request.BaseCommit, commits, request.IntegrationID)
	if err != nil {
		return MergeResult{TenantID: request.TenantID, IntegrationID: request.IntegrationID, ProjectID: request.ProjectID, Audit: audit}, fmt.Errorf("%w: %v", ErrMergeConflict, err)
	}
	if !commitID(commit) {
		return MergeResult{}, ErrMergeConflict
	}
	result := MergeResult{TenantID: request.TenantID, IntegrationID: request.IntegrationID, ProjectID: request.ProjectID, Commit: commit, RequestDigest: requestDigest, Audit: audit}
	if err := q.store.Put(ctx, result); err != nil {
		return MergeResult{}, err
	}
	return result, nil
}

func validateRequest(request Request) error {
	if request.TenantID == "" || request.ProjectID == "" || request.IntegrationID == "" || request.IdempotencyKey == "" || !commitID(request.BaseCommit) || len(request.Candidates) == 0 || !digestPattern(request.PolicyDigest) {
		return ErrInvalidRequest
	}
	seenTasks := make(map[string]bool, len(request.Candidates))
	for _, candidate := range request.Candidates {
		if candidate.TaskID == "" || candidate.ModuleID == "" || seenTasks[candidate.TaskID] || !commitID(candidate.SubmissionCommit) || candidate.ModuleSpecRef.Validate() != nil || !digestPattern(candidate.EvidenceSHA256) {
			return ErrInvalidRequest
		}
		seenTasks[candidate.TaskID] = true
	}
	return nil
}

func auditDigest(request Request, findings []Finding) (string, error) {
	value, err := json.Marshal(struct {
		IntegrationID string      `json:"integrationId"`
		ProjectID     string      `json:"projectId"`
		BaseCommit    string      `json:"baseCommit"`
		Candidates    []Candidate `json:"candidates"`
		Findings      []Finding   `json:"findings"`
	}{request.IntegrationID, request.ProjectID, request.BaseCommit, request.Candidates, findings})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(value)
}

func requestDigest(request Request) (string, error) {
	candidates := append([]Candidate(nil), request.Candidates...)
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].TaskID != candidates[right].TaskID {
			return candidates[left].TaskID < candidates[right].TaskID
		}
		return candidates[left].ModuleID < candidates[right].ModuleID
	})
	value, err := json.Marshal(struct {
		TenantID       string      `json:"tenantId"`
		ProjectID      string      `json:"projectId"`
		IntegrationID  string      `json:"integrationId"`
		IdempotencyKey string      `json:"idempotencyKey"`
		BaseCommit     string      `json:"baseCommit"`
		Candidates     []Candidate `json:"candidates"`
	}{request.TenantID, request.ProjectID, request.IntegrationID, request.IdempotencyKey, request.BaseCommit, candidates})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(value)
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
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func digestPattern(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
