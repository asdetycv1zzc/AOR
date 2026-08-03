// Package backup validates restored metadata before traffic is reopened.
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

var (
	ErrInvalidSnapshot   = errors.New("invalid backup snapshot")
	ErrDanglingReference = errors.New("backup contains a dangling reference")
	ErrArtifactIntegrity = errors.New("backup artifact integrity check failed")
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Snapshot struct {
	Version   int              `json:"version"`
	CreatedAt time.Time        `json:"createdAt"`
	Projects  []ProjectRecord  `json:"projects"`
	Goals     []GoalRecord     `json:"goals"`
	Plans     []PlanRecord     `json:"plans"`
	Tasks     []TaskRecord     `json:"tasks"`
	Audits    []AuditRecord    `json:"audits"`
	Artifacts []ArtifactRecord `json:"artifacts"`
}

type ProjectRecord struct {
	TenantID string `json:"tenantId"`
	ID       string `json:"id"`
}

type GoalRecord struct {
	TenantID  string `json:"tenantId"`
	ProjectID string `json:"projectId"`
	ID        string `json:"id"`
	Version   int    `json:"version"`
}

type PlanRecord struct {
	TenantID  string `json:"tenantId"`
	ProjectID string `json:"projectId"`
	ID        string `json:"id"`
	GoalID    string `json:"goalId"`
}

type TaskRecord struct {
	TenantID  string `json:"tenantId"`
	ProjectID string `json:"projectId"`
	ID        string `json:"id"`
	PlanID    string `json:"planId"`
}

type AuditRecord struct {
	TenantID    string   `json:"tenantId"`
	ProjectID   string   `json:"projectId"`
	ID          string   `json:"id"`
	TaskID      string   `json:"taskId"`
	ArtifactIDs []string `json:"artifactIds"`
}

type ArtifactRecord struct {
	TenantID  string `json:"tenantId"`
	ProjectID string `json:"projectId"`
	TaskID    string `json:"taskId"`
	ID        string `json:"id"`
	URI       string `json:"uri"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
}

type ArtifactVerifier interface {
	Verify(context.Context, ArtifactRecord) error
}

type Report struct {
	Projects  int
	Goals     int
	Plans     int
	Tasks     int
	Audits    int
	Artifacts int
	Digest    string
}

func (s Snapshot) Digest() (string, error) {
	encoded, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func Verify(ctx context.Context, snapshot Snapshot, artifacts ArtifactVerifier) (Report, error) {
	if ctx == nil || ctx.Err() != nil || artifacts == nil {
		return Report{}, ErrInvalidSnapshot
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Report{}, err
	}
	for _, artifact := range snapshot.Artifacts {
		if err := artifacts.Verify(ctx, artifact); err != nil {
			return Report{}, fmt.Errorf("%w: %s: %v", ErrArtifactIntegrity, artifact.ID, err)
		}
	}
	digest, err := snapshot.Digest()
	if err != nil {
		return Report{}, err
	}
	return Report{Projects: len(snapshot.Projects), Goals: len(snapshot.Goals), Plans: len(snapshot.Plans), Tasks: len(snapshot.Tasks), Audits: len(snapshot.Audits), Artifacts: len(snapshot.Artifacts), Digest: digest}, nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.Version < 1 || snapshot.CreatedAt.IsZero() {
		return ErrInvalidSnapshot
	}
	projects := make(map[string]struct{}, len(snapshot.Projects))
	for _, project := range snapshot.Projects {
		if project.TenantID == "" || project.ID == "" || !addUnique(projects, scopeKey(project.TenantID, project.ID)) {
			return ErrInvalidSnapshot
		}
	}
	goals := make(map[string]struct{}, len(snapshot.Goals))
	for _, goal := range snapshot.Goals {
		if goal.TenantID == "" || goal.ProjectID == "" || goal.ID == "" || goal.Version < 1 || !has(projects, goal.TenantID, goal.ProjectID) || !addUnique(goals, recordKey(goal.TenantID, goal.ProjectID, goal.ID)) {
			return ErrDanglingReference
		}
	}
	plans := make(map[string]struct{}, len(snapshot.Plans))
	for _, plan := range snapshot.Plans {
		if plan.TenantID == "" || plan.ProjectID == "" || plan.ID == "" || !has(projects, plan.TenantID, plan.ProjectID) || plan.GoalID != "" && !has(goals, plan.TenantID, plan.ProjectID, plan.GoalID) || !addUnique(plans, recordKey(plan.TenantID, plan.ProjectID, plan.ID)) {
			return ErrDanglingReference
		}
	}
	tasks := make(map[string]struct{}, len(snapshot.Tasks))
	for _, task := range snapshot.Tasks {
		if task.TenantID == "" || task.ProjectID == "" || task.ID == "" || !has(projects, task.TenantID, task.ProjectID) || task.PlanID != "" && !has(plans, task.TenantID, task.ProjectID, task.PlanID) || !addUnique(tasks, recordKey(task.TenantID, task.ProjectID, task.ID)) {
			return ErrDanglingReference
		}
	}
	artifacts := make(map[string]struct{}, len(snapshot.Artifacts))
	for _, artifact := range snapshot.Artifacts {
		if artifact.TenantID == "" || artifact.ProjectID == "" || artifact.ID == "" || artifact.URI == "" || !digestPattern.MatchString(artifact.SHA256) || artifact.Size < 0 || !has(projects, artifact.TenantID, artifact.ProjectID) || artifact.TaskID != "" && !has(tasks, artifact.TenantID, artifact.ProjectID, artifact.TaskID) || !addUnique(artifacts, recordKey(artifact.TenantID, artifact.ProjectID, artifact.ID)) {
			return ErrDanglingReference
		}
	}
	for _, audit := range snapshot.Audits {
		if audit.TenantID == "" || audit.ProjectID == "" || audit.ID == "" || !has(projects, audit.TenantID, audit.ProjectID) || audit.TaskID != "" && !has(tasks, audit.TenantID, audit.ProjectID, audit.TaskID) {
			return ErrDanglingReference
		}
		seen := make(map[string]struct{}, len(audit.ArtifactIDs))
		for _, artifactID := range audit.ArtifactIDs {
			if artifactID == "" || !addUnique(seen, artifactID) || !has(artifacts, audit.TenantID, audit.ProjectID, artifactID) {
				return ErrDanglingReference
			}
		}
	}
	return nil
}

func scopeKey(values ...string) string { return recordKey(values...) }

func recordKey(values ...string) string {
	return fmt.Sprintf("%q", values)
}

func addUnique(set map[string]struct{}, key string) bool {
	if _, found := set[key]; found {
		return false
	}
	set[key] = struct{}{}
	return true
}

func has(set map[string]struct{}, values ...string) bool {
	_, found := set[recordKey(values...)]
	return found
}

func SortedArtifactIDs(snapshot Snapshot) []string {
	ids := make([]string, 0, len(snapshot.Artifacts))
	for _, artifact := range snapshot.Artifacts {
		ids = append(ids, artifact.ID)
	}
	sort.Strings(ids)
	return ids
}
