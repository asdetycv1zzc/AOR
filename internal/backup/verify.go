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
	encoded, err := json.Marshal(canonicalSnapshot(s))
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func Verify(ctx context.Context, snapshot Snapshot, artifacts ArtifactVerifier) (Report, error) {
	if ctx == nil || artifacts == nil {
		return Report{}, ErrInvalidSnapshot
	}
	if err := ctx.Err(); err != nil {
		return Report{}, err
	}
	if err := validateSnapshot(snapshot); err != nil {
		return Report{}, err
	}
	for _, artifact := range snapshot.Artifacts {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
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
	audits := make(map[string]struct{}, len(snapshot.Audits))
	for _, audit := range snapshot.Audits {
		if audit.TenantID == "" || audit.ProjectID == "" || audit.ID == "" || !has(projects, audit.TenantID, audit.ProjectID) || audit.TaskID != "" && !has(tasks, audit.TenantID, audit.ProjectID, audit.TaskID) || !addUnique(audits, recordKey(audit.TenantID, audit.ProjectID, audit.ID)) {
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

// canonicalSnapshot returns a detached, deterministically ordered copy of a
// restored graph. Backup exports can be produced by different query plans, so
// row order must not change the evidence digest.
func canonicalSnapshot(snapshot Snapshot) Snapshot {
	canonical := snapshot
	canonical.CreatedAt = snapshot.CreatedAt.UTC()
	canonical.Projects = append([]ProjectRecord(nil), snapshot.Projects...)
	canonical.Goals = append([]GoalRecord(nil), snapshot.Goals...)
	canonical.Plans = append([]PlanRecord(nil), snapshot.Plans...)
	canonical.Tasks = append([]TaskRecord(nil), snapshot.Tasks...)
	canonical.Audits = make([]AuditRecord, len(snapshot.Audits))
	copy(canonical.Audits, snapshot.Audits)
	canonical.Artifacts = append([]ArtifactRecord(nil), snapshot.Artifacts...)
	sort.Slice(canonical.Projects, func(i, j int) bool {
		return compareStrings(canonical.Projects[i].TenantID, canonical.Projects[j].TenantID, canonical.Projects[i].ID, canonical.Projects[j].ID)
	})
	sort.Slice(canonical.Goals, func(i, j int) bool {
		return compareStrings(canonical.Goals[i].TenantID, canonical.Goals[j].TenantID, canonical.Goals[i].ProjectID, canonical.Goals[j].ProjectID, canonical.Goals[i].ID, canonical.Goals[j].ID)
	})
	sort.Slice(canonical.Plans, func(i, j int) bool {
		return compareStrings(canonical.Plans[i].TenantID, canonical.Plans[j].TenantID, canonical.Plans[i].ProjectID, canonical.Plans[j].ProjectID, canonical.Plans[i].ID, canonical.Plans[j].ID)
	})
	sort.Slice(canonical.Tasks, func(i, j int) bool {
		return compareStrings(canonical.Tasks[i].TenantID, canonical.Tasks[j].TenantID, canonical.Tasks[i].ProjectID, canonical.Tasks[j].ProjectID, canonical.Tasks[i].ID, canonical.Tasks[j].ID)
	})
	for index := range canonical.Audits {
		canonical.Audits[index].ArtifactIDs = append([]string(nil), canonical.Audits[index].ArtifactIDs...)
		sort.Strings(canonical.Audits[index].ArtifactIDs)
	}
	sort.Slice(canonical.Audits, func(i, j int) bool {
		return compareStrings(canonical.Audits[i].TenantID, canonical.Audits[j].TenantID, canonical.Audits[i].ProjectID, canonical.Audits[j].ProjectID, canonical.Audits[i].ID, canonical.Audits[j].ID)
	})
	sort.Slice(canonical.Artifacts, func(i, j int) bool {
		return compareStrings(canonical.Artifacts[i].TenantID, canonical.Artifacts[j].TenantID, canonical.Artifacts[i].ProjectID, canonical.Artifacts[j].ProjectID, canonical.Artifacts[i].ID, canonical.Artifacts[j].ID)
	})
	return canonical
}

func compareStrings(left ...string) bool {
	if len(left)%2 != 0 {
		return false
	}
	for index := 0; index < len(left); index += 2 {
		if left[index] == left[index+1] {
			continue
		}
		return left[index] < left[index+1]
	}
	return false
}

func SortedArtifactIDs(snapshot Snapshot) []string {
	ids := make([]string, 0, len(snapshot.Artifacts))
	for _, artifact := range snapshot.Artifacts {
		ids = append(ids, artifact.ID)
	}
	sort.Strings(ids)
	return ids
}
