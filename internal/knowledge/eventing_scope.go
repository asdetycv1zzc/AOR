package knowledge

import (
	"context"
	"encoding/json"

	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type EventingScopeResolver struct {
	store eventing.Store
}

func NewEventingScopeResolver(store eventing.Store) (*EventingScopeResolver, error) {
	if store == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge scope resolver"})
	}
	return &EventingScopeResolver{store: store}, nil
}

func (resolver *EventingScopeResolver) ResolveProject(ctx context.Context, tenantID, projectID string) (authz.ProjectScope, error) {
	if resolver == nil || resolver.store == nil || ctx == nil || tenantID == "" || projectID == "" {
		return authz.ProjectScope{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge project"})
	}
	projection, found, err := resolver.store.Load(ctx, tenantID, "project", projectID)
	if err != nil {
		return authz.ProjectScope{}, err
	}
	if !found {
		return authz.ProjectScope{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	var project state.Project
	if projection.TenantID != tenantID || projection.ProjectID != projectID || projection.AggregateType != "project" || projection.AggregateID != projectID || json.Unmarshal(projection.State, &project) != nil || project.TenantID != tenantID || project.ID != projectID || project.Version != projection.Version {
		return authz.ProjectScope{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	return authz.ProjectScope{TenantID: tenantID, ID: projectID, State: string(project.State), StateVersion: project.Version, Classification: project.DataClassification}, nil
}

func (resolver *EventingScopeResolver) ResolveTask(ctx context.Context, tenantID, projectID, taskID string) (authz.TaskScope, error) {
	if resolver == nil || resolver.store == nil || ctx == nil || tenantID == "" || projectID == "" || taskID == "" {
		return authz.TaskScope{}, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "knowledge task"})
	}
	projection, found, err := resolver.store.Load(ctx, tenantID, "task", taskID)
	if err != nil {
		return authz.TaskScope{}, err
	}
	if !found {
		return authz.TaskScope{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	var task state.ModuleTask
	if projection.TenantID != tenantID || projection.ProjectID != projectID || projection.AggregateType != "task" || projection.AggregateID != taskID || json.Unmarshal(projection.State, &task) != nil || task.TenantID != tenantID || task.ProjectID != projectID || task.ID != taskID || task.Version != projection.Version {
		return authz.TaskScope{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	return authz.TaskScope{TenantID: tenantID, ProjectID: projectID, ID: taskID, State: string(task.State), StateVersion: task.Version, SpecDigest: task.ModuleSpecRef.SHA256}, nil
}

var _ ScopeResolver = (*EventingScopeResolver)(nil)
