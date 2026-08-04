package orchestrator

import (
	"context"

	"github.com/akimisaka/aor/internal/eventing"
	"github.com/akimisaka/aor/internal/state"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

func (s *Service) Project(ctx context.Context, tenantID, projectID string) (state.Project, bool, error) {
	if tenantID == "" || projectID == "" {
		return state.Project{}, false, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "project query"})
	}
	projection, found, err := s.store.Load(ctx, tenantID, "project", projectID)
	if err != nil || !found {
		return state.Project{}, found, err
	}
	project, err := decodeProject(projection.State)
	if err != nil {
		return state.Project{}, false, err
	}
	if project.TenantID != tenantID || project.ID != projectID {
		return state.Project{}, false, aorerrors.New(aorerrors.CodeForbidden, "", nil)
	}
	return project, true, nil
}

func (s *Service) Task(ctx context.Context, tenantID, projectID, taskID string) (state.ModuleTask, bool, error) {
	if tenantID == "" || projectID == "" || taskID == "" {
		return state.ModuleTask{}, false, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "task query"})
	}
	projection, found, err := s.store.Load(ctx, tenantID, "task", taskID)
	if err != nil || !found {
		return state.ModuleTask{}, found, err
	}
	task, err := decodeTask(projection.State)
	if err != nil {
		return state.ModuleTask{}, false, err
	}
	if task.TenantID != tenantID || task.ProjectID != projectID || task.ID != taskID {
		return state.ModuleTask{}, false, aorerrors.New(aorerrors.CodeForbidden, "", nil)
	}
	return task, true, nil
}

func (s *Service) Tasks(ctx context.Context, tenantID, projectID string) ([]state.ModuleTask, error) {
	lister, ok := s.store.(eventing.ProjectionList)
	if !ok {
		return nil, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "projection list"})
	}
	projections, err := lister.ListProjections(ctx, tenantID, projectID, "task")
	if err != nil {
		return nil, err
	}
	tasks := make([]state.ModuleTask, 0, len(projections))
	for _, projection := range projections {
		task, decodeErr := decodeTask(projection.State)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if task.TenantID != tenantID || task.ProjectID != projectID || task.ID != projection.AggregateID {
			return nil, aorerrors.New(aorerrors.CodeInternalError, "", map[string]any{"scope": "task projection"})
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}
