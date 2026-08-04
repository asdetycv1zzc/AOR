package a2a

import (
	"context"
	"errors"
	"sort"
	"sync"
)

type TaskStore interface {
	Put(context.Context, Task) error
	Get(context.Context, string) (Task, bool, error)
	List(context.Context) ([]Task, error)
}

// MemoryTaskStore is a small, concurrency-safe TaskStore suitable for local
// protocol tests and single-process development. Production deployments can
// mirror the same snapshots into their durable workflow store.
type MemoryTaskStore struct {
	mu    sync.RWMutex
	tasks map[string]Task
}

func NewMemoryTaskStore() *MemoryTaskStore {
	return &MemoryTaskStore{tasks: make(map[string]Task)}
}

func (store *MemoryTaskStore) Put(ctx context.Context, task Task) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := task.Validate(); err != nil {
		return err
	}
	if store == nil {
		return errors.New("nil A2A task store")
	}
	store.mu.Lock()
	store.tasks[task.ID] = cloneTask(task)
	store.mu.Unlock()
	return nil
}

func (store *MemoryTaskStore) Get(ctx context.Context, id string) (Task, bool, error) {
	if err := contextErr(ctx); err != nil {
		return Task{}, false, err
	}
	if store == nil || id == "" {
		return Task{}, false, nil
	}
	store.mu.RLock()
	task, ok := store.tasks[id]
	store.mu.RUnlock()
	if !ok {
		return Task{}, false, nil
	}
	return cloneTask(task), true, nil
}

func (store *MemoryTaskStore) List(ctx context.Context) ([]Task, error) {
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("nil A2A task store")
	}
	store.mu.RLock()
	result := make([]Task, 0, len(store.tasks))
	for _, task := range store.tasks {
		result = append(result, cloneTask(task))
	}
	store.mu.RUnlock()
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result, nil
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
