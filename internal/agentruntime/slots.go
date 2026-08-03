package agentruntime

import (
	"context"
	"sync"
	"time"
)

const defaultAgingInterval = time.Minute

type SlotPool struct {
	mu            sync.Mutex
	limit         int
	active        int
	activeByGroup map[string]int
	softLimits    map[string]int
	waiters       []*slotWaiter
	clock         func() time.Time
	agingInterval time.Duration
}

type slotWaiter struct {
	role     Role
	group    string
	priority int
	enqueued time.Time
	granted  chan struct{}
	active   bool
}

type SlotPoolSnapshot struct {
	Limit         int
	Active        int
	ActiveByGroup map[string]int
	Waiting       int
}

func NewSlotPool(limit int, clock func() time.Time) (*SlotPool, error) {
	if limit <= 0 || limit > MaximumActiveAgentLimit {
		return nil, ErrActiveLimit
	}
	if clock == nil {
		clock = time.Now
	}
	return &SlotPool{
		limit: limit, activeByGroup: make(map[string]int), clock: clock, agingInterval: defaultAgingInterval,
		softLimits: map[string]int{"goal": 2, "plan": 4, "execution": 6, "audit": 4, "knowledge": 1},
	}, nil
}

func (p *SlotPool) Acquire(ctx context.Context, role Role, priority int) (func(), error) {
	if p == nil || !role.Valid() || priority < 0 {
		return nil, ErrActiveLimit
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if priority == 0 {
		priority = DefaultPriority(role)
	}
	waiter := &slotWaiter{role: role, group: roleGroup(role), priority: priority, enqueued: p.clock(), granted: make(chan struct{}, 1)}
	p.mu.Lock()
	p.waiters = append(p.waiters, waiter)
	p.dispatchLocked()
	p.mu.Unlock()

	select {
	case <-waiter.granted:
		var once sync.Once
		return func() {
			once.Do(func() { p.release(waiter) })
		}, nil
	case <-ctx.Done():
		p.mu.Lock()
		if waiter.active {
			p.releaseLocked(waiter)
		} else {
			p.removeWaiterLocked(waiter)
			p.dispatchLocked()
		}
		p.mu.Unlock()
		return nil, ctx.Err()
	}
}

func (p *SlotPool) Snapshot() SlotPoolSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	groups := make(map[string]int, len(p.activeByGroup))
	for key, value := range p.activeByGroup {
		groups[key] = value
	}
	return SlotPoolSnapshot{Limit: p.limit, Active: p.active, ActiveByGroup: groups, Waiting: len(p.waiters)}
}

func DefaultPriority(role Role) int {
	switch role {
	case RoleGoalProposer, RoleGoalChallenger:
		return 600
	case RoleModuleAuditor, RoleGlobalAuditor:
		return 500
	case RoleExecutor:
		return 400
	case RolePlanSupervisor, RoleModulePlanner:
		return 300
	case RoleKnowledgeCurator:
		return 100
	default:
		return 0
	}
}

func (p *SlotPool) dispatchLocked() {
	for p.active < p.limit && len(p.waiters) > 0 {
		index := p.nextWaiterLocked()
		waiter := p.waiters[index]
		p.waiters = append(p.waiters[:index], p.waiters[index+1:]...)
		waiter.active = true
		p.active++
		p.activeByGroup[waiter.group]++
		waiter.granted <- struct{}{}
	}
}

func (p *SlotPool) nextWaiterLocked() int {
	preferUnderSoft := false
	for _, waiter := range p.waiters {
		if p.activeByGroup[waiter.group] < p.softLimits[waiter.group] {
			preferUnderSoft = true
			break
		}
	}
	now := p.clock()
	selected := -1
	selectedPriority := 0
	for index, waiter := range p.waiters {
		underSoft := p.activeByGroup[waiter.group] < p.softLimits[waiter.group]
		if preferUnderSoft && !underSoft {
			continue
		}
		effective := waiter.priority
		if p.agingInterval > 0 {
			waited := now.Sub(waiter.enqueued)
			if waited > 0 {
				effective += int(waited / p.agingInterval)
			}
		}
		if selected == -1 || effective > selectedPriority || effective == selectedPriority && waiter.enqueued.Before(p.waiters[selected].enqueued) {
			selected = index
			selectedPriority = effective
		}
	}
	if selected < 0 {
		return 0
	}
	return selected
}

func (p *SlotPool) release(waiter *slotWaiter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.releaseLocked(waiter)
}

func (p *SlotPool) releaseLocked(waiter *slotWaiter) {
	if !waiter.active {
		return
	}
	waiter.active = false
	p.active--
	p.activeByGroup[waiter.group]--
	p.dispatchLocked()
}

func (p *SlotPool) removeWaiterLocked(expected *slotWaiter) {
	for index, waiter := range p.waiters {
		if waiter == expected {
			p.waiters = append(p.waiters[:index], p.waiters[index+1:]...)
			return
		}
	}
}

func roleGroup(role Role) string {
	switch role {
	case RoleGoalProposer, RoleGoalChallenger:
		return "goal"
	case RolePlanSupervisor, RoleModulePlanner:
		return "plan"
	case RoleExecutor:
		return "execution"
	case RoleModuleAuditor, RoleGlobalAuditor:
		return "audit"
	case RoleKnowledgeCurator:
		return "knowledge"
	default:
		return "unknown"
	}
}
