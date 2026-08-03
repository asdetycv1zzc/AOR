package deployment

import (
	"errors"
	"regexp"
	"sync"
	"time"
)

var (
	ErrRolloutInvalid  = errors.New("invalid configuration rollout")
	ErrRolloutBusy     = errors.New("configuration rollout already pending")
	ErrRolloutExpired  = errors.New("configuration rollout expired")
	ErrRolloutNotFound = errors.New("configuration rollout not found")
)

var rolloutIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var rolloutDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Revision struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

type RolloutState string

const (
	RolloutStarted    RolloutState = "STARTED"
	RolloutCommitted  RolloutState = "COMMITTED"
	RolloutRolledBack RolloutState = "ROLLED_BACK"
)

type RolloutEvent struct {
	RevisionID string       `json:"revisionId"`
	State      RolloutState `json:"state"`
	Reason     string       `json:"reason,omitempty"`
	At         time.Time    `json:"at"`
}

type pendingRollout struct {
	Revision Revision
	Deadline time.Time
}

type RolloutManager struct {
	mu       sync.Mutex
	clock    func() time.Time
	timeout  time.Duration
	active   Revision
	previous Revision
	pending  *pendingRollout
	history  []RolloutEvent
}

func NewRolloutManager(initial Revision, timeout time.Duration, clock func() time.Time) (*RolloutManager, error) {
	if !validRevision(initial) || timeout <= 0 || timeout > 15*time.Minute {
		return nil, ErrRolloutInvalid
	}
	if clock == nil {
		clock = time.Now
	}
	return &RolloutManager{clock: clock, timeout: timeout, active: initial, history: []RolloutEvent{}}, nil
}

func (m *RolloutManager) Start(revision Revision) error {
	if m == nil || !validRevision(revision) {
		return ErrRolloutInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked()
	if m.pending != nil {
		return ErrRolloutBusy
	}
	if revision.ID == m.active.ID || revision.Digest == m.active.Digest {
		return ErrRolloutInvalid
	}
	now := m.clock().UTC()
	m.pending = &pendingRollout{Revision: revision, Deadline: now.Add(m.timeout)}
	m.history = append(m.history, RolloutEvent{RevisionID: revision.ID, State: RolloutStarted, At: now})
	return nil
}

func (m *RolloutManager) Commit(revisionID string) error {
	if m == nil || !rolloutIDPattern.MatchString(revisionID) {
		return ErrRolloutInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked()
	if m.pending == nil || m.pending.Revision.ID != revisionID {
		return ErrRolloutNotFound
	}
	now := m.clock().UTC()
	m.previous, m.active = m.active, m.pending.Revision
	m.pending = nil
	m.history = append(m.history, RolloutEvent{RevisionID: revisionID, State: RolloutCommitted, At: now})
	return nil
}

func (m *RolloutManager) Rollback(revisionID, reason string) error {
	if m == nil || !rolloutIDPattern.MatchString(revisionID) || reason == "" {
		return ErrRolloutInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked()
	if m.active.ID != revisionID || m.previous.ID == "" {
		return ErrRolloutNotFound
	}
	now := m.clock().UTC()
	m.active, m.previous = m.previous, m.active
	m.history = append(m.history, RolloutEvent{RevisionID: revisionID, State: RolloutRolledBack, Reason: reason, At: now})
	return nil
}

func (m *RolloutManager) Active() Revision {
	if m == nil {
		return Revision{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked()
	return m.active
}

func (m *RolloutManager) Pending() (Revision, time.Time, bool) {
	if m == nil {
		return Revision{}, time.Time{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked()
	if m.pending == nil {
		return Revision{}, time.Time{}, false
	}
	return m.pending.Revision, m.pending.Deadline, true
}

func (m *RolloutManager) History() []RolloutEvent {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]RolloutEvent(nil), m.history...)
}

func (m *RolloutManager) reconcileLocked() {
	if m.pending == nil || m.clock().UTC().Before(m.pending.Deadline) {
		return
	}
	now := m.clock().UTC()
	m.history = append(m.history, RolloutEvent{RevisionID: m.pending.Revision.ID, State: RolloutRolledBack, Reason: ErrRolloutExpired.Error(), At: now})
	m.pending = nil
}

func validRevision(revision Revision) bool {
	return rolloutIDPattern.MatchString(revision.ID) && rolloutDigestPattern.MatchString(revision.Digest)
}
