package deployment

import (
	"errors"
	"regexp"
	"sync"
	"time"
)

var (
	ErrRolloutInvalid   = errors.New("invalid configuration rollout")
	ErrRolloutBusy      = errors.New("configuration rollout already pending")
	ErrRolloutExpired   = errors.New("configuration rollout expired")
	ErrRolloutUnhealthy = errors.New("configuration rollout health check failed")
	ErrRolloutApply     = errors.New("configuration apply failed")
	ErrRolloutNotFound  = errors.New("configuration rollout not found")
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
	OldDigest  string       `json:"oldDigest"`
	NewDigest  string       `json:"newDigest"`
	State      RolloutState `json:"state"`
	Reason     string       `json:"reason,omitempty"`
	At         time.Time    `json:"at"`
}

type ConfigurationApplier func(Revision) error
type ConfigurationHealthCheck func(Revision) error

type pendingRollout struct {
	Revision   Revision
	Previous   Revision
	Deadline   time.Time
	Generation uint64
}

type RolloutManager struct {
	mu             sync.Mutex
	clock          func() time.Time
	timeout        time.Duration
	apply          ConfigurationApplier
	health         ConfigurationHealthCheck
	healthInterval time.Duration
	active         Revision
	previous       Revision
	pending        *pendingRollout
	history        []RolloutEvent
	timer          *time.Timer
	generation     uint64
	lastErr        error
}

// NewRolloutManager retains the in-memory configuration model used by callers
// that do not own a live configuration target.
func NewRolloutManager(initial Revision, timeout time.Duration, clock func() time.Time) (*RolloutManager, error) {
	return newRolloutManager(initial, timeout, clock, func(Revision) error { return nil }, nil, 0)
}

// NewOperationalRolloutManager applies revisions to a live configuration target
// and automatically restores the previous revision on failed health or expiry.
func NewOperationalRolloutManager(
	initial Revision,
	timeout time.Duration,
	clock func() time.Time,
	apply ConfigurationApplier,
	health ConfigurationHealthCheck,
	healthInterval time.Duration,
) (*RolloutManager, error) {
	if apply == nil || health == nil || healthInterval <= 0 || healthInterval > timeout {
		return nil, ErrRolloutInvalid
	}
	return newRolloutManager(initial, timeout, clock, apply, health, healthInterval)
}

func newRolloutManager(
	initial Revision,
	timeout time.Duration,
	clock func() time.Time,
	apply ConfigurationApplier,
	health ConfigurationHealthCheck,
	healthInterval time.Duration,
) (*RolloutManager, error) {
	if !validRevision(initial) || timeout <= 0 || timeout > 15*time.Minute || apply == nil {
		return nil, ErrRolloutInvalid
	}
	if clock == nil {
		clock = time.Now
	}
	return &RolloutManager{
		clock:          clock,
		timeout:        timeout,
		apply:          apply,
		health:         health,
		healthInterval: healthInterval,
		active:         initial,
		history:        []RolloutEvent{},
	}, nil
}

func (m *RolloutManager) Start(revision Revision) error {
	if m == nil || !validRevision(revision) {
		return ErrRolloutInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked(true)
	if m.pending != nil {
		return ErrRolloutBusy
	}
	if revision.ID == m.active.ID || revision.Digest == m.active.Digest {
		return ErrRolloutInvalid
	}
	previous := m.active
	if err := m.apply(revision); err != nil {
		m.lastErr = ErrRolloutApply
		return ErrRolloutApply
	}
	now := m.clock().UTC()
	m.generation++
	m.active = revision
	m.pending = &pendingRollout{
		Revision:   revision,
		Previous:   previous,
		Deadline:   now.Add(m.timeout),
		Generation: m.generation,
	}
	m.lastErr = nil
	m.appendEventLocked(revision.ID, previous.Digest, revision.Digest, RolloutStarted, "", now)
	m.scheduleLocked()
	return nil
}

func (m *RolloutManager) Commit(revisionID string) error {
	if m == nil || !rolloutIDPattern.MatchString(revisionID) {
		return ErrRolloutInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked(true)
	if m.pending == nil || m.pending.Revision.ID != revisionID {
		return ErrRolloutNotFound
	}
	now := m.clock().UTC()
	old := m.pending.Previous
	current := m.pending.Revision
	m.previous = old
	m.pending = nil
	m.stopTimerLocked()
	m.lastErr = nil
	m.appendEventLocked(revisionID, old.Digest, current.Digest, RolloutCommitted, "", now)
	return nil
}

func (m *RolloutManager) Rollback(revisionID, reason string) error {
	if m == nil || !rolloutIDPattern.MatchString(revisionID) || reason == "" {
		return ErrRolloutInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked(true)
	if m.pending != nil && m.pending.Revision.ID == revisionID {
		return m.restorePendingLocked(reason, m.clock().UTC())
	}
	if m.active.ID != revisionID || m.previous.ID == "" {
		return ErrRolloutNotFound
	}
	now := m.clock().UTC()
	current, restore := m.active, m.previous
	if err := m.apply(restore); err != nil {
		m.lastErr = ErrRolloutApply
		return ErrRolloutApply
	}
	m.active, m.previous = restore, current
	m.lastErr = nil
	m.appendEventLocked(revisionID, current.Digest, restore.Digest, RolloutRolledBack, reason, now)
	return nil
}

func (m *RolloutManager) Active() Revision {
	if m == nil {
		return Revision{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked(true)
	return m.active
}

func (m *RolloutManager) Pending() (Revision, time.Time, bool) {
	if m == nil {
		return Revision{}, time.Time{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reconcileLocked(true)
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

func (m *RolloutManager) LastError() error {
	if m == nil {
		return ErrRolloutInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErr
}

func (m *RolloutManager) reconcileLocked(checkHealth bool) {
	if m.pending == nil {
		return
	}
	now := m.clock().UTC()
	if !now.Before(m.pending.Deadline) {
		if err := m.restorePendingLocked(ErrRolloutExpired.Error(), now); err != nil {
			m.scheduleLocked()
		}
		return
	}
	if checkHealth && m.health != nil {
		if err := m.health(m.pending.Revision); err != nil {
			if restoreErr := m.restorePendingLocked(ErrRolloutUnhealthy.Error(), now); restoreErr != nil {
				m.scheduleLocked()
			}
			return
		}
	}
	m.lastErr = nil
	m.scheduleLocked()
}

func (m *RolloutManager) restorePendingLocked(reason string, now time.Time) error {
	if m.pending == nil {
		return ErrRolloutNotFound
	}
	current, restore := m.pending.Revision, m.pending.Previous
	if err := m.apply(restore); err != nil {
		m.lastErr = ErrRolloutApply
		return ErrRolloutApply
	}
	m.active = restore
	m.previous = current
	m.pending = nil
	m.stopTimerLocked()
	m.lastErr = nil
	m.appendEventLocked(current.ID, current.Digest, restore.Digest, RolloutRolledBack, reason, now)
	return nil
}

func (m *RolloutManager) appendEventLocked(revisionID, oldDigest, newDigest string, state RolloutState, reason string, at time.Time) {
	m.history = append(m.history, RolloutEvent{
		RevisionID: revisionID,
		OldDigest:  oldDigest,
		NewDigest:  newDigest,
		State:      state,
		Reason:     reason,
		At:         at,
	})
}

func (m *RolloutManager) scheduleLocked() {
	if m.pending == nil {
		m.stopTimerLocked()
		return
	}
	delay := m.pending.Deadline.Sub(m.clock().UTC())
	if m.health != nil && m.healthInterval < delay {
		delay = m.healthInterval
	}
	if delay <= 0 {
		delay = time.Second
		if m.healthInterval > 0 && m.healthInterval < delay {
			delay = m.healthInterval
		}
	}
	generation := m.pending.Generation
	m.stopTimerLocked()
	m.timer = time.AfterFunc(delay, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.pending == nil || m.pending.Generation != generation {
			return
		}
		m.timer = nil
		m.reconcileLocked(true)
	})
}

func (m *RolloutManager) stopTimerLocked() {
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
}

func validRevision(revision Revision) bool {
	return rolloutIDPattern.MatchString(revision.ID) && rolloutDigestPattern.MatchString(revision.Digest)
}
