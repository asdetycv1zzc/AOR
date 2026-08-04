package modelgateway

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/akimisaka/aor/internal/observability"
)

const defaultReservationTTL = 24 * time.Hour

type BudgetAccount struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenantId"`
	ScopeType       string     `json:"scopeType"`
	ScopeID         string     `json:"scopeId"`
	Currency        string     `json:"currency"`
	LimitMicros     int64      `json:"hardLimitMinor"`
	SoftLimitMicros int64      `json:"softLimitMinor"`
	ReservedMicros  int64      `json:"reservedMinor"`
	SpentMicros     int64      `json:"spentMinor"`
	PeriodStart     time.Time  `json:"periodStart"`
	PeriodEnd       *time.Time `json:"periodEnd,omitempty"`
	Version         int64      `json:"version"`
}

// BudgetUsage is the tenant- and project-scoped usage snapshot exposed by the
// control plane. Cost values use the ledger's integer micro/minor unit and are
// never represented as floating point numbers.
type BudgetUsage struct {
	AccountID        string `json:"accountId"`
	Currency         string `json:"currency"`
	HardLimitMicros  int64  `json:"hardLimitMinor"`
	SoftLimitMicros  int64  `json:"softLimitMinor"`
	SpentMicros      int64  `json:"spentMinor"`
	ReservedMicros   int64  `json:"reservedMinor"`
	RemainingMicros  int64  `json:"remainingMinor"`
	Version          int64  `json:"version"`
	ReservationCount int64  `json:"reservationCount"`
	CallCount        int64  `json:"callCount"`
	InputTokens      int64  `json:"inputTokens"`
	OutputTokens     int64  `json:"outputTokens"`
	CostMicros       int64  `json:"costMinor"`
}

type BudgetAdjustment struct {
	TenantID        string
	ProjectID       string
	PrincipalID     string
	IdempotencyKey  string
	Traceparent     string
	Tracestate      string
	PolicyVersion   string
	PolicyRuleID    string
	PolicyDecision  string
	PolicyReasons   []string
	ParameterDigest string
	ProjectState    string
	ProjectVersion  int64
	ExpectedVersion int64
	HardLimitMicros int64
	SoftLimitMicros int64
	Currency        string
	Reason          string
}

type BudgetAdjustmentResult struct {
	Account   BudgetAccount `json:"account"`
	Usage     BudgetUsage   `json:"usage"`
	Duplicate bool          `json:"-"`
}

type BudgetAdministration interface {
	ListAccounts(context.Context, string, string) ([]BudgetAccount, error)
	Usage(context.Context, string, string) (BudgetUsage, error)
	Adjust(context.Context, BudgetAdjustment) (BudgetAdjustmentResult, error)
}

type ReservationState string

const (
	ReservationOpen      ReservationState = "RESERVED"
	ReservationSettled   ReservationState = "SETTLED"
	ReservationReleased  ReservationState = "RELEASED"
	ReservationReconcile ReservationState = "RECONCILE"
)

type Reservation struct {
	ID             string
	TenantID       string
	AccountID      string
	RequestID      string
	ReservedMicros int64
	SettledMicros  int64
	State          ReservationState
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

type BudgetLedgerBackend interface {
	Reserve(context.Context, string, string, string, string, int64) (Reservation, error)
	Settle(context.Context, string, string, int64) (Reservation, error)
	Release(context.Context, string, string) error
	Reconcile(context.Context, string, string, int64) (Reservation, error)
	RequireReconciliation(context.Context, string, string) (Reservation, error)
}

type BudgetLedger struct {
	mu             sync.Mutex
	accounts       map[string]BudgetAccount
	reservations   map[string]Reservation
	adjustments    map[string]memoryBudgetAdjustment
	modelCalls     map[string]ModelCall
	clock          func() time.Time
	reservationTTL time.Duration
}

type memoryBudgetAdjustment struct {
	request BudgetAdjustment
	result  BudgetAdjustmentResult
}

func NewBudgetLedger(clock func() time.Time) *BudgetLedger {
	if clock == nil {
		clock = time.Now
	}
	return &BudgetLedger{accounts: make(map[string]BudgetAccount), reservations: make(map[string]Reservation), adjustments: make(map[string]memoryBudgetAdjustment), modelCalls: make(map[string]ModelCall), clock: clock, reservationTTL: defaultReservationTTL}
}

func (l *BudgetLedger) CreateAccount(ctx context.Context, account BudgetAccount) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if account.ID == "" || account.TenantID == "" || account.LimitMicros < 0 || account.SoftLimitMicros < 0 || account.SoftLimitMicros > account.LimitMicros || account.ReservedMicros < 0 || account.SpentMicros < 0 || account.ReservedMicros > account.LimitMicros-account.SpentMicros {
		return ErrInvalidRequest
	}
	if account.ScopeType == "" {
		account.ScopeType = "PROJECT"
	}
	if account.ScopeID == "" {
		account.ScopeID = account.ID
	}
	if account.Currency == "" {
		account.Currency = "USD"
	}
	if account.PeriodStart.IsZero() {
		account.PeriodStart = l.clock().UTC()
	}
	if account.Version == 0 {
		account.Version = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := budgetKey(account.TenantID, account.ID)
	if _, exists := l.accounts[key]; exists {
		return ErrReservationConflict
	}
	l.accounts[key] = account
	return nil
}

func (l *BudgetLedger) Reserve(ctx context.Context, tenantID, accountID, reservationID, requestID string, amountMicros int64) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if tenantID == "" || accountID == "" || reservationID == "" || requestID == "" || amountMicros < 0 {
		return Reservation{}, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	reservationKey := budgetKey(tenantID, reservationID)
	if existing, exists := l.reservations[reservationKey]; exists {
		if existing.State == ReservationOpen && !l.clock().UTC().Before(existing.ExpiresAt) {
			existing.State = ReservationReconcile
			l.reservations[reservationKey] = existing
			return Reservation{}, ErrReconciliationRequired
		}
		if existing.AccountID == accountID && existing.RequestID == requestID && existing.ReservedMicros == amountMicros && existing.State == ReservationOpen {
			return existing, nil
		}
		if existing.State == ReservationReconcile {
			return Reservation{}, ErrReconciliationRequired
		}
		return Reservation{}, ErrReservationConflict
	}
	accountKey := budgetKey(tenantID, accountID)
	account, exists := l.accounts[accountKey]
	if !exists {
		return Reservation{}, ErrBudgetExceeded
	}
	if !budgetPeriodOpen(l.clock().UTC(), account) || amountMicros > account.LimitMicros-account.ReservedMicros-account.SpentMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	account.ReservedMicros += amountMicros
	account.Version++
	l.accounts[accountKey] = account
	createdAt := l.clock().UTC()
	reservation := Reservation{ID: reservationID, TenantID: tenantID, AccountID: accountID, RequestID: requestID, ReservedMicros: amountMicros, State: ReservationOpen, CreatedAt: createdAt, ExpiresAt: createdAt.Add(l.reservationTTL)}
	l.reservations[reservationKey] = reservation
	return reservation, nil
}

func (l *BudgetLedger) Settle(ctx context.Context, tenantID, reservationID string, actualMicros int64) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if tenantID == "" || reservationID == "" || actualMicros < 0 {
		return Reservation{}, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	reservationKey := budgetKey(tenantID, reservationID)
	reservation, exists := l.reservations[reservationKey]
	if !exists {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.State == ReservationSettled {
		if reservation.SettledMicros == actualMicros {
			return reservation, nil
		}
		return Reservation{}, ErrReservationConflict
	}
	if reservation.State != ReservationOpen {
		return Reservation{}, ErrReservationConflict
	}
	accountKey := budgetKey(tenantID, reservation.AccountID)
	account := l.accounts[accountKey]
	if account.ReservedMicros < reservation.ReservedMicros || actualMicros > account.LimitMicros-account.SpentMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	account.ReservedMicros -= reservation.ReservedMicros
	account.SpentMicros += actualMicros
	account.Version++
	l.accounts[accountKey] = account
	reservation.SettledMicros = actualMicros
	reservation.State = ReservationSettled
	l.reservations[reservationKey] = reservation
	return reservation, nil
}

func (l *BudgetLedger) Release(ctx context.Context, tenantID, reservationID string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if tenantID == "" || reservationID == "" {
		return ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	reservationKey := budgetKey(tenantID, reservationID)
	reservation, exists := l.reservations[reservationKey]
	if !exists {
		return ErrReservationNotFound
	}
	if reservation.State == ReservationReleased {
		return nil
	}
	if reservation.State != ReservationOpen {
		return ErrReservationConflict
	}
	accountKey := budgetKey(tenantID, reservation.AccountID)
	account := l.accounts[accountKey]
	if account.ReservedMicros < reservation.ReservedMicros {
		return ErrReservationConflict
	}
	account.ReservedMicros -= reservation.ReservedMicros
	account.Version++
	l.accounts[accountKey] = account
	reservation.State = ReservationReleased
	l.reservations[reservationKey] = reservation
	return nil
}

func (l *BudgetLedger) Reconcile(ctx context.Context, tenantID, reservationID string, actualMicros int64) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if tenantID == "" || reservationID == "" || actualMicros < 0 {
		return Reservation{}, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	reservationKey := budgetKey(tenantID, reservationID)
	reservation, exists := l.reservations[reservationKey]
	if !exists {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.State == ReservationSettled {
		if reservation.SettledMicros == actualMicros {
			return reservation, nil
		}
		return Reservation{}, ErrReservationConflict
	}
	if reservation.State != ReservationOpen && reservation.State != ReservationReconcile {
		return Reservation{}, ErrReservationConflict
	}
	accountKey := budgetKey(tenantID, reservation.AccountID)
	account := l.accounts[accountKey]
	if account.ReservedMicros < reservation.ReservedMicros || actualMicros > account.LimitMicros-account.SpentMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	account.ReservedMicros -= reservation.ReservedMicros
	account.SpentMicros += actualMicros
	account.Version++
	l.accounts[accountKey] = account
	reservation.SettledMicros = actualMicros
	reservation.State = ReservationSettled
	l.reservations[reservationKey] = reservation
	return reservation, nil
}

func (l *BudgetLedger) RequireReconciliation(ctx context.Context, tenantID, reservationID string) (Reservation, error) {
	if err := contextError(ctx); err != nil {
		return Reservation{}, err
	}
	if tenantID == "" || reservationID == "" {
		return Reservation{}, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := budgetKey(tenantID, reservationID)
	reservation, exists := l.reservations[key]
	if !exists {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.State == ReservationReconcile {
		return reservation, nil
	}
	if reservation.State != ReservationOpen {
		return Reservation{}, ErrReservationConflict
	}
	reservation.State = ReservationReconcile
	l.reservations[key] = reservation
	return reservation, nil
}

func (l *BudgetLedger) Account(tenantID, id string) (BudgetAccount, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	account, found := l.accounts[budgetKey(tenantID, id)]
	return account, found
}

func (l *BudgetLedger) ListAccounts(ctx context.Context, tenantID, projectID string) ([]BudgetAccount, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if tenantID == "" || projectID == "" {
		return nil, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	accounts := make([]BudgetAccount, 0, 1)
	for _, account := range l.accounts {
		if account.TenantID == tenantID && account.ScopeType == "PROJECT" && account.ScopeID == projectID {
			accounts = append(accounts, cloneBudgetAccount(account))
		}
	}
	sort.Slice(accounts, func(left, right int) bool { return accounts[left].ID < accounts[right].ID })
	return accounts, nil
}

func (l *BudgetLedger) Usage(ctx context.Context, tenantID, projectID string) (BudgetUsage, error) {
	if err := contextError(ctx); err != nil {
		return BudgetUsage{}, err
	}
	if tenantID == "" || projectID == "" {
		return BudgetUsage{}, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	account, found, err := l.projectAccountLocked(tenantID, projectID)
	if err != nil {
		return BudgetUsage{}, err
	}
	if !found {
		return BudgetUsage{}, ErrBudgetAccountNotFound
	}
	return l.usageFromAccountLocked(account), nil
}

func (l *BudgetLedger) Adjust(ctx context.Context, adjustment BudgetAdjustment) (BudgetAdjustmentResult, error) {
	if err := contextError(ctx); err != nil {
		return BudgetAdjustmentResult{}, err
	}
	if err := prepareBudgetAdjustment(&adjustment); err != nil {
		return BudgetAdjustmentResult{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	adjustmentKey := budgetKey(adjustment.TenantID, adjustment.PrincipalID+"\x00"+adjustment.IdempotencyKey)
	if prior, found := l.adjustments[adjustmentKey]; found {
		if !sameBudgetAdjustment(prior.request, adjustment) {
			return BudgetAdjustmentResult{}, ErrBudgetIdempotencyConflict
		}
		result := prior.result
		result.Account = cloneBudgetAccount(result.Account)
		result.Duplicate = true
		return result, nil
	}
	account, found, err := l.projectAccountLocked(adjustment.TenantID, adjustment.ProjectID)
	if err != nil {
		return BudgetAdjustmentResult{}, err
	}
	if !found {
		return BudgetAdjustmentResult{}, ErrBudgetAccountNotFound
	}
	if account.Version != adjustment.ExpectedVersion {
		return BudgetAdjustmentResult{}, ErrBudgetVersionConflict
	}
	if adjustment.Currency != account.Currency {
		return BudgetAdjustmentResult{}, ErrBudgetCurrencyConflict
	}
	if !budgetPeriodOpen(l.clock().UTC(), account) {
		return BudgetAdjustmentResult{}, ErrBudgetPeriodClosed
	}
	if adjustment.SoftLimitMicros > adjustment.HardLimitMicros || adjustment.HardLimitMicros < account.SpentMicros+account.ReservedMicros {
		return BudgetAdjustmentResult{}, ErrBudgetLimitConflict
	}
	account.LimitMicros = adjustment.HardLimitMicros
	account.SoftLimitMicros = adjustment.SoftLimitMicros
	account.Version++
	l.accounts[budgetKey(adjustment.TenantID, account.ID)] = account
	result := BudgetAdjustmentResult{Account: cloneBudgetAccount(account), Usage: l.usageFromAccountLocked(account)}
	l.adjustments[adjustmentKey] = memoryBudgetAdjustment{request: adjustment, result: result}
	return result, nil
}

func cloneBudgetAccount(account BudgetAccount) BudgetAccount {
	if account.PeriodEnd != nil {
		periodEnd := *account.PeriodEnd
		account.PeriodEnd = &periodEnd
	}
	return account
}

func usageFromAccount(account BudgetAccount) BudgetUsage {
	remaining := account.LimitMicros - account.SpentMicros - account.ReservedMicros
	if remaining < 0 {
		remaining = 0
	}
	return BudgetUsage{AccountID: account.ID, Currency: account.Currency, HardLimitMicros: account.LimitMicros, SoftLimitMicros: account.SoftLimitMicros, SpentMicros: account.SpentMicros, ReservedMicros: account.ReservedMicros, RemainingMicros: remaining, Version: account.Version}
}

func (l *BudgetLedger) usageFromAccountLocked(account BudgetAccount) BudgetUsage {
	usage := usageFromAccount(account)
	for _, reservation := range l.reservations {
		if reservation.TenantID == account.TenantID && reservation.AccountID == account.ID && inBudgetPeriod(reservation.CreatedAt, account.PeriodStart, account.PeriodEnd) {
			usage.ReservationCount++
		}
	}
	for _, call := range l.modelCalls {
		if call.TenantID == account.TenantID && call.ProjectID == account.ScopeID && inBudgetPeriod(call.CreatedAt, account.PeriodStart, account.PeriodEnd) {
			usage.CallCount++
			usage.InputTokens += call.InputTokens
			usage.OutputTokens += call.OutputTokens
			usage.CostMicros += call.CostMicros
		}
	}
	return usage
}

func inBudgetPeriod(at, start time.Time, end *time.Time) bool {
	if !start.IsZero() && at.Before(start) {
		return false
	}
	return end == nil || at.Before(*end)
}

func budgetPeriodOpen(at time.Time, account BudgetAccount) bool {
	if !account.PeriodStart.IsZero() && at.Before(account.PeriodStart) {
		return false
	}
	return account.PeriodEnd == nil || at.Before(*account.PeriodEnd)
}

func (l *BudgetLedger) projectAccountLocked(tenantID, projectID string) (BudgetAccount, bool, error) {
	var account BudgetAccount
	found := false
	for _, candidate := range l.accounts {
		if candidate.TenantID != tenantID || candidate.ScopeType != "PROJECT" || candidate.ScopeID != projectID {
			continue
		}
		if found {
			return BudgetAccount{}, false, ErrBudgetAccountConflict
		}
		account, found = candidate, true
	}
	return account, found, nil
}

func prepareBudgetAdjustment(adjustment *BudgetAdjustment) error {
	if adjustment == nil || adjustment.TenantID == "" || adjustment.ProjectID == "" || !safeBudgetText(adjustment.PrincipalID, 512) || !safeBudgetText(adjustment.IdempotencyKey, 256) || !safeBudgetText(adjustment.Reason, 2048) || adjustment.ProjectVersion < 0 || (adjustment.ProjectVersion > 0 && !safeBudgetText(adjustment.ProjectState, 64)) || adjustment.ExpectedVersion < 1 || adjustment.HardLimitMicros < 0 || adjustment.SoftLimitMicros < 0 || adjustment.SoftLimitMicros > adjustment.HardLimitMicros || !validCurrency(adjustment.Currency) {
		return ErrInvalidRequest
	}
	if (adjustment.PolicyVersion != "" && !safeBudgetText(adjustment.PolicyVersion, 256)) ||
		(adjustment.PolicyRuleID != "" && !safeBudgetText(adjustment.PolicyRuleID, 128)) ||
		(adjustment.PolicyDecision != "" && adjustment.PolicyDecision != "ALLOW") ||
		(adjustment.ParameterDigest != "" && !safeBudgetText(adjustment.ParameterDigest, 128)) {
		return ErrInvalidRequest
	}
	if len(adjustment.PolicyReasons) > 32 {
		return ErrInvalidRequest
	}
	for _, reason := range adjustment.PolicyReasons {
		if !safeBudgetText(reason, 128) {
			return ErrInvalidRequest
		}
	}
	if adjustment.Traceparent == "" {
		if adjustment.Tracestate != "" {
			return ErrInvalidRequest
		}
		trace, err := observability.NewRootTraceContext(false)
		if err != nil {
			return err
		}
		adjustment.Traceparent, err = trace.TraceParent()
		return err
	}
	trace, err := observability.ParseTraceParent(adjustment.Traceparent, adjustment.Tracestate)
	if err != nil {
		return ErrInvalidRequest
	}
	adjustment.Traceparent, err = trace.TraceParent()
	if err != nil {
		return ErrInvalidRequest
	}
	adjustment.Tracestate = trace.TraceState
	return nil
}

func sameBudgetAdjustment(left, right BudgetAdjustment) bool {
	return left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.PrincipalID == right.PrincipalID &&
		left.IdempotencyKey == right.IdempotencyKey && left.ExpectedVersion == right.ExpectedVersion &&
		left.HardLimitMicros == right.HardLimitMicros && left.SoftLimitMicros == right.SoftLimitMicros &&
		left.Currency == right.Currency && left.Reason == right.Reason
}

func (l *BudgetLedger) Reservation(tenantID, id string) (Reservation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	reservation, found := l.reservations[budgetKey(tenantID, id)]
	return reservation, found
}

func (l *BudgetLedger) ExpireReservations(ctx context.Context, tenantID string, limit int) ([]Reservation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if tenantID == "" || limit <= 0 {
		return nil, ErrInvalidRequest
	}
	now := l.clock().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	candidates := make([]Reservation, 0)
	for _, reservation := range l.reservations {
		if reservation.TenantID == tenantID && reservation.State == ReservationOpen && !now.Before(reservation.ExpiresAt) {
			candidates = append(candidates, reservation)
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].ExpiresAt.Equal(candidates[right].ExpiresAt) {
			return candidates[left].ID < candidates[right].ID
		}
		return candidates[left].ExpiresAt.Before(candidates[right].ExpiresAt)
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	for index := range candidates {
		candidates[index].State = ReservationReconcile
		l.reservations[budgetKey(tenantID, candidates[index].ID)] = candidates[index]
	}
	return candidates, nil
}

func budgetKey(tenantID, id string) string {
	return tenantID + "\x00" + id
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRequest
	}
	return ctx.Err()
}
