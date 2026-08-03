package modelgateway

import (
	"context"
	"sync"
	"time"
)

type BudgetAccount struct {
	ID             string
	TenantID       string
	LimitMicros    int64
	ReservedMicros int64
	SpentMicros    int64
}

type ReservationState string

const (
	ReservationOpen      ReservationState = "OPEN"
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
}

type BudgetLedgerBackend interface {
	Reserve(context.Context, string, string, string, string, int64) (Reservation, error)
	Settle(context.Context, string, string, int64) (Reservation, error)
	Release(context.Context, string, string) error
	Reconcile(context.Context, string, string, int64) (Reservation, error)
	RequireReconciliation(context.Context, string, string) (Reservation, error)
}

type BudgetLedger struct {
	mu           sync.Mutex
	accounts     map[string]BudgetAccount
	reservations map[string]Reservation
	clock        func() time.Time
}

func NewBudgetLedger(clock func() time.Time) *BudgetLedger {
	if clock == nil {
		clock = time.Now
	}
	return &BudgetLedger{accounts: make(map[string]BudgetAccount), reservations: make(map[string]Reservation), clock: clock}
}

func (l *BudgetLedger) CreateAccount(ctx context.Context, account BudgetAccount) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if account.ID == "" || account.TenantID == "" || account.LimitMicros < 0 || account.ReservedMicros < 0 || account.SpentMicros < 0 || account.ReservedMicros > account.LimitMicros-account.SpentMicros {
		return ErrInvalidRequest
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
	if !exists || amountMicros > account.LimitMicros-account.ReservedMicros-account.SpentMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	account.ReservedMicros += amountMicros
	l.accounts[accountKey] = account
	reservation := Reservation{ID: reservationID, TenantID: tenantID, AccountID: accountID, RequestID: requestID, ReservedMicros: amountMicros, State: ReservationOpen, CreatedAt: l.clock().UTC()}
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

func (l *BudgetLedger) Reservation(tenantID, id string) (Reservation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	reservation, found := l.reservations[budgetKey(tenantID, id)]
	return reservation, found
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
