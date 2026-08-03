package modelgateway

import (
	"context"
	"sync"
	"time"
)

type BudgetAccount struct {
	ID             string
	LimitMicros    int64
	ReservedMicros int64
	SpentMicros    int64
}

type ReservationState string

const (
	ReservationOpen      ReservationState = "OPEN"
	ReservationSettled   ReservationState = "SETTLED"
	ReservationReleased  ReservationState = "RELEASED"
	ReservationReconcile ReservationState = "RECONCILIATION_REQUIRED"
)

type Reservation struct {
	ID             string
	AccountID      string
	RequestID      string
	ReservedMicros int64
	SettledMicros  int64
	State          ReservationState
	CreatedAt      time.Time
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

func (l *BudgetLedger) CreateAccount(_ context.Context, account BudgetAccount) error {
	if account.ID == "" || account.LimitMicros < 0 {
		return ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.accounts[account.ID]; exists {
		return ErrReservationConflict
	}
	l.accounts[account.ID] = account
	return nil
}

func (l *BudgetLedger) Reserve(_ context.Context, accountID, reservationID, requestID string, amountMicros int64) (Reservation, error) {
	if accountID == "" || reservationID == "" || requestID == "" || amountMicros < 0 {
		return Reservation{}, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, exists := l.reservations[reservationID]; exists {
		if existing.AccountID == accountID && existing.RequestID == requestID && existing.ReservedMicros == amountMicros {
			return existing, nil
		}
		return Reservation{}, ErrReservationConflict
	}
	account, exists := l.accounts[accountID]
	if !exists || account.ReservedMicros+account.SpentMicros+amountMicros > account.LimitMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	account.ReservedMicros += amountMicros
	l.accounts[accountID] = account
	reservation := Reservation{ID: reservationID, AccountID: accountID, RequestID: requestID, ReservedMicros: amountMicros, State: ReservationOpen, CreatedAt: l.clock().UTC()}
	l.reservations[reservationID] = reservation
	return reservation, nil
}

func (l *BudgetLedger) Settle(_ context.Context, reservationID string, actualMicros int64) (Reservation, error) {
	if actualMicros < 0 {
		return Reservation{}, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	reservation, exists := l.reservations[reservationID]
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
	account := l.accounts[reservation.AccountID]
	account.ReservedMicros -= reservation.ReservedMicros
	if account.ReservedMicros < 0 || account.SpentMicros+actualMicros > account.LimitMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	account.SpentMicros += actualMicros
	l.accounts[account.ID] = account
	reservation.SettledMicros = actualMicros
	reservation.State = ReservationSettled
	l.reservations[reservationID] = reservation
	return reservation, nil
}

func (l *BudgetLedger) Release(_ context.Context, reservationID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	reservation, exists := l.reservations[reservationID]
	if !exists {
		return ErrReservationNotFound
	}
	if reservation.State == ReservationReleased {
		return nil
	}
	if reservation.State != ReservationOpen {
		return ErrReservationConflict
	}
	account := l.accounts[reservation.AccountID]
	account.ReservedMicros -= reservation.ReservedMicros
	if account.ReservedMicros < 0 {
		return ErrReservationConflict
	}
	l.accounts[account.ID] = account
	reservation.State = ReservationReleased
	l.reservations[reservationID] = reservation
	return nil
}

func (l *BudgetLedger) Reconcile(_ context.Context, reservationID string, actualMicros int64) (Reservation, error) {
	if actualMicros < 0 {
		return Reservation{}, ErrInvalidRequest
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	reservation, exists := l.reservations[reservationID]
	if !exists {
		return Reservation{}, ErrReservationNotFound
	}
	if reservation.State == ReservationSettled {
		return reservation, nil
	}
	account := l.accounts[reservation.AccountID]
	account.ReservedMicros -= reservation.ReservedMicros
	if account.ReservedMicros < 0 || account.SpentMicros+actualMicros > account.LimitMicros {
		return Reservation{}, ErrBudgetExceeded
	}
	account.SpentMicros += actualMicros
	l.accounts[account.ID] = account
	reservation.SettledMicros = actualMicros
	reservation.State = ReservationSettled
	l.reservations[reservationID] = reservation
	return reservation, nil
}

func (l *BudgetLedger) Account(id string) (BudgetAccount, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	account, found := l.accounts[id]
	return account, found
}
