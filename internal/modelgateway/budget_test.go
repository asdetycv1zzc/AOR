package modelgateway

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBudgetLedgerExpiresReservationsIntoReconciliation(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ledger := NewBudgetLedger(func() time.Time { return now })
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: tenantID, LimitMicros: 100}); err != nil {
			t.Fatal(err)
		}
		if _, err := ledger.Reserve(context.Background(), tenantID, "account", "reservation", "request", 40); err != nil {
			t.Fatal(err)
		}
	}

	now = now.Add(defaultReservationTTL)
	expired, err := ledger.ExpireReservations(context.Background(), "tenant-a", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired) != 1 || expired[0].TenantID != "tenant-a" || expired[0].State != ReservationReconcile {
		t.Fatalf("expired reservations = %#v", expired)
	}
	account, found := ledger.Account("tenant-a", "account")
	if !found || account.ReservedMicros != 40 || account.SpentMicros != 0 {
		t.Fatalf("expired reservation was released instead of retained: %#v", account)
	}
	other, found := ledger.Reservation("tenant-b", "reservation")
	if !found || other.State != ReservationOpen {
		t.Fatalf("another tenant was modified: %#v", other)
	}
	_, err = ledger.Reserve(context.Background(), "tenant-a", "account", "reservation", "request", 40)
	if !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("expired reservation reuse error = %v", err)
	}
	settled, err := ledger.Reconcile(context.Background(), "tenant-a", "reservation", 25)
	if err != nil || settled.State != ReservationSettled || settled.SettledMicros != 25 {
		t.Fatalf("reconciled reservation = %#v, error = %v", settled, err)
	}
	account, _ = ledger.Account("tenant-a", "account")
	if account.ReservedMicros != 0 || account.SpentMicros != 25 {
		t.Fatalf("reconciled account = %#v", account)
	}
}

func TestBudgetLedgerReserveDetectsExpiredReservationWithoutSweep(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ledger := NewBudgetLedger(func() time.Time { return now })
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "account", TenantID: "tenant", LimitMicros: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(context.Background(), "tenant", "account", "reservation", "request", 10); err != nil {
		t.Fatal(err)
	}
	now = now.Add(defaultReservationTTL + time.Nanosecond)
	if _, err := ledger.Reserve(context.Background(), "tenant", "account", "reservation", "request", 10); !errors.Is(err, ErrReconciliationRequired) {
		t.Fatalf("expired reservation reuse error = %v", err)
	}
	reservation, found := ledger.Reservation("tenant", "reservation")
	if !found || reservation.State != ReservationReconcile {
		t.Fatalf("expired reservation = %#v", reservation)
	}
}

func TestBudgetAdministrationAdjustsAndReplaysExactlyOnce(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ledger := NewBudgetLedger(func() time.Time { return now })
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{ID: "project-1", TenantID: "tenant", LimitMicros: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(context.Background(), "tenant", "project-1", "reservation", "request", 10); err != nil {
		t.Fatal(err)
	}
	adjustment := BudgetAdjustment{
		TenantID: "tenant", ProjectID: "project-1", PrincipalID: "principal", IdempotencyKey: "adjust-1",
		Traceparent:     "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		ExpectedVersion: 2, HardLimitMicros: 150, SoftLimitMicros: 120, Currency: "USD", Reason: "approved increase",
	}
	result, err := ledger.Adjust(context.Background(), adjustment)
	if err != nil {
		t.Fatal(err)
	}
	if result.Account.Version != 3 || result.Account.LimitMicros != 150 || result.Usage.RemainingMicros != 140 || result.Usage.ReservationCount != 1 {
		t.Fatalf("adjustment result = %#v", result)
	}
	adjustment.Traceparent = "00-abcdef0123456789abcdef0123456789-abcdef0123456789-00"
	replayed, err := ledger.Adjust(context.Background(), adjustment)
	if err != nil || !replayed.Duplicate || replayed.Account.Version != 3 {
		t.Fatalf("replayed adjustment = %#v, error = %v", replayed, err)
	}
	adjustment.HardLimitMicros = 160
	if _, err := ledger.Adjust(context.Background(), adjustment); !errors.Is(err, ErrBudgetIdempotencyConflict) {
		t.Fatalf("idempotency collision error = %v", err)
	}
}

func TestBudgetLedgerRejectsReservationsOutsideAccountPeriod(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	periodStart := now.Add(time.Hour)
	periodEnd := periodStart.Add(time.Hour)
	ledger := NewBudgetLedger(func() time.Time { return now })
	if err := ledger.CreateAccount(context.Background(), BudgetAccount{
		ID: "account", TenantID: "tenant", ScopeType: "PROJECT", ScopeID: "project", Currency: "USD",
		LimitMicros: 100, SoftLimitMicros: 80, PeriodStart: periodStart, PeriodEnd: &periodEnd,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve(context.Background(), "tenant", "account", "reservation", "request", 1); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("reservation before period error = %v", err)
	}
	now = periodStart
	if _, err := ledger.Reserve(context.Background(), "tenant", "account", "reservation", "request", 1); err != nil {
		t.Fatal(err)
	}
	now = periodEnd
	if _, err := ledger.Adjust(context.Background(), BudgetAdjustment{
		TenantID: "tenant", ProjectID: "project", PrincipalID: "principal", IdempotencyKey: "adjust",
		ExpectedVersion: 2, HardLimitMicros: 120, SoftLimitMicros: 100, Currency: "USD", Reason: "closed period",
	}); !errors.Is(err, ErrBudgetPeriodClosed) {
		t.Fatalf("adjustment after period error = %v", err)
	}
}
