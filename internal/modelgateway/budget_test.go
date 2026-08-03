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
