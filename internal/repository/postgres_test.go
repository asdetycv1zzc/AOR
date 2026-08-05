package repository

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestPostgresSubmissionStoreRequiresDatabase(t *testing.T) {
	if _, err := NewPostgresSubmissionStore(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil database error = %v", err)
	}
}

func TestNewSubmissionIDReturnsDistinctUUIDv7Values(t *testing.T) {
	first, err := newSubmissionID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newSubmissionID()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || first.Version() != uuid.Version(7) || second.Version() != uuid.Version(7) {
		t.Fatalf("submission IDs first=%s second=%s", first, second)
	}
}
