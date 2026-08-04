package repository

import (
	"errors"
	"testing"
)

func TestPostgresSubmissionStoreRequiresDatabase(t *testing.T) {
	if _, err := NewPostgresSubmissionStore(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil database error = %v", err)
	}
}
