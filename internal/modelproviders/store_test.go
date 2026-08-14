package modelproviders

import (
	"context"
	"errors"
	"testing"
)

func TestPutRejectsClearingAndReplacingAPIKeyTogether(t *testing.T) {
	store := &Store{}
	_, err := store.Put(context.Background(), "11111111-1111-4111-8111-111111111111", "openai", PutRequest{
		APIKey: "replacement", ClearAPIKey: true,
	})
	if !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("error=%v", err)
	}
}
