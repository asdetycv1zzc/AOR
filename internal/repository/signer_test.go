package repository

import (
	"context"
	"errors"
	"testing"
)

func TestHMACSignerAuthenticatesSubmissionPayload(t *testing.T) {
	signer, err := NewHMACSigner([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(context.Background(), []byte("submission"))
	if err != nil || signature.KID != repositorySigningKeyID {
		t.Fatalf("signature=%#v err=%v", signature, err)
	}
	if err := signer.Verify(context.Background(), []byte("submission"), signature); err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify(context.Background(), []byte("changed"), signature); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("tampered payload error = %v", err)
	}
}

func TestHMACSignerRejectsShortKeysAndCancellation(t *testing.T) {
	if _, err := NewHMACSigner([]byte("short")); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("short key error = %v", err)
	}
	signer, _ := NewHMACSigner([]byte("01234567890123456789012345678901"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.Sign(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}
