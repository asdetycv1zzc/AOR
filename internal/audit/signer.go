package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/akimisaka/aor/pkg/contracts"
)

type HMACSigner struct {
	key []byte
}

func NewHMACSigner(key []byte) (*HMACSigner, error) {
	if len(key) < 32 {
		return nil, ErrInvalidInput
	}
	return &HMACSigner{key: append([]byte(nil), key...)}, nil
}

func (s *HMACSigner) Sign(_ context.Context, payload []byte) (*contracts.Signature, error) {
	if s == nil || len(s.key) < 32 {
		return nil, ErrInvalidInput
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	return &contracts.Signature{Type: "HMAC-SHA256", KID: "audit-local", JWS: "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))}, nil
}

func (s *HMACSigner) Verify(_ context.Context, payload []byte, signature *contracts.Signature) error {
	if s == nil || len(s.key) < 32 || signature == nil || signature.Type != "HMAC-SHA256" || !strings.HasPrefix(signature.JWS, "hmac-sha256:") {
		return ErrInvalidInput
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signature.JWS, "hmac-sha256:"))
	if err != nil || len(provided) != sha256.Size {
		return ErrInvalidInput
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), provided) {
		return ErrInvalidInput
	}
	return nil
}
