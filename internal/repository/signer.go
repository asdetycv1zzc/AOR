package repository

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/akimisaka/aor/pkg/contracts"
)

const repositorySigningKeyID = "repository-submission-v1"

type HMACSigner struct {
	key []byte
}

func NewHMACSigner(key []byte) (*HMACSigner, error) {
	if len(key) < 32 {
		return nil, ErrInvalidRequest
	}
	return &HMACSigner{key: append([]byte(nil), key...)}, nil
}

func (signer *HMACSigner) Sign(ctx context.Context, payload []byte) (*contracts.Signature, error) {
	if signer == nil || len(signer.key) < 32 || ctx == nil {
		return nil, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write(payload)
	return &contracts.Signature{Type: "HMAC-SHA256", KID: repositorySigningKeyID, JWS: "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))}, nil
}

func (signer *HMACSigner) Verify(ctx context.Context, payload []byte, signature *contracts.Signature) error {
	if signer == nil || len(signer.key) < 32 || ctx == nil || signature == nil || signature.Type != "HMAC-SHA256" || signature.KID != repositorySigningKeyID || !strings.HasPrefix(signature.JWS, "hmac-sha256:") {
		return ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signature.JWS, "hmac-sha256:"))
	if err != nil || len(provided) != sha256.Size {
		return ErrInvalidRequest
	}
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), provided) {
		return ErrInvalidRequest
	}
	return nil
}

var _ Signer = (*HMACSigner)(nil)
