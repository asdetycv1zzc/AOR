package agentruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/aop"
)

func TestAgentCardSigningAndValidation(t *testing.T) {
	signer := digestSigner{}
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	card := AgentCard{
		Name: "AOR Execution Runtime", Description: "Executes one versioned module task under AOR control",
		SupportedInterfaces: []aop.CardInterface{{URL: "https://aor.example.internal/a2a/v1", ProtocolBinding: "HTTP+JSON", ProtocolVersion: aop.Version}},
		Capabilities:        aop.CardCapabilities{Streaming: true, Extensions: []aop.CardExtension{{URI: aop.ExtensionURI, Required: true}}},
		Skills: []aop.CardSkill{
			{ID: "aor-executor-v1", Name: "AOR Executor", Tags: []string{"executor"}},
			{ID: "aor-auditor-v1", Name: "AOR Auditor", Tags: []string{"auditor"}},
		},
		InputModes: []string{"application/json"}, OutputModes: []string{"application/json"},
		AuthenticationSchemes: []string{"mTLS"}, ExpiresAt: now.Add(time.Hour), KeyID: "kid_test",
	}
	signed, err := SignAgentCard(context.Background(), card, signer, now)
	if err != nil {
		t.Fatalf("sign card: %v", err)
	}
	if signed.Signature == "" || signed.Skills[0].ID != "aor-auditor-v1" {
		t.Fatalf("signed card is not canonical: %#v", signed)
	}
	if err := VerifyAgentCard(context.Background(), signed, signer, now, nil); err != nil {
		t.Fatalf("verify card: %v", err)
	}
	signed.Description = "tampered"
	if err := VerifyAgentCard(context.Background(), signed, signer, now, nil); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("tampered card error = %v", err)
	}
}

func TestAgentCardRejectsInsecureEndpointCredentialAndRevokedKey(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	base := AgentCard{
		Name: "Runtime", Description: "Agent runtime",
		SupportedInterfaces: []aop.CardInterface{{URL: "http://runtime.internal/a2a", ProtocolBinding: "HTTP+JSON", ProtocolVersion: aop.Version}},
		Capabilities:        aop.CardCapabilities{Extensions: []aop.CardExtension{{URI: aop.ExtensionURI, Required: true}}},
		Skills:              []aop.CardSkill{{ID: "aor-executor-v1", Name: "AOR Executor", Tags: []string{"executor"}}},
		InputModes:          []string{"application/json"}, OutputModes: []string{"application/json"},
		AuthenticationSchemes: []string{"mTLS"}, ExpiresAt: now.Add(time.Hour), KeyID: "kid_test",
	}
	if _, err := SignAgentCard(context.Background(), base, digestSigner{}, now); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("insecure endpoint error = %v", err)
	}
	base.SupportedInterfaces[0].URL = "https://runtime.internal/a2a"
	base.Description = "Bearer " + "abcdefghijklmnopqrstuvwxyz"
	if _, err := SignAgentCard(context.Background(), base, digestSigner{}, now); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("credential metadata error = %v", err)
	}
	base.Description = "Agent runtime"
	signed, err := SignAgentCard(context.Background(), base, digestSigner{}, now)
	if err != nil {
		t.Fatalf("sign valid card: %v", err)
	}
	if err := VerifyAgentCard(context.Background(), signed, digestSigner{}, now, map[string]bool{"kid_test": true}); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("revoked key error = %v", err)
	}
}

func TestAgentCardKeyRingRejectsUnknownExpiredRevokedAndRotatedKeys(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	oldSigner, err := NewHMACAgentCardSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	newSigner, err := NewHMACAgentCardSigner([]byte("abcdef0123456789abcdef0123456789"))
	if err != nil {
		t.Fatal(err)
	}

	oldCard := signedHMACAgentCard(t, oldSigner, "kid_old", now.Add(30*time.Second), now)
	ring, err := NewAgentCardKeyRing(map[string]AgentCardVerificationKey{
		"kid_old": {Verifier: oldSigner},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAgentCardWithKeyRing(context.Background(), oldCard, ring, now); err != nil {
		t.Fatalf("verify trusted key: %v", err)
	}

	unknown := oldCard
	unknown.KeyID = "kid_unknown"
	if err := VerifyAgentCardWithKeyRing(context.Background(), unknown, ring, now); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("unknown key error = %v", err)
	}
	if err := VerifyAgentCardWithKeyRing(context.Background(), oldCard, ring, oldCard.ExpiresAt); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("expired card error = %v", err)
	}
	if err := ring.RevokeKey("kid_old"); err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	if err := VerifyAgentCardWithKeyRing(context.Background(), oldCard, ring, now); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("revoked key error = %v", err)
	}

	ring, err = NewAgentCardKeyRing(map[string]AgentCardVerificationKey{
		"kid_old": {Verifier: oldSigner},
	})
	if err != nil {
		t.Fatal(err)
	}
	rotationAt := now.Add(time.Minute)
	if err := ring.Rotate("kid_old", rotationAt, "kid_new", AgentCardVerificationKey{Verifier: newSigner}); err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	oldCard = signedHMACAgentCard(t, oldSigner, "kid_old", now.Add(2*time.Minute), now)
	if err := VerifyAgentCardWithKeyRing(context.Background(), oldCard, ring, now); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("old key extended past retirement error = %v", err)
	}
	newCard := signedHMACAgentCard(t, newSigner, "kid_new", now.Add(2*time.Minute), now)
	if err := VerifyAgentCardWithKeyRing(context.Background(), newCard, ring, rotationAt); err != nil {
		t.Fatalf("rotated key error = %v", err)
	}
}

func TestAgentCardKeyRingConcurrentVerificationAndUpdates(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	signer, err := NewHMACAgentCardSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewAgentCardKeyRing(map[string]AgentCardVerificationKey{"kid_base": {Verifier: signer}})
	if err != nil {
		t.Fatal(err)
	}
	card := signedHMACAgentCard(t, signer, "kid_base", now.Add(time.Hour), now)
	var group sync.WaitGroup
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			if err := ring.AddKey(fmt.Sprintf("kid_%d", index), AgentCardVerificationKey{Verifier: signer}); err != nil {
				t.Errorf("add key: %v", err)
			}
			for attempt := 0; attempt < 32; attempt++ {
				if err := VerifyAgentCardWithKeyRing(context.Background(), card, ring, now); err != nil {
					t.Errorf("verify card: %v", err)
				}
			}
		}(index)
	}
	group.Wait()
}

func TestHMACAgentCardSignerRejectsInvalidKeysAndSignatures(t *testing.T) {
	if _, err := NewHMACAgentCardSigner([]byte("too-short")); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("short key error = %v", err)
	}
	signer, err := NewHMACAgentCardSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign([]byte("card"))
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Verify([]byte("different"), signature); !errors.Is(err, ErrAgentCardInvalid) {
		t.Fatalf("tampered payload error = %v", err)
	}
}

func signedHMACAgentCard(t *testing.T, signer AgentCardSigner, keyID string, expiresAt, now time.Time) AgentCard {
	t.Helper()
	card := AgentCard{
		Name: "Runtime", Description: "Agent runtime",
		SupportedInterfaces: []aop.CardInterface{{URL: "https://runtime.internal/a2a", ProtocolBinding: "HTTP+JSON", ProtocolVersion: aop.Version}},
		Capabilities:        aop.CardCapabilities{Extensions: []aop.CardExtension{{URI: aop.ExtensionURI, Required: true}}},
		Skills:              []aop.CardSkill{{ID: "aor-executor-v1", Name: "AOR Executor", Tags: []string{"executor"}}},
		InputModes:          []string{"application/json"}, OutputModes: []string{"application/json"},
		AuthenticationSchemes: []string{"mTLS"}, ExpiresAt: expiresAt, KeyID: keyID,
	}
	signed, err := SignAgentCard(context.Background(), card, signer, now)
	if err != nil {
		t.Fatalf("sign card: %v", err)
	}
	return signed
}

type digestSigner struct{}

func (digestSigner) Sign(payload []byte) (string, error) {
	sum := sha256.Sum256(payload)
	return "test-sha256:" + hex.EncodeToString(sum[:]), nil
}

func (signer digestSigner) Verify(payload []byte, signature string) error {
	expected, _ := signer.Sign(payload)
	if signature != expected {
		return errors.New("signature mismatch")
	}
	return nil
}
