package agentruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
