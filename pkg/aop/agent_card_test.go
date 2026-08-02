package aop

import (
	"testing"
	"time"
)

func TestAgentCardRequiresAOPAndRejectsUnknownRequiredExtension(t *testing.T) {
	card := validAgentCard()
	card.Capabilities.Extensions = append(card.Capabilities.Extensions, CardExtension{URI: "urn:unknown:critical", Required: true})
	if err := card.Validate(time.Now().UTC(), nil); err == nil {
		t.Fatal("unknown required extension was accepted")
	}
}

func TestAgentCardRejectsRevokedSigningKey(t *testing.T) {
	card := validAgentCard()
	if err := card.Validate(time.Now().UTC(), map[string]bool{"kid_1": true}); err == nil {
		t.Fatal("revoked card key was accepted")
	}
}

func validAgentCard() AgentCard {
	return AgentCard{
		Name:                  "AOR Executor",
		Description:           "Executes one ModuleSpec",
		SupportedInterfaces:   []CardInterface{{URL: "https://aor.test/a2a/v1", ProtocolBinding: "HTTP+JSON", ProtocolVersion: "1.0"}},
		Capabilities:          CardCapabilities{Extensions: []CardExtension{{URI: ExtensionURI, Required: true}}},
		Skills:                []CardSkill{{ID: "aor-executor-v1", Name: "AOR Module Executor", Tags: []string{"executor"}}},
		AuthenticationSchemes: []string{"mTLS"},
		ExpiresAt:             time.Now().UTC().Add(time.Hour),
		KeyID:                 "kid_1",
		Signature:             "detached-jws",
	}
}
