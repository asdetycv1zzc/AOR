package mcp

import (
	"errors"
	"testing"
)

func TestBaselineAndAllowedCompatibleVersionNegotiateExplicitly(t *testing.T) {
	profile := ServerProfile{SupportedProtocolVersions: []string{BaselineProtocolVersion, "2025-06-18"}, SecurityCapabilities: []SecurityCapability{SecurityTLS, SecurityMTLS}}
	for _, version := range []string{BaselineProtocolVersion, "2025-06-18"} {
		result, err := Negotiate(InitializeRequest{ProtocolVersion: version, RequiredSecurity: []SecurityCapability{SecurityTLS}}, profile)
		if err != nil || result.ProtocolVersion != version {
			t.Fatalf("version %s: result=%#v err=%v", version, result, err)
		}
	}
}

func TestNegotiationNeverSilentlyDowngradesVersionOrSecurity(t *testing.T) {
	profile := ServerProfile{SupportedProtocolVersions: []string{BaselineProtocolVersion, "2025-06-18"}, SecurityCapabilities: []SecurityCapability{SecurityTLS}}
	if _, err := Negotiate(InitializeRequest{ProtocolVersion: "2025-03-26"}, profile); !errors.Is(err, ErrUnsupportedProtocolVersion) {
		t.Fatalf("version downgrade error = %v", err)
	}
	if _, err := Negotiate(InitializeRequest{ProtocolVersion: BaselineProtocolVersion, RequiredSecurity: []SecurityCapability{SecurityMTLS}}, profile); !errors.Is(err, ErrSecurityCapabilityMissing) {
		t.Fatalf("security downgrade error = %v", err)
	}
}

func TestServerMustRetainBaselineWhenOfferingCompatibilityVersion(t *testing.T) {
	profile := ServerProfile{SupportedProtocolVersions: []string{"2025-06-18"}, SecurityCapabilities: []SecurityCapability{SecurityTLS}}
	if _, err := Negotiate(InitializeRequest{ProtocolVersion: "2025-06-18"}, profile); !errors.Is(err, ErrUnsupportedProtocolVersion) {
		t.Fatalf("baseline error = %v", err)
	}
}
