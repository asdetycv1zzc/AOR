// Package mcp implements the protocol-version and security-capability portion
// of the MCP initialize handshake. It does not authenticate a peer or create
// credentials; transports enforce the selected security requirements.
package mcp

import (
	"errors"
	"fmt"
	"sort"
)

const BaselineProtocolVersion = "2025-11-25"

var (
	ErrUnsupportedProtocolVersion = errors.New("unsupported MCP protocol version")
	ErrSecurityCapabilityMissing  = errors.New("required MCP security capability is unavailable")
)

type SecurityCapability string

const (
	SecurityTLS   SecurityCapability = "transport/tls"
	SecurityMTLS  SecurityCapability = "transport/mtls"
	SecurityOAuth SecurityCapability = "authorization/oauth"
)

type InitializeRequest struct {
	ProtocolVersion  string
	RequiredSecurity []SecurityCapability
}

type ServerProfile struct {
	SupportedProtocolVersions []string
	SecurityCapabilities      []SecurityCapability
}

type InitializeResult struct {
	ProtocolVersion      string
	SecurityCapabilities []SecurityCapability
}

func Negotiate(request InitializeRequest, profile ServerProfile) (InitializeResult, error) {
	if request.ProtocolVersion == "" || !contains(profile.SupportedProtocolVersions, request.ProtocolVersion) {
		return InitializeResult{}, fmt.Errorf("%w: %s", ErrUnsupportedProtocolVersion, request.ProtocolVersion)
	}
	if !contains(profile.SupportedProtocolVersions, BaselineProtocolVersion) {
		return InitializeResult{}, fmt.Errorf("%w: server does not advertise baseline %s", ErrUnsupportedProtocolVersion, BaselineProtocolVersion)
	}
	available := uniqueSorted(profile.SecurityCapabilities)
	for _, required := range uniqueSorted(request.RequiredSecurity) {
		if !contains(available, required) {
			return InitializeResult{}, fmt.Errorf("%w: %s", ErrSecurityCapabilityMissing, required)
		}
	}
	return InitializeResult{ProtocolVersion: request.ProtocolVersion, SecurityCapabilities: available}, nil
}

func contains[T comparable](values []T, target T) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func uniqueSorted[T ~string](values []T) []T {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]T, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left] < result[right] })
	return result
}
