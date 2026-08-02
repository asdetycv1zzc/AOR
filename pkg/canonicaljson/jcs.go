// Package canonicaljson provides the repository's RFC 8785 digest boundary.
package canonicaljson

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/deszhou/jcs"
)

// Canonicalize applies the Go standard library's RFC 8785 implementation.
// The returned bytes are safe to use as a signature or digest input.
func Canonicalize(input []byte) ([]byte, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("canonical JSON is empty")
	}
	value, err := jcs.Transform(input)
	if err != nil {
		return nil, fmt.Errorf("canonical JSON: %w", err)
	}
	return value, nil
}

// Digest returns the canonical content digest using the repository format.
func Digest(input []byte) (string, error) {
	canonical, err := Canonicalize(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// DigestObjectWithoutFields hashes an object after excluding only explicitly mutable envelope fields.
// Unknown optional fields remain part of the digest and cannot be silently substituted.
func DigestObjectWithoutFields(input []byte, excluded ...string) (string, error) {
	canonical, err := Canonicalize(input)
	if err != nil {
		return "", err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &object); err != nil {
		return "", fmt.Errorf("canonical JSON must be an object: %w", err)
	}
	if object == nil {
		return "", fmt.Errorf("canonical JSON must be an object")
	}
	for _, field := range excluded {
		delete(object, field)
	}
	without, err := json.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("marshal digest object: %w", err)
	}
	return Digest(without)
}
