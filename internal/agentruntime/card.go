package agentruntime

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type AgentCard = aop.AgentCard

type AgentCardSigner interface {
	Sign(payload []byte) (string, error)
	Verify(payload []byte, signature string) error
}

// AgentCardVerifier verifies a card signature. A verifier deliberately need
// not have signing authority, so trusted key rings can contain public keys.
type AgentCardVerifier interface {
	Verify(payload []byte, signature string) error
}

// AgentCardVerificationKey describes the lifecycle of a trusted verification
// key. RetiredAt is exclusive: a card is never accepted at or after that time.
type AgentCardVerificationKey struct {
	Verifier  AgentCardVerifier
	NotBefore time.Time
	RetiredAt time.Time
}

// AgentCardKeyRing resolves trusted verification keys by the card's KeyID.
// Its mutating operations are safe to use while cards are being verified.
type AgentCardKeyRing struct {
	mu      sync.RWMutex
	keys    map[string]AgentCardVerificationKey
	revoked map[string]struct{}
}

func NewAgentCardKeyRing(keys map[string]AgentCardVerificationKey) (*AgentCardKeyRing, error) {
	ring := &AgentCardKeyRing{
		keys:    make(map[string]AgentCardVerificationKey, len(keys)),
		revoked: make(map[string]struct{}),
	}
	for keyID, key := range keys {
		if !validAgentCardVerificationKey(keyID, key) {
			return nil, ErrAgentCardInvalid
		}
		ring.keys[keyID] = key
	}
	return ring, nil
}

// AddKey adds a previously unknown trusted key. Use Rotate to atomically
// install a replacement and retire its predecessor.
func (ring *AgentCardKeyRing) AddKey(keyID string, key AgentCardVerificationKey) error {
	if ring == nil || !validAgentCardVerificationKey(keyID, key) {
		return ErrAgentCardInvalid
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if _, exists := ring.keys[keyID]; exists {
		return ErrAgentCardInvalid
	}
	ring.keys[keyID] = key
	return nil
}

// Rotate atomically installs nextKey and retires previousKeyID at retiredAt.
// The retirement instant must not precede the old key's activation time.
func (ring *AgentCardKeyRing) Rotate(previousKeyID string, retiredAt time.Time, nextKeyID string, nextKey AgentCardVerificationKey) error {
	if ring == nil || previousKeyID == "" || nextKeyID == "" || retiredAt.IsZero() || !validAgentCardVerificationKey(nextKeyID, nextKey) {
		return ErrAgentCardInvalid
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	previous, exists := ring.keys[previousKeyID]
	if !exists || previousKeyID == nextKeyID || !previous.RetiredAt.IsZero() ||
		(!previous.NotBefore.IsZero() && retiredAt.Before(previous.NotBefore)) {
		return ErrAgentCardInvalid
	}
	if _, revoked := ring.revoked[previousKeyID]; revoked {
		return ErrAgentCardInvalid
	}
	if _, exists := ring.keys[nextKeyID]; exists {
		return ErrAgentCardInvalid
	}
	previous.RetiredAt = retiredAt.UTC()
	ring.keys[previousKeyID] = previous
	ring.keys[nextKeyID] = nextKey
	return nil
}

// RevokeKey immediately and permanently rejects cards signed with keyID.
func (ring *AgentCardKeyRing) RevokeKey(keyID string) error {
	if ring == nil || !safeProtocolString(keyID, 256) {
		return ErrAgentCardInvalid
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if _, exists := ring.keys[keyID]; !exists {
		return ErrAgentCardInvalid
	}
	ring.revoked[keyID] = struct{}{}
	return nil
}

func (ring *AgentCardKeyRing) resolve(keyID string, now time.Time) (AgentCardVerificationKey, bool) {
	if ring == nil {
		return AgentCardVerificationKey{}, false
	}
	ring.mu.RLock()
	defer ring.mu.RUnlock()
	key, found := ring.keys[keyID]
	if !found {
		return AgentCardVerificationKey{}, false
	}
	if _, revoked := ring.revoked[keyID]; revoked || (!key.NotBefore.IsZero() && now.Before(key.NotBefore)) ||
		(!key.RetiredAt.IsZero() && !now.Before(key.RetiredAt)) {
		return AgentCardVerificationKey{}, false
	}
	return key, true
}

func validAgentCardVerificationKey(keyID string, key AgentCardVerificationKey) bool {
	return safeProtocolString(keyID, 256) && key.Verifier != nil &&
		(key.NotBefore.IsZero() || key.RetiredAt.IsZero() || key.NotBefore.Before(key.RetiredAt))
}

// HMACAgentCardSigner implements HMAC-SHA256 card signatures using a key that
// is copied at construction time. It is appropriate only where both signing
// and verification endpoints can securely hold the same secret.
type HMACAgentCardSigner struct {
	key []byte
}

func NewHMACAgentCardSigner(key []byte) (*HMACAgentCardSigner, error) {
	if len(key) < 32 {
		return nil, ErrAgentCardInvalid
	}
	return &HMACAgentCardSigner{key: append([]byte(nil), key...)}, nil
}

func (signer *HMACAgentCardSigner) Sign(payload []byte) (string, error) {
	if signer == nil || len(signer.key) < 32 {
		return "", ErrAgentCardInvalid
	}
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write(payload)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func (signer *HMACAgentCardSigner) Verify(payload []byte, signature string) error {
	if signer == nil || len(signer.key) < 32 || !strings.HasPrefix(signature, "hmac-sha256:") {
		return ErrAgentCardInvalid
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(signature, "hmac-sha256:"))
	if err != nil || len(provided) != sha256.Size {
		return ErrAgentCardInvalid
	}
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write(payload)
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return ErrAgentCardInvalid
	}
	return nil
}

func SignAgentCard(ctx context.Context, card aop.AgentCard, signer AgentCardSigner, now time.Time) (aop.AgentCard, error) {
	if signer == nil || now.IsZero() || contextError(ctx) != nil {
		return aop.AgentCard{}, ErrAgentCardInvalid
	}
	card.Signature = ""
	card = canonicalAgentCard(card)
	if err := validateUnsignedAgentCard(card, now); err != nil {
		return aop.AgentCard{}, err
	}
	payload, err := agentCardPayload(card)
	if err != nil {
		return aop.AgentCard{}, ErrAgentCardInvalid
	}
	signature, err := signer.Sign(payload)
	if err != nil || signature == "" || containsCredential(signature) {
		return aop.AgentCard{}, ErrAgentCardInvalid
	}
	card.Signature = signature
	if err := card.Validate(now, nil); err != nil {
		return aop.AgentCard{}, ErrAgentCardInvalid
	}
	return card, nil
}

// VerifyAgentCard verifies a card using a single caller-supplied signer.
// Deprecated: use VerifyAgentCardWithKeyRing so KeyID is resolved against an
// explicit trusted key ring during key rotation.
func VerifyAgentCard(ctx context.Context, card aop.AgentCard, signer AgentCardSigner, now time.Time, revokedKeys map[string]bool) error {
	if signer == nil || now.IsZero() || card.Signature == "" || contextError(ctx) != nil {
		return ErrAgentCardInvalid
	}
	signature := card.Signature
	card = canonicalAgentCard(card)
	if err := card.Validate(now, revokedKeys); err != nil {
		return ErrAgentCardInvalid
	}
	card.Signature = ""
	if err := validateUnsignedAgentCard(card, now); err != nil {
		return err
	}
	payload, err := agentCardPayload(card)
	if err != nil || signer.Verify(payload, signature) != nil {
		return ErrAgentCardInvalid
	}
	return nil
}

// VerifyAgentCardWithKeyRing verifies a card only when its KeyID resolves to a
// currently trusted, non-revoked key. The card cannot outlive a scheduled key
// retirement, preventing an old signing key from extending its acceptance.
func VerifyAgentCardWithKeyRing(ctx context.Context, card aop.AgentCard, ring *AgentCardKeyRing, now time.Time) error {
	if ring == nil || now.IsZero() || card.Signature == "" || contextError(ctx) != nil {
		return ErrAgentCardInvalid
	}
	signature := card.Signature
	card = canonicalAgentCard(card)
	if err := card.Validate(now, nil); err != nil {
		return ErrAgentCardInvalid
	}
	key, found := ring.resolve(card.KeyID, now)
	if !found || (!key.RetiredAt.IsZero() && card.ExpiresAt.After(key.RetiredAt)) {
		return ErrAgentCardInvalid
	}
	card.Signature = ""
	if err := validateUnsignedAgentCard(card, now); err != nil {
		return err
	}
	payload, err := agentCardPayload(card)
	if err != nil || key.Verifier.Verify(payload, signature) != nil {
		return ErrAgentCardInvalid
	}
	return nil
}

func validateUnsignedAgentCard(card aop.AgentCard, now time.Time) error {
	if !safeProtocolString(card.Name, 256) || !safeProtocolString(card.Description, 4096) ||
		!safeProtocolString(card.KeyID, 256) || card.Signature != "" || !now.Before(card.ExpiresAt) ||
		len(card.SupportedInterfaces) == 0 || len(card.Skills) == 0 || len(card.InputModes) == 0 ||
		len(card.OutputModes) == 0 || len(card.AuthenticationSchemes) == 0 {
		return ErrAgentCardInvalid
	}
	encoded, err := json.Marshal(card)
	if err != nil || len(encoded) > 64<<10 || containsCredential(string(encoded)) {
		return ErrAgentCardInvalid
	}
	seenEndpoints := make(map[string]struct{}, len(card.SupportedInterfaces))
	for _, endpoint := range card.SupportedInterfaces {
		parsed, parseErr := url.Parse(endpoint.URL)
		if parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
			endpoint.ProtocolBinding != "HTTP+JSON" || endpoint.ProtocolVersion != aop.Version {
			return ErrAgentCardInvalid
		}
		if _, exists := seenEndpoints[endpoint.URL]; exists {
			return ErrAgentCardInvalid
		}
		seenEndpoints[endpoint.URL] = struct{}{}
	}
	if duplicateOrEmpty(card.InputModes) || duplicateOrEmpty(card.OutputModes) || duplicateOrEmpty(card.AuthenticationSchemes) {
		return ErrAgentCardInvalid
	}
	return nil
}

func canonicalAgentCard(card aop.AgentCard) aop.AgentCard {
	card.SupportedInterfaces = append([]aop.CardInterface(nil), card.SupportedInterfaces...)
	card.Capabilities.Extensions = append([]aop.CardExtension(nil), card.Capabilities.Extensions...)
	card.Skills = append([]aop.CardSkill(nil), card.Skills...)
	card.InputModes = append([]string(nil), card.InputModes...)
	card.OutputModes = append([]string(nil), card.OutputModes...)
	card.AuthenticationSchemes = append([]string(nil), card.AuthenticationSchemes...)
	for index := range card.Skills {
		card.Skills[index].Tags = append([]string(nil), card.Skills[index].Tags...)
		sort.Strings(card.Skills[index].Tags)
	}
	sort.Slice(card.SupportedInterfaces, func(i, j int) bool { return card.SupportedInterfaces[i].URL < card.SupportedInterfaces[j].URL })
	sort.Slice(card.Capabilities.Extensions, func(i, j int) bool { return card.Capabilities.Extensions[i].URI < card.Capabilities.Extensions[j].URI })
	sort.Slice(card.Skills, func(i, j int) bool { return card.Skills[i].ID < card.Skills[j].ID })
	sort.Strings(card.InputModes)
	sort.Strings(card.OutputModes)
	sort.Strings(card.AuthenticationSchemes)
	card.ExpiresAt = card.ExpiresAt.UTC()
	return card
}

func agentCardPayload(card aop.AgentCard) ([]byte, error) {
	card.Signature = ""
	encoded, err := json.Marshal(card)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func duplicateOrEmpty(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
