package agentruntime

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/aop"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type AgentCard = aop.AgentCard

type AgentCardSigner interface {
	Sign(payload []byte) (string, error)
	Verify(payload []byte, signature string) error
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
