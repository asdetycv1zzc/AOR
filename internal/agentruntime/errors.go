package agentruntime

import "errors"

var (
	ErrInvalidDeclaration    = errors.New("invalid agent declaration")
	ErrInvalidTransition     = errors.New("invalid agent lifecycle transition")
	ErrRunNotFound           = errors.New("agent run not found")
	ErrRunExists             = errors.New("agent run already exists")
	ErrRunBusy               = errors.New("agent run already has an active operation")
	ErrLeaseInvalid          = errors.New("agent lease invalid")
	ErrLeaseExpired          = errors.New("agent lease expired")
	ErrLeaseBinding          = errors.New("agent lease binding mismatch")
	ErrCapabilityDenied      = errors.New("agent capability denied")
	ErrPromptIntegrity       = errors.New("prompt bundle integrity validation failed")
	ErrContextIntegrity      = errors.New("context manifest integrity validation failed")
	ErrBlindAuditContext     = errors.New("blind auditor context contains forbidden input")
	ErrProviderUnavailable   = errors.New("model gateway unavailable")
	ErrToolBrokerUnavailable = errors.New("tool broker unavailable")
	ErrOutputInvalid         = errors.New("agent output invalid")
	ErrIntentDenied          = errors.New("agent output intent denied for role")
	ErrActiveLimit           = errors.New("invalid active agent limit")
	ErrAgentCardInvalid      = errors.New("agent card invalid")
)
