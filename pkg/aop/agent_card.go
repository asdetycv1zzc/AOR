package aop

import (
	"fmt"
	"net/url"
	"time"
)

type AgentCard struct {
	Name                  string           `json:"name"`
	Description           string           `json:"description"`
	SupportedInterfaces   []CardInterface  `json:"supportedInterfaces"`
	Capabilities          CardCapabilities `json:"capabilities"`
	Skills                []CardSkill      `json:"skills"`
	InputModes            []string         `json:"inputModes"`
	OutputModes           []string         `json:"outputModes"`
	AuthenticationSchemes []string         `json:"authenticationSchemes"`
	ExpiresAt             time.Time        `json:"expiresAt"`
	KeyID                 string           `json:"kid"`
	Signature             string           `json:"signature"`
}

type CardInterface struct {
	URL             string `json:"url"`
	ProtocolBinding string `json:"protocolBinding"`
	ProtocolVersion string `json:"protocolVersion"`
}

type CardCapabilities struct {
	Streaming         bool            `json:"streaming"`
	PushNotifications bool            `json:"pushNotifications"`
	Extensions        []CardExtension `json:"extensions"`
}

type CardExtension struct {
	URI         string `json:"uri"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required"`
}

type CardSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags"`
}

func (c AgentCard) Validate(now time.Time, revokedKeys map[string]bool) error {
	if c.Name == "" || c.Description == "" || len(c.SupportedInterfaces) == 0 || len(c.Skills) == 0 || len(c.AuthenticationSchemes) == 0 {
		return fmt.Errorf("agent card identity and capabilities are required")
	}
	if c.KeyID == "" || c.Signature == "" || !now.Before(c.ExpiresAt) || revokedKeys[c.KeyID] {
		return fmt.Errorf("agent card signature is absent, expired, or revoked")
	}
	for _, supported := range c.SupportedInterfaces {
		endpoint, err := url.Parse(supported.URL)
		if err != nil || endpoint.Scheme != "https" || supported.ProtocolBinding != "HTTP+JSON" || supported.ProtocolVersion != "1.0" {
			return fmt.Errorf("unsupported A2A interface")
		}
	}
	foundAOP := false
	for _, extension := range c.Capabilities.Extensions {
		if extension.URI == ExtensionURI {
			if !extension.Required {
				return fmt.Errorf("AOP extension must be required")
			}
			foundAOP = true
		} else if extension.Required {
			return fmt.Errorf("unknown required extension")
		}
	}
	if !foundAOP {
		return fmt.Errorf("AOP extension is missing")
	}
	return nil
}
