package agentruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bsk-[a-z0-9_-]{16,}\b`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9._-]{16,}`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`),
}

type AssembledPrompt struct {
	Messages []modelgateway.Message
	SHA256   string
}

type promptBundleDigestView struct {
	BundleID      string `json:"bundleId"`
	Version       string `json:"version"`
	Role          Role   `json:"role"`
	GlobalSafety  string `json:"globalSafety"`
	RolePrompt    string `json:"rolePrompt"`
	FixedWorkflow string `json:"fixedWorkflow"`
	OutputRules   string `json:"outputRules"`
}

func DigestPromptBundle(bundle PromptBundle) string {
	return digestJSON(promptBundleDigestView{
		BundleID: bundle.BundleID, Version: bundle.Version, Role: bundle.Role,
		GlobalSafety: bundle.GlobalSafety, RolePrompt: bundle.RolePrompt,
		FixedWorkflow: bundle.FixedWorkflow, OutputRules: bundle.OutputRules,
	})
}

type contextManifestDigestView struct {
	ManifestID string        `json:"manifestId"`
	Version    string        `json:"version"`
	Role       Role          `json:"role"`
	Items      []ContextItem `json:"items"`
}

func DigestContextManifest(manifest ContextManifest) string {
	items := append([]ContextItem(nil), manifest.Items...)
	sortContextItems(items)
	return digestJSON(contextManifestDigestView{ManifestID: manifest.ManifestID, Version: manifest.Version, Role: manifest.Role, Items: items})
}

func DigestContextContent(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func DigestToolDefinitions(tools []modelgateway.ToolDefinition) string {
	copyTools := append([]modelgateway.ToolDefinition(nil), tools...)
	sort.Slice(copyTools, func(i, j int) bool { return copyTools[i].Name < copyTools[j].Name })
	return digestJSON(copyTools)
}

func ValidatePromptBundle(bundle PromptBundle) error {
	if bundle.BundleID == "" || bundle.Version == "" || !bundle.Role.Valid() ||
		strings.TrimSpace(bundle.GlobalSafety) == "" || strings.TrimSpace(bundle.RolePrompt) == "" ||
		strings.TrimSpace(bundle.FixedWorkflow) == "" || strings.TrimSpace(bundle.OutputRules) == "" ||
		!validDigest(bundle.SHA256) || bundle.SHA256 != DigestPromptBundle(bundle) {
		return ErrPromptIntegrity
	}
	totalBytes := len(bundle.GlobalSafety) + len(bundle.RolePrompt) + len(bundle.FixedWorkflow) + len(bundle.OutputRules)
	if !safeProtocolString(bundle.BundleID, 128) || !safeProtocolString(bundle.Version, 128) || totalBytes > MaximumPromptBundleBytes {
		return ErrPromptIntegrity
	}
	for _, value := range []string{bundle.GlobalSafety, bundle.RolePrompt, bundle.FixedWorkflow, bundle.OutputRules} {
		if !utf8.ValidString(value) || containsCredential(value) {
			return ErrPromptIntegrity
		}
	}
	return nil
}

func ValidateContextManifest(manifest ContextManifest) error {
	if !safeProtocolString(manifest.ManifestID, 128) || !safeProtocolString(manifest.Version, 128) || !manifest.Role.Valid() ||
		!validDigest(manifest.SHA256) || manifest.SHA256 != DigestContextManifest(manifest) ||
		len(manifest.Items) > MaximumContextItems {
		return ErrContextIntegrity
	}
	seen := make(map[string]struct{}, len(manifest.Items))
	totalBytes := 0
	for _, item := range manifest.Items {
		if !safeProtocolString(item.ID, 128) || !item.Kind.Valid() || !safeProtocolString(item.Reference, 2048) ||
			(item.Revision != "" && !safeProtocolString(item.Revision, 256)) || !item.Trust.Valid() || !utf8.ValidString(item.Content) ||
			!validDigest(item.SHA256) || item.SHA256 != DigestContextContent(item.Content) ||
			(item.SourceSHA256 != "" && !validDigest(item.SourceSHA256)) || len(item.Content) > MaximumContextItemBytes {
			return ErrContextIntegrity
		}
		if contextRequiresSourceDigest(item.Kind) && item.SourceSHA256 == "" {
			return ErrContextIntegrity
		}
		if _, exists := seen[item.ID]; exists {
			return ErrContextIntegrity
		}
		seen[item.ID] = struct{}{}
		if (item.LineStart == 0) != (item.LineEnd == 0) || item.LineStart < 0 || item.LineEnd < item.LineStart ||
			(item.LineStart > 0 && item.LineEnd-item.LineStart+1 > 200) {
			return ErrContextIntegrity
		}
		if item.Kind == ContextKnowledgeSnippet && (item.Revision == "" || item.LineStart < 1) {
			return ErrContextIntegrity
		}
		if requiresUntrustedLabel(item.Kind) && item.Trust != TrustExternalUntrusted {
			return ErrContextIntegrity
		}
		if containsCredential(item.Content) {
			return ErrContextIntegrity
		}
		totalBytes += len(item.Content)
		if totalBytes > MaximumContextBytes {
			return ErrContextIntegrity
		}
	}
	if auditorRole(manifest.Role) {
		for _, item := range manifest.Items {
			if forbiddenAuditorContext(item.Kind) {
				return ErrBlindAuditContext
			}
			if manifest.Role == RoleModuleAuditor && !moduleAuditorContextAllowed(item.Kind) {
				return ErrBlindAuditContext
			}
		}
	}
	return nil
}

func AssemblePrompt(bundle PromptBundle, manifest ContextManifest, responseSchemaRef string, responseSchema json.RawMessage) (AssembledPrompt, error) {
	if err := ValidatePromptBundle(bundle); err != nil {
		return AssembledPrompt{}, err
	}
	if err := ValidateContextManifest(manifest); err != nil {
		return AssembledPrompt{}, err
	}
	if bundle.Role != manifest.Role || !safeProtocolString(responseSchemaRef, 2048) || len(responseSchema) == 0 || len(responseSchema) > MaximumResponseSchemaBytes || !json.Valid(responseSchema) {
		return AssembledPrompt{}, ErrPromptIntegrity
	}
	messages := []modelgateway.Message{
		{Role: "system", Content: authoritySection("GLOBAL_SAFETY", bundle.BundleID, bundle.Version, bundle.GlobalSafety)},
		{Role: "system", Content: authoritySection("ROLE", bundle.BundleID, bundle.Version, bundle.RolePrompt)},
		{Role: "system", Content: authoritySection("WORKFLOW", bundle.BundleID, bundle.Version, bundle.FixedWorkflow)},
		{Role: "system", Content: outputSection(bundle, responseSchemaRef, responseSchema)},
	}
	items := append([]ContextItem(nil), manifest.Items...)
	sortContextItems(items)
	for _, item := range items {
		messages = append(messages, modelgateway.Message{Role: contextMessageRole(item), Content: contextSection(item)})
	}
	assembled := AssembledPrompt{Messages: messages}
	assembled.SHA256 = digestJSON(struct {
		BundleDigest  string                 `json:"bundleDigest"`
		ContextDigest string                 `json:"contextDigest"`
		Messages      []modelgateway.Message `json:"messages"`
	}{BundleDigest: bundle.SHA256, ContextDigest: manifest.SHA256, Messages: messages})
	return assembled, nil
}

func authoritySection(kind, bundleID, version, content string) string {
	return encodeSection(struct {
		Section   string `json:"section"`
		Authority bool   `json:"authority"`
		BundleID  string `json:"bundleId"`
		Version   string `json:"version"`
		Content   string `json:"content"`
	}{Section: kind, Authority: true, BundleID: bundleID, Version: version, Content: content})
}

func outputSection(bundle PromptBundle, schemaRef string, schema json.RawMessage) string {
	return encodeSection(struct {
		Section   string          `json:"section"`
		Authority bool            `json:"authority"`
		BundleID  string          `json:"bundleId"`
		Version   string          `json:"version"`
		Rules     string          `json:"rules"`
		SchemaRef string          `json:"schemaRef"`
		Schema    json.RawMessage `json:"schema"`
	}{Section: "OUTPUT_SCHEMA", Authority: true, BundleID: bundle.BundleID, Version: bundle.Version, Rules: bundle.OutputRules, SchemaRef: schemaRef, Schema: schema})
}

func contextSection(item ContextItem) string {
	return encodeSection(struct {
		Section      string      `json:"section"`
		Authority    bool        `json:"authority"`
		Kind         ContextKind `json:"kind"`
		Reference    string      `json:"reference"`
		Revision     string      `json:"revision,omitempty"`
		SHA256       string      `json:"sha256"`
		SourceSHA256 string      `json:"sourceSha256,omitempty"`
		LineStart    int         `json:"lineStart,omitempty"`
		LineEnd      int         `json:"lineEnd,omitempty"`
		Trust        TrustLevel  `json:"trust"`
		Content      string      `json:"content"`
	}{Section: "CONTEXT", Authority: false, Kind: item.Kind, Reference: item.Reference, Revision: item.Revision, SHA256: item.SHA256, SourceSHA256: item.SourceSHA256, LineStart: item.LineStart, LineEnd: item.LineEnd, Trust: item.Trust, Content: item.Content})
}

func encodeSection(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func contextMessageRole(item ContextItem) string {
	if item.Kind == ContextUserInput {
		return "user"
	}
	return "user"
}

func sortContextItems(items []ContextItem) {
	sort.Slice(items, func(i, j int) bool {
		left, right := contextRank(items[i].Kind), contextRank(items[j].Kind)
		if left != right {
			return left < right
		}
		if items[i].Reference != items[j].Reference {
			return items[i].Reference < items[j].Reference
		}
		return items[i].ID < items[j].ID
	})
}

func contextRank(kind ContextKind) int {
	switch kind {
	case ContextGoalReference:
		return 50
	case ContextPlanReference:
		return 51
	case ContextModuleReference:
		return 52
	case ContextKnowledgeSnippet:
		return 60
	case ContextTaskState:
		return 70
	case ContextDeterministicDiff:
		return 71
	case ContextDeterministicResult:
		return 72
	case ContextPriorFinding:
		return 73
	default:
		return 80
	}
}

func requiresUntrustedLabel(kind ContextKind) bool {
	switch kind {
	case ContextUserInput, ContextRepositoryContent, ContextToolOutput, ContextExecutorStatement, ContextPrivateScratchpad, ContextAuditorFreeText:
		return true
	default:
		return false
	}
}

func contextRequiresSourceDigest(kind ContextKind) bool {
	switch kind {
	case ContextGoalReference, ContextPlanReference, ContextModuleReference, ContextKnowledgeSnippet:
		return true
	default:
		return false
	}
}

func forbiddenAuditorContext(kind ContextKind) bool {
	switch kind {
	case ContextExecutorStatement, ContextPrivateScratchpad, ContextAuditorFreeText, ContextExecutorIdentity:
		return true
	default:
		return false
	}
}

func moduleAuditorContextAllowed(kind ContextKind) bool {
	switch kind {
	case ContextGoalReference, ContextModuleReference, ContextDeterministicDiff, ContextDeterministicResult, ContextPriorFinding:
		return true
	default:
		return false
	}
}

func auditorRole(role Role) bool {
	return role == RoleModuleAuditor || role == RoleGlobalAuditor
}

func containsCredential(value string) bool {
	for _, pattern := range credentialPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func digestJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return ""
	}
	return digest
}
