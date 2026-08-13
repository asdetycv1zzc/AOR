package agentruntime

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/akimisaka/aor/internal/modelgateway"
)

const (
	DefaultEffectiveContextPercent = 95
	DefaultAutoCompactPercent      = 90
	MaximumRetainedUserTokens      = 20_000
)

type CompactionCheckpoint struct {
	Section             string   `json:"section"`
	Version             int      `json:"version"`
	SourceContextSHA256 string   `json:"sourceContextSha256"`
	SourceReferences    []string `json:"sourceReferences"`
	Summary             string   `json:"summary"`
	RetainedUserInput   []string `json:"retainedUserInput"`
}

type contextEnvelope struct {
	Section      string          `json:"section"`
	Authority    bool            `json:"authority"`
	Kind         ContextKind     `json:"kind"`
	Reference    string          `json:"reference"`
	SHA256       string          `json:"sha256"`
	SourceSHA256 string          `json:"sourceSha256"`
	Content      json.RawMessage `json:"content"`
}

type compactionContextReference struct {
	reference    string
	sha256       string
	sourceSHA256 string
}

const compactionCheckpointSection = "COMPACTION_CHECKPOINT"

func EffectiveContextTokens(contextWindowTokens int) int {
	if contextWindowTokens <= 0 {
		return 0
	}
	return contextWindowTokens * DefaultEffectiveContextPercent / 100
}

func DefaultCompactionThreshold(contextWindowTokens int) int {
	if contextWindowTokens <= 0 {
		return 0
	}
	return contextWindowTokens * DefaultAutoCompactPercent / 100
}

func ClampCompactionThreshold(contextWindowTokens, configured int) int {
	maximum := DefaultCompactionThreshold(contextWindowTokens)
	if configured <= 0 || configured > maximum {
		return maximum
	}
	return configured
}

func EstimateMessagesTokens(messages []modelgateway.Message) int64 {
	var total int64
	for _, message := range messages {
		total += estimateTextTokens(message.Role) + estimateTextTokens(message.Content) + 4
		for _, call := range message.ToolCalls {
			total += estimateTextTokens(call.ID) + estimateTextTokens(call.Name) + int64((len(call.Arguments)+3)/4) + 8
		}
		total += estimateTextTokens(message.ToolCallID)
	}
	return total
}

func EstimateRequestOverheadTokens(tools []modelgateway.ToolDefinition, responseSchema json.RawMessage) int64 {
	total := estimateTextTokens(string(responseSchema))
	for _, tool := range tools {
		total += estimateTextTokens(tool.Name) + estimateTextTokens(tool.Description) + estimateTextTokens(string(tool.Schema)) + 3
	}
	return total
}

func CompactMessages(messages []modelgateway.Message, sourceContextSHA256 string, targetTokens int) ([]modelgateway.Message, CompactionCheckpoint, error) {
	return compactMessages(messages, sourceContextSHA256, nil, targetTokens)
}

// CompactMessagesWithManifest keeps only context envelopes that match the
// validated declaration manifest. This prevents a model-authored message from
// manufacturing an authoritative-looking reference during compaction.
func CompactMessagesWithManifest(messages []modelgateway.Message, manifest ContextManifest, targetTokens int) ([]modelgateway.Message, CompactionCheckpoint, error) {
	allowed := make(map[string]compactionContextReference, len(manifest.Items))
	for _, item := range manifest.Items {
		if item.Kind != ContextGoalReference && item.Kind != ContextPlanReference && item.Kind != ContextModuleReference && item.Kind != ContextUserInput {
			continue
		}
		key := string(item.Kind) + "\x00" + item.Reference
		allowed[key] = compactionContextReference{reference: item.Reference, sha256: item.SHA256, sourceSHA256: item.SourceSHA256}
	}
	return compactMessages(messages, manifest.SHA256, allowed, targetTokens)
}

func compactMessages(messages []modelgateway.Message, sourceContextSHA256 string, allowed map[string]compactionContextReference, targetTokens int) ([]modelgateway.Message, CompactionCheckpoint, error) {
	if len(messages) == 0 || sourceContextSHA256 == "" || targetTokens <= 0 {
		return nil, CompactionCheckpoint{}, ErrInvalidDeclaration
	}
	prefix, body := canonicalPrefix(messages)
	if EstimateMessagesTokens(messages) <= int64(targetTokens) {
		return append([]modelgateway.Message(nil), messages...), CompactionCheckpoint{}, nil
	}
	canonicalReferences := make(map[string]struct{}, len(body))
	for _, message := range body {
		if message.Role != "user" {
			continue
		}
		if reference, preserve := canonicalContextReference(message.Content, allowed); preserve {
			canonicalReferences[reference] = struct{}{}
		}
	}
	references := make([]string, 0, len(body))
	canonical := make([]modelgateway.Message, 0, len(body))
	summaryParts := make([]string, 0, len(body))
	userMessages := make([]string, 0, len(body))
	for _, message := range body {
		switch message.Role {
		case "user":
			if previous, compacted := parseCompactionCheckpoint(message.Content); compacted {
				if previous.SourceContextSHA256 != sourceContextSHA256 {
					continue
				}
				for _, reference := range previous.SourceReferences {
					_, present := canonicalReferences[reference]
					if present && (allowed == nil || contextReferenceAllowed(allowed, reference)) {
						references = append(references, reference)
					}
				}
				if previous.Summary != "" {
					summaryParts = append(summaryParts, previous.Summary)
				}
				userMessages = append(userMessages, previous.RetainedUserInput...)
				continue
			}
			if reference, preserve := canonicalContextReference(message.Content, allowed); preserve {
				references = append(references, reference)
				canonical = append(canonical, message)
				continue
			}
			userMessages = append(userMessages, message.Content)
		case "assistant":
			if strings.TrimSpace(message.Content) != "" {
				summaryParts = append(summaryParts, "assistant: "+message.Content)
			}
			for _, call := range message.ToolCalls {
				summaryParts = append(summaryParts, "assistant tool "+call.Name+" ("+call.ID+"): "+string(call.Arguments))
			}
		case "tool":
			if strings.TrimSpace(message.Content) != "" {
				summaryParts = append(summaryParts, "tool "+message.ToolCallID+": "+message.Content)
			}
		}
	}
	retained := retainRecentUserInput(userMessages, MaximumRetainedUserTokens)
	summary := strings.Join(summaryParts, "\n")
	if summary == "" {
		summary = "The authoritative source context remains available through the checkpoint references."
	}
	checkpoint := CompactionCheckpoint{
		Section: compactionCheckpointSection, Version: 1, SourceContextSHA256: sourceContextSHA256,
		SourceReferences: uniqueSorted(references), Summary: summary, RetainedUserInput: retained,
	}
	compacted := append([]modelgateway.Message(nil), prefix...)
	compacted = append(compacted, canonical...)
	compacted = append(compacted, modelgateway.Message{Role: "user"})
	updateCheckpoint := func() error {
		encoded, marshalErr := json.Marshal(checkpoint)
		if marshalErr != nil {
			return marshalErr
		}
		compacted[len(compacted)-1].Content = string(encoded)
		return nil
	}
	if err := updateCheckpoint(); err != nil {
		return nil, CompactionCheckpoint{}, err
	}
	// Shorten generated history before discarding retained user decisions.
	for EstimateMessagesTokens(compacted) > int64(targetTokens) && checkpoint.Summary != "" {
		excess := EstimateMessagesTokens(compacted) - int64(targetTokens)
		maximumBytes := len(checkpoint.Summary) - int(excess)*4
		if maximumBytes >= len(checkpoint.Summary) {
			maximumBytes = len(checkpoint.Summary) - 1
		}
		if maximumBytes < 0 {
			maximumBytes = 0
		}
		checkpoint.Summary = truncateUTF8(checkpoint.Summary, maximumBytes)
		if err := updateCheckpoint(); err != nil {
			return nil, CompactionCheckpoint{}, err
		}
	}
	for EstimateMessagesTokens(compacted) > int64(targetTokens) && len(checkpoint.RetainedUserInput) > 1 {
		checkpoint.RetainedUserInput = checkpoint.RetainedUserInput[1:]
		if err := updateCheckpoint(); err != nil {
			return nil, CompactionCheckpoint{}, err
		}
	}
	for EstimateMessagesTokens(compacted) > int64(targetTokens) && len(checkpoint.RetainedUserInput) == 1 && checkpoint.RetainedUserInput[0] != "" {
		excess := EstimateMessagesTokens(compacted) - int64(targetTokens)
		maximumBytes := len(checkpoint.RetainedUserInput[0]) - int(excess)*4
		if maximumBytes >= len(checkpoint.RetainedUserInput[0]) {
			maximumBytes = len(checkpoint.RetainedUserInput[0]) - 1
		}
		if maximumBytes < 0 {
			maximumBytes = 0
		}
		checkpoint.RetainedUserInput[0] = truncateUTF8(checkpoint.RetainedUserInput[0], maximumBytes)
		if err := updateCheckpoint(); err != nil {
			return nil, CompactionCheckpoint{}, err
		}
	}
	if EstimateMessagesTokens(compacted) > int64(targetTokens) {
		return nil, CompactionCheckpoint{}, modelgateway.ErrContextWindowExceeded
	}
	return compacted, checkpoint, nil
}

func parseCompactionCheckpoint(content string) (CompactionCheckpoint, bool) {
	var checkpoint CompactionCheckpoint
	if json.Unmarshal([]byte(content), &checkpoint) != nil || checkpoint.Section != compactionCheckpointSection || checkpoint.Version != 1 || checkpoint.SourceContextSHA256 == "" {
		return CompactionCheckpoint{}, false
	}
	return checkpoint, true
}

func canonicalContextReference(content string, allowed map[string]compactionContextReference) (string, bool) {
	var envelope contextEnvelope
	if json.Unmarshal([]byte(content), &envelope) != nil || envelope.Section != "CONTEXT" || envelope.Authority {
		return "", false
	}
	if strings.TrimSpace(envelope.Reference) == "" {
		return "", false
	}
	switch envelope.Kind {
	case ContextGoalReference, ContextPlanReference, ContextModuleReference, ContextUserInput:
		if allowed == nil {
			return envelope.Reference, true
		}
		expected, found := allowed[string(envelope.Kind)+"\x00"+envelope.Reference]
		if !found || envelope.SHA256 != expected.sha256 || envelope.SourceSHA256 != expected.sourceSHA256 {
			return "", false
		}
		var contentText string
		if json.Unmarshal(envelope.Content, &contentText) != nil || DigestContextContent(contentText) != expected.sha256 {
			return "", false
		}
		return envelope.Reference, true
	default:
		return "", false
	}
}

func contextReferenceAllowed(allowed map[string]compactionContextReference, reference string) bool {
	for _, expected := range allowed {
		if expected.reference == reference {
			return true
		}
	}
	return false
}

func canonicalPrefix(messages []modelgateway.Message) ([]modelgateway.Message, []modelgateway.Message) {
	index := 0
	for index < len(messages) && messages[index].Role == "system" {
		index++
	}
	return append([]modelgateway.Message(nil), messages[:index]...), messages[index:]
}

func retainRecentUserInput(messages []string, maximumTokens int) []string {
	remaining := maximumTokens
	result := make([]string, 0, len(messages))
	for index := len(messages) - 1; index >= 0 && remaining > 0; index-- {
		content := messages[index]
		tokens := int(estimateTextTokens(content))
		if tokens > remaining {
			content = truncateUTF8(content, remaining*4)
			tokens = int(estimateTextTokens(content))
		}
		result = append(result, content)
		remaining -= tokens
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}

func estimateTextTokens(value string) int64 {
	if value == "" {
		return 0
	}
	if !utf8.ValidString(value) {
		return int64((len(value) + 3) / 4)
	}
	asciiBytes, nonASCII := 0, 0
	for _, runeValue := range value {
		if runeValue <= 0x7f {
			asciiBytes++
		} else {
			nonASCII++
		}
	}
	return int64((asciiBytes+3)/4 + nonASCII)
}

func truncateUTF8(value string, maximumBytes int) string {
	if len(value) <= maximumBytes {
		return value
	}
	end := maximumBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
