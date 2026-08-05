package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const defaultContentType = "text/markdown"

var sourceRevisionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/+@=-]{0,255}$`)

var sourceSchemes = map[string]struct{}{
	"artifact": {}, "file": {}, "git": {}, "http": {}, "https": {}, "kb": {}, "urn": {},
}

var markdownLinkPattern = regexp.MustCompile(`\[[^\]]*\]\(\s*<?([^\s)>]+)>?(?:\s+[^)]*)?\)`)

// Validate checks the immutable identity fields of a source declaration.  It
// intentionally does not fetch the URI: network retrieval would make a
// proposal non-deterministic and belongs to a separately attested importer.
func (source SourceReference) Validate() error {
	if source.URI == "" || len(source.URI) > 2048 || strings.ContainsAny(source.URI, "\r\n\x00") || !utf8.ValidString(source.URI) {
		return invalid("knowledge source uri")
	}
	parsed, err := url.Parse(source.URI)
	if err != nil || parsed.Scheme == "" || parsed.User != nil {
		return invalid("knowledge source uri")
	}
	if _, allowed := sourceSchemes[strings.ToLower(parsed.Scheme)]; !allowed {
		return invalid("knowledge source scheme")
	}
	if (strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")) && parsed.Host == "" {
		return invalid("knowledge source host")
	}
	if !sourceRevisionPattern.MatchString(source.Revision) || !revisionPattern.MatchString(source.SHA256) || !source.TrustLevel.Valid() {
		return invalid("knowledge source identity")
	}
	return nil
}

// VerifiedFor reports whether the source has enough declared provenance for a
// document trust level.  The check is structural and hash-bound; it does not
// claim that an external service was contacted.
func (source SourceReference) VerifiedFor(documentTrust TrustLevel) bool {
	if source.Validate() != nil {
		return false
	}
	return source.TrustLevel != TrustGeneratedUnreviewed && source.TrustLevel != TrustExternalUntrusted && trustRank(source.TrustLevel) >= trustRank(documentTrust)
}

// ValidationReportDigest computes the content address of a report without its
// self-referential SHA256 field.
func ValidationReportDigest(report ValidationReport) (string, error) {
	copyReport := report
	copyReport.SHA256 = ""
	copyReport.Checks = append([]ValidationCheck(nil), report.Checks...)
	encoded, err := json.Marshal(copyReport)
	if err != nil {
		return "", aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil)
	}
	return contentDigest(encoded), nil
}

// ValidateValidationReport verifies the durable report's structure, ordering,
// pass bit and content digest before it can be used as an approval gate.
func ValidateValidationReport(report ValidationReport) error {
	if report.Version != 1 || !revisionPattern.MatchString(report.ProposalDigest) || report.SHA256 == "" || !revisionPattern.MatchString(report.SHA256) || len(report.Checks) == 0 {
		return invalid("knowledge validation report")
	}
	passed := true
	previous := ""
	seen := make(map[string]struct{}, len(report.Checks))
	for _, check := range report.Checks {
		if check.RuleID == "" || (check.Status != ValidationPassed && check.Status != ValidationFailed) {
			return invalid("knowledge validation check")
		}
		key := check.RuleID + "\x00" + check.Path
		if _, exists := seen[key]; exists || (previous != "" && key < previous) {
			return invalid("knowledge validation ordering")
		}
		seen[key] = struct{}{}
		previous = key
		if check.Status != ValidationPassed {
			passed = false
		}
	}
	if report.Passed != passed {
		return invalid("knowledge validation result")
	}
	digest, err := ValidationReportDigest(report)
	if err != nil || digest != report.SHA256 {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", map[string]any{"scope": "knowledge validation report"})
	}
	return nil
}

func buildValidationReport(proposal UpdateProposal, digest string, documents map[string]visibleDocument) ValidationReport {
	checks := []ValidationCheck{{RuleID: "schema.proposal", Status: ValidationPassed, Message: "normalized proposal schema accepted"}}

	seenPaths := make(map[string]struct{}, len(proposal.Documents))
	sourceFailures := 0
	for _, document := range proposal.Documents {
		if _, duplicate := seenPaths[document.Path]; duplicate {
			continue
		}
		seenPaths[document.Path] = struct{}{}
		check := ValidationCheck{RuleID: "source.attribution", Status: ValidationPassed, Path: document.Path, Message: "source identity is hash-bound"}
		if document.Source != nil {
			if err := document.Source.Validate(); err != nil {
				check.Status, check.Message = ValidationFailed, "source identity is invalid"
				sourceFailures++
			} else if document.TrustLevel == TrustCurated && !document.Source.VerifiedFor(document.TrustLevel) {
				check.Status, check.Message = ValidationFailed, "curated document source is not sufficiently trusted"
				sourceFailures++
			}
		} else if document.TrustLevel == TrustCurated {
			check.Status, check.Message = ValidationFailed, "curated document requires a source reference"
			sourceFailures++
		} else {
			check.Message = "no source required for this trust level"
		}
		checks = append(checks, check)
	}
	if len(proposal.Documents) == 0 || sourceFailures == 0 {
		checks = append(checks, ValidationCheck{RuleID: "source.complete", Status: ValidationPassed, Message: "all changed documents have acceptable attribution"})
	} else {
		checks = append(checks, ValidationCheck{RuleID: "source.complete", Status: ValidationFailed, Message: "one or more changed documents lack acceptable attribution"})
	}

	linkChecks := validateMarkdownLinks(proposal, documents)
	checks = append(checks, linkChecks...)
	if len(linkChecks) == 0 {
		checks = append(checks, ValidationCheck{RuleID: "link.references", Status: ValidationPassed, Message: "no broken markdown links"})
	}
	checks = append(checks, ValidationCheck{RuleID: "lint.normalized", Status: ValidationPassed, Message: "paths, tags, content and duplicate rules are normalized"})

	sort.SliceStable(checks, func(i, j int) bool {
		if checks[i].RuleID != checks[j].RuleID {
			return checks[i].RuleID < checks[j].RuleID
		}
		if checks[i].Path != checks[j].Path {
			return checks[i].Path < checks[j].Path
		}
		return checks[i].Status < checks[j].Status
	})
	report := ValidationReport{Version: 1, ProposalDigest: digest, Checks: checks, Passed: true}
	for _, check := range checks {
		if check.Status != ValidationPassed {
			report.Passed = false
			break
		}
	}
	report.SHA256, _ = ValidationReportDigest(report)
	return report
}

func validateMarkdownLinks(proposal UpdateProposal, documents map[string]visibleDocument) []ValidationCheck {
	checks := make([]ValidationCheck, 0)
	seen := make(map[string]struct{})
	for _, candidate := range proposal.Documents {
		links := markdownLinkPattern.FindAllStringSubmatch(string(candidate.Content), -1)
		for _, match := range links {
			if len(match) < 2 {
				continue
			}
			destination := strings.TrimSpace(match[1])
			key := candidate.Path + "\x00" + destination
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			check := ValidationCheck{RuleID: "link.reference", Status: ValidationPassed, Path: candidate.Path + " -> " + destination, Message: "link target is resolvable"}
			if !validKnowledgeLink(candidate.Path, destination, documents) {
				check.Status, check.Message = ValidationFailed, "link target is not resolvable"
			}
			checks = append(checks, check)
		}
	}
	return checks
}

func validKnowledgeLink(documentPath, destination string, documents map[string]visibleDocument) bool {
	if destination == "" {
		return false
	}
	parsed, err := url.Parse(destination)
	if err != nil {
		return false
	}
	if parsed.Scheme != "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https", "mailto", "artifact", "kb", "urn":
			return parsed.Scheme == "mailto" || parsed.Host != "" || parsed.Opaque != ""
		default:
			return false
		}
	}
	target, unescapeErr := url.PathUnescape(parsed.Path)
	if unescapeErr != nil || strings.ContainsRune(target, '\x00') {
		return false
	}
	if target == "" {
		target = documentPath
	} else if strings.HasPrefix(target, "/") {
		return false
	} else {
		for _, segment := range strings.Split(target, "/") {
			if segment == ".." {
				return false
			}
		}
		target = path.Join(path.Dir(documentPath), target)
	}
	normalized, normalizeErr := normalizePath(target)
	if normalizeErr != nil {
		return false
	}
	_, exists := documents[normalized]
	return exists
}

func normalizeDocument(input DocumentInput) (StoredDocument, error) {
	normalizedPath, err := normalizePath(input.Path)
	if err != nil {
		return StoredDocument{}, err
	}
	if input.Title == "" || len(input.Title) > 512 || strings.ContainsAny(input.Title, "\r\n\x00") || !utf8.ValidString(input.Title) {
		return StoredDocument{}, invalid("title")
	}
	if !input.TrustLevel.Valid() {
		return StoredDocument{}, invalid("trust level")
	}
	if input.Source != nil {
		if err := input.Source.Validate(); err != nil {
			return StoredDocument{}, err
		}
	}
	contentType := input.ContentType
	if contentType == "" {
		contentType = defaultContentType
	}
	if len(contentType) > 128 || strings.ContainsAny(contentType, "\r\n\x00") {
		return StoredDocument{}, invalid("content type")
	}
	content, err := normalizeContent(input.Content)
	if err != nil {
		return StoredDocument{}, err
	}
	lines := splitLines(content)
	if len(lines) == 0 {
		return StoredDocument{}, invalid("content")
	}
	terminalLF := content[len(content)-1] == '\n'
	for index, line := range lines {
		lineBytes := len(line)
		if index < len(lines)-1 || terminalLF {
			lineBytes++
		}
		if lineBytes > MaxReadBytes {
			return StoredDocument{}, invalid("line exceeds read page")
		}
	}
	tags, err := normalizeTags(input.Tags)
	if err != nil {
		return StoredDocument{}, err
	}
	digest := contentDigest(content)
	return StoredDocument{
		Metadata: DocumentMetadata{
			Path: normalizedPath, Title: input.Title, Tags: tags, TrustLevel: input.TrustLevel,
			ContentType: contentType, SHA256: digest, LineCount: len(lines), Source: cloneSource(input.Source),
		},
		Content: content,
	}, nil
}

func normalizeContent(content []byte) ([]byte, error) {
	if !utf8.Valid(content) || len(content) == 0 {
		return nil, invalid("utf-8 content")
	}
	if strings.IndexByte(string(content), 0) >= 0 {
		return nil, invalid("content")
	}
	normalized := strings.ReplaceAll(string(content), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	return []byte(normalized), nil
}

func normalizePath(value string) (string, error) {
	if value == "" || len(value) > 1024 || strings.ContainsAny(value, "\\\x00:") || strings.HasPrefix(value, "/") || !utf8.ValidString(value) {
		return "", unauthorizedPath()
	}
	cleaned := path.Clean(value)
	if cleaned != value || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", unauthorizedPath()
	}
	for _, segment := range strings.Split(cleaned, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") || windowsReservedName(segment) {
			return "", unauthorizedPath()
		}
		for _, r := range segment {
			if r < 0x20 || r == 0x7f {
				return "", unauthorizedPath()
			}
		}
	}
	return cleaned, nil
}

func windowsReservedName(segment string) bool {
	base := strings.ToUpper(segment)
	if index := strings.IndexByte(base, '.'); index >= 0 {
		base = base[:index]
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return true
	default:
		return false
	}
}

func normalizeTags(input []string) ([]string, error) {
	if len(input) > 64 {
		return nil, invalid("tags")
	}
	if len(input) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(input))
	tags := make([]string, 0, len(input))
	for _, tag := range input {
		if tag == "" || len(tag) > 128 || strings.ContainsAny(tag, "\r\n\x00") || !utf8.ValidString(tag) {
			return nil, invalid("tag")
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags, nil
}

func splitLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	if len(lines) > 1 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func contentDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type canonicalDocument struct {
	Metadata DocumentMetadata `json:"metadata"`
	Content  string           `json:"content"`
}

type canonicalSnapshot struct {
	Version             int                 `json:"version"`
	TenantID            string              `json:"tenantId"`
	ProjectID           string              `json:"projectId"`
	CreatedAt           time.Time           `json:"createdAt"`
	ParentOrderExplicit bool                `json:"parentOrderExplicit"`
	Parents             []ParentSnapshot    `json:"parents"`
	Overrides           []string            `json:"overrides"`
	Documents           []canonicalDocument `json:"documents"`
}

func snapshotDigest(snapshot Snapshot) (string, error) {
	paths := sortedDocumentPaths(snapshot.Documents)
	documents := make([]canonicalDocument, 0, len(paths))
	for _, documentPath := range paths {
		document := snapshot.Documents[documentPath]
		documents = append(documents, canonicalDocument{Metadata: document.Metadata, Content: string(document.Content)})
	}
	payload := canonicalSnapshot{
		Version: snapshot.Manifest.Version, TenantID: snapshot.Manifest.TenantID,
		ProjectID: snapshot.Manifest.ProjectID, CreatedAt: snapshot.Manifest.CreatedAt,
		ParentOrderExplicit: snapshot.Manifest.ParentOrderExplicit,
		Parents:             append([]ParentSnapshot(nil), snapshot.Manifest.Parents...),
		Overrides:           append([]string(nil), snapshot.Manifest.Overrides...), Documents: documents,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil)
	}
	return contentDigest(encoded), nil
}

func proposalDigest(proposal UpdateProposal) (string, error) {
	if proposal.BaseRevision != "" && !revisionPattern.MatchString(proposal.BaseRevision) {
		return "", invalid("base revision")
	}
	if len(proposal.Parents) > 1 && !proposal.ParentOrderExplicit {
		return "", invalid("parent order")
	}
	parentProjects := make(map[string]struct{}, len(proposal.Parents))
	for index, parent := range proposal.Parents {
		if parent.ProjectID == "" || !revisionPattern.MatchString(parent.Revision) || parent.Order != index {
			return "", invalid("parent snapshot")
		}
		if _, duplicate := parentProjects[parent.ProjectID]; duplicate {
			return "", invalid("duplicate parent")
		}
		parentProjects[parent.ProjectID] = struct{}{}
	}
	documents := make([]DocumentInput, len(proposal.Documents))
	copy(documents, proposal.Documents)
	sort.Slice(documents, func(i, j int) bool { return documents[i].Path < documents[j].Path })
	type proposalDocument struct {
		Path        string           `json:"path"`
		Title       string           `json:"title"`
		Tags        []string         `json:"tags"`
		TrustLevel  TrustLevel       `json:"trustLevel"`
		ContentType string           `json:"contentType"`
		Content     string           `json:"content"`
		Source      *SourceReference `json:"source,omitempty"`
	}
	canonicalDocuments := make([]proposalDocument, 0, len(documents))
	for _, input := range documents {
		document, err := normalizeDocument(input)
		if err != nil {
			return "", err
		}
		canonicalDocuments = append(canonicalDocuments, proposalDocument{
			Path: document.Metadata.Path, Title: document.Metadata.Title, Tags: document.Metadata.Tags,
			TrustLevel: document.Metadata.TrustLevel, ContentType: document.Metadata.ContentType,
			Content: string(document.Content), Source: cloneSource(document.Metadata.Source),
		})
	}
	deletes, err := normalizePathSet(proposal.DeletePaths)
	if err != nil {
		return "", err
	}
	overrides, err := normalizePathSet(proposal.Overrides)
	if err != nil {
		return "", err
	}
	payload := struct {
		BaseRevision        string             `json:"baseRevision"`
		ParentOrderExplicit bool               `json:"parentOrderExplicit"`
		Parents             []ParentSnapshot   `json:"parents"`
		Overrides           []string           `json:"overrides"`
		Documents           []proposalDocument `json:"documents"`
		DeletePaths         []string           `json:"deletePaths"`
	}{proposal.BaseRevision, proposal.ParentOrderExplicit, append([]ParentSnapshot(nil), proposal.Parents...), overrides, canonicalDocuments, deletes}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil)
	}
	return contentDigest(encoded), nil
}

// ProposalDigest binds approval and capability lease proofs to the exact
// normalized update batch.
func ProposalDigest(proposal UpdateProposal) (string, error) {
	return proposalDigest(proposal)
}

func sortedDocumentPaths(documents map[string]StoredDocument) []string {
	paths := make([]string, 0, len(documents))
	for documentPath := range documents {
		paths = append(paths, documentPath)
	}
	sort.Strings(paths)
	return paths
}

func invalid(scope string) *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": scope})
}

func cloneSource(input *SourceReference) *SourceReference {
	if input == nil {
		return nil
	}
	copySource := *input
	return &copySource
}

func sameSource(left, right *SourceReference) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func unauthorizedPath() *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
}
