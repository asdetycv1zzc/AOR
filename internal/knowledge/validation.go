package knowledge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const defaultContentType = "text/markdown"

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
			ContentType: contentType, SHA256: digest, LineCount: len(lines),
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
		Path        string     `json:"path"`
		Title       string     `json:"title"`
		Tags        []string   `json:"tags"`
		TrustLevel  TrustLevel `json:"trustLevel"`
		ContentType string     `json:"contentType"`
		Content     string     `json:"content"`
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
			Content: string(document.Content),
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

func unauthorizedPath() *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeUnauthorizedPath, "", nil)
}
