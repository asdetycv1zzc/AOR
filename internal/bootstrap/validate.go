package bootstrap

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxScannedFileBytes = 2 << 20

var (
	requirementBoldPattern  = regexp.MustCompile(`\*\*(AOR-[A-Z]+-[0-9]+)\*\*`)
	requirementTablePattern = regexp.MustCompile(`^\|\s*(AOR-[A-Z]+-[0-9]+)\s*\|`)
	requirementIDPattern    = regexp.MustCompile(`^AOR-[A-Z]+-[0-9]+$`)
	secretPatterns          = []struct {
		name string
		re   *regexp.Regexp
	}{
		{name: "github_token", re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
		{name: "aws_access_key", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{name: "private_key", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`)},
		{name: "bearer_token", re: regexp.MustCompile(`(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~-]{20,}`)},
	}
)

type requirementCatalog struct {
	CatalogVersion int                    `yaml:"catalogVersion"`
	Spec           requirementCatalogSpec `yaml:"spec"`
	Requirements   []catalogRequirement   `yaml:"requirements"`
}

type requirementCatalogSpec struct {
	Name               string `yaml:"name"`
	Version            string `yaml:"version"`
	BaselineDate       string `yaml:"baselineDate"`
	ConflictResolution string `yaml:"conflictResolution"`
}

type catalogRequirement struct {
	ID             string   `yaml:"id"`
	Title          string   `yaml:"title"`
	Implementation []string `yaml:"implementation"`
	Tests          []string `yaml:"tests"`
	EvidenceType   string   `yaml:"evidenceType"`
	Owner          string   `yaml:"owner"`
	Status         string   `yaml:"status"`
}

// Finding is a deterministic repository validation result.
type Finding struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// DiscoverRequirementIDs returns the sorted, unique explicit AOR requirement IDs.
func DiscoverRequirementIDs(spec []byte) []string {
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(spec))
	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range []*regexp.Regexp{requirementBoldPattern, requirementTablePattern} {
			match := pattern.FindStringSubmatch(line)
			if len(match) == 2 {
				seen[match[1]] = struct{}{}
			}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ValidateRequirementCatalog validates catalog structure and SPEC coverage without filesystem checks.
func ValidateRequirementCatalog(spec, catalog []byte) []Finding {
	return validateRequirementCatalog("", spec, catalog)
}

// ValidateRequirementCatalogAt also verifies evidence paths against the repository root.
func ValidateRequirementCatalogAt(root string, spec, catalog []byte) []Finding {
	return validateRequirementCatalog(root, spec, catalog)
}

func validateRequirementCatalog(root string, spec, catalog []byte) []Finding {
	var findings []Finding
	if len(catalog) == 0 || len(catalog) > maxScannedFileBytes {
		return []Finding{{Code: "CATALOG_INVALID", Path: "conformance/requirements.yaml", Message: "catalog is empty or exceeds the size limit"}}
	}
	decoder := yaml.NewDecoder(bytes.NewReader(catalog))
	decoder.KnownFields(true)
	var parsed requirementCatalog
	if err := decoder.Decode(&parsed); err != nil {
		return []Finding{{Code: "CATALOG_INVALID", Path: "conformance/requirements.yaml", Message: err.Error()}}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple YAML documents are not allowed")
		}
		return []Finding{{Code: "CATALOG_INVALID", Path: "conformance/requirements.yaml", Message: err.Error()}}
	}
	if parsed.CatalogVersion != 1 || strings.TrimSpace(parsed.Spec.Name) == "" || strings.TrimSpace(parsed.Spec.Version) == "" || strings.TrimSpace(parsed.Spec.BaselineDate) == "" || strings.TrimSpace(parsed.Spec.ConflictResolution) == "" {
		findings = append(findings, Finding{Code: "CATALOG_METADATA_INVALID", Path: "conformance/requirements.yaml", Message: "catalog version and complete SPEC metadata are required"})
	}

	expected := make(map[string]struct{})
	for _, id := range DiscoverRequirementIDs(spec) {
		expected[id] = struct{}{}
	}
	known := make(map[string]struct{}, len(parsed.Requirements))
	for _, requirement := range parsed.Requirements {
		if !requirementIDPattern.MatchString(requirement.ID) {
			findings = append(findings, Finding{Code: "REQUIREMENT_ID_INVALID", Path: "conformance/requirements.yaml", Message: requirement.ID})
			continue
		}
		if _, exists := known[requirement.ID]; exists {
			findings = append(findings, Finding{Code: "REQUIREMENT_DUPLICATE", Path: "conformance/requirements.yaml", Message: requirement.ID})
			continue
		}
		known[requirement.ID] = struct{}{}
		if _, exists := expected[requirement.ID]; !exists {
			findings = append(findings, Finding{Code: "REQUIREMENT_UNEXPECTED", Path: "conformance/requirements.yaml", Message: requirement.ID})
		}
		if strings.TrimSpace(requirement.Title) == "" {
			findings = append(findings, Finding{Code: "REQUIREMENT_TITLE_MISSING", Path: "conformance/requirements.yaml", Message: requirement.ID})
		}
		if strings.TrimSpace(requirement.Owner) == "" {
			findings = append(findings, Finding{Code: "REQUIREMENT_OWNER_MISSING", Path: "conformance/requirements.yaml", Message: requirement.ID})
		}
		if requirement.Status != "planned" && requirement.Status != "implemented" {
			findings = append(findings, Finding{Code: "REQUIREMENT_STATUS_INVALID", Path: "conformance/requirements.yaml", Message: requirement.ID + ": " + requirement.Status})
			continue
		}
		if requirement.Status != "implemented" {
			continue
		}
		if len(requirement.Implementation) == 0 {
			findings = append(findings, Finding{Code: "REQUIREMENT_IMPLEMENTATION_MISSING", Path: "conformance/requirements.yaml", Message: requirement.ID})
		}
		if len(requirement.Tests) == 0 {
			findings = append(findings, Finding{Code: "REQUIREMENT_TESTS_MISSING", Path: "conformance/requirements.yaml", Message: requirement.ID})
		}
		if strings.TrimSpace(requirement.EvidenceType) == "" || requirement.EvidenceType == "pending" {
			findings = append(findings, Finding{Code: "REQUIREMENT_EVIDENCE_MISSING", Path: "conformance/requirements.yaml", Message: requirement.ID})
		}
		if root != "" {
			for _, reference := range append(append([]string(nil), requirement.Implementation...), requirement.Tests...) {
				if finding := validateCatalogPath(root, requirement.ID, reference); finding != nil {
					findings = append(findings, *finding)
				}
			}
		}
	}
	for id := range expected {
		if _, exists := known[id]; !exists {
			findings = append(findings, Finding{Code: "REQUIREMENT_MISSING", Path: "conformance/requirements.yaml", Message: id})
		}
	}
	return sortedFindings(findings)
}

func validateCatalogPath(root, requirementID, reference string) *Finding {
	trimmed := strings.TrimSuffix(reference, "/")
	if trimmed == "" || strings.Contains(reference, "\\") || strings.ContainsRune(reference, 0) || path.IsAbs(reference) || path.Clean(reference) != trimmed || trimmed == "." || strings.HasPrefix(trimmed, "../") {
		return &Finding{Code: "REQUIREMENT_PATH_INVALID", Path: "conformance/requirements.yaml", Message: requirementID + ": " + reference}
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return &Finding{Code: "REQUIREMENT_PATH_INVALID", Path: reference, Message: requirementID}
	}
	target := filepath.Join(absoluteRoot, filepath.FromSlash(trimmed))
	if !pathWithinRoot(absoluteRoot, target) {
		return &Finding{Code: "REQUIREMENT_PATH_INVALID", Path: "conformance/requirements.yaml", Message: requirementID + ": " + reference}
	}
	if _, err := os.Stat(target); err != nil {
		return &Finding{Code: "REQUIREMENT_PATH_MISSING", Path: reference, Message: requirementID}
	}
	resolvedRoot, rootErr := filepath.EvalSymlinks(absoluteRoot)
	resolvedTarget, targetErr := filepath.EvalSymlinks(target)
	if rootErr != nil || targetErr != nil || !pathWithinRoot(resolvedRoot, resolvedTarget) {
		return &Finding{Code: "REQUIREMENT_PATH_INVALID", Path: reference, Message: requirementID + ": path escapes repository root"}
	}
	return nil
}

func pathWithinRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

// RequiredPaths is the Phase 0 repository contract.
func RequiredPaths() []string {
	return []string{
		".github/workflows/ci.yml",
		".editorconfig",
		".gitattributes",
		".gitignore",
		"CODEOWNERS",
		"CONTRIBUTING.md",
		"LICENSE",
		"Makefile",
		"NOTICE",
		"README.md",
		"SECURITY.md",
		"SPEC.md",
		"adr",
		"agents",
		"api",
		"audit",
		"buf.yaml",
		"cmd",
		"conformance/requirements.yaml",
		"deploy",
		"docs/threat-model.md",
		"go.mod",
		"go.work",
		"internal",
		"knowledge",
		"migrations",
		"model-adapters",
		"observability",
		"package.json",
		"pnpm-workspace.yaml",
		"policies",
		"pkg",
		"prompts",
		"runbooks",
		"sandbox",
		"scripts",
		"security-corpus",
		"tests",
		"third_party",
		"tool-adapters",
		"work-packages/wp-00/ACCEPTANCE.json",
		"work-packages/wp-00/CHANGELOG.md",
		"work-packages/wp-00/DESIGN.md",
		"work-packages/wp-00/INTERFACES.md",
		"work-packages/wp-00/MIGRATION_PLAN.md",
		"work-packages/wp-00/MODULE_SPEC.md",
		"work-packages/wp-00/OPERATIONS.md",
		"work-packages/wp-00/TEST_PLAN.md",
		"work-packages/wp-00/THREAT_MODEL.md",
	}
}

// ValidateRepository checks the required Phase 0 paths and work-package handoff.
func ValidateRepository(root string) []Finding {
	var findings []Finding
	for _, path := range RequiredPaths() {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(path))); err != nil {
			if os.IsNotExist(err) {
				findings = append(findings, Finding{Code: "REQUIRED_PATH_MISSING", Path: path, Message: "required Phase 0 path is absent"})
			} else {
				findings = append(findings, Finding{Code: "PATH_STAT_ERROR", Path: path, Message: err.Error()})
			}
		}
	}
	return sortedFindings(findings)
}

// ValidateADRs checks required ADR numbering and mandatory sections.
func ValidateADRs(root string, minimum int) []Finding {
	requiredSections := []string{
		"## Context",
		"## Decision",
		"## Alternatives",
		"## Security Consequences",
		"## Operational Consequences",
		"## Migration",
		"## Status",
	}
	var findings []Finding
	for number := 1; number <= minimum; number++ {
		prefix := fmt.Sprintf("%04d-", number)
		matches, err := filepath.Glob(filepath.Join(root, "adr", prefix+"*.md"))
		if err != nil {
			findings = append(findings, Finding{Code: "ADR_GLOB_ERROR", Path: "adr", Message: err.Error()})
			continue
		}
		if len(matches) != 1 {
			findings = append(findings, Finding{Code: "ADR_MISSING", Path: "adr/" + prefix + "*.md", Message: "expected exactly one ADR"})
			continue
		}
		content, err := os.ReadFile(matches[0])
		if err != nil {
			findings = append(findings, Finding{Code: "ADR_READ_ERROR", Path: relativePath(root, matches[0]), Message: err.Error()})
			continue
		}
		for _, section := range requiredSections {
			if !bytes.Contains(content, []byte(section)) {
				findings = append(findings, Finding{Code: "ADR_SECTION_MISSING", Path: relativePath(root, matches[0]), Message: section})
			}
		}
	}
	return sortedFindings(findings)
}

// ScanSecrets identifies credential-shaped values without following links or scanning generated output.
func ScanSecrets(root string) []Finding {
	var findings []Finding
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			findings = append(findings, Finding{Code: "FILE_WALK_ERROR", Path: relativePath(root, path), Message: walkErr.Error()})
			return nil
		}
		if entry.IsDir() && isIgnoredDirectory(entry.Name()) {
			return filepath.SkipDir
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxScannedFileBytes {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil || bytes.IndexByte(content, 0) >= 0 {
			return nil
		}
		for _, pattern := range secretPatterns {
			if pattern.re.Match(content) {
				findings = append(findings, Finding{Code: "SECRET_PATTERN", Path: relativePath(root, path), Message: pattern.name})
			}
		}
		return nil
	})
	return sortedFindings(findings)
}

// ValidateJSONDocuments parses every source JSON document and checks Schema dialect declarations.
func ValidateJSONDocuments(root string) []Finding {
	var findings []Finding
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			findings = append(findings, Finding{Code: "FILE_WALK_ERROR", Path: relativePath(root, path), Message: walkErr.Error()})
			return nil
		}
		if entry.IsDir() && isIgnoredDirectory(entry.Name()) {
			return filepath.SkipDir
		}
		if entry.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			findings = append(findings, Finding{Code: "JSON_READ_ERROR", Path: relativePath(root, path), Message: err.Error()})
			return nil
		}
		var value any
		if err := json.Unmarshal(content, &value); err != nil {
			findings = append(findings, Finding{Code: "JSON_INVALID", Path: relativePath(root, path), Message: err.Error()})
			return nil
		}
		rel := filepath.ToSlash(relativePath(root, path))
		if strings.HasPrefix(rel, "api/json-schema/") {
			object, ok := value.(map[string]any)
			dialect, hasDialect := object["$schema"].(string)
			if !ok || !hasDialect || dialect != "https://json-schema.org/draft/2020-12/schema" {
				findings = append(findings, Finding{Code: "SCHEMA_DIALECT_INVALID", Path: rel, Message: "Draft 2020-12 is required"})
			}
		}
		return nil
	})
	return sortedFindings(findings)
}

// CheckGoFormat verifies source formatting without modifying files.
func CheckGoFormat(root string) []Finding {
	var findings []Finding
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			findings = append(findings, Finding{Code: "FILE_WALK_ERROR", Path: relativePath(root, path), Message: walkErr.Error()})
			return nil
		}
		if entry.IsDir() && isIgnoredDirectory(entry.Name()) {
			return filepath.SkipDir
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			findings = append(findings, Finding{Code: "GO_READ_ERROR", Path: relativePath(root, path), Message: err.Error()})
			return nil
		}
		formatted, err := format.Source(content)
		if err != nil {
			findings = append(findings, Finding{Code: "GO_PARSE_ERROR", Path: relativePath(root, path), Message: err.Error()})
		} else if !bytes.Equal(formatted, content) {
			findings = append(findings, Finding{Code: "GO_FORMAT_INVALID", Path: relativePath(root, path), Message: "gofmt output differs"})
		}
		return nil
	})
	return sortedFindings(findings)
}

// ValidateLicenseBaseline checks repository-level license declarations.
func ValidateLicenseBaseline(root string) []Finding {
	var findings []Finding
	license, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		findings = append(findings, Finding{Code: "LICENSE_MISSING", Path: "LICENSE", Message: err.Error()})
	} else if !bytes.HasPrefix(license, []byte("MIT License\n")) {
		findings = append(findings, Finding{Code: "LICENSE_UNRECOGNIZED", Path: "LICENSE", Message: "expected approved MIT license text"})
	}
	if _, err := os.Stat(filepath.Join(root, "NOTICE")); err != nil {
		findings = append(findings, Finding{Code: "NOTICE_MISSING", Path: "NOTICE", Message: err.Error()})
	}
	return sortedFindings(findings)
}

// ValidateSourceMarkers rejects unowned deferred work and skipped-test directives in implementation files.
func ValidateSourceMarkers(root string) []Finding {
	markers := []*regexp.Regexp{
		regexp.MustCompile(`\bTO` + `DO\b`),
		regexp.MustCompile(`\bFIX` + `ME\b`),
		regexp.MustCompile(`\bt\.Skip\s*\(`),
	}
	var findings []Finding
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() && isIgnoredDirectory(entry.Name()) {
			return filepath.SkipDir
		}
		if entry.IsDir() || !sourceMarkerExtension(filepath.Ext(path)) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, marker := range markers {
			if marker.Match(content) {
				findings = append(findings, Finding{Code: "DEFERRED_WORK_MARKER", Path: relativePath(root, path), Message: marker.String()})
			}
		}
		return nil
	})
	return sortedFindings(findings)
}

func isIgnoredDirectory(name string) bool {
	switch name {
	case ".git", ".cache", "bin", "coverage", "dist", "node_modules", "release-evidence":
		return true
	default:
		return false
	}
}

func sourceMarkerExtension(extension string) bool {
	switch extension {
	case ".go", ".js", ".json", ".proto", ".rego", ".sh", ".ts", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func relativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(relative)
}

func sortedFindings(findings []Finding) []Finding {
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i].Code + "\x00" + findings[i].Path + "\x00" + findings[i].Message
		right := findings[j].Code + "\x00" + findings[j].Path + "\x00" + findings[j].Message
		return left < right
	})
	return findings
}

// ADRName returns the canonical numeric prefix for repository tooling.
func ADRName(number int) string {
	return strings.Repeat("0", max(0, 4-len(strconv.Itoa(number)))) + strconv.Itoa(number)
}
