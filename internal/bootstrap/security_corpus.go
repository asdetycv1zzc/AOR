package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	securityCorpusDirectory = "security-corpus"
	securityCorpusManifest  = "manifest.json"
)

var (
	securityCorpusIDPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,63}$`)
	securityCorpusVersionPattern = regexp.MustCompile(`^[1-9][0-9]*\.[0-9]+\.[0-9]+$`)
	requiredSecurityVectors      = map[string][]string{
		"archive-resource-exhaustion": {"archive-bomb", "oversized-output", "recursive-directory", "zip-slip"},
		"audit-evidence":              {"auditor-manipulation", "evidence-forgery", "test-result-tampering"},
		"budget-recursion":            {"budget-exhaustion", "recursive-agent-creation"},
		"command-arguments":           {"cmd", "powershell", "shell"},
		"git-repository":              {"clean-filter", "hook", "lfs", "repository-config", "smudge-filter", "submodule"},
		"hidden-test-inference":       {"enumeration", "side-channel"},
		"model-output":                {"json-injection", "schema-bypass", "unicode-spoofing"},
		"path-boundary":               {"hard-link", "junction", "normalization", "symlink", "traversal"},
		"peer-protocol":               {"downgrade", "forged-agent-card", "malicious-a2a-peer", "malicious-mcp-peer", "replay"},
		"prompt-context-injection":    {"context-poisoning", "indirect-prompt-injection", "prompt-injection"},
		"ssrf":                        {"cloud-metadata", "dns-rebinding", "ipv4-ambiguity", "ipv6-ambiguity", "loopback", "private-network", "redirect"},
		"tenant-isolation":            {"count-enumeration", "error-oracle", "resource-id-guessing", "timing-oracle"},
		"tool-authorization":          {"obfuscated-encoding", "parameter-substitution", "unauthorized-tool-call"},
	}
	securityCorpusDecisions = map[string]bool{
		"DENY":          true,
		"FAIL_CLOSED":   true,
		"NO_DISCLOSURE": true,
	}
)

type securityCorpusManifestDocument struct {
	SchemaVersion int                      `json:"schemaVersion"`
	CorpusVersion string                   `json:"corpusVersion"`
	Categories    []securityCorpusCategory `json:"categories"`
}

type securityCorpusCategory struct {
	ID             string   `json:"id"`
	File           string   `json:"file"`
	RequirementIDs []string `json:"requirementIds"`
}

type securityCorpusFixture struct {
	SchemaVersion int                  `json:"schemaVersion"`
	CorpusVersion string               `json:"corpusVersion"`
	Category      string               `json:"category"`
	Cases         []securityCorpusCase `json:"cases"`
}

type securityCorpusCase struct {
	ID               string `json:"id"`
	Vector           string `json:"vector"`
	Payload          string `json:"payload"`
	ExpectedDecision string `json:"expectedDecision"`
	Invariant        string `json:"invariant"`
}

// ValidateSecurityCorpus verifies that the adversarial corpus is versioned,
// strictly parseable, complete for every mandatory attack vector, and free of
// orphaned fixtures. It validates local regression evidence only; live sandbox
// and cross-tenant acceptance gates remain separate requirements.
func ValidateSecurityCorpus(root string) []Finding {
	corpusRoot := filepath.Join(root, securityCorpusDirectory)
	info, err := os.Lstat(corpusRoot)
	if err != nil {
		return []Finding{{Code: "SECURITY_CORPUS_MISSING", Path: securityCorpusDirectory, Message: err.Error()}}
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return []Finding{{Code: "SECURITY_CORPUS_INVALID", Path: securityCorpusDirectory, Message: "corpus root must be a real directory"}}
	}

	manifestPath := filepath.Join(corpusRoot, securityCorpusManifest)
	var manifest securityCorpusManifestDocument
	if finding := decodeSecurityCorpusDocument(root, manifestPath, &manifest); finding != nil {
		return []Finding{*finding}
	}
	var findings []Finding
	manifestRelative := filepath.ToSlash(filepath.Join(securityCorpusDirectory, securityCorpusManifest))
	if manifest.SchemaVersion != 1 || !securityCorpusVersionPattern.MatchString(manifest.CorpusVersion) {
		findings = append(findings, Finding{Code: "SECURITY_CORPUS_VERSION_INVALID", Path: manifestRelative, Message: "schemaVersion 1 and a stable semantic corpusVersion are required"})
	}
	if len(manifest.Categories) == 0 {
		findings = append(findings, Finding{Code: "SECURITY_CORPUS_CATEGORY_MISSING", Path: manifestRelative, Message: "manifest has no categories"})
	}

	referencedFiles := map[string]struct{}{securityCorpusManifest: {}}
	seenCategories := make(map[string]struct{}, len(manifest.Categories))
	seenCases := make(map[string]struct{})
	fixtures := make(map[string]securityCorpusFixture, len(manifest.Categories))
	previousCategory := ""
	for _, category := range manifest.Categories {
		if !securityCorpusIDPattern.MatchString(category.ID) {
			findings = append(findings, Finding{Code: "SECURITY_CORPUS_CATEGORY_INVALID", Path: manifestRelative, Message: category.ID})
		}
		if previousCategory != "" && category.ID <= previousCategory {
			findings = append(findings, Finding{Code: "SECURITY_CORPUS_ORDER_INVALID", Path: manifestRelative, Message: "categories must be unique and sorted by id"})
		}
		previousCategory = category.ID
		if _, exists := seenCategories[category.ID]; exists {
			findings = append(findings, Finding{Code: "SECURITY_CORPUS_CATEGORY_DUPLICATE", Path: manifestRelative, Message: category.ID})
			continue
		}
		seenCategories[category.ID] = struct{}{}
		if !validSecurityCorpusFilename(category.File) {
			findings = append(findings, Finding{Code: "SECURITY_CORPUS_FILE_INVALID", Path: manifestRelative, Message: category.ID + ": " + category.File})
			continue
		}
		if _, exists := referencedFiles[category.File]; exists {
			findings = append(findings, Finding{Code: "SECURITY_CORPUS_FILE_DUPLICATE", Path: manifestRelative, Message: category.File})
			continue
		}
		referencedFiles[category.File] = struct{}{}
		validateSecurityRequirementIDs(manifestRelative, category, &findings)

		fixturePath := filepath.Join(corpusRoot, category.File)
		var fixture securityCorpusFixture
		if finding := decodeSecurityCorpusDocument(root, fixturePath, &fixture); finding != nil {
			findings = append(findings, *finding)
			continue
		}
		fixtureRelative := filepath.ToSlash(filepath.Join(securityCorpusDirectory, category.File))
		if fixture.SchemaVersion != manifest.SchemaVersion || fixture.CorpusVersion != manifest.CorpusVersion {
			findings = append(findings, Finding{Code: "SECURITY_CORPUS_VERSION_MISMATCH", Path: fixtureRelative, Message: category.ID})
		}
		if fixture.Category != category.ID {
			findings = append(findings, Finding{Code: "SECURITY_CORPUS_CATEGORY_MISMATCH", Path: fixtureRelative, Message: fixture.Category + " != " + category.ID})
		}
		fixtures[category.ID] = fixture
		validateSecurityCases(fixtureRelative, category.ID, fixture.Cases, seenCases, &findings)
	}

	for category, vectors := range requiredSecurityVectors {
		if _, exists := seenCategories[category]; !exists {
			findings = append(findings, Finding{Code: "SECURITY_CORPUS_CATEGORY_MISSING", Path: manifestRelative, Message: category})
			continue
		}
		fixture, exists := fixtures[category]
		if !exists {
			continue
		}
		seenVectors := make(map[string]struct{}, len(fixture.Cases))
		for _, testCase := range fixture.Cases {
			seenVectors[testCase.Vector] = struct{}{}
		}
		for _, vector := range vectors {
			if _, exists := seenVectors[vector]; !exists {
				findings = append(findings, Finding{Code: "SECURITY_CORPUS_VECTOR_MISSING", Path: filepath.ToSlash(filepath.Join(securityCorpusDirectory, category)), Message: category + ": " + vector})
			}
		}
	}

	entries, err := os.ReadDir(corpusRoot)
	if err != nil {
		findings = append(findings, Finding{Code: "SECURITY_CORPUS_READ_ERROR", Path: securityCorpusDirectory, Message: err.Error()})
	} else {
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			if _, exists := referencedFiles[entry.Name()]; !exists {
				findings = append(findings, Finding{Code: "SECURITY_CORPUS_FILE_UNREFERENCED", Path: filepath.ToSlash(filepath.Join(securityCorpusDirectory, entry.Name())), Message: "JSON fixture is not bound by manifest.json"})
			}
		}
	}
	return sortedFindings(findings)
}

func decodeSecurityCorpusDocument(root, filename string, target any) *Finding {
	relative := filepath.ToSlash(relativePath(root, filename))
	info, err := os.Lstat(filename)
	if err != nil {
		return &Finding{Code: "SECURITY_CORPUS_FILE_MISSING", Path: relative, Message: err.Error()}
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > maxScannedFileBytes {
		return &Finding{Code: "SECURITY_CORPUS_FILE_INVALID", Path: relative, Message: "fixture must be a non-empty regular file within the size limit"}
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return &Finding{Code: "SECURITY_CORPUS_READ_ERROR", Path: relative, Message: err.Error()}
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return &Finding{Code: "SECURITY_CORPUS_JSON_INVALID", Path: relative, Message: err.Error()}
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values are not allowed")
		}
		return &Finding{Code: "SECURITY_CORPUS_JSON_INVALID", Path: relative, Message: err.Error()}
	}
	return nil
}

func validSecurityCorpusFilename(filename string) bool {
	return filename != securityCorpusManifest && filepath.Ext(filename) == ".json" && filepath.Base(filename) == filename && !strings.Contains(filename, "\\") && !strings.ContainsRune(filename, 0)
}

func validateSecurityRequirementIDs(path string, category securityCorpusCategory, findings *[]Finding) {
	if len(category.RequirementIDs) == 0 {
		*findings = append(*findings, Finding{Code: "SECURITY_CORPUS_REQUIREMENT_MISSING", Path: path, Message: category.ID})
		return
	}
	previous := ""
	for _, id := range category.RequirementIDs {
		if !requirementIDPattern.MatchString(id) {
			*findings = append(*findings, Finding{Code: "SECURITY_CORPUS_REQUIREMENT_INVALID", Path: path, Message: category.ID + ": " + id})
		}
		if previous != "" && id <= previous {
			*findings = append(*findings, Finding{Code: "SECURITY_CORPUS_ORDER_INVALID", Path: path, Message: category.ID + " requirementIds must be unique and sorted"})
		}
		previous = id
	}
}

func validateSecurityCases(path, category string, cases []securityCorpusCase, seenCases map[string]struct{}, findings *[]Finding) {
	if len(cases) == 0 {
		*findings = append(*findings, Finding{Code: "SECURITY_CORPUS_CASE_MISSING", Path: path, Message: category})
		return
	}
	previous := ""
	for _, testCase := range cases {
		if !securityCorpusIDPattern.MatchString(testCase.ID) || !securityCorpusIDPattern.MatchString(testCase.Vector) {
			*findings = append(*findings, Finding{Code: "SECURITY_CORPUS_CASE_INVALID", Path: path, Message: testCase.ID})
		}
		if previous != "" && testCase.ID <= previous {
			*findings = append(*findings, Finding{Code: "SECURITY_CORPUS_ORDER_INVALID", Path: path, Message: category + " cases must be unique and sorted by id"})
		}
		previous = testCase.ID
		if _, exists := seenCases[testCase.ID]; exists {
			*findings = append(*findings, Finding{Code: "SECURITY_CORPUS_CASE_DUPLICATE", Path: path, Message: testCase.ID})
		}
		seenCases[testCase.ID] = struct{}{}
		if len(testCase.Payload) == 0 || len(testCase.Payload) > 64<<10 || strings.TrimSpace(testCase.Invariant) == "" || !securityCorpusDecisions[testCase.ExpectedDecision] {
			*findings = append(*findings, Finding{Code: "SECURITY_CORPUS_EXPECTATION_INVALID", Path: path, Message: testCase.ID})
		}
	}
}
