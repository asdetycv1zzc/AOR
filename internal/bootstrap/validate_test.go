package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverRequirementIDs(t *testing.T) {
	spec := []byte("- **AOR-INV-002**: invariant\n| AOR-ACC-001 | acceptance |\n- **AOR-INV-002**: repeated\nexample AOR-SEC-004")
	got := DiscoverRequirementIDs(spec)
	want := []string{"AOR-ACC-001", "AOR-INV-002"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestValidateRequirementCatalog(t *testing.T) {
	spec := []byte("- **AOR-INV-001**: one\n- **AOR-INV-002**: two\n")
	catalog := []byte("catalogVersion: 1\nspec:\n  name: test\n  version: 1.0.0\n  baselineDate: 2030-01-01\n  conflictResolution: adr/test.md\nrequirements:\n  - id: AOR-INV-001\n    title: one\n    implementation: []\n    tests: []\n    evidenceType: pending\n    owner: test\n    status: planned\n")
	findings := ValidateRequirementCatalog(spec, catalog)
	if !hasFinding(findings, "REQUIREMENT_MISSING") {
		t.Fatalf("expected missing requirement finding, got %#v", findings)
	}
}

func TestValidateRequirementCatalogAtRequiresRealImplementedEvidence(t *testing.T) {
	root := t.TempDir()
	spec := []byte("- **AOR-INV-001**: one\n")
	catalog := []byte("catalogVersion: 1\nspec:\n  name: test\n  version: 1.0.0\n  baselineDate: 2030-01-01\n  conflictResolution: adr/test.md\nrequirements:\n  - id: AOR-INV-001\n    title: one\n    implementation:\n      - internal/feature.go\n    tests:\n      - internal/feature_test.go\n    evidenceType: go-test\n    owner: test\n    status: implemented\n")
	findings := ValidateRequirementCatalogAt(root, spec, catalog)
	if !hasFinding(findings, "REQUIREMENT_PATH_MISSING") {
		t.Fatalf("expected missing evidence path, got %#v", findings)
	}
	if err := os.MkdirAll(filepath.Join(root, "internal"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"feature.go", "feature_test.go"} {
		if err := os.WriteFile(filepath.Join(root, "internal", name), []byte("package internal\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if findings := ValidateRequirementCatalogAt(root, spec, catalog); len(findings) != 0 {
		t.Fatalf("valid implemented evidence rejected: %#v", findings)
	}
}

func TestValidateRequirementCatalogRejectsFalseImplementationClaims(t *testing.T) {
	root := t.TempDir()
	spec := []byte("- **AOR-INV-001**: one\n")
	catalog := []byte("catalogVersion: 1\nspec:\n  name: test\n  version: 1.0.0\n  baselineDate: 2030-01-01\n  conflictResolution: adr/test.md\nrequirements:\n  - id: AOR-INV-001\n    title: one\n    implementation:\n      - ../outside.go\n    tests: []\n    evidenceType: pending\n    owner: test\n    status: implemented\n")
	findings := ValidateRequirementCatalogAt(root, spec, catalog)
	for _, code := range []string{"REQUIREMENT_PATH_INVALID", "REQUIREMENT_TESTS_MISSING", "REQUIREMENT_EVIDENCE_MISSING"} {
		if !hasFinding(findings, code) {
			t.Fatalf("expected %s, got %#v", code, findings)
		}
	}
}

func TestValidateRequirementCatalogRejectsUnknownFieldsAndStatuses(t *testing.T) {
	spec := []byte("- **AOR-INV-001**: one\n")
	unknown := []byte("catalogVersion: 1\nspec:\n  name: test\n  version: 1.0.0\n  baselineDate: 2030-01-01\n  conflictResolution: adr/test.md\nrequirements:\n  - id: AOR-INV-001\n    title: one\n    implementation: []\n    tests: []\n    evidenceType: pending\n    owner: test\n    status: planned\n    typoField: true\n")
	if findings := ValidateRequirementCatalog(spec, unknown); !hasFinding(findings, "CATALOG_INVALID") {
		t.Fatalf("unknown field accepted: %#v", findings)
	}
	invalidStatus := []byte("catalogVersion: 1\nspec:\n  name: test\n  version: 1.0.0\n  baselineDate: 2030-01-01\n  conflictResolution: adr/test.md\nrequirements:\n  - id: AOR-INV-001\n    title: one\n    implementation: []\n    tests: []\n    evidenceType: pending\n    owner: test\n    status: complete\n")
	if findings := ValidateRequirementCatalog(spec, invalidStatus); !hasFinding(findings, "REQUIREMENT_STATUS_INVALID") {
		t.Fatalf("unknown status accepted: %#v", findings)
	}
}

func TestValidateProductionRequirementCatalogRejectsPlannedEntries(t *testing.T) {
	spec := []byte("- **AOR-INV-001**: one\n")
	catalog := []byte("catalogVersion: 1\nspec:\n  name: test\n  version: 1.0.0\n  baselineDate: 2030-01-01\n  conflictResolution: adr/test.md\nrequirements:\n  - id: AOR-INV-001\n    title: one\n    implementation: []\n    tests: []\n    evidenceType: pending\n    owner: test\n    status: planned\n")
	findings := ValidateProductionRequirementCatalogAt("", spec, catalog)
	if !hasFinding(findings, "REQUIREMENT_NOT_IMPLEMENTED") {
		t.Fatalf("planned requirement accepted for production: %#v", findings)
	}
}

func TestValidateRepositoryRequiresBaselinePaths(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := ValidateRepository(root)
	if !hasFinding(findings, "REQUIRED_PATH_MISSING") {
		t.Fatalf("expected required path finding, got %#v", findings)
	}
}

func TestValidateRunbooksRequiresOperationalSections(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "runbooks")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range RequiredRunbooks() {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("Severity: SEV-2\nAlert: test\nSymptoms: test\nContainment: test\nDiagnosis: test\nRecovery: test\nVerification: test\nEvidence: test\nRetrospective: test\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if findings := ValidateRunbooks(root); len(findings) != 0 {
		t.Fatalf("valid runbooks rejected: %#v", findings)
	}
	if err := os.WriteFile(filepath.Join(directory, RequiredRunbooks()[0]), []byte("Severity: SEV-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if findings := ValidateRunbooks(root); !hasFinding(findings, "RUNBOOK_SECTION_MISSING") {
		t.Fatalf("incomplete runbook accepted: %#v", findings)
	}
}

func TestScanSecretsDetectsCredentialShape(t *testing.T) {
	root := t.TempDir()
	value := "gh" + "p_" + strings.Repeat("a", 36)
	if err := os.WriteFile(filepath.Join(root, "bad.txt"), []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := ScanSecrets(root)
	if !hasFinding(findings, "SECRET_PATTERN") {
		t.Fatalf("expected secret finding, got %#v", findings)
	}
}

func TestScanSecretsIgnoresGitAndBuildOutput(t *testing.T) {
	root := t.TempDir()
	value := "gh" + "p_" + strings.Repeat("a", 36)
	for _, name := range []string{".git", "bin"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ignored"), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if findings := ScanSecrets(root); len(findings) != 0 {
		t.Fatalf("expected ignored files, got %#v", findings)
	}
}

func TestScanSecretsIgnoresLocalComposeSecrets(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "deploy", "compose", "secrets")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	value := "sk-" + strings.Repeat("a", 32)
	if err := os.WriteFile(filepath.Join(directory, "model_provider_key"), []byte(value), 0o400); err != nil {
		t.Fatal(err)
	}
	if findings := ScanSecrets(root); len(findings) != 0 {
		t.Fatalf("expected local secret files to be ignored, got %#v", findings)
	}
}

func TestValidateADRSections(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "adr")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "0001-test.md"), []byte("# ADR\n\n## Context\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := ValidateADRs(root, 1)
	if !hasFinding(findings, "ADR_SECTION_MISSING") {
		t.Fatalf("expected missing ADR section finding, got %#v", findings)
	}
}

func TestValidateSourceMarkersDetectsDeferredWork(t *testing.T) {
	root := t.TempDir()
	marker := "TO" + "DO"
	if err := os.WriteFile(filepath.Join(root, "deferred.go"), []byte("package deferred\n// "+marker+": owner missing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := ValidateSourceMarkers(root)
	if !hasFinding(findings, "DEFERRED_WORK_MARKER") {
		t.Fatalf("expected deferred work finding, got %#v", findings)
	}
}

func hasFinding(findings []Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
