package bootstrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSecurityCorpusRepositoryFixtures(t *testing.T) {
	if findings := ValidateSecurityCorpus("../.."); len(findings) != 0 {
		t.Fatalf("repository security corpus rejected: %#v", findings)
	}
}

func TestValidateSecurityCorpusRejectsMissingVectorAndVersionDrift(t *testing.T) {
	root := copySecurityCorpus(t)
	path := filepath.Join(root, securityCorpusDirectory, "ssrf.json")
	fixture := readSecurityFixture(t, path)
	fixture.Cases = fixture.Cases[1:]
	writeSecurityFixture(t, path, fixture)
	if findings := ValidateSecurityCorpus(root); !hasFinding(findings, "SECURITY_CORPUS_VECTOR_MISSING") {
		t.Fatalf("missing mandatory vector accepted: %#v", findings)
	}

	root = copySecurityCorpus(t)
	path = filepath.Join(root, securityCorpusDirectory, "tenant-isolation.json")
	fixture = readSecurityFixture(t, path)
	fixture.CorpusVersion = "2.0.0"
	writeSecurityFixture(t, path, fixture)
	if findings := ValidateSecurityCorpus(root); !hasFinding(findings, "SECURITY_CORPUS_VERSION_MISMATCH") {
		t.Fatalf("fixture version drift accepted: %#v", findings)
	}
}

func TestValidateSecurityCorpusRejectsUnknownFieldsAndOrphanedFixtures(t *testing.T) {
	root := copySecurityCorpus(t)
	path := filepath.Join(root, securityCorpusDirectory, securityCorpusManifest)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	document["unreviewedField"] = true
	writeSecurityJSON(t, path, document)
	if findings := ValidateSecurityCorpus(root); !hasFinding(findings, "SECURITY_CORPUS_JSON_INVALID") {
		t.Fatalf("unknown manifest field accepted: %#v", findings)
	}

	root = copySecurityCorpus(t)
	writeSecurityJSON(t, filepath.Join(root, securityCorpusDirectory, "orphan.json"), map[string]any{"schemaVersion": 1})
	if findings := ValidateSecurityCorpus(root); !hasFinding(findings, "SECURITY_CORPUS_FILE_UNREFERENCED") {
		t.Fatalf("orphan fixture accepted: %#v", findings)
	}
}

func copySecurityCorpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, securityCorpusDirectory)
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join("../..", securityCorpusDirectory))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		content, err := os.ReadFile(filepath.Join("../..", securityCorpusDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, entry.Name()), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readSecurityFixture(t *testing.T, path string) securityCorpusFixture {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture securityCorpusFixture
	if err := json.Unmarshal(content, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func writeSecurityFixture(t *testing.T, path string, fixture securityCorpusFixture) {
	t.Helper()
	writeSecurityJSON(t, path, fixture)
}

func writeSecurityJSON(t *testing.T, path string, value any) {
	t.Helper()
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
