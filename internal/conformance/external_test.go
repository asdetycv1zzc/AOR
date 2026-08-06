package conformance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akimisaka/aor/internal/bootstrap"
)

func TestExternalDriverBindsSignedManifestScopeAndRawEvidence(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	corpusPath := filepath.Join(root, "security-corpus", "prompt-injection.json")
	corpus, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	build, err := buildDigest(root, output)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ExternalDriverManifest{
		ProtocolVersion:  externalDriverProtocolVersion,
		Tool:             "independent-security-driver",
		ToolVersion:      "1.2.3",
		Executable:       executable,
		ExecutableSHA256: digestBytes(mustReadExternalTestFile(t, executable)),
		Args:             []string{"-test.run=TestExternalDriverProcess"},
		CorpusPath:       "security-corpus/prompt-injection.json",
		CorpusSHA256:     digestBytes(corpus),
		Target:           "",
		SpecVersion:      "2.0.0",
		ReleaseVersion:   "0.1.0-dev",
		SourceCommit:     "unknown",
		BuildDigest:      build,
		TenantID:         "tenant-conformance",
		Namespace:        "run-scope",
		Groups:           []string{"security"},
		TimeoutSeconds:   10,
		MaxOutputBytes:   1 << 20,
	}
	manifest.CorpusSignature = signExternalTestPayload(t, privateKey, []byte("aor-conformance-driver-corpus-v1\n"+manifest.CorpusSHA256), "driver-test")
	manifestBytes := signExternalTestManifest(t, manifest, privateKey)
	manifestPath := filepath.Join(t.TempDir(), "driver-manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(nil)
	evidence, runErr := runner.Run(context.Background(), Request{
		Root:           root,
		Profile:        "test",
		SpecVersion:    "2.0.0",
		ReleaseVersion: "0.1.0-dev",
		SourceCommit:   "unknown",
		OutputDir:      output,
		Groups:         []string{"security"},
		ExternalDriver: &ExternalDriverConfig{ManifestPath: manifestPath, PublicKey: privateKey.Public().(ed25519.PublicKey)},
	})
	if runErr != nil {
		t.Fatalf("external driver run failed: %v (%#v)", runErr, evidence.Exceptions)
	}
	if len(evidence.Results) != 1 || evidence.Results[0].Status != "PASS" || evidence.Results[0].RequirementID != "AOR-ACC-043" {
		t.Fatalf("external result = %#v", evidence.Results)
	}
	var foundManifest, foundExecutable, foundCorpus, foundRaw bool
	for _, reference := range evidence.Results[0].EvidenceURIs {
		foundManifest = foundManifest || strings.HasPrefix(reference, "artifact://conformance/driver-manifest#sha256=")
		foundExecutable = foundExecutable || strings.Contains(reference, "/driver-executable")
		foundCorpus = foundCorpus || strings.Contains(reference, "/driver-corpus")
		foundRaw = foundRaw || strings.HasPrefix(reference, "file:raw/external/")
	}
	if !foundManifest || !foundExecutable || !foundCorpus || !foundRaw {
		t.Fatalf("external evidence references = %#v", evidence.Results[0].EvidenceURIs)
	}
}

func TestExternalDriverRejectsTamperedSignedManifest(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := filepath.Abs("../..")
	output := t.TempDir()
	corpus, err := os.ReadFile(filepath.Join(root, "security-corpus", "prompt-injection.json"))
	if err != nil {
		t.Fatal(err)
	}
	executable, _ := filepath.Abs(os.Args[0])
	build, err := buildDigest(root, output)
	if err != nil {
		t.Fatal(err)
	}
	manifest := ExternalDriverManifest{ProtocolVersion: externalDriverProtocolVersion, Tool: "driver", ToolVersion: "1", Executable: executable, ExecutableSHA256: digestBytes(mustReadExternalTestFile(t, executable)), Args: []string{"-test.run=TestExternalDriverProcess"}, CorpusPath: "security-corpus/prompt-injection.json", CorpusSHA256: digestBytes(corpus), Target: "", SpecVersion: "2.0.0", ReleaseVersion: "0.1.0-dev", SourceCommit: "unknown", BuildDigest: build, TenantID: "tenant", Namespace: "namespace", Groups: []string{"security"}, TimeoutSeconds: 5, MaxOutputBytes: 1 << 20}
	manifest.CorpusSignature = signExternalTestPayload(t, privateKey, []byte("aor-conformance-driver-corpus-v1\n"+manifest.CorpusSHA256), "driver-test")
	encoded := signExternalTestManifest(t, manifest, privateKey)
	encoded[len(encoded)-2] ^= 1
	manifestPath := filepath.Join(t.TempDir(), "driver-manifest.json")
	if err := os.WriteFile(manifestPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := NewRunner(nil)
	_, runErr := runner.Run(context.Background(), Request{Root: root, Profile: "test", SpecVersion: "2.0.0", ReleaseVersion: "0.1.0-dev", SourceCommit: "unknown", OutputDir: output, Groups: []string{"security"}, ExternalDriver: &ExternalDriverConfig{ManifestPath: manifestPath, PublicKey: privateKey.Public().(ed25519.PublicKey)}})
	if !errors.Is(runErr, ErrGateFailed) {
		t.Fatalf("tampered manifest error = %v", runErr)
	}
}

func TestExternalGroupRequirementsCoverReliabilityAndPerformanceGates(t *testing.T) {
	chaos := externalRequirementsForGroup("chaos")
	if len(chaos) != 9 || chaos[0] != "AOR-ACC-056" || chaos[len(chaos)-1] != "AOR-ACC-064" {
		t.Fatalf("chaos requirements = %#v", chaos)
	}
	performance := externalRequirementsForGroup("performance")
	if len(performance) != 9 || performance[0] != "AOR-ACC-066" || performance[len(performance)-1] != "AOR-ACC-075" {
		t.Fatalf("performance requirements = %#v", performance)
	}
}

func TestFullExternalGroupCompletesCoverageWithoutDuplicateOwnership(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	externalGroups := requestedExternalGroups(productionGroups)
	expected, err := externalRequirementsForGroups(root, externalGroups, productionGroups)
	if err != nil {
		t.Fatal(err)
	}
	owners := make(map[string]string)
	for _, group := range productionGroups {
		requirements, external := expected[group]
		if !external {
			requirements = requirementIDsForGroup(group)
		}
		for _, requirement := range requirements {
			if previous, exists := owners[requirement]; exists {
				t.Fatalf("requirement %s owned by %s and %s", requirement, previous, group)
			}
			owners[requirement] = group
		}
	}
	spec, err := os.ReadFile(filepath.Join(root, "SPEC.md"))
	if err != nil {
		t.Fatal(err)
	}
	requirements := bootstrap.DiscoverRequirementIDs(spec)
	if len(owners) != len(requirements) {
		t.Fatalf("owned requirements = %d, SPEC requirements = %d", len(owners), len(requirements))
	}
	for _, requirement := range requirements {
		if owners[requirement] == "" {
			t.Fatalf("requirement %s has no conformance owner", requirement)
		}
	}
	if owners["AOR-ACC-042"] != "authz" || owners["AOR-ACC-044"] != "tool-broker" {
		t.Fatalf("authorization ownership = ACC-042:%s ACC-044:%s", owners["AOR-ACC-042"], owners["AOR-ACC-044"])
	}
}

func TestExternalEvidenceCopiesAreBoundToRequirement(t *testing.T) {
	outputDirectory := t.TempDir()
	evidenceDirectory := t.TempDir()
	for _, fixture := range []struct {
		path    string
		content string
	}{
		{path: "one/trace.json", content: "first"},
		{path: "two/trace.json", content: "second"},
	} {
		path := filepath.Join(evidenceDirectory, filepath.FromSlash(fixture.path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(fixture.content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := copyExternalEvidence(outputDirectory, evidenceDirectory, "run-1", "chaos", "AOR-ACC-056", []ExternalDriverEvidence{{Path: "one/trace.json", SHA256: digestBytes([]byte("first")), Kind: "trace"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := copyExternalEvidence(outputDirectory, evidenceDirectory, "run-1", "chaos", "AOR-ACC-057", []ExternalDriverEvidence{{Path: "two/trace.json", SHA256: digestBytes([]byte("second")), Kind: "trace"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(second) != 1 || first[0] == second[0] {
		t.Fatalf("evidence references collided: first=%#v second=%#v", first, second)
	}
	firstPath := filepath.Join(outputDirectory, "raw", "external", "run-1", "chaos", "AOR-ACC-056", "000-trace.json")
	secondPath := filepath.Join(outputDirectory, "raw", "external", "run-1", "chaos", "AOR-ACC-057", "000-trace.json")
	firstValue, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatal(err)
	}
	secondValue, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstValue) != "first" || string(secondValue) != "second" {
		t.Fatalf("copied evidence was overwritten: first=%q second=%q", firstValue, secondValue)
	}
}

func TestExternalDriverProcess(t *testing.T) {
	if os.Getenv("AOR_CONFORMANCE_PROTOCOL_VERSION") != externalDriverProtocolVersion {
		return
	}
	externalDriverHelperProcess()
}

func externalDriverHelperProcess() {
	evidenceDirectory := os.Getenv("AOR_CONFORMANCE_EVIDENCE_DIR")
	if evidenceDirectory == "" {
		os.Exit(2)
	}
	executable, err := os.Executable()
	if err != nil || filepath.Dir(executable) != evidenceDirectory || !strings.HasPrefix(filepath.Base(executable), "driver-executable") {
		os.Exit(2)
	}
	corpusPath := os.Getenv("AOR_CONFORMANCE_CORPUS_PATH")
	if filepath.Dir(corpusPath) != evidenceDirectory || !strings.HasPrefix(filepath.Base(corpusPath), "driver-corpus") {
		os.Exit(2)
	}
	if corpus, err := os.ReadFile(corpusPath); err != nil || len(corpus) == 0 {
		os.Exit(2)
	}
	evidence := []byte("independent trace\n")
	if err := os.WriteFile(filepath.Join(evidenceDirectory, "trace.json"), evidence, 0o600); err != nil {
		os.Exit(2)
	}
	output := ExternalDriverOutput{
		ProtocolVersion: externalDriverProtocolVersion,
		ManifestSHA256:  os.Getenv("AOR_CONFORMANCE_MANIFEST_SHA256"),
		Target:          os.Getenv("AOR_CONFORMANCE_TARGET"),
		SpecVersion:     os.Getenv("AOR_CONFORMANCE_SPEC_VERSION"),
		ReleaseVersion:  os.Getenv("AOR_CONFORMANCE_RELEASE_VERSION"),
		SourceCommit:    os.Getenv("AOR_CONFORMANCE_SOURCE_COMMIT"),
		BuildDigest:     os.Getenv("AOR_CONFORMANCE_BUILD_DIGEST"),
		TenantID:        os.Getenv("AOR_CONFORMANCE_TENANT_ID"),
		Namespace:       os.Getenv("AOR_CONFORMANCE_NAMESPACE"),
		RunID:           os.Getenv("AOR_CONFORMANCE_RUN_ID"),
		Results: []ExternalDriverResult{{
			Group:         "security",
			RequirementID: "AOR-ACC-043",
			Status:        "PASS",
			Evidence: []ExternalDriverEvidence{{
				Path:   "trace.json",
				SHA256: digestBytes(evidence),
				Kind:   "trace",
			}},
		}},
	}
	encoded, _ := json.Marshal(output)
	_, _ = os.Stdout.Write(encoded)
	os.Exit(0)
}

func signExternalTestManifest(t *testing.T, manifest ExternalDriverManifest, private ed25519.PrivateKey) []byte {
	t.Helper()
	manifest.ManifestSHA256 = ""
	manifest.Signature = nil
	unsigned, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payload, digest, err := externalSignedPayload(unsigned, "signature", "manifestSha256", "aor-conformance-driver-manifest-v1")
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestSHA256 = digest
	manifest.Signature = &Signature{Type: "Ed25519", KID: "driver-test", Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payload))}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func signExternalTestPayload(t *testing.T, private ed25519.PrivateKey, payload []byte, kid string) *Signature {
	t.Helper()
	return &Signature{Type: "Ed25519", KID: kid, Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, payload))}
}

func mustReadExternalTestFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
