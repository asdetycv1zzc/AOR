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
)

func TestExternalDriverBindsSignedManifestScopeAndRawEvidence(t *testing.T) {
	if os.Getenv("AOR_EXTERNAL_DRIVER_HELPER") == "1" {
		externalDriverHelperProcess()
		return
	}
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
		Args:             []string{"-test.run=TestExternalDriverBindsSignedManifestScopeAndRawEvidence"},
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
	os.Setenv("AOR_EXTERNAL_DRIVER_HELPER", "1")
	os.Setenv("AOR_EXTERNAL_DRIVER_PRIVATE_KEY", base64.RawStdEncoding.EncodeToString(privateKey))
	defer os.Unsetenv("AOR_EXTERNAL_DRIVER_HELPER")
	defer os.Unsetenv("AOR_EXTERNAL_DRIVER_PRIVATE_KEY")
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
	var foundManifest, foundRaw bool
	for _, reference := range evidence.Results[0].EvidenceURIs {
		foundManifest = foundManifest || strings.HasPrefix(reference, "artifact://conformance/driver-manifest#sha256=")
		foundRaw = foundRaw || strings.HasPrefix(reference, "file:raw/external/")
	}
	if !foundManifest || !foundRaw {
		t.Fatalf("external evidence references = %#v", evidence.Results[0].EvidenceURIs)
	}
}

func TestExternalDriverRejectsTamperedSignedManifest(t *testing.T) {
	if os.Getenv("AOR_EXTERNAL_DRIVER_HELPER") == "1" {
		return
	}
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
	manifest := ExternalDriverManifest{ProtocolVersion: externalDriverProtocolVersion, Tool: "driver", ToolVersion: "1", Executable: executable, ExecutableSHA256: digestBytes(mustReadExternalTestFile(t, executable)), Args: []string{"-test.run=TestExternalDriverBindsSignedManifestScopeAndRawEvidence"}, CorpusPath: "security-corpus/prompt-injection.json", CorpusSHA256: digestBytes(corpus), Target: "", SpecVersion: "2.0.0", ReleaseVersion: "0.1.0-dev", SourceCommit: "unknown", BuildDigest: build, TenantID: "tenant", Namespace: "namespace", Groups: []string{"security"}, TimeoutSeconds: 5, MaxOutputBytes: 1 << 20}
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

func externalDriverHelperProcess() {
	if os.Getenv("AOR_EXTERNAL_DRIVER_HELPER") != "1" {
		return
	}
	evidenceDirectory := os.Getenv("AOR_CONFORMANCE_EVIDENCE_DIR")
	if evidenceDirectory == "" {
		os.Exit(2)
	}
	evidence := []byte("independent trace\n")
	if err := os.WriteFile(filepath.Join(evidenceDirectory, "trace.json"), evidence, 0o600); err != nil {
		os.Exit(2)
	}
	output := externalDriverOutput{
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
		Results: []externalDriverResult{{
			Group:         "security",
			RequirementID: "AOR-ACC-043",
			Status:        "PASS",
			Evidence: []externalDriverEvidence{{
				Path:   "trace.json",
				SHA256: digestBytes(evidence),
				Kind:   "trace",
			}},
		}},
	}
	privateRaw, err := base64.RawStdEncoding.DecodeString(os.Getenv("AOR_EXTERNAL_DRIVER_PRIVATE_KEY"))
	if err == nil && len(privateRaw) == ed25519.PrivateKeySize {
		unsigned, _ := json.Marshal(output)
		payload, _, _ := externalSignedPayload(unsigned, "signature", "", "aor-conformance-driver-result-v1")
		output.Signature = &Signature{Type: "Ed25519", KID: "driver-test", Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(privateRaw), payload))}
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
