package supplychain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyReleaseBundleOffline(t *testing.T) {
	root := t.TempDir()
	artifact := []byte("aor binary")
	if err := os.WriteFile(filepath.Join(root, "aor"), artifact, 0o500); err != nil {
		t.Fatal(err)
	}
	sbom := []byte(`{"spdxVersion":"SPDX-2.3","packages":[]}`)
	provenance := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[]}`)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{
		Version: "1.0.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", BuilderIdentity: "ci/aor",
		Artifacts:  []Artifact{{Path: "aor", SHA256: ArtifactDigest(artifact), Size: int64(len(artifact))}},
		SBOMSHA256: ArtifactDigest(sbom), ProvenanceSHA256: ArtifactDigest(provenance),
	}
	manifest, err = SignManifest(manifest, privateKey, "release-1")
	if err != nil {
		t.Fatal(err)
	}
	report, err := Verify(context.Background(), Bundle{Root: root, Manifest: manifest, SBOM: sbom, Provenance: provenance}, Keyring{"release-1": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if report.Artifacts != 1 || !report.SBOMVerified || !report.ProvenanceVerified || report.SignatureKID != "release-1" || report.ManifestSHA256 == "" {
		t.Fatalf("unexpected verification report: %#v", report)
	}
}

func TestVerifyRejectsTamperingAndUnknownKeys(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "aor"), []byte("good"), 0o500); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	sbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5"}`)
	provenance := []byte(`{"_type":"in-toto","subject":[]}`)
	manifest := Manifest{Version: "1.0.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", BuilderIdentity: "ci/aor", Artifacts: []Artifact{{Path: "aor", SHA256: ArtifactDigest([]byte("good")), Size: 4}}, SBOMSHA256: ArtifactDigest(sbom), ProvenanceSHA256: ArtifactDigest(provenance)}
	manifest, _ = SignManifest(manifest, privateKey, "release-1")
	if _, err := Verify(context.Background(), Bundle{Root: root, Manifest: manifest, SBOM: sbom, Provenance: provenance}, Keyring{"other": publicKey}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("unknown key result = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "aor"), []byte("tampered"), 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), Bundle{Root: root, Manifest: manifest, SBOM: sbom, Provenance: provenance}, Keyring{"release-1": publicKey}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tamper result = %v", err)
	}
}
