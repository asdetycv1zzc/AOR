package supplychain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

func TestVerifyReleaseBundleOffline(t *testing.T) {
	bundle, publicKey := signedBundleFixture(t)
	report, err := Verify(context.Background(), bundle, Keyring{"release-1": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if report.Artifacts != len(bundle.Manifest.Artifacts) || !report.SBOMVerified || !report.ProvenanceVerified || !report.ReleaseEvidenceValid || report.ArtifactSignatures != len(bundle.Manifest.Artifacts) || report.ManifestSignatureKID != "release-1" || report.ManifestSHA256 == "" {
		t.Fatalf("unexpected verification report: %#v", report)
	}
}

func TestVerifyRejectsArtifactAndManifestTampering(t *testing.T) {
	bundle, publicKey := signedBundleFixture(t)
	if err := os.WriteFile(filepath.Join(bundle.Root, "bin", "aor"), []byte("tampered"), 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), bundle, Keyring{"release-1": publicKey}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("artifact tamper result = %v", err)
	}

	bundle, publicKey = signedBundleFixture(t)
	bundle.Manifest.BuilderIdentity = "ci/other"
	if _, err := Verify(context.Background(), bundle, Keyring{"release-1": publicKey}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("manifest tamper result = %v", err)
	}
}

func TestVerifyRejectsUnknownKeysAndArtifactSignatureTampering(t *testing.T) {
	bundle, publicKey := signedBundleFixture(t)
	if _, err := Verify(context.Background(), bundle, Keyring{"other": publicKey}); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("unknown key result = %v", err)
	}
	bundle.Manifest.Artifacts[0].Signature.Value = strings.Repeat("A", 86)
	if _, err := Verify(context.Background(), bundle, Keyring{"release-1": publicKey}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("artifact signature result = %v", err)
	}
}

func TestVerifyRejectsIncompleteSBOMAndUnboundProvenance(t *testing.T) {
	bundle, publicKey := signedBundleFixture(t)
	var sbom map[string]any
	if err := json.Unmarshal(bundle.SBOM, &sbom); err != nil {
		t.Fatal(err)
	}
	sbom["files"] = []any{}
	bundle.SBOM = mustJSON(sbom)
	resignSpecialFixture(t, &bundle, publicKey, SBOMFile, bundle.SBOM)
	if _, err := Verify(context.Background(), bundle, Keyring{"release-1": publicKey}); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("incomplete SBOM result = %v", err)
	}

	bundle, publicKey = signedBundleFixture(t)
	var provenance map[string]any
	if err := json.Unmarshal(bundle.Provenance, &provenance); err != nil {
		t.Fatal(err)
	}
	predicate := provenance["predicate"].(map[string]any)
	runDetails := predicate["runDetails"].(map[string]any)
	builder := runDetails["builder"].(map[string]any)
	builder["id"] = "ci/other"
	bundle.Provenance = mustJSON(provenance)
	resignSpecialFixture(t, &bundle, publicKey, ProvenanceFile, bundle.Provenance)
	if _, err := Verify(context.Background(), bundle, Keyring{"release-1": publicKey}); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("unbound provenance result = %v", err)
	}
}

func TestVerifyRejectsNonProductionReleaseEvidence(t *testing.T) {
	bundle, publicKey := signedBundleFixture(t)
	var evidence map[string]any
	if err := json.Unmarshal(bundle.ReleaseEvidence, &evidence); err != nil {
		t.Fatal(err)
	}
	evidence["environment"] = "test"
	evidence["evidenceDigest"] = ""
	digest, err := canonicaljson.DigestObjectWithoutFields(mustJSON(evidence), "evidenceDigest", "signature")
	if err != nil {
		t.Fatal(err)
	}
	evidence["evidenceDigest"] = digest
	bundle.ReleaseEvidence = mustJSON(evidence)
	resignSpecialFixture(t, &bundle, publicKey, ReleaseEvidenceFile, bundle.ReleaseEvidence)
	if _, err := Verify(context.Background(), bundle, Keyring{"release-1": publicKey}); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("non-production evidence result = %v", err)
	}
}

func TestSignManifestRejectsUnsortedAndIncompleteArtifacts(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{SchemaVersion: ManifestSchemaVersion, Version: "1.0.0", SourceURI: "https://example.invalid/aor.git", SourceCommit: "0123456789abcdef0123456789abcdef01234567", BuilderIdentity: "ci/aor", BuildType: "aor/release", Materials: []Material{{URI: "git+https://example.invalid/aor.git?path=go.mod", SHA256: ArtifactDigest([]byte("go.mod"))}}, SBOMSHA256: ArtifactDigest([]byte("sbom")), ProvenanceSHA256: ArtifactDigest([]byte("provenance")), ReleaseEvidenceSHA256: ArtifactDigest([]byte("evidence")), Artifacts: []Artifact{{Path: "z", SHA256: ArtifactDigest(nil), Kind: ArtifactBinary, MediaType: "application/octet-stream"}, {Path: "a", SHA256: ArtifactDigest(nil), Kind: ArtifactContainerImage, MediaType: "application/vnd.oci.image.layer.v1.tar"}}}
	if _, err := SignManifest(manifest, privateKey, "release-1"); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("invalid manifest result = %v", err)
	}
}

func signedBundleFixture(t *testing.T) (Bundle, ed25519.PublicKey) {
	t.Helper()
	root := t.TempDir()
	files := map[string][]byte{
		"bin/aor":             []byte("aor binary"),
		"images/aor.oci.tar":  []byte("oci image layout"),
		"deploy/helm.tgz":     []byte("helm package"),
		LicenseFile:           []byte("MIT License\n"),
		NoticeFile:            []byte("AOR notice\n"),
		ThirdPartyNoticesFile: []byte("# Third-party notices\n"),
	}
	for path, content := range files {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	artifacts := []Artifact{
		artifactFixture("bin/aor", ArtifactBinary, "application/octet-stream", files["bin/aor"]),
		artifactFixture("deploy/helm.tgz", ArtifactDeployment, "application/gzip", files["deploy/helm.tgz"]),
		artifactFixture("images/aor.oci.tar", ArtifactContainerImage, "application/vnd.oci.image.layer.v1.tar", files["images/aor.oci.tar"]),
		artifactFixture(LicenseFile, ArtifactLicense, "text/plain", files[LicenseFile]),
		artifactFixture(NoticeFile, ArtifactNotice, "text/plain", files[NoticeFile]),
		artifactFixture(ThirdPartyNoticesFile, ArtifactThirdPartyNotices, "text/markdown", files[ThirdPartyNoticesFile]),
	}
	manifest := Manifest{
		SchemaVersion:   ManifestSchemaVersion,
		Version:         "2.0.0-rc.1",
		SourceURI:       "https://example.invalid/akimisaka/aor.git",
		SourceCommit:    "0123456789abcdef0123456789abcdef01234567",
		BuilderIdentity: "https://github.com/akimisaka/aor/.github/workflows/release.yml@refs/tags/v2.0.0-rc.1",
		BuildType:       "https://aor.dev/build-types/release/v1",
		Materials:       []Material{{URI: "git+https://example.invalid/akimisaka/aor.git?path=go.mod", SHA256: ArtifactDigest([]byte("go.mod"))}, {URI: "git+https://example.invalid/akimisaka/aor.git?path=go.sum", SHA256: ArtifactDigest([]byte("go.sum"))}},
		Artifacts:       artifacts,
	}
	evidence := releaseEvidenceFixture(t, manifest)
	artifacts = append(artifacts, artifactFixture(ReleaseEvidenceFile, ArtifactReleaseEvidence, "application/json", evidence))
	sbom := spdxFixture(manifest, artifacts)
	artifacts = append(artifacts, artifactFixture(SBOMFile, ArtifactSBOM, "application/spdx+json", sbom))
	manifest.Artifacts = append([]Artifact(nil), artifacts...)
	provenance := provenanceFixture(manifest)
	artifacts = append(artifacts, artifactFixture(ProvenanceFile, ArtifactProvenance, "application/vnd.in-toto+json", provenance))
	sortArtifacts(artifacts)
	manifest.Artifacts = artifacts
	manifest.SBOMSHA256 = ArtifactDigest(sbom)
	manifest.ProvenanceSHA256 = ArtifactDigest(provenance)
	manifest.ReleaseEvidenceSHA256 = ArtifactDigest(evidence)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixturePrivateKeys[string(publicKey)] = privateKey
	manifest, err = SignManifest(manifest, privateKey, "release-1")
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range map[string][]byte{SBOMFile: sbom, ProvenanceFile: provenance, ReleaseEvidenceFile: evidence} {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Bundle{Root: root, Manifest: manifest, SBOM: sbom, Provenance: provenance, ReleaseEvidence: evidence}, publicKey
}

func artifactFixture(path string, kind ArtifactKind, mediaType string, content []byte) Artifact {
	return Artifact{Path: path, SHA256: ArtifactDigest(content), Size: int64(len(content)), Kind: kind, MediaType: mediaType}
}

func sortArtifacts(artifacts []Artifact) {
	for left := range artifacts {
		for right := left + 1; right < len(artifacts); right++ {
			if artifacts[right].Path < artifacts[left].Path {
				artifacts[left], artifacts[right] = artifacts[right], artifacts[left]
			}
		}
	}
}

func spdxFixture(manifest Manifest, artifacts []Artifact) []byte {
	files := make([]map[string]any, 0, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Path == SBOMFile || artifact.Path == ProvenanceFile {
			continue
		}
		files = append(files, map[string]any{"SPDXID": "SPDXRef-File-" + strings.NewReplacer("/", "-", ".", "-").Replace(artifact.Path), "fileName": artifact.Path, "checksums": []map[string]string{{"algorithm": "SHA256", "checksumValue": strings.TrimPrefix(artifact.SHA256, "sha256:")}}, "licenseConcluded": "NOASSERTION"})
	}
	return mustJSON(map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "aor-" + manifest.Version, "documentNamespace": "https://aor.dev/sbom/" + manifest.SourceCommit, "creationInfo": map[string]any{"created": "2026-08-04T00:00:00Z", "creators": []string{"Tool: aor-release-2.0.0"}}, "packages": []map[string]any{{"SPDXID": "SPDXRef-Package-AOR", "name": "aor", "versionInfo": manifest.Version, "downloadLocation": "NOASSERTION", "filesAnalyzed": true, "licenseConcluded": "MIT", "licenseDeclared": "MIT"}}, "files": files})
}

func provenanceFixture(manifest Manifest) []byte {
	subjects := make([]map[string]any, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if artifact.Path == ProvenanceFile {
			continue
		}
		subjects = append(subjects, map[string]any{"name": artifact.Path, "digest": map[string]string{"sha256": strings.TrimPrefix(artifact.SHA256, "sha256:")}})
	}
	dependencies := make([]map[string]any, 0, len(manifest.Materials))
	for _, material := range manifest.Materials {
		dependencies = append(dependencies, map[string]any{"uri": material.URI, "digest": map[string]string{"sha256": strings.TrimPrefix(material.SHA256, "sha256:")}})
	}
	return mustJSON(map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": subjects, "predicateType": "https://slsa.dev/provenance/v1", "predicate": map[string]any{"buildDefinition": map[string]any{"buildType": manifest.BuildType, "externalParameters": map[string]any{"source": map[string]any{"uri": manifest.SourceURI, "digest": map[string]string{"gitCommit": manifest.SourceCommit}}}, "internalParameters": map[string]any{}, "resolvedDependencies": dependencies}, "runDetails": map[string]any{"builder": map[string]string{"id": manifest.BuilderIdentity}, "metadata": map[string]string{"invocationId": "build-01", "startedOn": "2026-08-04T00:00:00Z", "finishedOn": "2026-08-04T00:01:00Z"}}}})
}

func releaseEvidenceFixture(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	evidence := map[string]any{"evidenceVersion": "1.0", "specVersion": "2.0.0", "releaseVersion": manifest.Version, "sourceCommit": manifest.SourceCommit, "buildDigest": ArtifactDigest([]byte("build")), "startedAt": time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC).Format(time.RFC3339), "completedAt": time.Date(2026, 8, 4, 0, 1, 0, 0, time.UTC).Format(time.RFC3339), "environment": "production", "target": "https://preprod.example.invalid", "results": []map[string]any{{"requirementId": "AOR-ACC-050", "status": "PASS", "tool": "aor-conformance", "toolVersion": "2.0.0"}}, "exceptions": []string{}, "evidenceDigest": "", "signature": map[string]string{"type": "kms-signature", "kid": "release-approver", "value": "fixture-signature"}}
	digest, err := canonicaljson.DigestObjectWithoutFields(mustJSON(evidence), "evidenceDigest", "signature")
	if err != nil {
		t.Fatal(err)
	}
	evidence["evidenceDigest"] = digest
	return mustJSON(evidence)
}

func resignSpecialFixture(t *testing.T, bundle *Bundle, publicKey ed25519.PublicKey, path string, content []byte) {
	t.Helper()
	privateKey := privateKeyForFixture(t, publicKey)
	for index := range bundle.Manifest.Artifacts {
		if bundle.Manifest.Artifacts[index].Path == path {
			bundle.Manifest.Artifacts[index].SHA256 = ArtifactDigest(content)
			bundle.Manifest.Artifacts[index].Size = int64(len(content))
		}
	}
	switch path {
	case SBOMFile:
		bundle.Manifest.SBOMSHA256 = ArtifactDigest(content)
	case ProvenanceFile:
		bundle.Manifest.ProvenanceSHA256 = ArtifactDigest(content)
	case ReleaseEvidenceFile:
		bundle.Manifest.ReleaseEvidenceSHA256 = ArtifactDigest(content)
	}
	absolute := filepath.Join(bundle.Root, filepath.FromSlash(path))
	if err := os.WriteFile(absolute, content, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := SignManifest(bundle.Manifest, privateKey, "release-1")
	if err != nil {
		t.Fatal(err)
	}
	bundle.Manifest = manifest
}

var fixturePrivateKeys = map[string]ed25519.PrivateKey{}

func privateKeyForFixture(t *testing.T, publicKey ed25519.PublicKey) ed25519.PrivateKey {
	t.Helper()
	privateKey, found := fixturePrivateKeys[string(publicKey)]
	if !found {
		t.Fatal("fixture private key missing")
	}
	return privateKey
}
