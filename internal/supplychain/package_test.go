package supplychain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAssembleCreatesDeterministicOfflineVerifiablePackage(t *testing.T) {
	request, publicKey := assembleRequestFixture(t)
	report, err := Assemble(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if report.Artifacts != 9 || !report.SBOMVerified || !report.ProvenanceVerified || !report.ReleaseEvidenceValid || report.ArtifactSignatures != report.Artifacts {
		t.Fatalf("unexpected report: %#v", report)
	}
	bundle, err := LoadBundle(request.OutputDir)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(context.Background(), bundle, Keyring{request.KID: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	if verified.ManifestSHA256 != report.ManifestSHA256 {
		t.Fatalf("manifest digest changed: %s != %s", verified.ManifestSHA256, report.ManifestSHA256)
	}
	for _, path := range []string{ManifestFile, SBOMFile, ProvenanceFile, ReleaseEvidenceFile, LicenseFile, NoticeFile, ThirdPartyNoticesFile, "bin/aor", "images/aor.oci.tar", "deploy/aor.tgz"} {
		info, err := os.Lstat(filepath.Join(request.OutputDir, filepath.FromSlash(path)))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("package file %s: info=%v err=%v", path, info, err)
		}
	}

	second := request
	second.OutputDir = filepath.Join(t.TempDir(), "nested", "release")
	secondReport, err := Assemble(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if secondReport.ManifestSHA256 != report.ManifestSHA256 {
		t.Fatalf("non-deterministic manifest: %s != %s", secondReport.ManifestSHA256, report.ManifestSHA256)
	}
	for _, path := range []string{ManifestFile, SBOMFile, ProvenanceFile, ThirdPartyNoticesFile} {
		firstValue, err := os.ReadFile(filepath.Join(request.OutputDir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		secondValue, err := os.ReadFile(filepath.Join(second.OutputDir, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if string(firstValue) != string(secondValue) {
			t.Fatalf("generated file %s is not deterministic", path)
		}
	}
}

func TestAssembleRejectsExistingOutputAndSymlinkInputs(t *testing.T) {
	request, _ := assembleRequestFixture(t)
	if err := os.Mkdir(request.OutputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Assemble(context.Background(), request); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("existing output result = %v", err)
	}

	request, _ = assembleRequestFixture(t)
	symlink := filepath.Join(t.TempDir(), "binary-link")
	if err := os.Symlink(request.Artifacts[0].SourcePath, symlink); err != nil {
		t.Fatal(err)
	}
	request.Artifacts[0].SourcePath = symlink
	if _, err := Assemble(context.Background(), request); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("symlink source result = %v", err)
	}
}

func TestAssembleRejectsUnapprovedDependencyLicense(t *testing.T) {
	request, _ := assembleRequestFixture(t)
	request.Dependencies[0].License = "Proprietary"
	if _, err := Assemble(context.Background(), request); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("unapproved license result = %v", err)
	}
}

func TestLoadBundleRejectsSymlinkedMetadata(t *testing.T) {
	request, _ := assembleRequestFixture(t)
	if _, err := Assemble(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(request.OutputDir, SBOMFile)
	replacement := filepath.Join(t.TempDir(), "sbom.json")
	value, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, target); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBundle(request.OutputDir); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("symlink metadata result = %v", err)
	}
}

func TestReleaseKeyParsingSupportsPEMAndRawEncoding(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedPublic, err := MarshalPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	parsedPublic, err := ParsePublicKey(encodedPublic)
	if err != nil || !publicKey.Equal(parsedPublic) {
		t.Fatalf("PEM public key result = %v error=%v", parsedPublic, err)
	}
	parsedPrivate, err := ParsePrivateKey([]byte(base64.RawURLEncoding.EncodeToString(privateKey.Seed())))
	if err != nil || !privateKey.Equal(parsedPrivate) {
		t.Fatalf("raw private key result = %v error=%v", parsedPrivate, err)
	}
	if _, err := ParsePublicKey([]byte("not-a-key")); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("invalid public key result = %v", err)
	}
}

func assembleRequestFixture(t *testing.T) (AssembleRequest, ed25519.PublicKey) {
	t.Helper()
	sources := t.TempDir()
	binaryPath := writePackageFixture(t, sources, "aor", []byte("binary"))
	imagePath := writePackageFixture(t, sources, "image.tar", []byte("OCI image"))
	deploymentPath := writePackageFixture(t, sources, "aor.tgz", []byte("Helm chart"))
	licensePath := writePackageFixture(t, sources, "LICENSE", []byte("MIT License\n"))
	noticePath := writePackageFixture(t, sources, "NOTICE", []byte("AOR notice\n"))
	manifest := Manifest{Version: "2.0.0-rc.1", SourceCommit: "0123456789abcdef0123456789abcdef01234567"}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evidencePath := writePackageFixture(t, sources, "release-evidence.json", releaseEvidenceFixture(t, manifest, privateKey))
	return AssembleRequest{
		OutputDir:       filepath.Join(t.TempDir(), "release"),
		Version:         manifest.Version,
		SourceURI:       "https://example.invalid/akimisaka/aor.git",
		SourceCommit:    manifest.SourceCommit,
		BuilderIdentity: "ci/aor",
		BuildType:       "aor/release",
		InvocationID:    "release-build-01",
		StartedAt:       time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC),
		FinishedAt:      time.Date(2026, 8, 4, 0, 1, 0, 0, time.UTC),
		Materials: []Material{
			{URI: "git+https://example.invalid/akimisaka/aor.git?path=go.mod", SHA256: ArtifactDigest([]byte("go.mod"))},
			{URI: "git+https://example.invalid/akimisaka/aor.git?path=go.sum", SHA256: ArtifactDigest([]byte("go.sum"))},
		},
		Artifacts: []PackageArtifact{
			{SourcePath: binaryPath, Path: "bin/aor", Kind: ArtifactBinary, MediaType: "application/octet-stream"},
			{SourcePath: imagePath, Path: "images/aor.oci.tar", Kind: ArtifactContainerImage, MediaType: "application/vnd.oci.image.layer.v1.tar"},
			{SourcePath: deploymentPath, Path: "deploy/aor.tgz", Kind: ArtifactDeployment, MediaType: "application/gzip"},
		},
		Dependencies: []Dependency{
			{Name: "example.invalid/dependency", Version: "v1.2.3", SourceURI: "https://example.invalid/dependency", SHA256: ArtifactDigest([]byte("dependency archive")), License: "MIT", LicenseText: "Permission is hereby granted."},
		},
		LicenseSource:         licensePath,
		NoticeSource:          noticePath,
		ReleaseEvidenceSource: evidencePath,
		PrivateKey:            privateKey,
		KID:                   "release-1",
	}, publicKey
}

func writePackageFixture(t *testing.T, root, name string, value []byte) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
