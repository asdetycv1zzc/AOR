// Package supplychain verifies release material without network access.
package supplychain

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

var (
	ErrInvalidManifest  = errors.New("invalid release manifest")
	ErrDigestMismatch   = errors.New("release material digest mismatch")
	ErrSignatureInvalid = errors.New("release manifest signature is invalid")
	ErrKeyUnavailable   = errors.New("release verification key is unavailable")
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KID       string `json:"kid"`
	Value     string `json:"value"`
}

type Manifest struct {
	Version          string     `json:"version"`
	SourceCommit     string     `json:"sourceCommit"`
	BuilderIdentity  string     `json:"builderIdentity"`
	Artifacts        []Artifact `json:"artifacts"`
	SBOMSHA256       string     `json:"sbomSha256"`
	ProvenanceSHA256 string     `json:"provenanceSha256"`
	Signature        Signature  `json:"signature"`
}

type Bundle struct {
	Root       string
	Manifest   Manifest
	SBOM       []byte
	Provenance []byte
}

type Report struct {
	ManifestSHA256     string
	Artifacts          int
	SBOMVerified       bool
	ProvenanceVerified bool
	SignatureKID       string
}

type Keyring map[string]ed25519.PublicKey

func Verify(ctx context.Context, bundle Bundle, keys Keyring) (Report, error) {
	if ctx == nil || ctx.Err() != nil || bundle.Root == "" {
		return Report{}, ErrInvalidManifest
	}
	if err := validateManifest(bundle.Manifest); err != nil {
		return Report{}, err
	}
	if len(bundle.SBOM) == 0 || len(bundle.Provenance) == 0 || !digestMatches(bundle.SBOM, bundle.Manifest.SBOMSHA256) || !digestMatches(bundle.Provenance, bundle.Manifest.ProvenanceSHA256) {
		return Report{}, ErrDigestMismatch
	}
	if err := validateSBOM(bundle.SBOM); err != nil {
		return Report{}, fmt.Errorf("%w: SBOM: %v", ErrInvalidManifest, err)
	}
	if err := validateProvenance(bundle.Provenance); err != nil {
		return Report{}, fmt.Errorf("%w: provenance: %v", ErrInvalidManifest, err)
	}
	key, found := keys[bundle.Manifest.Signature.KID]
	if !found || len(key) != ed25519.PublicKeySize {
		return Report{}, ErrKeyUnavailable
	}
	payload, err := unsignedBytes(bundle.Manifest)
	if err != nil {
		return Report{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.Manifest.Signature.Value)
	if err != nil || !ed25519.Verify(key, payload, signature) {
		return Report{}, ErrSignatureInvalid
	}
	for _, artifact := range bundle.Manifest.Artifacts {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		if err := verifyArtifact(bundle.Root, artifact); err != nil {
			return Report{}, err
		}
	}
	digest, err := digestBytes(mustJSON(bundle.Manifest))
	if err != nil {
		return Report{}, err
	}
	return Report{ManifestSHA256: digest, Artifacts: len(bundle.Manifest.Artifacts), SBOMVerified: true, ProvenanceVerified: true, SignatureKID: bundle.Manifest.Signature.KID}, nil
}

func SignManifest(manifest Manifest, privateKey ed25519.PrivateKey, kid string) (Manifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize || kid == "" {
		return Manifest{}, ErrInvalidManifest
	}
	manifest.Signature = Signature{Algorithm: "Ed25519", KID: kid}
	payload, err := unsignedBytes(manifest)
	if err != nil {
		return Manifest{}, err
	}
	manifest.Signature.Value = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return manifest, nil
}

func validateManifest(manifest Manifest) error {
	if strings.TrimSpace(manifest.Version) == "" || !commitPattern.MatchString(manifest.SourceCommit) || strings.TrimSpace(manifest.BuilderIdentity) == "" || !digestPattern.MatchString(manifest.SBOMSHA256) || !digestPattern.MatchString(manifest.ProvenanceSHA256) || manifest.Signature.Algorithm != "Ed25519" || manifest.Signature.KID == "" || manifest.Signature.Value == "" || len(manifest.Artifacts) == 0 {
		return ErrInvalidManifest
	}
	seen := make(map[string]struct{}, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		clean := filepath.ToSlash(filepath.Clean(artifact.Path))
		if artifact.Path == "" || clean != artifact.Path || filepath.IsAbs(artifact.Path) || strings.HasPrefix(clean, "../") || strings.ContainsRune(artifact.Path, 0) || !digestPattern.MatchString(artifact.SHA256) || artifact.Size < 0 {
			return ErrInvalidManifest
		}
		if _, exists := seen[clean]; exists {
			return ErrInvalidManifest
		}
		seen[clean] = struct{}{}
	}
	return nil
}

func verifyArtifact(root string, artifact Artifact) error {
	absolute := filepath.Join(root, filepath.FromSlash(artifact.Path))
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return ErrInvalidManifest
	}
	artifactAbsolute, err := filepath.Abs(absolute)
	if err != nil {
		return ErrInvalidManifest
	}
	relative, err := filepath.Rel(rootAbsolute, artifactAbsolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return ErrInvalidManifest
	}
	info, err := os.Lstat(artifactAbsolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != artifact.Size {
		return ErrDigestMismatch
	}
	file, err := os.Open(artifactAbsolute)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return ErrDigestMismatch
	}
	return nil
}

func validateSBOM(value []byte) error {
	var document map[string]any
	if err := json.Unmarshal(value, &document); err != nil {
		return err
	}
	if _, spdx := document["spdxVersion"]; spdx {
		return nil
	}
	if format, ok := document["bomFormat"].(string); ok && format == "CycloneDX" {
		return nil
	}
	return errors.New("unsupported SBOM format")
}

func validateProvenance(value []byte) error {
	var document map[string]any
	if err := json.Unmarshal(value, &document); err != nil {
		return err
	}
	if _, ok := document["_type"]; !ok {
		return errors.New("provenance _type is required")
	}
	if _, ok := document["subject"]; !ok {
		return errors.New("provenance subject is required")
	}
	return nil
}

func unsignedBytes(manifest Manifest) ([]byte, error) {
	manifest.Signature = Signature{}
	return json.Marshal(manifest)
}

func digestMatches(value []byte, expected string) bool {
	return rawDigest(value) == expected
}

func digestBytes(value []byte) (string, error) {
	return canonicaljson.Digest(value)
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func ArtifactDigest(value []byte) string {
	return rawDigest(value)
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func SortedArtifacts(manifest Manifest) []Artifact {
	artifacts := append([]Artifact(nil), manifest.Artifacts...)
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Path < artifacts[right].Path })
	return artifacts
}
