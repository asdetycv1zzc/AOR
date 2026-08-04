// Package supplychain creates and verifies release material without network access.
package supplychain

import (
	"bytes"
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
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const (
	ManifestSchemaVersion = "1.0"
	ManifestFile          = "release-manifest.json"
	SBOMFile              = "metadata/sbom.spdx.json"
	ProvenanceFile        = "metadata/provenance.intoto.json"
	ReleaseEvidenceFile   = "metadata/release-evidence.json"
	LicenseFile           = "LICENSE"
	NoticeFile            = "NOTICE"
	ThirdPartyNoticesFile = "THIRD_PARTY_NOTICES.md"
)

var (
	ErrInvalidManifest  = errors.New("invalid release manifest")
	ErrDigestMismatch   = errors.New("release material digest mismatch")
	ErrSignatureInvalid = errors.New("release signature is invalid")
	ErrKeyUnavailable   = errors.New("release verification key is unavailable")
)

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	digestHexPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionPattern    = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	mediaTypePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+-]*/[a-z0-9][a-z0-9!#$&^_.+-]*(?:;[ -~]+)?$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$`)
)

type ArtifactKind string

const (
	ArtifactBinary            ArtifactKind = "binary"
	ArtifactContainerImage    ArtifactKind = "container-image"
	ArtifactDeployment        ArtifactKind = "deployment"
	ArtifactLicense           ArtifactKind = "license"
	ArtifactNotice            ArtifactKind = "notice"
	ArtifactThirdPartyNotices ArtifactKind = "third-party-notices"
	ArtifactSBOM              ArtifactKind = "sbom"
	ArtifactProvenance        ArtifactKind = "provenance"
	ArtifactReleaseEvidence   ArtifactKind = "release-evidence"
)

type Artifact struct {
	Path      string       `json:"path"`
	SHA256    string       `json:"sha256"`
	Size      int64        `json:"size"`
	Kind      ArtifactKind `json:"kind"`
	MediaType string       `json:"mediaType"`
	Signature Signature    `json:"signature"`
}

type Material struct {
	URI    string `json:"uri"`
	SHA256 string `json:"sha256"`
}

type Signature struct {
	Algorithm string `json:"algorithm"`
	KID       string `json:"kid"`
	Value     string `json:"value"`
}

type Manifest struct {
	SchemaVersion         string     `json:"schemaVersion"`
	Version               string     `json:"releaseVersion"`
	SourceURI             string     `json:"sourceUri"`
	SourceCommit          string     `json:"sourceCommit"`
	BuilderIdentity       string     `json:"builderIdentity"`
	BuildType             string     `json:"buildType"`
	Materials             []Material `json:"materials"`
	Artifacts             []Artifact `json:"artifacts"`
	SBOMSHA256            string     `json:"sbomSha256"`
	ProvenanceSHA256      string     `json:"provenanceSha256"`
	ReleaseEvidenceSHA256 string     `json:"releaseEvidenceSha256"`
	Signature             Signature  `json:"signature"`
}

type Bundle struct {
	Root            string
	Manifest        Manifest
	SBOM            []byte
	Provenance      []byte
	ReleaseEvidence []byte
}

type Report struct {
	ManifestSHA256       string
	Artifacts            int
	SBOMVerified         bool
	ProvenanceVerified   bool
	ReleaseEvidenceValid bool
	ArtifactSignatures   int
	ManifestSignatureKID string
}

type Keyring map[string]ed25519.PublicKey

func Verify(ctx context.Context, bundle Bundle, keys Keyring) (Report, error) {
	if ctx == nil || ctx.Err() != nil || strings.TrimSpace(bundle.Root) == "" {
		return Report{}, ErrInvalidManifest
	}
	if err := validateManifest(bundle.Manifest); err != nil {
		return Report{}, err
	}
	payload, err := unsignedBytes(bundle.Manifest)
	if err != nil {
		return Report{}, err
	}
	if err := verifySignature(keys, bundle.Manifest.Signature, payload); err != nil {
		return Report{}, err
	}
	if !digestMatches(bundle.SBOM, bundle.Manifest.SBOMSHA256) || !digestMatches(bundle.Provenance, bundle.Manifest.ProvenanceSHA256) || !digestMatches(bundle.ReleaseEvidence, bundle.Manifest.ReleaseEvidenceSHA256) {
		return Report{}, ErrDigestMismatch
	}
	if err := verifySpecialArtifact(bundle.Manifest, SBOMFile, ArtifactSBOM, bundle.SBOM); err != nil {
		return Report{}, err
	}
	if err := verifySpecialArtifact(bundle.Manifest, ProvenanceFile, ArtifactProvenance, bundle.Provenance); err != nil {
		return Report{}, err
	}
	if err := verifySpecialArtifact(bundle.Manifest, ReleaseEvidenceFile, ArtifactReleaseEvidence, bundle.ReleaseEvidence); err != nil {
		return Report{}, err
	}
	if err := validateSBOM(bundle.SBOM, bundle.Manifest); err != nil {
		return Report{}, fmt.Errorf("%w: SBOM: %v", ErrInvalidManifest, err)
	}
	if err := validateProvenance(bundle.Provenance, bundle.Manifest); err != nil {
		return Report{}, fmt.Errorf("%w: provenance: %v", ErrInvalidManifest, err)
	}
	if err := validateReleaseEvidence(bundle.ReleaseEvidence, bundle.Manifest); err != nil {
		return Report{}, fmt.Errorf("%w: release evidence: %v", ErrInvalidManifest, err)
	}
	for _, artifact := range bundle.Manifest.Artifacts {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		if err := verifyArtifact(bundle.Root, artifact); err != nil {
			return Report{}, err
		}
		if err := verifySignature(keys, artifact.Signature, artifactSignaturePayload(artifact)); err != nil {
			return Report{}, fmt.Errorf("%w: %s", err, artifact.Path)
		}
	}
	digest, err := canonicaljson.Digest(mustJSON(bundle.Manifest))
	if err != nil {
		return Report{}, err
	}
	return Report{
		ManifestSHA256:       digest,
		Artifacts:            len(bundle.Manifest.Artifacts),
		SBOMVerified:         true,
		ProvenanceVerified:   true,
		ReleaseEvidenceValid: true,
		ArtifactSignatures:   len(bundle.Manifest.Artifacts),
		ManifestSignatureKID: bundle.Manifest.Signature.KID,
	}, nil
}

func SignManifest(manifest Manifest, privateKey ed25519.PrivateKey, kid string) (Manifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !identifierPattern.MatchString(kid) {
		return Manifest{}, ErrInvalidManifest
	}
	manifest.Signature = Signature{}
	for index := range manifest.Artifacts {
		manifest.Artifacts[index].Signature = Signature{}
	}
	if err := validateUnsignedManifest(manifest); err != nil {
		return Manifest{}, err
	}
	for index := range manifest.Artifacts {
		manifest.Artifacts[index].Signature = signPayload(privateKey, kid, artifactSignaturePayload(manifest.Artifacts[index]))
	}
	payload, err := unsignedBytes(manifest)
	if err != nil {
		return Manifest{}, err
	}
	manifest.Signature = signPayload(privateKey, kid, payload)
	return manifest, nil
}

func validateManifest(manifest Manifest) error {
	if err := validateUnsignedManifest(manifest); err != nil {
		return err
	}
	if err := validateSignature(manifest.Signature); err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		if err := validateSignature(artifact.Signature); err != nil {
			return err
		}
	}
	return nil
}

func validateUnsignedManifest(manifest Manifest) error {
	if manifest.SchemaVersion != ManifestSchemaVersion || !versionPattern.MatchString(manifest.Version) || strings.TrimSpace(manifest.SourceURI) == "" || !commitPattern.MatchString(manifest.SourceCommit) || !identifierPattern.MatchString(manifest.BuilderIdentity) || !identifierPattern.MatchString(manifest.BuildType) || !digestPattern.MatchString(manifest.SBOMSHA256) || !digestPattern.MatchString(manifest.ProvenanceSHA256) || !digestPattern.MatchString(manifest.ReleaseEvidenceSHA256) || len(manifest.Materials) == 0 || len(manifest.Artifacts) == 0 {
		return ErrInvalidManifest
	}
	if strings.ContainsAny(manifest.SourceURI, "\x00\r\n") {
		return ErrInvalidManifest
	}
	materialURIs := make(map[string]struct{}, len(manifest.Materials))
	for index, material := range manifest.Materials {
		if strings.TrimSpace(material.URI) == "" || strings.ContainsAny(material.URI, "\x00\r\n") || !digestPattern.MatchString(material.SHA256) {
			return ErrInvalidManifest
		}
		if index > 0 && manifest.Materials[index-1].URI >= material.URI {
			return ErrInvalidManifest
		}
		if _, exists := materialURIs[material.URI]; exists {
			return ErrInvalidManifest
		}
		materialURIs[material.URI] = struct{}{}
	}
	required := map[string]ArtifactKind{
		LicenseFile:           ArtifactLicense,
		NoticeFile:            ArtifactNotice,
		ThirdPartyNoticesFile: ArtifactThirdPartyNotices,
		SBOMFile:              ArtifactSBOM,
		ProvenanceFile:        ArtifactProvenance,
		ReleaseEvidenceFile:   ArtifactReleaseEvidence,
	}
	seen := make(map[string]ArtifactKind, len(manifest.Artifacts))
	hasBinary := false
	hasImage := false
	for index, artifact := range manifest.Artifacts {
		clean := filepath.ToSlash(filepath.Clean(artifact.Path))
		if artifact.Path == "" || clean != artifact.Path || filepath.IsAbs(artifact.Path) || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsRune(artifact.Path, 0) || !digestPattern.MatchString(artifact.SHA256) || artifact.Size < 0 || !validArtifactKind(artifact.Kind) || !mediaTypePattern.MatchString(artifact.MediaType) {
			return ErrInvalidManifest
		}
		if index > 0 && manifest.Artifacts[index-1].Path >= artifact.Path {
			return ErrInvalidManifest
		}
		if _, exists := seen[clean]; exists {
			return ErrInvalidManifest
		}
		seen[clean] = artifact.Kind
		hasBinary = hasBinary || artifact.Kind == ArtifactBinary
		hasImage = hasImage || artifact.Kind == ArtifactContainerImage
	}
	if !hasBinary || !hasImage {
		return ErrInvalidManifest
	}
	for path, kind := range required {
		if seen[path] != kind {
			return ErrInvalidManifest
		}
	}
	if artifact, ok := findArtifact(manifest, SBOMFile); !ok || artifact.SHA256 != manifest.SBOMSHA256 {
		return ErrInvalidManifest
	}
	if artifact, ok := findArtifact(manifest, ProvenanceFile); !ok || artifact.SHA256 != manifest.ProvenanceSHA256 {
		return ErrInvalidManifest
	}
	if artifact, ok := findArtifact(manifest, ReleaseEvidenceFile); !ok || artifact.SHA256 != manifest.ReleaseEvidenceSHA256 {
		return ErrInvalidManifest
	}
	return nil
}

func validArtifactKind(kind ArtifactKind) bool {
	switch kind {
	case ArtifactBinary, ArtifactContainerImage, ArtifactDeployment, ArtifactLicense, ArtifactNotice, ArtifactThirdPartyNotices, ArtifactSBOM, ArtifactProvenance, ArtifactReleaseEvidence:
		return true
	default:
		return false
	}
}

func validateSignature(signature Signature) error {
	if signature.Algorithm != "Ed25519" || !identifierPattern.MatchString(signature.KID) || signature.Value == "" {
		return ErrInvalidManifest
	}
	value, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || len(value) != ed25519.SignatureSize {
		return ErrInvalidManifest
	}
	return nil
}

func verifySignature(keys Keyring, signature Signature, payload []byte) error {
	if err := validateSignature(signature); err != nil {
		return err
	}
	key, found := keys[signature.KID]
	if !found || len(key) != ed25519.PublicKeySize {
		return ErrKeyUnavailable
	}
	value, _ := base64.RawURLEncoding.DecodeString(signature.Value)
	if !ed25519.Verify(key, payload, value) {
		return ErrSignatureInvalid
	}
	return nil
}

func signPayload(key ed25519.PrivateKey, kid string, payload []byte) Signature {
	return Signature{Algorithm: "Ed25519", KID: kid, Value: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload))}
}

func artifactSignaturePayload(artifact Artifact) []byte {
	artifact.Signature = Signature{}
	return mustJSON(artifact)
}

func verifySpecialArtifact(manifest Manifest, path string, kind ArtifactKind, value []byte) error {
	if len(value) == 0 {
		return ErrDigestMismatch
	}
	artifact, ok := findArtifact(manifest, path)
	if !ok || artifact.Kind != kind || artifact.SHA256 != ArtifactDigest(value) || artifact.Size != int64(len(value)) {
		return ErrDigestMismatch
	}
	return nil
}

func findArtifact(manifest Manifest, path string) (Artifact, bool) {
	index := sort.Search(len(manifest.Artifacts), func(index int) bool { return manifest.Artifacts[index].Path >= path })
	if index >= len(manifest.Artifacts) || manifest.Artifacts[index].Path != path {
		return Artifact{}, false
	}
	return manifest.Artifacts[index], true
}

func verifyArtifact(root string, artifact Artifact) error {
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return ErrInvalidManifest
	}
	artifactAbsolute, err := filepath.Abs(filepath.Join(rootAbsolute, filepath.FromSlash(artifact.Path)))
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
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return ErrDigestMismatch
	}
	return nil
}

type spdxDocument struct {
	SPDXVersion       string `json:"spdxVersion"`
	DataLicense       string `json:"dataLicense"`
	SPDXID            string `json:"SPDXID"`
	Name              string `json:"name"`
	DocumentNamespace string `json:"documentNamespace"`
	CreationInfo      struct {
		Created  string   `json:"created"`
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	Packages []json.RawMessage `json:"packages"`
	Files    []struct {
		FileName  string `json:"fileName"`
		Checksums []struct {
			Algorithm     string `json:"algorithm"`
			ChecksumValue string `json:"checksumValue"`
		} `json:"checksums"`
	} `json:"files"`
}

type cycloneDXDocument struct {
	BomFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Version     int    `json:"version"`
	Metadata    struct {
		Timestamp string `json:"timestamp"`
		Component struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"component"`
	} `json:"metadata"`
	Components []struct {
		Name   string `json:"name"`
		Hashes []struct {
			Algorithm string `json:"alg"`
			Content   string `json:"content"`
		} `json:"hashes"`
	} `json:"components"`
}

func validateSBOM(value []byte, manifest Manifest) error {
	var format struct {
		SPDXVersion string `json:"spdxVersion"`
		BomFormat   string `json:"bomFormat"`
	}
	if err := json.Unmarshal(value, &format); err != nil {
		return err
	}
	expected := subjectArtifacts(manifest, SBOMFile, ProvenanceFile)
	if format.SPDXVersion != "" {
		var document spdxDocument
		if err := json.Unmarshal(value, &document); err != nil {
			return err
		}
		if document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" || document.SPDXID != "SPDXRef-DOCUMENT" || strings.TrimSpace(document.Name) == "" || !strings.HasPrefix(document.DocumentNamespace, "https://") || len(document.CreationInfo.Creators) == 0 || len(document.Packages) == 0 {
			return errors.New("incomplete SPDX 2.3 document")
		}
		if _, err := time.Parse(time.RFC3339, document.CreationInfo.Created); err != nil {
			return errors.New("invalid SPDX creation time")
		}
		files := make(map[string]string, len(document.Files))
		for _, file := range document.Files {
			for _, checksum := range file.Checksums {
				if checksum.Algorithm == "SHA256" && digestHexPattern.MatchString(checksum.ChecksumValue) {
					files[file.FileName] = "sha256:" + checksum.ChecksumValue
				}
			}
		}
		return requireArtifactCoverage(expected, files)
	}
	if format.BomFormat == "CycloneDX" {
		var document cycloneDXDocument
		if err := json.Unmarshal(value, &document); err != nil {
			return err
		}
		if document.BomFormat != "CycloneDX" || document.SpecVersion == "" || document.Version < 1 || strings.TrimSpace(document.Metadata.Component.Name) == "" || document.Metadata.Component.Version != manifest.Version || len(document.Components) == 0 {
			return errors.New("incomplete CycloneDX document")
		}
		if _, err := time.Parse(time.RFC3339, document.Metadata.Timestamp); err != nil {
			return errors.New("invalid CycloneDX timestamp")
		}
		components := make(map[string]string, len(document.Components))
		for _, component := range document.Components {
			for _, hash := range component.Hashes {
				if hash.Algorithm == "SHA-256" && digestHexPattern.MatchString(hash.Content) {
					components[component.Name] = "sha256:" + hash.Content
				}
			}
		}
		return requireArtifactCoverage(expected, components)
	}
	return errors.New("unsupported SBOM format")
}

func requireArtifactCoverage(expected []Artifact, actual map[string]string) error {
	for _, artifact := range expected {
		if actual[artifact.Path] != artifact.SHA256 {
			return fmt.Errorf("artifact %s is absent or has the wrong digest", artifact.Path)
		}
	}
	return nil
}

type provenanceStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		BuildDefinition struct {
			BuildType          string `json:"buildType"`
			ExternalParameters struct {
				Source struct {
					URI    string            `json:"uri"`
					Digest map[string]string `json:"digest"`
				} `json:"source"`
			} `json:"externalParameters"`
			InternalParameters   json.RawMessage `json:"internalParameters"`
			ResolvedDependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Metadata struct {
				InvocationID string `json:"invocationId"`
				StartedOn    string `json:"startedOn"`
				FinishedOn   string `json:"finishedOn"`
			} `json:"metadata"`
		} `json:"runDetails"`
	} `json:"predicate"`
}

func validateProvenance(value []byte, manifest Manifest) error {
	var statement provenanceStatement
	if err := decodeStrict(value, &statement); err != nil {
		return err
	}
	if statement.Type != "https://in-toto.io/Statement/v1" || statement.PredicateType != "https://slsa.dev/provenance/v1" || statement.Predicate.BuildDefinition.BuildType != manifest.BuildType || statement.Predicate.RunDetails.Builder.ID != manifest.BuilderIdentity || strings.TrimSpace(statement.Predicate.RunDetails.Metadata.InvocationID) == "" {
		return errors.New("SLSA provenance identity does not match the manifest")
	}
	source := statement.Predicate.BuildDefinition.ExternalParameters.Source
	if source.URI != manifest.SourceURI || source.Digest["gitCommit"] != manifest.SourceCommit {
		return errors.New("provenance source does not match the manifest")
	}
	started, startErr := time.Parse(time.RFC3339, statement.Predicate.RunDetails.Metadata.StartedOn)
	finished, finishErr := time.Parse(time.RFC3339, statement.Predicate.RunDetails.Metadata.FinishedOn)
	if startErr != nil || finishErr != nil || finished.Before(started) {
		return errors.New("invalid provenance build time")
	}
	expectedSubjects := subjectArtifacts(manifest, ProvenanceFile)
	subjects := make(map[string]string, len(statement.Subject))
	for _, subject := range statement.Subject {
		if subject.Name == "" || !digestHexPattern.MatchString(subject.Digest["sha256"]) {
			return errors.New("invalid provenance subject")
		}
		if _, exists := subjects[subject.Name]; exists {
			return errors.New("duplicate provenance subject")
		}
		subjects[subject.Name] = "sha256:" + subject.Digest["sha256"]
	}
	if len(subjects) != len(expectedSubjects) {
		return errors.New("provenance subject set is incomplete")
	}
	if err := requireArtifactCoverage(expectedSubjects, subjects); err != nil {
		return err
	}
	dependencies := make(map[string]string, len(statement.Predicate.BuildDefinition.ResolvedDependencies))
	for _, dependency := range statement.Predicate.BuildDefinition.ResolvedDependencies {
		digest := dependency.Digest["sha256"]
		if dependency.URI == "" || !digestHexPattern.MatchString(digest) {
			return errors.New("invalid provenance material")
		}
		if _, exists := dependencies[dependency.URI]; exists {
			return errors.New("duplicate provenance material")
		}
		dependencies[dependency.URI] = "sha256:" + digest
	}
	if len(dependencies) != len(manifest.Materials) {
		return errors.New("provenance material set is incomplete")
	}
	for _, material := range manifest.Materials {
		if dependencies[material.URI] != material.SHA256 {
			return fmt.Errorf("material %s is absent or has the wrong digest", material.URI)
		}
	}
	return nil
}

func validateReleaseEvidence(value []byte, manifest Manifest) error {
	var document struct {
		EvidenceVersion string `json:"evidenceVersion"`
		SpecVersion     string `json:"specVersion"`
		ReleaseVersion  string `json:"releaseVersion"`
		SourceCommit    string `json:"sourceCommit"`
		BuildDigest     string `json:"buildDigest"`
		StartedAt       string `json:"startedAt"`
		CompletedAt     string `json:"completedAt"`
		Environment     string `json:"environment"`
		Target          string `json:"target"`
		Results         []struct {
			RequirementID string   `json:"requirementId"`
			Status        string   `json:"status"`
			EvidenceURIs  []string `json:"evidenceUris,omitempty"`
			Tool          string   `json:"tool"`
			ToolVersion   string   `json:"toolVersion"`
		} `json:"results"`
		Exceptions     []string       `json:"exceptions"`
		EvidenceDigest string         `json:"evidenceDigest"`
		Signature      map[string]any `json:"signature"`
	}
	if err := decodeStrict(value, &document); err != nil {
		return err
	}
	if document.EvidenceVersion == "" || document.SpecVersion == "" || document.ReleaseVersion != manifest.Version || document.SourceCommit != manifest.SourceCommit || !digestPattern.MatchString(document.BuildDigest) || document.Environment != "production" || len(document.Results) == 0 || len(document.Exceptions) != 0 || !digestPattern.MatchString(document.EvidenceDigest) || len(document.Signature) == 0 {
		return errors.New("release evidence is not a signed production PASS report for this release")
	}
	for _, result := range document.Results {
		if result.RequirementID == "" || result.Status != "PASS" {
			return errors.New("release evidence contains a non-PASS result")
		}
	}
	computed, err := canonicaljson.DigestObjectWithoutFields(value, "evidenceDigest", "signature")
	if err != nil || computed != document.EvidenceDigest {
		return errors.New("release evidence digest is invalid")
	}
	return nil
}

func subjectArtifacts(manifest Manifest, excluded ...string) []Artifact {
	exclude := make(map[string]struct{}, len(excluded))
	for _, path := range excluded {
		exclude[path] = struct{}{}
	}
	output := make([]Artifact, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if _, found := exclude[artifact.Path]; !found {
			output = append(output, artifact)
		}
	}
	return output
}

func decodeStrict(value []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON documents are not allowed")
		}
		return err
	}
	return nil
}

func unsignedBytes(manifest Manifest) ([]byte, error) {
	manifest.Signature = Signature{}
	return json.Marshal(manifest)
}

func digestMatches(value []byte, expected string) bool {
	return len(value) > 0 && ArtifactDigest(value) == expected
}

func ArtifactDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func SortedArtifacts(manifest Manifest) []Artifact {
	artifacts := append([]Artifact(nil), manifest.Artifacts...)
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Path < artifacts[right].Path })
	return artifacts
}

func SortedMaterials(materials []Material) []Material {
	output := append([]Material(nil), materials...)
	sort.Slice(output, func(left, right int) bool { return output[left].URI < output[right].URI })
	return output
}
