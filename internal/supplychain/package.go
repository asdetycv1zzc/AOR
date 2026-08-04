package supplychain

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
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
)

const maxDependencyLicenseBytes = 4 << 20

var licenseExpressionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-.+() ]{0,255}$`)

var approvedLicenseIdentifiers = map[string]struct{}{
	"0BSD":         {},
	"Apache-2.0":   {},
	"BSD-2-Clause": {},
	"BSD-3-Clause": {},
	"ISC":          {},
	"MIT":          {},
	"MPL-2.0":      {},
}

type PackageArtifact struct {
	SourcePath string
	Path       string
	Kind       ArtifactKind
	MediaType  string
}

type Dependency struct {
	Name        string
	Version     string
	SourceURI   string
	SHA256      string
	License     string
	LicenseText string
}

type AssembleRequest struct {
	OutputDir             string
	Version               string
	SourceURI             string
	SourceCommit          string
	BuilderIdentity       string
	BuildType             string
	InvocationID          string
	StartedAt             time.Time
	FinishedAt            time.Time
	Materials             []Material
	Artifacts             []PackageArtifact
	Dependencies          []Dependency
	LicenseSource         string
	NoticeSource          string
	ReleaseEvidenceSource string
	PrivateKey            ed25519.PrivateKey
	KID                   string
}

func Assemble(ctx context.Context, request AssembleRequest) (Report, error) {
	if ctx == nil || ctx.Err() != nil {
		return Report{}, ErrInvalidManifest
	}
	if err := validateAssembleRequest(request); err != nil {
		return Report{}, err
	}
	output, err := filepath.Abs(request.OutputDir)
	if err != nil {
		return Report{}, err
	}
	if _, err := os.Lstat(output); err == nil || !errors.Is(err, os.ErrNotExist) {
		return Report{}, fmt.Errorf("%w: output directory must not exist", ErrInvalidManifest)
	}
	parent := filepath.Dir(output)
	if info, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return Report{}, err
		}
		info, err = os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return Report{}, ErrInvalidManifest
		}
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Report{}, ErrInvalidManifest
	}
	temporary, err := os.MkdirTemp(parent, ".aor-release-")
	if err != nil {
		return Report{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(temporary)
		}
	}()

	artifacts := make([]Artifact, 0, len(request.Artifacts)+6)
	for _, input := range request.Artifacts {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		artifact, err := copyPackageArtifact(temporary, input)
		if err != nil {
			return Report{}, err
		}
		artifacts = append(artifacts, artifact)
	}
	for _, input := range []PackageArtifact{
		{SourcePath: request.LicenseSource, Path: LicenseFile, Kind: ArtifactLicense, MediaType: "text/plain"},
		{SourcePath: request.NoticeSource, Path: NoticeFile, Kind: ArtifactNotice, MediaType: "text/plain"},
		{SourcePath: request.ReleaseEvidenceSource, Path: ReleaseEvidenceFile, Kind: ArtifactReleaseEvidence, MediaType: "application/json"},
	} {
		artifact, err := copyPackageArtifact(temporary, input)
		if err != nil {
			return Report{}, err
		}
		artifacts = append(artifacts, artifact)
	}
	notices, err := generateThirdPartyNotices(request.Dependencies)
	if err != nil {
		return Report{}, err
	}
	noticeArtifact, err := writeGeneratedArtifact(temporary, ThirdPartyNoticesFile, ArtifactThirdPartyNotices, "text/markdown", notices)
	if err != nil {
		return Report{}, err
	}
	artifacts = append(artifacts, noticeArtifact)
	sortArtifactsByPath(artifacts)

	manifest := Manifest{
		SchemaVersion:   ManifestSchemaVersion,
		Version:         request.Version,
		SourceURI:       request.SourceURI,
		SourceCommit:    request.SourceCommit,
		BuilderIdentity: request.BuilderIdentity,
		BuildType:       request.BuildType,
		Materials:       SortedMaterials(request.Materials),
		Artifacts:       append([]Artifact(nil), artifacts...),
	}
	sbom, err := generateSPDX(manifest, request.Dependencies, request.FinishedAt)
	if err != nil {
		return Report{}, err
	}
	sbomArtifact, err := writeGeneratedArtifact(temporary, SBOMFile, ArtifactSBOM, "application/spdx+json", sbom)
	if err != nil {
		return Report{}, err
	}
	artifacts = append(artifacts, sbomArtifact)
	sortArtifactsByPath(artifacts)
	manifest.Artifacts = append([]Artifact(nil), artifacts...)
	manifest.SBOMSHA256 = sbomArtifact.SHA256

	provenance, err := generateProvenance(manifest, request.InvocationID, request.StartedAt, request.FinishedAt)
	if err != nil {
		return Report{}, err
	}
	provenanceArtifact, err := writeGeneratedArtifact(temporary, ProvenanceFile, ArtifactProvenance, "application/vnd.in-toto+json", provenance)
	if err != nil {
		return Report{}, err
	}
	artifacts = append(artifacts, provenanceArtifact)
	sortArtifactsByPath(artifacts)
	manifest.Artifacts = artifacts
	manifest.ProvenanceSHA256 = provenanceArtifact.SHA256
	evidenceArtifact, found := findArtifact(manifest, ReleaseEvidenceFile)
	if !found {
		return Report{}, ErrInvalidManifest
	}
	manifest.ReleaseEvidenceSHA256 = evidenceArtifact.SHA256
	manifest, err = SignManifest(manifest, request.PrivateKey, request.KID)
	if err != nil {
		return Report{}, err
	}
	if err := WriteManifest(temporary, manifest); err != nil {
		return Report{}, err
	}
	bundle, err := LoadBundle(temporary)
	if err != nil {
		return Report{}, err
	}
	publicKey := request.PrivateKey.Public().(ed25519.PublicKey)
	report, err := Verify(ctx, bundle, Keyring{request.KID: publicKey})
	if err != nil {
		return Report{}, err
	}
	if err := os.Rename(temporary, output); err != nil {
		return Report{}, err
	}
	cleanup = false
	if err := syncDirectory(parent); err != nil {
		return Report{}, err
	}
	return report, nil
}

func validateAssembleRequest(request AssembleRequest) error {
	if strings.TrimSpace(request.OutputDir) == "" || strings.ContainsRune(request.OutputDir, 0) || !versionPattern.MatchString(request.Version) || strings.TrimSpace(request.SourceURI) == "" || strings.ContainsAny(request.SourceURI, "\x00\r\n") || !commitPattern.MatchString(request.SourceCommit) || !identifierPattern.MatchString(request.BuilderIdentity) || !identifierPattern.MatchString(request.BuildType) || !identifierPattern.MatchString(request.InvocationID) || request.StartedAt.IsZero() || request.FinishedAt.IsZero() || request.FinishedAt.Before(request.StartedAt) || len(request.PrivateKey) != ed25519.PrivateKeySize || !identifierPattern.MatchString(request.KID) || len(request.Materials) == 0 || len(request.Artifacts) == 0 || len(request.Dependencies) == 0 {
		return ErrInvalidManifest
	}
	for _, path := range []string{request.LicenseSource, request.NoticeSource, request.ReleaseEvidenceSource} {
		if strings.TrimSpace(path) == "" || strings.ContainsRune(path, 0) {
			return ErrInvalidManifest
		}
	}
	seen := map[string]struct{}{}
	hasBinary := false
	hasImage := false
	hasDeployment := false
	reserved := map[string]struct{}{ManifestFile: {}, LicenseFile: {}, NoticeFile: {}, ThirdPartyNoticesFile: {}, SBOMFile: {}, ProvenanceFile: {}, ReleaseEvidenceFile: {}}
	for _, artifact := range request.Artifacts {
		if _, found := reserved[artifact.Path]; found || !validPackagePath(artifact.Path) || strings.TrimSpace(artifact.SourcePath) == "" || strings.ContainsRune(artifact.SourcePath, 0) || !mediaTypePattern.MatchString(artifact.MediaType) {
			return ErrInvalidManifest
		}
		switch artifact.Kind {
		case ArtifactBinary:
			hasBinary = true
		case ArtifactContainerImage:
			hasImage = true
		case ArtifactDeployment:
			hasDeployment = true
		default:
			return ErrInvalidManifest
		}
		if _, found := seen[artifact.Path]; found {
			return ErrInvalidManifest
		}
		seen[artifact.Path] = struct{}{}
	}
	if !hasBinary || !hasImage || !hasDeployment {
		return ErrInvalidManifest
	}
	materialURIs := map[string]struct{}{}
	for _, material := range request.Materials {
		if strings.TrimSpace(material.URI) == "" || strings.ContainsAny(material.URI, "\x00\r\n") || !digestPattern.MatchString(material.SHA256) {
			return ErrInvalidManifest
		}
		if _, found := materialURIs[material.URI]; found {
			return ErrInvalidManifest
		}
		materialURIs[material.URI] = struct{}{}
	}
	dependencies := map[string]struct{}{}
	for _, dependency := range request.Dependencies {
		identity := dependency.Name + "@" + dependency.Version
		if strings.TrimSpace(dependency.Name) == "" || strings.TrimSpace(dependency.Version) == "" || strings.TrimSpace(dependency.SourceURI) == "" || strings.ContainsAny(identity+dependency.SourceURI, "\x00\r\n") || !digestPattern.MatchString(dependency.SHA256) || !licenseExpressionPattern.MatchString(dependency.License) || !approvedLicenseExpression(dependency.License) || strings.TrimSpace(dependency.LicenseText) == "" || len(dependency.LicenseText) > maxDependencyLicenseBytes {
			return ErrInvalidManifest
		}
		if _, found := dependencies[identity]; found {
			return ErrInvalidManifest
		}
		dependencies[identity] = struct{}{}
	}
	return nil
}

func approvedLicenseExpression(expression string) bool {
	for _, token := range strings.FieldsFunc(expression, func(value rune) bool {
		return value == ' ' || value == '(' || value == ')'
	}) {
		switch token {
		case "AND", "OR", "WITH":
			continue
		}
		if _, found := approvedLicenseIdentifiers[token]; !found {
			return false
		}
	}
	return true
}

func copyPackageArtifact(root string, input PackageArtifact) (Artifact, error) {
	info, err := os.Lstat(input.SourcePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Artifact{}, ErrInvalidManifest
	}
	source, err := os.Open(input.SourcePath)
	if err != nil {
		return Artifact{}, err
	}
	destinationPath := filepath.Join(root, filepath.FromSlash(input.Path))
	if err := os.MkdirAll(filepath.Dir(destinationPath), 0o700); err != nil {
		_ = source.Close()
		return Artifact{}, err
	}
	mode := os.FileMode(0o400)
	if input.Kind == ArtifactBinary {
		mode = 0o500
	}
	destination, err := os.OpenFile(destinationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		_ = source.Close()
		return Artifact{}, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(destination, hash), source)
	sourceCloseErr := source.Close()
	syncErr := destination.Sync()
	destinationCloseErr := destination.Close()
	for _, current := range []error{copyErr, sourceCloseErr, syncErr, destinationCloseErr} {
		if current != nil {
			return Artifact{}, current
		}
	}
	return Artifact{Path: input.Path, SHA256: "sha256:" + hex.EncodeToString(hash.Sum(nil)), Size: written, Kind: input.Kind, MediaType: input.MediaType}, nil
}

func writeGeneratedArtifact(root, path string, kind ArtifactKind, mediaType string, value []byte) (Artifact, error) {
	if len(value) == 0 || !validPackagePath(path) {
		return Artifact{}, ErrInvalidManifest
	}
	absolute := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
		return Artifact{}, err
	}
	file, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
	if err != nil {
		return Artifact{}, err
	}
	_, writeErr := file.Write(value)
	syncErr := file.Sync()
	closeErr := file.Close()
	for _, current := range []error{writeErr, syncErr, closeErr} {
		if current != nil {
			return Artifact{}, current
		}
	}
	return Artifact{Path: path, SHA256: ArtifactDigest(value), Size: int64(len(value)), Kind: kind, MediaType: mediaType}, nil
}

func validPackagePath(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	return path != "" && clean == path && !filepath.IsAbs(path) && clean != ".." && !strings.HasPrefix(clean, "../") && !strings.ContainsRune(path, 0)
}

func generateThirdPartyNotices(input []Dependency) ([]byte, error) {
	dependencies := append([]Dependency(nil), input...)
	sort.Slice(dependencies, func(left, right int) bool {
		return dependencies[left].Name+"@"+dependencies[left].Version < dependencies[right].Name+"@"+dependencies[right].Version
	})
	var output strings.Builder
	output.WriteString("# Third-party notices\n\n")
	output.WriteString("This file is generated from the locked release dependency inventory.\n")
	for _, dependency := range dependencies {
		output.WriteString("\n## ")
		output.WriteString(dependency.Name)
		output.WriteString(" ")
		output.WriteString(dependency.Version)
		output.WriteString("\n\nSource: ")
		output.WriteString(dependency.SourceURI)
		output.WriteString("\n\nSHA-256: ")
		output.WriteString(dependency.SHA256)
		output.WriteString("\n\nLicense: ")
		output.WriteString(dependency.License)
		output.WriteString("\n\n```text\n")
		output.WriteString(strings.TrimSpace(dependency.LicenseText))
		output.WriteString("\n```\n")
	}
	return []byte(output.String()), nil
}

func generateSPDX(manifest Manifest, input []Dependency, created time.Time) ([]byte, error) {
	dependencies := append([]Dependency(nil), input...)
	sort.Slice(dependencies, func(left, right int) bool {
		return dependencies[left].Name+"@"+dependencies[left].Version < dependencies[right].Name+"@"+dependencies[right].Version
	})
	packages := make([]map[string]any, 0, len(dependencies)+1)
	packages = append(packages, map[string]any{"SPDXID": "SPDXRef-Package-AOR", "name": "aor", "versionInfo": manifest.Version, "downloadLocation": manifest.SourceURI, "filesAnalyzed": true, "licenseConcluded": "MIT", "licenseDeclared": "MIT"})
	for index, dependency := range dependencies {
		packages = append(packages, map[string]any{"SPDXID": fmt.Sprintf("SPDXRef-Dependency-%d", index+1), "name": dependency.Name, "versionInfo": dependency.Version, "downloadLocation": dependency.SourceURI, "filesAnalyzed": false, "licenseConcluded": dependency.License, "licenseDeclared": dependency.License, "checksums": []map[string]string{{"algorithm": "SHA256", "checksumValue": strings.TrimPrefix(dependency.SHA256, "sha256:")}}})
	}
	files := make([]map[string]any, 0, len(manifest.Artifacts))
	relationships := make([]map[string]string, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		identifier := "SPDXRef-File-" + shortIdentifier(artifact.Path)
		files = append(files, map[string]any{"SPDXID": identifier, "fileName": artifact.Path, "checksums": []map[string]string{{"algorithm": "SHA256", "checksumValue": strings.TrimPrefix(artifact.SHA256, "sha256:")}}, "licenseConcluded": "NOASSERTION"})
		relationships = append(relationships, map[string]string{"spdxElementId": "SPDXRef-Package-AOR", "relationshipType": "CONTAINS", "relatedSpdxElement": identifier})
	}
	document := map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "aor-" + manifest.Version, "documentNamespace": "https://aor.dev/sbom/" + manifest.SourceCommit + "/" + manifest.Version, "creationInfo": map[string]any{"created": created.UTC().Format(time.RFC3339), "creators": []string{"Tool: aor-release-" + manifest.Version, "Organization: AOR"}}, "packages": packages, "files": files, "relationships": relationships}
	return json.Marshal(document)
}

func generateProvenance(manifest Manifest, invocationID string, started, finished time.Time) ([]byte, error) {
	subjects := make([]map[string]any, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		subjects = append(subjects, map[string]any{"name": artifact.Path, "digest": map[string]string{"sha256": strings.TrimPrefix(artifact.SHA256, "sha256:")}})
	}
	dependencies := make([]map[string]any, 0, len(manifest.Materials))
	for _, material := range manifest.Materials {
		dependencies = append(dependencies, map[string]any{"uri": material.URI, "digest": map[string]string{"sha256": strings.TrimPrefix(material.SHA256, "sha256:")}})
	}
	statement := map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": subjects, "predicateType": "https://slsa.dev/provenance/v1", "predicate": map[string]any{"buildDefinition": map[string]any{"buildType": manifest.BuildType, "externalParameters": map[string]any{"source": map[string]any{"uri": manifest.SourceURI, "digest": map[string]string{"gitCommit": manifest.SourceCommit}}}, "internalParameters": map[string]any{}, "resolvedDependencies": dependencies}, "runDetails": map[string]any{"builder": map[string]string{"id": manifest.BuilderIdentity}, "metadata": map[string]string{"invocationId": invocationID, "startedOn": started.UTC().Format(time.RFC3339), "finishedOn": finished.UTC().Format(time.RFC3339)}}}}
	return json.Marshal(statement)
}

func shortIdentifier(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}

func sortArtifactsByPath(artifacts []Artifact) {
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Path < artifacts[right].Path })
}
