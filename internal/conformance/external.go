package conformance

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

const (
	externalDriverProtocolVersion = "1.0"
	maxExternalManifestBytes      = 1 << 20
	maxExternalPublicKeyBytes     = 16 << 10
	maxExternalDriverOutputBytes  = 8 << 20
	maxExternalEvidenceBytes      = 32 << 20
	maxExternalDriverTimeout      = 15 * time.Minute
	minExternalDriverTimeout      = time.Second
	maxExternalEvidenceReferences = 256
)

var (
	externalDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	externalScopePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// ExternalDriverConfig describes a separately operated environment gate. The
// manifest, executable and corpus are all authenticated before the process is
// started. A nil config preserves the local/test behaviour of Runner.
type ExternalDriverConfig struct {
	ManifestPath   string
	PublicKeyPath  string
	PublicKey      ed25519.PublicKey
	Verifier       Signer
	Timeout        time.Duration
	MaxOutputBytes int64
}

// ExternalDriverManifest is the signed, machine-readable driver contract. The
// driver receives the target and isolation scope through environment variables
// and must return an ExternalDriverOutput on stdout.
type ExternalDriverManifest struct {
	ProtocolVersion  string     `json:"protocolVersion"`
	Tool             string     `json:"tool"`
	ToolVersion      string     `json:"toolVersion"`
	Executable       string     `json:"executable"`
	ExecutableSHA256 string     `json:"executableSha256"`
	Args             []string   `json:"args,omitempty"`
	CorpusPath       string     `json:"corpusPath"`
	CorpusSHA256     string     `json:"corpusSha256"`
	CorpusSignature  *Signature `json:"corpusSignature"`
	Target           string     `json:"target"`
	SpecVersion      string     `json:"specVersion"`
	ReleaseVersion   string     `json:"releaseVersion"`
	SourceCommit     string     `json:"sourceCommit"`
	BuildDigest      string     `json:"buildDigest"`
	TenantID         string     `json:"tenantId"`
	Namespace        string     `json:"namespace"`
	Groups           []string   `json:"groups"`
	TimeoutSeconds   int        `json:"timeoutSeconds"`
	MaxOutputBytes   int64      `json:"maxOutputBytes"`
	ManifestSHA256   string     `json:"manifestSha256"`
	Signature        *Signature `json:"signature"`
}

type externalDriverEvidence struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
}

type externalDriverResult struct {
	Group         string                   `json:"group"`
	RequirementID string                   `json:"requirementId"`
	Status        string                   `json:"status"`
	Evidence      []externalDriverEvidence `json:"evidence"`
	Message       string                   `json:"message,omitempty"`
}

type externalDriverOutput struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	ManifestSHA256  string                 `json:"manifestSha256"`
	Target          string                 `json:"target"`
	SpecVersion     string                 `json:"specVersion"`
	ReleaseVersion  string                 `json:"releaseVersion"`
	SourceCommit    string                 `json:"sourceCommit"`
	BuildDigest     string                 `json:"buildDigest"`
	TenantID        string                 `json:"tenantId"`
	Namespace       string                 `json:"namespace"`
	RunID           string                 `json:"runId"`
	Results         []externalDriverResult `json:"results"`
	Signature       *Signature             `json:"signature"`
}

type externalDriverRun struct {
	results map[string]RequirementResult
}

// runExternalDriver verifies and executes the independent gate. It returns
// only results whose requirement IDs are bound to the requested groups.
func (r *Runner) runExternalDriver(ctx context.Context, root string, request Request, buildDigest string, groups []string) (*externalDriverRun, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	config := request.ExternalDriver
	if config == nil {
		return nil, ErrEnvironmentGate
	}
	if len(groups) == 0 || strings.TrimSpace(config.ManifestPath) == "" || request.OutputDir == "" {
		return nil, errors.New("external driver manifest and raw output directory are required")
	}
	manifestBytes, err := readExternalFile(config.ManifestPath, maxExternalManifestBytes)
	if err != nil {
		return nil, fmt.Errorf("driver manifest: %w", err)
	}
	manifest, manifestPayload, manifestDigest, err := decodeExternalManifest(manifestBytes)
	if err != nil {
		return nil, err
	}
	if err := verifyExternalSignature(ctx, config, manifestPayload, manifest.Signature); err != nil {
		return nil, fmt.Errorf("driver manifest signature: %w", err)
	}
	if request.Profile == "production" && manifest.Signature.Type != "Ed25519" {
		return nil, errors.New("production driver manifests require an Ed25519 signature")
	}
	if err := validateExternalManifest(manifest, request, buildDigest, groups); err != nil {
		return nil, err
	}
	corpusPath, err := resolveExternalPath(root, manifest.CorpusPath, false)
	if err != nil {
		return nil, fmt.Errorf("driver corpus path: %w", err)
	}
	corpusBytes, err := readExternalFile(corpusPath, maxExternalEvidenceBytes)
	if err != nil {
		return nil, fmt.Errorf("driver corpus: %w", err)
	}
	if digestBytes(corpusBytes) != manifest.CorpusSHA256 {
		return nil, errors.New("driver corpus digest does not match the signed manifest")
	}
	corpusPayload := []byte("aor-conformance-driver-corpus-v1\n" + manifest.CorpusSHA256)
	if err := verifyExternalSignature(ctx, config, corpusPayload, manifest.CorpusSignature); err != nil {
		return nil, fmt.Errorf("driver corpus signature: %w", err)
	}
	if manifest.CorpusSignature.KID != manifest.Signature.KID {
		return nil, errors.New("driver corpus and manifest signer identities differ")
	}
	if request.Profile == "production" && manifest.CorpusSignature.Type != "Ed25519" {
		return nil, errors.New("production driver corpora require an Ed25519 signature")
	}
	executable, err := resolveExecutable(root, manifest.Executable)
	if err != nil {
		return nil, fmt.Errorf("driver executable: %w", err)
	}
	executableBytes, err := readExternalFile(executable, maxExternalEvidenceBytes)
	if err != nil {
		return nil, fmt.Errorf("driver executable: %w", err)
	}
	if digestBytes(executableBytes) != manifest.ExecutableSHA256 {
		return nil, errors.New("driver executable digest does not match the signed manifest")
	}

	runID, err := externalRunID()
	if err != nil {
		return nil, errors.New("external driver run ID generation failed")
	}
	outputDirectory, err := filepath.Abs(request.OutputDir)
	if err != nil {
		return nil, err
	}
	evidenceDirectory := filepath.Join(outputDirectory, "raw", "external", runID)
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("external evidence directory: %w", err)
	}
	if err := ensurePrivateDirectory(outputDirectory); err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectoryTree(filepath.Join(outputDirectory, "raw"), filepath.Join(outputDirectory, "raw", "external", runID)); err != nil {
		return nil, err
	}
	resolvedEvidenceDirectory, err := filepath.EvalSymlinks(evidenceDirectory)
	if err != nil {
		return nil, err
	}
	manifestRef, err := writeExternalRaw(outputDirectory, filepath.Join("external", runID, "driver-manifest.json"), manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("driver manifest evidence: %w", err)
	}
	manifestArtifactRef := "artifact://conformance/driver-manifest#sha256=" + strings.TrimPrefix(manifestDigest, "sha256:")

	timeout := time.Duration(manifest.TimeoutSeconds) * time.Second
	if config.Timeout > 0 && timeout > config.Timeout {
		return nil, errors.New("driver timeout exceeds the configured limit")
	}
	maxOutput := manifest.MaxOutputBytes
	if config.MaxOutputBytes > 0 && maxOutput > config.MaxOutputBytes {
		return nil, errors.New("driver output limit exceeds the configured limit")
	}
	stdout := &externalLimitedBuffer{limit: maxOutput}
	stderr := &externalLimitedBuffer{limit: maxOutput}
	driverContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(driverContext, executable, manifest.Args...)
	command.Dir = root
	command.Stdout = stdout
	command.Stderr = stderr
	command.Env = appendExternalEnvironment(os.Environ(),
		"AOR_CONFORMANCE_PROTOCOL_VERSION="+externalDriverProtocolVersion,
		"AOR_CONFORMANCE_MANIFEST_SHA256="+manifestDigest,
		"AOR_CONFORMANCE_TARGET="+manifest.Target,
		"AOR_CONFORMANCE_SPEC_VERSION="+manifest.SpecVersion,
		"AOR_CONFORMANCE_RELEASE_VERSION="+manifest.ReleaseVersion,
		"AOR_CONFORMANCE_SOURCE_COMMIT="+manifest.SourceCommit,
		"AOR_CONFORMANCE_BUILD_DIGEST="+buildDigest,
		"AOR_CONFORMANCE_TENANT_ID="+manifest.TenantID,
		"AOR_CONFORMANCE_NAMESPACE="+manifest.Namespace,
		"AOR_CONFORMANCE_RUN_ID="+runID,
		"AOR_CONFORMANCE_GROUPS="+strings.Join(manifest.Groups, ","),
		"AOR_CONFORMANCE_EVIDENCE_DIR="+evidenceDirectory,
	)
	runErr := command.Run()
	stdoutRef, stdoutErr := writeExternalRaw(outputDirectory, filepath.Join("external", runID, "driver.stdout"), stdout.Bytes())
	stderrRef, stderrErr := writeExternalRaw(outputDirectory, filepath.Join("external", runID, "driver.stderr"), stderr.Bytes())
	if stdoutErr != nil || stderrErr != nil {
		return nil, errors.New("driver output evidence could not be stored")
	}
	if stdout.Overflowed() || stderr.Overflowed() {
		return nil, errors.New("driver output exceeds the configured limit")
	}
	if errors.Is(driverContext.Err(), context.DeadlineExceeded) {
		return nil, errors.New("driver timed out")
	}
	if runErr != nil {
		return nil, fmt.Errorf("driver exited unsuccessfully: %w", runErr)
	}
	outputBytes := stdout.Bytes()
	driverOutput, resultPayload, err := decodeExternalOutput(outputBytes)
	if err != nil {
		return nil, err
	}
	if err := validateExternalOutput(ctx, driverOutput, resultPayload, config, request.Profile, manifest, manifestDigest, buildDigest, runID, groups); err != nil {
		return nil, err
	}
	resultRef, err := writeExternalRaw(outputDirectory, filepath.Join("external", runID, "driver-result.json"), outputBytes)
	if err != nil {
		return nil, fmt.Errorf("driver result evidence: %w", err)
	}
	commonRefs := []string{manifestRef, manifestArtifactRef, stdoutRef, stderrRef, resultRef,
		"artifact://conformance/driver-corpus#sha256=" + strings.TrimPrefix(manifest.CorpusSHA256, "sha256:"),
		"artifact://conformance/driver-executable#sha256=" + strings.TrimPrefix(manifest.ExecutableSHA256, "sha256:"),
	}
	result := &externalDriverRun{results: make(map[string]RequirementResult, len(driverOutput.Results))}
	currentEvidenceDirectory, err := filepath.EvalSymlinks(evidenceDirectory)
	if err != nil || currentEvidenceDirectory != resolvedEvidenceDirectory {
		return nil, errors.New("driver changed the evidence directory")
	}
	for _, item := range driverOutput.Results {
		refs, err := copyExternalEvidence(outputDirectory, resolvedEvidenceDirectory, runID, item.Group, item.Evidence)
		if err != nil {
			return nil, err
		}
		allRefs := append(append([]string(nil), commonRefs...), refs...)
		result.results[item.Group] = RequirementResult{RequirementID: item.RequirementID, Status: item.Status, EvidenceURIs: allRefs, Tool: manifest.Tool, ToolVersion: manifest.ToolVersion}
	}
	return result, nil
}

func validateExternalManifest(manifest ExternalDriverManifest, request Request, buildDigest string, groups []string) error {
	if manifest.ProtocolVersion != externalDriverProtocolVersion || strings.TrimSpace(manifest.Tool) == "" || strings.TrimSpace(manifest.ToolVersion) == "" || strings.ContainsAny(manifest.Tool, "\r\n") || strings.ContainsAny(manifest.ToolVersion, "\r\n") {
		return errors.New("driver manifest protocol or tool identity is invalid")
	}
	if !externalDigestPattern.MatchString(manifest.ManifestSHA256) || manifest.ManifestSHA256 == "" {
		return errors.New("driver manifest digest is invalid")
	}
	if !externalDigestPattern.MatchString(manifest.ExecutableSHA256) || !externalDigestPattern.MatchString(manifest.CorpusSHA256) {
		return errors.New("driver executable and corpus digests are required")
	}
	if manifest.Target != request.Target || manifest.SpecVersion != request.SpecVersion || manifest.ReleaseVersion != request.ReleaseVersion || manifest.SourceCommit != request.SourceCommit || manifest.BuildDigest != buildDigest || manifest.Target == "" && request.Profile == "production" {
		return errors.New("driver manifest is not bound to the requested target or release")
	}
	if !externalScopePattern.MatchString(manifest.TenantID) || !externalScopePattern.MatchString(manifest.Namespace) {
		return errors.New("driver manifest must declare a bounded tenant and deletable namespace")
	}
	if manifest.TimeoutSeconds < int(minExternalDriverTimeout/time.Second) || manifest.TimeoutSeconds > int(maxExternalDriverTimeout/time.Second) {
		return errors.New("driver timeout is outside the allowed range")
	}
	if manifest.MaxOutputBytes <= 0 || manifest.MaxOutputBytes > maxExternalDriverOutputBytes {
		return errors.New("driver output limit is outside the allowed range")
	}
	if len(manifest.Args) > 64 {
		return errors.New("driver argument count exceeds the limit")
	}
	for _, arg := range manifest.Args {
		if strings.ContainsRune(arg, 0) || len(arg) > 4096 {
			return errors.New("driver argument is invalid")
		}
	}
	want := append([]string(nil), groups...)
	got := append([]string(nil), manifest.Groups...)
	if !sameGroups(got, want) {
		return errors.New("driver manifest groups do not match the requested external groups")
	}
	for _, group := range got {
		if _, ok := externalRequirementForGroup(group); !ok {
			return errors.New("driver manifest contains a non-external group")
		}
	}
	return nil
}

func validateExternalOutput(ctx context.Context, output externalDriverOutput, payload []byte, config *ExternalDriverConfig, profile string, manifest ExternalDriverManifest, manifestDigest, buildDigest, runID string, groups []string) error {
	if output.ProtocolVersion != externalDriverProtocolVersion || output.ManifestSHA256 != manifestDigest || output.Target != manifest.Target || output.SpecVersion != manifest.SpecVersion || output.ReleaseVersion != manifest.ReleaseVersion || output.SourceCommit != manifest.SourceCommit || output.BuildDigest != buildDigest || output.TenantID != manifest.TenantID || output.Namespace != manifest.Namespace || output.RunID != runID {
		return errors.New("driver result is not bound to the signed target, scope, build, or run")
	}
	if config.Verifier != nil || len(config.PublicKey) > 0 || config.PublicKeyPath != "" {
		if output.Signature == nil {
			if profile == "production" {
				return errors.New("signed driver result is required")
			}
		} else if err := verifyExternalSignature(ctx, config, payload, output.Signature); err != nil {
			return fmt.Errorf("driver result signature: %w", err)
		}
		if output.Signature != nil && output.Signature.KID != manifest.Signature.KID {
			return errors.New("driver result and manifest signer identities differ")
		}
		if profile == "production" && output.Signature != nil && output.Signature.Type != "Ed25519" {
			return errors.New("production driver results require an Ed25519 signature")
		}
	}
	if len(output.Results) != len(groups) {
		return errors.New("driver result must contain exactly one result per external group")
	}
	wanted := make(map[string]string, len(groups))
	for _, group := range groups {
		wanted[group], _ = externalRequirementForGroup(group)
	}
	seen := make(map[string]struct{}, len(output.Results))
	for _, item := range output.Results {
		requirement, ok := wanted[item.Group]
		if !ok || item.RequirementID != requirement {
			return errors.New("driver result requirement mapping is invalid")
		}
		if _, exists := seen[item.Group]; exists {
			return errors.New("driver returned duplicate group results")
		}
		seen[item.Group] = struct{}{}
		if item.Status != "PASS" && item.Status != "FAIL" && item.Status != "INCONCLUSIVE" {
			return errors.New("driver result status is invalid")
		}
		if len(item.Evidence) == 0 || len(item.Evidence) > maxExternalEvidenceReferences {
			return errors.New("driver result must reference raw evidence")
		}
		for _, evidence := range item.Evidence {
			if !externalDigestPattern.MatchString(evidence.SHA256) || evidence.Path == "" || !validExternalEvidenceKind(evidence.Kind) {
				return errors.New("driver evidence reference is invalid")
			}
		}
	}
	if len(seen) != len(groups) {
		return errors.New("driver omitted an external group result")
	}
	return nil
}

func externalRequirementForGroup(group string) (string, bool) {
	switch group {
	case "security":
		return "AOR-ACC-043", true
	case "authn":
		return "AOR-ACC-041", true
	case "authz", "tool-broker":
		return "AOR-ACC-042", true
	case "sandbox-linux":
		return "AOR-ACC-054", true
	case "sandbox-windows":
		return "AOR-ACC-055", true
	case "budget":
		return "AOR-ACC-072", true
	case "knowledge":
		return "AOR-ACC-012", true
	case "audit":
		return "AOR-ACC-048", true
	case "integration":
		return "AOR-ACC-019", true
	case "observability":
		return "AOR-ACC-078", true
	case "backup-restore":
		return "AOR-ACC-036", true
	case "chaos":
		return "AOR-ACC-056", true
	case "performance":
		return "AOR-ACC-066", true
	case "supply-chain":
		return "AOR-ACC-050", true
	case "full":
		return "AOR-ACC-100", true
	default:
		return "", false
	}
}

func requestedExternalGroups(groups []string) []string {
	result := make([]string, 0, len(groups))
	for _, group := range groups {
		if _, ok := externalRequirementForGroup(group); ok {
			result = append(result, group)
		}
	}
	sort.Strings(result)
	return result
}

func decodeExternalManifest(raw []byte) (ExternalDriverManifest, []byte, string, error) {
	var manifest ExternalDriverManifest
	if err := decodeStrictExternal(raw, &manifest); err != nil {
		return ExternalDriverManifest{}, nil, "", fmt.Errorf("driver manifest: %w", err)
	}
	payload, digest, err := externalSignedPayload(raw, "signature", "manifestSha256", "aor-conformance-driver-manifest-v1")
	if err != nil {
		return ExternalDriverManifest{}, nil, "", fmt.Errorf("driver manifest digest: %w", err)
	}
	if manifest.ManifestSHA256 != digest {
		return ExternalDriverManifest{}, nil, "", errors.New("driver manifest digest does not match its signed content")
	}
	if manifest.Signature == nil {
		return ExternalDriverManifest{}, nil, "", errors.New("driver manifest signature is required")
	}
	return manifest, payload, digest, nil
}

func decodeExternalOutput(raw []byte) (externalDriverOutput, []byte, error) {
	var output externalDriverOutput
	if len(raw) == 0 || len(raw) > maxExternalDriverOutputBytes {
		return externalDriverOutput{}, nil, errors.New("driver result is empty or exceeds the limit")
	}
	if err := decodeStrictExternal(raw, &output); err != nil {
		return externalDriverOutput{}, nil, fmt.Errorf("driver result: %w", err)
	}
	payload, _, err := externalSignedPayload(raw, "signature", "", "aor-conformance-driver-result-v1")
	if err != nil {
		return externalDriverOutput{}, nil, fmt.Errorf("driver result digest: %w", err)
	}
	return output, payload, nil
}

func externalSignedPayload(raw []byte, signatureField, digestField, domain string) ([]byte, string, error) {
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return nil, "", err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &object); err != nil || object == nil {
		return nil, "", errors.New("signed document must be a JSON object")
	}
	delete(object, signatureField)
	if digestField != "" {
		delete(object, digestField)
	}
	unsigned, err := json.Marshal(object)
	if err != nil {
		return nil, "", err
	}
	canonical, err = canonicaljson.Canonicalize(unsigned)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(canonical)
	payload := append([]byte(domain+"\n"), canonical...)
	return payload, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func verifyExternalSignature(ctx context.Context, config *ExternalDriverConfig, payload []byte, signature *Signature) error {
	if signature == nil || strings.TrimSpace(signature.KID) == "" || signature.Type != "Ed25519" && config.Verifier == nil {
		return ErrGateFailed
	}
	if len(signature.Value) > 512 {
		return ErrGateFailed
	}
	if config.Verifier != nil {
		return config.Verifier.Verify(ctx, payload, signature)
	}
	publicKey, err := externalPublicKey(config)
	if err != nil {
		return err
	}
	encoded, err := base64.RawURLEncoding.DecodeString(signature.Value)
	if err != nil || len(encoded) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, encoded) {
		return ErrGateFailed
	}
	return nil
}

func externalPublicKey(config *ExternalDriverConfig) (ed25519.PublicKey, error) {
	if len(config.PublicKey) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), config.PublicKey...), nil
	}
	if config.PublicKeyPath == "" {
		return nil, errors.New("driver public key is required")
	}
	raw, err := readExternalFile(config.PublicKeyPath, maxExternalPublicKeyBytes)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("driver public key is not Ed25519")
		}
		return append(ed25519.PublicKey(nil), key...), nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == ed25519.PublicKeySize {
		return append(ed25519.PublicKey(nil), trimmed...), nil
	}
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
		decoded, decodeErr := encoding.DecodeString(string(trimmed))
		if decodeErr == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}
	return nil, errors.New("driver public key encoding is invalid")
}

func resolveExternalPath(root, value string, allowOutside bool) (string, error) {
	if value == "" || strings.ContainsRune(value, 0) || strings.Contains(value, "\\") {
		return "", ErrInvalidRequest
	}
	if filepath.IsAbs(value) {
		if !allowOutside {
			return "", ErrInvalidRequest
		}
		return filepath.Clean(value), nil
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if clean == "." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || clean == ".." {
		return "", ErrInvalidRequest
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absolute := filepath.Join(absoluteRoot, clean)
	if !pathWithinExternalRoot(absoluteRoot, absolute) {
		return "", ErrInvalidRequest
	}
	return absolute, nil
}

func resolveExecutable(root, value string) (string, error) {
	if strings.TrimSpace(value) == "" || strings.ContainsRune(value, 0) {
		return "", ErrInvalidRequest
	}
	if filepath.IsAbs(value) || strings.ContainsAny(value, `/\\`) {
		path, err := resolveExternalPath(root, value, true)
		if err != nil {
			return "", err
		}
		return path, nil
	}
	path, err := exec.LookPath(value)
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}

func readExternalFile(path string, limit int64) ([]byte, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, ErrInvalidRequest
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		if err != nil {
			return nil, err
		}
		return nil, ErrInvalidRequest
	}
	if info.Size() > limit {
		return nil, errors.New("file exceeds the configured limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(value)) > limit {
		return nil, errors.New("file exceeds the configured limit")
	}
	return value, nil
}

func decodeStrictExternal(raw []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON documents are not allowed")
		}
		return err
	}
	return nil
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func appendExternalEnvironment(base []string, values ...string) []string {
	filtered := make([]string, 0, len(base)+len(values))
	for _, item := range base {
		if strings.HasPrefix(item, "AOR_CONFORMANCE_") {
			continue
		}
		filtered = append(filtered, item)
	}
	return append(filtered, values...)
}

func externalRunID() (string, error) {
	var value [16]byte
	// The run identifier is generated by the runner and is never accepted from
	// the target or the driver.
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

type externalLimitedBuffer struct {
	mu       sync.Mutex
	value    bytes.Buffer
	limit    int64
	overflow bool
}

func (b *externalLimitedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - int64(b.value.Len())
	if remaining <= 0 {
		b.overflow = true
		return 0, errors.New("external driver output limit exceeded")
	}
	if int64(len(value)) > remaining {
		_, _ = b.value.Write(value[:remaining])
		b.overflow = true
		return int(remaining), errors.New("external driver output limit exceeded")
	}
	return b.value.Write(value)
}

func (b *externalLimitedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.value.Bytes()...)
}

func (b *externalLimitedBuffer) Overflowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

func copyExternalEvidence(outputDirectory, evidenceDirectory, runID, group string, evidence []externalDriverEvidence) ([]string, error) {
	if len(evidence) > maxExternalEvidenceReferences {
		return nil, errors.New("driver evidence reference count exceeds the limit")
	}
	refs := make([]string, 0, len(evidence))
	var totalBytes int64
	for index, item := range evidence {
		if strings.ContainsRune(item.Path, 0) || strings.Contains(item.Path, "\\") || filepath.IsAbs(item.Path) || filepath.Clean(filepath.FromSlash(item.Path)) != filepath.FromSlash(item.Path) || item.Path == "." || strings.HasPrefix(item.Path, "../") {
			return nil, errors.New("driver evidence path escapes the evidence directory")
		}
		path := filepath.Join(evidenceDirectory, filepath.FromSlash(item.Path))
		if !pathWithinExternalRoot(evidenceDirectory, path) {
			return nil, errors.New("driver evidence path escapes the evidence directory")
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("driver evidence path must be a regular non-symlink file")
		}
		resolvedRoot, err := filepath.EvalSymlinks(evidenceDirectory)
		if err != nil {
			return nil, err
		}
		resolvedPath, err := filepath.EvalSymlinks(path)
		if err != nil || !pathWithinExternalRoot(resolvedRoot, resolvedPath) {
			return nil, errors.New("driver evidence path is not contained in the evidence directory")
		}
		value, err := readExternalFile(resolvedPath, maxExternalEvidenceBytes)
		if err != nil {
			return nil, err
		}
		if digestBytes(value) != item.SHA256 {
			return nil, errors.New("driver evidence digest does not match the signed result")
		}
		totalBytes += int64(len(value))
		if totalBytes > maxExternalDriverOutputBytes*8 {
			return nil, errors.New("driver evidence exceeds the aggregate limit")
		}
		name := fmt.Sprintf("%s/%03d-%s", filepath.ToSlash(filepath.Join("external", runID, group)), index, filepath.Base(filepath.FromSlash(item.Path)))
		ref, err := writeExternalRaw(outputDirectory, name, value)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

func validExternalEvidenceKind(kind string) bool {
	switch kind {
	case "trace", "log", "artifact", "result", "other":
		return true
	default:
		return false
	}
}

func writeExternalRaw(outputDirectory, relative string, value []byte) (string, error) {
	if strings.ContainsRune(relative, 0) || filepath.IsAbs(relative) || strings.Contains(relative, "\\") {
		return "", ErrInvalidRequest
	}
	clean := filepath.Clean(filepath.FromSlash(relative))
	if clean == "." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || clean == ".." {
		return "", ErrInvalidRequest
	}
	root := filepath.Join(outputDirectory, "raw")
	path := filepath.Join(root, clean)
	if !pathWithinExternalRoot(root, path) {
		return "", ErrInvalidRequest
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return "", err
	}
	if err := ensurePrivateDirectoryTree(root, filepath.Dir(path)); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".external-evidence-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(value); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return "", err
	}
	digest := sha256.Sum256(value)
	return "file:raw/" + filepath.ToSlash(clean) + "#sha256=" + hex.EncodeToString(digest[:]), nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		if err != nil {
			return err
		}
		return ErrInvalidRequest
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("external evidence directory must be owner-only: %w", err)
		}
	}
	return nil
}

func ensurePrivateDirectoryTree(root, target string) error {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absoluteTarget, err := filepath.Abs(target)
	if err != nil || !pathWithinExternalRoot(absoluteRoot, absoluteTarget) {
		return ErrInvalidRequest
	}
	relative, err := filepath.Rel(absoluteRoot, absoluteTarget)
	if err != nil {
		return err
	}
	current := absoluteRoot
	if err := ensurePrivateDirectory(current); err != nil {
		return err
	}
	for _, part := range strings.Split(relative, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		if err := ensurePrivateDirectory(current); err != nil {
			return err
		}
	}
	return nil
}

func pathWithinExternalRoot(root, target string) bool {
	relative, err := filepath.Rel(root, target)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && !filepath.IsAbs(relative)
}
