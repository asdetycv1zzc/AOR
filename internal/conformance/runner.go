package conformance

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/bootstrap"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/pkg/canonicaljson"
)

var (
	ErrInvalidRequest  = errors.New("invalid conformance request")
	ErrGateFailed      = errors.New("conformance gate failed")
	ErrEnvironmentGate = errors.New("conformance requires an external environment gate")
)

type RequirementResult struct {
	RequirementID string   `json:"requirementId"`
	Status        string   `json:"status"`
	EvidenceURIs  []string `json:"evidenceUris,omitempty"`
	Tool          string   `json:"tool"`
	ToolVersion   string   `json:"toolVersion"`
}

type ReleaseEvidence struct {
	EvidenceVersion string              `json:"evidenceVersion"`
	SpecVersion     string              `json:"specVersion"`
	BuildDigest     string              `json:"buildDigest"`
	StartedAt       string              `json:"startedAt"`
	CompletedAt     string              `json:"completedAt"`
	Environment     string              `json:"environment"`
	Target          string              `json:"target,omitempty"`
	Results         []RequirementResult `json:"results"`
	Exceptions      []string            `json:"exceptions"`
	EvidenceDigest  string              `json:"evidenceDigest"`
	Signature       *Signature          `json:"signature,omitempty"`
}

type Signature struct {
	Type  string `json:"type"`
	KID   string `json:"kid"`
	Value string `json:"value"`
}

type Signer interface {
	Sign(context.Context, []byte) (*Signature, error)
	Verify(context.Context, []byte, *Signature) error
}

type Request struct {
	Root        string
	Target      string
	Profile     string
	SpecVersion string
	OutputDir   string
	Groups      []string
	Signer      Signer
	Clock       func() time.Time
}

type Runner struct {
	clock func() time.Time
}

var productionGroups = []string{"contracts", "state-machine", "idempotency", "a2a", "aop", "mcp", "authn", "authz", "budget", "tool-broker", "sandbox-linux", "sandbox-windows", "knowledge", "audit", "integration", "observability", "backup-restore", "chaos", "performance", "supply-chain", "full"}

func NewRunner(clock func() time.Time) *Runner {
	if clock == nil {
		clock = time.Now
	}
	return &Runner{clock: clock}
}

func (r *Runner) Run(ctx context.Context, request Request) (ReleaseEvidence, error) {
	if err := contextErr(ctx); err != nil {
		return ReleaseEvidence{}, err
	}
	if request.Root == "" || request.SpecVersion == "" || (request.Profile != "test" && request.Profile != "preproduction" && request.Profile != "production") || request.Profile == "production" && request.Target == "" {
		return ReleaseEvidence{}, ErrInvalidRequest
	}
	root, err := filepath.Abs(request.Root)
	if err != nil {
		return ReleaseEvidence{}, ErrInvalidRequest
	}
	if len(request.Groups) == 0 {
		if request.Profile == "production" {
			request.Groups = append([]string(nil), productionGroups...)
		} else {
			request.Groups = []string{"contracts", "state-machine", "idempotency", "security", "observability"}
		}
	}
	if err := validateGroups(request.Groups); err != nil {
		return ReleaseEvidence{}, err
	}
	if request.Profile == "production" && !sameGroups(request.Groups, productionGroups) {
		return ReleaseEvidence{}, ErrInvalidRequest
	}
	started := r.clock().UTC()
	build, err := buildDigest(root, request.OutputDir)
	if err != nil {
		return ReleaseEvidence{}, err
	}
	evidence := ReleaseEvidence{EvidenceVersion: "1.0", SpecVersion: request.SpecVersion, BuildDigest: build, StartedAt: started.Format(time.RFC3339), Environment: request.Profile, Target: request.Target, Results: []RequirementResult{}, Exceptions: []string{}}
	hardFailure := false
	if request.Profile == "production" {
		spec, specErr := os.ReadFile(filepath.Join(root, "SPEC.md"))
		catalog, catalogErr := os.ReadFile(filepath.Join(root, "conformance", "requirements.yaml"))
		if specErr != nil || catalogErr != nil {
			evidence.Exceptions = append(evidence.Exceptions, "requirement catalog: SPEC.md and conformance/requirements.yaml are required")
			hardFailure = true
		} else if findings := bootstrap.ValidateProductionRequirementCatalogAt(root, spec, catalog); len(findings) > 0 {
			for _, finding := range findings {
				evidence.Exceptions = append(evidence.Exceptions, "requirement catalog: "+finding.Code+": "+finding.Message)
			}
			hardFailure = true
		}
	}
	for _, group := range request.Groups {
		results, gateErr, environmentGate := runGroup(ctx, root, group)
		evidence.Results = append(evidence.Results, results...)
		if environmentGate {
			if request.Profile == "production" {
				evidence.Exceptions = append(evidence.Exceptions, group+": external preproduction evidence required")
			} else {
				evidence.Exceptions = append(evidence.Exceptions, group+": environment gate not executed in local runner")
			}
		}
		if gateErr != nil {
			evidence.Exceptions = append(evidence.Exceptions, group+": "+gateErr.Error())
			hardFailure = true
		}
	}
	sort.Slice(evidence.Results, func(left, right int) bool {
		return evidence.Results[left].RequirementID < evidence.Results[right].RequirementID
	})
	evidence.CompletedAt = r.clock().UTC().Format(time.RFC3339)
	if request.Profile == "production" && request.Signer == nil {
		evidence.Exceptions = append(evidence.Exceptions, "release signer is required for production")
	}
	if err := finalize(&evidence, request.Signer); err != nil {
		return ReleaseEvidence{}, err
	}
	if request.OutputDir != "" {
		if err := Write(request.OutputDir, evidence); err != nil {
			return ReleaseEvidence{}, err
		}
	}
	if hardFailure || request.Profile != "test" && len(evidence.Exceptions) > 0 {
		return evidence, ErrGateFailed
	}
	return evidence, nil
}

func runGroup(ctx context.Context, root, group string) ([]RequirementResult, error, bool) {
	tool := "aor-conformance"
	version := "2.0.0"
	pass := func(id string, paths ...string) RequirementResult {
		return RequirementResult{RequirementID: id, Status: "PASS", EvidenceURIs: paths, Tool: tool, ToolVersion: version}
	}
	inconclusive := func(id string, paths ...string) RequirementResult {
		return RequirementResult{RequirementID: id, Status: "INCONCLUSIVE", EvidenceURIs: paths, Tool: tool, ToolVersion: version}
	}
	fail := func(id string, message string) (RequirementResult, error) {
		return RequirementResult{RequirementID: id, Status: "FAIL", EvidenceURIs: []string{message}, Tool: tool, ToolVersion: version}, ErrGateFailed
	}
	switch group {
	case "contracts", "a2a", "aop", "mcp", "idempotency":
		if findings := bootstrap.ValidateJSONDocuments(root); len(findings) > 0 {
			result, err := fail(conformanceRequirement(group), findings[0].Message)
			return []RequirementResult{result}, err, false
		}
		return []RequirementResult{pass(conformanceRequirement(group), "artifact://conformance/"+group)}, nil, false
	case "state-machine":
		if findings := state.Conformance(); len(findings) > 0 {
			result, err := fail("AOR-INV-001", findings[0].Error())
			return []RequirementResult{result}, err, false
		}
		return []RequirementResult{pass("AOR-INV-001", "artifact://conformance/state-machine")}, nil, false
	case "security", "authn", "authz", "tool-broker", "sandbox-linux", "sandbox-windows", "budget", "knowledge", "audit":
		return []RequirementResult{inconclusive(environmentRequirement(group), "artifact://conformance/security/"+group)}, nil, true
	case "observability":
		return []RequirementResult{inconclusive("AOR-ACC-078", "artifact://conformance/observability")}, nil, true
	case "backup-restore", "chaos", "performance", "supply-chain", "integration", "full":
		return []RequirementResult{inconclusive(environmentRequirement(group), "artifact://conformance/"+group)}, nil, true
	default:
		return nil, ErrInvalidRequest, false
	}
}

func environmentRequirement(group string) string {
	switch group {
	case "authn":
		return "AOR-ACC-041"
	case "authz", "tool-broker":
		return "AOR-ACC-042"
	case "sandbox-linux":
		return "AOR-ACC-054"
	case "sandbox-windows":
		return "AOR-ACC-055"
	case "budget":
		return "AOR-ACC-072"
	case "knowledge":
		return "AOR-ACC-012"
	case "audit":
		return "AOR-ACC-048"
	case "integration":
		return "AOR-ACC-019"
	case "backup-restore":
		return "AOR-ACC-036"
	case "chaos":
		return "AOR-ACC-056"
	case "performance":
		return "AOR-ACC-066"
	case "supply-chain":
		return "AOR-ACC-050"
	case "full":
		return "AOR-ACC-100"
	default:
		return "AOR-ACC-043"
	}
}

func conformanceRequirement(group string) string {
	switch group {
	case "a2a":
		return "AOR-ACC-021"
	case "aop":
		return "AOR-ACC-022"
	case "mcp":
		return "AOR-ACC-028"
	case "idempotency":
		return "AOR-ACC-023"
	default:
		return "AOR-ACC-025"
	}
}

func finalize(evidence *ReleaseEvidence, signer Signer) error {
	evidence.EvidenceDigest = ""
	evidence.Signature = nil
	payload, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(payload, "evidenceDigest", "signature")
	if err != nil {
		return err
	}
	evidence.EvidenceDigest = digest
	if signer != nil {
		signature, err := signer.Sign(context.Background(), signaturePayload(*evidence))
		if err != nil {
			return err
		}
		evidence.Signature = signature
	}
	return nil
}

func Write(directory string, evidence ReleaseEvidence) error {
	if directory == "" || strings.ContainsRune(directory, 0) {
		return ErrInvalidRequest
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	temporary := filepath.Join(directory, ".release-evidence.json.tmp")
	final := filepath.Join(directory, "release-evidence.json")
	if err := os.WriteFile(temporary, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, final)
}

func Verify(ctx context.Context, evidence ReleaseEvidence, signer Signer) error {
	if evidence.EvidenceDigest == "" {
		return ErrInvalidRequest
	}
	if (evidence.Environment == "production" || evidence.Environment == "preproduction") && signer == nil || evidence.Signature != nil && signer == nil {
		return ErrGateFailed
	}
	digest := evidence.EvidenceDigest
	signature := evidence.Signature
	evidence.EvidenceDigest = ""
	evidence.Signature = nil
	computed, err := canonicaljson.DigestObjectWithoutFields(mustJSON(evidence), "evidenceDigest", "signature")
	if err != nil || computed != digest {
		return ErrGateFailed
	}
	if signer != nil {
		if signature == nil {
			return ErrGateFailed
		}
		evidence.EvidenceDigest = digest
		if err := signer.Verify(ctx, signaturePayload(evidence), signature); err != nil {
			return err
		}
	}
	return nil
}

func buildDigest(root, outputDirectory string) (string, error) {
	excluded := ""
	if outputDirectory != "" {
		absolute, err := filepath.Abs(outputDirectory)
		if err != nil {
			return "", err
		}
		excluded = filepath.Clean(absolute)
	}
	paths := []string{}
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		clean := filepath.Clean(name)
		if entry.IsDir() && (entry.Name() == ".git" || excluded != "" && clean == excluded) {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, clean)
		if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return ErrInvalidRequest
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(paths)
	digest := sha256.New()
	for _, relative := range paths {
		absolute := filepath.Join(root, filepath.FromSlash(relative))
		info, err := os.Lstat(absolute)
		if err != nil {
			return "", err
		}
		writeDigestField(digest, []byte(relative))
		writeDigestField(digest, []byte(info.Mode().String()))
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(absolute)
			if err != nil {
				return "", err
			}
			writeDigestField(digest, []byte(target))
			continue
		}
		if !info.Mode().IsRegular() {
			return "", ErrInvalidRequest
		}
		file, err := os.Open(absolute)
		if err != nil {
			return "", err
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(info.Size()))
		_, _ = digest.Write(size[:])
		_, copyErr := io.Copy(digest, file)
		closeErr := file.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), nil
}

func writeDigestField(destination io.Writer, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = destination.Write(size[:])
	_, _ = destination.Write(value)
}

func validateGroups(groups []string) error {
	allowed := map[string]bool{"contracts": true, "state-machine": true, "idempotency": true, "a2a": true, "aop": true, "mcp": true, "authn": true, "authz": true, "security": true, "budget": true, "tool-broker": true, "sandbox-linux": true, "sandbox-windows": true, "knowledge": true, "audit": true, "integration": true, "observability": true, "backup-restore": true, "chaos": true, "performance": true, "supply-chain": true, "full": true}
	for _, group := range groups {
		if !allowed[group] {
			return ErrInvalidRequest
		}
	}
	return nil
}

func sameGroups(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] || index > 0 && leftCopy[index] == leftCopy[index-1] {
			return false
		}
	}
	return true
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}
func mustJSON(value any) []byte { encoded, _ := json.Marshal(value); return encoded }

func signaturePayload(evidence ReleaseEvidence) []byte {
	evidence.Signature = nil
	return mustJSON(evidence)
}

type HMACSigner struct{ key []byte }

func NewHMACSigner(key []byte) (*HMACSigner, error) {
	if len(key) < 32 {
		return nil, ErrInvalidRequest
	}
	return &HMACSigner{key: append([]byte(nil), key...)}, nil
}
func (s *HMACSigner) Sign(_ context.Context, payload []byte) (*Signature, error) {
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(payload)
	return &Signature{Type: "HMAC-SHA256", KID: "release-local", Value: "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))}, nil
}
func (s *HMACSigner) Verify(_ context.Context, payload []byte, signature *Signature) error {
	if signature == nil || signature.Type != "HMAC-SHA256" || !strings.HasPrefix(signature.Value, "hmac-sha256:") {
		return ErrGateFailed
	}
	expected := hmac.New(sha256.New, s.key)
	_, _ = expected.Write(payload)
	provided, err := hex.DecodeString(strings.TrimPrefix(signature.Value, "hmac-sha256:"))
	if err != nil || !hmac.Equal(expected.Sum(nil), provided) {
		return ErrGateFailed
	}
	return nil
}
