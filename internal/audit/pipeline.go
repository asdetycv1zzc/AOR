package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

var (
	digestPattern          = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	pipelineVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

func NewPipeline(checks []Check, auditors AuditorFactory, signer Signer, store EvidenceStore, version string, clock func() time.Time) (*Pipeline, error) {
	return newPipeline(checks, auditors, signer, store, nil, nil, version, clock)
}

func NewPipelineWithArtifactStore(checks []Check, auditors AuditorFactory, signer Signer, store EvidenceStore, artifacts ArtifactPublisher, version string, clock func() time.Time) (*Pipeline, error) {
	return newPipeline(checks, auditors, signer, store, artifacts, nil, version, clock)
}

func NewPersistentPipeline(checks []Check, auditors AuditorFactory, signer Signer, store EvidenceStore, artifacts ArtifactPublisher, runStore AuditRunStore, version string, clock func() time.Time) (*Pipeline, error) {
	if runStore == nil {
		return nil, ErrInvalidInput
	}
	return newPipeline(checks, auditors, signer, store, artifacts, runStore, version, clock)
}

func newPipeline(checks []Check, auditors AuditorFactory, signer Signer, store EvidenceStore, artifacts ArtifactPublisher, runStore AuditRunStore, version string, clock func() time.Time) (*Pipeline, error) {
	if signer == nil || store == nil || !pipelineVersionPattern.MatchString(version) {
		return nil, ErrInvalidInput
	}
	if clock == nil {
		clock = time.Now
	}
	if len(checks) == 0 {
		checks = DefaultChecks()
	}
	seen := make(map[string]bool, len(checks))
	for _, check := range checks {
		if check == nil || !safeCheckID(check.ID()) || seen[check.ID()] {
			return nil, ErrInvalidInput
		}
		seen[check.ID()] = true
	}
	return &Pipeline{checks: append([]Check(nil), checks...), auditors: auditors, signer: signer, store: store, runStore: runStore, artifacts: artifacts, clock: clock, version: version}, nil
}

func (p *Pipeline) Run(ctx context.Context, input DeterministicInput) (AuditResult, error) {
	return p.run(ctx, input, nil)
}

// RunWithDeterministicGate commits the authoritative DETERMINISTIC_SUCCESS
// transition before a fresh LLM Auditor can be created.
func (p *Pipeline) RunWithDeterministicGate(ctx context.Context, input DeterministicInput, gate func(context.Context, string) error) (AuditResult, error) {
	if gate == nil {
		return AuditResult{}, ErrInvalidInput
	}
	return p.run(ctx, input, gate)
}

func (p *Pipeline) run(ctx context.Context, input DeterministicInput, gate func(context.Context, string) error) (AuditResult, error) {
	if err := contextErr(ctx); err != nil {
		return AuditResult{}, err
	}
	if err := validateInput(input); err != nil {
		return AuditResult{}, err
	}
	if p.artifacts != nil && strings.TrimSpace(input.TenantID) == "" {
		return AuditResult{}, ErrInvalidInput
	}
	var runStarted time.Time
	if p.runStore != nil {
		if !validAuditRunID(input.AuditRunID) || strings.TrimSpace(input.SubmissionID) == "" {
			return AuditResult{}, ErrInvalidInput
		}
		runStarted = p.clock().UTC()
	}
	checks := make([]contracts.EvidenceCheck, 0, len(p.checks))
	findings := []contracts.AuditFinding{}
	artifactRefs := []string{}
	deterministicPassed := true
	for ordinal, check := range p.checks {
		started := p.clock().UTC()
		result := check.Run(ctx, cloneDeterministicInput(input))
		ended := p.clock().UTC()
		status := result.Status
		if status != StatusPass {
			deterministicPassed = false
			if status != StatusFail && status != StatusError {
				status = StatusError
			}
			if len(result.Findings) == 0 {
				result.Findings = []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "DETERMINISTIC", check.ID(), "", check.ID(), "check-"+strings.ToLower(string(status)), "required deterministic check passes", "required deterministic check returned "+string(status), "fix the reported check failure without weakening the check")}
			} else {
				result.Findings = cloneFindings(result.Findings)
			}
		}
		findings = append(findings, result.Findings...)
		outputs, err := p.persistCheckOutputs(ctx, input, check.ID(), result)
		if err != nil {
			return AuditResult{}, err
		}
		artifactRefs = appendUnique(artifactRefs, outputs.refs...)
		checks = append(checks, contracts.EvidenceCheck{CheckID: check.ID(), Ordinal: ordinal + 1, Type: "DETERMINISTIC", Status: string(status), Tool: contracts.CheckTool{Name: "aor-audit", Version: p.version, Digest: digestBytes([]byte(p.version))}, StartedAt: started.Format(time.RFC3339), CompletedAt: ended.Format(time.RFC3339), StdoutURI: outputs.stdout, StderrURI: outputs.stderr, ResultURI: outputs.result, ResultSHA256: outputs.resultDigest})
	}
	var err error
	findings, err = canonicalFindings(findings)
	if err != nil {
		return AuditResult{}, ErrInvalidInput
	}
	bundle := contracts.EvidenceBundle{EvidenceBundleVersion: 1, ProjectID: input.Manifest.ProjectID, TaskID: input.Manifest.ModuleTaskID, AttemptSeriesID: input.Manifest.AttemptSeriesID, Attempt: input.Manifest.Attempt, SpecVersion: input.ModuleSpecRef.Version, BaseCommit: input.Manifest.BaseCommit, SubmissionCommit: input.Manifest.HeadCommit, PipelineVersion: p.version, PolicyBundleDigest: input.PolicyDigest, ExecutionPlatform: input.Platform, IsolationLevel: input.Isolation, SandboxAttestation: input.SandboxAttestation, Checks: checks, Findings: cloneFindings(findings), CriteriaResults: []contracts.CriterionResult{}, ResidualRisks: []string{}, Confidence: 0, Artifacts: artifactRefs, LLMAudit: contracts.LLMAudit{Verdict: "NOT_RUN"}}
	if deterministicPassed {
		if gate != nil {
			digest, err := deterministicGateDigest(input, checks, findings)
			if err != nil {
				return AuditResult{}, err
			}
			if err := gate(ctx, digest); err != nil {
				return AuditResult{Bundle: bundle, Deterministic: checks, Verdict: "INCONCLUSIVE"}, err
			}
		}
		blind := BlindAuditInput{AuditRunID: input.AuditRunID, TenantID: input.TenantID, ProjectID: input.Manifest.ProjectID, TaskID: input.Manifest.ModuleTaskID, AttemptSeriesID: input.Manifest.AttemptSeriesID, Attempt: input.Manifest.Attempt, ModuleSpecRef: input.ModuleSpecRef, ModuleSpec: cloneOptionalModuleSpec(input.ModuleSpec), BaseCommit: input.Manifest.BaseCommit, SubmissionCommit: input.Manifest.HeadCommit, ChangedFiles: append([]string(nil), input.Manifest.ChangedFiles...), RequiredCriteria: append([]string(nil), input.RequiredCriteria...), TestRequirements: append([]string(nil), input.TestRequirements...), DeterministicChecks: append([]contracts.EvidenceCheck(nil), checks...)}
		if p.auditors == nil {
			return AuditResult{Bundle: bundle, Deterministic: checks, Verdict: "INCONCLUSIVE"}, ErrAuditorUnavailable
		}
		auditor, err := p.auditors.New(ctx)
		if err != nil || auditor == nil {
			return AuditResult{Bundle: bundle, Deterministic: checks, Verdict: "INCONCLUSIVE"}, ErrAuditorUnavailable
		}
		if err := validateBlindInput(blind); err != nil {
			return AuditResult{}, err
		}
		bundle.ManifestSHA256 = ""
		blind.EvidenceBundle = bundle
		llm, err := auditor.Audit(ctx, blind)
		if err != nil {
			return AuditResult{Bundle: bundle, Deterministic: checks, Verdict: "INCONCLUSIVE"}, err
		}
		llm, err = canonicalLLMResult(llm, input.RequiredCriteria)
		if err != nil {
			return AuditResult{}, err
		}
		if err := validateLLMResult(llm, input.RequiredCriteria, input.Manifest.Attempt); err != nil {
			return AuditResult{}, err
		}
		bundle.LLMAudit = contracts.LLMAudit{AuditorRunID: llm.AuditorRunID, ModelIdentity: llm.ModelIdentity, PromptDigest: llm.PromptDigest, ContextManifestDigest: llm.ContextDigest, Verdict: llm.Verdict}
		findings = append(findings, llm.Findings...)
		findings, err = canonicalFindings(findings)
		if err != nil {
			return AuditResult{}, ErrInvalidInput
		}
		bundle.Findings = cloneFindings(findings)
		bundle.CriteriaResults = cloneCriteriaResults(llm.CriteriaResults)
		bundle.ResidualRisks = cloneStrings(llm.ResidualRisks)
		bundle.Confidence = llm.Confidence
		verdict := llm.Verdict
		if !bundle.PassesAuditGate() && verdict == "PASS" {
			verdict = "FAIL"
		}
		result := AuditResult{Bundle: bundle, Deterministic: checks, LLM: &llm, Verdict: verdict}
		if err := p.persistResult(ctx, input, runStarted, &result); err != nil {
			return AuditResult{}, err
		}
		if !result.Bundle.PassesAuditGate() {
			return result, ErrDeterministicGate
		}
		return result, nil
	}
	result := AuditResult{Bundle: bundle, Deterministic: checks, Verdict: "FAIL"}
	if err := p.persistResult(ctx, input, runStarted, &result); err != nil {
		return AuditResult{}, err
	}
	return result, ErrDeterministicGate
}

func deterministicGateDigest(input DeterministicInput, checks []contracts.EvidenceCheck, findings []contracts.AuditFinding) (string, error) {
	type gateCheck struct {
		CheckID      string              `json:"checkId"`
		Ordinal      int                 `json:"ordinal"`
		Type         string              `json:"type"`
		Status       string              `json:"status"`
		Tool         contracts.CheckTool `json:"tool"`
		ResultSHA256 string              `json:"resultSha256"`
	}
	stableChecks := make([]gateCheck, len(checks))
	for index, check := range checks {
		stableChecks[index] = gateCheck{
			CheckID: check.CheckID, Ordinal: check.Ordinal, Type: check.Type,
			Status: check.Status, Tool: check.Tool, ResultSHA256: check.ResultSHA256,
		}
	}
	payload, err := json.Marshal(struct {
		SubmissionID     string                      `json:"submissionId"`
		ManifestSHA256   string                      `json:"manifestSha256"`
		ModuleSpecRef    contracts.SpecRef           `json:"moduleSpecRef"`
		PolicyDigest     string                      `json:"policyDigest"`
		Platform         contracts.ExecutionPlatform `json:"platform"`
		Isolation        contracts.IsolationLevel    `json:"isolation"`
		Sandbox          string                      `json:"sandboxAttestation"`
		RequiredCriteria []string                    `json:"requiredCriteria"`
		TestRequirements []string                    `json:"testRequirements"`
		Checks           []gateCheck                 `json:"checks"`
		Findings         []contracts.AuditFinding    `json:"findings"`
	}{
		SubmissionID: input.SubmissionID, ManifestSHA256: input.Manifest.SHA256,
		ModuleSpecRef: input.ModuleSpecRef, PolicyDigest: input.PolicyDigest,
		Platform: input.Platform, Isolation: input.Isolation, Sandbox: input.SandboxAttestation,
		RequiredCriteria: append([]string(nil), input.RequiredCriteria...), TestRequirements: append([]string(nil), input.TestRequirements...), Checks: stableChecks,
		Findings: cloneFindings(findings),
	})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(payload)
}

func (p *Pipeline) persistResult(ctx context.Context, input DeterministicInput, startedAt time.Time, result *AuditResult) error {
	if err := p.finalize(ctx, &result.Bundle); err != nil {
		return err
	}
	if err := p.store.Put(ctx, input.TenantID, result.Bundle); err != nil {
		return err
	}
	if p.runStore == nil {
		return nil
	}
	phase := "DETERMINISTIC"
	if result.LLM != nil {
		phase = "LLM"
	}
	return p.runStore.Put(ctx, AuditRun{
		ID:                input.AuditRunID,
		TenantID:          input.TenantID,
		ProjectID:         input.Manifest.ProjectID,
		SubmissionID:      input.SubmissionID,
		Phase:             phase,
		PipelineVersion:   p.version,
		Platform:          input.Platform,
		Isolation:         input.Isolation,
		StartedAt:         startedAt,
		CompletedAt:       p.clock().UTC(),
		Verdict:           result.Verdict,
		EvidenceBundleRef: result.Bundle.ManifestSHA256,
		Findings:          cloneFindings(result.Bundle.Findings),
	})
}

func (p *Pipeline) finalize(ctx context.Context, bundle *contracts.EvidenceBundle) error {
	bundle.ManifestSHA256 = ""
	payload, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(payload, "manifestSha256", "signature")
	if err != nil {
		return err
	}
	bundle.ManifestSHA256 = digest
	signed, err := p.signer.Sign(ctx, mustJSON(bundle))
	if err != nil {
		return err
	}
	bundle.Signature = signed
	if err := bundle.Validate(); err != nil {
		return err
	}
	return nil
}

func DefaultChecks() []Check {
	return []Check{schemaCheck{}, commitCheck{}, pathCheck{}, outputCheck{}}
}

type schemaCheck struct{}

func (schemaCheck) ID() string { return "submission-schema" }
func (schemaCheck) Run(_ context.Context, input DeterministicInput) CheckResult {
	if input.Manifest.Validate() != nil || input.Manifest.ModuleSpecRef != input.ModuleSpecRef {
		return CheckResult{Status: StatusFail, Findings: []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "INTEGRITY", "submission-schema", "", "submission-manifest", "invalid-manifest-or-spec-reference", "submission manifest and immutable ModuleSpec reference are valid", "submission manifest or immutable ModuleSpec reference is invalid", "correct the manifest without changing the approved ModuleSpec")}}
	}
	return CheckResult{Status: StatusPass, Result: []byte("schema-pass")}
}

type commitCheck struct{}

func (commitCheck) ID() string { return "commit-integrity" }
func (commitCheck) Run(_ context.Context, input DeterministicInput) CheckResult {
	if input.Manifest.BaseCommit == input.Manifest.HeadCommit || !commitID(input.Manifest.BaseCommit) || !commitID(input.Manifest.HeadCommit) {
		return CheckResult{Status: StatusFail, Findings: []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "INTEGRITY", "commit-integrity", "", "submission-commit", "invalid-or-unchanged-commit", "submission is bound to distinct immutable base and head commits", "submission commit is not immutable", "create a valid commit without rewriting the approved base")}}
	}
	return CheckResult{Status: StatusPass, Result: []byte(input.Manifest.BaseCommit + ".." + input.Manifest.HeadCommit)}
}

type pathCheck struct{}

func (pathCheck) ID() string { return "path-ownership" }
func (pathCheck) Run(_ context.Context, input DeterministicInput) CheckResult {
	if len(input.AllowedPaths) == 0 {
		return CheckResult{Status: StatusFail, Findings: []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "OWNERSHIP", "path-ownership", "", "module-owned-paths", "missing-owned-paths", "ModuleSpec grants at least one owned path", "ModuleSpec has no owned paths", "revise the ModuleSpec through the authorized planning flow")}}
	}
	for _, name := range append(append([]string(nil), input.Manifest.ChangedFiles...), input.Manifest.DeletedFiles...) {
		if !owned(input.AllowedPaths, input.ForbiddenPaths, name) {
			file := ""
			if safePath(name) {
				file = name
			}
			return CheckResult{Status: StatusFail, Findings: []contracts.AuditFinding{deterministicFinding(contracts.FindingHigh, "OWNERSHIP", "path-ownership", file, "module-owned-path-boundary", "unowned-path", "all changed paths are owned and not forbidden", "submission changes a path outside its ownership", "move the change into an owned module or revise ownership through the approved plan")}}
		}
	}
	return CheckResult{Status: StatusPass, Result: []byte("ownership-pass")}
}

type outputCheck struct{}

func (outputCheck) ID() string { return "evidence-bounds" }
func (outputCheck) Run(_ context.Context, input DeterministicInput) CheckResult {
	if len(input.Manifest.ChangedFiles) > 4096 || len(input.Manifest.LocalTestEvidenceRefs) > 256 {
		return CheckResult{Status: StatusFail, Findings: []contracts.AuditFinding{deterministicFinding(contracts.FindingMedium, "EVIDENCE", "evidence-bounds", "", "submission-evidence-cardinality", "cardinality-limit-exceeded", "submission evidence remains within configured cardinality limits", "evidence cardinality exceeds bounds", "split the submission or reduce redundant evidence without removing required evidence")}}
	}
	return CheckResult{Status: StatusPass, Result: []byte("bounds-pass")}
}

func validateInput(input DeterministicInput) error {
	if strings.TrimSpace(input.TenantID) == "" || input.Manifest.Validate() != nil || input.ModuleSpecRef.Validate() != nil || input.Manifest.ModuleSpecRef != input.ModuleSpecRef || !digestPattern.MatchString(input.PolicyDigest) || !contractsPlatformIsolation(input.Platform, input.Isolation) || input.SandboxAttestation == "" || !validRequiredCriteria(input.RequiredCriteria) {
		return ErrInvalidInput
	}
	if input.ModuleSpec != nil && (input.ModuleSpec.Validate() != nil || input.ModuleSpec.ModuleSpecVersion != input.ModuleSpecRef.Version || input.ModuleSpec.SHA256 != input.ModuleSpecRef.SHA256 || !slices.Equal(input.ModuleSpec.AcceptanceCriteria, input.RequiredCriteria) || !slices.Equal(input.ModuleSpec.TestRequirements, input.TestRequirements)) {
		return ErrInvalidInput
	}
	return nil
}

func validateBlindInput(input BlindAuditInput) error {
	if input.ProjectID == "" || input.TaskID == "" || input.Attempt < 1 || input.Attempt > 3 || input.ModuleSpecRef.Validate() != nil || !commitID(input.BaseCommit) || !commitID(input.SubmissionCommit) || input.BaseCommit == input.SubmissionCommit || len(input.ChangedFiles) > 4096 || !validRequiredCriteria(input.RequiredCriteria) {
		return ErrBlindContext
	}
	if input.ModuleSpec != nil && (input.ModuleSpec.Validate() != nil || input.ModuleSpec.ModuleSpecVersion != input.ModuleSpecRef.Version || input.ModuleSpec.SHA256 != input.ModuleSpecRef.SHA256 || !slices.Equal(input.ModuleSpec.AcceptanceCriteria, input.RequiredCriteria) || !slices.Equal(input.ModuleSpec.TestRequirements, input.TestRequirements)) {
		return ErrBlindContext
	}
	for _, name := range input.ChangedFiles {
		if !safePath(name) {
			return ErrBlindContext
		}
	}
	return nil
}

func validateLLMResult(result LLMAuditResult, requiredCriteria []string, attempt int) error {
	if result.AuditorRunID == "" || result.ModelIdentity == "" || !digestPattern.MatchString(result.PromptDigest) || !digestPattern.MatchString(result.ContextDigest) || (result.Verdict != "PASS" && result.Verdict != "FAIL" && result.Verdict != "INCONCLUSIVE") || attempt < 1 || result.Findings == nil || result.CriteriaResults == nil || result.ResidualRisks == nil || math.IsNaN(result.Confidence) || math.IsInf(result.Confidence, 0) || result.Confidence < 0 || result.Confidence > 1 {
		return ErrInvalidInput
	}
	if !criteriaMatch(requiredCriteria, result.CriteriaResults) {
		return ErrInvalidInput
	}
	return nil
}

func contractsPlatformIsolation(platform contracts.ExecutionPlatform, isolation contracts.IsolationLevel) bool {
	return (platform == contracts.PlatformLinux && isolation == contracts.IsolationContainer) || (platform == contracts.PlatformWindows && isolation == contracts.IsolationNone)
}

func owned(allowed, forbidden []string, name string) bool {
	if !safePath(name) {
		return false
	}
	for _, item := range forbidden {
		if pathMatch(item, name) {
			return false
		}
	}
	for _, item := range allowed {
		if pathMatch(item, name) {
			return true
		}
	}
	return false
}

func pathMatch(pattern, name string) bool {
	clean := path.Clean(strings.ReplaceAll(pattern, "\\", "/"))
	if clean == name || strings.HasSuffix(clean, "/...") && (name == strings.TrimSuffix(clean, "/...") || strings.HasPrefix(name, strings.TrimSuffix(clean, "/...")+"/")) {
		return true
	}
	if strings.ContainsAny(clean, "*?[") {
		matched, _ := path.Match(clean, name)
		return matched
	}
	return strings.HasPrefix(name, clean+"/")
}

func safePath(value string) bool {
	clean := path.Clean(strings.ReplaceAll(value, "\\", "/"))
	return value != "" && clean == value && clean != "." && !strings.HasPrefix(clean, "/") && clean != ".." && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, ".git")
}

func commitID(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func artifactURI(value []byte) string {
	if len(value) == 0 {
		return "artifact://empty"
	}
	return "artifact://sha256/" + strings.TrimPrefix(digestBytes(value), "sha256:")
}

type persistedOutputs struct {
	stdout       string
	stderr       string
	result       string
	resultDigest string
	refs         []string
}

func (p *Pipeline) persistCheckOutputs(ctx context.Context, input DeterministicInput, checkID string, result CheckResult) (persistedOutputs, error) {
	if p.artifacts == nil {
		if result.StdoutStream != nil || result.StderrStream != nil || result.ResultStream != nil {
			return persistedOutputs{}, ErrArtifactStore
		}
		return persistedOutputs{stdout: artifactURI(result.Stdout), stderr: artifactURI(result.Stderr), result: artifactURI(result.Result), resultDigest: digestBytes(result.Result)}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	outputs := persistedOutputs{}
	var err error
	outputs.stdout, err = p.persistOutput(ctx, input, checkID, "stdout", result.Stdout, result.StdoutStream)
	if err != nil {
		return persistedOutputs{}, err
	}
	outputs.stderr, err = p.persistOutput(ctx, input, checkID, "stderr", result.Stderr, result.StderrStream)
	if err != nil {
		return persistedOutputs{}, err
	}
	outputs.result, err = p.persistOutput(ctx, input, checkID, "result", result.Result, result.ResultStream)
	if err != nil {
		return persistedOutputs{}, err
	}
	outputs.resultDigest = strings.TrimPrefix(outputs.result, "artifact://sha256/")
	if len(outputs.resultDigest) == 64 {
		outputs.resultDigest = "sha256:" + outputs.resultDigest
	} else {
		return persistedOutputs{}, artifact.ErrIntegrity
	}
	outputs.refs = appendUnique(outputs.refs, outputs.stdout, outputs.stderr, outputs.result)
	return outputs, nil
}

func (p *Pipeline) persistOutput(ctx context.Context, input DeterministicInput, checkID, kind string, value []byte, stream *StreamOutput) (string, error) {
	if stream != nil && len(value) > 0 {
		return "", ErrInvalidInput
	}
	mediaType := "application/octet-stream"
	if kind == "stdout" || kind == "stderr" {
		mediaType = "text/plain; charset=utf-8"
	}
	var produce func(io.Writer) error
	if stream != nil {
		if stream.Write == nil {
			return "", ErrInvalidInput
		}
		if stream.MediaType != "" {
			mediaType = stream.MediaType
		}
		produce = func(destination io.Writer) error {
			return stream.Write(ctx, destination)
		}
	} else {
		contents := append([]byte(nil), value...)
		produce = func(destination io.Writer) error {
			_, err := destination.Write(contents)
			return err
		}
	}
	manifest, err := p.artifacts.Put(ctx, artifact.PutRequest{TenantID: input.TenantID, ProjectID: input.Manifest.ProjectID, TaskID: input.Manifest.ModuleTaskID, ArtifactID: auditArtifactID(input, checkID, kind), MediaType: mediaType, CreatedBy: "aor-audit-service", RetentionPolicy: "audit-evidence", Encrypted: true}, produce)
	if err != nil {
		return "", err
	}
	if !digestPattern.MatchString(manifest.SHA256) || manifest.URI != "artifact://sha256/"+strings.TrimPrefix(manifest.SHA256, "sha256:") || manifest.Size < 0 {
		return "", artifact.ErrIntegrity
	}
	return manifest.URI, nil
}

func auditArtifactID(input DeterministicInput, checkID, kind string) string {
	seed := input.Manifest.ProjectID + "\x00" + input.Manifest.ModuleTaskID + "\x00" + input.Manifest.AttemptSeriesID + "\x00" + strconv.Itoa(input.Manifest.Attempt) + "\x00" + checkID + "\x00" + kind
	digest := sha256.Sum256([]byte(seed))
	return "audit-" + hex.EncodeToString(digest[:])
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func safeCheckID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
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

func cloneDeterministicInput(input DeterministicInput) DeterministicInput {
	input.Manifest.ChangedFiles = append([]string(nil), input.Manifest.ChangedFiles...)
	input.Manifest.DeletedFiles = append([]string(nil), input.Manifest.DeletedFiles...)
	input.AllowedPaths = append([]string(nil), input.AllowedPaths...)
	input.ForbiddenPaths = append([]string(nil), input.ForbiddenPaths...)
	input.RequiredCriteria = append([]string(nil), input.RequiredCriteria...)
	input.TestRequirements = append([]string(nil), input.TestRequirements...)
	input.ModuleSpec = cloneOptionalModuleSpec(input.ModuleSpec)
	return input
}

func cloneOptionalModuleSpec(module *contracts.ModuleSpec) *contracts.ModuleSpec {
	if module == nil {
		return nil
	}
	return cloneModuleSpec(*module)
}

func CheckOrder(checks []Check) []string {
	result := make([]string, 0, len(checks))
	for _, check := range checks {
		result = append(result, check.ID())
	}
	return result
}

func SortedFindings(findings []contracts.AuditFinding) []contracts.AuditFinding {
	result := cloneFindings(findings)
	sort.Slice(result, func(left, right int) bool {
		return result[left].StableFingerprint < result[right].StableFingerprint
	})
	return result
}

func deterministicFinding(severity contracts.FindingSeverity, category, ruleID, file, semanticLocation, evidencePattern, expected, observed, remediation string) contracts.AuditFinding {
	return contracts.AuditFinding{Severity: severity, Category: category, RuleID: ruleID, File: file, Status: contracts.FindingOpen, SemanticLocation: semanticLocation, EvidencePattern: evidencePattern, EvidenceRefs: []string{}, ExpectedBehavior: expected, ObservedBehavior: observed, RemediationConstraint: remediation}
}

func canonicalFindings(findings []contracts.AuditFinding) ([]contracts.AuditFinding, error) {
	result := make([]contracts.AuditFinding, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for index, finding := range findings {
		canonical, err := contracts.CanonicalAuditFinding(finding)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[canonical.StableFingerprint]; exists {
			return nil, ErrInvalidInput
		}
		seen[canonical.StableFingerprint] = struct{}{}
		result[index] = canonical
	}
	return SortedFindings(result), nil
}

func canonicalLLMResult(result LLMAuditResult, requiredCriteria []string) (LLMAuditResult, error) {
	var err error
	result.Findings, err = canonicalFindings(result.Findings)
	if err != nil {
		return LLMAuditResult{}, ErrInvalidInput
	}
	result.CriteriaResults = cloneCriteriaResults(result.CriteriaResults)
	sort.Slice(result.CriteriaResults, func(left, right int) bool {
		return result.CriteriaResults[left].CriterionID < result.CriteriaResults[right].CriterionID
	})
	result.ResidualRisks = cloneStrings(result.ResidualRisks)
	sort.Strings(result.ResidualRisks)
	if !criteriaMatch(requiredCriteria, result.CriteriaResults) {
		return LLMAuditResult{}, ErrInvalidInput
	}
	for _, criterion := range result.CriteriaResults {
		if criterion.Validate() != nil {
			return LLMAuditResult{}, ErrInvalidInput
		}
	}
	for _, risk := range result.ResidualRisks {
		if strings.TrimSpace(risk) == "" || strings.TrimSpace(risk) != risk || strings.ContainsRune(risk, '\x00') {
			return LLMAuditResult{}, ErrInvalidInput
		}
	}
	return result, nil
}

func validRequiredCriteria(criteria []string) bool {
	if len(criteria) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(criteria))
	for _, criterion := range criteria {
		if strings.TrimSpace(criterion) == "" || strings.TrimSpace(criterion) != criterion || strings.ContainsAny(criterion, "\x00\r\n") {
			return false
		}
		if _, exists := seen[criterion]; exists {
			return false
		}
		seen[criterion] = struct{}{}
	}
	return true
}

func criteriaMatch(required []string, results []contracts.CriterionResult) bool {
	if len(required) != len(results) {
		return false
	}
	wanted := make(map[string]struct{}, len(required))
	for _, criterion := range required {
		wanted[criterion] = struct{}{}
	}
	for _, result := range results {
		if _, exists := wanted[result.CriterionID]; !exists {
			return false
		}
		delete(wanted, result.CriterionID)
	}
	return len(wanted) == 0
}
