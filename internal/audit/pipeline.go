package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func NewPipeline(checks []Check, auditors AuditorFactory, signer Signer, store EvidenceStore, version string, clock func() time.Time) (*Pipeline, error) {
	if signer == nil || store == nil || strings.TrimSpace(version) == "" {
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
	return &Pipeline{checks: append([]Check(nil), checks...), auditors: auditors, signer: signer, store: store, clock: clock, version: version}, nil
}

func (p *Pipeline) Run(ctx context.Context, input DeterministicInput) (AuditResult, error) {
	if err := contextErr(ctx); err != nil {
		return AuditResult{}, err
	}
	if err := validateInput(input); err != nil {
		return AuditResult{}, err
	}
	checks := make([]contracts.EvidenceCheck, 0, len(p.checks))
	findings := []string{}
	for ordinal, check := range p.checks {
		started := p.clock().UTC()
		result := check.Run(ctx, cloneDeterministicInput(input))
		ended := p.clock().UTC()
		status := string(result.Status)
		if result.Status == "" {
			status = string(StatusError)
		}
		if result.Status != StatusPass {
			findings = append(findings, result.Findings...)
		}
		resultDigest := digestBytes(result.Result)
		checks = append(checks, contracts.EvidenceCheck{CheckID: check.ID(), Ordinal: ordinal + 1, Type: "DETERMINISTIC", Status: status, Tool: contracts.CheckTool{Name: "aor-audit", Version: p.version, Digest: digestBytes([]byte(p.version))}, StartedAt: started.Format(time.RFC3339), CompletedAt: ended.Format(time.RFC3339), StdoutURI: artifactURI(result.Stdout), StderrURI: artifactURI(result.Stderr), ResultURI: artifactURI(result.Result), ResultSHA256: resultDigest})
	}
	bundle := contracts.EvidenceBundle{EvidenceBundleVersion: 1, ProjectID: input.Manifest.ProjectID, TaskID: input.Manifest.ModuleTaskID, AttemptSeriesID: input.Manifest.AttemptSeriesID, Attempt: input.Manifest.Attempt, SpecVersion: input.ModuleSpecRef.Version, BaseCommit: input.Manifest.BaseCommit, SubmissionCommit: input.Manifest.HeadCommit, PipelineVersion: p.version, PolicyBundleDigest: input.PolicyDigest, ExecutionPlatform: input.Platform, IsolationLevel: input.Isolation, SandboxAttestation: input.SandboxAttestation, Checks: checks, Findings: append([]string(nil), findings...), Artifacts: []string{}, LLMAudit: contracts.LLMAudit{Verdict: "NOT_RUN"}}
	if len(findings) == 0 {
		blind := BlindAuditInput{ProjectID: input.Manifest.ProjectID, TaskID: input.Manifest.ModuleTaskID, Attempt: input.Manifest.Attempt, ModuleSpecRef: input.ModuleSpecRef, BaseCommit: input.Manifest.BaseCommit, SubmissionCommit: input.Manifest.HeadCommit, ChangedFiles: append([]string(nil), input.Manifest.ChangedFiles...), DeterministicChecks: append([]contracts.EvidenceCheck(nil), checks...)}
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
		if err := validateLLMResult(llm, input.Manifest.Attempt); err != nil {
			return AuditResult{}, err
		}
		bundle.LLMAudit = contracts.LLMAudit{AuditorRunID: llm.AuditorRunID, ModelIdentity: llm.ModelIdentity, PromptDigest: llm.PromptDigest, ContextManifestDigest: llm.ContextDigest, Verdict: llm.Verdict}
		findings = append(findings, llm.Findings...)
		bundle.Findings = append([]string(nil), findings...)
		result := AuditResult{Bundle: bundle, Deterministic: checks, LLM: &llm, Verdict: llm.Verdict}
		if err := p.finalize(ctx, &result.Bundle); err != nil {
			return AuditResult{}, err
		}
		if err := p.store.Put(ctx, result.Bundle); err != nil {
			return AuditResult{}, err
		}
		if llm.Verdict != "PASS" {
			return result, ErrDeterministicGate
		}
		return result, nil
	}
	result := AuditResult{Bundle: bundle, Deterministic: checks, Verdict: "FAIL"}
	if err := p.finalize(ctx, &result.Bundle); err != nil {
		return AuditResult{}, err
	}
	if err := p.store.Put(ctx, result.Bundle); err != nil {
		return AuditResult{}, err
	}
	return result, ErrDeterministicGate
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
		return CheckResult{Status: StatusFail, Findings: []string{"submission manifest or immutable ModuleSpec reference is invalid"}}
	}
	return CheckResult{Status: StatusPass, Result: []byte("schema-pass")}
}

type commitCheck struct{}

func (commitCheck) ID() string { return "commit-integrity" }
func (commitCheck) Run(_ context.Context, input DeterministicInput) CheckResult {
	if input.Manifest.BaseCommit == input.Manifest.HeadCommit || !commitID(input.Manifest.BaseCommit) || !commitID(input.Manifest.HeadCommit) {
		return CheckResult{Status: StatusFail, Findings: []string{"submission commit is not immutable"}}
	}
	return CheckResult{Status: StatusPass, Result: []byte(input.Manifest.BaseCommit + ".." + input.Manifest.HeadCommit)}
}

type pathCheck struct{}

func (pathCheck) ID() string { return "path-ownership" }
func (pathCheck) Run(_ context.Context, input DeterministicInput) CheckResult {
	if len(input.AllowedPaths) == 0 {
		return CheckResult{Status: StatusFail, Findings: []string{"ModuleSpec has no owned paths"}}
	}
	for _, name := range append(append([]string(nil), input.Manifest.ChangedFiles...), input.Manifest.DeletedFiles...) {
		if !owned(input.AllowedPaths, input.ForbiddenPaths, name) {
			return CheckResult{Status: StatusFail, Findings: []string{"unowned changed path: " + name}}
		}
	}
	return CheckResult{Status: StatusPass, Result: []byte("ownership-pass")}
}

type outputCheck struct{}

func (outputCheck) ID() string { return "evidence-bounds" }
func (outputCheck) Run(_ context.Context, input DeterministicInput) CheckResult {
	if len(input.Manifest.ChangedFiles) > 4096 || len(input.Manifest.LocalTestEvidenceRefs) > 256 {
		return CheckResult{Status: StatusFail, Findings: []string{"evidence cardinality exceeds bounds"}}
	}
	return CheckResult{Status: StatusPass, Result: []byte("bounds-pass")}
}

func validateInput(input DeterministicInput) error {
	if input.Manifest.Validate() != nil || input.ModuleSpecRef.Validate() != nil || input.Manifest.ModuleSpecRef != input.ModuleSpecRef || !digestPattern.MatchString(input.PolicyDigest) || !contractsPlatformIsolation(input.Platform, input.Isolation) || input.SandboxAttestation == "" {
		return ErrInvalidInput
	}
	return nil
}

func validateBlindInput(input BlindAuditInput) error {
	if input.ProjectID == "" || input.TaskID == "" || input.Attempt < 1 || input.Attempt > 3 || input.ModuleSpecRef.Validate() != nil || !commitID(input.BaseCommit) || !commitID(input.SubmissionCommit) || input.BaseCommit == input.SubmissionCommit || len(input.ChangedFiles) > 4096 {
		return ErrBlindContext
	}
	for _, name := range input.ChangedFiles {
		if !safePath(name) {
			return ErrBlindContext
		}
	}
	return nil
}

func validateLLMResult(result LLMAuditResult, attempt int) error {
	if result.AuditorRunID == "" || result.ModelIdentity == "" || !digestPattern.MatchString(result.PromptDigest) || !digestPattern.MatchString(result.ContextDigest) || (result.Verdict != "PASS" && result.Verdict != "FAIL" && result.Verdict != "INCONCLUSIVE") || attempt < 1 {
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
	return input
}

func CheckOrder(checks []Check) []string {
	result := make([]string, 0, len(checks))
	for _, check := range checks {
		result = append(result, check.ID())
	}
	return result
}

func SortedFindings(findings []string) []string {
	result := append([]string(nil), findings...)
	sort.Strings(result)
	return result
}
