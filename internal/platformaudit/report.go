package platformaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"time"

	"github.com/akimisaka/aor/internal/audit"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

const pipelineVersion = "1.0.0"

var ErrNotEquivalent = errors.New("platform audit reports are not equivalent")

type Case struct {
	CaseVersion      int                          `json:"caseVersion"`
	TenantID         string                       `json:"tenantId"`
	ModuleSpecRef    contracts.SpecRef            `json:"moduleSpecRef"`
	Manifest         contracts.SubmissionManifest `json:"manifest"`
	AllowedPaths     []string                     `json:"allowedPaths"`
	ForbiddenPaths   []string                     `json:"forbiddenPaths"`
	RequiredCriteria []string                     `json:"requiredCriteria"`
	PolicyDigest     string                       `json:"policyDigest"`
}

type Runner struct {
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
}

type FunctionalCheck struct {
	CheckID      string              `json:"checkId"`
	Ordinal      int                 `json:"ordinal"`
	Type         string              `json:"type"`
	Status       string              `json:"status"`
	Tool         contracts.CheckTool `json:"tool"`
	ResultSHA256 string              `json:"resultSha256"`
}

type FunctionalAudit struct {
	Verdict  string                   `json:"verdict"`
	Checks   []FunctionalCheck        `json:"checks"`
	Findings []contracts.AuditFinding `json:"findings"`
	SHA256   string                   `json:"sha256"`
}

type SecurityProfile struct {
	ExecutionPlatform                   contracts.ExecutionPlatform `json:"executionPlatform"`
	IsolationLevel                      contracts.IsolationLevel    `json:"isolationLevel"`
	UntrustedProductionWorkloadsAllowed bool                        `json:"untrustedProductionWorkloadsAllowed"`
	ComparisonProcessAttested           bool                        `json:"comparisonProcessAttested"`
	Limitations                         []string                    `json:"limitations"`
}

type Report struct {
	ReportVersion    int               `json:"reportVersion"`
	Runner           Runner            `json:"runner"`
	ModuleSpecRef    contracts.SpecRef `json:"moduleSpecRef"`
	SubmissionSHA256 string            `json:"submissionSha256"`
	InputSHA256      string            `json:"inputSha256"`
	PolicyDigest     string            `json:"policyDigest"`
	PipelineVersion  string            `json:"pipelineVersion"`
	FunctionalAudit  FunctionalAudit   `json:"functionalAudit"`
	SecurityProfile  SecurityProfile   `json:"securityProfile"`
}

func GenerateNative(ctx context.Context, testCase Case) (Report, error) {
	return Generate(ctx, testCase, runtime.GOOS, runtime.GOARCH)
}

func Generate(ctx context.Context, testCase Case, goos, goarch string) (Report, error) {
	if err := validateCase(testCase); err != nil {
		return Report{}, err
	}
	profile, attestation, err := securityProfile(goos, goarch)
	if err != nil {
		return Report{}, err
	}
	instant := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	pipeline, err := audit.NewPipeline(nil, nil, comparisonSigner{}, audit.NewMemoryEvidenceStore(), pipelineVersion, func() time.Time { return instant })
	if err != nil {
		return Report{}, err
	}
	result, runErr := pipeline.Run(ctx, audit.DeterministicInput{
		TenantID:           testCase.TenantID,
		Manifest:           testCase.Manifest,
		ModuleSpecRef:      testCase.ModuleSpecRef,
		AllowedPaths:       append([]string(nil), testCase.AllowedPaths...),
		ForbiddenPaths:     append([]string(nil), testCase.ForbiddenPaths...),
		RequiredCriteria:   append([]string(nil), testCase.RequiredCriteria...),
		PolicyDigest:       testCase.PolicyDigest,
		Platform:           profile.ExecutionPlatform,
		Isolation:          profile.IsolationLevel,
		SandboxAttestation: attestation,
	})
	if !errors.Is(runErr, audit.ErrAuditorUnavailable) {
		return Report{}, fmt.Errorf("run deterministic audit: %w", runErr)
	}
	functional := FunctionalAudit{Verdict: "PASS", Findings: append([]contracts.AuditFinding(nil), result.Bundle.Findings...)}
	functional.Checks = make([]FunctionalCheck, len(result.Deterministic))
	for index, check := range result.Deterministic {
		functional.Checks[index] = FunctionalCheck{
			CheckID: check.CheckID, Ordinal: check.Ordinal, Type: check.Type,
			Status: check.Status, Tool: check.Tool, ResultSHA256: check.ResultSHA256,
		}
		if check.Status != string(audit.StatusPass) {
			functional.Verdict = "FAIL"
		}
	}
	functional.SHA256, err = functionalDigest(functional)
	if err != nil {
		return Report{}, err
	}
	inputDigest, err := functionalInputDigest(testCase)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		ReportVersion: 1, Runner: Runner{GOOS: goos, GOARCH: goarch},
		ModuleSpecRef: testCase.ModuleSpecRef, SubmissionSHA256: testCase.Manifest.SHA256,
		InputSHA256: inputDigest, PolicyDigest: testCase.PolicyDigest, PipelineVersion: pipelineVersion,
		FunctionalAudit: functional, SecurityProfile: profile,
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

type comparisonSigner struct{}

func (comparisonSigner) Sign(context.Context, []byte) (*contracts.Signature, error) {
	return nil, errors.New("functional comparison does not sign evidence")
}

func (comparisonSigner) Verify(context.Context, []byte, *contracts.Signature) error {
	return errors.New("functional comparison does not verify evidence")
}

func Compare(linux, windows Report) error {
	if err := linux.Validate(); err != nil {
		return fmt.Errorf("linux report: %w", err)
	}
	if err := windows.Validate(); err != nil {
		return fmt.Errorf("windows report: %w", err)
	}
	if linux.Runner != (Runner{GOOS: "linux", GOARCH: "arm64"}) || windows.Runner != (Runner{GOOS: "windows", GOARCH: "amd64"}) {
		return fmt.Errorf("%w: required native runner pair is linux/arm64 and windows/amd64", ErrNotEquivalent)
	}
	if linux.ModuleSpecRef != windows.ModuleSpecRef || linux.SubmissionSHA256 != windows.SubmissionSHA256 || linux.InputSHA256 != windows.InputSHA256 || linux.PolicyDigest != windows.PolicyDigest || linux.PipelineVersion != windows.PipelineVersion {
		return fmt.Errorf("%w: immutable audit inputs differ", ErrNotEquivalent)
	}
	if !reflect.DeepEqual(linux.FunctionalAudit, windows.FunctionalAudit) {
		return fmt.Errorf("%w: functional audit results differ", ErrNotEquivalent)
	}
	if linux.SecurityProfile.ExecutionPlatform != contracts.PlatformLinux || linux.SecurityProfile.IsolationLevel != contracts.IsolationContainer || !linux.SecurityProfile.UntrustedProductionWorkloadsAllowed {
		return fmt.Errorf("%w: Linux CONTAINER security contract is missing", ErrNotEquivalent)
	}
	if windows.SecurityProfile.ExecutionPlatform != contracts.PlatformWindows || windows.SecurityProfile.IsolationLevel != contracts.IsolationNone || windows.SecurityProfile.UntrustedProductionWorkloadsAllowed {
		return fmt.Errorf("%w: Windows NONE security contract is missing", ErrNotEquivalent)
	}
	if reflect.DeepEqual(linux.SecurityProfile, windows.SecurityProfile) {
		return fmt.Errorf("%w: platform security difference is not explicit", ErrNotEquivalent)
	}
	return nil
}

func (report Report) Validate() error {
	if report.ReportVersion != 1 || report.ModuleSpecRef.Validate() != nil || (contracts.SpecRef{Version: 1, SHA256: report.SubmissionSHA256}).Validate() != nil || (contracts.SpecRef{Version: 1, SHA256: report.InputSHA256}).Validate() != nil || (contracts.SpecRef{Version: 1, SHA256: report.PolicyDigest}).Validate() != nil || report.PipelineVersion != pipelineVersion || len(report.FunctionalAudit.Checks) == 0 || len(report.SecurityProfile.Limitations) == 0 || report.SecurityProfile.ComparisonProcessAttested {
		return errors.New("invalid platform audit report")
	}
	if err := validateFunctionalAudit(report.FunctionalAudit); err != nil {
		return err
	}
	profile, _, err := securityProfile(report.Runner.GOOS, report.Runner.GOARCH)
	if err != nil || !reflect.DeepEqual(profile, report.SecurityProfile) {
		return errors.New("invalid platform security profile")
	}
	digest, err := functionalDigest(report.FunctionalAudit)
	if err != nil || digest != report.FunctionalAudit.SHA256 {
		return errors.New("invalid functional audit digest")
	}
	return nil
}

func validateFunctionalAudit(functional FunctionalAudit) error {
	verdict := "PASS"
	for index, check := range functional.Checks {
		if check.CheckID == "" || check.Ordinal != index+1 || check.Type != "DETERMINISTIC" || check.Tool.Name == "" || check.Tool.Version == "" || (contracts.SpecRef{Version: 1, SHA256: check.Tool.Digest}).Validate() != nil || (contracts.SpecRef{Version: 1, SHA256: check.ResultSHA256}).Validate() != nil {
			return errors.New("invalid functional audit check")
		}
		if check.Status != string(audit.StatusPass) && check.Status != string(audit.StatusFail) && check.Status != string(audit.StatusError) {
			return errors.New("invalid functional audit status")
		}
		if check.Status != string(audit.StatusPass) {
			verdict = "FAIL"
		}
	}
	if functional.Verdict != verdict {
		return errors.New("invalid functional audit verdict")
	}
	return nil
}

func validateCase(testCase Case) error {
	if testCase.CaseVersion != 1 || testCase.TenantID == "" || testCase.ModuleSpecRef.Validate() != nil || testCase.Manifest.Validate() != nil || testCase.Manifest.ModuleSpecRef != testCase.ModuleSpecRef || testCase.PolicyDigest == "" || len(testCase.RequiredCriteria) == 0 {
		return errors.New("invalid platform audit case")
	}
	digest, err := manifestDigest(testCase.Manifest)
	if err != nil || digest != testCase.Manifest.SHA256 {
		return fmt.Errorf("invalid platform audit manifest digest: expected %s", digest)
	}
	return nil
}

func manifestDigest(manifest contracts.SubmissionManifest) (string, error) {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	return canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
}

func functionalInputDigest(testCase Case) (string, error) {
	encoded, err := json.Marshal(testCase)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func functionalDigest(functional FunctionalAudit) (string, error) {
	encoded, err := json.Marshal(struct {
		Verdict  string                   `json:"verdict"`
		Checks   []FunctionalCheck        `json:"checks"`
		Findings []contracts.AuditFinding `json:"findings"`
	}{Verdict: functional.Verdict, Checks: functional.Checks, Findings: functional.Findings})
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func securityProfile(goos, goarch string) (SecurityProfile, string, error) {
	switch {
	case goos == "linux" && goarch == "arm64":
		return SecurityProfile{
			ExecutionPlatform: contracts.PlatformLinux, IsolationLevel: contracts.IsolationContainer,
			UntrustedProductionWorkloadsAllowed: true, ComparisonProcessAttested: false,
			Limitations: []string{"Production execution requires an OCI container; this functional comparison does not attest the CI process sandbox.", "Container isolation shares the host kernel."},
		}, "oci:functional-comparison-not-runtime-attestation", nil
	case goos == "windows" && goarch == "amd64":
		return SecurityProfile{
			ExecutionPlatform: contracts.PlatformWindows, IsolationLevel: contracts.IsolationNone,
			UntrustedProductionWorkloadsAllowed: false, ComparisonProcessAttested: false,
			Limitations: []string{"Windows execution has no isolation and accepts trusted workloads only.", "This functional comparison does not provide a sandbox security attestation."},
		}, "windows:none", nil
	default:
		return SecurityProfile{}, "", fmt.Errorf("unsupported native platform %s/%s", goos, goarch)
	}
}
