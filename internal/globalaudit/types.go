package globalaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	"github.com/google/uuid"
)

const ReportVersion = 1

var (
	ErrInvalidReport = errors.New("invalid global audit report")
	ErrStore         = errors.New("global audit store unavailable")
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionPattern   = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

type FocusArea string

const (
	FocusArchitecture       FocusArea = "CROSS_MODULE_ARCHITECTURE"
	FocusGoalCoverage       FocusArea = "GOAL_COVERAGE"
	FocusSecurityDataFlow   FocusArea = "SECURITY_AND_DATA_FLOW"
	FocusDeliveryOperations FocusArea = "DEPLOYMENT_MIGRATION_ROLLBACK_OPERATIONS"
	FocusTestGaps           FocusArea = "SYSTEM_TEST_GAPS"
	FocusResidualRisk       FocusArea = "RESIDUAL_RISK"
)

var orderedFocusAreas = []FocusArea{
	FocusArchitecture,
	FocusGoalCoverage,
	FocusSecurityDataFlow,
	FocusDeliveryOperations,
	FocusTestGaps,
	FocusResidualRisk,
}

type FocusResult struct {
	Area         FocusArea `json:"area"`
	Status       string    `json:"status"`
	EvidenceRefs []string  `json:"evidenceRefs"`
}

// Decision is the only model-produced part of a global audit report. Identity,
// immutable specification bindings, environment facts and timestamps are added
// by the service from authoritative sources.
type Decision struct {
	Verdict         string                      `json:"verdict"`
	FocusResults    []FocusResult               `json:"focusResults"`
	CriteriaResults []contracts.CriterionResult `json:"criteriaResults"`
	Findings        []contracts.AuditFinding    `json:"findings"`
	ResidualRisks   []string                    `json:"residualRisks"`
	Confidence      float64                     `json:"confidence"`
}

type Report struct {
	ReportVersion         int                         `json:"reportVersion"`
	RunID                 string                      `json:"runId"`
	TenantID              string                      `json:"tenantId"`
	ProjectID             string                      `json:"projectId"`
	GoalSpecRef           contracts.SpecRef           `json:"goalSpecRef"`
	PlanSpecRef           contracts.SpecRef           `json:"planSpecRef"`
	ReleaseCommit         string                      `json:"releaseCommit"`
	PipelineVersion       string                      `json:"pipelineVersion"`
	ExecutionPlatform     contracts.ExecutionPlatform `json:"executionPlatform"`
	IsolationLevel        contracts.IsolationLevel    `json:"isolationLevel"`
	SandboxImageDigest    string                      `json:"sandboxImageDigest"`
	AuditorAgentID        string                      `json:"auditorAgentId"`
	ModelIdentity         string                      `json:"modelIdentity"`
	PromptDigest          string                      `json:"promptDigest"`
	ContextManifestDigest string                      `json:"contextManifestDigest"`
	Verdict               string                      `json:"verdict"`
	FocusResults          []FocusResult               `json:"focusResults"`
	CriteriaResults       []contracts.CriterionResult `json:"criteriaResults"`
	Findings              []contracts.AuditFinding    `json:"findings"`
	ResidualRisks         []string                    `json:"residualRisks"`
	Confidence            float64                     `json:"confidence"`
	StartedAt             time.Time                   `json:"startedAt"`
	CompletedAt           time.Time                   `json:"completedAt"`
	ManifestSHA256        string                      `json:"manifestSha256"`
	Signature             *contracts.Signature        `json:"signature"`
}

type Signer interface {
	Sign(context.Context, []byte) (*contracts.Signature, error)
	Verify(context.Context, []byte, *contracts.Signature) error
}

func Finalize(ctx context.Context, report Report, signer Signer) (Report, error) {
	if ctx == nil || ctx.Err() != nil || signer == nil {
		return Report{}, ErrInvalidReport
	}
	report = canonicalReport(report)
	report.ManifestSHA256 = ""
	report.Signature = nil
	if err := validateReportCore(report, false); err != nil {
		return Report{}, err
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return Report{}, ErrInvalidReport
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(payload, "manifestSha256", "signature")
	if err != nil {
		return Report{}, ErrInvalidReport
	}
	report.ManifestSHA256 = digest
	signaturePayload, err := unsignedReportBytes(report)
	if err != nil {
		return Report{}, err
	}
	report.Signature, err = signer.Sign(ctx, signaturePayload)
	if err != nil || report.Signature == nil {
		return Report{}, ErrInvalidReport
	}
	if err := report.Validate(); err != nil {
		return Report{}, err
	}
	return report, nil
}

func Verify(ctx context.Context, report Report, signer Signer) error {
	if ctx == nil || ctx.Err() != nil || signer == nil {
		return ErrInvalidReport
	}
	if err := report.Validate(); err != nil {
		return err
	}
	payload, err := unsignedReportBytes(report)
	if err != nil || signer.Verify(ctx, payload, report.Signature) != nil {
		return ErrInvalidReport
	}
	return nil
}

func (report Report) Validate() error {
	if err := validateReportCore(report, true); err != nil {
		return err
	}
	payload, err := json.Marshal(report)
	if err != nil {
		return ErrInvalidReport
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(payload, "manifestSha256", "signature")
	if err != nil || digest != report.ManifestSHA256 {
		return ErrInvalidReport
	}
	canonical := canonicalReport(report)
	canonical.ManifestSHA256 = report.ManifestSHA256
	canonical.Signature = cloneSignature(report.Signature)
	if !sameReportEncoding(report, canonical) {
		return ErrInvalidReport
	}
	return nil
}

func (report Report) PassesGate() bool {
	if report.Validate() != nil || report.Verdict != "PASS" {
		return false
	}
	for _, focus := range report.FocusResults {
		if focus.Status != "PASS" {
			return false
		}
	}
	for _, criterion := range report.CriteriaResults {
		if criterion.Status != contracts.CriterionPass || len(criterion.EvidenceRefs) == 0 {
			return false
		}
	}
	for _, finding := range report.Findings {
		if finding.Status == contracts.FindingOpen && (finding.Severity == contracts.FindingHigh || finding.Severity == contracts.FindingCritical) {
			return false
		}
	}
	return true
}

func validateReportCore(report Report, finalized bool) error {
	if report.ReportVersion != ReportVersion || !uuidV7(report.RunID) || !canonicalUUID(report.TenantID) || !canonicalUUID(report.ProjectID) ||
		report.GoalSpecRef.Validate() != nil || report.PlanSpecRef.Validate() != nil || !commitPattern.MatchString(report.ReleaseCommit) ||
		!versionPattern.MatchString(report.PipelineVersion) || report.ExecutionPlatform != contracts.PlatformLinux || report.IsolationLevel != contracts.IsolationContainer ||
		!digestPattern.MatchString(report.SandboxImageDigest) || !safeText(report.AuditorAgentID, 256) || !safeText(report.ModelIdentity, 256) ||
		!digestPattern.MatchString(report.PromptDigest) || !digestPattern.MatchString(report.ContextManifestDigest) || !validVerdict(report.Verdict) ||
		report.StartedAt.IsZero() || report.CompletedAt.IsZero() || report.CompletedAt.Before(report.StartedAt) ||
		math.IsNaN(report.Confidence) || math.IsInf(report.Confidence, 0) || report.Confidence < 0 || report.Confidence > 1 {
		return ErrInvalidReport
	}
	if finalized {
		if !digestPattern.MatchString(report.ManifestSHA256) || !validSignature(report.Signature) {
			return ErrInvalidReport
		}
	} else if report.ManifestSHA256 != "" || report.Signature != nil {
		return ErrInvalidReport
	}
	decision := Decision{
		Verdict: report.Verdict, FocusResults: report.FocusResults, CriteriaResults: report.CriteriaResults,
		Findings: report.Findings, ResidualRisks: report.ResidualRisks, Confidence: report.Confidence,
	}
	return validateDecision(decision)
}

func validateDecision(decision Decision) error {
	if !validVerdict(decision.Verdict) || len(decision.FocusResults) != len(orderedFocusAreas) || len(decision.CriteriaResults) == 0 ||
		decision.Findings == nil || decision.ResidualRisks == nil || math.IsNaN(decision.Confidence) || math.IsInf(decision.Confidence, 0) ||
		decision.Confidence < 0 || decision.Confidence > 1 {
		return ErrInvalidReport
	}
	seenFocus := make(map[FocusArea]struct{}, len(decision.FocusResults))
	for _, focus := range decision.FocusResults {
		if !validFocusArea(focus.Area) || !validVerdict(focus.Status) || len(focus.EvidenceRefs) == 0 || !validEvidenceRefs(focus.EvidenceRefs) {
			return ErrInvalidReport
		}
		if _, exists := seenFocus[focus.Area]; exists {
			return ErrInvalidReport
		}
		seenFocus[focus.Area] = struct{}{}
	}
	seenCriteria := make(map[string]struct{}, len(decision.CriteriaResults))
	for _, criterion := range decision.CriteriaResults {
		if criterion.Validate() != nil || len(criterion.EvidenceRefs) == 0 {
			return ErrInvalidReport
		}
		if _, exists := seenCriteria[criterion.CriterionID]; exists {
			return ErrInvalidReport
		}
		seenCriteria[criterion.CriterionID] = struct{}{}
	}
	seenFindings := make(map[string]struct{}, len(decision.Findings))
	for _, finding := range decision.Findings {
		if finding.Validate() != nil {
			return ErrInvalidReport
		}
		if _, exists := seenFindings[finding.StableFingerprint]; exists {
			return ErrInvalidReport
		}
		seenFindings[finding.StableFingerprint] = struct{}{}
	}
	seenRisks := make(map[string]struct{}, len(decision.ResidualRisks))
	for _, risk := range decision.ResidualRisks {
		if !safeText(risk, 4096) {
			return ErrInvalidReport
		}
		if _, exists := seenRisks[risk]; exists {
			return ErrInvalidReport
		}
		seenRisks[risk] = struct{}{}
	}
	return nil
}

func canonicalReport(report Report) Report {
	report.StartedAt = report.StartedAt.UTC().Truncate(time.Microsecond)
	report.CompletedAt = report.CompletedAt.UTC().Truncate(time.Microsecond)
	report.FocusResults = append([]FocusResult(nil), report.FocusResults...)
	for index := range report.FocusResults {
		report.FocusResults[index].EvidenceRefs = sortedStrings(report.FocusResults[index].EvidenceRefs)
	}
	sort.Slice(report.FocusResults, func(left, right int) bool {
		return focusOrdinal(report.FocusResults[left].Area) < focusOrdinal(report.FocusResults[right].Area)
	})
	report.CriteriaResults = append([]contracts.CriterionResult(nil), report.CriteriaResults...)
	for index := range report.CriteriaResults {
		report.CriteriaResults[index].EvidenceRefs = sortedStrings(report.CriteriaResults[index].EvidenceRefs)
	}
	sort.Slice(report.CriteriaResults, func(left, right int) bool {
		return report.CriteriaResults[left].CriterionID < report.CriteriaResults[right].CriterionID
	})
	report.Findings = append([]contracts.AuditFinding(nil), report.Findings...)
	for index := range report.Findings {
		canonical, err := contracts.CanonicalAuditFinding(report.Findings[index])
		if err == nil {
			canonical.EvidenceRefs = sortedStrings(canonical.EvidenceRefs)
			report.Findings[index] = canonical
		}
	}
	sort.Slice(report.Findings, func(left, right int) bool {
		return report.Findings[left].StableFingerprint < report.Findings[right].StableFingerprint
	})
	report.ResidualRisks = sortedStrings(report.ResidualRisks)
	report.Signature = cloneSignature(report.Signature)
	return report
}

func unsignedReportBytes(report Report) ([]byte, error) {
	report.Signature = nil
	payload, err := json.Marshal(report)
	if err != nil {
		return nil, ErrInvalidReport
	}
	return payload, nil
}

func sameReportEncoding(left, right Report) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}

func cloneSignature(signature *contracts.Signature) *contracts.Signature {
	if signature == nil {
		return nil
	}
	value := *signature
	return &value
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func focusOrdinal(area FocusArea) int {
	for index, candidate := range orderedFocusAreas {
		if area == candidate {
			return index
		}
	}
	return len(orderedFocusAreas)
}

func validFocusArea(area FocusArea) bool {
	return focusOrdinal(area) < len(orderedFocusAreas)
}

func validVerdict(value string) bool {
	return value == "PASS" || value == "FAIL" || value == "INCONCLUSIVE"
}

func validEvidenceRefs(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validEvidenceRef(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validEvidenceRef(value string) bool {
	if !safeText(value, 4096) {
		return false
	}
	if strings.HasPrefix(value, "artifact://sha256/") {
		return len(value) == len("artifact://sha256/")+64 && strings.Trim(value[len("artifact://sha256/"):], "0123456789abcdef") == ""
	}
	return strings.HasPrefix(value, "git://") || strings.HasPrefix(value, "audit://") || strings.HasPrefix(value, "kb://")
}

func validSignature(signature *contracts.Signature) bool {
	return signature != nil && safeText(signature.Type, 128) && safeText(signature.KID, 256) && safeText(signature.JWS, 8192)
}

func safeText(value string, limit int) bool {
	return value != "" && len(value) <= limit && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value && parsed != uuid.Nil
}

func uuidV7(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value && parsed != uuid.Nil && parsed.Version() == 7
}
