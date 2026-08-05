package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"path"
	"strings"
	"time"
)

type FindingSeverity string

const (
	FindingInfo     FindingSeverity = "INFO"
	FindingLow      FindingSeverity = "LOW"
	FindingMedium   FindingSeverity = "MEDIUM"
	FindingHigh     FindingSeverity = "HIGH"
	FindingCritical FindingSeverity = "CRITICAL"
)

type FindingStatus string

const (
	FindingOpen          FindingStatus = "OPEN"
	FindingFixed         FindingStatus = "FIXED"
	FindingAccepted      FindingStatus = "ACCEPTED"
	FindingFalsePositive FindingStatus = "FALSE_POSITIVE"
)

type CriterionStatus string

const (
	CriterionPass      CriterionStatus = "PASS"
	CriterionFail      CriterionStatus = "FAIL"
	CriterionNotTested CriterionStatus = "NOT_TESTED"
)

type AuditFinding struct {
	FindingID             string          `json:"findingId"`
	StableFingerprint     string          `json:"stableFingerprint"`
	Severity              FindingSeverity `json:"severity"`
	Category              string          `json:"category"`
	RuleID                string          `json:"ruleId"`
	File                  string          `json:"file"`
	LineStart             int             `json:"lineStart"`
	LineEnd               int             `json:"lineEnd"`
	Status                FindingStatus   `json:"status"`
	SemanticLocation      string          `json:"semanticLocation"`
	EvidencePattern       string          `json:"evidencePattern"`
	EvidenceRefs          []string        `json:"evidenceRefs"`
	ExpectedBehavior      string          `json:"expectedBehavior"`
	ObservedBehavior      string          `json:"observedBehavior"`
	RemediationConstraint string          `json:"remediationConstraint"`
}

type CriterionResult struct {
	CriterionID  string          `json:"criterionId"`
	Status       CriterionStatus `json:"status"`
	EvidenceRefs []string        `json:"evidenceRefs"`
}

// AuditFindingFingerprint is independent of line numbers so a moved finding
// remains the same finding across audit attempts.
func AuditFindingFingerprint(ruleID, file, semanticLocation, evidencePattern string) (string, error) {
	if !validAuditSingleLine(ruleID) || !validAuditSingleLine(semanticLocation) || !validAuditSingleLine(evidencePattern) {
		return "", fmt.Errorf("finding fingerprint components are required")
	}
	normalizedPath, err := normalizeAuditPath(file)
	if err != nil {
		return "", err
	}
	value := strings.Join([]string{ruleID, normalizedPath, semanticLocation, evidencePattern}, "\x00")
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// CanonicalAuditFinding normalizes a producer result and derives the only
// accepted stable fingerprint and finding ID.
func CanonicalAuditFinding(finding AuditFinding) (AuditFinding, error) {
	if !validFindingSeverity(finding.Severity) || !validFindingStatus(finding.Status) ||
		!validAuditSingleLine(finding.Category) || !validAuditSingleLine(finding.RuleID) ||
		!validAuditSingleLine(finding.SemanticLocation) || !validAuditSingleLine(finding.EvidencePattern) ||
		!validAuditNarrative(finding.ExpectedBehavior) || !validAuditNarrative(finding.ObservedBehavior) ||
		!validAuditNarrative(finding.RemediationConstraint) {
		return AuditFinding{}, fmt.Errorf("finding fields are invalid")
	}
	normalizedPath, err := normalizeAuditPath(finding.File)
	if err != nil {
		return AuditFinding{}, err
	}
	if normalizedPath == "" {
		if finding.LineStart != 0 || finding.LineEnd != 0 {
			return AuditFinding{}, fmt.Errorf("finding lines require a file")
		}
	} else if finding.LineStart < 0 || finding.LineEnd < 0 ||
		(finding.LineStart == 0) != (finding.LineEnd == 0) ||
		(finding.LineStart > 0 && finding.LineEnd < finding.LineStart) {
		return AuditFinding{}, fmt.Errorf("finding line range is invalid")
	}
	if err := validateAuditRefs(finding.EvidenceRefs); err != nil {
		return AuditFinding{}, err
	}
	fingerprint, err := AuditFindingFingerprint(finding.RuleID, normalizedPath, finding.SemanticLocation, finding.EvidencePattern)
	if err != nil {
		return AuditFinding{}, err
	}
	findingID := "FND-" + strings.TrimPrefix(fingerprint, "sha256:")
	finding.File = normalizedPath
	finding.StableFingerprint = fingerprint
	finding.FindingID = findingID
	if finding.EvidenceRefs == nil {
		finding.EvidenceRefs = []string{}
	}
	return finding, nil
}

func (finding AuditFinding) Validate() error {
	canonical, err := CanonicalAuditFinding(finding)
	if err != nil {
		return err
	}
	if finding.FindingID != canonical.FindingID || finding.StableFingerprint != canonical.StableFingerprint ||
		finding.File != canonical.File || finding.EvidenceRefs == nil {
		return fmt.Errorf("finding is not canonical")
	}
	return nil
}

func (criterion CriterionResult) Validate() error {
	if !validAuditSingleLine(criterion.CriterionID) || !validCriterionStatus(criterion.Status) || criterion.EvidenceRefs == nil {
		return fmt.Errorf("criterion result is invalid")
	}
	return validateAuditRefs(criterion.EvidenceRefs)
}

// PassesAuditGate implements the signed-evidence part of SPEC 22.6. Current
// version and authorization checks remain the integration gate's responsibility.
func (bundle EvidenceBundle) PassesAuditGate() bool {
	if validateAuditResults(bundle) != nil || bundle.LLMAudit.Verdict != "PASS" {
		return false
	}
	for _, check := range bundle.Checks {
		if check.Status != "PASS" {
			return false
		}
	}
	for _, finding := range bundle.Findings {
		if finding.Status == FindingOpen && (finding.Severity == FindingHigh || finding.Severity == FindingCritical) {
			return false
		}
	}
	for _, criterion := range bundle.CriteriaResults {
		if criterion.Status != CriterionPass {
			return false
		}
	}
	return true
}

func validateAuditResults(bundle EvidenceBundle) error {
	if len(bundle.Checks) == 0 || bundle.Findings == nil || bundle.CriteriaResults == nil || bundle.ResidualRisks == nil || bundle.Artifacts == nil ||
		math.IsNaN(bundle.Confidence) || math.IsInf(bundle.Confidence, 0) || bundle.Confidence < 0 || bundle.Confidence > 1 {
		return fmt.Errorf("evidence audit result is incomplete")
	}
	allChecksPass := true
	for index, check := range bundle.Checks {
		if check.CheckID == "" || check.Ordinal != index+1 || check.Type == "" ||
			(check.Status != "PASS" && check.Status != "FAIL" && check.Status != "ERROR" && check.Status != "SKIPPED") ||
			check.Tool.Name == "" || check.Tool.Version == "" || validateDigest(check.Tool.Digest) != nil ||
			validateEvidenceTimeRange(check.StartedAt, check.CompletedAt) != nil ||
			!validArtifactRef(check.StdoutURI) || !validArtifactRef(check.StderrURI) || !validArtifactRef(check.ResultURI) ||
			validateDigest(check.ResultSHA256) != nil {
			return fmt.Errorf("evidence check %d is invalid", index+1)
		}
		if check.Status != "PASS" {
			allChecksPass = false
		}
	}
	seenFindings := make(map[string]struct{}, len(bundle.Findings))
	for _, finding := range bundle.Findings {
		if err := finding.Validate(); err != nil {
			return err
		}
		if _, exists := seenFindings[finding.StableFingerprint]; exists {
			return fmt.Errorf("duplicate finding stable fingerprint")
		}
		seenFindings[finding.StableFingerprint] = struct{}{}
	}
	seenCriteria := make(map[string]struct{}, len(bundle.CriteriaResults))
	for _, criterion := range bundle.CriteriaResults {
		if err := criterion.Validate(); err != nil {
			return err
		}
		if _, exists := seenCriteria[criterion.CriterionID]; exists {
			return fmt.Errorf("duplicate criterion result")
		}
		seenCriteria[criterion.CriterionID] = struct{}{}
	}
	for _, risk := range bundle.ResidualRisks {
		if !validAuditNarrative(risk) {
			return fmt.Errorf("residual risk is invalid")
		}
	}
	seenArtifacts := make(map[string]struct{}, len(bundle.Artifacts))
	for _, artifactRef := range bundle.Artifacts {
		if !validArtifactRef(artifactRef) {
			return fmt.Errorf("artifact reference is invalid")
		}
		if _, exists := seenArtifacts[artifactRef]; exists {
			return fmt.Errorf("duplicate artifact reference")
		}
		seenArtifacts[artifactRef] = struct{}{}
	}
	switch bundle.LLMAudit.Verdict {
	case "PASS", "FAIL", "INCONCLUSIVE":
		if len(bundle.CriteriaResults) == 0 || !validAuditSingleLine(bundle.LLMAudit.AuditorRunID) || !validAuditSingleLine(bundle.LLMAudit.ModelIdentity) ||
			validateDigest(bundle.LLMAudit.PromptDigest) != nil || validateDigest(bundle.LLMAudit.ContextManifestDigest) != nil {
			return fmt.Errorf("LLM audit identity is invalid")
		}
	case "NOT_RUN":
		if allChecksPass || len(bundle.Findings) == 0 || bundle.LLMAudit.AuditorRunID != "" || bundle.LLMAudit.ModelIdentity != "" ||
			bundle.LLMAudit.PromptDigest != "" || bundle.LLMAudit.ContextManifestDigest != "" ||
			len(bundle.CriteriaResults) != 0 || bundle.Confidence != 0 {
			return fmt.Errorf("NOT_RUN LLM audit is inconsistent")
		}
	default:
		return fmt.Errorf("LLM audit verdict is invalid")
	}
	return nil
}

func normalizeAuditPath(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	clean := path.Clean(normalized)
	if clean != normalized || clean == "." || strings.HasPrefix(clean, "/") || clean == ".." ||
		strings.HasPrefix(clean, "../") || clean == ".git" || strings.HasPrefix(clean, ".git/") {
		return "", fmt.Errorf("finding file path is invalid")
	}
	return clean, nil
}

func validFindingSeverity(value FindingSeverity) bool {
	switch value {
	case FindingInfo, FindingLow, FindingMedium, FindingHigh, FindingCritical:
		return true
	default:
		return false
	}
}

func validFindingStatus(value FindingStatus) bool {
	switch value {
	case FindingOpen, FindingFixed, FindingAccepted, FindingFalsePositive:
		return true
	default:
		return false
	}
}

func validCriterionStatus(value CriterionStatus) bool {
	return value == CriterionPass || value == CriterionFail || value == CriterionNotTested
}

func validAuditSingleLine(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validAuditNarrative(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func validateAuditRefs(values []string) error {
	for _, value := range values {
		if !validAuditSingleLine(value) {
			return fmt.Errorf("audit evidence reference is invalid")
		}
	}
	return nil
}

func validArtifactRef(value string) bool {
	return len(value) > len("artifact://") && strings.HasPrefix(value, "artifact://") && validAuditSingleLine(value)
}

func validateEvidenceTimeRange(startedAt, completedAt string) error {
	started, err := time.Parse(time.RFC3339, startedAt)
	if err != nil {
		return err
	}
	completed, err := time.Parse(time.RFC3339, completedAt)
	if err != nil || completed.Before(started) {
		return fmt.Errorf("evidence check time range is invalid")
	}
	return nil
}
