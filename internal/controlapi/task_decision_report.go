package controlapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

const decisionReportKeyID = "aor-decision-report-hs256-v1"

type TaskDecisionReportReader interface {
	DecisionReport(context.Context, string, string, string) (contracts.UserDecisionReport, error)
}

type TaskDecisionReportSigner interface {
	Sign(context.Context, []byte) (*contracts.Signature, error)
}

type HMACTaskDecisionReportSigner struct {
	key []byte
}

func NewHMACTaskDecisionReportSigner(key []byte) (*HMACTaskDecisionReportSigner, error) {
	if len(key) < 32 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "decision report signing key"})
	}
	return &HMACTaskDecisionReportSigner{key: append([]byte(nil), key...)}, nil
}

func (signer *HMACTaskDecisionReportSigner) Sign(ctx context.Context, payload []byte) (*contracts.Signature, error) {
	if signer == nil || len(signer.key) < 32 || len(payload) == 0 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "decision report signature"})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	protected := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"` + decisionReportKeyID + `","typ":"JOSE"}`))
	payload64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, signer.key)
	_, _ = mac.Write([]byte(protected + "." + payload64))
	jws := protected + ".." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return &contracts.Signature{Type: "detached-jws", KID: decisionReportKeyID, JWS: jws}, nil
}

func (signer *HMACTaskDecisionReportSigner) Verify(ctx context.Context, payload []byte, signature *contracts.Signature) bool {
	if signer == nil || signature == nil || signature.Type != "detached-jws" || signature.KID != decisionReportKeyID {
		return false
	}
	expected, err := signer.Sign(ctx, payload)
	return err == nil && hmac.Equal([]byte(expected.JWS), []byte(signature.JWS))
}

type PostgresTaskDecisionReportReader struct {
	database *sql.DB
	signer   TaskDecisionReportSigner
}

func NewPostgresTaskDecisionReportReader(database *sql.DB, signer TaskDecisionReportSigner) (*PostgresTaskDecisionReportReader, error) {
	if database == nil || signer == nil {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "decision report reader"})
	}
	return &PostgresTaskDecisionReportReader{database: database, signer: signer}, nil
}

type decisionReportBase struct {
	state             string
	attempt           int
	attemptSeriesID   string
	moduleName        string
	goalVersion       int
	goalSHA256        string
	criticalPathScore int
	currency          string
}

type decisionAttemptEvidence struct {
	summary     contracts.AttemptSummary
	auditID     string
	completedAt time.Time
	findings    []contracts.AuditFinding
}

func (reader *PostgresTaskDecisionReportReader) DecisionReport(ctx context.Context, tenantID, projectID, taskID string) (contracts.UserDecisionReport, error) {
	if reader == nil || reader.database == nil || reader.signer == nil || tenantID == "" || projectID == "" || taskID == "" {
		return contracts.UserDecisionReport{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "decision report reader"})
	}
	tx, err := reader.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return contracts.UserDecisionReport{}, decisionReportDependencyError(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('aor.tenant_id', $1, true)`, tenantID); err != nil {
		return contracts.UserDecisionReport{}, decisionReportDependencyError(err)
	}

	base, err := loadDecisionReportBase(ctx, tx, tenantID, projectID, taskID)
	if err != nil {
		return contracts.UserDecisionReport{}, err
	}
	dependencyImpact, err := loadDecisionDependencyImpact(ctx, tx, tenantID, projectID, taskID, base.criticalPathScore)
	if err != nil {
		return contracts.UserDecisionReport{}, err
	}
	attempts, err := loadDecisionAttempts(ctx, tx, tenantID, projectID, taskID, base.attemptSeriesID)
	if err != nil {
		return contracts.UserDecisionReport{}, err
	}
	inputTokens, outputTokens, costMicros, err := loadDecisionCost(ctx, tx, tenantID, projectID, taskID)
	if err != nil {
		return contracts.UserDecisionReport{}, err
	}
	if err := tx.Commit(); err != nil {
		return contracts.UserDecisionReport{}, decisionReportDependencyError(err)
	}

	report := contracts.UserDecisionReport{
		ReportVersion: "1.0", ProjectID: projectID,
		GoalSpec:     contracts.SpecRef{Version: base.goalVersion, SHA256: base.goalSHA256},
		ModuleTaskID: taskID, ModuleName: base.moduleName,
		State: contracts.TaskBlockedUserDecision, AttemptLimit: 3,
		Attempts:         make([]contracts.AttemptSummary, 0, len(attempts)),
		BlockingFindings: decisionBlockingFindings(attempts), DependencyImpact: dependencyImpact,
		CostSummary:      contracts.DecisionCostSummary{InputTokens: inputTokens, OutputTokens: outputTokens, EstimatedCost: microsDecimal(costMicros), Currency: base.currency},
		AllowedDecisions: []contracts.Decision{contracts.DecisionAuthorizeNewAttemptSeries},
		GeneratedAt:      attempts[len(attempts)-1].completedAt.UTC().Format(time.RFC3339Nano),
	}
	for _, attempt := range attempts {
		report.Attempts = append(report.Attempts, attempt.summary)
	}
	if err := validateTaskDecisionReport(report, projectID, taskID); err != nil {
		return contracts.UserDecisionReport{}, err
	}
	unsigned, err := canonicalDecisionReport(report)
	if err != nil {
		return contracts.UserDecisionReport{}, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, map[string]any{"scope": "decision report encoding"})
	}
	report.Signature, err = reader.signer.Sign(ctx, unsigned)
	if err != nil {
		return contracts.UserDecisionReport{}, decisionReportDependencyError(err)
	}
	if err := validateTaskDecisionReport(report, projectID, taskID); err != nil {
		return contracts.UserDecisionReport{}, err
	}
	return report, nil
}

func loadDecisionReportBase(ctx context.Context, tx *sql.Tx, tenantID, projectID, taskID string) (decisionReportBase, error) {
	var base decisionReportBase
	err := tx.QueryRowContext(ctx, `
SELECT task.state, task.attempt_count, task.active_attempt_series_id::text,
       spec.content_jsonb->>'name', goal.version, goal.content_sha256,
       task.critical_path_score, budget.currency
FROM module_tasks AS task
JOIN module_specs AS spec ON spec.tenant_id = task.tenant_id AND spec.id = task.module_spec_id
JOIN projects AS project ON project.tenant_id = task.tenant_id AND project.id = task.project_id
JOIN goal_specs AS goal ON goal.tenant_id = project.tenant_id AND goal.id = project.active_goal_spec_id
JOIN budget_accounts AS budget ON budget.tenant_id = project.tenant_id
  AND budget.scope_type = 'PROJECT' AND budget.scope_id = project.id::text
WHERE task.tenant_id = $1::uuid AND task.project_id = $2::uuid AND task.id = $3::uuid`, tenantID, projectID, taskID).Scan(
		&base.state, &base.attempt, &base.attemptSeriesID, &base.moduleName, &base.goalVersion,
		&base.goalSHA256, &base.criticalPathScore, &base.currency,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return decisionReportBase{}, aorerrors.New(aorerrors.CodeNotFound, "", nil)
	}
	if err != nil {
		return decisionReportBase{}, decisionReportDependencyError(err)
	}
	goalRef := contracts.SpecRef{Version: base.goalVersion, SHA256: base.goalSHA256}
	if base.state != string(contracts.TaskBlockedUserDecision) || base.attempt != 3 || base.attemptSeriesID == "" || strings.TrimSpace(base.moduleName) == "" || goalRef.Validate() != nil || !validCurrency(base.currency) {
		return decisionReportBase{}, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "decision report state"})
	}
	return base, nil
}

func loadDecisionDependencyImpact(ctx context.Context, tx *sql.Tx, tenantID, projectID, taskID string, taskCriticalPathScore int) (contracts.DecisionDependencyImpact, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT dependent.id::text, dependent.state, dependent.critical_path_score, dependent.blocked_reason
FROM task_dependencies AS dependency
JOIN module_tasks AS dependent ON dependent.tenant_id = dependency.tenant_id AND dependent.id = dependency.task_id
WHERE dependency.tenant_id = $1::uuid AND dependent.project_id = $2::uuid
  AND dependency.depends_on_task_id = $3::uuid
ORDER BY dependent.id`, tenantID, projectID, taskID)
	if err != nil {
		return contracts.DecisionDependencyImpact{}, decisionReportDependencyError(err)
	}
	defer rows.Close()
	impact := contracts.DecisionDependencyImpact{FrozenTaskIDs: []string{}, CriticalPathImpact: taskCriticalPathScore > 0}
	for rows.Next() {
		var dependentID, dependentState string
		var criticalPathScore int
		var blockedReason sql.NullString
		if err := rows.Scan(&dependentID, &dependentState, &criticalPathScore, &blockedReason); err != nil {
			return contracts.DecisionDependencyImpact{}, decisionReportDependencyError(err)
		}
		var blockers []string
		if dependentState != string(contracts.TaskBlockedDependency) || !blockedReason.Valid || json.Unmarshal([]byte(blockedReason.String), &blockers) != nil || !containsDecisionValue(blockers, taskID) {
			return contracts.DecisionDependencyImpact{}, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "frozen dependency evidence"})
		}
		impact.FrozenTaskIDs = append(impact.FrozenTaskIDs, dependentID)
		impact.CriticalPathImpact = impact.CriticalPathImpact || criticalPathScore > 0
	}
	if err := rows.Err(); err != nil {
		return contracts.DecisionDependencyImpact{}, decisionReportDependencyError(err)
	}
	return impact, nil
}

func loadDecisionAttempts(ctx context.Context, tx *sql.Tx, tenantID, projectID, taskID, attemptSeriesID string) ([]decisionAttemptEvidence, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT submission.attempt, submission.head_commit, audit.id::text, audit.phase,
       audit.completed_at, audit.evidence_bundle_ref, evidence.uri
FROM submissions AS submission
JOIN audit_runs AS audit ON audit.tenant_id = submission.tenant_id AND audit.submission_id = submission.id
JOIN artifacts AS evidence ON evidence.tenant_id = submission.tenant_id AND evidence.project_id = submission.project_id
  AND evidence.metadata_jsonb->>'kind' = 'evidence-bundle'
  AND evidence.metadata_jsonb->>'taskId' = submission.module_task_id::text
  AND evidence.metadata_jsonb->>'attemptSeriesId' = submission.attempt_series_id::text
  AND evidence.metadata_jsonb->>'attempt' = submission.attempt::text
  AND evidence.metadata_jsonb->>'manifestSha256' = audit.evidence_bundle_ref
WHERE submission.tenant_id = $1::uuid AND submission.project_id = $2::uuid
  AND submission.module_task_id = $3::uuid AND submission.attempt_series_id = $4::uuid
  AND audit.state = 'COMPLETED' AND audit.verdict IN ('FAIL', 'INCONCLUSIVE')
ORDER BY submission.attempt, audit.completed_at, audit.id`, tenantID, projectID, taskID, attemptSeriesID)
	if err != nil {
		return nil, decisionReportDependencyError(err)
	}
	defer rows.Close()
	attempts := make([]decisionAttemptEvidence, 0, 3)
	for rows.Next() {
		var attempt decisionAttemptEvidence
		var number int
		var phase, evidenceSHA256, evidenceURI string
		if err := rows.Scan(&number, &attempt.summary.SubmissionCommit, &attempt.auditID, &phase, &attempt.completedAt, &evidenceSHA256, &evidenceURI); err != nil {
			return nil, decisionReportDependencyError(err)
		}
		if number < 1 || number > 3 || len(attempts) != number-1 || attempt.completedAt.IsZero() || !validSHA256(evidenceSHA256) || !validArtifactURI(evidenceURI) {
			return nil, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "third-attempt audit sequence"})
		}
		stage, ok := decisionFailureStage(phase)
		if !ok {
			return nil, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "third-attempt audit phase"})
		}
		attempt.summary.Attempt = number
		attempt.summary.FailureStage = stage
		attempt.summary.FindingIDs = []string{}
		attempt.summary.EvidenceURI = evidenceURI
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, decisionReportDependencyError(err)
	}
	if len(attempts) != 3 {
		return nil, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "third-attempt audit sequence"})
	}
	for index := range attempts {
		attempts[index].findings, err = loadDecisionFindings(ctx, tx, tenantID, attempts[index].auditID)
		if err != nil {
			return nil, err
		}
		for _, finding := range attempts[index].findings {
			attempts[index].summary.FindingIDs = append(attempts[index].summary.FindingIDs, finding.FindingID)
		}
		sort.Strings(attempts[index].summary.FindingIDs)
	}
	return attempts, nil
}

func loadDecisionFindings(ctx context.Context, tx *sql.Tx, tenantID, auditID string) ([]contracts.AuditFinding, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT content_jsonb
FROM audit_findings
WHERE tenant_id = $1::uuid AND audit_run_id = $2::uuid
ORDER BY stable_fingerprint`, tenantID, auditID)
	if err != nil {
		return nil, decisionReportDependencyError(err)
	}
	defer rows.Close()
	findings := make([]contracts.AuditFinding, 0)
	for rows.Next() {
		var content []byte
		var finding contracts.AuditFinding
		if err := rows.Scan(&content); err != nil {
			return nil, decisionReportDependencyError(err)
		}
		if json.Unmarshal(content, &finding) != nil || finding.Validate() != nil {
			return nil, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "audit finding integrity"})
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, decisionReportDependencyError(err)
	}
	return findings, nil
}

func loadDecisionCost(ctx context.Context, tx *sql.Tx, tenantID, projectID, taskID string) (int64, int64, int64, error) {
	var inputTokens, outputTokens, costMicros int64
	err := tx.QueryRowContext(ctx, `
SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), COALESCE(SUM(cost_micros), 0)
FROM model_calls
WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND task_id = $3::uuid`, tenantID, projectID, taskID).Scan(&inputTokens, &outputTokens, &costMicros)
	if err != nil {
		return 0, 0, 0, decisionReportDependencyError(err)
	}
	if inputTokens < 0 || outputTokens < 0 || costMicros < 0 {
		return 0, 0, 0, aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": "decision report cost"})
	}
	return inputTokens, outputTokens, costMicros, nil
}

func decisionBlockingFindings(attempts []decisionAttemptEvidence) []contracts.BlockingFinding {
	if len(attempts) != 3 {
		return nil
	}
	firstSeen := make(map[string]int)
	lastSeen := make(map[string]int)
	for _, attempt := range attempts {
		for _, finding := range attempt.findings {
			if _, found := firstSeen[finding.StableFingerprint]; !found {
				firstSeen[finding.StableFingerprint] = attempt.summary.Attempt
			}
			lastSeen[finding.StableFingerprint] = attempt.summary.Attempt
		}
	}
	blocking := make([]contracts.BlockingFinding, 0)
	last := attempts[len(attempts)-1]
	for _, finding := range last.findings {
		if finding.Status != contracts.FindingOpen || finding.Severity != contracts.FindingHigh && finding.Severity != contracts.FindingCritical {
			continue
		}
		location := finding.SemanticLocation
		if finding.File != "" {
			location = finding.File
			if finding.LineStart > 0 {
				location += ":" + strconv.Itoa(finding.LineStart)
				if finding.LineEnd != finding.LineStart {
					location += "-" + strconv.Itoa(finding.LineEnd)
				}
			}
		}
		reproductionURI := last.summary.EvidenceURI
		for _, reference := range finding.EvidenceRefs {
			if validArtifactURI(reference) {
				reproductionURI = reference
				break
			}
		}
		blocking = append(blocking, contracts.BlockingFinding{
			ID: finding.FindingID, Severity: string(finding.Severity), Category: finding.Category,
			Summary: finding.ObservedBehavior, Location: location, ReproductionURI: reproductionURI,
			FirstObservedAttempt: firstSeen[finding.StableFingerprint], LastObservedAttempt: lastSeen[finding.StableFingerprint],
		})
	}
	sort.Slice(blocking, func(left, right int) bool { return blocking[left].ID < blocking[right].ID })
	return blocking
}

func validateTaskDecisionReport(report contracts.UserDecisionReport, projectID, taskID string) error {
	invalid := func(scope string) error {
		return aorerrors.New(aorerrors.CodeAuditEvidenceInvalid, "", map[string]any{"scope": scope})
	}
	if report.ReportVersion != "1.0" || report.ProjectID != projectID || report.ModuleTaskID != taskID || strings.TrimSpace(report.ModuleName) == "" || report.GoalSpec.Validate() != nil || report.State != contracts.TaskBlockedUserDecision || report.AttemptLimit != 3 || len(report.Attempts) != 3 || len(report.BlockingFindings) == 0 {
		return invalid("decision report shape")
	}
	seenFindings := make(map[string]bool)
	for index, attempt := range report.Attempts {
		if attempt.Attempt != index+1 || !validCommit(attempt.SubmissionCommit) || attempt.FailureStage != "DETERMINISTIC_AUDIT" && attempt.FailureStage != "LLM_AUDIT" || attempt.FindingIDs == nil || !validArtifactURI(attempt.EvidenceURI) {
			return invalid("decision report attempt")
		}
		for _, findingID := range attempt.FindingIDs {
			if findingID == "" {
				return invalid("decision report finding identifier")
			}
		}
	}
	for _, finding := range report.BlockingFindings {
		if finding.ID == "" || seenFindings[finding.ID] || finding.Severity != string(contracts.FindingHigh) && finding.Severity != string(contracts.FindingCritical) || strings.TrimSpace(finding.Category) == "" || strings.TrimSpace(finding.Summary) == "" || strings.TrimSpace(finding.Location) == "" || !validArtifactURI(finding.ReproductionURI) || finding.FirstObservedAttempt < 1 || finding.LastObservedAttempt < finding.FirstObservedAttempt || finding.LastObservedAttempt != 3 {
			return invalid("decision report blocking finding")
		}
		seenFindings[finding.ID] = true
	}
	if report.DependencyImpact.FrozenTaskIDs == nil || report.CostSummary.InputTokens < 0 || report.CostSummary.OutputTokens < 0 || !validDecimal(report.CostSummary.EstimatedCost) || !validCurrency(report.CostSummary.Currency) {
		return invalid("decision report impact or cost")
	}
	seenTasks := make(map[string]bool)
	for _, frozenTaskID := range report.DependencyImpact.FrozenTaskIDs {
		if frozenTaskID == "" || seenTasks[frozenTaskID] {
			return invalid("decision report frozen task")
		}
		seenTasks[frozenTaskID] = true
	}
	if len(report.AllowedDecisions) == 0 {
		return invalid("decision report allowed decisions")
	}
	seenDecisions := make(map[contracts.Decision]bool)
	for _, decision := range report.AllowedDecisions {
		if seenDecisions[decision] || !canonicalTaskDecision(decision) {
			return invalid("decision report allowed decision")
		}
		seenDecisions[decision] = true
	}
	if generatedAt, err := time.Parse(time.RFC3339Nano, report.GeneratedAt); err != nil || generatedAt.IsZero() {
		return invalid("decision report generated time")
	}
	if report.Signature != nil && (report.Signature.Type != "detached-jws" && report.Signature.Type != "sigstore-bundle" && report.Signature.Type != "kms-signature" || report.Signature.KID == "" || len(report.Signature.KID) > 256 || len(report.Signature.JWS) < 16 || len(report.Signature.JWS) > 16384) {
		return invalid("decision report signature")
	}
	return nil
}

func canonicalDecisionReport(report contracts.UserDecisionReport) ([]byte, error) {
	report.Signature = nil
	encoded, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func decisionReportDigest(report contracts.UserDecisionReport) (string, error) {
	encoded, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func decisionFailureStage(phase string) (string, bool) {
	switch phase {
	case "DETERMINISTIC":
		return "DETERMINISTIC_AUDIT", true
	case "LLM":
		return "LLM_AUDIT", true
	default:
		return "", false
	}
}

func canonicalTaskDecision(decision contracts.Decision) bool {
	switch decision {
	case contracts.DecisionAbortProject, contracts.DecisionAbortModule, contracts.DecisionReviseGoal,
		contracts.DecisionReviseModuleSpec, contracts.DecisionHandOffToHuman, contracts.DecisionAuthorizeNewAttemptSeries:
		return true
	default:
		return false
	}
}

func validSHA256(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 20
}

func validArtifactURI(value string) bool {
	return len(value) == len("artifact://sha256/")+64 && strings.HasPrefix(value, "artifact://sha256/") && validSHA256("sha256:"+strings.TrimPrefix(value, "artifact://sha256/"))
}

func validDecimal(value string) bool {
	if value == "" {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || parts[0] == "" || len(parts) == 2 && (len(parts[1]) < 1 || len(parts[1]) > 6) {
		return false
	}
	for _, part := range parts {
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func microsDecimal(value int64) string {
	whole := strconv.FormatInt(value/1_000_000, 10)
	remainder := value % 1_000_000
	if remainder == 0 {
		return whole
	}
	fraction := strconv.FormatInt(remainder, 10)
	fraction = strings.Repeat("0", 6-len(fraction)) + fraction
	return whole + "." + strings.TrimRight(fraction, "0")
}

func containsDecisionValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func decisionReportDependencyError(err error) error {
	var typed *aorerrors.Error
	if errors.As(err, &typed) {
		return err
	}
	return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, map[string]any{"scope": "decision report"})
}
