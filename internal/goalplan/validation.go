package goalplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

func decodeStrict(input []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateGoalContent(content contracts.GoalContent) error {
	if content.GoalSpecVersion != 2 || content.ProjectID == "" || content.Version < 1 || strings.TrimSpace(content.Title) == "" || strings.TrimSpace(content.Summary) == "" || strings.TrimSpace(content.ProblemStatement) == "" {
		return ErrAgentOutput
	}
	if content.BusinessOutcomes == nil || content.Scope.Included == nil || content.Scope.Excluded == nil || content.UserPersonas == nil || content.FunctionalRequirements == nil || content.NonFunctionalRequirements.Security == nil || content.NonFunctionalRequirements.Privacy == nil || content.NonFunctionalRequirements.Performance == nil || content.NonFunctionalRequirements.Reliability == nil || content.NonFunctionalRequirements.Operability == nil || content.Constraints == nil || content.Assumptions == nil || content.Decisions == nil || content.UnresolvedItems == nil || content.AcceptanceCriteria == nil || content.HumanApprovalPoints == nil || content.DeploymentTargets == nil || content.SourceReferences == nil {
		return ErrAgentOutput
	}
	if len(content.BusinessOutcomes) == 0 || len(content.AcceptanceCriteria) == 0 {
		return ErrAgentOutput
	}
	if content.RiskTolerance != contracts.RiskLow && content.RiskTolerance != contracts.RiskMedium && content.RiskTolerance != contracts.RiskHigh {
		return ErrAgentOutput
	}
	if content.DataClassification != contracts.DataPublic && content.DataClassification != contracts.DataInternal && content.DataClassification != contracts.DataConfidential && content.DataClassification != contracts.DataRestricted {
		return ErrAgentOutput
	}
	if content.Toolchain == nil || content.Toolchain.Validate() != nil || content.Toolchain.RequiresInstallation() && len(content.UnresolvedItems) == 0 {
		return ErrAgentOutput
	}
	seen := make(map[string]bool)
	for _, outcome := range content.BusinessOutcomes {
		if outcome.ID == "" || strings.TrimSpace(outcome.Statement) == "" || seen[outcome.ID] {
			return ErrAgentOutput
		}
		seen[outcome.ID] = true
	}
	clear(seen)
	for _, criterion := range content.AcceptanceCriteria {
		if criterion.ID == "" || strings.TrimSpace(criterion.Statement) == "" || strings.TrimSpace(criterion.EvidenceType) == "" || seen[criterion.ID] {
			return ErrAgentOutput
		}
		seen[criterion.ID] = true
	}
	return nil
}

func encodeGoal(content contracts.GoalContent, status contracts.GoalStatus, approvedBy *contracts.ApprovalActor) (contracts.GoalSpec, []byte, error) {
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return contracts.GoalSpec{}, nil, err
	}
	digest, err := canonicaljson.Digest(contentBytes)
	if err != nil {
		return contracts.GoalSpec{}, nil, err
	}
	goal := contracts.GoalSpec{Content: content, Status: status, ApprovedBy: approvedBy, ContentSHA256: digest}
	if err := goal.Validate(); err != nil {
		return contracts.GoalSpec{}, nil, err
	}
	encoded, err := json.Marshal(goal)
	if err != nil {
		return contracts.GoalSpec{}, nil, err
	}
	if err := contracts.ValidateGoalJSON(encoded); err != nil {
		return contracts.GoalSpec{}, nil, err
	}
	return goal, encoded, nil
}

func validateChallenge(report ChallengeReport) error {
	if report.ReportVersion != 1 || report.ProjectID == "" || report.GoalSpecRef.Validate() != nil || report.CreatedBy.AgentInstanceID == "" || report.CreatedBy.Role != "GOAL_CHALLENGER" {
		return ErrAgentOutput
	}
	for _, finding := range report.Findings {
		switch finding.Severity {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			return ErrAgentOutput
		}
		if finding.AffectedClause == "" || finding.Evidence == "" || finding.Question == "" {
			return ErrAgentOutput
		}
	}
	return nil
}

func validatePlanOwnership(plan contracts.PlanSpec) error {
	type owner struct {
		module string
		path   string
	}
	var owned []owner
	interfaces := make(map[string]string)
	responsibilities := make(map[string]string)
	totalPaths := 0
	totalInterfaces := 0
	for _, module := range plan.Modules {
		totalPaths += len(module.OwnedPaths) + len(module.ForbiddenPaths)
		totalInterfaces += len(module.PublicInterfaces)
		if totalPaths > 4096 || totalInterfaces > 4096 {
			return ErrOwnershipConflict
		}
		responsibility := strings.ToLower(strings.TrimSpace(module.Responsibility))
		if prior := responsibilities[responsibility]; prior != "" {
			return fmt.Errorf("%w: responsibility %s and %s", ErrOwnershipConflict, prior, module.ModuleID)
		}
		responsibilities[responsibility] = module.ModuleID
		seenPaths := make(map[string]bool)
		for _, rawPath := range module.OwnedPaths {
			clean, ok := cleanOwnedPath(rawPath)
			if !ok || seenPaths[clean] {
				return ErrOwnershipConflict
			}
			seenPaths[clean] = true
			owned = append(owned, owner{module: module.ModuleID, path: clean})
		}
		if module.VerificationEntrypoint != "" || module.ToolchainIDs != nil {
			entrypoint, ok := cleanOwnedPath(module.VerificationEntrypoint)
			if !ok || strings.ContainsAny(entrypoint, "*?[") {
				return ErrOwnershipConflict
			}
			entrypointOwned := false
			for ownedPath := range seenPaths {
				if ownedPathCovers(ownedPath, entrypoint) {
					entrypointOwned = true
					break
				}
			}
			if !entrypointOwned {
				return ErrOwnershipConflict
			}
		}
		for _, rawPath := range module.ForbiddenPaths {
			clean, ok := cleanForbiddenPath(rawPath)
			if !ok {
				return ErrOwnershipConflict
			}
			for ownedPath := range seenPaths {
				if forbiddenPathConflicts(clean, ownedPath) {
					return ErrOwnershipConflict
				}
			}
		}
		for _, publicInterface := range module.PublicInterfaces {
			key := strings.ToLower(strings.TrimSpace(publicInterface))
			if key == "" || interfaces[key] != "" {
				return ErrOwnershipConflict
			}
			interfaces[key] = module.ModuleID
		}
	}
	sort.Slice(owned, func(i, j int) bool { return owned[i].path < owned[j].path })
	for left := 0; left < len(owned); left++ {
		for right := left + 1; right < len(owned); right++ {
			if owned[left].module == owned[right].module {
				continue
			}
			if pathContains(owned[left].path, owned[right].path) || pathContains(owned[right].path, owned[left].path) {
				return fmt.Errorf("%w: %s and %s", ErrOwnershipConflict, owned[left].module, owned[right].module)
			}
		}
	}
	return nil
}

func validatePlanShape(plan contracts.PlanSpec, requireToolchains bool) error {
	if plan.Architecture.Components == nil || plan.Architecture.DataFlows == nil || plan.Architecture.TrustBoundaries == nil || plan.Architecture.DeploymentUnits == nil || plan.QualityAttributes == nil || plan.Modules == nil || plan.IntegrationPlan == nil || plan.ReleasePlan == nil || plan.TestStrategy == nil || plan.RollbackStrategy == nil || plan.OpenDecisions == nil || len(plan.OpenDecisions) != 0 {
		return ErrAgentOutput
	}
	names := make(map[string]bool, len(plan.Modules))
	for _, module := range plan.Modules {
		name := strings.ToLower(strings.TrimSpace(module.Name))
		if name == "" || names[name] || module.OwnedPaths == nil || len(module.OwnedPaths) == 0 || module.ForbiddenPaths == nil || module.PublicInterfaces == nil || module.Dependencies == nil || module.AcceptanceCriteria == nil {
			return ErrAgentOutput
		}
		if requireToolchains && (module.ToolchainIDs == nil || len(module.ToolchainIDs) == 0 || strings.TrimSpace(module.VerificationEntrypoint) == "") {
			return ErrAgentOutput
		}
		names[name] = true
	}
	return nil
}

func validateModuleShape(module contracts.ModuleSpec) error {
	if strings.TrimSpace(module.Name) == "" || strings.TrimSpace(module.Purpose) == "" || module.Responsibilities == nil || len(module.Responsibilities) == 0 || module.NonResponsibilities == nil || module.Inputs == nil || module.Outputs == nil || module.Interfaces == nil || module.DataOwnership == nil || module.Dependencies == nil || module.AllowedPaths == nil || len(module.AllowedPaths) == 0 || module.ForbiddenPaths == nil || module.NetworkPolicy.Destinations == nil || module.ToolCapabilities == nil || module.ToolchainIDs == nil || len(module.ToolchainIDs) == 0 || module.Toolchains == nil || len(module.Toolchains) == 0 || strings.TrimSpace(module.VerificationEntrypoint) == "" || module.KnowledgeRefs == nil || module.AcceptanceCriteria == nil || len(module.AcceptanceCriteria) == 0 || module.TestRequirements == nil || module.ObservabilityRequirements == nil || module.SecurityRequirements == nil || module.Budget.MaxInputTokens <= 0 || module.Budget.MaxOutputTokens <= 0 || module.Budget.MaxCost == "" || module.Budget.Currency == "" {
		return ErrAgentOutput
	}
	return nil
}

func cleanOwnedPath(value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", false
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	clean := path.Clean(normalized)
	if clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") || clean == ".git" || strings.HasPrefix(clean, ".git/") || strings.ContainsAny(clean, "*?[") {
		return "", false
	}
	return clean, true
}

func cleanForbiddenPath(value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", false
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	clean := path.Clean(normalized)
	if clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

func pathContains(parent, child string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}

func ownedPathCovers(owned, candidate string) bool {
	for _, suffix := range []string{"/...", "/**"} {
		if strings.HasSuffix(owned, suffix) {
			owned = strings.TrimSuffix(owned, suffix)
			break
		}
	}
	return pathContains(owned, candidate)
}

func forbiddenPathConflicts(forbidden, owned string) bool {
	if pathContains(owned, forbidden) || pathPatternMatches(forbidden, owned) {
		return true
	}
	lowerForbidden := strings.ToLower(forbidden)
	lowerOwned := strings.ToLower(owned)
	return pathContains(lowerOwned, lowerForbidden) || pathPatternMatches(lowerForbidden, lowerOwned)
}

func pathPatternMatches(pattern, candidate string) bool {
	if pattern == candidate {
		return true
	}
	for _, suffix := range []string{"/...", "/**"} {
		if strings.HasSuffix(pattern, suffix) {
			root := strings.TrimSuffix(pattern, suffix)
			return candidate == root || strings.HasPrefix(candidate, root+"/")
		}
	}
	if strings.ContainsAny(pattern, "*?[") {
		matched, _ := path.Match(pattern, candidate)
		return matched
	}
	return strings.HasPrefix(candidate, pattern+"/")
}
