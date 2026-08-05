package controlapi

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/akimisaka/aor/internal/authn"
	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/sandbox"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type adminCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type adminReport struct {
	Operation   string       `json:"operation"`
	Status      string       `json:"status"`
	Checks      []adminCheck `json:"checks"`
	Policy      string       `json:"policyVersion,omitempty"`
	GeneratedAt time.Time    `json:"generatedAt"`
}

// sandboxProbeRequest is intentionally a subset of SandboxSpec. A probe must
// validate the security profile without creating a workload or accepting
// caller-controlled paths and commands.
type sandboxProbeRequest struct {
	Platform                 sandbox.Platform          `json:"platform"`
	IsolationLevel           sandbox.IsolationLevel    `json:"isolationLevel"`
	WorkloadTrust            sandbox.WorkloadTrust     `json:"workloadTrust"`
	DeploymentProfile        sandbox.DeploymentProfile `json:"deploymentProfile"`
	RequiresHiddenTests      bool                      `json:"requiresHiddenTests,omitempty"`
	RequiresNetworkIsolation bool                      `json:"requiresNetworkIsolation,omitempty"`
}

func (handler *Handler) admin(response http.ResponseWriter, request *http.Request, principal authn.Principal, operation string) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(response, request)
		return
	}
	if err := requiredAdmin(principal); err != nil {
		writeError(response, request, err)
		return
	}
	if _, err := requiredIdempotencyKey(request); err != nil {
		writeError(response, request, err)
		return
	}
	switch operation {
	case "doctor":
		handler.adminDoctor(response, request)
	case "policy-test":
		handler.adminPolicyTest(response, request, principal)
	case "sandbox-probe":
		handler.adminSandboxProbe(response, request)
	default:
		writeError(response, request, aorerrors.New(aorerrors.CodeNotFound, "", nil))
	}
}

func requiredAdmin(principal authn.Principal) error {
	if principal.Validate() != nil || (principal.Type != authn.PrincipalBreakGlassAdmin && principal.Role != authn.RoleBreakGlassAdmin) {
		return aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "administration"})
	}
	return nil
}

func (handler *Handler) adminDoctor(response http.ResponseWriter, request *http.Request) {
	checks := []adminCheck{
		adminDependencyCheck("event_store", handler != nil && handler.store != nil),
		adminDependencyCheck("event_log", handler != nil && handler.events != nil),
		adminDependencyCheck("policy_engine", handler != nil && handler.authorizer != nil),
		adminDependencyCheck("knowledge_service", handler != nil && handler.knowledge != nil),
		adminDependencyCheck("knowledge_curator", handler != nil && handler.knowledgeCurator != nil),
		adminDependencyCheck("artifact_catalog", handler != nil && handler.artifacts != nil),
		adminDependencyCheck("lease_authority", handler != nil && handler.leases != nil),
		adminDependencyCheck("goal_plan", handler != nil && handler.goalPlan.Negotiator != nil && handler.goalPlan.Planner != nil),
	}
	if handler != nil && handler.database != nil {
		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		err := handler.database.PingContext(ctx)
		cancel()
		checks = append(checks, adminDependencyCheck("database", err == nil))
	} else {
		checks = append(checks, adminCheck{Name: "database", Status: "SKIPPED", Detail: "database is not configured"})
	}
	writeAdminReport(response, request, "doctor", checks, "")
}

func adminDependencyCheck(name string, healthy bool) adminCheck {
	if healthy {
		return adminCheck{Name: name, Status: "PASS"}
	}
	return adminCheck{Name: name, Status: "FAIL", Detail: "dependency unavailable"}
}

func (handler *Handler) adminPolicyTest(response http.ResponseWriter, request *http.Request, principal authn.Principal) {
	var input authz.PolicyInput
	if err := decodeJSON(request, &input); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "policy test"}))
		return
	}
	// The authenticated identity is authoritative. Never evaluate a policy
	// test using a principal supplied in the request body.
	input.Principal = principal
	if input.Project.TenantID != principal.TenantID || input.Project.ID == "" || principal.ProjectID != "" && input.Project.ID != principal.ProjectID {
		writeError(response, request, aorerrors.New(aorerrors.CodeForbidden, "", map[string]any{"scope": "policy test project"}))
		return
	}
	if validationErr := input.Validate(time.Now().UTC()); validationErr != nil {
		writeError(response, request, validationErr)
		return
	}
	if handler == nil || handler.authorizer == nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", map[string]any{"scope": "policy engine"}))
		return
	}
	decision, err := handler.authorizer.Evaluate(request.Context(), input)
	if err != nil {
		writeError(response, request, err)
		return
	}
	if validationErr := decision.Validate(time.Now().UTC()); validationErr != nil {
		writeError(response, request, validationErr)
		return
	}
	writeJSON(response, http.StatusOK, decision)
}

func (handler *Handler) adminSandboxProbe(response http.ResponseWriter, request *http.Request) {
	var probe sandboxProbeRequest
	if err := decodeJSON(request, &probe); err != nil {
		writeError(response, request, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "sandbox probe"}))
		return
	}
	checks := validateSandboxProbe(probe)
	writeAdminReport(response, request, "sandbox-probe", checks, "")
}

func validateSandboxProbe(probe sandboxProbeRequest) []adminCheck {
	checks := []adminCheck{
		{Name: "platform", Status: "PASS"},
		{Name: "isolation", Status: "PASS"},
		{Name: "workload_policy", Status: "PASS"},
	}
	if probe.Platform != sandbox.PlatformLinux && probe.Platform != sandbox.PlatformWindows {
		checks[0] = adminCheck{Name: "platform", Status: "FAIL", Detail: "platform must be LINUX or WINDOWS"}
	}
	if probe.Platform == sandbox.PlatformLinux && probe.IsolationLevel != sandbox.IsolationContainer {
		checks[1] = adminCheck{Name: "isolation", Status: "FAIL", Detail: "Linux workloads require CONTAINER isolation"}
	}
	if probe.Platform == sandbox.PlatformWindows && probe.IsolationLevel != sandbox.IsolationNone {
		checks[1] = adminCheck{Name: "isolation", Status: "FAIL", Detail: "Windows workloads require NONE isolation"}
	}
	if probe.Platform == sandbox.PlatformWindows && (probe.WorkloadTrust == sandbox.TrustUntrusted || probe.RequiresHiddenTests || probe.RequiresNetworkIsolation) {
		checks[2] = adminCheck{Name: "workload_policy", Status: "FAIL", Detail: "Windows NONE cannot run untrusted, hidden-test, or network-isolated workloads"}
	}
	return checks
}

func writeAdminReport(response http.ResponseWriter, request *http.Request, operation string, checks []adminCheck, policyVersion string) {
	sort.Slice(checks, func(left, right int) bool { return checks[left].Name < checks[right].Name })
	status := "PASS"
	for _, check := range checks {
		if check.Status == "FAIL" {
			status = "FAIL"
			break
		}
	}
	writeJSON(response, http.StatusOK, adminReport{Operation: operation, Status: status, Checks: checks, Policy: policyVersion, GeneratedAt: time.Now().UTC()})
}
