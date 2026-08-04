package aor.authz_test

import data.aor.authz
import rego.v1

base_input := {
    "principal": {"id": "agent_1", "type": "AGENT_INSTANCE", "role": "EXECUTOR", "tenantId": "tenant_1"},
    "project": {"id": "project_1", "tenantId": "tenant_1", "state": "EXECUTING"},
    "task": {"id": "task_1", "projectId": "project_1", "tenantId": "tenant_1", "state": "EXECUTING", "ownedPaths": ["internal/auth/**"]},
    "resource": {"path": "internal/auth/token.go"},
}

grant_input := {
	"principal": {"id": "agent_1", "type": "AGENT_INSTANCE", "role": "EXECUTOR", "tenantId": "tenant_1"},
	"project": {"id": "project_1", "tenantId": "tenant_1", "state": "EXECUTING", "stateVersion": 7},
	"task": {
		"id": "task_1", "projectId": "project_1", "tenantId": "tenant_1", "state": "EXECUTING", "stateVersion": 9,
		"specDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"ownedPaths": ["internal/auth/**"],
	},
	"action": "tool.invoke",
	"resource": {"type": "tool", "id": "tool://repository/repo.read@1.0.0"},
	"parameterDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	"budget": {"accountId": "budget_1", "available": true},
}

test_unknown_action_is_denied if {
    result := authz.decision with input as object.union(base_input, {"action": "unknown.action"})
    result.decision == "DENY"
}

test_repo_write_without_lease_is_denied if {
    result := authz.decision with input as object.union(base_input, {"action": "repo.write"})
    result.decision == "DENY"
    "LEASE_REQUIRED" in result.reasonCodes
}

test_owned_repo_write_with_current_lease_is_allowed if {
    request := object.union(base_input, {
        "action": "repo.write",
        "lease": {
            "id": "lease_1",
            "policyVersion": data.aor.policy.version,
            "fencingToken": 1,
            "expiresAt": "2099-01-01T00:00:00Z",
        },
    })
    result := authz.decision with input as request
    result.decision == "ALLOW"
    result.constraints.pathGlob == "internal/auth/**"
}

test_sandbox_exec_requires_current_lease_and_execution_state if {
	request := object.union(base_input, {
		"action": "sandbox.exec",
		"resource": {"type": "sandbox", "id": "sandbox_1"},
		"lease": {
			"id": "lease_1",
			"policyVersion": data.aor.policy.version,
			"fencingToken": 1,
			"expiresAt": "2099-01-01T00:00:00Z",
		},
	})
	result := authz.decision with input as request
	result.decision == "ALLOW"

	stale := object.union(request, {"task": object.union(request.task, {"state": "CANCELED"})})
	stale_result := authz.decision with input as stale
	stale_result.decision == "DENY"
}

test_tool_invoke_with_current_lease_is_allowed if {
	request := object.union(grant_input, {
		"lease": {
			"id": "lease_1",
			"policyVersion": data.aor.policy.version,
			"fencingToken": 1,
			"expiresAt": "2099-01-01T00:00:00Z",
		},
	})
	result := authz.decision with input as request
	result.decision == "ALLOW"
	result.ruleId == "aor.tool.invoke"
}

test_tool_invoke_lease_grant_is_exactly_bound if {
	result := authz.lease_grant with input as grant_input
	result.decision == "ALLOW"
	result.binding.principalId == grant_input.principal.id
	result.binding.projectVersion == grant_input.project.stateVersion
	result.binding.taskVersion == grant_input.task.stateVersion
	result.binding.resource == grant_input.resource
	result.binding.parameterDigest == grant_input.parameterDigest
}

test_lease_grant_rejects_terminal_task_or_missing_budget if {
	terminal := object.union(grant_input, {"task": object.union(grant_input.task, {"state": "CANCELED"})})
	terminal_result := authz.lease_grant with input as terminal
	terminal_result.decision == "DENY"

	without_budget := object.union(grant_input, {"budget": object.union(grant_input.budget, {"available": false})})
	budget_result := authz.lease_grant with input as without_budget
	budget_result.decision == "DENY"
}

test_model_reconcile_requires_service_principal if {
	request := object.union(base_input, {
		"action": "model.reconcile",
		"budget": {"accountId": "budget_1", "available": true},
	})
	agent_result := authz.decision with input as request
	agent_result.decision == "DENY"

	service_request := object.union(request, {
		"principal": object.union(request.principal, {"type": "SERVICE"}),
	})
	service_result := authz.decision with input as service_request
	service_result.decision == "ALLOW"
}
