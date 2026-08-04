package aor.authz_test

import data.aor.authz
import rego.v1

base_input := {
    "principal": {"id": "agent_1", "type": "AGENT_INSTANCE", "role": "EXECUTOR", "tenantId": "tenant_1"},
    "project": {"id": "project_1", "tenantId": "tenant_1", "state": "EXECUTING"},
    "task": {"id": "task_1", "tenantId": "tenant_1", "state": "EXECUTING", "ownedPaths": ["internal/auth/**"]},
    "resource": {"path": "internal/auth/token.go"},
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
