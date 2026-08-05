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

project_grant_input := {
	"principal": {"id": "agent_goal", "type": "AGENT_INSTANCE", "role": "GOAL_PROPOSER", "tenantId": "tenant_1"},
	"project": {"id": "project_1", "tenantId": "tenant_1", "state": "GOAL_NEGOTIATING", "stateVersion": 3},
	"task": {"id": "", "stateVersion": 0, "specDigest": ""},
	"action": "model.generate",
	"resource": {"type": "model", "id": "model://goal/default"},
	"parameterDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	"budget": {"accountId": "budget_1", "available": true},
}

task_model_grant_input := {
	"principal": {"id": "agent_planner", "type": "AGENT_INSTANCE", "role": "MODULE_PLANNER", "tenantId": "tenant_1"},
	"project": {"id": "project_1", "tenantId": "tenant_1", "state": "PLANNING", "stateVersion": 7},
	"task": {
		"id": "task_1", "projectId": "project_1", "tenantId": "tenant_1", "state": "PLANNING", "stateVersion": 9,
		"specDigest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
	},
	"action": "model.generate",
	"resource": {"type": "model", "id": "model://planning/default"},
	"parameterDigest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
	"budget": {"accountId": "budget_1", "available": true},
}

curator_grant_input := {
	"principal": {
		"id": "curator_1", "type": "KNOWLEDGE_CURATOR", "role": "KNOWLEDGE_CURATOR",
		"tenantId": "tenant_1", "projectId": "project_1",
	},
	"project": {"id": "project_1", "tenantId": "tenant_1", "state": "EXECUTING", "stateVersion": 7},
	"task": {"id": "", "stateVersion": 0, "specDigest": ""},
	"action": "knowledge.write",
	"resource": {"type": "knowledge.write", "path": "knowledge/global/rules.md"},
	"parameterDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
	"budget": {"accountId": "budget_1", "available": true},
	"approval": {
		"id": "approval_1", "tenantId": "tenant_1", "projectId": "project_1", "principalId": "user_1",
		"subjectType": "knowledge.write", "subjectId": "knowledge/global/rules.md", "subjectVersion": 7,
		"subjectDigest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
		"issuedAt": "2020-01-01T00:00:00Z", "expiresAt": "2099-01-01T00:00:00Z", "signature": "signed-approval",
	},
}

test_unknown_action_is_denied if {
    result := authz.decision with input as object.union(base_input, {"action": "unknown.action"})
    result.decision == "DENY"
}

test_project_bound_principal_cannot_cross_project if {
	principal := object.union(base_input.principal, {"projectId": "project_2"})
	request := object.union(base_input, {"principal": principal, "action": "knowledge.read"})
	result := authz.decision with input as request
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

test_project_agent_lease_grant_has_no_task_binding if {
	result := authz.lease_grant with input as project_grant_input
	result.decision == "ALLOW"
	result.binding.taskId == ""
	result.binding.taskVersion == 0
	result.binding.specDigest == ""

	request := object.union(project_grant_input, {
		"lease": {
			"id": "lease_goal",
			"policyVersion": data.aor.policy.version,
			"fencingToken": 1,
			"expiresAt": "2099-01-01T00:00:00Z",
		},
	})
	authorized := authz.decision with input as request
	authorized.decision == "ALLOW"
}

test_knowledge_curator_model_grant_has_no_task_binding if {
	principal := object.union(project_grant_input.principal, {"role": "KNOWLEDGE_CURATOR"})
	request := object.union(project_grant_input, {"principal": principal})
	result := authz.lease_grant with input as request
	result.decision == "ALLOW"
	result.binding.taskId == ""
	result.binding.taskVersion == 0
	result.binding.specDigest == ""
}

test_knowledge_curator_lease_grant_is_project_bound if {
	result := authz.lease_grant with input as curator_grant_input
	result.decision == "ALLOW"
	result.binding.projectId == curator_grant_input.project.id
	result.binding.projectVersion == curator_grant_input.project.stateVersion
	result.binding.taskId == ""
	result.binding.taskVersion == 0
	result.binding.specDigest == ""
	result.binding.parameterDigest == curator_grant_input.parameterDigest
}

test_knowledge_curator_missing_approval_requires_approval if {
	request := object.union(curator_grant_input, {"approval": {}})
	result := authz.lease_grant with input as request
	result.decision == "APPROVAL_REQUIRED"
}

test_knowledge_curator_requires_exact_project_approval if {
	stale_approval := object.union(curator_grant_input.approval, {"subjectVersion": 6})
	stale_request := object.union(curator_grant_input, {"approval": stale_approval})
	stale_result := authz.lease_grant with input as stale_request
	stale_result.decision == "DENY"

	wrong_digest_approval := object.union(curator_grant_input.approval, {
		"subjectDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
	})
	wrong_digest_request := object.union(curator_grant_input, {"approval": wrong_digest_approval})
	wrong_digest_result := authz.lease_grant with input as wrong_digest_request
	wrong_digest_result.decision == "DENY"

	wrong_project_approval := object.union(curator_grant_input.approval, {"projectId": "project_2"})
	wrong_project_request := object.union(curator_grant_input, {"approval": wrong_project_approval})
	wrong_project_result := authz.lease_grant with input as wrong_project_request
	wrong_project_result.decision == "DENY"
}

test_knowledge_curator_rejects_task_scope_or_wrong_identity if {
	task_request := object.union(curator_grant_input, {"task": grant_input.task})
	task_result := authz.lease_grant with input as task_request
	task_result.decision == "DENY"

	wrong_type_principal := object.union(curator_grant_input.principal, {"type": "AGENT_INSTANCE"})
	wrong_type_request := object.union(curator_grant_input, {"principal": wrong_type_principal})
	wrong_type_result := authz.lease_grant with input as wrong_type_request
	wrong_type_result.decision == "DENY"

	wrong_role_principal := object.union(curator_grant_input.principal, {"role": "EXECUTOR"})
	wrong_role_request := object.union(curator_grant_input, {"principal": wrong_role_principal})
	wrong_role_result := authz.lease_grant with input as wrong_role_request
	wrong_role_result.decision == "DENY"

	wrong_project_principal := object.union(curator_grant_input.principal, {"projectId": "project_2"})
	wrong_project_request := object.union(curator_grant_input, {"principal": wrong_project_principal})
	wrong_project_result := authz.lease_grant with input as wrong_project_request
	wrong_project_result.decision == "DENY"
}

test_knowledge_curator_commit_requires_exact_proposal_and_current_project if {
	lease := {
		"id": "lease_curator", "policyVersion": data.aor.policy.version, "fencingToken": 1,
		"expiresAt": "2099-01-01T00:00:00Z",
	}
	request := object.union(curator_grant_input, {"lease": lease})
	result := authz.decision with input as request
	result.decision == "ALLOW"

	changed_proposal := object.union(request, {
		"parameterDigest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
	})
	changed_result := authz.decision with input as changed_proposal
	changed_result.decision == "DENY"

	changed_project := object.union(request, {
		"project": object.union(request.project, {"stateVersion": 8}),
	})
	changed_project_result := authz.decision with input as changed_project
	changed_project_result.decision == "DENY"
}

test_task_model_lease_grant_is_task_bound if {
	result := authz.lease_grant with input as task_model_grant_input
	result.decision == "ALLOW"
	result.binding.taskId == task_model_grant_input.task.id
	result.binding.taskVersion == task_model_grant_input.task.stateVersion
	result.binding.specDigest == task_model_grant_input.task.specDigest

	terminal := object.union(task_model_grant_input, {"task": object.union(task_model_grant_input.task, {"state": "CANCELED"})})
	terminal_result := authz.lease_grant with input as terminal
	terminal_result.decision == "DENY"
}

test_task_agent_lease_grant_still_requires_task if {
	request := object.union(project_grant_input, {
		"principal": object.union(project_grant_input.principal, {"role": "EXECUTOR"}),
	})
	result := authz.lease_grant with input as request
	result.decision == "DENY"
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
