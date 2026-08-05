package aor.authz

import rego.v1

default_deny := {
    "decision": "DENY",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["DEFAULT_DENY"],
    "ruleId": "aor.default.deny",
}

side_effect_actions := {
    "repo.write",
    "repo.apply_patch",
    "tool.invoke",
    "knowledge.write",
    "artifact.publish",
    "policy.write",
	"deploy",
	"sandbox.exec",
}

read_actions := {
	"project.read",
    "goal.read",
    "plan.read",
    "task.read",
    "knowledge.read",
}

human_control_actions := {
	"project.create",
	"project.command",
	"task.command",
}

model_actions := {
    "model.generate",
    "model.stream",
    "model.cancel",
	"model.reconcile",
    "model.capabilities",
}

project_lease_roles := {
	"GOAL_PROPOSER",
	"GOAL_CHALLENGER",
	"PLAN_SUPERVISOR",
	"GLOBAL_AUDITOR",
}

task_model_lease_roles := {
	"MODULE_PLANNER",
	"EXECUTOR",
	"AUDITOR",
	"MODULE_AUDITOR",
}

valid_project_scope if {
    input.principal.id != ""
    input.principal.type != ""
    input.project.tenantId != ""
    input.project.id != ""
    input.principal.tenantId in {"", input.project.tenantId}
}

valid_task_scope if {
	valid_project_scope
	input.task.tenantId == input.project.tenantId
	input.task.projectId == input.project.id
	input.task.id != ""
}

read_allowed if {
	valid_project_scope
    input.action in read_actions
	input.action != "task.read"
}

read_allowed if {
	valid_task_scope
	input.action == "task.read"
}

human_control_allowed if {
	valid_project_scope
	input.action in human_control_actions
	input.principal.type in {"USER", "BREAK_GLASS_ADMIN"}
	input.principal.role in {"USER", "BREAK_GLASS_ADMIN"}
	input.action != "task.command"
}

model_scope_valid if {
    valid_project_scope
    input.action in model_actions
    input.principal.role != ""
    input.project.state != "ABORTED"
    input.project.state != "ARCHIVED"
    input.project.state != "FAILED_SYSTEM"
	object.get(object.get(input, "task", {}), "id", "") == ""
}

model_scope_valid if {
    valid_task_scope
    input.action in model_actions
    input.principal.role != ""
    input.project.state != "ABORTED"
    input.project.state != "ARCHIVED"
    input.project.state != "FAILED_SYSTEM"
}

model_allowed if {
    model_scope_valid
    input.action == "model.capabilities"
}

model_allowed if {
    model_scope_valid
    input.action != "model.capabilities"
	input.action != "model.reconcile"
    input.budget.available
}

model_allowed if {
	model_scope_valid
	input.action == "model.reconcile"
	input.principal.type == "SERVICE"
	input.budget.available
}

human_control_allowed if {
	valid_task_scope
	input.action == "task.command"
	input.principal.type in {"USER", "BREAK_GLASS_ADMIN"}
	input.principal.role in {"USER", "BREAK_GLASS_ADMIN"}
}

audit_service_state_valid if {
	input.resource.attributes.command == "START_AUDIT"
	input.task.state == "SUBMITTED"
}

audit_service_state_valid if {
	input.resource.attributes.command in {"DETERMINISTIC_SUCCESS", "DETERMINISTIC_FAILURE"}
	input.task.state == "DETERMINISTIC_AUDIT"
}

audit_service_state_valid if {
	input.resource.attributes.command in {"LLM_SUCCESS", "LLM_FAILURE"}
	input.task.state == "LLM_AUDIT"
}

audit_service_control_allowed if {
	valid_task_scope
	input.action == "task.command"
	input.principal.type == "SERVICE"
	input.principal.role == "SERVICE"
	input.project.state in {"EXECUTING", "GLOBAL_AUDIT"}
	input.resource.type == "task"
	input.resource.id == input.task.id
	input.resource.attributes.policy_digest == data.aor.policy.version
	audit_service_state_valid
}

active_lease if {
    input.lease.id != ""
    input.lease.policyVersion == data.aor.policy.version
    input.lease.fencingToken > 0
    time.parse_rfc3339_ns(input.lease.expiresAt) > time.now_ns()
}

repo_write_allowed if {
	valid_task_scope
    input.action in {"repo.write", "repo.apply_patch"}
    input.principal.type == "AGENT_INSTANCE"
    input.principal.role == "EXECUTOR"
    input.project.state == "EXECUTING"
    input.task.state == "EXECUTING"
    active_lease
    some owned in input.task.ownedPaths
    glob.match(owned, ["/"], input.resource.path)
}

sandbox_exec_allowed if {
	valid_task_scope
	input.action == "sandbox.exec"
	input.resource.type == "sandbox"
	input.resource.id != ""
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "EXECUTOR"
	input.project.state == "EXECUTING"
	input.task.state == "EXECUTING"
	active_lease
}

tool_invoke_allowed if {
	valid_task_scope
	input.action == "tool.invoke"
	input.resource.type == "tool"
	input.resource.id != ""
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role in {"GOAL_PROPOSER", "GOAL_CHALLENGER", "PLAN_SUPERVISOR", "MODULE_PLANNER", "EXECUTOR", "AUDITOR", "KNOWLEDGE_CURATOR", "SERVICE"}
	input.project.state != "ABORTED"
	input.project.state != "ARCHIVED"
	input.project.state != "FAILED_SYSTEM"
	input.project.state != "PAUSED"
	input.task.state != "CANCELED"
	input.task.state != "SUPERSEDED"
	input.task.state != "PASSED"
	input.task.state != "INTEGRATED"
	input.budget.available
	active_lease
}

lease_grant_input_valid if {
	valid_task_scope
	input.action in side_effect_actions
	not input.lease
	input.parameterDigest != ""
	input.task.specDigest != ""
	input.budget.accountId != ""
	input.budget.available
}

lease_grant_input_valid if {
	valid_task_scope
	input.action == "model.generate"
	not input.lease
	input.parameterDigest != ""
	input.task.specDigest != ""
	input.budget.accountId != ""
	input.budget.available
}

lease_grant_input_valid if {
	valid_project_scope
	input.principal.role in project_lease_roles
	object.get(object.get(input, "task", {}), "id", "") == ""
	object.get(object.get(input, "task", {}), "specDigest", "") == ""
	input.action == "model.generate"
	not input.lease
	input.parameterDigest != ""
	input.budget.accountId != ""
	input.budget.available
}

repo_write_grant_allowed if {
	lease_grant_input_valid
	input.action in {"repo.write", "repo.apply_patch"}
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "EXECUTOR"
	input.project.state == "EXECUTING"
	input.task.state == "EXECUTING"
	some owned in input.task.ownedPaths
	glob.match(owned, ["/"], input.resource.path)
}

sandbox_exec_grant_allowed if {
	lease_grant_input_valid
	input.action == "sandbox.exec"
	input.resource.type == "sandbox"
	input.resource.id != ""
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "EXECUTOR"
	input.project.state == "EXECUTING"
	input.task.state == "EXECUTING"
}

sandbox_exec_grant_allowed if {
	lease_grant_input_valid
	input.action == "sandbox.exec"
	input.resource.type == "sandbox"
	input.resource.id != ""
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "AUDITOR"
	input.project.state in {"EXECUTING", "GLOBAL_AUDIT"}
	input.task.state in {"DETERMINISTIC_AUDIT", "LLM_AUDIT"}
}

tool_invoke_grant_allowed if {
	lease_grant_input_valid
	input.action == "tool.invoke"
	input.resource.type == "tool"
	input.resource.id != ""
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role in {"GOAL_PROPOSER", "GOAL_CHALLENGER", "PLAN_SUPERVISOR", "MODULE_PLANNER", "EXECUTOR", "AUDITOR", "KNOWLEDGE_CURATOR", "SERVICE"}
	input.project.state != "ABORTED"
	input.project.state != "ARCHIVED"
	input.project.state != "FAILED_SYSTEM"
	input.project.state != "PAUSED"
	input.task.state != "CANCELED"
	input.task.state != "SUPERSEDED"
	input.task.state != "PASSED"
	input.task.state != "INTEGRATED"
}

model_generate_grant_allowed if {
	lease_grant_input_valid
	input.action == "model.generate"
	input.resource.type == "model"
	input.resource.id != ""
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role in project_lease_roles
	object.get(object.get(input, "task", {}), "id", "") == ""
	input.project.state != "ABORTED"
	input.project.state != "ARCHIVED"
	input.project.state != "FAILED_SYSTEM"
	input.project.state != "PAUSED"
}

model_generate_grant_allowed if {
	lease_grant_input_valid
	input.action == "model.generate"
	input.resource.type == "model"
	input.resource.id != ""
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role in task_model_lease_roles
	valid_task_scope
	input.project.state != "ABORTED"
	input.project.state != "ARCHIVED"
	input.project.state != "FAILED_SYSTEM"
	input.project.state != "PAUSED"
	input.task.state != "CANCELED"
	input.task.state != "SUPERSEDED"
	input.task.state != "PASSED"
	input.task.state != "INTEGRATED"
}

lease_grant_allowed if {
	repo_write_grant_allowed
}

lease_grant_allowed if {
	sandbox_exec_grant_allowed
}

lease_grant_allowed if {
	tool_invoke_grant_allowed
}

lease_grant_allowed if {
	model_generate_grant_allowed
}

lease_grant_binding := {
	"principalId": input.principal.id,
	"tenantId": input.project.tenantId,
	"projectId": input.project.id,
	"projectVersion": input.project.stateVersion,
	"taskId": object.get(object.get(input, "task", {}), "id", ""),
	"taskVersion": object.get(object.get(input, "task", {}), "stateVersion", 0),
	"specDigest": object.get(object.get(input, "task", {}), "specDigest", ""),
	"role": input.principal.role,
	"action": input.action,
	"resource": input.resource,
	"parameterDigest": input.parameterDigest,
	"budgetAccountId": input.budget.accountId,
} if {
	lease_grant_input_valid
}

lease_grant := {
	"decision": "ALLOW",
	"policyVersion": data.aor.policy.version,
	"reasonCodes": ["LEASE_GRANT_ALLOWED", "CURRENT_SCOPE_VALID"],
	"ruleId": "aor.lease.grant",
	"binding": lease_grant_binding,
} if {
	lease_grant_allowed
}

lease_grant := default_deny if {
	not lease_grant_allowed
}

sandbox_exec_allowed if {
	valid_task_scope
	input.action == "sandbox.exec"
	input.resource.type == "sandbox"
	input.resource.id != ""
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "AUDITOR"
	input.project.state in {"EXECUTING", "GLOBAL_AUDIT"}
	input.task.state in {"DETERMINISTIC_AUDIT", "LLM_AUDIT"}
	active_lease
}

decision := {
    "decision": "ALLOW",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["ROLE_ALLOWED", "PROJECT_SCOPE_VALID"],
    "ruleId": "aor.read",
} if {
    read_allowed
}

decision := {
	"decision": "ALLOW",
	"policyVersion": data.aor.policy.version,
	"reasonCodes": ["HUMAN_CONTROL_ALLOWED", "PROJECT_SCOPE_VALID"],
	"ruleId": "aor.human.control",
} if {
	human_control_allowed
}

decision := {
	"decision": "ALLOW",
	"policyVersion": data.aor.policy.version,
	"reasonCodes": ["AUDIT_SERVICE_ALLOWED", "TASK_STATE_VALID"],
	"ruleId": "aor.audit.service.control",
} if {
	audit_service_control_allowed
}

decision := {
    "decision": "ALLOW",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["MODEL_POLICY_ALLOWED", "PROJECT_SCOPE_VALID"],
    "ruleId": "aor.model.invoke",
} if {
    model_allowed
}

decision := {
    "decision": "ALLOW",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["ROLE_ALLOWED", "TASK_OWNS_PATH", "LEASE_VALID"],
    "ruleId": "aor.repo.owned_path",
    "constraints": {
        "pathGlob": owned,
        "maxBytes": data.aor.policy.maxWriteBytes,
        "expiresAt": input.lease.expiresAt,
    },
} if {
	repo_write_allowed
    some owned in input.task.ownedPaths
    glob.match(owned, ["/"], input.resource.path)
}

decision := {
	"decision": "ALLOW",
	"policyVersion": data.aor.policy.version,
	"reasonCodes": ["EXECUTION_ROLE_ALLOWED", "TASK_STATE_VALID", "LEASE_VALID"],
	"ruleId": "aor.sandbox.exec",
	"constraints": {"expiresAt": input.lease.expiresAt},
} if {
	sandbox_exec_allowed
}

decision := {
	"decision": "ALLOW",
	"policyVersion": data.aor.policy.version,
	"reasonCodes": ["ROLE_ALLOWED", "BUDGET_AVAILABLE", "LEASE_VALID"],
	"ruleId": "aor.tool.invoke",
	"constraints": {
		"maxBytes": data.aor.policy.maxWriteBytes,
		"expiresAt": input.lease.expiresAt,
	},
} if {
	tool_invoke_allowed
}

decision := {
    "decision": "APPROVAL_REQUIRED",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["CURATOR_APPROVAL_REQUIRED"],
    "ruleId": "aor.approval.required",
} if {
    valid_project_scope
    input.action == "knowledge.write"
    input.principal.role == "KNOWLEDGE_CURATOR"
    not input.approval.id
}

curator_missing_approval if {
    input.action == "knowledge.write"
    not input.approval.id
}

matched if {
    read_allowed
}

matched if {
	human_control_allowed
}

matched if {
	audit_service_control_allowed
}

matched if {
    model_allowed
}

matched if {
	repo_write_allowed
}

matched if {
	sandbox_exec_allowed
}

matched if {
	tool_invoke_allowed
}

matched if {
    valid_project_scope
    input.action == "knowledge.write"
    input.principal.role == "KNOWLEDGE_CURATOR"
    not input.approval.id
}

matched if {
    valid_project_scope
    input.action == "knowledge.write"
    input.principal.role == "KNOWLEDGE_CURATOR"
    input.approval.id != ""
    active_lease
}

matched if {
    valid_project_scope
    input.action in side_effect_actions
    not active_lease
    not curator_missing_approval
}

decision := {
    "decision": "ALLOW",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["CURATOR_ALLOWED", "APPROVAL_VALID", "LEASE_VALID"],
    "ruleId": "aor.knowledge.write",
    "constraints": {"expiresAt": input.lease.expiresAt},
} if {
    valid_project_scope
    input.action == "knowledge.write"
    input.principal.role == "KNOWLEDGE_CURATOR"
    input.approval.id != ""
    active_lease
}

decision := {
    "decision": "DENY",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["LEASE_REQUIRED"],
    "ruleId": "aor.lease.required",
} if {
    valid_project_scope
    input.action in side_effect_actions
    not active_lease
    not curator_missing_approval
}

decision := default_deny if {
    not matched
}
