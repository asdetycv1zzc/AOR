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
	"integration.merge",
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
	"KNOWLEDGE_CURATOR",
}

task_model_lease_roles := {
	"MODULE_PLANNER",
	"EXECUTOR",
	"AUDITOR",
	"MODULE_AUDITOR",
}

global_auditor_read_tools := {
	"artifact.read",
	"knowledge.read_range",
	"knowledge.search",
	"repository.file.read",
}

global_auditor_read_tool_resource if {
	input.resource.type == "tool"
	input.resource.path != ""
	startswith(input.resource.id, "tool://")
	some tool_id in global_auditor_read_tools
	contains(input.resource.id, concat("", ["/", tool_id, "@"]))
}

valid_project_scope if {
    input.principal.id != ""
    input.principal.type != ""
    input.project.tenantId != ""
    input.project.id != ""
    input.principal.tenantId in {"", input.project.tenantId}
	object.get(input.principal, "projectId", "") in {"", input.project.id}
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

audit_service_state_valid if {
	input.resource.attributes.command == "QUEUE_REWORK"
	input.task.state == "REWORK_REQUIRED"
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

integration_service_project_state_valid if {
	input.resource.attributes.command == "BEGIN_INTEGRATION"
	input.project.state == "EXECUTING"
}

integration_service_project_state_valid if {
	input.resource.attributes.command == "BEGIN_GLOBAL_AUDIT"
	input.project.state == "INTEGRATING"
}

integration_service_control_allowed if {
	valid_project_scope
	input.action == "project.command"
	input.principal.type == "SERVICE"
	input.principal.role == "SERVICE"
	input.resource.type == "project"
	input.resource.id == input.project.id
	input.resource.attributes.policy_digest == data.aor.policy.version
	integration_service_project_state_valid
}

integration_service_control_allowed if {
	valid_task_scope
	input.action == "task.command"
	input.principal.type == "SERVICE"
	input.principal.role == "SERVICE"
	input.project.state == "INTEGRATING"
	input.task.state == "PASSED"
	input.resource.type == "task"
	input.resource.id == input.task.id
	input.resource.attributes.command == "INTEGRATE"
	input.resource.attributes.policy_digest == data.aor.policy.version
}

authorization_time_ns := time.parse_rfc3339_ns(object.get(object.get(input, "context", {}), "authorizationTime", "")) if {
	object.get(object.get(input, "context", {}), "authorizationTime", "") != ""
}

authorization_time_ns := time.now_ns() if {
	object.get(object.get(input, "context", {}), "authorizationTime", "") == ""
}

active_lease if {
    input.lease.id != ""
    input.lease.policyVersion == data.aor.policy.version
    input.lease.fencingToken > 0
    time.parse_rfc3339_ns(input.lease.expiresAt) > authorization_time_ns
}

knowledge_curator_scope_valid if {
	valid_project_scope
	input.action == "knowledge.write"
	input.principal.type == "KNOWLEDGE_CURATOR"
	input.principal.role == "KNOWLEDGE_CURATOR"
	object.get(input.principal, "projectId", "") in {"", input.project.id}
	input.project.stateVersion >= 0
	object.get(object.get(input, "task", {}), "id", "") == ""
	object.get(object.get(input, "task", {}), "stateVersion", 0) == 0
	object.get(object.get(input, "task", {}), "specDigest", "") == ""
}

knowledge_subject_id := input.resource.id if {
	object.get(input.resource, "id", "") != ""
}

knowledge_subject_id := input.resource.path if {
	object.get(input.resource, "id", "") == ""
	object.get(input.resource, "path", "") != ""
}

knowledge_approval_active if {
	input.approval.issuedAt != ""
	input.approval.expiresAt != ""
	time.parse_rfc3339_ns(input.approval.issuedAt) <= authorization_time_ns
	time.parse_rfc3339_ns(input.approval.expiresAt) > authorization_time_ns
	object.get(input.approval, "revokedAt", "") == ""
}

knowledge_approval_active if {
	input.approval.issuedAt != ""
	input.approval.expiresAt != ""
	time.parse_rfc3339_ns(input.approval.issuedAt) <= authorization_time_ns
	time.parse_rfc3339_ns(input.approval.expiresAt) > authorization_time_ns
	time.parse_rfc3339_ns(input.approval.revokedAt) > authorization_time_ns
}

knowledge_write_request_valid if {
	knowledge_curator_scope_valid
	knowledge_subject_id != ""
	regex.match("^sha256:[0-9a-f]{64}$", input.parameterDigest)
	input.budget.accountId != ""
	input.budget.available
}

knowledge_approval_valid if {
	knowledge_write_request_valid
	input.approval.id != ""
	input.approval.principalId != ""
	input.approval.tenantId == input.project.tenantId
	input.approval.projectId == input.project.id
	input.approval.subjectId == knowledge_subject_id
	input.approval.subjectVersion == input.project.stateVersion
	input.approval.subjectDigest == input.parameterDigest
	input.approval.subjectType in {input.action, input.resource.type}
	input.approval.signature != ""
	knowledge_approval_active
}

knowledge_write_allowed if {
	knowledge_write_request_valid
	knowledge_approval_valid
	active_lease
}

artifact_publish_task_valid if {
	object.get(object.get(input, "task", {}), "id", "") == ""
}

artifact_publish_task_valid if {
	valid_task_scope
	not input.task.state in {"CANCELED", "SUPERSEDED", "PASSED", "INTEGRATED"}
}

artifact_subject_version := input.task.stateVersion if {
	object.get(object.get(input, "task", {}), "id", "") != ""
}

artifact_subject_version := input.project.stateVersion if {
	object.get(object.get(input, "task", {}), "id", "") == ""
}

artifact_project_state_valid if {
	not input.project.state in {"PAUSED", "ABORTED", "FAILED_SYSTEM", "ARCHIVED"}
}

artifact_project_state_valid if {
	input.project.state in {"PAUSED", "ARCHIVED"}
	object.get(object.get(object.get(input, "resource", {}), "attributes", {}), "operation", "") == "deletion-proof"
	object.get(object.get(object.get(input, "resource", {}), "attributes", {}), "deletionId", "") != ""
}

artifact_project_state_valid if {
	input.project.state in {"PAUSED", "ABORTED", "ARCHIVED"}
	object.get(object.get(object.get(input, "resource", {}), "attributes", {}), "operation", "") == "project-export"
}

artifact_publish_request_valid if {
	valid_project_scope
	artifact_publish_task_valid
	input.action == "artifact.publish"
	input.principal.type == "SERVICE"
	input.principal.role == "SERVICE"
	artifact_project_state_valid
	input.resource.type == "artifact"
	regex.match("^artifact://sha256/[0-9a-f]{64}$", input.resource.id)
	regex.match("^sha256:[0-9a-f]{64}$", input.parameterDigest)
	input.budget.accountId != ""
	input.budget.available
}

artifact_approval_valid if {
	artifact_publish_request_valid
	input.approval.id != ""
	input.approval.principalId != ""
	input.approval.tenantId == input.project.tenantId
	input.approval.projectId == input.project.id
	input.approval.subjectId == input.resource.id
	input.approval.subjectVersion == artifact_subject_version
	input.approval.subjectDigest == input.parameterDigest
	input.approval.subjectType in {input.action, input.resource.type}
	input.approval.signature != ""
	knowledge_approval_active
}

artifact_approval_satisfied if {
	not input.approval
}

artifact_approval_satisfied if {
	artifact_approval_valid
}

artifact_publish_allowed if {
	artifact_publish_request_valid
	artifact_approval_satisfied
	active_lease
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

tool_invoke_allowed if {
	valid_project_scope
	input.action == "tool.invoke"
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "GLOBAL_AUDITOR"
	input.project.state == "GLOBAL_AUDIT"
	global_auditor_read_tool_resource
	input.budget.available
	active_lease
}

tool_invoke_allowed if {
	valid_task_scope
	input.action == "tool.invoke"
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "MODULE_AUDITOR"
	input.project.state == "EXECUTING"
	input.task.state == "LLM_AUDIT"
	global_auditor_read_tool_resource
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

lease_grant_input_valid if {
	artifact_publish_request_valid
	object.get(object.get(input, "task", {}), "id", "") == ""
	not input.lease
}

lease_grant_input_valid if {
	knowledge_write_request_valid
	not input.lease
}

lease_grant_input_valid if {
	valid_project_scope
	input.principal.role == "GLOBAL_AUDITOR"
	object.get(object.get(input, "task", {}), "id", "") == ""
	object.get(object.get(input, "task", {}), "specDigest", "") == ""
	input.action == "tool.invoke"
	global_auditor_read_tool_resource
	not input.lease
	input.parameterDigest != ""
	input.budget.accountId != ""
	input.budget.available
}

lease_grant_input_valid if {
	valid_project_scope
	input.principal.type == "SERVICE"
	input.principal.role == "SERVICE"
	object.get(object.get(input, "task", {}), "id", "") == ""
	object.get(object.get(input, "task", {}), "specDigest", "") == ""
	input.action == "integration.merge"
	input.resource.type == "integration"
	input.resource.id != ""
	input.project.state == "INTEGRATING"
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

tool_invoke_grant_allowed if {
	lease_grant_input_valid
	input.action == "tool.invoke"
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "GLOBAL_AUDITOR"
	input.project.state == "GLOBAL_AUDIT"
	global_auditor_read_tool_resource
}

tool_invoke_grant_allowed if {
	lease_grant_input_valid
	input.action == "tool.invoke"
	input.principal.type == "AGENT_INSTANCE"
	input.principal.role == "MODULE_AUDITOR"
	input.project.state == "EXECUTING"
	input.task.state == "LLM_AUDIT"
	global_auditor_read_tool_resource
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

integration_merge_grant_allowed if {
	lease_grant_input_valid
	input.action == "integration.merge"
	input.principal.type == "SERVICE"
	input.principal.role == "SERVICE"
	input.project.state == "INTEGRATING"
	input.resource.type == "integration"
	input.resource.id != ""
}

knowledge_write_grant_allowed if {
	lease_grant_input_valid
	knowledge_approval_valid
}

artifact_publish_grant_allowed if {
	lease_grant_input_valid
	artifact_approval_satisfied
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

lease_grant_allowed if {
	integration_merge_grant_allowed
}

lease_grant_allowed if {
	knowledge_write_grant_allowed
}

lease_grant_allowed if {
	artifact_publish_grant_allowed
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

lease_grant := {
	"decision": "APPROVAL_REQUIRED",
	"policyVersion": data.aor.policy.version,
	"reasonCodes": ["CURATOR_APPROVAL_REQUIRED"],
	"ruleId": "aor.approval.required",
} if {
	knowledge_write_request_valid
	not input.lease
	not input.approval.id
}

knowledge_write_approval_missing if {
	knowledge_write_request_valid
	not input.lease
	not input.approval.id
}

lease_grant := default_deny if {
	not lease_grant_allowed
	not knowledge_write_approval_missing
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

integration_merge_allowed if {
	valid_project_scope
	input.action == "integration.merge"
	input.principal.type == "SERVICE"
	input.principal.role == "SERVICE"
	input.project.state == "INTEGRATING"
	input.resource.type == "integration"
	input.resource.id != ""
	object.get(object.get(input, "task", {}), "id", "") == ""
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
	"reasonCodes": ["INTEGRATION_SERVICE_ALLOWED", "PROJECT_STATE_VALID"],
	"ruleId": "aor.integration.service.control",
} if {
	integration_service_control_allowed
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
	"reasonCodes": ["TRUSTED_SERVICE_ALLOWED", "PROJECT_STATE_VALID", "LEASE_VALID"],
	"ruleId": "aor.integration.merge",
	"constraints": {"expiresAt": input.lease.expiresAt},
} if {
	integration_merge_allowed
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
	"decision": "ALLOW",
	"policyVersion": data.aor.policy.version,
	"reasonCodes": ["TRUSTED_SERVICE_ALLOWED", "LEASE_VALID"],
	"ruleId": "aor.artifact.publish",
	"constraints": {"expiresAt": input.lease.expiresAt},
} if {
	artifact_publish_allowed
}

decision := {
    "decision": "APPROVAL_REQUIRED",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["CURATOR_APPROVAL_REQUIRED"],
    "ruleId": "aor.approval.required",
} if {
	knowledge_write_request_valid
    not input.approval.id
}

curator_missing_approval if {
	knowledge_write_request_valid
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
	integration_service_control_allowed
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
	integration_merge_allowed
}

matched if {
	tool_invoke_allowed
}

matched if {
	knowledge_write_request_valid
    not input.approval.id
}

matched if {
	knowledge_write_allowed
}

matched if {
	artifact_publish_allowed
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
	knowledge_write_allowed
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
