package aor.authz

import rego.v1

default decision := {
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
}

read_actions := {
    "goal.read",
    "plan.read",
    "task.read",
    "knowledge.read",
}

valid_scope if {
    input.principal.id != ""
    input.principal.type != ""
    input.project.tenantId != ""
    input.project.id != ""
    input.task.tenantId == input.project.tenantId
    input.principal.tenantId in {"", input.project.tenantId}
}

active_lease if {
    input.lease.id != ""
    input.lease.policyVersion == data.aor.policy.version
    input.lease.fencingToken > 0
    time.parse_rfc3339_ns(input.lease.expiresAt) > time.now_ns()
}

decision := {
    "decision": "ALLOW",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["ROLE_ALLOWED", "PROJECT_SCOPE_VALID"],
    "ruleId": "aor.read",
} if {
    valid_scope
    input.action in read_actions
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
    valid_scope
    input.action in {"repo.write", "repo.apply_patch"}
    input.principal.type == "AGENT_INSTANCE"
    input.principal.role == "EXECUTOR"
    input.project.state == "EXECUTING"
    input.task.state == "EXECUTING"
    active_lease
    some owned in input.task.ownedPaths
    glob.match(owned, ["/"], input.resource.path)
}

decision := {
    "decision": "APPROVAL_REQUIRED",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["CURATOR_APPROVAL_REQUIRED"],
    "ruleId": "aor.approval.required",
} if {
    valid_scope
    input.action == "knowledge.write"
    input.principal.role == "KNOWLEDGE_CURATOR"
    not input.approval.id
}

curator_missing_approval if {
    input.action == "knowledge.write"
    not input.approval.id
}

decision := {
    "decision": "ALLOW",
    "policyVersion": data.aor.policy.version,
    "reasonCodes": ["CURATOR_ALLOWED", "APPROVAL_VALID", "LEASE_VALID"],
    "ruleId": "aor.knowledge.write",
    "constraints": {"expiresAt": input.lease.expiresAt},
} if {
    valid_scope
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
    valid_scope
    input.action in side_effect_actions
    not active_lease
    not curator_missing_approval
}
