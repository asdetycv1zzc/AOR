package goalplan

import "encoding/json"

type agentResponseSchema struct {
	Reference string
	Document  json.RawMessage
}

func responseSchemaFor(stage string) (agentResponseSchema, error) {
	var schema agentResponseSchema
	switch stage {
	case "GOAL_DRAFT", "GOAL_REVISION":
		schema = agentResponseSchema{Reference: "urn:aor:goalplan:goal-draft:v1", Document: json.RawMessage(goalDraftSchema)}
	case "GOAL_CHALLENGE":
		schema = agentResponseSchema{Reference: "urn:aor:goalplan:goal-challenge:v1", Document: json.RawMessage(goalChallengeSchema)}
	case "PLAN_DRAFT":
		schema = agentResponseSchema{Reference: "urn:aor:goalplan:plan-draft:v1", Document: json.RawMessage(planDraftSchema)}
	case "PLAN_SUMMARY":
		schema = agentResponseSchema{Reference: "urn:aor:goalplan:plan-summary:v1", Document: json.RawMessage(planSummarySchema)}
	case "MODULE_SPEC":
		schema = agentResponseSchema{Reference: "urn:aor:goalplan:module-draft:v1", Document: json.RawMessage(moduleDraftSchema)}
	case "KNOWLEDGE_UPDATE_DRAFT":
		schema = agentResponseSchema{Reference: "urn:aor:knowledge:update-draft:v1", Document: json.RawMessage(knowledgeUpdateDraftSchema)}
	default:
		return agentResponseSchema{}, ErrInvalidRequest
	}
	schema.Document = append(json.RawMessage(nil), schema.Document...)
	return schema, nil
}

const goalDraftSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["title", "summary", "problemStatement", "businessOutcomes", "scope", "userPersonas", "functionalRequirements", "nonFunctionalRequirements", "constraints", "assumptions", "decisions", "unresolvedItems", "acceptanceCriteria", "riskTolerance", "humanApprovalPoints", "dataClassification", "deploymentTargets", "sourceReferences"],
  "properties": {
    "title": {"type": "string", "minLength": 1, "maxLength": 256},
    "summary": {"type": "string", "minLength": 1, "maxLength": 4096},
    "problemStatement": {"type": "string", "minLength": 1, "maxLength": 16384},
    "businessOutcomes": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"$ref": "#/$defs/statement"}},
    "scope": {
      "type": "object",
      "additionalProperties": false,
      "required": ["included", "excluded"],
      "properties": {"included": {"$ref": "#/$defs/strings"}, "excluded": {"$ref": "#/$defs/strings"}}
    },
    "userPersonas": {"$ref": "#/$defs/strings"},
    "functionalRequirements": {"$ref": "#/$defs/strings"},
    "nonFunctionalRequirements": {
      "type": "object",
      "additionalProperties": false,
      "required": ["security", "privacy", "performance", "reliability", "operability"],
      "properties": {
        "security": {"$ref": "#/$defs/strings"},
        "privacy": {"$ref": "#/$defs/strings"},
        "performance": {"$ref": "#/$defs/strings"},
        "reliability": {"$ref": "#/$defs/strings"},
        "operability": {"$ref": "#/$defs/strings"}
      }
    },
    "constraints": {"$ref": "#/$defs/strings"},
    "assumptions": {"type": "array", "maxItems": 1000, "items": {"$ref": "#/$defs/assumption"}},
    "decisions": {"$ref": "#/$defs/strings"},
    "unresolvedItems": {"description": "Substantive unresolved requirements or decisions only. Do not include pending approval or a request for approval; use an empty array when substantive decisions are resolved.", "$ref": "#/$defs/strings"},
    "acceptanceCriteria": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"$ref": "#/$defs/criterion"}},
    "riskTolerance": {"enum": ["LOW", "MEDIUM", "HIGH"]},
    "humanApprovalPoints": {"$ref": "#/$defs/strings"},
    "dataClassification": {"enum": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]},
    "deploymentTargets": {"$ref": "#/$defs/strings"},
    "sourceReferences": {"$ref": "#/$defs/strings"}
  },
  "$defs": {
    "strings": {"type": "array", "maxItems": 1000, "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "statement": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "statement"],
      "properties": {"id": {"type": "string", "minLength": 1, "maxLength": 128}, "statement": {"type": "string", "minLength": 1, "maxLength": 4096}}
    },
    "assumption": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "statement", "status"],
      "properties": {
        "id": {"type": "string", "minLength": 1, "maxLength": 128},
        "statement": {"type": "string", "minLength": 1, "maxLength": 4096},
        "status": {"enum": ["OPEN", "CONFIRMED", "REJECTED"]}
      }
    },
    "criterion": {
      "type": "object",
      "additionalProperties": false,
      "required": ["id", "statement", "evidenceType"],
      "properties": {
        "id": {"type": "string", "minLength": 1, "maxLength": 128},
        "statement": {"type": "string", "minLength": 1, "maxLength": 4096},
        "evidenceType": {"enum": ["AUTOMATED", "USER_APPROVAL", "EXTERNAL_CERTIFICATION"]}
      }
    }
  }
}`

const goalChallengeSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["findings"],
  "properties": {
    "findings": {
      "type": "array",
      "maxItems": 1000,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["severity", "affectedClause", "evidence", "question"],
        "properties": {
          "severity": {"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
          "affectedClause": {"type": "string", "minLength": 1, "maxLength": 4096},
          "evidence": {"type": "string", "minLength": 1, "maxLength": 16384},
          "question": {"type": "string", "minLength": 1, "maxLength": 4096}
        }
      }
    }
  }
}`

const planDraftSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["architecture", "qualityAttributes", "modules", "integrationPlan", "releasePlan", "testStrategy", "rollbackStrategy", "openDecisions"],
  "properties": {
    "architecture": {
      "type": "object",
      "additionalProperties": false,
      "required": ["style", "components", "dataFlows", "trustBoundaries", "deploymentUnits"],
      "properties": {
        "style": {"type": "string", "minLength": 1, "maxLength": 256},
        "components": {"$ref": "#/$defs/strings"},
        "dataFlows": {"$ref": "#/$defs/strings"},
        "trustBoundaries": {"$ref": "#/$defs/strings"},
        "deploymentUnits": {"$ref": "#/$defs/strings"}
      }
    },
    "qualityAttributes": {"$ref": "#/$defs/strings"},
    "modules": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"$ref": "#/$defs/module"}},
    "integrationPlan": {"$ref": "#/$defs/strings"},
    "releasePlan": {"$ref": "#/$defs/strings"},
    "testStrategy": {"$ref": "#/$defs/strings"},
    "rollbackStrategy": {"$ref": "#/$defs/strings"},
    "openDecisions": {"type": "array", "maxItems": 0}
  },
  "$defs": {
    "strings": {"type": "array", "maxItems": 4096, "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "module": {
      "type": "object",
      "additionalProperties": false,
      "required": ["moduleId", "name", "responsibility", "executionPlatform", "sandboxLevel", "ownedPaths", "forbiddenPaths", "publicInterfaces", "dependencies", "acceptanceCriteria", "risk"],
      "properties": {
        "moduleId": {"type": "string", "pattern": "^(?:[A-Za-z][A-Za-z0-9_-]{2,127}|[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$"},
        "name": {"type": "string", "minLength": 1, "maxLength": 128},
        "responsibility": {"type": "string", "minLength": 1, "maxLength": 4096},
        "executionPlatform": {"enum": ["LINUX", "WINDOWS"]},
        "sandboxLevel": {"enum": ["CONTAINER", "NONE"]},
        "ownedPaths": {"type": "array", "minItems": 1, "maxItems": 4096, "items": {"type": "string", "minLength": 1, "maxLength": 4096, "not": {"enum": [".", ".."]}, "description": "Concrete repository-relative file or directory path. Never use '.', '..', an absolute path, or traversal; list root-level files individually."}},
        "forbiddenPaths": {"$ref": "#/$defs/strings"},
        "publicInterfaces": {"$ref": "#/$defs/strings"},
        "dependencies": {"type": "array", "maxItems": 1000, "items": {"type": "string", "minLength": 1, "maxLength": 128}},
        "acceptanceCriteria": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
        "risk": {"enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]}
      },
      "allOf": [
        {"if": {"properties": {"executionPlatform": {"const": "LINUX"}}, "required": ["executionPlatform"]}, "then": {"properties": {"sandboxLevel": {"const": "CONTAINER"}}}},
        {"if": {"properties": {"executionPlatform": {"const": "WINDOWS"}}, "required": ["executionPlatform"]}, "then": {"properties": {"sandboxLevel": {"const": "NONE"}}}}
      ]
    }
  }
}`

const moduleDraftSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["purpose", "responsibilities", "nonResponsibilities", "inputs", "outputs", "dataOwnership", "networkPolicy", "workloadProfile", "toolCapabilities", "knowledgeRefs", "testRequirements", "observabilityRequirements", "securityRequirements", "budget"],
  "properties": {
    "purpose": {"type": "string", "minLength": 1, "maxLength": 4096},
    "responsibilities": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "nonResponsibilities": {"$ref": "#/$defs/strings"},
    "inputs": {"$ref": "#/$defs/strings"},
    "outputs": {"$ref": "#/$defs/strings"},
    "dataOwnership": {"$ref": "#/$defs/strings"},
    "networkPolicy": {
      "type": "object",
      "additionalProperties": false,
      "required": ["mode", "destinations"],
      "properties": {
        "mode": {"enum": ["DENY_ALL", "ALLOWLIST", "UNRESTRICTED"]},
        "destinations": {"$ref": "#/$defs/strings"}
      }
    },
    "workloadProfile": {
      "type": "object",
      "additionalProperties": false,
      "required": ["trust", "hostileMultiTenant", "requiresNetworkIsolation", "requiresHiddenTestConfidentiality"],
      "properties": {
        "trust": {"enum": ["TRUSTED", "UNTRUSTED"]},
        "hostileMultiTenant": {"type": "boolean"},
        "requiresNetworkIsolation": {"type": "boolean"},
        "requiresHiddenTestConfidentiality": {"type": "boolean"}
      }
    },
    "toolCapabilities": {"$ref": "#/$defs/strings"},
    "knowledgeRefs": {"type": "array", "maxItems": 1000, "description": "Exact existing Knowledge Service paths only. Use an empty array when no knowledge is required; do not put explanatory prose here.", "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "testRequirements": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "observabilityRequirements": {"$ref": "#/$defs/strings"},
    "securityRequirements": {"type": "array", "minItems": 1, "maxItems": 1000, "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
    "budget": {
      "type": "object",
      "additionalProperties": false,
      "required": ["maxInputTokens", "maxOutputTokens", "maxCost", "currency"],
      "properties": {
        "maxInputTokens": {"type": "integer", "minimum": 1},
        "maxOutputTokens": {"type": "integer", "minimum": 1},
        "maxCost": {"type": "string", "pattern": "^[0-9]+(?:\\.[0-9]{1,6})?$"},
        "currency": {"type": "string", "pattern": "^[A-Z]{3}$"}
      }
    }
  },
  "$defs": {
    "strings": {"type": "array", "maxItems": 1000, "items": {"type": "string", "minLength": 1, "maxLength": 4096}}
  }
}`

const planSummarySchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["overview", "modules", "crossModuleFindings", "recommendedNextActions"],
  "properties": {
    "overview": {"type": "string", "minLength": 1, "maxLength": 8192},
    "modules": {
      "type": "array",
      "minItems": 1,
      "maxItems": 1000,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["moduleId", "summary"],
        "properties": {
          "moduleId": {"type": "string", "minLength": 1, "maxLength": 128},
          "summary": {"type": "string", "minLength": 1, "maxLength": 8192}
        }
      }
    },
    "crossModuleFindings": {
      "type": "array",
      "maxItems": 1000,
      "items": {"type": "string", "minLength": 1, "maxLength": 8192}
    },
    "recommendedNextActions": {
      "type": "array",
      "maxItems": 1000,
      "items": {"type": "string", "minLength": 1, "maxLength": 8192}
    }
  }
}`

const knowledgeUpdateDraftSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["baseRevision", "parentOrderExplicit", "parents", "overrides", "documents", "deletePaths", "changeSummary"],
  "properties": {
    "baseRevision": {"type": "string", "pattern": "^(?:|sha256:[0-9a-f]{64})$"},
    "parentOrderExplicit": {"type": "boolean"},
    "parents": {
      "type": "array",
      "maxItems": 32,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["projectId", "revision", "order"],
        "properties": {
          "projectId": {"type": "string", "minLength": 1, "maxLength": 256},
          "revision": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
          "order": {"type": "integer", "minimum": 0, "maximum": 31}
        }
      }
    },
    "overrides": {"$ref": "#/$defs/paths"},
    "documents": {
      "type": "array",
      "maxItems": 1000,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["path", "title", "tags", "trustLevel", "contentType", "content"],
        "properties": {
          "path": {"$ref": "#/$defs/path"},
          "title": {"type": "string", "minLength": 1, "maxLength": 512},
          "tags": {"type": "array", "maxItems": 128, "items": {"type": "string", "minLength": 1, "maxLength": 128}},
          "trustLevel": {"enum": ["CURATED", "PROJECT_APPROVED", "GENERATED_UNREVIEWED", "EXTERNAL_UNTRUSTED"]},
          "contentType": {"type": "string", "minLength": 1, "maxLength": 256},
          "content": {"type": "string", "minLength": 1, "maxLength": 262144}
        }
      }
    },
    "deletePaths": {"$ref": "#/$defs/paths"},
    "changeSummary": {"type": "string", "minLength": 1, "maxLength": 8192}
  },
  "$defs": {
    "path": {"type": "string", "pattern": "^(?:inherited|requirements|architecture|modules|interfaces|decisions|prompts|workflows|tools|security|operations|lessons)/.+$", "maxLength": 4096},
    "paths": {"type": "array", "maxItems": 4096, "items": {"$ref": "#/$defs/path"}}
  }
}`
