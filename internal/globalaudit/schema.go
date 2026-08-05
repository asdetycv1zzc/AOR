package globalaudit

import "encoding/json"

const DecisionSchemaReference = "https://schemas.aor.local/global-audit-decision.v1.schema.json"

var decisionSchema = json.RawMessage(`{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://schemas.aor.local/global-audit-decision.v1.schema.json",
  "type":"object",
  "additionalProperties":false,
  "required":["verdict","focusResults","criteriaResults","findings","residualRisks","confidence"],
  "properties":{
    "verdict":{"enum":["PASS","FAIL","INCONCLUSIVE"]},
    "focusResults":{
      "type":"array","minItems":6,"maxItems":6,
      "items":{
        "type":"object","additionalProperties":false,
        "required":["area","status","evidenceRefs"],
        "properties":{
          "area":{"enum":["CROSS_MODULE_ARCHITECTURE","GOAL_COVERAGE","SECURITY_AND_DATA_FLOW","DEPLOYMENT_MIGRATION_ROLLBACK_OPERATIONS","SYSTEM_TEST_GAPS","RESIDUAL_RISK"]},
          "status":{"enum":["PASS","FAIL","INCONCLUSIVE"]},
          "evidenceRefs":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":4096}}
        }
      }
    },
    "criteriaResults":{
      "type":"array","minItems":1,
      "items":{
        "type":"object","additionalProperties":false,
        "required":["criterionId","status","evidenceRefs"],
        "properties":{
          "criterionId":{"type":"string","minLength":1,"maxLength":4096},
          "status":{"enum":["PASS","FAIL","NOT_TESTED"]},
          "evidenceRefs":{"type":"array","minItems":1,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":4096}}
        }
      }
    },
    "findings":{
      "type":"array",
      "items":{
        "type":"object","additionalProperties":false,
        "required":["severity","category","ruleId","file","lineStart","lineEnd","status","semanticLocation","evidencePattern","evidenceRefs","expectedBehavior","observedBehavior","remediationConstraint"],
        "properties":{
          "findingId":{"type":"string"},
          "stableFingerprint":{"type":"string"},
          "severity":{"enum":["INFO","LOW","MEDIUM","HIGH","CRITICAL"]},
          "category":{"type":"string","minLength":1,"maxLength":4096},
          "ruleId":{"type":"string","minLength":1,"maxLength":4096},
          "file":{"type":"string","maxLength":4096},
          "lineStart":{"type":"integer","minimum":0},
          "lineEnd":{"type":"integer","minimum":0},
          "status":{"enum":["OPEN","FIXED","ACCEPTED","FALSE_POSITIVE"]},
          "semanticLocation":{"type":"string","minLength":1,"maxLength":4096},
          "evidencePattern":{"type":"string","minLength":1,"maxLength":4096},
          "evidenceRefs":{"type":"array","uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":4096}},
          "expectedBehavior":{"type":"string","minLength":1,"maxLength":16384},
          "observedBehavior":{"type":"string","minLength":1,"maxLength":16384},
          "remediationConstraint":{"type":"string","minLength":1,"maxLength":16384}
        }
      }
    },
    "residualRisks":{"type":"array","uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":4096}},
    "confidence":{"type":"number","minimum":0,"maximum":1}
  }
}`)

func DecisionSchema() json.RawMessage {
	return append(json.RawMessage(nil), decisionSchema...)
}
