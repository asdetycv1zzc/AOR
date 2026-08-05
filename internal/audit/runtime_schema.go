package audit

import "encoding/json"

const ModuleAuditDecisionSchemaReference = "https://schemas.aor.local/module-audit-decision.v1.schema.json"

var moduleAuditDecisionSchema = json.RawMessage(`{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"https://schemas.aor.local/module-audit-decision.v1.schema.json",
  "type":"object","additionalProperties":false,
  "required":["auditorRunId","modelIdentity","promptDigest","contextDigest","verdict","findings","criteriaResults","residualRisks","confidence"],
  "properties":{
    "auditorRunId":{"type":"string","minLength":1,"maxLength":256},
    "modelIdentity":{"type":"string","minLength":1,"maxLength":512},
    "promptDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
    "contextDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
    "verdict":{"enum":["PASS","FAIL","INCONCLUSIVE"]},
    "findings":{"type":"array","items":{"$ref":"#/$defs/finding"}},
    "criteriaResults":{"type":"array","items":{"$ref":"#/$defs/criterion"}},
    "residualRisks":{"type":"array","items":{"type":"string","minLength":1,"maxLength":4096}},
    "confidence":{"type":"number","minimum":0,"maximum":1}
  },
  "$defs":{
    "finding":{"type":"object","additionalProperties":false,
      "required":["findingId","stableFingerprint","severity","category","ruleId","file","lineStart","lineEnd","status","semanticLocation","evidencePattern","evidenceRefs","expectedBehavior","observedBehavior","remediationConstraint"],
      "properties":{
        "findingId":{"type":"string","minLength":1,"maxLength":256},"stableFingerprint":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$"},
        "severity":{"enum":["INFO","LOW","MEDIUM","HIGH","CRITICAL"]},"category":{"type":"string","minLength":1,"maxLength":4096},"ruleId":{"type":"string","minLength":1,"maxLength":4096},"file":{"type":"string","maxLength":4096},"lineStart":{"type":"integer","minimum":0},"lineEnd":{"type":"integer","minimum":0},"status":{"enum":["OPEN","FIXED","ACCEPTED","FALSE_POSITIVE"]},"semanticLocation":{"type":"string","minLength":1,"maxLength":4096},"evidencePattern":{"type":"string","minLength":1,"maxLength":4096},"evidenceRefs":{"type":"array","items":{"type":"string","minLength":1,"maxLength":4096},"uniqueItems":true},"expectedBehavior":{"type":"string","minLength":1,"maxLength":16384},"observedBehavior":{"type":"string","minLength":1,"maxLength":16384},"remediationConstraint":{"type":"string","minLength":1,"maxLength":16384}
      }},
    "criterion":{"type":"object","additionalProperties":false,"required":["criterionId","status","evidenceRefs"],"properties":{"criterionId":{"type":"string","minLength":1,"maxLength":4096},"status":{"enum":["PASS","FAIL","NOT_TESTED"]},"evidenceRefs":{"type":"array","items":{"type":"string","minLength":1,"maxLength":4096},"uniqueItems":true}}}
  }
}`)

func ModuleAuditDecisionSchema() json.RawMessage {
	return append(json.RawMessage(nil), moduleAuditDecisionSchema...)
}
