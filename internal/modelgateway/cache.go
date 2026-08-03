package modelgateway

import (
	"encoding/json"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type CacheKeyInput struct {
	TenantID           string `json:"tenantId"`
	ProjectID          string `json:"projectId"`
	ModelVersion       string `json:"modelVersion"`
	PromptBundleDigest string `json:"promptBundleDigest"`
	ToolSchemaDigest   string `json:"toolSchemaDigest"`
	PolicyDigest       string `json:"policyDigest"`
	DataClassification string `json:"dataClassification"`
	PrefixDigest       string `json:"prefixDigest"`
	DynamicDigest      string `json:"dynamicDigest"`
}

func CacheKey(input CacheKeyInput) (string, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}
