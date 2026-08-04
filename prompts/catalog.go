// Package prompts loads the audited, versioned prompt baseline used by AOR.
package prompts

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/akimisaka/aor/internal/agentruntime"
)

const BaselineVersion = "1.0.0"

var ErrInvalidCatalog = errors.New("invalid prompt catalog")

//go:embed v1.0.0/catalog.json
var catalogFiles embed.FS

type catalog struct {
	Version      string                           `json:"version"`
	GlobalSafety string                           `json:"globalSafety"`
	Roles        map[agentruntime.Role]rolePrompt `json:"roles"`
}

type rolePrompt struct {
	RolePrompt    string `json:"rolePrompt"`
	FixedWorkflow string `json:"fixedWorkflow"`
	OutputRules   string `json:"outputRules"`
}

// LoadBaseline returns a fresh PromptBundle whose digest covers every prompt
// section. The source is an embedded, versioned repository artifact.
func LoadBaseline(role agentruntime.Role) (agentruntime.PromptBundle, error) {
	if !role.Valid() {
		return agentruntime.PromptBundle{}, ErrInvalidCatalog
	}
	content, err := catalogFiles.ReadFile("v1.0.0/catalog.json")
	if err != nil {
		return agentruntime.PromptBundle{}, ErrInvalidCatalog
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var source catalog
	if err := decoder.Decode(&source); err != nil {
		return agentruntime.PromptBundle{}, ErrInvalidCatalog
	}
	if err := requireJSONEOF(decoder); err != nil || source.Version != BaselineVersion || source.GlobalSafety == "" || len(source.Roles) != len(AllRoles()) {
		return agentruntime.PromptBundle{}, ErrInvalidCatalog
	}
	for _, requiredRole := range AllRoles() {
		if _, found := source.Roles[requiredRole]; !found {
			return agentruntime.PromptBundle{}, ErrInvalidCatalog
		}
	}
	roleSource, found := source.Roles[role]
	if !found {
		return agentruntime.PromptBundle{}, ErrInvalidCatalog
	}
	bundle := agentruntime.PromptBundle{
		BundleID:      "aor/" + string(role),
		Version:       source.Version,
		Role:          role,
		GlobalSafety:  source.GlobalSafety,
		RolePrompt:    roleSource.RolePrompt,
		FixedWorkflow: roleSource.FixedWorkflow,
		OutputRules:   roleSource.OutputRules,
	}
	bundle.SHA256 = agentruntime.DigestPromptBundle(bundle)
	if err := agentruntime.ValidatePromptBundle(bundle); err != nil {
		return agentruntime.PromptBundle{}, ErrInvalidCatalog
	}
	return bundle, nil
}

func AllRoles() []agentruntime.Role {
	roles := []agentruntime.Role{
		agentruntime.RoleGoalProposer,
		agentruntime.RoleGoalChallenger,
		agentruntime.RolePlanSupervisor,
		agentruntime.RoleModulePlanner,
		agentruntime.RoleExecutor,
		agentruntime.RoleModuleAuditor,
		agentruntime.RoleGlobalAuditor,
		agentruntime.RoleKnowledgeCurator,
	}
	sort.Slice(roles, func(left, right int) bool { return roles[left] < roles[right] })
	return roles
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalidCatalog
	}
	return nil
}
