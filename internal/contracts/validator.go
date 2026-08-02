package contracts

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/akimisaka/aor/pkg/cloudevents"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type Finding struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

type fixtureManifest struct {
	Cases []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Name     string `json:"name"`
	Schema   string `json:"schema"`
	Instance string `json:"instance"`
	Valid    bool   `json:"valid"`
}

type schemaResource struct {
	Path string
	ID   string
	Doc  any
}

func ValidateRepositoryContracts(root string) []Finding {
	resources, findings := loadSchemas(root)
	if len(findings) != 0 {
		return sorted(findings)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	compiled := make(map[string]*jsonschema.Schema, len(resources))
	for _, resource := range resources {
		if err := compiler.AddResource(resource.ID, resource.Doc); err != nil {
			findings = append(findings, Finding{Code: "SCHEMA_RESOURCE_INVALID", Path: resource.Path, Message: err.Error()})
		}
	}
	if len(findings) != 0 {
		return sorted(findings)
	}
	for _, resource := range resources {
		schema, err := compiler.Compile(resource.ID)
		if err != nil {
			findings = append(findings, Finding{Code: "SCHEMA_COMPILE_FAILED", Path: resource.Path, Message: err.Error()})
			continue
		}
		compiled[filepath.ToSlash(resource.Path)] = schema
	}
	findings = append(findings, validateFixtures(root, compiled)...)
	findings = append(findings, validateEventCatalog(root)...)
	findings = append(findings, validateErrorCatalog(root)...)
	findings = append(findings, validateAPIDocuments(root)...)
	findings = append(findings, validateTraceability(root)...)
	return sorted(findings)
}

func loadSchemas(root string) ([]schemaResource, []Finding) {
	apiRoot := filepath.Join(root, "api")
	var resources []schemaResource
	var findings []Finding
	_ = filepath.WalkDir(apiRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			findings = append(findings, Finding{Code: "SCHEMA_WALK_FAILED", Path: relative(root, path), Message: walkErr.Error()})
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			findings = append(findings, Finding{Code: "SCHEMA_READ_FAILED", Path: relative(root, path), Message: err.Error()})
			return nil
		}
		doc, decodeErr := jsonschema.UnmarshalJSON(file)
		closeErr := file.Close()
		if decodeErr != nil {
			findings = append(findings, Finding{Code: "SCHEMA_JSON_INVALID", Path: relative(root, path), Message: decodeErr.Error()})
			return nil
		}
		if closeErr != nil {
			findings = append(findings, Finding{Code: "SCHEMA_READ_FAILED", Path: relative(root, path), Message: closeErr.Error()})
			return nil
		}
		object, ok := doc.(map[string]any)
		id, hasID := object["$id"].(string)
		if !ok || !hasID || id == "" {
			findings = append(findings, Finding{Code: "SCHEMA_ID_MISSING", Path: relative(root, path), Message: "schema requires a unique $id"})
			return nil
		}
		resources = append(resources, schemaResource{Path: relative(root, path), ID: id, Doc: doc})
		return nil
	})
	sort.Slice(resources, func(i, j int) bool { return resources[i].Path < resources[j].Path })
	return resources, findings
}

func validateFixtures(root string, schemas map[string]*jsonschema.Schema) []Finding {
	manifestPath := filepath.Join(root, "conformance", "contracts", "fixtures.json")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return []Finding{{Code: "FIXTURE_MANIFEST_MISSING", Path: relative(root, manifestPath), Message: err.Error()}}
	}
	var manifest fixtureManifest
	if err := json.Unmarshal(content, &manifest); err != nil {
		return []Finding{{Code: "FIXTURE_MANIFEST_INVALID", Path: relative(root, manifestPath), Message: err.Error()}}
	}
	var findings []Finding
	for _, test := range manifest.Cases {
		schema := schemas[filepath.ToSlash(test.Schema)]
		if schema == nil {
			findings = append(findings, Finding{Code: "FIXTURE_SCHEMA_UNKNOWN", Path: test.Schema, Message: test.Name})
			continue
		}
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(test.Instance)))
		if err != nil {
			findings = append(findings, Finding{Code: "FIXTURE_READ_FAILED", Path: test.Instance, Message: err.Error()})
			continue
		}
		value, decodeErr := jsonschema.UnmarshalJSON(file)
		closeErr := file.Close()
		if decodeErr != nil || closeErr != nil {
			findings = append(findings, Finding{Code: "FIXTURE_JSON_INVALID", Path: test.Instance, Message: firstError(decodeErr, closeErr).Error()})
			continue
		}
		validationErr := schema.Validate(value)
		if test.Valid && validationErr != nil {
			findings = append(findings, Finding{Code: "VALID_FIXTURE_REJECTED", Path: test.Instance, Message: validationErr.Error()})
		}
		if !test.Valid && validationErr == nil {
			findings = append(findings, Finding{Code: "INVALID_FIXTURE_ACCEPTED", Path: test.Instance, Message: test.Name})
		}
	}
	return findings
}

func validateEventCatalog(root string) []Finding {
	path := filepath.Join(root, "api", "cloudevents", "catalog.v1.json")
	content, err := os.ReadFile(path)
	if err != nil {
		return []Finding{{Code: "EVENT_CATALOG_MISSING", Path: relative(root, path), Message: err.Error()}}
	}
	var catalog struct {
		Events map[string]string `json:"events"`
	}
	if err := json.Unmarshal(content, &catalog); err != nil {
		return []Finding{{Code: "EVENT_CATALOG_INVALID", Path: relative(root, path), Message: err.Error()}}
	}
	return compareStringMaps("EVENT_CATALOG_DRIFT", relative(root, path), cloudevents.Catalog, catalog.Events)
}

func validateErrorCatalog(root string) []Finding {
	path := filepath.Join(root, "api", "errors", "catalog.v1.json")
	content, err := os.ReadFile(path)
	if err != nil {
		return []Finding{{Code: "ERROR_CATALOG_MISSING", Path: relative(root, path), Message: err.Error()}}
	}
	var catalog struct {
		Errors []struct {
			Code       aorerrors.Code `json:"code"`
			HTTPStatus int            `json:"httpStatus"`
			Retryable  bool           `json:"retryable"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(content, &catalog); err != nil {
		return []Finding{{Code: "ERROR_CATALOG_INVALID", Path: relative(root, path), Message: err.Error()}}
	}
	seen := make(map[aorerrors.Code]bool)
	var findings []Finding
	for _, entry := range catalog.Errors {
		meta := aorerrors.MetadataFor(entry.Code)
		if seen[entry.Code] || meta.HTTPStatus != entry.HTTPStatus || meta.Retryable != entry.Retryable {
			findings = append(findings, Finding{Code: "ERROR_CATALOG_DRIFT", Path: relative(root, path), Message: string(entry.Code)})
		}
		seen[entry.Code] = true
	}
	for _, code := range aorerrors.AllCodes() {
		if !seen[code] {
			findings = append(findings, Finding{Code: "ERROR_CATALOG_MISSING_CODE", Path: relative(root, path), Message: string(code)})
		}
	}
	return findings
}

func validateAPIDocuments(root string) []Finding {
	checks := []struct {
		path     string
		required []string
	}{
		{path: "api/openapi/aor.v1.yaml", required: []string{"openapi: 3.2.0", "Idempotency-Key", "If-Match", "ETag", "/v1/projects/{projectId}:approve-release", "/v1/projects/{projectId}:request-deletion", "/v1/projects/{projectId}/export"}},
		{path: "api/asyncapi/aor-events.v1.yaml", required: []string{"asyncapi: 3.1.0", "application/cloudevents+json", "projectDeadLetters", "aggregateVersion"}},
	}
	var findings []Finding
	for _, check := range checks {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(check.path)))
		if err != nil {
			findings = append(findings, Finding{Code: "API_DOCUMENT_MISSING", Path: check.path, Message: err.Error()})
			continue
		}
		var document map[string]any
		if err := yaml.Unmarshal(content, &document); err != nil {
			findings = append(findings, Finding{Code: "API_DOCUMENT_INVALID", Path: check.path, Message: err.Error()})
			continue
		}
		for _, required := range check.required {
			if !strings.Contains(string(content), required) {
				findings = append(findings, Finding{Code: "API_DOCUMENT_INCOMPLETE", Path: check.path, Message: required})
			}
		}
	}
	return findings
}

func validateTraceability(root string) []Finding {
	path := filepath.Join(root, "conformance", "requirements.yaml")
	content, err := os.ReadFile(path)
	if err != nil {
		return []Finding{{Code: "TRACEABILITY_MISSING", Path: relative(root, path), Message: err.Error()}}
	}
	var catalog struct {
		Requirements []struct {
			ID             string   `yaml:"id"`
			Implementation []string `yaml:"implementation"`
			Tests          []string `yaml:"tests"`
			Status         string   `yaml:"status"`
		} `yaml:"requirements"`
	}
	if err := yaml.Unmarshal(content, &catalog); err != nil {
		return []Finding{{Code: "TRACEABILITY_INVALID", Path: relative(root, path), Message: err.Error()}}
	}
	var findings []Finding
	for _, requirement := range catalog.Requirements {
		if requirement.Status != "planned" && requirement.Status != "implemented" && requirement.Status != "retired" {
			findings = append(findings, Finding{Code: "TRACEABILITY_STATUS_INVALID", Path: relative(root, path), Message: requirement.ID})
		}
		if requirement.Status != "implemented" {
			continue
		}
		if len(requirement.Implementation) == 0 || len(requirement.Tests) == 0 {
			findings = append(findings, Finding{Code: "TRACEABILITY_EVIDENCE_EMPTY", Path: relative(root, path), Message: requirement.ID})
			continue
		}
		for _, evidencePath := range append(append([]string(nil), requirement.Implementation...), requirement.Tests...) {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(evidencePath))); err != nil {
				findings = append(findings, Finding{Code: "TRACEABILITY_PATH_MISSING", Path: evidencePath, Message: requirement.ID})
			}
		}
	}
	return findings
}

func compareStringMaps(code, path string, expected, actual map[string]string) []Finding {
	var findings []Finding
	for key, value := range expected {
		if actual[key] != value {
			findings = append(findings, Finding{Code: code, Path: path, Message: key})
		}
	}
	for key := range actual {
		if _, exists := expected[key]; !exists {
			findings = append(findings, Finding{Code: code, Path: path, Message: key})
		}
	}
	return findings
}

func firstError(values ...error) error {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return fmt.Errorf("unknown error")
}

func relative(root, path string) string {
	value, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(value)
}

func sorted(findings []Finding) []Finding {
	sort.Slice(findings, func(i, j int) bool {
		left := findings[i].Code + "\x00" + findings[i].Path + "\x00" + findings[i].Message
		right := findings[j].Code + "\x00" + findings[j].Path + "\x00" + findings[j].Message
		return left < right
	})
	return findings
}
