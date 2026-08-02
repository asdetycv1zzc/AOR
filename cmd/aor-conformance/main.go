package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/akimisaka/aor/internal/bootstrap"
)

type result struct {
	Check    string              `json:"check"`
	Status   string              `json:"status"`
	Findings []bootstrap.Finding `json:"findings,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage", []bootstrap.Finding{{Code: "INVALID_ARGUMENT", Message: "usage: aor-conformance <source-format|schemas|repository|secrets|licenses>"}})
	}
	root, err := os.Getwd()
	if err != nil {
		fail(os.Args[1], []bootstrap.Finding{{Code: "WORKDIR_ERROR", Message: err.Error()}})
	}

	check := os.Args[1]
	var findings []bootstrap.Finding
	switch check {
	case "source-format":
		findings = bootstrap.CheckGoFormat(root)
	case "schemas":
		findings = bootstrap.ValidateJSONDocuments(root)
	case "repository":
		findings = append(findings, bootstrap.ValidateRepository(root)...)
		findings = append(findings, bootstrap.ValidateADRs(root, 25)...)
		findings = append(findings, bootstrap.ValidateSourceMarkers(root)...)
		spec, specErr := os.ReadFile(filepath.Join(root, "SPEC.md"))
		catalog, catalogErr := os.ReadFile(filepath.Join(root, "conformance", "requirements.yaml"))
		if specErr != nil {
			findings = append(findings, bootstrap.Finding{Code: "SPEC_READ_ERROR", Path: "SPEC.md", Message: specErr.Error()})
		}
		if catalogErr != nil {
			findings = append(findings, bootstrap.Finding{Code: "CATALOG_READ_ERROR", Path: "conformance/requirements.yaml", Message: catalogErr.Error()})
		}
		if specErr == nil && catalogErr == nil {
			findings = append(findings, bootstrap.ValidateRequirementCatalog(spec, catalog)...)
		}
	case "secrets":
		findings = bootstrap.ScanSecrets(root)
	case "licenses":
		findings = bootstrap.ValidateLicenseBaseline(root)
	default:
		findings = []bootstrap.Finding{{Code: "UNKNOWN_CHECK", Message: check}}
	}

	if len(findings) != 0 {
		fail(check, findings)
	}
	write(result{Check: check, Status: "PASS"})
}

func fail(check string, findings []bootstrap.Finding) {
	write(result{Check: check, Status: "FAIL", Findings: findings})
	os.Exit(1)
}

func write(value result) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
