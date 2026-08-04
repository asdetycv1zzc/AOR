package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/akimisaka/aor/internal/bootstrap"
	aorconformance "github.com/akimisaka/aor/internal/conformance"
	contractcheck "github.com/akimisaka/aor/internal/contracts"
	"github.com/akimisaka/aor/internal/state"
)

type result struct {
	Check    string              `json:"check"`
	Status   string              `json:"status"`
	Findings []bootstrap.Finding `json:"findings,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fail("usage", []bootstrap.Finding{{Code: "INVALID_ARGUMENT", Message: "usage: aor-conformance <check> or run --profile <test|preproduction|production> --spec-version <version>"}})
	}
	root, err := os.Getwd()
	if err != nil {
		fail(os.Args[1], []bootstrap.Finding{{Code: "WORKDIR_ERROR", Message: err.Error()}})
	}

	check := os.Args[1]
	if check == "run" {
		runConformance(root, os.Args[2:])
		return
	}
	if len(os.Args) != 2 {
		fail("usage", []bootstrap.Finding{{Code: "INVALID_ARGUMENT", Message: "single-check mode accepts exactly one check"}})
	}
	var findings []bootstrap.Finding
	switch check {
	case "source-format":
		findings = bootstrap.CheckGoFormat(root)
	case "schemas":
		findings = bootstrap.ValidateJSONDocuments(root)
		findings = append(findings, convertContractFindings(contractcheck.ValidateRepositoryContracts(root))...)
	case "contracts", "aop", "a2a", "cloudevents", "openapi", "asyncapi":
		findings = convertContractFindings(contractcheck.ValidateRepositoryContracts(root))
	case "state-machine":
		for _, err := range state.Conformance() {
			findings = append(findings, bootstrap.Finding{Code: "STATE_CONFORMANCE_FAILED", Path: "conformance/state-machine/core.feature", Message: err.Error()})
		}
	case "repository":
		findings = append(findings, bootstrap.ValidateRepository(root)...)
		findings = append(findings, bootstrap.ValidateRunbooks(root)...)
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
			findings = append(findings, bootstrap.ValidateRequirementCatalogAt(root, spec, catalog)...)
		}
	case "secrets":
		findings = bootstrap.ScanSecrets(root)
	case "security-corpus":
		findings = bootstrap.ValidateSecurityCorpus(root)
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

func runConformance(root string, arguments []string) {
	profile := "test"
	specVersion := "2.0.0"
	target := ""
	output := ""
	groups := []string{}
	for index := 0; index < len(arguments); index++ {
		if index+1 >= len(arguments) {
			fail("run", []bootstrap.Finding{{Code: "INVALID_ARGUMENT", Message: arguments[index]}})
		}
		value := arguments[index+1]
		switch arguments[index] {
		case "--profile":
			profile = value
		case "--spec-version":
			specVersion = value
		case "--target":
			target = value
		case "--output":
			output = value
		case "--groups":
			groups = strings.Split(value, ",")
		default:
			fail("run", []bootstrap.Finding{{Code: "INVALID_ARGUMENT", Message: arguments[index]}})
		}
		index++
	}
	var signer aorconformance.Signer
	if key := os.Getenv("AOR_RELEASE_SIGNING_KEY"); key != "" {
		created, err := aorconformance.NewHMACSigner([]byte(key))
		if err != nil {
			fail("run", []bootstrap.Finding{{Code: "SIGNER_INVALID", Message: err.Error()}})
		}
		signer = created
	}
	runner := aorconformance.NewRunner(nil)
	evidence, err := runner.Run(context.Background(), aorconformance.Request{Root: root, Target: target, Profile: profile, SpecVersion: specVersion, OutputDir: output, Groups: groups, Signer: signer})
	encoded, marshalErr := json.Marshal(result{Check: "run", Status: "PASS"})
	if marshalErr != nil {
		os.Exit(2)
	}
	if output != "" {
		encoded, _ = json.Marshal(struct {
			Check    string `json:"check"`
			Status   string `json:"status"`
			Evidence string `json:"evidence"`
		}{Check: "run", Status: "PASS", Evidence: filepath.Join(output, "release-evidence.json")})
	}
	if err != nil {
		fail("run", []bootstrap.Finding{{Code: "CONFORMANCE_FAILED", Path: output, Message: err.Error()}})
	}
	os.Stdout.Write(append(encoded, '\n'))
	_ = evidence
}

func convertContractFindings(input []contractcheck.Finding) []bootstrap.Finding {
	output := make([]bootstrap.Finding, 0, len(input))
	for _, finding := range input {
		output = append(output, bootstrap.Finding{Code: finding.Code, Path: finding.Path, Message: finding.Message})
	}
	return output
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
