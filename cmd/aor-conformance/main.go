package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/akimisaka/aor/internal/bootstrap"
	aorconformance "github.com/akimisaka/aor/internal/conformance"
	contractcheck "github.com/akimisaka/aor/internal/contracts"
	"github.com/akimisaka/aor/internal/state"
	"github.com/akimisaka/aor/internal/supplychain"
	"github.com/akimisaka/aor/internal/version"
)

type result struct {
	Check    string              `json:"check"`
	Status   string              `json:"status"`
	Findings []bootstrap.Finding `json:"findings,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fail("usage", []bootstrap.Finding{{Code: "INVALID_ARGUMENT", Message: "usage: aor-conformance <check> or run --profile <test|preproduction|production> --spec-version <version> [--target <url> --output <directory> --driver-manifest <file> --driver-public-key <file>]"}})
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
	driverManifest := os.Getenv("AOR_CONFORMANCE_DRIVER_MANIFEST")
	driverPublicKey := os.Getenv("AOR_CONFORMANCE_DRIVER_PUBLIC_KEY_FILE")
	releaseVersion := version.Version
	sourceCommit := version.Commit
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
		case "--release-version":
			releaseVersion = value
		case "--source-commit":
			sourceCommit = value
		case "--output":
			output = value
		case "--driver-manifest":
			driverManifest = value
		case "--driver-public-key":
			driverPublicKey = value
		case "--groups":
			groups = strings.Split(value, ",")
		default:
			fail("run", []bootstrap.Finding{{Code: "INVALID_ARGUMENT", Message: arguments[index]}})
		}
		index++
	}
	signer, signerErr := releaseSigner(profile)
	if signerErr != nil {
		fail("run", []bootstrap.Finding{{Code: "SIGNER_INVALID", Message: signerErr.Error()}})
	}
	runner := aorconformance.NewRunner(nil)
	var externalDriver *aorconformance.ExternalDriverConfig
	if driverManifest != "" {
		externalDriver = &aorconformance.ExternalDriverConfig{ManifestPath: driverManifest, PublicKeyPath: driverPublicKey}
	}
	evidence, err := runner.Run(context.Background(), aorconformance.Request{Root: root, Target: target, Profile: profile, SpecVersion: specVersion, ReleaseVersion: releaseVersion, SourceCommit: sourceCommit, OutputDir: output, Groups: groups, Signer: signer, ExternalDriver: externalDriver})
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
		message := err.Error()
		if len(evidence.Exceptions) > 0 {
			message += ": " + strings.Join(evidence.Exceptions, "; ")
		}
		fail("run", []bootstrap.Finding{{Code: "CONFORMANCE_FAILED", Path: output, Message: message}})
	}
	os.Stdout.Write(append(encoded, '\n'))
}

func releaseSigner(profile string) (aorconformance.Signer, error) {
	privateKeyPath := os.Getenv("AOR_RELEASE_SIGNING_PRIVATE_KEY_FILE")
	if privateKeyPath != "" {
		info, err := os.Lstat(privateKeyPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("release private key must be an owner-only regular file")
		}
		value, err := os.ReadFile(privateKeyPath)
		if err != nil {
			return nil, err
		}
		privateKey, err := supplychain.ParsePrivateKey(value)
		if err != nil {
			return nil, err
		}
		kid := os.Getenv("AOR_RELEASE_SIGNING_KID")
		if kid == "" {
			return nil, errors.New("AOR_RELEASE_SIGNING_KID is required with a private key")
		}
		return aorconformance.NewEd25519Signer(privateKey, kid)
	}
	if key := os.Getenv("AOR_RELEASE_SIGNING_KEY"); key != "" {
		if profile == "production" {
			return nil, errors.New("production requires AOR_RELEASE_SIGNING_PRIVATE_KEY_FILE or an injected KMS signer; HMAC is local-only")
		}
		return aorconformance.NewHMACSigner([]byte(key))
	}
	return nil, nil
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
