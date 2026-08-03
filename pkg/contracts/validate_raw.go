package contracts

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

func ValidateGoalJSON(input []byte) error {
	canonical, err := canonicaljson.Canonicalize(input)
	if err != nil {
		return err
	}
	var envelope struct {
		Content       json.RawMessage `json:"content"`
		ContentSHA256 string          `json:"contentSha256"`
	}
	if err := json.Unmarshal(canonical, &envelope); err != nil || len(envelope.Content) == 0 {
		return fmt.Errorf("goal envelope is invalid")
	}
	digest, err := canonicaljson.Digest(envelope.Content)
	if err != nil {
		return err
	}
	if !sameDigest(digest, envelope.ContentSHA256) {
		return fmt.Errorf("goal content digest mismatch")
	}
	var goal GoalSpec
	if err := json.Unmarshal(canonical, &goal); err != nil {
		return fmt.Errorf("decode GoalSpec: %w", err)
	}
	return goal.Validate()
}

func ValidatePlanJSON(input []byte) error {
	canonical, err := canonicaljson.Canonicalize(input)
	if err != nil {
		return err
	}
	var plan PlanSpec
	if err := json.Unmarshal(canonical, &plan); err != nil {
		return fmt.Errorf("decode PlanSpec: %w", err)
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(canonical, "sha256", "signature")
	if err != nil {
		return err
	}
	if !sameDigest(digest, plan.SHA256) {
		return fmt.Errorf("plan digest mismatch")
	}
	return nil
}

func ValidateModuleJSON(input []byte) error {
	canonical, err := canonicaljson.Canonicalize(input)
	if err != nil {
		return err
	}
	var module ModuleSpec
	if err := json.Unmarshal(canonical, &module); err != nil {
		return fmt.Errorf("decode ModuleSpec: %w", err)
	}
	if err := module.Validate(); err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(canonical, "sha256", "signature")
	if err != nil {
		return err
	}
	if !sameDigest(digest, module.SHA256) {
		return fmt.Errorf("module digest mismatch")
	}
	return nil
}

func ValidateSubmissionJSON(input []byte) error {
	canonical, err := canonicaljson.Canonicalize(input)
	if err != nil {
		return err
	}
	var manifest SubmissionManifest
	if err := json.Unmarshal(canonical, &manifest); err != nil {
		return fmt.Errorf("decode Submission Manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(canonical, "sha256", "signature")
	if err != nil {
		return err
	}
	if !sameDigest(digest, manifest.SHA256) {
		return fmt.Errorf("submission manifest digest mismatch")
	}
	return nil
}

func ValidateEvidenceJSON(input []byte) error {
	canonical, err := canonicaljson.Canonicalize(input)
	if err != nil {
		return err
	}
	var bundle EvidenceBundle
	if err := json.Unmarshal(canonical, &bundle); err != nil {
		return fmt.Errorf("decode Evidence Bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(canonical, "manifestSha256", "signature")
	if err != nil {
		return err
	}
	if !sameDigest(digest, bundle.ManifestSHA256) {
		return fmt.Errorf("evidence manifest digest mismatch")
	}
	return nil
}

func sameDigest(expected, actual string) bool {
	if len(expected) != len(actual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}
