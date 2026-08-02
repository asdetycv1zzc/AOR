package errors

import (
	stderrors "errors"
	"testing"
)

func TestProblemNeverExposesWrappedCauseOrUnsafeDetails(t *testing.T) {
	cause := stderrors.New("provider credential and /private/path")
	err := Wrap(CodePolicyDenied, "corr_1", cause, map[string]any{"policyVersion": "pol_2", "internalPath": "/private/path"})
	problem := err.Problem()
	if problem.Error.Message != MetadataFor(CodePolicyDenied).Message {
		t.Fatalf("message = %q", problem.Error.Message)
	}
	if _, exists := problem.Error.Details["internalPath"]; exists {
		t.Fatal("unsafe detail was exposed")
	}
	if problem.Error.Details["policyVersion"] != "pol_2" {
		t.Fatal("safe detail was removed")
	}
	if !stderrors.Is(err, cause) {
		t.Fatal("wrapped cause should remain available in-process")
	}
}

func TestEveryCodeHasPublicMetadata(t *testing.T) {
	for _, code := range AllCodes() {
		metadata := MetadataFor(code)
		if metadata.Message == "" || metadata.HTTPStatus < 400 || metadata.HTTPStatus > 599 {
			t.Fatalf("invalid metadata for %s: %#v", code, metadata)
		}
	}
}
