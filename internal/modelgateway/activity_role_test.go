package modelgateway

import (
	"testing"

	"github.com/akimisaka/aor/internal/projectactivity"
)

func TestCommandReviewerDoesNotAcceptInterventions(t *testing.T) {
	if activityRequestAcceptsInterventions(NormalizedRequest{Role: "EXECUTOR", Model: CommandReviewModel, PromptBundleVersion: CommandReviewPromptVersion}, projectactivity.FlowExecution) {
		t.Fatal("command reviewer must not claim executor interventions")
	}
	if !activityRequestAcceptsInterventions(NormalizedRequest{Role: "EXECUTOR", Model: CommandReviewModel, PromptBundleVersion: "executor-v1"}, projectactivity.FlowExecution) {
		t.Fatal("executor interventions must remain enabled")
	}
	if !activityRequestAcceptsInterventions(NormalizedRequest{Role: "EXECUTOR", Model: "gpt-5.6-sol", PromptBundleVersion: CommandReviewPromptVersion}, projectactivity.FlowExecution) {
		t.Fatal("prompt version alone must not identify a command reviewer")
	}
	if role := activityDisplayRole(NormalizedRequest{Role: "EXECUTOR", Model: CommandReviewModel, PromptBundleVersion: CommandReviewPromptVersion}); role != "COMMAND_REVIEWER" {
		t.Fatalf("display role=%q", role)
	}
}
