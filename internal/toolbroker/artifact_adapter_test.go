package toolbroker

import (
	"context"
	"testing"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
)

type recordingArtifactPublisher struct {
	publication artifact.Publication
}

func (publisher *recordingArtifactPublisher) Publish(_ context.Context, publication artifact.Publication) (artifact.Record, error) {
	publisher.publication = publication
	return artifact.Record{URI: "artifact://sha256/" + "1f" + "00000000000000000000000000000000000000000000000000000000000000", SHA256: "sha256:" + "1f" + "00000000000000000000000000000000000000000000000000000000000000", SizeBytes: int64(len(publication.Data)), ContentType: publication.ContentType}, nil
}

func TestArtifactPublisherBindsToolInvocationMetadata(t *testing.T) {
	recorder := &recordingArtifactPublisher{}
	publisher, err := NewArtifactPublisher(recorder)
	if err != nil {
		t.Fatal(err)
	}
	request := ToolRequest{
		RequestID: "request-1", TenantID: "11111111-1111-4111-8111-111111111111",
		ProjectID: "22222222-2222-4222-8222-222222222222", TaskID: "33333333-3333-4333-8333-333333333333",
		Principal: Principal{ID: "agent-1", Type: string(authn.PrincipalAgentInstance), Role: authn.RoleExecutor},
		ToolID:    "repository.read", Version: "1.0.0",
	}
	ctx, err := authn.ContextWithPrincipal(context.Background(), authn.Principal{ID: request.Principal.ID, Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: request.TenantID, ProjectID: request.ProjectID})
	if err != nil {
		t.Fatal(err)
	}
	result, err := publisher.Put(ctx, request, []byte(`{"ok":true}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if result.URI == "" || result.SHA256 == "" || recorder.publication.TenantID != request.TenantID || recorder.publication.ProjectID != request.ProjectID || recorder.publication.TaskID != request.TaskID || recorder.publication.CreatedByPrincipal != request.Principal.ID {
		t.Fatalf("result=%#v publication=%#v", result, recorder.publication)
	}
	if recorder.publication.Metadata["invocationId"] != stableInvocationID(request) || recorder.publication.Metadata["requestId"] != request.RequestID {
		t.Fatalf("metadata=%#v", recorder.publication.Metadata)
	}
}

func TestArtifactPublisherRejectsMismatchedAuthenticatedScope(t *testing.T) {
	publisher, err := NewArtifactPublisher(&recordingArtifactPublisher{})
	if err != nil {
		t.Fatal(err)
	}
	request := ToolRequest{TenantID: "11111111-1111-4111-8111-111111111111", ProjectID: "22222222-2222-4222-8222-222222222222", Principal: Principal{ID: "agent-1"}}
	ctx, err := authn.ContextWithPrincipal(context.Background(), authn.Principal{ID: "agent-2", Type: authn.PrincipalAgentInstance, Role: authn.RoleExecutor, TenantID: request.TenantID, ProjectID: request.ProjectID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisher.Put(ctx, request, []byte(`{}`), "application/json"); err != ErrInvalidRequest {
		t.Fatalf("error=%v", err)
	}
}
