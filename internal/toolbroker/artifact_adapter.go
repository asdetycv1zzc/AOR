package toolbroker

import (
	"context"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/internal/authn"
)

type ArtifactPublisher struct {
	publisher artifact.Publisher
}

func NewArtifactPublisher(publisher artifact.Publisher) (*ArtifactPublisher, error) {
	if publisher == nil {
		return nil, ErrInvalidRequest
	}
	return &ArtifactPublisher{publisher: publisher}, nil
}

func (publisher *ArtifactPublisher) Put(ctx context.Context, request ToolRequest, data []byte, mediaType string) (ArtifactRef, error) {
	principal, ok := authn.PrincipalFromContext(ctx)
	if publisher == nil || publisher.publisher == nil || !ok || principal.ID != request.Principal.ID || principal.TenantID != "" && principal.TenantID != request.TenantID || principal.ProjectID != "" && principal.ProjectID != request.ProjectID {
		return ArtifactRef{}, ErrInvalidRequest
	}
	record, err := publisher.publisher.Publish(ctx, artifact.Publication{
		TenantID:           request.TenantID,
		ProjectID:          request.ProjectID,
		TaskID:             request.TaskID,
		CreatedByPrincipal: request.Principal.ID,
		ContentType:        mediaType,
		Metadata: map[string]any{
			"source":       "tool-output",
			"requestId":    request.RequestID,
			"toolId":       request.ToolID,
			"toolVersion":  request.Version,
			"invocationId": stableInvocationID(request),
		},
		Data: append([]byte(nil), data...),
	})
	if err != nil {
		return ArtifactRef{}, ErrInvocationRecord
	}
	return ArtifactRef{URI: record.URI, SHA256: record.SHA256, Size: record.SizeBytes, MediaType: record.ContentType}, nil
}

var _ ArtifactStore = (*ArtifactPublisher)(nil)
