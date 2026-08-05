package audit

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/akimisaka/aor/internal/artifact"
)

const maximumAuditOutputBytes = 64 << 20

type catalogArtifactPublisher struct {
	publisher artifact.Publisher
}

func NewCatalogArtifactPublisher(publisher artifact.Publisher) (ArtifactPublisher, error) {
	if publisher == nil {
		return nil, ErrArtifactStore
	}
	return &catalogArtifactPublisher{publisher: publisher}, nil
}

func (publisher *catalogArtifactPublisher) Put(ctx context.Context, request artifact.PutRequest, produce func(io.Writer) error) (artifact.Manifest, error) {
	if publisher == nil || publisher.publisher == nil || ctx == nil || ctx.Err() != nil || produce == nil {
		return artifact.Manifest{}, ErrArtifactStore
	}
	output := &limitedAuditBuffer{remaining: maximumAuditOutputBytes}
	if err := produce(output); err != nil {
		return artifact.Manifest{}, err
	}
	record, err := publisher.publisher.Publish(ctx, artifact.Publication{
		TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		IdempotencyKey:     auditPublicationKey("audit-check-output", request.TaskID, request.ArtifactID),
		CreatedByPrincipal: request.CreatedBy, ContentType: request.MediaType,
		Metadata: map[string]any{"kind": "audit-check-output", "sourceArtifactId": request.ArtifactID, "retentionPolicy": request.RetentionPolicy, "encrypted": request.Encrypted},
		Data:     output.Bytes(),
	})
	if err != nil {
		return artifact.Manifest{}, err
	}
	return artifact.Manifest{
		Version: 1, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID,
		ArtifactID: request.ArtifactID, URI: record.URI, SHA256: record.SHA256, Size: record.SizeBytes,
		MediaType: request.MediaType, CreatedBy: request.CreatedBy, RetentionPolicy: request.RetentionPolicy,
		Encrypted: request.Encrypted, CreatedAt: record.CreatedAt,
	}, nil
}

type limitedAuditBuffer struct {
	bytes.Buffer
	remaining int
}

func (buffer *limitedAuditBuffer) Write(value []byte) (int, error) {
	if len(value) > buffer.remaining {
		return 0, errors.Join(ErrArtifactStore, artifact.ErrInvalidRequest)
	}
	written, err := buffer.Buffer.Write(value)
	buffer.remaining -= written
	return written, err
}

var _ ArtifactPublisher = (*catalogArtifactPublisher)(nil)
