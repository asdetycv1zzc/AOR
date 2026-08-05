package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/google/uuid"
)

func TestCatalogArtifactPublisherUsesDurableKeyAndGeneratedPrimaryID(t *testing.T) {
	backend := newKeyedPublisherFake()
	publisher, err := NewCatalogArtifactPublisher(backend)
	if err != nil {
		t.Fatal(err)
	}
	request := artifact.PutRequest{
		TenantID: "11111111-1111-4111-8111-111111111111", ProjectID: "22222222-2222-4222-8222-222222222222",
		TaskID: "33333333-3333-4333-8333-333333333333", ArtifactID: "unit-test-stdout", MediaType: "text/plain",
		CreatedBy: "aor-audit-service", RetentionPolicy: "audit", Encrypted: true,
	}
	write := func(output io.Writer) error {
		_, err := output.Write([]byte("stable output"))
		return err
	}
	first, err := publisher.Put(context.Background(), request, write)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := publisher.Put(context.Background(), request, write)
	if err != nil || replayed.URI != first.URI || replayed.CreatedAt != first.CreatedAt {
		t.Fatalf("replay = %#v, %v", replayed, err)
	}
	if len(backend.publications) != 2 || backend.publications[0].ArtifactID != "" || backend.publications[0].IdempotencyKey == "" || backend.publications[0].IdempotencyKey != backend.publications[1].IdempotencyKey {
		t.Fatalf("publications = %#v", backend.publications)
	}
	generated, err := uuid.Parse(backend.records[backend.publications[0].IdempotencyKey].ID)
	if err != nil || generated.Version() != uuid.Version(7) {
		t.Fatalf("generated artifact ID = %q", generated)
	}
	_, err = publisher.Put(context.Background(), request, func(output io.Writer) error {
		_, writeErr := output.Write([]byte("changed output"))
		return writeErr
	})
	if !errors.Is(err, artifact.ErrConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
}

type keyedPublisherFake struct {
	publications []artifact.Publication
	records      map[string]artifact.Record
	data         map[string][]byte
}

func newKeyedPublisherFake() *keyedPublisherFake {
	return &keyedPublisherFake{records: make(map[string]artifact.Record), data: make(map[string][]byte)}
}

func (publisher *keyedPublisherFake) Publish(_ context.Context, publication artifact.Publication) (artifact.Record, error) {
	publisher.publications = append(publisher.publications, publication)
	if record, ok := publisher.records[publication.IdempotencyKey]; ok {
		if bytes.Equal(publisher.data[publication.IdempotencyKey], publication.Data) {
			return record, nil
		}
		return artifact.Record{}, artifact.ErrConflict
	}
	id, err := uuid.NewV7()
	if err != nil {
		return artifact.Record{}, err
	}
	digest := evidenceBytesDigest(publication.Data)
	uri, err := artifact.URIFromDigest(digest)
	if err != nil {
		return artifact.Record{}, err
	}
	record := artifact.Record{
		ID: id.String(), TenantID: publication.TenantID, ProjectID: publication.ProjectID, URI: uri,
		SHA256: digest, SizeBytes: int64(len(publication.Data)), ContentType: publication.ContentType,
		Classification: "INTERNAL", CreatedByPrincipal: publication.CreatedByPrincipal,
		Metadata: publication.Metadata, CreatedAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	publisher.records[publication.IdempotencyKey] = record
	publisher.data[publication.IdempotencyKey] = append([]byte(nil), publication.Data...)
	return record, nil
}
