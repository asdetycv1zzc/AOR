package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akimisaka/aor/internal/artifact"
	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

func TestArtifactEvidenceStoreRoundTripImmutabilityAndTenantIsolation(t *testing.T) {
	catalog := newEvidenceCatalogFake()
	store, err := NewArtifactEvidenceStore(catalog, catalog)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bundle := testEvidenceBundle(t, "pipeline-v1")
	unsigned := bundle
	unsigned.Signature = nil
	if err := store.Put(ctx, "11111111-1111-4111-8111-111111111111", unsigned); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unsigned Put error = %v", err)
	}

	if err := store.Put(ctx, "11111111-1111-4111-8111-111111111111", bundle); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, "11111111-1111-4111-8111-111111111111", bundle); err != nil {
		t.Fatalf("idempotent Put: %v", err)
	}
	if catalog.publishCount != 1 {
		t.Fatalf("publish count = %d, want 1", catalog.publishCount)
	}

	got, found, err := store.Get(ctx, "11111111-1111-4111-8111-111111111111", bundle.ProjectID, bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt)
	if err != nil || !found || got.ManifestSHA256 != bundle.ManifestSHA256 {
		t.Fatalf("Get = (%+v, %t, %v)", got, found, err)
	}

	changed := testEvidenceBundle(t, "pipeline-v2")
	if err := store.Put(ctx, "11111111-1111-4111-8111-111111111111", changed); !errors.Is(err, ErrEvidenceConflict) {
		t.Fatalf("conflicting Put error = %v", err)
	}
	if _, found, err := store.Get(ctx, "22222222-2222-4222-8222-222222222222", bundle.ProjectID, bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt); err != nil || found {
		t.Fatalf("cross-tenant Get found = %t, error = %v", found, err)
	}
	if err := store.Put(ctx, "22222222-2222-4222-8222-222222222222", bundle); err != nil {
		t.Fatal(err)
	}
	if catalog.publications[0].ArtifactID == catalog.publications[1].ArtifactID {
		t.Fatal("artifact ID is not tenant-scoped")
	}
}

func TestArtifactEvidenceStoreRejectsTamperedBytes(t *testing.T) {
	catalog := newEvidenceCatalogFake()
	store, err := NewArtifactEvidenceStore(catalog, catalog)
	if err != nil {
		t.Fatal(err)
	}
	bundle := testEvidenceBundle(t, "pipeline-v1")
	tenantID := "11111111-1111-4111-8111-111111111111"
	if err := store.Put(context.Background(), tenantID, bundle); err != nil {
		t.Fatal(err)
	}

	key := catalogKey(tenantID, bundle.ProjectID, catalog.publications[0].ArtifactID)
	catalog.mu.Lock()
	item := catalog.items[key]
	item.data = append([]byte(nil), item.data...)
	item.data[len(item.data)/2] ^= 1
	catalog.items[key] = item
	catalog.mu.Unlock()

	if _, _, err := store.Get(context.Background(), tenantID, bundle.ProjectID, bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt); !errors.Is(err, artifact.ErrIntegrity) {
		t.Fatalf("tampered Get error = %v", err)
	}
}

func testEvidenceBundle(t *testing.T, pipelineVersion string) contracts.EvidenceBundle {
	t.Helper()
	bundle := contracts.EvidenceBundle{
		EvidenceBundleVersion: 1,
		ProjectID:             "33333333-3333-4333-8333-333333333333",
		TaskID:                "44444444-4444-4444-8444-444444444444",
		AttemptSeriesID:       "series-1",
		Attempt:               1,
		SpecVersion:           1,
		BaseCommit:            strings.Repeat("1", 40),
		SubmissionCommit:      strings.Repeat("2", 40),
		PipelineVersion:       pipelineVersion,
		PolicyBundleDigest:    "sha256:" + strings.Repeat("3", 64),
		ExecutionPlatform:     contracts.PlatformLinux,
		IsolationLevel:        contracts.IsolationContainer,
		SandboxAttestation:    "oci:test",
		Checks:                []contracts.EvidenceCheck{},
		Findings:              []string{},
		Artifacts:             []string{},
		Signature:             &contracts.Signature{Type: "TEST", KID: "audit-test", JWS: "test-signature"},
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle.ManifestSHA256, err = canonicaljson.DigestObjectWithoutFields(encoded, "manifestSha256", "signature")
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatal(err)
	}
	return bundle
}

type evidenceCatalogItem struct {
	record artifact.Record
	data   []byte
}

type evidenceCatalogFake struct {
	mu           sync.Mutex
	items        map[string]evidenceCatalogItem
	publications []artifact.Publication
	publishCount int
}

func newEvidenceCatalogFake() *evidenceCatalogFake {
	return &evidenceCatalogFake{items: make(map[string]evidenceCatalogItem)}
}

func (catalog *evidenceCatalogFake) Publish(_ context.Context, publication artifact.Publication) (artifact.Record, error) {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	catalog.publishCount++
	catalog.publications = append(catalog.publications, publication)
	key := catalogKey(publication.TenantID, publication.ProjectID, publication.ArtifactID)
	if existing, ok := catalog.items[key]; ok {
		if bytes.Equal(existing.data, publication.Data) {
			return existing.record, nil
		}
		return artifact.Record{}, artifact.ErrConflict
	}
	digest := evidenceBytesDigest(publication.Data)
	uri, _ := artifact.URIFromDigest(digest)
	metadata := make(map[string]any, len(publication.Metadata)+1)
	for key, value := range publication.Metadata {
		metadata[key] = value
	}
	metadata["taskId"] = publication.TaskID
	record := artifact.Record{
		ID:                 publication.ArtifactID,
		TenantID:           publication.TenantID,
		ProjectID:          publication.ProjectID,
		URI:                uri,
		SHA256:             digest,
		SizeBytes:          int64(len(publication.Data)),
		ContentType:        publication.ContentType,
		Classification:     "INTERNAL",
		CreatedByPrincipal: publication.CreatedByPrincipal,
		Metadata:           metadata,
		CreatedAt:          time.Now().UTC(),
	}
	catalog.items[key] = evidenceCatalogItem{record: record, data: append([]byte(nil), publication.Data...)}
	return record, nil
}

func (catalog *evidenceCatalogFake) Open(_ context.Context, tenantID, projectID, artifactID string) (artifact.Record, io.ReadCloser, error) {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	item, ok := catalog.items[catalogKey(tenantID, projectID, artifactID)]
	if !ok {
		return artifact.Record{}, nil, artifact.ErrNotFound
	}
	return item.record, io.NopCloser(bytes.NewReader(append([]byte(nil), item.data...))), nil
}

func catalogKey(tenantID, projectID, artifactID string) string {
	return tenantID + "\x00" + projectID + "\x00" + artifactID
}
