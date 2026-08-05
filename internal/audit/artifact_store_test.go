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
	"github.com/google/uuid"
)

func TestArtifactEvidenceStoreRoundTripImmutabilityAndTenantIsolation(t *testing.T) {
	catalog := newEvidenceCatalogFake()
	store, err := NewArtifactEvidenceStore(catalog, catalog)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bundle := testEvidenceBundle(t, "1.0.0")
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

	restarted, err := NewArtifactEvidenceStore(catalog, catalog)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := restarted.Get(ctx, "11111111-1111-4111-8111-111111111111", bundle.ProjectID, bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt)
	if err != nil || !found || got.ManifestSHA256 != bundle.ManifestSHA256 {
		t.Fatalf("Get = (%+v, %t, %v)", got, found, err)
	}

	changed := testEvidenceBundle(t, "1.0.1")
	if err := store.Put(ctx, "11111111-1111-4111-8111-111111111111", changed); !errors.Is(err, ErrEvidenceConflict) {
		t.Fatalf("conflicting Put error = %v", err)
	}
	if _, found, err := store.Get(ctx, "22222222-2222-4222-8222-222222222222", bundle.ProjectID, bundle.TaskID, bundle.AttemptSeriesID, bundle.Attempt); err != nil || found {
		t.Fatalf("cross-tenant Get found = %t, error = %v", found, err)
	}
	if err := store.Put(ctx, "22222222-2222-4222-8222-222222222222", bundle); err != nil {
		t.Fatal(err)
	}
	firstID, firstErr := uuid.Parse(catalog.artifactIDs[0])
	secondID, secondErr := uuid.Parse(catalog.artifactIDs[1])
	if firstErr != nil || secondErr != nil || firstID.Version() != uuid.Version(7) || secondID.Version() != uuid.Version(7) || firstID == secondID {
		t.Fatalf("artifact IDs = %q and %q", catalog.artifactIDs[0], catalog.artifactIDs[1])
	}
	if catalog.publications[0].ArtifactID != "" || catalog.publications[1].ArtifactID != "" {
		t.Fatal("evidence store supplied a predictable artifact primary key")
	}
	if catalog.publications[0].IdempotencyKey == "" || catalog.publications[0].IdempotencyKey != catalog.publications[1].IdempotencyKey {
		t.Fatal("artifact ID is not tenant-scoped")
	}
}

func TestArtifactEvidenceStoreRejectsTamperedBytes(t *testing.T) {
	catalog := newEvidenceCatalogFake()
	store, err := NewArtifactEvidenceStore(catalog, catalog)
	if err != nil {
		t.Fatal(err)
	}
	bundle := testEvidenceBundle(t, "1.0.0")
	tenantID := "11111111-1111-4111-8111-111111111111"
	if err := store.Put(context.Background(), tenantID, bundle); err != nil {
		t.Fatal(err)
	}

	key := catalogKey(tenantID, bundle.ProjectID, catalog.artifactIDs[0])
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
	finding, err := contracts.CanonicalAuditFinding(contracts.AuditFinding{
		Severity:              contracts.FindingHigh,
		Category:              "DETERMINISTIC",
		RuleID:                "test-check",
		Status:                contracts.FindingOpen,
		SemanticLocation:      "test-check",
		EvidencePattern:       "failed-check",
		EvidenceRefs:          []string{},
		ExpectedBehavior:      "test check passes",
		ObservedBehavior:      "test check failed",
		RemediationConstraint: "fix the test check",
	})
	if err != nil {
		t.Fatal(err)
	}
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
		Checks: []contracts.EvidenceCheck{{
			CheckID: "test-check", Ordinal: 1, Type: "DETERMINISTIC", Status: "FAIL",
			Tool:      contracts.CheckTool{Name: "aor-audit", Version: pipelineVersion, Digest: "sha256:" + strings.Repeat("4", 64)},
			StartedAt: "2030-01-01T00:00:00Z", CompletedAt: "2030-01-01T00:00:01Z",
			StdoutURI: "artifact://empty", StderrURI: "artifact://empty", ResultURI: "artifact://empty", ResultSHA256: "sha256:" + strings.Repeat("5", 64),
		}},
		Findings:        []contracts.AuditFinding{finding},
		CriteriaResults: []contracts.CriterionResult{},
		ResidualRisks:   []string{},
		Confidence:      0,
		Artifacts:       []string{},
		LLMAudit:        contracts.LLMAudit{Verdict: "NOT_RUN"},
		Signature:       &contracts.Signature{Type: "HMAC-SHA256", KID: "audit-test", JWS: "hmac-sha256:" + strings.Repeat("0", 64)},
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
	keys         map[string]string
	publications []artifact.Publication
	artifactIDs  []string
	publishCount int
}

func newEvidenceCatalogFake() *evidenceCatalogFake {
	return &evidenceCatalogFake{items: make(map[string]evidenceCatalogItem), keys: make(map[string]string)}
}

func (catalog *evidenceCatalogFake) Publish(_ context.Context, publication artifact.Publication) (artifact.Record, error) {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	catalog.publishCount++
	catalog.publications = append(catalog.publications, publication)
	bindingKey := catalogKey(publication.TenantID, publication.ProjectID, publication.IdempotencyKey)
	if artifactID, ok := catalog.keys[bindingKey]; ok {
		existing := catalog.items[catalogKey(publication.TenantID, publication.ProjectID, artifactID)]
		if bytes.Equal(existing.data, publication.Data) {
			return existing.record, nil
		}
		return artifact.Record{}, artifact.ErrConflict
	}
	artifactID := publication.ArtifactID
	if artifactID == "" {
		generated, err := uuid.NewV7()
		if err != nil {
			return artifact.Record{}, err
		}
		artifactID = generated.String()
	}
	catalog.artifactIDs = append(catalog.artifactIDs, artifactID)
	key := catalogKey(publication.TenantID, publication.ProjectID, artifactID)
	digest := evidenceBytesDigest(publication.Data)
	uri, _ := artifact.URIFromDigest(digest)
	metadata := make(map[string]any, len(publication.Metadata)+1)
	for key, value := range publication.Metadata {
		metadata[key] = value
	}
	metadata["taskId"] = publication.TaskID
	record := artifact.Record{
		ID:                 artifactID,
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
	catalog.keys[bindingKey] = artifactID
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

func (catalog *evidenceCatalogFake) OpenByIdempotencyKey(_ context.Context, tenantID, projectID, key string) (artifact.Record, io.ReadCloser, error) {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	artifactID, ok := catalog.keys[catalogKey(tenantID, projectID, key)]
	if !ok {
		return artifact.Record{}, nil, artifact.ErrNotFound
	}
	item, ok := catalog.items[catalogKey(tenantID, projectID, artifactID)]
	if !ok {
		return artifact.Record{}, nil, artifact.ErrNotFound
	}
	return item.record, io.NopCloser(bytes.NewReader(append([]byte(nil), item.data...))), nil
}

func catalogKey(tenantID, projectID, artifactID string) string {
	return tenantID + "\x00" + projectID + "\x00" + artifactID
}
