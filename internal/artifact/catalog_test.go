package artifact

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestArtifactURIRequiresCanonicalSHA256(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	uri, err := URIFromDigest(digest)
	if err != nil || uri != "artifact://sha256/"+strings.Repeat("a", 64) {
		t.Fatalf("uri=%q err=%v", uri, err)
	}
	parsedDigest, objectName, err := ParseURI(uri)
	if err != nil || parsedDigest != digest || objectName != "sha256/"+strings.Repeat("a", 64) {
		t.Fatalf("digest=%q object=%q err=%v", parsedDigest, objectName, err)
	}
	for _, invalid := range []string{
		"artifact://sha256/" + strings.Repeat("A", 64),
		"artifact://sha256/" + strings.Repeat("a", 63),
		"artifact://sha256/" + strings.Repeat("a", 64) + "?download=true",
		"https://example.test/" + strings.Repeat("a", 64),
	} {
		if _, _, err := ParseURI(invalid); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid URI %q error=%v", invalid, err)
		}
	}
}

func TestCatalogObjectNamesAreProjectScoped(t *testing.T) {
	tenantID := "11111111-1111-4111-8111-111111111111"
	digest := "sha256:" + strings.Repeat("a", 64)
	left := projectObjectName(tenantID, "22222222-2222-4222-8222-222222222222", digest)
	right := projectObjectName(tenantID, "33333333-3333-4333-8333-333333333333", digest)
	if left == right || !strings.HasPrefix(left, "tenants/"+tenantID+"/projects/") || !strings.HasSuffix(left, strings.Repeat("a", 64)) {
		t.Fatalf("project-scoped object names left=%q right=%q", left, right)
	}
}

func TestCatalogCursorIsProjectBoundAndStrict(t *testing.T) {
	projectID := "11111111-1111-4111-8111-111111111111"
	artifactID := "22222222-2222-4222-8222-222222222222"
	createdAt := time.Date(2030, 1, 2, 3, 4, 5, 6, time.UTC)
	cursor, err := encodeCatalogCursor(projectID, createdAt, artifactID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeCatalogCursor(projectID, cursor)
	if err != nil || decoded.ID != artifactID || decoded.ProjectID != projectID || decoded.CreatedAt != createdAt.Format(time.RFC3339Nano) {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	if _, err := decodeCatalogCursor("33333333-3333-4333-8333-333333333333", cursor); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("cross-project cursor error=%v", err)
	}
	if _, err := decodeCatalogCursor(projectID, cursor+"="); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("noncanonical cursor error=%v", err)
	}
}

func TestNewArtifactIDReturnsDistinctUUIDv7Values(t *testing.T) {
	first, err := newArtifactID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newArtifactID()
	if err != nil {
		t.Fatal(err)
	}
	firstUUID, firstErr := uuid.Parse(first)
	secondUUID, secondErr := uuid.Parse(second)
	if firstErr != nil || secondErr != nil || first == second || firstUUID.Version() != uuid.Version(7) || secondUUID.Version() != uuid.Version(7) {
		t.Fatalf("artifact IDs first=%q second=%q", first, second)
	}
}

func TestSameContentPublicationReusesProjectArtifact(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	uri, err := URIFromDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	left := Record{ID: "11111111-1111-7111-8111-111111111111", ProjectID: "11111111-1111-4111-8111-111111111111", URI: uri, SHA256: digest, SizeBytes: 12, ContentType: "application/json", Classification: "INTERNAL", CreatedByPrincipal: "agent-1", Metadata: map[string]any{"requestId": "one"}}
	right := left
	right.ID = "22222222-2222-7222-8222-222222222222"
	right.CreatedByPrincipal = "agent-2"
	right.Metadata = map[string]any{"requestId": "two"}
	if !samePublication(left, right) {
		t.Fatal("identical project content was not reusable")
	}
	right.ProjectID = "33333333-3333-4333-8333-333333333333"
	if samePublication(left, right) {
		t.Fatal("cross-project artifact metadata was reused")
	}
}

func TestPublicationRejectsUnsafeContentType(t *testing.T) {
	publication := Publication{
		TenantID:           "11111111-1111-4111-8111-111111111111",
		ProjectID:          "22222222-2222-4222-8222-222222222222",
		CreatedByPrincipal: "agent-1",
		ContentType:        "application/json",
	}
	if !validPublication(publication) {
		t.Fatal("valid publication was rejected")
	}
	publication.ContentType = " application/json"
	if validPublication(publication) {
		t.Fatal("whitespace-padded content type was accepted")
	}
	publication.ContentType = strings.Repeat("a", 257)
	if validPublication(publication) {
		t.Fatal("oversized content type was accepted")
	}
	publication.ContentType = "application/json"
	publication.IdempotencyKey = " key"
	if validPublication(publication) {
		t.Fatal("whitespace-padded idempotency key was accepted")
	}
	publication.IdempotencyKey = strings.Repeat("k", 257)
	if validPublication(publication) {
		t.Fatal("oversized idempotency key was accepted")
	}
}

func TestArtifactContentPolicyRejectsCredentialMaterial(t *testing.T) {
	secret := []byte("refresh_token=synthetic-production-credential")
	if err := validateContent(secret); !errors.Is(err, ErrCredentialDetected) {
		t.Fatalf("credential content error = %v", err)
	}
	if err := validateContent([]byte("deterministic audit output")); err != nil {
		t.Fatalf("ordinary artifact content error = %v", err)
	}
	metadata, err := json.Marshal(map[string]any{"authorization": "Bearer abcdefghijklmnopqrstuvwxyz"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateContent(metadata); !errors.Is(err, ErrCredentialDetected) {
		t.Fatalf("credential metadata error = %v", err)
	}
}

func TestRetentionRequiresTerminalProjectWithoutActiveLegalHold(t *testing.T) {
	tenantID := "11111111-1111-4111-8111-111111111111"
	projectID := "22222222-2222-4222-8222-222222222222"
	projection := retentionProjectProjection{
		TenantID: tenantID, ID: projectID, State: "COMPLETED", Version: 7,
	}
	content, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if !retentionProjectEligible(content, tenantID, projectID, "COMPLETED", 7, "") {
		t.Fatal("eligible terminal project was rejected")
	}
	if retentionProjectEligible(content, tenantID, projectID, "EXECUTING", 7, "") {
		t.Fatal("active project was eligible for retention purge")
	}
	if retentionProjectEligible(content, tenantID, projectID, "COMPLETED", 7, "READY") {
		t.Fatal("project deletion workflow was eligible for retention purge")
	}

	projection.LegalHolds = append(projection.LegalHolds, struct {
		ReleasedAt *time.Time `json:"releasedAt,omitempty"`
	}{})
	content, err = json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if retentionProjectEligible(content, tenantID, projectID, "COMPLETED", 7, "") {
		t.Fatal("active legal hold was eligible for retention purge")
	}

	releasedAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	projection.LegalHolds[0].ReleasedAt = &releasedAt
	content, err = json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	if !retentionProjectEligible(content, tenantID, projectID, "COMPLETED", 7, "") {
		t.Fatal("released legal hold still blocked retention purge")
	}
}
