package artifact

import (
	"errors"
	"strings"
	"testing"
	"time"
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

func TestDeterministicArtifactIDIsStableUUID(t *testing.T) {
	first := deterministicArtifactID("tenant", "project", "artifact://sha256/"+strings.Repeat("0", 64))
	second := deterministicArtifactID("tenant", "project", "artifact://sha256/"+strings.Repeat("0", 64))
	if first != second || !uuidValuePattern.MatchString(first) {
		t.Fatalf("artifact IDs first=%q second=%q", first, second)
	}
}

func TestSameContentPublicationReusesProjectArtifact(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	uri, err := URIFromDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	left := Record{ProjectID: "11111111-1111-4111-8111-111111111111", URI: uri, SHA256: digest, SizeBytes: 12, ContentType: "application/json", Classification: "INTERNAL", CreatedByPrincipal: "agent-1", Metadata: map[string]any{"requestId": "one"}}
	right := left
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
}
