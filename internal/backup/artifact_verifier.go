package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/akimisaka/aor/internal/artifact"
)

var (
	ErrArtifactRecordMismatch  = errors.New("backup artifact catalog record mismatch")
	ErrArtifactContentMismatch = errors.New("backup artifact content mismatch")
)

// CatalogArtifactVerifier checks both the catalog row and the immutable object
// addressed by that row. The catalog remains responsible for authorization,
// object-store addressing, and its own metadata checks.
type CatalogArtifactVerifier struct {
	catalog artifact.Catalog
}

func NewCatalogArtifactVerifier(catalog artifact.Catalog) (*CatalogArtifactVerifier, error) {
	if catalog == nil {
		return nil, ErrInvalidSnapshot
	}
	return &CatalogArtifactVerifier{catalog: catalog}, nil
}

func (verifier *CatalogArtifactVerifier) Verify(ctx context.Context, expected ArtifactRecord) error {
	if verifier == nil || verifier.catalog == nil || ctx == nil || expected.TenantID == "" || expected.ProjectID == "" || expected.ID == "" {
		return ErrInvalidSnapshot
	}
	actual, reader, err := verifier.catalog.Open(ctx, expected.TenantID, expected.ProjectID, expected.ID)
	if err != nil {
		return err
	}
	if reader == nil {
		return ErrArtifactRecordMismatch
	}

	actualErr := compareArtifactRecord(actual, expected)
	digest := sha256.New()
	bytesRead, readErr := io.Copy(digest, reader)
	closeErr := reader.Close()
	if actualErr != nil {
		return actualErr
	}
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	actualDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
	if bytesRead != expected.Size || actualDigest != expected.SHA256 {
		return fmt.Errorf("%w: artifact %s", ErrArtifactContentMismatch, expected.ID)
	}
	return nil
}

func compareArtifactRecord(actual artifact.Record, expected ArtifactRecord) error {
	if actual.ID != expected.ID || actual.TenantID != expected.TenantID || actual.ProjectID != expected.ProjectID || actual.URI != expected.URI || actual.SHA256 != expected.SHA256 || actual.SizeBytes != expected.Size {
		return fmt.Errorf("%w: artifact %s", ErrArtifactRecordMismatch, expected.ID)
	}
	if strings.TrimSpace(actual.URI) == "" || strings.TrimSpace(actual.SHA256) == "" {
		return ErrArtifactRecordMismatch
	}
	return nil
}

var _ ArtifactVerifier = (*CatalogArtifactVerifier)(nil)
