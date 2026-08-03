package artifact

import (
	"context"
	"io"
	"time"
)

type InventoryObject struct {
	PublishedObject
	ModifiedAt time.Time
}

type ObjectInventory interface {
	ListObjects(context.Context) ([]InventoryObject, error)
	RemoveObject(context.Context, InventoryObject) error
}

type ManifestInventory interface {
	ListManifests(context.Context) ([]Manifest, error)
}

type IntegrityIssue struct {
	ArtifactID string
	URI        string
	Reason     string
}

type IntegrityReport struct {
	CheckedManifests int
	CheckedObjects   int
	OrphansFound     int
	OrphansRemoved   int
	Issues           []IntegrityIssue
}

type IntegrityScanner struct {
	objects   ObjectStore
	objectSet ObjectInventory
	manifests ManifestInventory
	clock     func() time.Time
}

func NewIntegrityScanner(objects ObjectStore, objectSet ObjectInventory, manifests ManifestInventory, clock func() time.Time) (*IntegrityScanner, error) {
	if objects == nil || objectSet == nil || manifests == nil {
		return nil, ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	return &IntegrityScanner{objects: objects, objectSet: objectSet, manifests: manifests, clock: clock}, nil
}

func (scanner *IntegrityScanner) RunOnce(ctx context.Context, orphanGrace time.Duration, removeOrphans bool) (IntegrityReport, error) {
	if ctx == nil || ctx.Err() != nil || orphanGrace < 0 {
		return IntegrityReport{}, ErrInvalidRequest
	}
	manifests, err := scanner.manifests.ListManifests(ctx)
	if err != nil {
		return IntegrityReport{}, err
	}
	referenced := make(map[string]struct{}, len(manifests))
	report := IntegrityReport{CheckedManifests: len(manifests), Issues: []IntegrityIssue{}}
	buffer := make([]byte, verificationBufferBytes)
	for _, manifest := range manifests {
		if err := validateManifest(manifest); err != nil {
			report.Issues = append(report.Issues, IntegrityIssue{ArtifactID: manifest.ArtifactID, URI: manifest.URI, Reason: ErrIntegrity.Error()})
			continue
		}
		referenced[manifest.SHA256] = struct{}{}
		object := PublishedObject{URI: manifest.URI, SHA256: manifest.SHA256, Size: manifest.Size}
		reader, err := scanner.objects.Open(ctx, object)
		if err == nil {
			verified := newVerifyingReader(ctx, reader, object)
			_, copyErr := io.CopyBuffer(io.Discard, verified, buffer)
			closeErr := verified.Close()
			if copyErr != nil {
				err = copyErr
			} else {
				err = closeErr
			}
		}
		if err != nil {
			report.Issues = append(report.Issues, IntegrityIssue{ArtifactID: manifest.ArtifactID, URI: manifest.URI, Reason: err.Error()})
		}
	}
	objects, err := scanner.objectSet.ListObjects(ctx)
	if err != nil {
		return IntegrityReport{}, err
	}
	report.CheckedObjects = len(objects)
	cutoff := scanner.clock().UTC().Add(-orphanGrace)
	for _, object := range objects {
		if _, found := referenced[object.SHA256]; found || object.ModifiedAt.After(cutoff) {
			continue
		}
		report.OrphansFound++
		if removeOrphans {
			if err := scanner.objectSet.RemoveObject(ctx, object); err != nil {
				report.Issues = append(report.Issues, IntegrityIssue{URI: object.URI, Reason: err.Error()})
				continue
			}
			report.OrphansRemoved++
		}
	}
	return report, nil
}
