package knowledge

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileRepositoryInitializeCreatesIdempotentEmptyBaseline(t *testing.T) {
	repository, err := NewFileRepository(filepath.Join(t.TempDir(), "knowledge"))
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 4, 8, 30, 0, 0, time.FixedZone("test", 2*60*60))
	manifest, err := repository.Initialize(context.Background(), "tenant-1", "project-1", createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 1 || manifest.TenantID != "tenant-1" || manifest.ProjectID != "project-1" || manifest.Revision == "" {
		t.Fatalf("unexpected baseline manifest: %#v", manifest)
	}
	if !manifest.CreatedAt.Equal(createdAt) || manifest.CreatedAt.Location() != time.UTC {
		t.Fatalf("createdAt was not normalized to UTC: %s", manifest.CreatedAt)
	}
	if manifest.Parents == nil || manifest.Overrides == nil || manifest.Documents == nil || len(manifest.Documents) != 0 {
		t.Fatalf("baseline collections must be present and empty: %#v", manifest)
	}

	again, err := repository.Initialize(context.Background(), "tenant-1", "project-1", createdAt.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if again.Revision != manifest.Revision || !again.CreatedAt.Equal(manifest.CreatedAt) {
		t.Fatalf("initialize was not idempotent: first=%#v again=%#v", manifest, again)
	}
	snapshot, err := repository.Load(context.Background(), "tenant-1", "project-1", manifest.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Documents) != 0 {
		t.Fatalf("baseline contains documents: %#v", snapshot.Documents)
	}
}

func TestFileRepositoryInitializeConvergesWhenConcurrent(t *testing.T) {
	repository, err := NewFileRepository(filepath.Join(t.TempDir(), "knowledge"))
	if err != nil {
		t.Fatal(err)
	}
	const callers = 8
	revisions := make(chan string, callers)
	errors := make(chan error, callers)
	var group sync.WaitGroup
	for index := 0; index < callers; index++ {
		group.Add(1)
		go func(offset int) {
			defer group.Done()
			manifest, initializeErr := repository.Initialize(
				context.Background(), "tenant-1", "project-1", knowledgeTestNow.Add(time.Duration(offset)*time.Second),
			)
			if initializeErr != nil {
				errors <- initializeErr
				return
			}
			revisions <- manifest.Revision
		}(index)
	}
	group.Wait()
	close(errors)
	close(revisions)
	for initializeErr := range errors {
		t.Fatal(initializeErr)
	}
	var expected string
	for revision := range revisions {
		if expected == "" {
			expected = revision
		}
		if revision != expected {
			t.Fatalf("initializers did not converge: got %s, want %s", revision, expected)
		}
	}
	if expected == "" {
		t.Fatal("no initializer returned a revision")
	}
}
