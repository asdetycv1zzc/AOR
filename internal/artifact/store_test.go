package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var artifactTestRequest = PutRequest{TenantID: "tenant-1", ProjectID: "project-1", TaskID: "task-1", ArtifactID: "audit-1", MediaType: "application/octet-stream", CreatedBy: "audit-service", RetentionPolicy: "audit-evidence", Encrypted: true}

func TestFileStoreStagesVerifiesAndPublishesManifest(t *testing.T) {
	store, err := NewFileStore(t.TempDir(), func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	contents := []byte("streamed evidence\n")
	manifest, err := store.Put(context.Background(), artifactTestRequest, func(destination io.Writer) error {
		_, err := destination.Write(contents)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.URI != artifactURI(manifest.SHA256) || manifest.Size != int64(len(contents)) || manifest.CreatedAt.IsZero() {
		t.Fatalf("invalid manifest: %#v", manifest)
	}
	loaded, reader, err := store.Open(context.Background(), artifactTestRequest.TenantID, artifactTestRequest.ProjectID, artifactTestRequest.TaskID, artifactTestRequest.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != manifest {
		t.Fatalf("loaded manifest changed: %#v", loaded)
	}
	read, err := io.ReadAll(reader)
	if closeErr := reader.Close(); err != nil || closeErr != nil {
		t.Fatalf("stream read failed: read=%v close=%v", err, closeErr)
	}
	if string(read) != string(contents) {
		t.Fatalf("content mismatch: %q", read)
	}
}

func TestStoreDoesNotPublishManifestWhenObjectVerificationFails(t *testing.T) {
	wantErr := errors.New("temporary object verification unavailable")
	objects := &failingObjectStore{verifyErr: wantErr}
	manifests := NewMemoryManifestStore()
	store, err := NewStore(objects, manifests, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Put(context.Background(), artifactTestRequest, func(destination io.Writer) error {
		_, writeErr := destination.Write([]byte("evidence"))
		return writeErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("verification error = %v", err)
	}
	if objects.publishCalls != 0 || objects.abortCalls != 1 {
		t.Fatalf("object publication was not fenced: %#v", objects)
	}
	if _, found, getErr := manifests.Get(context.Background(), artifactTestRequest.TenantID, artifactTestRequest.ProjectID, artifactTestRequest.TaskID, artifactTestRequest.ArtifactID); getErr != nil || found {
		t.Fatalf("manifest was published after verification failure: found=%v err=%v", found, getErr)
	}
}

func TestStoreRecoversUnknownManifestCommit(t *testing.T) {
	root := t.TempDir()
	objects, err := NewFileObjectStore(root)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := NewFileManifestStore(root)
	if err != nil {
		t.Fatal(err)
	}
	manifests := &unknownCommitManifestStore{inner: inner}
	store, err := NewStore(objects, manifests, func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	produce := func(destination io.Writer) error {
		_, writeErr := destination.Write([]byte("recoverable"))
		return writeErr
	}
	first, err := store.Put(context.Background(), artifactTestRequest, produce)
	if err != nil {
		t.Fatalf("unknown commit was not reconciled: %v", err)
	}
	manifest, err := store.Put(context.Background(), artifactTestRequest, produce)
	if err != nil {
		t.Fatal(err)
	}
	if manifests.publishCalls != 1 || first != manifest || manifest.Size != int64(len("recoverable")) {
		t.Fatalf("retry did not recover committed manifest: calls=%d first=%#v manifest=%#v", manifests.publishCalls, first, manifest)
	}
}

func TestFileStoreDetectsTamperedObjectOnStreamingRead(t *testing.T) {
	objects, err := NewFileObjectStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	manifests := NewMemoryManifestStore()
	store, err := NewStore(objects, manifests, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := store.Put(context.Background(), artifactTestRequest, func(destination io.Writer) error {
		_, writeErr := destination.Write([]byte("original"))
		return writeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(objects.objects, manifest.SHA256[len("sha256:"):])
	if err := os.WriteFile(name, []byte("tampered"), 0o400); err != nil {
		t.Fatal(err)
	}
	_, reader, err := store.Open(context.Background(), artifactTestRequest.TenantID, artifactTestRequest.ProjectID, artifactTestRequest.TaskID, artifactTestRequest.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if !errors.Is(readErr, ErrIntegrity) {
		t.Fatalf("tamper was not detected: %v", readErr)
	}
}

func TestFileStoreStreamsWithoutAWholeObjectBuffer(t *testing.T) {
	store, err := NewFileStore(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	const total = int64(8 << 20)
	const chunkSize = 32 << 10
	chunk := make([]byte, chunkSize)
	var written int64
	manifest, err := store.Put(context.Background(), artifactTestRequest, func(destination io.Writer) error {
		for written < total {
			amount := int64(len(chunk))
			if remaining := total - written; remaining < amount {
				amount = remaining
			}
			if _, err := destination.Write(chunk[:amount]); err != nil {
				return err
			}
			written += amount
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, reader, err := store.Open(context.Background(), artifactTestRequest.TenantID, artifactTestRequest.ProjectID, artifactTestRequest.TaskID, artifactTestRequest.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	count, err := io.CopyBuffer(io.Discard, reader, make([]byte, 16<<10))
	closeErr := reader.Close()
	if err != nil || closeErr != nil || count != total || manifest.Size != total {
		t.Fatalf("streaming transfer failed: count=%d size=%d read=%v close=%v", count, manifest.Size, err, closeErr)
	}
}

func TestFileStoreConcurrentIdempotentPublish(t *testing.T) {
	store, err := NewFileStore(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	produce := func(destination io.Writer) error {
		_, writeErr := destination.Write([]byte("same"))
		return writeErr
	}
	const workers = 8
	results := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, putErr := store.Put(context.Background(), artifactTestRequest, produce)
			results <- putErr
		}()
	}
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrityScannerReportsCorruptionAndRemovesOldOrphans(t *testing.T) {
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	objects, err := NewFileObjectStore(root)
	if err != nil {
		t.Fatal(err)
	}
	manifests, err := NewFileManifestStore(root)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(objects, manifests, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	referenced, err := store.Put(context.Background(), artifactTestRequest, func(destination io.Writer) error {
		_, writeErr := destination.Write([]byte("referenced"))
		return writeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	staged, err := objects.Stage(context.Background(), func(destination io.Writer) error {
		_, writeErr := destination.Write([]byte("orphan"))
		return writeErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.Verify(context.Background(), staged); err != nil {
		t.Fatal(err)
	}
	orphan, err := objects.Publish(context.Background(), staged)
	if err != nil {
		t.Fatal(err)
	}
	orphanName := filepath.Join(objects.objects, orphan.SHA256[len("sha256:"):])
	old := now.Add(-2 * time.Hour)
	if err := os.Chtimes(orphanName, old, old); err != nil {
		t.Fatal(err)
	}
	scanner, err := NewIntegrityScanner(objects, objects, manifests, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	report, err := scanner.RunOnce(context.Background(), time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.CheckedManifests != 1 || report.CheckedObjects != 2 || report.OrphansFound != 1 || report.OrphansRemoved != 1 || len(report.Issues) != 0 {
		t.Fatalf("unexpected integrity report: %#v", report)
	}
	if _, err := os.Stat(orphanName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old orphan was not removed: %v", err)
	}
	referencedName := filepath.Join(objects.objects, referenced.SHA256[len("sha256:"):])
	if err := os.WriteFile(referencedName, []byte("corrupt"), 0o400); err != nil {
		t.Fatal(err)
	}
	report, err = scanner.RunOnce(context.Background(), time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Issues) != 1 || report.Issues[0].ArtifactID != artifactTestRequest.ArtifactID {
		t.Fatalf("referenced corruption was not reported: %#v", report)
	}
}

type failingObjectStore struct {
	verifyErr    error
	publishCalls int
	abortCalls   int
}

func (s *failingObjectStore) Stage(_ context.Context, produce func(io.Writer) error) (StagedObject, error) {
	digesting := digestingWriter{ctx: context.Background()}
	digesting.digest = sha256.New()
	digesting.destination = io.Discard
	if err := produce(&digesting); err != nil {
		return StagedObject{}, err
	}
	return StagedObject{Token: ".upload-test", SHA256: "sha256:" + hex.EncodeToString(digesting.digest.Sum(nil)), Size: digesting.size}, nil
}

func (s *failingObjectStore) Verify(context.Context, StagedObject) error { return s.verifyErr }

func (s *failingObjectStore) Publish(context.Context, StagedObject) (PublishedObject, error) {
	s.publishCalls++
	return PublishedObject{}, nil
}

func (s *failingObjectStore) Abort(context.Context, StagedObject) error {
	s.abortCalls++
	return nil
}

func (s *failingObjectStore) Open(context.Context, PublishedObject) (io.ReadCloser, error) {
	return io.NopCloser(stringsReader("")), nil
}

type unknownCommitManifestStore struct {
	inner        ManifestStore
	once         bool
	publishCalls int
}

var errUnknownCommit = errors.New("manifest commit result unknown")

func (s *unknownCommitManifestStore) Get(ctx context.Context, tenantID, projectID, taskID, artifactID string) (Manifest, bool, error) {
	return s.inner.Get(ctx, tenantID, projectID, taskID, artifactID)
}

func (s *unknownCommitManifestStore) Publish(ctx context.Context, manifest Manifest) error {
	if s.once {
		return s.inner.Publish(ctx, manifest)
	}
	s.once = true
	s.publishCalls++
	if err := s.inner.Publish(ctx, manifest); err != nil {
		return err
	}
	return errUnknownCommit
}

type stringsReader string

func (r stringsReader) Read(destination []byte) (int, error) {
	if len(r) == 0 {
		return 0, io.EOF
	}
	amount := copy(destination, []byte(r))
	return amount, nil
}

func (r stringsReader) Close() error { return nil }
