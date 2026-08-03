package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"mime"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidRequest = errors.New("invalid artifact request")
	ErrConflict       = errors.New("artifact manifest is immutable")
	ErrNotFound       = errors.New("artifact not found")
	ErrIntegrity      = errors.New("artifact integrity check failed")
	ErrIncompleteRead = errors.New("artifact stream was not fully read")
)

const verificationBufferBytes = 64 << 10

var (
	idPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type PutRequest struct {
	TenantID        string
	ProjectID       string
	TaskID          string
	ArtifactID      string
	MediaType       string
	CreatedBy       string
	RetentionPolicy string
	Encrypted       bool
}

type Manifest struct {
	Version         int       `json:"version"`
	TenantID        string    `json:"tenantId"`
	ProjectID       string    `json:"projectId"`
	TaskID          string    `json:"taskId"`
	ArtifactID      string    `json:"artifactId"`
	URI             string    `json:"uri"`
	SHA256          string    `json:"sha256"`
	Size            int64     `json:"size"`
	MediaType       string    `json:"mediaType"`
	CreatedBy       string    `json:"createdBy"`
	RetentionPolicy string    `json:"retentionPolicy"`
	Encrypted       bool      `json:"encrypted"`
	CreatedAt       time.Time `json:"createdAt"`
}

type StagedObject struct {
	Token  string
	SHA256 string
	Size   int64
}

type PublishedObject struct {
	URI    string
	SHA256 string
	Size   int64
}

type ObjectStore interface {
	Stage(context.Context, func(io.Writer) error) (StagedObject, error)
	Verify(context.Context, StagedObject) error
	Publish(context.Context, StagedObject) (PublishedObject, error)
	Abort(context.Context, StagedObject) error
	Open(context.Context, PublishedObject) (io.ReadCloser, error)
}

type ManifestStore interface {
	Get(context.Context, string, string, string, string) (Manifest, bool, error)
	Publish(context.Context, Manifest) error
}

type Store struct {
	objects   ObjectStore
	manifests ManifestStore
	clock     func() time.Time
}

func NewStore(objects ObjectStore, manifests ManifestStore, clock func() time.Time) (*Store, error) {
	if objects == nil || manifests == nil {
		return nil, ErrInvalidRequest
	}
	if clock == nil {
		clock = time.Now
	}
	return &Store{objects: objects, manifests: manifests, clock: clock}, nil
}

func (s *Store) Put(ctx context.Context, request PutRequest, produce func(io.Writer) error) (Manifest, error) {
	if ctx == nil || ctx.Err() != nil || validateRequest(request) != nil || produce == nil {
		return Manifest{}, ErrInvalidRequest
	}
	staged, err := s.objects.Stage(ctx, produce)
	if err != nil {
		return Manifest{}, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = s.objects.Abort(context.Background(), staged)
		}
	}()
	if err := validateStaged(staged); err != nil {
		return Manifest{}, err
	}
	if err := s.objects.Verify(ctx, staged); err != nil {
		return Manifest{}, err
	}
	if existing, found, err := s.manifests.Get(ctx, request.TenantID, request.ProjectID, request.TaskID, request.ArtifactID); err != nil {
		return Manifest{}, err
	} else if found {
		if !manifestMatchesRequest(existing, request, staged.SHA256, staged.Size) {
			return Manifest{}, ErrConflict
		}
		if err := s.verifyPublished(ctx, PublishedObject{URI: existing.URI, SHA256: existing.SHA256, Size: existing.Size}); err != nil {
			return Manifest{}, err
		}
		return existing, nil
	}
	published, err := s.objects.Publish(ctx, staged)
	if err != nil {
		return Manifest{}, err
	}
	cleanup = false
	if err := validatePublished(published, staged); err != nil {
		return Manifest{}, err
	}
	if err := s.verifyPublished(ctx, published); err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{
		Version:         1,
		TenantID:        request.TenantID,
		ProjectID:       request.ProjectID,
		TaskID:          request.TaskID,
		ArtifactID:      request.ArtifactID,
		URI:             published.URI,
		SHA256:          published.SHA256,
		Size:            published.Size,
		MediaType:       request.MediaType,
		CreatedBy:       request.CreatedBy,
		RetentionPolicy: request.RetentionPolicy,
		Encrypted:       request.Encrypted,
		CreatedAt:       s.clock().UTC(),
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	if err := s.manifests.Publish(ctx, manifest); err != nil {
		if existing, found, lookupErr := s.manifests.Get(ctx, request.TenantID, request.ProjectID, request.TaskID, request.ArtifactID); lookupErr == nil && found && sameArtifact(existing, manifest) {
			return existing, nil
		}
		return Manifest{}, err
	}
	return manifest, nil
}

func (s *Store) Open(ctx context.Context, tenantID, projectID, taskID, artifactID string) (Manifest, io.ReadCloser, error) {
	if ctx == nil || ctx.Err() != nil || !validID(tenantID) || !validID(projectID) || !validID(taskID) || !validID(artifactID) {
		return Manifest{}, nil, ErrInvalidRequest
	}
	manifest, found, err := s.manifests.Get(ctx, tenantID, projectID, taskID, artifactID)
	if err != nil {
		return Manifest{}, nil, err
	}
	if !found {
		return Manifest{}, nil, ErrNotFound
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, nil, ErrIntegrity
	}
	object := PublishedObject{URI: manifest.URI, SHA256: manifest.SHA256, Size: manifest.Size}
	reader, err := s.objects.Open(ctx, object)
	if err != nil {
		return Manifest{}, nil, err
	}
	return manifest, newVerifyingReader(ctx, reader, object), nil
}

func (s *Store) verifyPublished(ctx context.Context, object PublishedObject) error {
	reader, err := s.objects.Open(ctx, object)
	if err != nil {
		return err
	}
	verified := newVerifyingReader(ctx, reader, object)
	_, copyErr := io.CopyBuffer(io.Discard, verified, make([]byte, verificationBufferBytes))
	closeErr := verified.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

type verifyingReader struct {
	ctx      context.Context
	source   io.ReadCloser
	digest   hash.Hash
	expected PublishedObject
	read     int64
	finished bool
	pending  error
}

func newVerifyingReader(ctx context.Context, source io.ReadCloser, expected PublishedObject) *verifyingReader {
	return &verifyingReader{ctx: ctx, source: source, digest: sha256.New(), expected: expected}
}

func (r *verifyingReader) Read(destination []byte) (int, error) {
	if r.pending != nil {
		err := r.pending
		r.pending = nil
		return 0, err
	}
	if r.finished {
		return 0, io.EOF
	}
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	amount, readErr := r.source.Read(destination)
	if amount > 0 {
		_, _ = r.digest.Write(destination[:amount])
		r.read += int64(amount)
	}
	if readErr == io.EOF {
		r.finished = true
		actual := "sha256:" + hex.EncodeToString(r.digest.Sum(nil))
		if r.read != r.expected.Size || actual != r.expected.SHA256 {
			if amount > 0 {
				r.pending = ErrIntegrity
				return amount, nil
			}
			return 0, ErrIntegrity
		}
	}
	return amount, readErr
}

func (r *verifyingReader) Close() error {
	closeErr := r.source.Close()
	if closeErr != nil {
		return closeErr
	}
	if !r.finished {
		return ErrIncompleteRead
	}
	if r.pending != nil {
		return r.pending
	}
	return nil
}

type MemoryManifestStore struct {
	mu    sync.RWMutex
	items map[string]Manifest
}

func NewMemoryManifestStore() *MemoryManifestStore {
	return &MemoryManifestStore{items: make(map[string]Manifest)}
}

func (s *MemoryManifestStore) Get(_ context.Context, tenantID, projectID, taskID, artifactID string) (Manifest, bool, error) {
	s.mu.RLock()
	manifest, found := s.items[manifestKey(tenantID, projectID, taskID, artifactID)]
	s.mu.RUnlock()
	return manifest, found, nil
}

func (s *MemoryManifestStore) Publish(_ context.Context, manifest Manifest) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	key := manifestKey(manifest.TenantID, manifest.ProjectID, manifest.TaskID, manifest.ArtifactID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found := s.items[key]; found {
		if existing == manifest {
			return nil
		}
		return ErrConflict
	}
	s.items[key] = manifest
	return nil
}

func validateRequest(request PutRequest) error {
	if !validID(request.TenantID) || !validID(request.ProjectID) || !validID(request.TaskID) || !validID(request.ArtifactID) || !validText(request.CreatedBy) || !validText(request.RetentionPolicy) {
		return ErrInvalidRequest
	}
	mediaType, _, err := mime.ParseMediaType(request.MediaType)
	if err != nil || mediaType == "" {
		return ErrInvalidRequest
	}
	return nil
}

func validateStaged(staged StagedObject) error {
	if staged.Token == "" || !digestPattern.MatchString(staged.SHA256) || staged.Size < 0 {
		return ErrIntegrity
	}
	return nil
}

func validatePublished(published PublishedObject, staged StagedObject) error {
	if published.SHA256 != staged.SHA256 || published.Size != staged.Size || published.URI != artifactURI(staged.SHA256) {
		return ErrIntegrity
	}
	return nil
}

func validateManifest(manifest Manifest) error {
	request := PutRequest{TenantID: manifest.TenantID, ProjectID: manifest.ProjectID, TaskID: manifest.TaskID, ArtifactID: manifest.ArtifactID, MediaType: manifest.MediaType, CreatedBy: manifest.CreatedBy, RetentionPolicy: manifest.RetentionPolicy, Encrypted: manifest.Encrypted}
	if manifest.Version != 1 || validateRequest(request) != nil || !digestPattern.MatchString(manifest.SHA256) || manifest.Size < 0 || manifest.URI != artifactURI(manifest.SHA256) || manifest.CreatedAt.IsZero() {
		return ErrIntegrity
	}
	return nil
}

func manifestMatchesRequest(manifest Manifest, request PutRequest, digest string, size int64) bool {
	return manifest.TenantID == request.TenantID && manifest.ProjectID == request.ProjectID && manifest.TaskID == request.TaskID && manifest.ArtifactID == request.ArtifactID && manifest.MediaType == request.MediaType && manifest.CreatedBy == request.CreatedBy && manifest.RetentionPolicy == request.RetentionPolicy && manifest.Encrypted == request.Encrypted && manifest.SHA256 == digest && manifest.Size == size
}

func sameArtifact(left, right Manifest) bool {
	return left.Version == right.Version && left.TenantID == right.TenantID && left.ProjectID == right.ProjectID && left.TaskID == right.TaskID && left.ArtifactID == right.ArtifactID && left.URI == right.URI && left.SHA256 == right.SHA256 && left.Size == right.Size && left.MediaType == right.MediaType && left.CreatedBy == right.CreatedBy && left.RetentionPolicy == right.RetentionPolicy && left.Encrypted == right.Encrypted
}

func validID(value string) bool {
	return idPattern.MatchString(value)
}

func validText(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == value && value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\x00\r\n")
}

func artifactURI(digest string) string {
	return "artifact://sha256/" + strings.TrimPrefix(digest, "sha256:")
}

func manifestKey(tenantID, projectID, taskID, artifactID string) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s", tenantID, projectID, taskID, artifactID)
}
