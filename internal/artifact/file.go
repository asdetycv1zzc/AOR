package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maximumManifestBytes = 64 << 10

type FileObjectStore struct {
	mu      sync.Mutex
	root    string
	staging string
	objects string
}

type FileManifestStore struct {
	root string
}

func NewFileStore(root string, clock func() time.Time) (*Store, error) {
	objects, err := NewFileObjectStore(root)
	if err != nil {
		return nil, err
	}
	manifests, err := NewFileManifestStore(root)
	if err != nil {
		return nil, err
	}
	return NewStore(objects, manifests, clock)
}

func NewFileObjectStore(root string) (*FileObjectStore, error) {
	resolved, err := prepareRoot(root)
	if err != nil {
		return nil, err
	}
	staging := filepath.Join(resolved, "temporary")
	objects := filepath.Join(resolved, "objects", "sha256")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(objects, 0o700); err != nil {
		return nil, err
	}
	return &FileObjectStore{root: resolved, staging: staging, objects: objects}, nil
}

func NewFileManifestStore(root string) (*FileManifestStore, error) {
	resolved, err := prepareRoot(root)
	if err != nil {
		return nil, err
	}
	manifestRoot := filepath.Join(resolved, "manifests")
	if err := os.MkdirAll(manifestRoot, 0o700); err != nil {
		return nil, err
	}
	return &FileManifestStore{root: manifestRoot}, nil
}

func (s *FileObjectStore) Stage(ctx context.Context, produce func(io.Writer) error) (StagedObject, error) {
	if ctx == nil || ctx.Err() != nil || produce == nil {
		return StagedObject{}, ErrInvalidRequest
	}
	file, err := os.CreateTemp(s.staging, ".upload-")
	if err != nil {
		return StagedObject{}, err
	}
	name := file.Name()
	keep := false
	defer func() {
		_ = file.Close()
		if !keep {
			_ = os.Remove(name)
		}
	}()
	destination := &digestingWriter{ctx: ctx, destination: file, digest: sha256.New()}
	if err := produce(destination); err != nil {
		return StagedObject{}, err
	}
	if err := ctx.Err(); err != nil {
		return StagedObject{}, err
	}
	if err := file.Sync(); err != nil {
		return StagedObject{}, err
	}
	if err := file.Close(); err != nil {
		return StagedObject{}, err
	}
	keep = true
	return StagedObject{Token: filepath.Base(name), SHA256: "sha256:" + hex.EncodeToString(destination.digest.Sum(nil)), Size: destination.size}, nil
}

func (s *FileObjectStore) Verify(ctx context.Context, staged StagedObject) error {
	if ctx == nil || ctx.Err() != nil || !validStageToken(staged.Token) || validateStaged(staged) != nil {
		return ErrInvalidRequest
	}
	actualDigest, actualSize, err := hashFile(ctx, filepath.Join(s.staging, staged.Token))
	if err != nil {
		return err
	}
	if actualDigest != staged.SHA256 || actualSize != staged.Size {
		return ErrIntegrity
	}
	return nil
}

func (s *FileObjectStore) Publish(ctx context.Context, staged StagedObject) (PublishedObject, error) {
	if ctx == nil || ctx.Err() != nil {
		return PublishedObject{}, ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.Verify(ctx, staged); err != nil {
		return PublishedObject{}, err
	}
	source := filepath.Join(s.staging, staged.Token)
	destination := filepath.Join(s.objects, strings.TrimPrefix(staged.SHA256, "sha256:"))
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return PublishedObject{}, ErrIntegrity
		}
		digest, size, hashErr := hashFile(ctx, destination)
		if hashErr != nil {
			return PublishedObject{}, hashErr
		}
		if digest != staged.SHA256 || size != staged.Size {
			return PublishedObject{}, ErrIntegrity
		}
		if err := os.Remove(source); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return PublishedObject{}, err
		}
		return PublishedObject{URI: artifactURI(staged.SHA256), SHA256: staged.SHA256, Size: staged.Size}, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return PublishedObject{}, err
	}
	if err := os.Chmod(source, 0o400); err != nil {
		return PublishedObject{}, err
	}
	if err := os.Link(source, destination); err != nil {
		if errors.Is(err, fs.ErrExist) {
			info, statErr := os.Lstat(destination)
			if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return PublishedObject{}, ErrIntegrity
			}
			digest, size, hashErr := hashFile(ctx, destination)
			if hashErr != nil || digest != staged.SHA256 || size != staged.Size {
				if hashErr != nil {
					return PublishedObject{}, hashErr
				}
				return PublishedObject{}, ErrIntegrity
			}
			if removeErr := os.Remove(source); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				return PublishedObject{}, removeErr
			}
			return PublishedObject{URI: artifactURI(staged.SHA256), SHA256: staged.SHA256, Size: staged.Size}, nil
		}
		return PublishedObject{}, err
	}
	if err := os.Remove(source); err != nil {
		return PublishedObject{}, err
	}
	return PublishedObject{URI: artifactURI(staged.SHA256), SHA256: staged.SHA256, Size: staged.Size}, nil
}

func (s *FileObjectStore) Abort(_ context.Context, staged StagedObject) error {
	if !validStageToken(staged.Token) {
		return ErrInvalidRequest
	}
	err := os.Remove(filepath.Join(s.staging, staged.Token))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (s *FileObjectStore) Open(ctx context.Context, object PublishedObject) (io.ReadCloser, error) {
	if ctx == nil || ctx.Err() != nil || !digestPattern.MatchString(object.SHA256) || object.Size < 0 || object.URI != artifactURI(object.SHA256) {
		return nil, ErrInvalidRequest
	}
	name := filepath.Join(s.objects, strings.TrimPrefix(object.SHA256, "sha256:"))
	info, err := os.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrIntegrity
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, ErrIntegrity
	}
	return file, nil
}

func (s *FileObjectStore) ListObjects(ctx context.Context) ([]InventoryObject, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalidRequest
	}
	entries, err := os.ReadDir(s.objects)
	if err != nil {
		return nil, err
	}
	objects := make([]InventoryObject, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		digest := "sha256:" + entry.Name()
		if !digestPattern.MatchString(digest) || entry.Type()&os.ModeSymlink != 0 {
			return nil, ErrIntegrity
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, ErrIntegrity
		}
		objects = append(objects, InventoryObject{PublishedObject: PublishedObject{URI: artifactURI(digest), SHA256: digest, Size: info.Size()}, ModifiedAt: info.ModTime().UTC()})
	}
	return objects, nil
}

func (s *FileObjectStore) RemoveObject(ctx context.Context, object InventoryObject) error {
	if ctx == nil || ctx.Err() != nil || !digestPattern.MatchString(object.SHA256) || object.URI != artifactURI(object.SHA256) || object.Size < 0 || object.ModifiedAt.IsZero() {
		return ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	name := filepath.Join(s.objects, strings.TrimPrefix(object.SHA256, "sha256:"))
	info, err := os.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != object.Size || !info.ModTime().UTC().Equal(object.ModifiedAt) {
		return ErrConflict
	}
	return os.Remove(name)
}

func (s *FileManifestStore) Get(ctx context.Context, tenantID, projectID, taskID, artifactID string) (Manifest, bool, error) {
	if ctx == nil || ctx.Err() != nil || !validID(tenantID) || !validID(projectID) || !validID(taskID) || !validID(artifactID) {
		return Manifest{}, false, ErrInvalidRequest
	}
	name := s.manifestPath(tenantID, projectID, taskID, artifactID)
	manifest, err := readManifest(name)
	if errors.Is(err, fs.ErrNotExist) {
		return Manifest{}, false, nil
	}
	if err != nil {
		return Manifest{}, false, err
	}
	if manifest.TenantID != tenantID || manifest.ProjectID != projectID || manifest.TaskID != taskID || manifest.ArtifactID != artifactID {
		return Manifest{}, false, ErrIntegrity
	}
	return manifest, true, nil
}

func (s *FileManifestStore) Publish(ctx context.Context, manifest Manifest) error {
	if ctx == nil || ctx.Err() != nil || validateManifest(manifest) != nil {
		return ErrInvalidRequest
	}
	destination := s.manifestPath(manifest.TenantID, manifest.ProjectID, manifest.TaskID, manifest.ArtifactID)
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	payload, err := json.Marshal(manifest)
	if err != nil || len(payload) > maximumManifestBytes {
		return ErrInvalidRequest
	}
	temporary, err := os.CreateTemp(directory, ".manifest-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}()
	if _, err := temporary.Write(payload); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryName, destination); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	existing, err := readManifest(destination)
	if err != nil {
		return err
	}
	if existing == manifest {
		return nil
	}
	return ErrConflict
}

func (s *FileManifestStore) ListManifests(ctx context.Context) ([]Manifest, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalidRequest
	}
	manifests := []Manifest{}
	err := filepath.WalkDir(s.root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrIntegrity
		}
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".manifest-") {
			return nil
		}
		if filepath.Ext(entry.Name()) != ".json" {
			return ErrIntegrity
		}
		manifest, err := readManifest(name)
		if err != nil {
			return err
		}
		manifests = append(manifests, manifest)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return manifests, nil
}

func (s *FileManifestStore) manifestPath(tenantID, projectID, taskID, artifactID string) string {
	digest := sha256.Sum256([]byte(manifestKey(tenantID, projectID, taskID, artifactID)))
	encoded := hex.EncodeToString(digest[:])
	return filepath.Join(s.root, encoded[:2], encoded+".json")
}

type digestingWriter struct {
	ctx         context.Context
	destination io.Writer
	digest      hash.Hash
	size        int64
}

func (w *digestingWriter) Write(value []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	amount, err := w.destination.Write(value)
	if amount > 0 {
		_, _ = w.digest.Write(value[:amount])
		w.size += int64(amount)
	}
	return amount, err
}

func hashFile(ctx context.Context, name string) (string, int64, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", 0, ErrIntegrity
	}
	file, err := os.Open(name)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return "", 0, ErrIntegrity
	}
	digest := sha256.New()
	buffer := make([]byte, verificationBufferBytes)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		amount, readErr := file.Read(buffer)
		if amount > 0 {
			_, _ = digest.Write(buffer[:amount])
			size += int64(amount)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", 0, readErr
		}
	}
	return "sha256:" + hex.EncodeToString(digest.Sum(nil)), size, nil
}

func readManifest(name string) (Manifest, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return Manifest{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, ErrIntegrity
	}
	file, err := os.Open(name)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return Manifest{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() <= 0 || opened.Size() > maximumManifestBytes {
		return Manifest{}, ErrIntegrity
	}
	decoder := json.NewDecoder(io.LimitReader(file, maximumManifestBytes+1))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, ErrIntegrity
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return Manifest{}, ErrIntegrity
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func prepareRoot(root string) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", ErrInvalidRequest
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalidRequest
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func validStageToken(token string) bool {
	return strings.HasPrefix(token, ".upload-") && filepath.Base(token) == token && !strings.ContainsAny(token, "/\\\x00\r\n")
}

var _ ObjectStore = (*FileObjectStore)(nil)
var _ ManifestStore = (*FileManifestStore)(nil)
var _ ObjectInventory = (*FileObjectStore)(nil)
var _ ManifestInventory = (*FileManifestStore)(nil)
