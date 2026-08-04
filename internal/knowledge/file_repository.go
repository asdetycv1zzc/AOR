package knowledge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

var revisionPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type FileRepository struct {
	root string
	mu   sync.Mutex
}

func NewFileRepository(root string) (*FileRepository, error) {
	if root == "" {
		return nil, invalid("knowledge root")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, aorerrors.Wrap(aorerrors.CodeInvalidArgument, "", err, map[string]any{"scope": "knowledge root"})
	}
	if err := createRootSecure(absolute, 0o750); err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(absolute) {
		return nil, unauthorizedPath()
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || unsafeFileInfo(info) {
		return nil, unauthorizedPath()
	}
	return &FileRepository{root: absolute}, nil
}

// Initialize creates the immutable empty baseline used by a newly created
// project. Repeated and concurrent calls return the first committed baseline.
func (repository *FileRepository) Initialize(ctx context.Context, tenantID, projectID string, createdAt time.Time) (Manifest, error) {
	if repository == nil {
		return Manifest{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if createdAt.IsZero() {
		return Manifest{}, invalid("snapshot metadata")
	}
	createdAt = createdAt.UTC()
	current, err := repository.Head(ctx, tenantID, projectID)
	if err != nil {
		return Manifest{}, err
	}
	if current != "" {
		snapshot, loadErr := repository.Load(ctx, tenantID, projectID, current)
		if loadErr != nil {
			return Manifest{}, loadErr
		}
		return snapshot.Manifest, nil
	}

	manifest, err := repository.Commit(ctx, CommitRequest{
		TenantID: tenantID, ProjectID: projectID,
		Snapshot: Snapshot{
			Manifest: Manifest{
				Version: 1, TenantID: tenantID, ProjectID: projectID, CreatedAt: createdAt,
				Parents: []ParentSnapshot{}, Overrides: []string{}, Documents: []DocumentMetadata{},
			},
			Documents: map[string]StoredDocument{},
		},
	})
	if err == nil {
		return manifest, nil
	}
	var conflict *aorerrors.Error
	if !errors.As(err, &conflict) || conflict.Code != aorerrors.CodeStateVersionConflict {
		return Manifest{}, err
	}
	current, err = repository.Head(ctx, tenantID, projectID)
	if err != nil {
		return Manifest{}, err
	}
	snapshot, err := repository.Load(ctx, tenantID, projectID, current)
	if err != nil {
		return Manifest{}, err
	}
	return snapshot.Manifest, nil
}

func (repository *FileRepository) Head(ctx context.Context, tenantID, projectID string) (string, error) {
	if repository == nil {
		return "", aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.readHead(tenantID, projectID)
}

func (repository *FileRepository) readHead(tenantID, projectID string) (string, error) {
	projectDirectory, err := repository.projectDirectory(tenantID, projectID)
	if err != nil {
		return "", err
	}
	if err := rejectLinks(repository.root, projectDirectory); err != nil {
		return "", err
	}
	headPath := filepath.Join(projectDirectory, "HEAD")
	info, err := os.Lstat(headPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.Mode().IsRegular() || unsafeFileInfo(info) {
		return "", unauthorizedPath()
	}
	data, err := os.ReadFile(headPath)
	if err != nil {
		return "", aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	revision := strings.TrimSpace(string(data))
	if !revisionPattern.MatchString(revision) {
		return "", aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	return revision, nil
}

func (repository *FileRepository) Load(ctx context.Context, tenantID, projectID, revision string) (Snapshot, error) {
	if repository == nil {
		return Snapshot{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if !revisionPattern.MatchString(revision) {
		return Snapshot{}, revisionUnavailable()
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.loadUnlocked(tenantID, projectID, revision)
}

func (repository *FileRepository) loadUnlocked(tenantID, projectID, revision string) (Snapshot, error) {
	revisionDirectory, err := repository.revisionDirectory(tenantID, projectID, revision)
	if err != nil {
		return Snapshot{}, err
	}
	if err := rejectLinks(repository.root, revisionDirectory); err != nil {
		return Snapshot{}, err
	}
	info, err := os.Lstat(revisionDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, revisionUnavailable()
	}
	if err != nil || !info.IsDir() || unsafeFileInfo(info) {
		return Snapshot{}, unauthorizedPath()
	}
	manifestPath := filepath.Join(revisionDirectory, "manifest.json")
	manifestData, err := readRegularFile(manifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{}, revisionUnavailable()
	}
	if err != nil {
		return Snapshot{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Snapshot{}, aorerrors.Wrap(aorerrors.CodeArtifactHashMismatch, "", err, nil)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Snapshot{}, err
	}
	_, createdOffset := manifest.CreatedAt.Zone()
	if manifest.Version != 1 || manifest.TenantID != tenantID || manifest.ProjectID != projectID || manifest.Revision != revision || manifest.CreatedAt.IsZero() || createdOffset != 0 {
		return Snapshot{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	if _, err := validateParents(projectID, manifest.Parents, manifest.ParentOrderExplicit); err != nil {
		return Snapshot{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	if normalizedOverrides, err := normalizePathSet(manifest.Overrides); err != nil || !sameStrings(normalizedOverrides, manifest.Overrides) {
		return Snapshot{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	documents := make(map[string]StoredDocument, len(manifest.Documents))
	previousPath := ""
	for _, metadata := range manifest.Documents {
		documentPath, pathErr := normalizePath(metadata.Path)
		if pathErr != nil || documentPath != metadata.Path || previousPath >= documentPath || !metadata.TrustLevel.Valid() || metadata.LineCount < 1 || !revisionPattern.MatchString(metadata.SHA256) {
			return Snapshot{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
		}
		previousPath = documentPath
		filePath := filepath.Join(revisionDirectory, "files", filepath.FromSlash(documentPath))
		if err := ensureWithin(filepath.Join(revisionDirectory, "files"), filePath); err != nil {
			return Snapshot{}, err
		}
		content, readErr := readRegularFile(filePath)
		if readErr != nil {
			return Snapshot{}, aorerrors.Wrap(aorerrors.CodeArtifactHashMismatch, "", readErr, nil)
		}
		normalized, normalizeErr := normalizeDocument(DocumentInput{
			Path: metadata.Path, Title: metadata.Title, Tags: metadata.Tags, TrustLevel: metadata.TrustLevel,
			ContentType: metadata.ContentType, Content: content,
		})
		if normalizeErr != nil || !bytes.Equal(normalized.Content, content) || !sameMetadata(normalized.Metadata, metadata) || contentDigest(content) != metadata.SHA256 || len(splitLines(content)) != metadata.LineCount {
			return Snapshot{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
		}
		documents[documentPath] = StoredDocument{Metadata: cloneMetadata(metadata), Content: append([]byte(nil), content...)}
	}
	if err := verifyDocumentTree(filepath.Join(revisionDirectory, "files"), documents); err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{Manifest: cloneManifest(manifest), Documents: documents}
	digest, err := snapshotDigest(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	if digest != revision {
		return Snapshot{}, aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	return snapshot, nil
}

func (repository *FileRepository) Commit(ctx context.Context, request CommitRequest) (Manifest, error) {
	if repository == nil {
		return Manifest{}, aorerrors.New(aorerrors.CodeDependencyUnavailable, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return Manifest{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	current, err := repository.readHead(request.TenantID, request.ProjectID)
	if err != nil {
		return Manifest{}, err
	}
	if current != request.BaseRevision {
		return Manifest{}, aorerrors.New(aorerrors.CodeStateVersionConflict, "", nil)
	}
	snapshot := cloneSnapshot(request.Snapshot)
	if snapshot.Manifest.TenantID != request.TenantID || snapshot.Manifest.ProjectID != request.ProjectID || snapshot.Manifest.Version != 1 {
		return Manifest{}, invalid("snapshot scope")
	}
	if err := validateCommitSnapshot(snapshot); err != nil {
		return Manifest{}, err
	}
	revision, err := snapshotDigest(snapshot)
	if err != nil {
		return Manifest{}, err
	}
	snapshot.Manifest.Revision = revision
	snapshot.Manifest.Documents = make([]DocumentMetadata, 0, len(snapshot.Documents))
	for _, documentPath := range sortedDocumentPaths(snapshot.Documents) {
		document := snapshot.Documents[documentPath]
		snapshot.Manifest.Documents = append(snapshot.Manifest.Documents, cloneMetadata(document.Metadata))
	}

	projectDirectory, err := repository.ensureProjectDirectory(request.TenantID, request.ProjectID)
	if err != nil {
		return Manifest{}, err
	}
	revisionDirectory, err := repository.revisionDirectory(request.TenantID, request.ProjectID, revision)
	if err != nil {
		return Manifest{}, err
	}
	if _, statErr := os.Lstat(revisionDirectory); statErr == nil {
		existing, loadErr := repository.loadUnlocked(request.TenantID, request.ProjectID, revision)
		if loadErr != nil {
			return Manifest{}, loadErr
		}
		if err := repository.writeHead(projectDirectory, revision); err != nil {
			return Manifest{}, err
		}
		return existing.Manifest, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return Manifest{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", statErr, nil)
	}

	stage, err := os.MkdirTemp(projectDirectory, ".staging-")
	if err != nil {
		return Manifest{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()
	filesDirectory := filepath.Join(stage, "files")
	if err := os.Mkdir(filesDirectory, 0o700); err != nil {
		return Manifest{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	for _, documentPath := range sortedDocumentPaths(snapshot.Documents) {
		document := snapshot.Documents[documentPath]
		filePath := filepath.Join(filesDirectory, filepath.FromSlash(documentPath))
		if err := ensureWithin(filesDirectory, filePath); err != nil {
			return Manifest{}, err
		}
		if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
			return Manifest{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
		}
		if err := writeExclusive(filePath, document.Content, 0o440); err != nil {
			return Manifest{}, err
		}
	}
	manifestData, err := json.MarshalIndent(snapshot.Manifest, "", "  ")
	if err != nil {
		return Manifest{}, aorerrors.Wrap(aorerrors.CodeInternalError, "", err, nil)
	}
	manifestData = append(manifestData, '\n')
	if err := writeExclusive(filepath.Join(stage, "manifest.json"), manifestData, 0o440); err != nil {
		return Manifest{}, err
	}
	if err := hardenTree(stage); err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(stage, revisionDirectory); err != nil {
		return Manifest{}, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	committed = true
	if err := syncDirectory(filepath.Dir(revisionDirectory)); err != nil {
		return Manifest{}, err
	}
	if err := repository.writeHead(projectDirectory, revision); err != nil {
		return Manifest{}, err
	}
	return cloneManifest(snapshot.Manifest), nil
}

func (repository *FileRepository) LocalPath(tenantID, projectID, revision, documentPath string) (string, error) {
	if repository == nil || !revisionPattern.MatchString(revision) {
		return "", revisionUnavailable()
	}
	normalized, err := normalizePath(documentPath)
	if err != nil {
		return "", err
	}
	revisionDirectory, err := repository.revisionDirectory(tenantID, projectID, revision)
	if err != nil {
		return "", err
	}
	result := filepath.Join(revisionDirectory, "files", filepath.FromSlash(normalized))
	if err := ensureWithin(filepath.Join(revisionDirectory, "files"), result); err != nil {
		return "", err
	}
	if err := rejectLinks(repository.root, result); err != nil {
		return "", err
	}
	return result, nil
}

func (repository *FileRepository) ensureProjectDirectory(tenantID, projectID string) (string, error) {
	projectDirectory, err := repository.projectDirectory(tenantID, projectID)
	if err != nil {
		return "", err
	}
	if err := secureMkdirAll(repository.root, filepath.Join(projectDirectory, "revisions"), 0o750); err != nil {
		return "", err
	}
	if err := rejectLinks(repository.root, projectDirectory); err != nil {
		return "", err
	}
	return projectDirectory, nil
}

func (repository *FileRepository) projectDirectory(tenantID, projectID string) (string, error) {
	if tenantID == "" || projectID == "" {
		return "", invalid("project scope")
	}
	tenantSegment := hex.EncodeToString([]byte(tenantID))
	projectSegment := hex.EncodeToString([]byte(projectID))
	result := filepath.Join(repository.root, "tenants", tenantSegment, "projects", projectSegment)
	if err := ensureWithin(repository.root, result); err != nil {
		return "", err
	}
	return result, nil
}

func (repository *FileRepository) revisionDirectory(tenantID, projectID, revision string) (string, error) {
	if !revisionPattern.MatchString(revision) {
		return "", revisionUnavailable()
	}
	projectDirectory, err := repository.projectDirectory(tenantID, projectID)
	if err != nil {
		return "", err
	}
	result := filepath.Join(projectDirectory, "revisions", strings.TrimPrefix(revision, "sha256:"))
	if err := ensureWithin(projectDirectory, result); err != nil {
		return "", err
	}
	return result, nil
}

func (repository *FileRepository) writeHead(projectDirectory, revision string) error {
	temporary, err := os.CreateTemp(projectDirectory, ".head-")
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		_ = temporary.Close()
		if cleanup {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o640); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if _, err := temporary.WriteString(revision + "\n"); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if err := temporary.Sync(); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if err := temporary.Close(); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if err := os.Rename(temporaryPath, filepath.Join(projectDirectory, "HEAD")); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	cleanup = false
	return syncDirectory(projectDirectory)
}

func writeExclusive(filePath string, content []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	if err := file.Close(); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	return nil
}

func validateCommitSnapshot(snapshot Snapshot) error {
	_, createdOffset := snapshot.Manifest.CreatedAt.Zone()
	if snapshot.Manifest.Revision != "" || snapshot.Manifest.CreatedAt.IsZero() || createdOffset != 0 {
		return invalid("snapshot metadata")
	}
	if _, err := validateParents(snapshot.Manifest.ProjectID, snapshot.Manifest.Parents, snapshot.Manifest.ParentOrderExplicit); err != nil {
		return err
	}
	overrides, err := normalizePathSet(snapshot.Manifest.Overrides)
	if err != nil || !sameStrings(overrides, snapshot.Manifest.Overrides) {
		return invalid("snapshot overrides")
	}
	for documentPath, document := range snapshot.Documents {
		normalized, err := normalizeDocument(DocumentInput{
			Path: document.Metadata.Path, Title: document.Metadata.Title, Tags: document.Metadata.Tags,
			TrustLevel: document.Metadata.TrustLevel, ContentType: document.Metadata.ContentType,
			Content: document.Content,
		})
		if err != nil {
			return err
		}
		if documentPath != normalized.Metadata.Path || !bytes.Equal(document.Content, normalized.Content) || !sameMetadata(document.Metadata, normalized.Metadata) {
			return invalid("snapshot document")
		}
	}
	return nil
}

func readRegularFile(filePath string) ([]byte, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || unsafeFileInfo(info) {
		return nil, unauthorizedPath()
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	return data, nil
}

func rejectLinks(root, target string) error {
	if err := ensureWithin(root, target); err != nil {
		return err
	}
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return unauthorizedPath()
	}
	current := root
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		if segment == "" || segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		if statErr != nil || unsafeFileInfo(info) {
			return unauthorizedPath()
		}
	}
	return nil
}

func createRootSecure(target string, mode fs.FileMode) error {
	volume := filepath.VolumeName(target)
	base := string(filepath.Separator)
	if volume != "" {
		base = volume + string(filepath.Separator)
	}
	return secureMkdirAll(base, target, mode)
}

func secureMkdirAll(root, target string, mode fs.FileMode) error {
	if err := ensureWithin(root, target); err != nil {
		return err
	}
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return unauthorizedPath()
	}
	current := filepath.Clean(root)
	rootInfo, err := os.Lstat(current)
	if err != nil || !rootInfo.IsDir() || unsafeFileInfo(rootInfo) {
		return unauthorizedPath()
	}
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		if segment == "" || segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			if mkdirErr := os.Mkdir(current, mode); mkdirErr != nil {
				return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", mkdirErr, nil)
			}
			continue
		}
		if statErr != nil || !info.IsDir() || unsafeFileInfo(info) {
			return unauthorizedPath()
		}
	}
	return nil
}

func ensureWithin(root, target string) error {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return unauthorizedPath()
	}
	return nil
}

func hardenTree(root string) error {
	entries := make([]string, 0)
	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(filePath)
		if err != nil || unsafeFileInfo(info) {
			return unauthorizedPath()
		}
		entries = append(entries, filePath)
		return nil
	})
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	sort.Slice(entries, func(i, j int) bool { return len(entries[i]) > len(entries[j]) })
	for _, filePath := range entries {
		info, err := os.Lstat(filePath)
		if err != nil {
			return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
		}
		mode := fs.FileMode(0o440)
		if info.IsDir() {
			mode = 0o550
		}
		if err := os.Chmod(filePath, mode); err != nil {
			return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
		}
		if info.IsDir() {
			if err := syncDirectory(filePath); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyDocumentTree(root string, documents map[string]StoredDocument) error {
	seen := make(map[string]struct{}, len(documents))
	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filePath == root {
			return nil
		}
		info, err := os.Lstat(filePath)
		if err != nil || unsafeFileInfo(info) {
			return unauthorizedPath()
		}
		if info.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, filePath)
		if err != nil {
			return unauthorizedPath()
		}
		documentPath := filepath.ToSlash(relative)
		if _, exists := documents[documentPath]; !exists {
			return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
		}
		seen[documentPath] = struct{}{}
		return nil
	})
	if err != nil {
		if _, ok := err.(*aorerrors.Error); ok {
			return err
		}
		return aorerrors.Wrap(aorerrors.CodeArtifactHashMismatch, "", err, nil)
	}
	if len(seen) != len(documents) {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	return nil
}

func syncDirectory(directory string) error {
	file, err := os.Open(directory)
	if err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return aorerrors.Wrap(aorerrors.CodeDependencyUnavailable, "", err, nil)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return aorerrors.New(aorerrors.CodeArtifactHashMismatch, "", nil)
	}
	return nil
}

func revisionUnavailable() *aorerrors.Error {
	return aorerrors.New(aorerrors.CodeKnowledgeRevisionUnavailable, "", nil)
}

func cloneMetadata(input DocumentMetadata) DocumentMetadata {
	input.Tags = append([]string(nil), input.Tags...)
	return input
}

func sameMetadata(left, right DocumentMetadata) bool {
	return left.Path == right.Path && left.Title == right.Title && left.TrustLevel == right.TrustLevel &&
		left.ContentType == right.ContentType && left.SHA256 == right.SHA256 && left.LineCount == right.LineCount &&
		sameStrings(left.Tags, right.Tags)
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneManifest(input Manifest) Manifest {
	if input.Parents != nil {
		input.Parents = append([]ParentSnapshot{}, input.Parents...)
	}
	if input.Overrides != nil {
		input.Overrides = append([]string{}, input.Overrides...)
	}
	if input.Documents != nil {
		input.Documents = append([]DocumentMetadata{}, input.Documents...)
	}
	for index := range input.Documents {
		input.Documents[index] = cloneMetadata(input.Documents[index])
	}
	return input
}

func cloneSnapshot(input Snapshot) Snapshot {
	output := Snapshot{Manifest: cloneManifest(input.Manifest), Documents: make(map[string]StoredDocument, len(input.Documents))}
	for documentPath, document := range input.Documents {
		output.Documents[documentPath] = StoredDocument{Metadata: cloneMetadata(document.Metadata), Content: append([]byte(nil), document.Content...)}
	}
	return output
}
