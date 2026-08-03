package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akimisaka/aor/pkg/canonicaljson"
	"github.com/akimisaka/aor/pkg/contracts"
)

var safeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type Service struct {
	root       string
	leases     LeaseValidator
	store      SubmissionStore
	signer     Signer
	clock      func() time.Time
	mu         sync.RWMutex
	workspaces map[string]Workspace
}

func NewService(root string, leases LeaseValidator, store SubmissionStore, signer Signer, clock func() time.Time) (*Service, error) {
	if root == "" {
		return nil, ErrInvalidRequest
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if info, statErr := os.Stat(absolute); statErr == nil && !info.IsDir() {
		return nil, ErrInvalidRequest
	}
	if store == nil {
		store = NewMemorySubmissionStore()
	}
	if clock == nil {
		clock = time.Now
	}
	return &Service{root: absolute, leases: leases, store: store, signer: signer, clock: clock, workspaces: make(map[string]Workspace)}, nil
}

func (s *Service) CreateWorkspace(ctx context.Context, request WorkspaceRequest) (Workspace, error) {
	if err := contextErr(ctx); err != nil {
		return Workspace{}, err
	}
	if !safeIDPattern.MatchString(request.TenantID) || !safeIDPattern.MatchString(request.ProjectID) || !safeIDPattern.MatchString(request.TaskID) || !safeIDPattern.MatchString(request.AttemptSeriesID) || request.Attempt < 1 || request.Attempt > 3 || request.ModuleSpec.Validate() != nil || request.AgentIdentity.AgentInstanceID == "" || request.AgentIdentity.Role != "EXECUTOR" || request.AgentIdentity.LeaseID != request.Lease.ID || request.Lease.ID == "" || request.Lease.FencingToken < 1 {
		return Workspace{}, ErrInvalidRequest
	}
	if err := s.validateLease(ctx, request.Lease); err != nil {
		return Workspace{}, err
	}
	if err := validateCommit(request.BaseCommit); err != nil {
		return Workspace{}, ErrInvalidRequest
	}
	id := workspaceID(request)
	workspaceRoot := filepath.Join(s.root, ".aor-workspaces")
	source := request.RepositoryPath
	if source == "" {
		source = s.root
	}
	source, err := filepath.Abs(source)
	if err != nil {
		return Workspace{}, ErrInvalidRequest
	}
	directory := filepath.Join(workspaceRoot, cleanID(request.TenantID), cleanID(request.ProjectID), cleanID(request.TaskID), fmt.Sprintf("attempt-%d", request.Attempt))
	if filepath.Clean(source) == filepath.Clean(directory) {
		return Workspace{}, ErrInvalidRequest
	}
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		return Workspace{}, err
	}
	if err := rejectSymlinkTree(s.root, directory); err != nil {
		return Workspace{}, err
	}
	if err := cloneRepository(ctx, source, directory); err != nil {
		return Workspace{}, err
	}
	if _, err := git(ctx, directory, "rev-parse", "--verify", request.BaseCommit+"^{commit}"); err != nil {
		return Workspace{}, ErrInitialCommitNeeded
	}
	workspace := Workspace{ID: id, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, Attempt: request.Attempt, AttemptSeriesID: request.AttemptSeriesID, Path: directory, BaseCommit: request.BaseCommit, AllowedPaths: append([]string(nil), request.ModuleSpec.AllowedPaths...), ForbiddenPaths: append([]string(nil), request.ModuleSpec.ForbiddenPaths...), ModuleSpecRef: contracts.SpecRef{Version: request.ModuleSpec.ModuleSpecVersion, SHA256: request.ModuleSpec.SHA256}, AgentIdentity: request.AgentIdentity}
	if err := checkoutCommit(ctx, workspace, request.BaseCommit); err != nil {
		return Workspace{}, err
	}
	s.mu.Lock()
	s.workspaces[id] = workspace
	s.mu.Unlock()
	return cloneWorkspace(workspace), nil
}

func (s *Service) WriteFile(ctx context.Context, request WriteRequest) error {
	workspace, err := s.workspace(request.WorkspaceID)
	if err != nil {
		return err
	}
	if err := s.validateLease(ctx, request.Lease); err != nil {
		return err
	}
	relative, err := ownedPath(workspace, request.Path)
	if err != nil {
		return err
	}
	if len(request.Content) > 4<<20 {
		return ErrInvalidRequest
	}
	target := filepath.Join(workspace.Path, filepath.FromSlash(relative))
	if err := rejectSymlinkTree(workspace.Path, target); err != nil {
		return err
	}
	if info, statErr := os.Lstat(target); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrPathDenied
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(request.Content); err != nil {
		return err
	}
	return file.Sync()
}

func (s *Service) DeleteFile(ctx context.Context, request DeleteRequest) error {
	workspace, err := s.workspace(request.WorkspaceID)
	if err != nil {
		return err
	}
	if err := s.validateLease(ctx, request.Lease); err != nil {
		return err
	}
	relative, err := ownedPath(workspace, request.Path)
	if err != nil {
		return err
	}
	target := filepath.Join(workspace.Path, filepath.FromSlash(relative))
	if err := rejectSymlinkTree(workspace.Path, target); err != nil {
		return err
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Service) ReadFile(ctx context.Context, workspaceID, name string) ([]byte, error) {
	workspace, err := s.workspace(workspaceID)
	if err != nil {
		return nil, err
	}
	relative, err := ownedPath(workspace, name)
	if err != nil {
		return nil, err
	}
	target := filepath.Join(workspace.Path, filepath.FromSlash(relative))
	if err := rejectSymlinkTree(workspace.Path, target); err != nil {
		return nil, err
	}
	content, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	if len(content) > 4<<20 {
		return nil, ErrInvalidRequest
	}
	return append([]byte(nil), content...), nil
}

func (s *Service) Submit(ctx context.Context, request SubmissionRequest) (Submission, error) {
	workspace, err := s.workspace(request.WorkspaceID)
	if err != nil {
		return Submission{}, err
	}
	if request.Attempt != workspace.Attempt || request.Attempt < 1 || request.Attempt > 3 || request.IdempotencyKey == "" {
		return Submission{}, ErrInvalidRequest
	}
	if err := s.validateLease(ctx, request.Lease); err != nil {
		return Submission{}, err
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = s.clock().UTC()
	}
	if !request.CreatedAt.Before(s.clock().UTC().Add(time.Minute)) {
		return Submission{}, ErrInvalidRequest
	}
	if prior, found, err := s.store.Get(ctx, workspace.TenantID, workspace.TaskID, request.Attempt); err != nil {
		return Submission{}, err
	} else if found {
		return cloneSubmission(prior), nil
	}
	changed, deleted, created, err := s.commitWorkspace(ctx, workspace, request.Lease, request.IdempotencyKey)
	if err != nil {
		return Submission{}, err
	}
	head, err := git(ctx, workspace.Path, "rev-parse", "HEAD")
	if err != nil {
		return Submission{}, ErrGitUnavailable
	}
	manifest := contracts.SubmissionManifest{SubmissionVersion: 1, ProjectID: workspace.ProjectID, ModuleTaskID: workspace.TaskID, AttemptSeriesID: workspace.AttemptSeriesID, Attempt: request.Attempt, ModuleSpecRef: workspace.ModuleSpecRef, BaseCommit: workspace.BaseCommit, HeadCommit: strings.TrimSpace(head), ChangedFiles: changed, DeletedFiles: deleted, CreatedFiles: created, ClaimedCriteria: append([]string(nil), request.ClaimedCriteria...), LocalTestEvidenceRefs: append([]string(nil), request.LocalTestEvidenceRefs...), AgentIdentity: workspace.AgentIdentity, CreatedAt: request.CreatedAt.UTC().Format(time.RFC3339)}
	if err := fillManifestDigest(&manifest); err != nil {
		return Submission{}, err
	}
	if s.signer != nil {
		payload, digestErr := manifestPayload(manifest)
		if digestErr != nil {
			return Submission{}, digestErr
		}
		manifest.Signature, err = s.signer.Sign(ctx, payload)
		if err != nil {
			return Submission{}, err
		}
	}
	if err := manifest.Validate(); err != nil {
		return Submission{}, err
	}
	submission := Submission{Manifest: manifest, Workspace: cloneWorkspace(workspace), CommitAt: s.clock().UTC()}
	if err := s.store.Put(ctx, submission); err != nil {
		return Submission{}, err
	}
	return cloneSubmission(submission), nil
}

func (s *Service) Workspace(id string) (Workspace, bool) {
	workspace, err := s.workspace(id)
	return workspace, err == nil
}

func (s *Service) workspace(id string) (Workspace, error) {
	if id == "" {
		return Workspace{}, ErrWorkspaceNotFound
	}
	s.mu.RLock()
	workspace, found := s.workspaces[id]
	s.mu.RUnlock()
	if !found {
		return Workspace{}, ErrWorkspaceNotFound
	}
	return cloneWorkspace(workspace), nil
}

func (s *Service) validateLease(ctx context.Context, lease LeaseProof) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	if lease.ID == "" || lease.FencingToken < 1 || lease.ExpiresAt.IsZero() || !s.clock().Before(lease.ExpiresAt) {
		return ErrLeaseStale
	}
	if s.leases == nil {
		return ErrLeaseRequired
	}
	if err := s.leases.Validate(ctx, lease); err != nil {
		return fmt.Errorf("%w: %v", ErrLeaseStale, err)
	}
	return nil
}

func (s *Service) commitWorkspace(ctx context.Context, workspace Workspace, lease LeaseProof, idempotencyKey string) ([]string, []string, []string, error) {
	if idempotencyKey == "" {
		return nil, nil, nil, ErrInvalidRequest
	}
	status, err := git(ctx, workspace.Path, "status", "--porcelain=v1", "-z")
	if err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	paths, err := parseStatusPaths(status)
	if err != nil || len(paths) == 0 {
		return nil, nil, nil, ErrRepositoryDirty
	}
	for _, name := range paths {
		if _, pathErr := ownedPath(workspace, name); pathErr != nil {
			return nil, nil, nil, pathErr
		}
	}
	if _, err := git(ctx, workspace.Path, "add", "--all", "."); err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	if _, err := git(ctx, workspace.Path, "diff", "--cached", "--check"); err != nil {
		return nil, nil, nil, ErrRepositoryDirty
	}
	message := fmt.Sprintf("aor(%s): attempt-%d %s", workspace.TaskID, workspace.Attempt, idempotencyKey)
	if _, err := git(ctx, workspace.Path, "commit", "--no-verify", "-m", message); err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	nameStatus, err := git(ctx, workspace.Path, "diff", "--name-status", "--find-renames", workspace.BaseCommit+"..HEAD")
	if err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	return classifyChanges(nameStatus)
}

func checkoutCommit(ctx context.Context, workspace Workspace, commit string) error {
	if _, err := git(ctx, workspace.Path, "checkout", "--detach", commit); err != nil {
		return ErrGitUnavailable
	}
	return nil
}

func cloneRepository(ctx context.Context, source, directory string) error {
	if _, err := os.Stat(filepath.Join(source, ".git")); err != nil {
		return ErrInitialCommitNeeded
	}
	if _, err := gitFrom(ctx, filepath.Dir(directory), "clone", "--no-local", source, directory); err != nil {
		return ErrGitUnavailable
	}
	return nil
}

func git(ctx context.Context, directory string, args ...string) (string, error) {
	return gitFrom(ctx, directory, args...)
}

func gitFrom(ctx context.Context, directory string, args ...string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_AUTHOR_NAME=AOR Repository Service", "GIT_AUTHOR_EMAIL=repository-service@aor.invalid", "GIT_COMMITTER_NAME=AOR Repository Service", "GIT_COMMITTER_EMAIL=repository-service@aor.invalid")
	output, err := command.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(output), nil
}

func ownedPath(workspace Workspace, candidate string) (string, error) {
	relative, ok := cleanRelative(candidate)
	if !ok || relative == ".git" || strings.HasPrefix(relative, ".git/") {
		return "", ErrPathDenied
	}
	for _, forbidden := range workspace.ForbiddenPaths {
		if matchesPath(forbidden, relative) {
			return "", ErrPathDenied
		}
	}
	if len(workspace.AllowedPaths) == 0 {
		return "", ErrPathDenied
	}
	for _, allowed := range workspace.AllowedPaths {
		if matchesPath(allowed, relative) {
			return relative, nil
		}
	}
	return "", ErrPathDenied
}

func matchesPath(pattern, candidate string) bool {
	cleanPattern, ok := cleanRelative(pattern)
	if !ok {
		return false
	}
	if cleanPattern == candidate || strings.HasSuffix(cleanPattern, "/...") && (candidate == strings.TrimSuffix(cleanPattern, "/...") || strings.HasPrefix(candidate, strings.TrimSuffix(cleanPattern, "/...")+"/")) {
		return true
	}
	if strings.ContainsAny(cleanPattern, "*?[") {
		matched, _ := path.Match(cleanPattern, candidate)
		return matched
	}
	return strings.HasPrefix(candidate, cleanPattern+"/")
}

func cleanRelative(value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", false
	}
	clean := path.Clean(strings.ReplaceAll(value, "\\", "/"))
	if clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	return clean, true
}

func rejectSymlinkTree(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return ErrPathDenied
	}
	current := root
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == "" || segment == "." {
			continue
		}
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				break
			}
			return statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrPathDenied
		}
	}
	return nil
}

func parseStatusPaths(value string) ([]string, error) {
	parts := strings.Split(value, "\x00")
	paths := make([]string, 0, len(parts))
	for index := 0; index < len(parts); index++ {
		part := parts[index]
		if part == "" {
			continue
		}
		if len(part) < 4 {
			return nil, ErrRepositoryDirty
		}
		name := strings.TrimSpace(part[3:])
		if len(name) == 0 {
			return nil, ErrRepositoryDirty
		}
		if strings.HasPrefix(name, "\"") {
			return nil, ErrRepositoryDirty
		}
		paths = append(paths, name)
		if part[0] == 'R' || part[0] == 'C' {
			if index+1 >= len(parts) || parts[index+1] == "" {
				return nil, ErrRepositoryDirty
			}
			paths = append(paths, parts[index+1])
			index++
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func classifyChanges(value string) ([]string, []string, []string, error) {
	var changed, deleted, created []string
	for _, line := range strings.Split(strings.TrimSpace(value), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[len(fields)-1]
		changed = append(changed, name)
		switch fields[0][0] {
		case 'D':
			deleted = append(deleted, name)
		case 'A':
			created = append(created, name)
		}
	}
	sort.Strings(changed)
	sort.Strings(deleted)
	sort.Strings(created)
	return changed, deleted, created, nil
}

func fillManifestDigest(manifest *contracts.SubmissionManifest) error {
	manifest.SHA256 = ""
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	digest, err := canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
	if err != nil {
		return err
	}
	manifest.SHA256 = digest
	return nil
}

func manifestPayload(manifest contracts.SubmissionManifest) ([]byte, error) {
	manifest.SHA256 = ""
	manifest.Signature = nil
	return canonicaljson.Canonicalize(mustJSON(manifest))
}

func mustJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func workspaceID(request WorkspaceRequest) string {
	return request.TenantID + ":" + request.ProjectID + ":" + request.TaskID + ":" + strconv.Itoa(request.Attempt)
}

func cleanID(value string) string {
	return strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(value)
}

func validateCommit(value string) error {
	if len(value) != 40 {
		return ErrInvalidRequest
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func cloneWorkspace(value Workspace) Workspace {
	value.AllowedPaths = append([]string(nil), value.AllowedPaths...)
	value.ForbiddenPaths = append([]string(nil), value.ForbiddenPaths...)
	return value
}

func DigestManifest(manifest contracts.SubmissionManifest) (string, error) {
	manifest.SHA256 = ""
	manifest.Signature = nil
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	return canonicaljson.DigestObjectWithoutFields(encoded, "sha256", "signature")
}

func DigestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
