package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

var (
	safeIDPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	artifactDigestPattern = regexp.MustCompile(`^artifact://sha256/[0-9a-f]{64}$`)
)

type Service struct {
	root       string
	leases     LeaseValidator
	store      SubmissionStore
	signer     Signer
	clock      func() time.Time
	mu         sync.RWMutex
	submitMu   sync.Mutex
	workspaces map[string]Workspace
}

func NewService(root string, leases LeaseValidator, store SubmissionStore, signer Signer, clock func() time.Time) (*Service, error) {
	if root == "" || leases == nil || signer == nil {
		return nil, ErrInvalidRequest
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, ErrInvalidRequest
	}
	if info, statErr := os.Lstat(absolute); statErr != nil || !info.IsDir() || unsafePathInfo(info) {
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
	gitDirectory := filepath.Join(s.root, ".aor-git", workspaceIDDigest(id))
	if filepath.Clean(source) == filepath.Clean(directory) {
		return Workspace{}, ErrInvalidRequest
	}
	moduleSpecRef := contracts.SpecRef{Version: request.ModuleSpec.ModuleSpecVersion, SHA256: request.ModuleSpec.SHA256}
	parameterDigest, err := leaseParameterDigest(struct {
		Source          string            `json:"source"`
		BaseCommit      string            `json:"baseCommit"`
		ModuleSpecRef   contracts.SpecRef `json:"moduleSpecRef"`
		AttemptSeriesID string            `json:"attemptSeriesId"`
		Attempt         int               `json:"attempt"`
	}{source, request.BaseCommit, moduleSpecRef, request.AttemptSeriesID, request.Attempt})
	if err != nil {
		return Workspace{}, err
	}
	validation := LeaseValidation{Proof: request.Lease, Action: LeaseActionCreateWorkspace, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, AttemptSeriesID: request.AttemptSeriesID, Attempt: request.Attempt, ModuleSpecRef: moduleSpecRef, AgentInstanceID: request.AgentIdentity.AgentInstanceID, Role: request.AgentIdentity.Role, ResourcePath: directory, ParameterDigest: parameterDigest}
	if err := s.validateLease(ctx, validation); err != nil {
		return Workspace{}, err
	}
	if err := os.MkdirAll(filepath.Dir(directory), 0o700); err != nil {
		return Workspace{}, err
	}
	if err := rejectSymlinkTree(s.root, directory); err != nil {
		return Workspace{}, err
	}
	if err := cloneRepository(ctx, source, directory, gitDirectory); err != nil {
		return Workspace{}, err
	}
	if err := configureWorkspaceVisibility(ctx, directory, request.ModuleSpec.AllowedPaths, request.ModuleSpec.ForbiddenPaths); err != nil {
		_ = os.RemoveAll(gitDirectory)
		return Workspace{}, err
	}
	if _, err := git(ctx, directory, "rev-parse", "--verify", request.BaseCommit+"^{commit}"); err != nil {
		_ = os.RemoveAll(gitDirectory)
		return Workspace{}, ErrInitialCommitNeeded
	}
	workspace := Workspace{ID: id, TenantID: request.TenantID, ProjectID: request.ProjectID, TaskID: request.TaskID, Attempt: request.Attempt, AttemptSeriesID: request.AttemptSeriesID, Path: directory, Branch: workspaceBranch(request), BaseCommit: request.BaseCommit, AllowedPaths: append([]string(nil), request.ModuleSpec.AllowedPaths...), ForbiddenPaths: effectiveForbiddenPaths(request.ModuleSpec.ForbiddenPaths), AcceptanceCriteria: append([]string(nil), request.ModuleSpec.AcceptanceCriteria...), ModuleSpecRef: moduleSpecRef, AgentIdentity: request.AgentIdentity, gitDir: gitDirectory}
	if err := checkoutCommit(ctx, workspace, request.BaseCommit); err != nil {
		_ = os.RemoveAll(gitDirectory)
		return Workspace{}, err
	}
	if err := s.validateLease(ctx, validation); err != nil {
		_ = os.RemoveAll(gitDirectory)
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
	relative, err := ownedPath(workspace, request.Path)
	if err != nil {
		return err
	}
	if len(request.Content) > 4<<20 {
		return ErrInvalidRequest
	}
	parameterDigest, err := leaseParameterDigest(struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	}{relative, DigestBytes(request.Content), len(request.Content)})
	if err != nil {
		return err
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionWriteFile, relative, parameterDigest); err != nil {
		return err
	}
	target := filepath.Join(workspace.Path, filepath.FromSlash(relative))
	if err := rejectSymlinkTree(workspace.Path, target); err != nil {
		return err
	}
	if info, statErr := os.Lstat(target); statErr == nil && unsafePathInfo(info) {
		return ErrPathDenied
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionWriteFile, relative, parameterDigest); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	file, err := openFileNoFollow(target)
	if err != nil {
		return err
	}
	defer file.Close()
	if unsafeOpenedFile(file) {
		return ErrPathDenied
	}
	if err := file.Truncate(0); err != nil {
		return err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
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
	relative, err := ownedPath(workspace, request.Path)
	if err != nil {
		return err
	}
	parameterDigest, err := leaseParameterDigest(struct {
		Path string `json:"path"`
	}{relative})
	if err != nil {
		return err
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionDeleteFile, relative, parameterDigest); err != nil {
		return err
	}
	target := filepath.Join(workspace.Path, filepath.FromSlash(relative))
	if err := rejectSymlinkTree(workspace.Path, target); err != nil {
		return err
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionDeleteFile, relative, parameterDigest); err != nil {
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
	file, err := openReadFileNoFollow(target)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if unsafeOpenedFile(file) {
		return nil, ErrPathDenied
	}
	content, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > 4<<20 {
		return nil, ErrInvalidRequest
	}
	return append([]byte(nil), content...), nil
}

func (s *Service) Submit(ctx context.Context, request SubmissionRequest) (Submission, error) {
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	workspace, err := s.workspace(request.WorkspaceID)
	if err != nil {
		return Submission{}, err
	}
	if request.Attempt != workspace.Attempt || request.Attempt < 1 || request.Attempt > 3 || !safeCommitMetadata(request.IdempotencyKey) {
		return Submission{}, ErrInvalidRequest
	}
	if !validSubmissionMetadata(workspace, request) {
		return Submission{}, ErrInvalidRequest
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = s.clock().UTC()
	}
	if !request.CreatedAt.Before(s.clock().UTC().Add(time.Minute)) {
		return Submission{}, ErrInvalidRequest
	}
	requestDigest, err := submissionRequestDigest(request)
	if err != nil {
		return Submission{}, err
	}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return Submission{}, err
	}
	if prior, found, err := s.store.Get(ctx, workspace.TenantID, workspace.TaskID, workspace.AttemptSeriesID, request.Attempt); err != nil {
		return Submission{}, err
	} else if found {
		if prior.IdempotencyKey != request.IdempotencyKey || prior.RequestSHA256 != requestDigest {
			return Submission{}, ErrSubmissionConflict
		}
		return cloneSubmission(prior), nil
	}
	changed, deleted, created, err := s.commitWorkspace(ctx, workspace, request.Lease, requestDigest, request.IdempotencyKey)
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
	payload, digestErr := manifestPayload(manifest)
	if digestErr != nil {
		return Submission{}, digestErr
	}
	manifest.Signature, err = s.signer.Sign(ctx, payload)
	if err != nil || !validServiceSignature(manifest.Signature) {
		return Submission{}, ErrInvalidRequest
	}
	if err := s.signer.Verify(ctx, payload, manifest.Signature); err != nil {
		return Submission{}, ErrInvalidRequest
	}
	if err := manifest.Validate(); err != nil {
		return Submission{}, err
	}
	submission := Submission{Manifest: manifest, Workspace: cloneWorkspace(workspace), CommitAt: s.clock().UTC(), IdempotencyKey: request.IdempotencyKey, RequestSHA256: requestDigest}
	if err := s.validateWorkspaceLease(ctx, workspace, request.Lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return Submission{}, err
	}
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

func (s *Service) validateWorkspaceLease(ctx context.Context, workspace Workspace, proof LeaseProof, action LeaseAction, resourcePath, parameterDigest string) error {
	if proof.ID == "" || proof.ID != workspace.AgentIdentity.LeaseID {
		return ErrLeaseStale
	}
	return s.validateLease(ctx, LeaseValidation{Proof: proof, Action: action, TenantID: workspace.TenantID, ProjectID: workspace.ProjectID, TaskID: workspace.TaskID, AttemptSeriesID: workspace.AttemptSeriesID, Attempt: workspace.Attempt, ModuleSpecRef: workspace.ModuleSpecRef, AgentInstanceID: workspace.AgentIdentity.AgentInstanceID, Role: workspace.AgentIdentity.Role, ResourcePath: resourcePath, ParameterDigest: parameterDigest})
}

func (s *Service) validateLease(ctx context.Context, validation LeaseValidation) error {
	if err := contextErr(ctx); err != nil {
		return err
	}
	lease := validation.Proof
	if lease.ID == "" || lease.FencingToken < 1 || lease.ExpiresAt.IsZero() || !s.clock().Before(lease.ExpiresAt) || validation.Action == "" || validation.TenantID == "" || validation.ProjectID == "" || validation.TaskID == "" || validation.AttemptSeriesID == "" || validation.Attempt < 1 || validation.Attempt > 3 || validation.ModuleSpecRef.Validate() != nil || validation.AgentInstanceID == "" || validation.Role != "EXECUTOR" || validation.ResourcePath == "" || !strings.HasPrefix(validation.ParameterDigest, "sha256:") {
		return ErrLeaseStale
	}
	if s.leases == nil {
		return ErrLeaseRequired
	}
	if err := s.leases.Validate(ctx, validation); err != nil {
		return fmt.Errorf("%w: %v", ErrLeaseStale, err)
	}
	return nil
}

func (s *Service) commitWorkspace(ctx context.Context, workspace Workspace, lease LeaseProof, requestDigest, idempotencyKey string) ([]string, []string, []string, error) {
	if !safeCommitMetadata(idempotencyKey) {
		return nil, nil, nil, ErrInvalidRequest
	}
	expectedMessage := submissionCommitMessage(workspace, idempotencyKey)
	head, err := git(ctx, workspace.Path, "rev-parse", "HEAD")
	if err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	if strings.TrimSpace(head) != workspace.BaseCommit {
		message, messageErr := git(ctx, workspace.Path, "log", "-1", "--format=%B")
		if messageErr != nil || strings.TrimSpace(message) != strings.TrimSpace(expectedMessage) {
			return nil, nil, nil, ErrRepositoryDirty
		}
		nameStatus, statusErr := git(ctx, workspace.Path, "diff", "--name-status", "--find-renames", "-z", workspace.BaseCommit+"..HEAD")
		if statusErr != nil {
			return nil, nil, nil, ErrGitUnavailable
		}
		return classifyChanges(nameStatus)
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
	if err := s.validateWorkspaceLease(ctx, workspace, lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return nil, nil, nil, err
	}
	if _, err := git(ctx, workspace.Path, "add", "--all", "."); err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	if _, err := git(ctx, workspace.Path, "diff", "--cached", "--check"); err != nil {
		return nil, nil, nil, ErrRepositoryDirty
	}
	if err := s.validateWorkspaceLease(ctx, workspace, lease, LeaseActionSubmit, workspace.Path, requestDigest); err != nil {
		return nil, nil, nil, err
	}
	if _, err := git(ctx, workspace.Path, "commit", "--no-verify", "-m", expectedMessage); err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	nameStatus, err := git(ctx, workspace.Path, "diff", "--name-status", "--find-renames", "-z", workspace.BaseCommit+"..HEAD")
	if err != nil {
		return nil, nil, nil, ErrGitUnavailable
	}
	return classifyChanges(nameStatus)
}

func checkoutCommit(ctx context.Context, workspace Workspace, commit string) error {
	if workspace.Branch == "" {
		return ErrInvalidRequest
	}
	if _, err := git(ctx, workspace.Path, "checkout", "-B", workspace.Branch, commit); err != nil {
		return ErrGitUnavailable
	}
	return nil
}

func cloneRepository(ctx context.Context, source, directory, gitDirectory string) error {
	if _, err := os.Stat(filepath.Join(source, ".git")); err != nil {
		return ErrInitialCommitNeeded
	}
	if gitDirectory == "" || filepath.Clean(gitDirectory) == filepath.Clean(directory) || strings.HasPrefix(filepath.Clean(gitDirectory), filepath.Clean(directory)+string(os.PathSeparator)) {
		return ErrInvalidRequest
	}
	if err := os.MkdirAll(filepath.Dir(gitDirectory), 0o700); err != nil {
		return err
	}
	if _, err := gitFrom(ctx, filepath.Dir(directory), "clone", "--no-local", "--separate-git-dir", gitDirectory, source, directory); err != nil {
		_ = os.RemoveAll(gitDirectory)
		return ErrGitUnavailable
	}
	// Disable repository-provided hooks and file-system monitors before the
	// untrusted checkout is materialized.
	if _, err := git(ctx, directory, "config", "core.hooksPath", filepath.Join(gitDirectory, "disabled-hooks")); err != nil {
		_ = os.RemoveAll(gitDirectory)
		return ErrGitUnavailable
	}
	return nil
}

func configureWorkspaceVisibility(ctx context.Context, directory string, allowed, forbidden []string) error {
	if len(allowed) == 0 {
		return ErrPathDenied
	}
	patterns := []string{"/*"}
	for _, value := range effectiveForbiddenPaths(forbidden) {
		clean, valid := cleanRelative(value)
		if !valid {
			return ErrPathDenied
		}
		if clean == ".git" || strings.HasPrefix(clean, ".git/") {
			continue
		}
		pattern, ok := sparsePattern(value)
		if !ok {
			return ErrPathDenied
		}
		patterns = append(patterns, "!"+pattern)
	}
	arguments := append([]string{"sparse-checkout", "set", "--no-cone", "--"}, patterns...)
	if _, err := git(ctx, directory, arguments...); err != nil {
		return ErrGitUnavailable
	}
	return validateVisibleTree(directory, effectiveForbiddenPaths(forbidden))
}

var defaultForbiddenWorkspacePaths = []string{
	"policies/...",
	"hidden-tests/...",
	".aor-hidden-tests/...",
	"audit/private/...",
	".aor-private/...",
}

func effectiveForbiddenPaths(forbidden []string) []string {
	result := append([]string(nil), forbidden...)
	result = append(result, defaultForbiddenWorkspacePaths...)
	return result
}

func sparsePattern(value string) (string, bool) {
	clean, ok := cleanRelative(value)
	if !ok || clean == ".git" || strings.HasPrefix(clean, ".git/") {
		return "", false
	}
	recursive := strings.HasSuffix(clean, "/...") || strings.HasSuffix(clean, "/**")
	clean = strings.TrimSuffix(clean, "/...")
	clean = strings.TrimSuffix(clean, "/**")
	if clean == "" || clean == "." {
		return "", false
	}
	if strings.ContainsAny(clean, "*?[") {
		return "/" + clean, true
	}
	if recursive {
		return "/" + clean + "/**", true
	}
	return "/" + clean, true
}

func validateVisibleTree(directory string, forbidden []string) error {
	return filepath.WalkDir(directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == directory {
			return nil
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(directory, name)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			return nil
		}
		if !matchesAnyPath(forbidden, relative) {
			return nil
		}
		return ErrPathDenied
	})
}

func matchesAnyPath(patterns []string, candidate string) bool {
	for _, pattern := range patterns {
		if matchesPath(pattern, candidate) {
			return true
		}
	}
	return false
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
	if !ok || strings.EqualFold(relative, ".git") || len(relative) > len(".git/") && strings.EqualFold(relative[:len(".git/")], ".git/") {
		return "", ErrPathDenied
	}
	for _, forbidden := range workspace.ForbiddenPaths {
		if matchesPath(forbidden, relative) || matchesPath(strings.ToLower(forbidden), strings.ToLower(relative)) {
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
	if cleanPattern == candidate || recursivePatternMatch(cleanPattern, candidate) {
		return true
	}
	if strings.ContainsAny(cleanPattern, "*?[") {
		matched, _ := path.Match(cleanPattern, candidate)
		return matched
	}
	return strings.HasPrefix(candidate, cleanPattern+"/")
}

func recursivePatternMatch(pattern, candidate string) bool {
	for _, suffix := range []string{"/...", "/**"} {
		if strings.HasSuffix(pattern, suffix) {
			root := strings.TrimSuffix(pattern, suffix)
			return candidate == root || strings.HasPrefix(candidate, root+"/")
		}
	}
	return false
}

func cleanRelative(value string) (string, bool) {
	if value == "" || strings.ContainsRune(value, 0) {
		return "", false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return "", false
		}
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	clean := path.Clean(normalized)
	if clean != normalized || clean == "." || strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
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
		entries, readErr := os.ReadDir(current)
		if readErr != nil {
			return readErr
		}
		for _, entry := range entries {
			if entry.Name() != segment && strings.EqualFold(entry.Name(), segment) {
				return ErrPathDenied
			}
		}
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				break
			}
			return statErr
		}
		if unsafePathInfo(info) {
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
		if part[0] == 'R' || part[0] == 'C' || part[1] == 'R' || part[1] == 'C' {
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
	parts := strings.Split(value, "\x00")
	for index := 0; index < len(parts); {
		status := parts[index]
		index++
		if status == "" {
			continue
		}
		if index >= len(parts) || parts[index] == "" {
			return nil, nil, nil, ErrRepositoryDirty
		}
		first := parts[index]
		index++
		switch status[0] {
		case 'R', 'C':
			if index >= len(parts) || parts[index] == "" {
				return nil, nil, nil, ErrRepositoryDirty
			}
			second := parts[index]
			index++
			changed = append(changed, first, second)
		case 'D':
			changed = append(changed, first)
			deleted = append(deleted, first)
		case 'A':
			changed = append(changed, first)
			created = append(created, first)
		default:
			changed = append(changed, first)
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

func workspaceIDDigest(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

func workspaceBranch(request WorkspaceRequest) string {
	return "agent/" + branchPart(request.ProjectID) + "/" + branchPart(request.TaskID) + "/attempt-" + strconv.Itoa(request.Attempt)
}

func branchPart(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}

func submissionCommitMessage(workspace Workspace, idempotencyKey string) string {
	return fmt.Sprintf("aor(%s): submission attempt %d\n\nAOR-Task: %s\nAOR-Attempt: %d\nAOR-Attempt-Series: %s\nAOR-Module-Spec: v%d %s\nAOR-Agent: %s\nAOR-Lease: %s\nAOR-Idempotency-Key: %s", workspace.TaskID, workspace.Attempt, workspace.TaskID, workspace.Attempt, workspace.AttemptSeriesID, workspace.ModuleSpecRef.Version, workspace.ModuleSpecRef.SHA256, workspace.AgentIdentity.AgentInstanceID, workspace.AgentIdentity.LeaseID, idempotencyKey)
}

func safeCommitMetadata(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func validSubmissionMetadata(workspace Workspace, request SubmissionRequest) bool {
	if len(request.ClaimedCriteria) > 256 || len(request.LocalTestEvidenceRefs) > 256 {
		return false
	}
	allowedCriteria := make(map[string]struct{}, len(workspace.AcceptanceCriteria))
	for _, criterion := range workspace.AcceptanceCriteria {
		allowedCriteria[criterion] = struct{}{}
	}
	seenCriteria := make(map[string]struct{}, len(request.ClaimedCriteria))
	for _, criterion := range request.ClaimedCriteria {
		if criterion == "" || len(criterion) > 1024 {
			return false
		}
		if _, allowed := allowedCriteria[criterion]; !allowed {
			return false
		}
		if _, duplicate := seenCriteria[criterion]; duplicate {
			return false
		}
		seenCriteria[criterion] = struct{}{}
	}
	seenEvidence := make(map[string]struct{}, len(request.LocalTestEvidenceRefs))
	for _, reference := range request.LocalTestEvidenceRefs {
		if !artifactDigestPattern.MatchString(reference) {
			return false
		}
		if _, duplicate := seenEvidence[reference]; duplicate {
			return false
		}
		seenEvidence[reference] = struct{}{}
	}
	return true
}

func validServiceSignature(signature *contracts.Signature) bool {
	return signature != nil && signature.Type != "" && len(signature.Type) <= 128 &&
		signature.KID != "" && len(signature.KID) <= 256 && signature.JWS != "" && len(signature.JWS) <= 16<<10
}

func cleanID(value string) string {
	return strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(value)
}

func validateCommit(value string) error {
	if len(value) != 40 || strings.ToLower(value) != value {
		return ErrInvalidRequest
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func leaseParameterDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return canonicaljson.Digest(encoded)
}

func submissionRequestDigest(request SubmissionRequest) (string, error) {
	return leaseParameterDigest(struct {
		WorkspaceID           string   `json:"workspaceId"`
		Attempt               int      `json:"attempt"`
		ClaimedCriteria       []string `json:"claimedCriteria"`
		LocalTestEvidenceRefs []string `json:"localTestEvidenceRefs"`
		IdempotencyKey        string   `json:"idempotencyKey"`
	}{request.WorkspaceID, request.Attempt, request.ClaimedCriteria, request.LocalTestEvidenceRefs, request.IdempotencyKey})
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
	value.AcceptanceCriteria = append([]string(nil), value.AcceptanceCriteria...)
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
