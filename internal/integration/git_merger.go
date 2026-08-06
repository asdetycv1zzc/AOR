package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/akimisaka/aor/internal/observability"
)

const gitOutputLimit = 64 << 10

type GitMerger struct {
	repositoryPath string
	mu             sync.Mutex
}

func NewGitMerger(repositoryPath string) (*GitMerger, error) {
	absolute, err := filepath.Abs(repositoryPath)
	if err != nil || repositoryPath == "" || !filepath.IsAbs(repositoryPath) || filepath.Clean(repositoryPath) != absolute {
		return nil, ErrInvalidRequest
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return nil, ErrInvalidRequest
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidRequest
	}
	objects, err := os.Lstat(filepath.Join(absolute, "objects"))
	if err != nil || !objects.IsDir() || objects.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidRequest
	}
	merger := &GitMerger{repositoryPath: absolute}
	bare, err := merger.git(context.Background(), "rev-parse", "--is-bare-repository")
	if err != nil || bare != "true" {
		return nil, ErrInvalidRequest
	}
	objectFormat, err := merger.git(context.Background(), "rev-parse", "--show-object-format")
	if err != nil || objectFormat != "sha1" {
		return nil, ErrInvalidRequest
	}
	return merger, nil
}

func (m *GitMerger) Merge(ctx context.Context, baseCommit string, candidates []string, integrationID string) (commit string, resultErr error) {
	if m == nil || ctx == nil || ctx.Err() != nil || !commitID(baseCommit) || !safeIntegrationID(integrationID) || len(candidates) == 0 || len(candidates) > 1024 {
		return "", ErrInvalidRequest
	}
	commits := append([]string(nil), candidates...)
	sort.Strings(commits)
	for index, candidate := range commits {
		if !commitID(candidate) || candidate == baseCommit || index > 0 && candidate == commits[index-1] {
			return "", ErrInvalidRequest
		}
	}
	ctx, traceSpan := observability.StartSpan(ctx, observability.SpanRepoCommit, observability.Correlation{
		ProjectIDReason:  observability.ReasonUnavailable,
		WorkflowID:       integrationID,
		TaskIDReason:     observability.ReasonNotApplicable,
		AgentRunIDReason: observability.ReasonNotApplicable,
	}, nil)
	defer func() {
		attributes := map[string]string{}
		if commit != "" {
			attributes["aor.repo.commit.id"] = commit
		}
		observability.EndSpan(ctx, traceSpan, resultErr, observability.TraceOutcome{}, attributes)
	}()

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, found, err := m.lookup(ctx, integrationID); err != nil {
		return "", err
	} else if found {
		return existing, nil
	}
	if err := m.verifyCommit(ctx, baseCommit); err != nil {
		return "", err
	}
	for _, candidate := range commits {
		if err := m.verifyCommit(ctx, candidate); err != nil {
			return "", err
		}
		if _, err := m.git(ctx, "merge-base", "--is-ancestor", baseCommit, candidate); err != nil {
			return "", ErrMergeConflict
		}
	}

	current := baseCommit
	for _, candidate := range commits {
		tree, err := m.git(ctx, "merge-tree", "--write-tree", "--no-messages", current, candidate)
		if err != nil || !commitID(tree) {
			return "", ErrMergeConflict
		}
		current, err = m.git(ctx, "commit-tree", tree, "-p", current, "-p", candidate, "-m", "aor: integrate "+integrationID)
		if err != nil || !commitID(current) {
			return "", ErrMergeConflict
		}
	}

	ref := integrationRef(integrationID)
	zero := strings.Repeat("0", 40)
	if _, err := m.git(ctx, "update-ref", ref, current, zero); err != nil {
		if existing, found, lookupErr := m.lookup(ctx, integrationID); lookupErr == nil && found {
			return existing, nil
		}
		return "", ErrMergeConflict
	}
	commit = current
	return commit, nil
}

func (m *GitMerger) Lookup(ctx context.Context, integrationID string) (string, bool, error) {
	if m == nil || ctx == nil || ctx.Err() != nil || !safeIntegrationID(integrationID) {
		return "", false, ErrInvalidRequest
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lookup(ctx, integrationID)
}

func (m *GitMerger) lookup(ctx context.Context, integrationID string) (string, bool, error) {
	commit, err := m.git(ctx, "for-each-ref", "--format=%(objectname)", "--count=1", integrationRef(integrationID))
	if err != nil {
		return "", false, ErrMergeConflict
	}
	if commit == "" {
		return "", false, nil
	}
	if !commitID(commit) || m.verifyCommit(ctx, commit) != nil {
		return "", false, ErrMergeConflict
	}
	return commit, true, nil
}

func (m *GitMerger) verifyCommit(ctx context.Context, commit string) error {
	resolved, err := m.git(ctx, "rev-parse", "--verify", commit+"^{commit}")
	if err != nil || resolved != commit {
		return ErrMergeConflict
	}
	return nil
}

func (m *GitMerger) git(ctx context.Context, arguments ...string) (string, error) {
	if ctx == nil {
		return "", ErrInvalidRequest
	}
	base := []string{"--no-pager", "--no-replace-objects", "--git-dir", m.repositoryPath, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false"}
	command := exec.CommandContext(ctx, "git", append(base, arguments...)...)
	command.Dir = m.repositoryPath
	command.Env = []string{
		"LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_AUTHOR_NAME=AOR Integration",
		"GIT_AUTHOR_EMAIL=aor-integration@localhost",
		"GIT_COMMITTER_NAME=AOR Integration",
		"GIT_COMMITTER_EMAIL=aor-integration@localhost",
	}
	var stdout, stderr boundedGitOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", ctx.Err()
		}
		return "", err
	}
	return strings.TrimSpace(stdout.String()), nil
}

func integrationRef(integrationID string) string {
	digest := sha256.Sum256([]byte(integrationID))
	return "refs/aor/integrations/" + hex.EncodeToString(digest[:])
}

func safeIntegrationID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

type boundedGitOutput struct {
	data []byte
}

func (output *boundedGitOutput) Write(value []byte) (int, error) {
	remaining := gitOutputLimit - len(output.data)
	if remaining > len(value) {
		remaining = len(value)
	}
	if remaining > 0 {
		output.data = append(output.data, value[:remaining]...)
	}
	return len(value), nil
}

func (output *boundedGitOutput) String() string {
	return string(output.data)
}

var _ MergeExecutor = (*GitMerger)(nil)
