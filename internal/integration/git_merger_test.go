package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type gitMergerFixture struct {
	bare      string
	base      string
	moduleA   string
	moduleB   string
	conflictA string
	conflictB string
	retry     string
	unrelated string
}

func TestGitMergerCreatesRecoverableIntegrationCommit(t *testing.T) {
	fixture := newGitMergerFixture(t)
	merger, err := NewGitMerger(fixture.bare)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := merger.Merge(context.Background(), fixture.base, []string{fixture.moduleB, fixture.moduleA}, "integration-clean")
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{fixture.moduleA, fixture.moduleB} {
		if _, err := testGit(fixture.bare, "merge-base", "--is-ancestor", candidate, merged); err != nil {
			t.Fatalf("candidate %s is not an ancestor of %s", candidate, merged)
		}
	}
	if content, err := testGit(fixture.bare, "show", merged+":modules/a.txt"); err != nil || content != "module a" {
		t.Fatalf("unexpected module a content %q: %v", content, err)
	}
	if content, err := testGit(fixture.bare, "show", merged+":modules/b.txt"); err != nil || content != "module b" {
		t.Fatalf("unexpected module b content %q: %v", content, err)
	}
	recovered, found, err := merger.Lookup(context.Background(), "integration-clean")
	if err != nil || !found || recovered != merged {
		t.Fatalf("lookup = %q, %t, %v", recovered, found, err)
	}
	duplicate, err := merger.Merge(context.Background(), fixture.base, []string{fixture.moduleA, fixture.moduleB}, "integration-clean")
	if err != nil || duplicate != merged {
		t.Fatalf("duplicate merge = %q, %v", duplicate, err)
	}
}

func TestGitMergerRejectsContentConflict(t *testing.T) {
	fixture := newGitMergerFixture(t)
	merger, err := NewGitMerger(fixture.bare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := merger.Merge(context.Background(), fixture.base, []string{fixture.conflictA, fixture.conflictB}, "integration-conflict"); !errors.Is(err, ErrMergeConflict) {
		t.Fatalf("merge error = %v", err)
	}
	if commit, found, err := merger.Lookup(context.Background(), "integration-conflict"); err != nil || found || commit != "" {
		t.Fatalf("conflicted lookup = %q, %t, %v", commit, found, err)
	}
}

func TestGitMergerAcceptsRetryDescendedFromProjectBase(t *testing.T) {
	fixture := newGitMergerFixture(t)
	merger, err := NewGitMerger(fixture.bare)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := merger.Merge(context.Background(), fixture.base, []string{fixture.retry}, "integration-retry")
	if err != nil {
		t.Fatal(err)
	}
	if content, err := testGit(fixture.bare, "show", merged+":retry.txt"); err != nil || content != "attempt two" {
		t.Fatalf("unexpected retry content %q: %v", content, err)
	}
}

func TestGitMergerRejectsNonDescendantCandidate(t *testing.T) {
	fixture := newGitMergerFixture(t)
	merger, err := NewGitMerger(fixture.bare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := merger.Merge(context.Background(), fixture.base, []string{fixture.unrelated}, "integration-unrelated"); !errors.Is(err, ErrMergeConflict) {
		t.Fatalf("merge error = %v", err)
	}
}

func newGitMergerFixture(t *testing.T) gitMergerFixture {
	t.Helper()
	root := t.TempDir()
	work := filepath.Join(root, "work")
	bare := filepath.Join(root, "project.git")
	mustTestGit(t, root, "init", "--initial-branch=main", work)
	mustTestGit(t, work, "config", "user.name", "AOR Test")
	mustTestGit(t, work, "config", "user.email", "aor-test@localhost")
	writeGitFixtureFile(t, work, "shared.txt", "base")
	mustTestGit(t, work, "add", "shared.txt")
	mustTestGit(t, work, "commit", "-m", "base")
	base := mustTestGit(t, work, "rev-parse", "HEAD")

	mustTestGit(t, work, "switch", "-c", "module-a", base)
	writeGitFixtureFile(t, work, "modules/a.txt", "module a")
	mustTestGit(t, work, "add", "modules/a.txt")
	mustTestGit(t, work, "commit", "-m", "module a")
	moduleA := mustTestGit(t, work, "rev-parse", "HEAD")

	mustTestGit(t, work, "switch", "-c", "module-b", base)
	writeGitFixtureFile(t, work, "modules/b.txt", "module b")
	mustTestGit(t, work, "add", "modules/b.txt")
	mustTestGit(t, work, "commit", "-m", "module b")
	moduleB := mustTestGit(t, work, "rev-parse", "HEAD")

	mustTestGit(t, work, "switch", "-c", "conflict-a", base)
	writeGitFixtureFile(t, work, "shared.txt", "left")
	mustTestGit(t, work, "commit", "-am", "conflict a")
	conflictA := mustTestGit(t, work, "rev-parse", "HEAD")

	mustTestGit(t, work, "switch", "-c", "conflict-b", base)
	writeGitFixtureFile(t, work, "shared.txt", "right")
	mustTestGit(t, work, "commit", "-am", "conflict b")
	conflictB := mustTestGit(t, work, "rev-parse", "HEAD")

	mustTestGit(t, work, "switch", "-c", "retry-one", base)
	writeGitFixtureFile(t, work, "retry.txt", "attempt one")
	mustTestGit(t, work, "add", "retry.txt")
	mustTestGit(t, work, "commit", "-m", "retry one")
	mustTestGit(t, work, "switch", "-c", "retry-two")
	writeGitFixtureFile(t, work, "retry.txt", "attempt two")
	mustTestGit(t, work, "commit", "-am", "retry two")
	retry := mustTestGit(t, work, "rev-parse", "HEAD")

	tree := mustTestGit(t, work, "rev-parse", base+"^{tree}")
	unrelated := mustTestGit(t, work, "commit-tree", tree, "-m", "unrelated")
	mustTestGit(t, work, "branch", "unrelated", unrelated)
	mustTestGit(t, root, "clone", "--bare", work, bare)
	return gitMergerFixture{bare: bare, base: base, moduleA: moduleA, moduleB: moduleB, conflictA: conflictA, conflictB: conflictB, retry: retry, unrelated: unrelated}
}

func writeGitFixtureFile(t *testing.T, root, name, content string) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustTestGit(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	output, err := testGit(directory, arguments...)
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(arguments, " "), err)
	}
	return output
}

func testGit(directory string, arguments ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	output, err := command.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}
