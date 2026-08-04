//go:build windows

package repository

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsPathBoundaryRejectsJunctionAndCaseAlias(t *testing.T) {
	base := t.TempDir()
	workspace := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(filepath.Join(workspace, "owned"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(workspace, "owned", "junction")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}
	if err := rejectSymlinkTree(workspace, filepath.Join(junction, "escape.txt")); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("junction traversal error = %v", err)
	}

	caseWorkspace := filepath.Join(base, "case-workspace")
	if err := os.MkdirAll(filepath.Join(caseWorkspace, "OWNED"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rejectSymlinkTree(caseWorkspace, filepath.Join(caseWorkspace, "owned", "file.txt")); !errors.Is(err, ErrPathDenied) {
		t.Fatalf("case-folded alias error = %v", err)
	}
}

func TestWindowsPathBoundaryHandlesLongPathsAndRejectsAmbiguousNames(t *testing.T) {
	root := t.TempDir()
	directory := root
	for index := 0; len(directory) < 300; index++ {
		directory = filepath.Join(directory, "segment-"+strings.Repeat("x", 24))
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(directory, "content.txt")
	file, err := openFileNoFollow(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("native windows path")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = openReadFileNoFollow(name)
	if err != nil {
		t.Fatal(err)
	}
	if unsafeOpenedFile(file) {
		_ = file.Close()
		t.Fatal("long-path regular file was classified as unsafe")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	for _, candidate := range []string{
		"owned/line\nbreak.txt",
		"owned/line\rbreak.txt",
		"owned/caf\u00e9.go",
		"owned/cafe\u0301.go",
	} {
		if _, ok := cleanRelative(candidate); ok {
			t.Fatalf("ambiguous Windows path accepted: %q", candidate)
		}
	}
}
