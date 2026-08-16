package toolchain

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/akimisaka/aor/pkg/contracts"
)

func TestArchiveInstallerInstallsPortableGoArchive(t *testing.T) {
	workspace := t.TempDir()
	archive := portableArchive(t, "go/bin/go", "#!/bin/sh\necho 'go version go1.26.5 linux/amd64'\n")
	client := &http.Client{Transport: staticArchiveTransport{content: archive}}
	installer, err := NewArchiveInstaller(ArchiveInstallerConfig{
		ToolchainRoot: filepath.Join(workspace, "tools"), WorkRoot: filepath.Join(workspace, "work"), HTTPClient: client,
		Clock: func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	tool := archiveTool("Go", "1.26.5", archive)
	installed, err := installer.Install(context.Background(), tool, []string{"Go"})
	if err != nil {
		t.Fatal(err)
	}
	if installed.Provenance == nil || installed.Provenance.Method != contracts.ToolchainInstallUserArchive || installed.Provenance.InstalledAt != "2030-01-02T03:04:05Z" {
		t.Fatalf("unexpected provenance: %#v", installed.Provenance)
	}
	if _, err := os.Stat(filepath.Join(installer.toolchainRoot, installed.ID, "bin", "go")); err != nil {
		t.Fatal(err)
	}
	second, err := installer.Install(context.Background(), tool, []string{"Go"})
	if err != nil || second.ID != installed.ID {
		t.Fatalf("idempotent installation failed: %#v %v", second, err)
	}
}

func TestArchiveInstallerRejectsTraversalAndGCC(t *testing.T) {
	workspace := t.TempDir()
	client := &http.Client{Transport: staticArchiveTransport{content: traversalArchive(t)}}
	installer, err := NewArchiveInstaller(ArchiveInstallerConfig{ToolchainRoot: filepath.Join(workspace, "tools"), WorkRoot: filepath.Join(workspace, "work"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	traversal := traversalArchive(t)
	client.Transport = staticArchiveTransport{content: traversal}
	_, err = installer.Install(context.Background(), archiveTool("Go", "1.26.5", traversal), []string{"Go"})
	if !errors.Is(err, ErrUnsupportedArchive) {
		t.Fatalf("expected unsafe archive rejection, got %v", err)
	}
	gcc := archiveTool("GCC", "15.2.0", traversal)
	_, err = installer.Install(context.Background(), gcc, []string{"C"})
	if !errors.Is(err, ErrUnsupportedTool) {
		t.Fatalf("expected GCC rejection, got %v", err)
	}
}

// Minimal BSD-3-Clause fixture from bodgit/sevenzip v1.6.5 containing "bar" and "foo".
const test7zArchiveBase64 = "N3q8ryccAASgR6WICAAAAAAAAABmAAAAAAAAAN2R8/FiYXIKZm9vCgEEBgACCQQEAAcLAgABAQABAQAMBAQACAoB6bOiBKhlMn4AAAUCGQUAAAAAABERAGIAYQByAAAAZgBvAG8AAAAZAgAAFBIBAACFM3PyY9YBAFgCcvJj1gEVCgEAIICkgSCApIEAAA=="

func TestArchiveKindFromUploadedContent(t *testing.T) {
	sevenZip, err := base64.StdEncoding.DecodeString(test7zArchiveBase64)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		payload []byte
		kind    string
	}{
		{name: "tar", payload: portableArchive(t, "bin/tool", "tool"), kind: "tar"},
		{name: "tar gzip", payload: []byte{0x1f, 0x8b}, kind: "tar.gz"},
		{name: "tar xz", payload: []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, kind: "tar.xz"},
		{name: "zip", payload: []byte{'P', 'K', 0x03, 0x04}, kind: "zip"},
		{name: "7z", payload: sevenZip, kind: "7z"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "uploaded.archive")
			if err := os.WriteFile(path, test.payload, 0o600); err != nil {
				t.Fatal(err)
			}
			kind, err := archiveKindFromFile(path)
			if err != nil || kind != test.kind {
				t.Fatalf("kind = %q, err = %v; want %q", kind, err, test.kind)
			}
		})
	}
}

func TestArchiveInstallerExtractsUploaded7zWithinLimits(t *testing.T) {
	archive, err := base64.StdEncoding.DecodeString(test7zArchiveBase64)
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	archivePath := filepath.Join(workspace, "toolchain.archive")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	installer, err := NewArchiveInstaller(ArchiveInstallerConfig{
		ToolchainRoot: filepath.Join(workspace, "tools"), WorkRoot: filepath.Join(workspace, "work"), MaxExtractBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(workspace, "extracted")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installer.extract(context.Background(), archivePath, "", destination); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bar", "foo"} {
		content, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != name+"\n" {
			t.Fatalf("%s content = %q", name, content)
		}
	}
}

func TestArchiveInstallerRejectsOversizedUploaded7z(t *testing.T) {
	archive, err := base64.StdEncoding.DecodeString(test7zArchiveBase64)
	if err != nil {
		t.Fatal(err)
	}
	workspace := t.TempDir()
	archivePath := filepath.Join(workspace, "toolchain.archive")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	installer, err := NewArchiveInstaller(ArchiveInstallerConfig{
		ToolchainRoot: filepath.Join(workspace, "tools"), WorkRoot: filepath.Join(workspace, "work"), MaxExtractBytes: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(workspace, "extracted")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := installer.extract(context.Background(), archivePath, "", destination); !errors.Is(err, ErrArchiveLimit) {
		t.Fatalf("expected archive limit error, got %v", err)
	}
}

func archiveTool(name, version string, archive []byte) contracts.VersionedTool {
	digest := sha256.Sum256(archive)
	return contracts.VersionedTool{
		Kind: contracts.ToolchainCompiler, Name: name, Version: version, Platform: contracts.PlatformLinux,
		Architecture: runtime.GOARCH, Source: contracts.ToolchainInstallRequired,
		Install: &contracts.ToolchainInstall{Method: contracts.ToolchainInstallUserArchive, Authorized: true,
			EvidenceRef: "artifact://sha256/" + strings.Repeat("a", 64), DownloadURL: "https://downloads.example.invalid/tool.tar",
			SourceSHA256: "sha256:" + hex.EncodeToString(digest[:])},
	}
}

type staticArchiveTransport struct {
	content []byte
}

func (transport staticArchiveTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(transport.content)), ContentLength: int64(len(transport.content)), Header: make(http.Header), Request: request}, nil
}

func portableArchive(t *testing.T, name, content string) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func traversalArchive(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{Name: "../outside", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
