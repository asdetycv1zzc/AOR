package controlapi

import (
	"archive/tar"
	"bytes"
	"testing"
)

func TestUploadedToolchainArchiveFormats(t *testing.T) {
	var tarPayload bytes.Buffer
	tarWriter := tar.NewWriter(&tarPayload)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "toolchain/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		fileName    string
		kind        string
		contentType string
		probe       []byte
	}{
		{name: "tar", fileName: "toolchain.tar", kind: "tar", contentType: "application/x-tar", probe: tarPayload.Bytes()},
		{name: "tar xz", fileName: "toolchain.TAR.XZ", kind: "tar.xz", contentType: "application/x-xz", probe: []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}},
		{name: "tar gzip", fileName: "toolchain.tar.gz", kind: "tar.gz", contentType: "application/gzip", probe: []byte{0x1f, 0x8b}},
		{name: "zip", fileName: "toolchain.zip", kind: "zip", contentType: "application/zip", probe: []byte{'P', 'K', 0x03, 0x04}},
		{name: "7z", fileName: "toolchain.7z", kind: "7z", contentType: "application/x-7z-compressed", probe: []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kind, contentType := uploadedToolchainArchiveType(test.fileName)
			if kind != test.kind || contentType != test.contentType {
				t.Fatalf("type = %q, %q; want %q, %q", kind, contentType, test.kind, test.contentType)
			}
			if !validUploadedToolchainArchive(kind, test.probe) {
				t.Fatalf("valid %s archive rejected", test.kind)
			}
		})
	}
}

func TestUploadedToolchainArchiveRejectsUnsupportedOrMismatchedFiles(t *testing.T) {
	if kind, contentType := uploadedToolchainArchiveType("toolchain.rar"); kind != "" || contentType != "" {
		t.Fatalf("unsupported type = %q, %q", kind, contentType)
	}
	if validUploadedToolchainArchive("7z", []byte{'P', 'K', 0x03, 0x04}) {
		t.Fatal("zip payload accepted as 7z")
	}
	if validUploadedToolchainArchive("tar", make([]byte, toolchainArchiveProbeBytes)) {
		t.Fatal("invalid tar payload accepted")
	}
}
