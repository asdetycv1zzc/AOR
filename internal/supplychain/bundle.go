package supplychain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxManifestBytes = 16 << 20
	maxMetadataBytes = 256 << 20
)

func LoadBundle(root string) (Bundle, error) {
	if strings.TrimSpace(root) == "" || strings.ContainsRune(root, 0) {
		return Bundle{}, ErrInvalidManifest
	}
	manifestBytes, err := readRegularFile(root, ManifestFile, maxManifestBytes)
	if err != nil {
		return Bundle{}, err
	}
	var manifest Manifest
	if err := decodeStrict(manifestBytes, &manifest); err != nil {
		return Bundle{}, fmt.Errorf("%w: manifest JSON: %v", ErrInvalidManifest, err)
	}
	sbom, err := readRegularFile(root, SBOMFile, maxMetadataBytes)
	if err != nil {
		return Bundle{}, err
	}
	provenance, err := readRegularFile(root, ProvenanceFile, maxMetadataBytes)
	if err != nil {
		return Bundle{}, err
	}
	evidence, err := readRegularFile(root, ReleaseEvidenceFile, maxMetadataBytes)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{Root: root, Manifest: manifest, SBOM: sbom, Provenance: provenance, ReleaseEvidence: evidence}, nil
}

func WriteManifest(root string, manifest Manifest) error {
	if strings.TrimSpace(root) == "" || strings.ContainsRune(root, 0) {
		return ErrInvalidManifest
	}
	if err := validateManifest(manifest); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temporary := filepath.Join(root, ".release-manifest.json.tmp")
	final := filepath.Join(root, ManifestFile)
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, final); err != nil {
		return err
	}
	removeTemporary = false
	return syncDirectory(root)
}

func ParsePublicKey(value []byte) (ed25519.PublicKey, error) {
	trimmed := bytes.TrimSpace(value)
	if block, _ := pem.Decode(trimmed); block != nil {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, ErrKeyUnavailable
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, ErrKeyUnavailable
		}
		return append(ed25519.PublicKey(nil), key...), nil
	}
	decoded, err := decodeRawKey(trimmed)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, ErrKeyUnavailable
	}
	return ed25519.PublicKey(decoded), nil
}

func ParsePrivateKey(value []byte) (ed25519.PrivateKey, error) {
	trimmed := bytes.TrimSpace(value)
	if block, _ := pem.Decode(trimmed); block != nil {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrKeyUnavailable
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok || len(key) != ed25519.PrivateKeySize {
			return nil, ErrKeyUnavailable
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	}
	decoded, err := decodeRawKey(trimmed)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	default:
		return nil, ErrKeyUnavailable
	}
}

func MarshalPublicKey(key ed25519.PublicKey) ([]byte, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrKeyUnavailable
	}
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), nil
}

func readRegularFile(root, relative string, maximum int64) ([]byte, error) {
	if maximum <= 0 {
		return nil, ErrInvalidManifest
	}
	absolute := filepath.Join(root, filepath.FromSlash(relative))
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maximum {
		return nil, ErrInvalidManifest
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
	value, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(value)) > maximum {
		return nil, ErrInvalidManifest
	}
	return value, nil
}

func decodeRawKey(value []byte) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(string(value)); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(string(value)); err == nil {
		return decoded, nil
	}
	decoded, err := hex.DecodeString(string(value))
	if err != nil {
		return nil, errors.New("unsupported key encoding")
	}
	return decoded, nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}
