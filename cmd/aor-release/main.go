package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/akimisaka/aor/internal/supplychain"
)

type releaseConfig struct {
	SchemaVersion         string                   `json:"schemaVersion"`
	OutputDir             string                   `json:"outputDir"`
	Version               string                   `json:"version"`
	SourceURI             string                   `json:"sourceUri"`
	SourceCommit          string                   `json:"sourceCommit"`
	BuilderIdentity       string                   `json:"builderIdentity"`
	BuildType             string                   `json:"buildType"`
	InvocationID          string                   `json:"invocationId"`
	StartedAt             string                   `json:"startedAt"`
	FinishedAt            string                   `json:"finishedAt"`
	Materials             []supplychain.Material   `json:"materials"`
	Artifacts             []releaseArtifact        `json:"artifacts"`
	Dependencies          []supplychain.Dependency `json:"dependencies"`
	LicenseSource         string                   `json:"licenseSource"`
	NoticeSource          string                   `json:"noticeSource"`
	ReleaseEvidenceSource string                   `json:"releaseEvidenceSource"`
	PrivateKeyFile        string                   `json:"privateKeyFile"`
	KID                   string                   `json:"kid"`
}

type releaseArtifact struct {
	SourcePath string                   `json:"sourcePath"`
	Path       string                   `json:"path"`
	Kind       supplychain.ArtifactKind `json:"kind"`
	MediaType  string                   `json:"mediaType"`
}

func main() {
	if len(os.Args) < 2 {
		fatal("usage: aor-release assemble --config release-input.json | verify --root package --public-key release.pub")
	}
	var err error
	switch os.Args[1] {
	case "assemble":
		err = assemble(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		err = errors.New("unknown command: " + os.Args[1])
	}
	if err != nil {
		fatal(err.Error())
	}
}

func assemble(arguments []string) error {
	configPath := argument(arguments, "--config")
	if configPath == "" {
		return errors.New("--config is required")
	}
	configBytes, err := readRegular(configPath, 16<<20)
	if err != nil {
		return err
	}
	var config releaseConfig
	decoder := json.NewDecoder(strings.NewReader(string(configBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("invalid release config: %w", err)
	}
	if config.SchemaVersion != "1.0" {
		return errors.New("release config schemaVersion must be 1.0")
	}
	configRoot, err := filepath.Abs(filepath.Dir(configPath))
	if err != nil {
		return err
	}
	started, err := time.Parse(time.RFC3339, config.StartedAt)
	if err != nil {
		return fmt.Errorf("invalid startedAt: %w", err)
	}
	finished, err := time.Parse(time.RFC3339, config.FinishedAt)
	if err != nil {
		return fmt.Errorf("invalid finishedAt: %w", err)
	}
	privateKeyPath := resolve(configRoot, config.PrivateKeyFile)
	privateKeyBytes, err := readPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	privateKey, err := supplychain.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return err
	}
	request := supplychain.AssembleRequest{
		OutputDir:             resolve(configRoot, config.OutputDir),
		Version:               config.Version,
		SourceURI:             config.SourceURI,
		SourceCommit:          config.SourceCommit,
		BuilderIdentity:       config.BuilderIdentity,
		BuildType:             config.BuildType,
		InvocationID:          config.InvocationID,
		StartedAt:             started,
		FinishedAt:            finished,
		Materials:             config.Materials,
		Dependencies:          config.Dependencies,
		LicenseSource:         resolve(configRoot, config.LicenseSource),
		NoticeSource:          resolve(configRoot, config.NoticeSource),
		ReleaseEvidenceSource: resolve(configRoot, config.ReleaseEvidenceSource),
		PrivateKey:            privateKey,
		KID:                   config.KID,
	}
	for _, artifact := range config.Artifacts {
		request.Artifacts = append(request.Artifacts, supplychain.PackageArtifact{SourcePath: resolve(configRoot, artifact.SourcePath), Path: artifact.Path, Kind: artifact.Kind, MediaType: artifact.MediaType})
	}
	report, err := supplychain.Assemble(context.Background(), request)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

func verify(arguments []string) error {
	root := argument(arguments, "--root")
	publicKeyPath := argument(arguments, "--public-key")
	if root == "" || publicKeyPath == "" {
		return errors.New("--root and --public-key are required")
	}
	bundle, err := supplychain.LoadBundle(root)
	if err != nil {
		return err
	}
	keyBytes, err := readRegular(publicKeyPath, 1<<20)
	if err != nil {
		return err
	}
	publicKey, err := supplychain.ParsePublicKey(keyBytes)
	if err != nil {
		return err
	}
	report, err := supplychain.Verify(context.Background(), bundle, supplychain.Keyring{bundle.Manifest.Signature.KID: publicKey})
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

func argument(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}

func resolve(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

func readPrivateKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key must be a regular file with owner-only permissions")
	}
	return readRegular(path, 1<<20)
}

func readRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maximum {
		return nil, errors.New("input must be a bounded regular file")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
