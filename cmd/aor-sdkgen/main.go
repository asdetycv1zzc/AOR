package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/akimisaka/aor/internal/sdkgen"
)

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "verify committed clients are current")
	flag.Parse()
	input, err := os.ReadFile(filepath.Join(*root, "api", "openapi", "aor.v1.yaml"))
	if err != nil {
		fatal(err)
	}
	outputs, err := sdkgen.Generate(input)
	if err != nil {
		fatal(err)
	}
	files := map[string][]byte{
		filepath.Join("sdk", "go", "aor", "client.gen.go"):      outputs.Go,
		filepath.Join("sdk", "typescript", "aor-client.gen.ts"): outputs.TypeScript,
		filepath.Join("sdk", "python", "aor_client_gen.py"):     outputs.Python,
	}
	for name, content := range files {
		path := filepath.Join(*root, name)
		if *check {
			existing, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(existing, content) {
				fatal(fmt.Errorf("generated client is stale: %s", name))
			}
			continue
		}
		if err := writeAtomic(path, content); err != nil {
			fatal(err)
		}
	}
}

func writeAtomic(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".sdkgen-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func fatal(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
