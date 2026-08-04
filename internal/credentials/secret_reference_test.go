package credentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretResolverReadsRelativeReference(t *testing.T) {
	root := t.TempDir()
	writeSecret(t, root, "provider/key", []byte("value\n"))

	value, err := NewSecretResolver(root).Resolve(context.Background(), "secret://provider/key")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(value), "value"; got != want {
		t.Fatalf("secret value = %q, want %q", got, want)
	}
}

func TestSecretResolverTrimsOnlyOneFinalNewline(t *testing.T) {
	root := t.TempDir()
	writeSecret(t, root, "key", []byte("value\n\n"))

	value, err := NewSecretResolver(root).Resolve(context.Background(), "secret://key")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(value), "value\n"; got != want {
		t.Fatalf("secret value = %q, want %q", got, want)
	}
}

func TestSecretResolverTrimsCRLF(t *testing.T) {
	root := t.TempDir()
	writeSecret(t, root, "key", []byte("value\r\n"))

	value, err := NewSecretResolver(root).Resolve(context.Background(), "secret://key")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(value), "value"; got != want {
		t.Fatalf("secret value = %q, want %q", got, want)
	}
}

func TestSecretResolverRejectsInvalidReferences(t *testing.T) {
	resolver := NewSecretResolver(t.TempDir())
	for _, reference := range []string{
		"key",
		"secret://",
		"secret:///key",
		"secret://../key",
		"secret://provider/../key",
		"secret://provider\\key",
		"secret://provider/\x00key",
		"secret://provider//key",
		"secret://./key",
	} {
		_, err := resolver.Resolve(context.Background(), reference)
		if !errors.Is(err, ErrInvalidSecretReference) {
			t.Errorf("Resolve(%q) error = %v, want invalid reference", reference, err)
		}
	}
}

func TestSecretResolverRejectsLinksAndNonRegularFiles(t *testing.T) {
	root := t.TempDir()
	writeSecret(t, root, "target", []byte("value"))
	if err := os.Symlink("target", filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "parent"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../target", filepath.Join(root, "parent", "linked")); err != nil {
		t.Fatal(err)
	}

	resolver := NewSecretResolver(root)
	for _, reference := range []string{"secret://linked", "secret://directory", "secret://parent/linked"} {
		_, err := resolver.Resolve(context.Background(), reference)
		if !errors.Is(err, ErrSecretUnavailable) {
			t.Errorf("Resolve(%q) error = %v, want unavailable", reference, err)
		}
	}
}

func TestSecretResolverRejectsEmptySecret(t *testing.T) {
	root := t.TempDir()
	writeSecret(t, root, "empty", nil)

	_, err := NewSecretResolver(root).Resolve(context.Background(), "secret://empty")
	if !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("Resolve() error = %v, want unavailable", err)
	}
}

func TestSecretResolverRejectsOversizedValueWithoutLeakingIt(t *testing.T) {
	root := t.TempDir()
	value := strings.Repeat("x", MaxSecretSize+1)
	writeSecret(t, root, "large", []byte(value))

	_, err := NewSecretResolver(root).Resolve(context.Background(), "secret://large")
	if !errors.Is(err, ErrSecretTooLarge) {
		t.Fatalf("Resolve() error = %v, want oversized secret", err)
	}
	if strings.Contains(err.Error(), value) {
		t.Fatal("secret content leaked in error")
	}
}

func TestSecretResolverAcceptsMaximumValue(t *testing.T) {
	root := t.TempDir()
	writeSecret(t, root, "maximum", []byte(strings.Repeat("x", MaxSecretSize)))

	value, err := NewSecretResolver(root).Resolve(context.Background(), "secret://maximum")
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != MaxSecretSize {
		t.Fatalf("secret length = %d, want %d", len(value), MaxSecretSize)
	}
}

func TestSecretResolverHonorsCanceledContext(t *testing.T) {
	root := t.TempDir()
	writeSecret(t, root, "key", []byte("value"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := NewSecretResolver(root).Resolve(ctx, "secret://key")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolve() error = %v, want context canceled", err)
	}
}

func writeSecret(t *testing.T, root, name string, value []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
}
