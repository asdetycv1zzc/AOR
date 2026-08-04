package credentials

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
)

const (
	// DefaultSecretRoot is the directory used by container secret mounts.
	DefaultSecretRoot = "/run/secrets"
	// MaxSecretSize limits a secret read to 64 KiB.
	MaxSecretSize = 64 * 1024
)

var (
	ErrInvalidSecretReference = errors.New("invalid secret reference")
	ErrSecretUnavailable      = errors.New("secret unavailable")
	ErrSecretTooLarge         = errors.New("secret exceeds maximum size")
)

// SecretResolver resolves file-backed secret references beneath a trusted root.
type SecretResolver struct {
	root string
}

// NewSecretResolver creates a resolver. An empty root uses DefaultSecretRoot.
func NewSecretResolver(root string) *SecretResolver {
	if root == "" {
		root = DefaultSecretRoot
	}
	return &SecretResolver{root: root}
}

// Resolve reads a secret:// relative reference without allowing it to escape
// the resolver root. It removes one final LF (and its preceding CR, if any).
func (resolver *SecretResolver) Resolve(ctx context.Context, reference string) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	name, err := secretName(reference)
	if err != nil {
		return nil, err
	}
	if rootInfo, err := os.Lstat(resolver.root); err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, ErrSecretUnavailable
	}

	root, err := os.OpenRoot(resolver.root)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	defer root.Close()

	if err := verifySecretPath(root, name); err != nil {
		return nil, err
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}

	file, err := root.Open(name)
	if err != nil {
		return nil, ErrSecretUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrSecretUnavailable
	}

	value, err := readSecret(ctx, file)
	if err != nil {
		return nil, err
	}
	value = trimFinalNewline(value)
	if len(value) == 0 {
		return nil, ErrSecretUnavailable
	}
	return value, nil
}

func secretName(reference string) (string, error) {
	const prefix = "secret://"
	if !strings.HasPrefix(reference, prefix) {
		return "", ErrInvalidSecretReference
	}
	name := strings.TrimPrefix(reference, prefix)
	if name == "" || strings.ContainsAny(name, "\\\x00") {
		return "", ErrInvalidSecretReference
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." {
			return "", ErrInvalidSecretReference
		}
	}
	return name, nil
}

func verifySecretPath(root *os.Root, name string) error {
	components := strings.Split(name, "/")
	for index := range components {
		info, err := root.Lstat(strings.Join(components[:index+1], "/"))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrSecretUnavailable
		}
		if index < len(components)-1 && !info.IsDir() {
			return ErrSecretUnavailable
		}
		if index == len(components)-1 && !info.Mode().IsRegular() {
			return ErrSecretUnavailable
		}
	}
	return nil
}

func readSecret(ctx context.Context, file *os.File) ([]byte, error) {
	reader := io.LimitReader(file, MaxSecretSize+1)
	var value bytes.Buffer
	buffer := make([]byte, 4096)
	for {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		count, err := reader.Read(buffer)
		if count > 0 {
			_, _ = value.Write(buffer[:count])
			if value.Len() > MaxSecretSize {
				return nil, ErrSecretTooLarge
			}
		}
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		if err == io.EOF {
			return value.Bytes(), nil
		}
		if err != nil {
			return nil, ErrSecretUnavailable
		}
	}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidSecretReference
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func trimFinalNewline(value []byte) []byte {
	if len(value) == 0 || value[len(value)-1] != '\n' {
		return value
	}
	value = value[:len(value)-1]
	if len(value) > 0 && value[len(value)-1] == '\r' {
		return value[:len(value)-1]
	}
	return value
}
