package servicebootstrap

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/akimisaka/aor/internal/authz"
	"github.com/akimisaka/aor/internal/runtimeclient"
	"github.com/akimisaka/aor/internal/runtimeconfig"
)

type controlLeaseGrantEvaluator struct{}

func (controlLeaseGrantEvaluator) EvaluateLeaseGrant(context.Context, authz.PolicyInput) (authz.PolicyDecision, error) {
	return authz.PolicyDecision{}, nil
}

func TestControlLeaseAuthorityUsesConfiguredPersistentStoreAndSecret(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "authz"), 0o700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(root, "authz", "lease-signing-key")
	if err := os.WriteFile(secretPath, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AOR_SECRET_ROOT", root)
	database, err := sql.Open("pgx", "postgres://unused:unused@localhost/unused")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	service, err := controlLeaseAuthority(runtimeconfig.Config{
		LeaseSigningKeyRef: "secret://authz/lease-signing-key",
		DeploymentProfile:  "TEST",
	}, database, controlLeaseGrantEvaluator{})
	if err != nil || service == nil {
		t.Fatalf("service=%#v error=%v", service, err)
	}
}

func TestControlLeaseAuthorityFailsClosedWithoutValidKeyOrDependencies(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "short-key"), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AOR_SECRET_ROOT", root)
	database, err := sql.Open("pgx", "postgres://unused:unused@localhost/unused")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	config := runtimeconfig.Config{LeaseSigningKeyRef: "secret://short-key", DeploymentProfile: "TEST"}

	if _, err := controlLeaseAuthority(config, database, controlLeaseGrantEvaluator{}); !errors.Is(err, runtimeconfig.ErrInvalidConfiguration) {
		t.Fatalf("short key error = %v", err)
	}
	if _, err := controlLeaseAuthority(config, nil, controlLeaseGrantEvaluator{}); !errors.Is(err, runtimeclient.ErrInvalidClientConfig) {
		t.Fatalf("nil database error = %v", err)
	}
	if _, err := controlLeaseAuthority(config, database, nil); !errors.Is(err, runtimeclient.ErrInvalidClientConfig) {
		t.Fatalf("nil authorizer error = %v", err)
	}
}

var _ authz.LeaseGrantEvaluator = controlLeaseGrantEvaluator{}
