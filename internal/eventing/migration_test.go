package eventing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoreMigrationContainsAtomicityAndIsolationConstraints(t *testing.T) {
	path := filepath.Join("..", "..", "migrations", "postgres", "000001_core.up.sql")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sql := string(content)
	required := []string{
		"BEGIN;", "COMMIT;", "CREATE TABLE domain_events", "CREATE TABLE aggregate_projections", "CREATE TABLE command_results", "CREATE TABLE outbox", "CREATE TABLE inbox",
		"PRIMARY KEY (tenant_id, principal_id, idempotency_key)", "UNIQUE (tenant_id, aggregate_type, aggregate_id, aggregate_version)", "UNIQUE (tenant_id, attempt_series_id, attempt)",
		"CREATE TRIGGER domain_events_immutable", "ENABLE ROW LEVEL SECURITY", "FORCE ROW LEVEL SECURITY", "aor_current_tenant()", "AUTHORIZE_NEW_ATTEMPT_SERIES",
		"FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id)",
		"FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id)",
		"FOREIGN KEY (tenant_id, event_id) REFERENCES domain_events(tenant_id, event_id)",
	}
	for _, value := range required {
		if !strings.Contains(sql, value) {
			t.Errorf("migration missing %q", value)
		}
	}
	if strings.Contains(sql, "ACCEPT_RISK_AND_CONTINUE") || strings.Contains(sql, "ON DELETE CASCADE") {
		t.Fatal("migration contains a forbidden completion bypass or cascading history deletion")
	}
	manifestContent, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Migrations []struct {
			SHA256 string `json:"sha256"`
		} `json:"migrations"`
	}
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if len(manifest.Migrations) != 1 || manifest.Migrations[0].SHA256 != digest {
		t.Fatalf("migration manifest digest does not match %s", digest)
	}
}
