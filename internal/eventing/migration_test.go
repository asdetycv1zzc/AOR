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
		"BEGIN;", "COMMIT;", "CREATE TABLE domain_events", "CREATE TABLE aggregate_projections", "CREATE TABLE command_results", "CREATE TABLE outbox", "CREATE TABLE inbox", "CREATE TABLE budget_accounts", "CREATE TABLE budget_reservations",
		"PRIMARY KEY (tenant_id, principal_id, idempotency_key)", "UNIQUE (tenant_id, aggregate_type, aggregate_id, aggregate_version)", "UNIQUE (tenant_id, attempt_series_id, attempt)",
		"CREATE TRIGGER domain_events_immutable", "ENABLE ROW LEVEL SECURITY", "FORCE ROW LEVEL SECURITY", "aor_current_tenant()", "AUTHORIZE_NEW_ATTEMPT_SERIES",
		"FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id)",
		"FOREIGN KEY (tenant_id, module_task_id) REFERENCES module_tasks(tenant_id, id)",
		"FOREIGN KEY (tenant_id, event_id) REFERENCES domain_events(tenant_id, event_id)",
		"UNIQUE (tenant_id, request_id, account_id)", "state IN ('RESERVED', 'SETTLED', 'RELEASED', 'RECONCILE')",
		"ALTER TABLE budget_accounts FORCE ROW LEVEL SECURITY", "ALTER TABLE budget_reservations FORCE ROW LEVEL SECURITY",
	}
	for _, value := range required {
		if !strings.Contains(sql, value) {
			t.Errorf("migration missing %q", value)
		}
	}
	if strings.Contains(sql, "ACCEPT_RISK_AND_CONTINUE") || strings.Contains(sql, "ON DELETE CASCADE") {
		t.Fatal("migration contains a forbidden completion bypass or cascading history deletion")
	}
	claimPath := filepath.Join("..", "..", "migrations", "postgres", "000002_inbox_claims.up.sql")
	claimContent, err := os.ReadFile(claimPath)
	if err != nil {
		t.Fatal(err)
	}
	claimSQL := string(claimContent)
	for _, value := range []string{
		"ADD COLUMN status", "result_jsonb jsonb", "claim_token text", "claim_attempt integer", "lease_expires_at timestamptz",
		"ALTER COLUMN result_sha256 DROP NOT NULL", "inbox_status_check", "inbox_completed_result_check", "inbox_processing_claim_check", "inbox_retryable_claim_index",
	} {
		if !strings.Contains(claimSQL, value) {
			t.Errorf("inbox claims migration missing %q", value)
		}
	}
	rolePath := filepath.Join("..", "..", "migrations", "postgres", "000003_runtime_app_role.up.sql")
	roleContent, err := os.ReadFile(rolePath)
	if err != nil {
		t.Fatal(err)
	}
	modelAuthorizerPath := filepath.Join("..", "..", "migrations", "postgres", "000004_model_authorizer_reads.up.sql")
	modelAuthorizerContent, err := os.ReadFile(modelAuthorizerPath)
	if err != nil {
		t.Fatal(err)
	}
	roleSQL := string(roleContent)
	for _, value := range []string{
		"CREATE ROLE aor_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
		"ALTER ROLE aor_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD",
		"GRANT USAGE ON SCHEMA public TO aor_app", "GRANT SELECT, INSERT, UPDATE ON TABLE public.inbox TO aor_app",
		"GRANT EXECUTE ON FUNCTION public.aor_current_tenant() TO aor_app", "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM aor_app",
	} {
		if !strings.Contains(roleSQL, value) {
			t.Errorf("runtime role migration missing %q", value)
		}
	}
	manifestContent, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Migrations []struct {
			File   string `json:"file"`
			SHA256 string `json:"sha256"`
		} `json:"migrations"`
	}
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		t.Fatal(err)
	}
	for index, migration := range []struct {
		file    string
		content []byte
	}{{file: "000001_core.up.sql", content: content}, {file: "000002_inbox_claims.up.sql", content: claimContent}, {file: "000003_runtime_app_role.up.sql", content: roleContent}, {file: "000004_model_authorizer_reads.up.sql", content: modelAuthorizerContent}} {
		sum := sha256.Sum256(migration.content)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if len(manifest.Migrations) != 4 || manifest.Migrations[index].File != migration.file || manifest.Migrations[index].SHA256 != digest {
			t.Fatalf("migration manifest digest does not match %s", digest)
		}
	}
}
