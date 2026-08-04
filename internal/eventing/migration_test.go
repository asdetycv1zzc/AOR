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
	for _, value := range []string{"CREATE TABLE goal_specs", "ALTER TABLE goal_specs FORCE ROW LEVEL SECURITY", "CREATE POLICY goal_specs_tenant_policy"} {
		if !strings.Contains(sql, value) {
			t.Errorf("GoalSpec persistence missing %q", value)
		}
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
	if !strings.Contains(string(modelAuthorizerContent), "GRANT SELECT ON TABLE public.module_specs, public.module_tasks TO aor_app") {
		t.Fatal("model authorizer migration is missing task and spec reads")
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
	goalGrantPath := filepath.Join("..", "..", "migrations", "postgres", "000011_goal_spec_runtime_grants.up.sql")
	goalGrantContent, err := os.ReadFile(goalGrantPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(goalGrantContent), "GRANT SELECT, INSERT, UPDATE ON TABLE public.goal_specs TO aor_app") {
		t.Fatal("GoalSpec runtime migration is missing least-privilege table grants")
	}
	relationalPath := filepath.Join("..", "..", "migrations", "postgres", "000017_relational_projection_sync.up.sql")
	relationalContent, err := os.ReadFile(relationalPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"GRANT SELECT, INSERT, UPDATE ON TABLE public.plan_specs TO aor_app",
		"GRANT SELECT, INSERT, UPDATE ON TABLE public.module_specs TO aor_app",
		"GRANT SELECT, INSERT, UPDATE ON TABLE public.module_tasks TO aor_app",
		"GRANT SELECT, INSERT, UPDATE ON TABLE public.attempt_series TO aor_app",
		"GRANT SELECT, INSERT ON TABLE public.task_dependencies TO aor_app",
		"CREATE INDEX relational_spec_artifact_lookup_idx",
	} {
		if !strings.Contains(string(relationalContent), value) {
			t.Errorf("relational projection migration missing %q", value)
		}
	}
	manifestContent, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Migrations []struct {
			Version int    `json:"version"`
			File    string `json:"file"`
			SHA256  string `json:"sha256"`
		} `json:"migrations"`
	}
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Migrations) == 0 {
		t.Fatal("migration manifest is empty")
	}
	for index, migration := range manifest.Migrations {
		if migration.Version != index+1 {
			t.Fatalf("migration version %d is out of order", migration.Version)
		}
		migrationContent, readErr := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", migration.File))
		if readErr != nil {
			t.Fatal(readErr)
		}
		sum := sha256.Sum256(migrationContent)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		if migration.SHA256 != digest {
			t.Fatalf("migration manifest digest does not match %s", digest)
		}
	}
}

func TestEventReplayStateMigrationIsForwardOnlyAndPaired(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "000021_event_replay_state.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, required := range []string{"replay_state_jsonb", "replay_state_sha256", "domain_events_replay_state_pair", "(replay_state_jsonb IS NULL) = (replay_state_sha256 IS NULL)", "jsonb_typeof"} {
		if !strings.Contains(text, required) {
			t.Errorf("event replay migration missing %q", required)
		}
	}
	if strings.Contains(strings.ToUpper(text), "DROP ") || strings.Contains(strings.ToUpper(text), "DELETE ") {
		t.Fatal("event replay migration is destructive")
	}
}

func TestStagedPlanningMigrationBindsPlanningAuthority(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "000023_staged_module_planning.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := string(content)
	for _, required := range []string{
		"ADD COLUMN planning_spec_id uuid", "ALTER COLUMN module_spec_id DROP NOT NULL",
		"module_tasks_planning_binding_check", "project.id::text || ':PLAN_SUPERVISOR'",
		"plan_specs_created_by_agent_fk", "ADD COLUMN created_by_agent_id text",
		"module_specs_created_by_agent_fk", "REFERENCES agent_instances(tenant_id, id)",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("staged planning migration missing %q", required)
		}
	}
}

func TestProjectErasureMigrationIsTenantScopedAndResumable(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "migrations", "postgres", "000016_project_erasure.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	sql := string(content)
	for _, required := range []string{
		"ADD COLUMN deletion_status", "CREATE TABLE project_erasure_jobs", "CREATE TABLE project_erasure_items",
		"CREATE TABLE project_key_revocations", "project_erasure_items_pending_idx", "FORCE ROW LEVEL SECURITY",
		"status IN ('PREPARED', 'COMPLETE')", "records_deleted", "objects_deleted",
	} {
		if !strings.Contains(sql, required) {
			t.Errorf("project erasure migration missing %q", required)
		}
	}
	if strings.Contains(sql, "DELETE FROM domain_events") || strings.Contains(sql, "DELETE FROM approvals") || strings.Contains(sql, "DELETE FROM submissions") {
		t.Fatal("project erasure migration permits immutable evidence deletion")
	}
}
