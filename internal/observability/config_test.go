package observability

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCollectorSeparatesAuditAndRetainsCriticalTracePolicies(t *testing.T) {
	var config struct {
		Processors map[string]struct {
			Policies []struct {
				Name string `yaml:"name"`
			} `yaml:"policies"`
		} `yaml:"processors"`
		Service struct {
			Pipelines map[string]struct {
				Receivers []string `yaml:"receivers"`
				Exporters []string `yaml:"exporters"`
			} `yaml:"pipelines"`
		} `yaml:"service"`
	}
	decodeYAMLFile(t, "../../observability/otel-collector.yaml", &config)
	application := config.Service.Pipelines["logs/application"]
	audit := config.Service.Pipelines["logs/audit"]
	if len(application.Exporters) != 1 || len(audit.Exporters) != 1 || application.Exporters[0] == audit.Exporters[0] {
		t.Fatal("collector does not separate application and audit log exporters")
	}
	if len(application.Receivers) != 1 || len(audit.Receivers) != 1 || application.Receivers[0] == audit.Receivers[0] {
		t.Fatal("collector does not separate application and audit ingestion")
	}
	required := map[string]bool{"errors": false, "critical": false, "third-attempt": false, "security-denial": false, "budget-denial": false}
	for _, policy := range config.Processors["tail_sampling"].Policies {
		if _, exists := required[policy.Name]; exists {
			required[policy.Name] = true
		}
	}
	for policy, found := range required {
		if !found {
			t.Fatalf("mandatory retention policy missing: %s", policy)
		}
	}
}

func TestEveryRequiredAlertHasDrillScenario(t *testing.T) {
	var rules struct {
		Groups []struct {
			Rules []struct {
				Alert string `yaml:"alert"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	decodeYAMLFile(t, "../../observability/prometheus-rules.yaml", &rules)
	alerts := map[string]bool{}
	for _, group := range rules.Groups {
		for _, rule := range group.Rules {
			if rule.Alert != "" {
				alerts[rule.Alert] = false
			}
		}
	}
	required := []string{
		"AORControlPlaneAvailability", "AORControlPlaneErrorRate", "AOROutboxBacklog", "AORWorkflowStuck",
		"AORAgentConcurrencySaturated", "AORBudgetGrowthAnomaly", "AORThirdAttemptFailure",
		"AORHighCriticalSecurityEvent", "AORArtifactHashMismatch", "AORDatabaseReplicationFailure",
		"AORBackupFailure", "AORSandboxLifecycleFailure",
	}
	for _, alert := range required {
		if _, exists := alerts[alert]; !exists {
			t.Fatalf("required alert missing: %s", alert)
		}
	}
	var drills struct {
		Scenarios []struct {
			ID     string `yaml:"id"`
			Alert  string `yaml:"alert"`
			Inject string `yaml:"inject"`
		} `yaml:"scenarios"`
		Evidence struct {
			RetentionDays  int      `yaml:"retentionDays"`
			RequiredFields []string `yaml:"requiredFields"`
		} `yaml:"evidence"`
	}
	decodeYAMLFile(t, "../../observability/fault-drills.yaml", &drills)
	for _, scenario := range drills.Scenarios {
		if scenario.ID == "" || scenario.Inject == "" {
			t.Fatal("drill scenario is not executable")
		}
		if _, exists := alerts[scenario.Alert]; !exists {
			t.Fatalf("drill references unknown alert: %s", scenario.Alert)
		}
		alerts[scenario.Alert] = true
	}
	for alert, drilled := range alerts {
		if !drilled {
			t.Fatalf("alert has no drill: %s", alert)
		}
	}
	if drills.Evidence.RetentionDays < 400 || len(drills.Evidence.RequiredFields) == 0 {
		t.Fatal("drill evidence retention is incomplete")
	}
}

func TestDashboardSupportsCostDrillDownAndRequiredQualityMetrics(t *testing.T) {
	payload, err := os.ReadFile("../../observability/grafana-dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	var dashboard map[string]any
	if err := json.Unmarshal(payload, &dashboard); err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, dimension := range []string{"$project", "$role", "$model", "$task", "$attempt", "$trace_id", "traceql"} {
		if !strings.Contains(text, dimension) {
			t.Fatalf("cost drill-down dimension missing: %s", dimension)
		}
	}
	for _, metric := range []string{"aor_module_rework_total", "aor_user_takeovers_total", "aor:slo:audit_failure", "aor:slo:cache_hit", "aor:slo:tool_denial"} {
		if !strings.Contains(text, metric) {
			t.Fatalf("dashboard signal missing: %s", metric)
		}
	}
}

func TestAuditStoragePolicyRequiresWORMRetention(t *testing.T) {
	var policy struct {
		Spec struct {
			DestinationClass               string `yaml:"destinationClass"`
			ApplicationLogDestinationClass string `yaml:"applicationLogDestinationClass"`
			AppendOnly                     bool   `yaml:"appendOnly"`
			DenyDeleteBeforeRetention      bool   `yaml:"denyDeleteBeforeRetention"`
			ReadAccessAudited              bool   `yaml:"readAccessAudited"`
			ObjectLock                     struct {
				Enabled       bool   `yaml:"enabled"`
				Mode          string `yaml:"mode"`
				RetentionDays int    `yaml:"retentionDays"`
			} `yaml:"objectLock"`
		} `yaml:"spec"`
	}
	decodeYAMLFile(t, "../../observability/audit-storage-policy.yaml", &policy)
	if policy.Spec.DestinationClass == policy.Spec.ApplicationLogDestinationClass || !policy.Spec.AppendOnly || !policy.Spec.DenyDeleteBeforeRetention || !policy.Spec.ReadAccessAudited {
		t.Fatal("audit storage is not separate and append-only")
	}
	if !policy.Spec.ObjectLock.Enabled || policy.Spec.ObjectLock.Mode != "COMPLIANCE" || policy.Spec.ObjectLock.RetentionDays < 400 {
		t.Fatal("audit storage lacks compliant WORM retention")
	}
}

func decodeYAMLFile(t *testing.T, path string, destination any) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(payload, destination); err != nil {
		t.Fatal(err)
	}
}
