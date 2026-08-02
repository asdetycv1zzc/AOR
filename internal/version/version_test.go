package version

import "testing"

func TestCurrentIsDevelopmentVersion(t *testing.T) {
	info := Current("aor-test")
	if info.Component != "aor-test" {
		t.Fatalf("component = %q", info.Component)
	}
	if info.Version == "" || info.SpecVersion != "2.0.0" {
		t.Fatalf("unexpected version info: %#v", info)
	}
	if info.ProductionReady {
		t.Fatal("bootstrap must not claim production readiness")
	}
}
