package performance

import (
	"errors"
	"testing"
	"time"
)

func TestPercentileAndThreshold(t *testing.T) {
	var samples Samples
	for _, value := range []time.Duration{5, 1, 3, 2, 4} {
		if err := samples.Add(value); err != nil {
			t.Fatal(err)
		}
	}
	value, err := samples.Percentile(0.95)
	if err != nil || value != 4*time.Nanosecond {
		t.Fatalf("p95 = %s, error = %v", value, err)
	}
	report, err := Measure("AOR-ACC-070", "test", samples, Threshold{RequirementID: "AOR-ACC-070", Percentile: 0.99, Maximum: 5}, time.Unix(1, 0))
	if err != nil || !report.Passed || report.SampleCount != 5 {
		t.Fatalf("report = %#v, error = %v", report, err)
	}
}

func TestPercentileRejectsEmptyAndExceededThreshold(t *testing.T) {
	var empty Samples
	if _, err := empty.Percentile(0.99); !errors.Is(err, ErrNoSamples) {
		t.Fatalf("empty percentile error = %v", err)
	}
	var samples Samples
	if err := samples.Add(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := Measure("AOR-ACC-066", "production", samples, Threshold{RequirementID: "AOR-ACC-066", Percentile: 0.95, Maximum: time.Second}, time.Unix(1, 0)); !errors.Is(err, ErrThresholdExceeded) {
		t.Fatalf("threshold error = %v", err)
	}
}
