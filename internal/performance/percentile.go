// Package performance contains the small, deterministic measurement gates
// used by local benchmarks and the production conformance driver.
package performance

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"sort"
	"time"
)

var (
	ErrNoSamples         = errors.New("performance sample set is empty")
	ErrInvalidPercentile = errors.New("performance percentile is invalid")
	ErrThresholdExceeded = errors.New("performance threshold exceeded")
)

// Samples stores elapsed observations in nanoseconds. It intentionally keeps
// the raw values so a signed report can be independently recomputed.
type Samples struct {
	values []time.Duration
}

func (s *Samples) Add(value time.Duration) error {
	if s == nil || value < 0 {
		return ErrInvalidPercentile
	}
	s.values = append(s.values, value)
	return nil
}

func (s Samples) Len() int {
	return len(s.values)
}

func (s Samples) Values() []time.Duration {
	return append([]time.Duration(nil), s.values...)
}

// Percentile uses nearest-rank interpolation over a sorted copy. q must be in
// the inclusive [0,1] interval.
func (s Samples) Percentile(q float64) (time.Duration, error) {
	if len(s.values) == 0 {
		return 0, ErrNoSamples
	}
	if math.IsNaN(q) || math.IsInf(q, 0) || q < 0 || q > 1 {
		return 0, ErrInvalidPercentile
	}
	values := s.Values()
	sort.Slice(values, func(left, right int) bool { return values[left] < values[right] })
	if len(values) == 1 {
		return values[0], nil
	}
	position := q * float64(len(values)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return values[lower], nil
	}
	weight := position - float64(lower)
	return time.Duration(float64(values[lower]) + weight*float64(values[upper]-values[lower])), nil
}

type Threshold struct {
	RequirementID string        `json:"requirementId"`
	Percentile    float64       `json:"percentile"`
	Maximum       time.Duration `json:"maximumNanos"`
}

type Report struct {
	RequirementID string        `json:"requirementId"`
	Environment   string        `json:"environment"`
	MeasuredAt    time.Time     `json:"measuredAt"`
	SampleCount   int           `json:"sampleCount"`
	P95           time.Duration `json:"p95Nanos,omitempty"`
	P99           time.Duration `json:"p99Nanos,omitempty"`
	Maximum       time.Duration `json:"maximumNanos,omitempty"`
	Threshold     Threshold     `json:"threshold"`
	Passed        bool          `json:"passed"`
}

func Measure(requirementID, environment string, samples Samples, threshold Threshold, measuredAt time.Time) (Report, error) {
	if requirementID == "" || environment == "" || threshold.RequirementID != requirementID || measuredAt.IsZero() {
		return Report{}, ErrInvalidPercentile
	}
	p95, err := samples.Percentile(0.95)
	if err != nil {
		return Report{}, err
	}
	p99, err := samples.Percentile(0.99)
	if err != nil {
		return Report{}, err
	}
	maximum := time.Duration(0)
	for _, value := range samples.values {
		if value > maximum {
			maximum = value
		}
	}
	percentile := threshold.Percentile
	measured := p99
	if percentile == 0.95 {
		measured = p95
	} else if percentile != 0.99 {
		return Report{}, ErrInvalidPercentile
	}
	report := Report{RequirementID: requirementID, Environment: environment, MeasuredAt: measuredAt.UTC(), SampleCount: samples.Len(), P95: p95, P99: p99, Maximum: maximum, Threshold: threshold, Passed: measured <= threshold.Maximum}
	if !report.Passed {
		return report, ErrThresholdExceeded
	}
	return report, nil
}

func WriteReport(path string, report Report) error {
	if path == "" || report.RequirementID == "" || report.MeasuredAt.IsZero() {
		return ErrInvalidPercentile
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
