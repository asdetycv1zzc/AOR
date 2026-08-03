package observability

import (
	"encoding/binary"
	"encoding/hex"
	"math"
)

type TraceOutcome struct {
	Failed         bool
	Attempt        int
	SecurityDenied bool
	BudgetDenied   bool
	Critical       bool
}

type Sampler interface {
	ShouldSample(TraceContext, TraceOutcome) bool
}

type RetentionSampler struct {
	NormalRate float64
}

func (s RetentionSampler) ShouldSample(trace TraceContext, outcome TraceOutcome) bool {
	if outcome.Critical || outcome.SecurityDenied || outcome.BudgetDenied || outcome.Failed || (outcome.Attempt >= 3 && outcome.Failed) {
		return true
	}
	rate := s.NormalRate
	if rate <= 0 {
		return false
	}
	if rate >= 1 {
		return true
	}
	decoded, err := hex.DecodeString(trace.TraceID[:min(len(trace.TraceID), 16)])
	if err != nil || len(decoded) != 8 {
		return false
	}
	value := binary.BigEndian.Uint64(decoded)
	threshold := uint64(rate * float64(math.MaxUint64))
	return value <= threshold
}
