package agentruntime

import (
	"context"
	"encoding/json"

	"github.com/akimisaka/aor/pkg/canonicaljson"
)

type OperationLeaseRequest struct {
	Operation   LeaseOperation
	RequestID   string
	Provider    string
	Model       string
	ModelCall   ModelCall
	ToolID      string
	ToolVersion string
	Parameters  json.RawMessage
}

// OperationLeaseAuthority derives a narrowly bound capability lease from the
// stable execution lease. Derived leases must retain its identity and fence.
type OperationLeaseAuthority interface {
	LeaseAuthority
	AcquireOperationLease(context.Context, AgentLease, OperationLeaseRequest) (AgentLease, error)
}

func ModelOperationBinding(call ModelCall) (string, string, error) {
	if validateModelCall(call) != nil {
		return "", "", ErrLeaseInvalid
	}
	encoded, err := json.Marshal(call)
	if err != nil {
		return "", "", ErrLeaseInvalid
	}
	digest, err := canonicaljson.Digest(encoded)
	if err != nil {
		return "", "", ErrLeaseInvalid
	}
	return call.Provider + "/" + call.Model, digest, nil
}
