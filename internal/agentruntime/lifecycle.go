package agentruntime

import (
	"strings"
	"time"
)

func validTransition(from, to State) bool {
	if from == to {
		return false
	}
	switch from {
	case StateDeclared:
		return to == StateQueued || to == StateCanceled || to == StateTerminated
	case StateQueued:
		return to == StateLeased || to == StateCanceled || to == StateTerminated
	case StateLeased:
		return to == StateStarting || to == StateCanceled || to == StateExpired || to == StateTerminated
	case StateStarting:
		return to == StateRunning || to == StateFailed || to == StateCanceled || to == StateExpired || to == StateTerminated
	case StateRunning:
		return to == StateWaitingInput || to == StateWaitingTool || to == StateWaitingDependency ||
			to == StateCompleted || to == StateFailed || to == StateCanceled || to == StateExpired || to == StateTerminated
	case StateWaitingInput, StateWaitingTool, StateWaitingDependency:
		return to == StateRunning || to == StateFailed || to == StateCanceled || to == StateExpired || to == StateTerminated
	default:
		return false
	}
}

func validateLeaseShape(lease AgentLease, now time.Time) error {
	if !safeIdentifier(lease.LeaseID) || !safeIdentifier(lease.AgentInstanceID) || !safeIdentifier(lease.TenantID) ||
		!safeIdentifier(lease.ProjectID) || !lease.Role.Valid() || lease.PolicyVersion == "" ||
		!safeIdentifier(lease.BudgetAccountID) || !safeIdentifier(lease.Nonce) || lease.Signature == "" ||
		lease.FencingToken < 1 ||
		lease.HeartbeatIntervalSeconds != DefaultHeartbeatSeconds || len(lease.Capabilities) == 0 ||
		lease.IssuedAt.IsZero() || lease.ExpiresAt.IsZero() || lease.LastHeartbeatAt.IsZero() ||
		!lease.IssuedAt.Before(lease.ExpiresAt) || lease.LastHeartbeatAt.Before(lease.IssuedAt) ||
		lease.LastHeartbeatAt.After(lease.ExpiresAt) || now.Before(lease.IssuedAt) {
		return ErrLeaseInvalid
	}
	if roleRequiresTask(lease.Role) && !safeIdentifier(lease.TaskID) {
		return ErrLeaseInvalid
	}
	if lease.TaskID != "" && !safeIdentifier(lease.TaskID) {
		return ErrLeaseInvalid
	}
	seen := make(map[string]struct{}, len(lease.Capabilities))
	for _, capability := range lease.Capabilities {
		if !safeIdentifier(capability) {
			return ErrLeaseInvalid
		}
		if _, exists := seen[capability]; exists {
			return ErrLeaseInvalid
		}
		seen[capability] = struct{}{}
	}
	if leaseExpired(lease, now) {
		return ErrLeaseExpired
	}
	return nil
}

func leaseExpired(lease AgentLease, now time.Time) bool {
	if !now.Before(lease.ExpiresAt) {
		return true
	}
	missedDeadline := lease.LastHeartbeatAt.Add(time.Duration(lease.HeartbeatIntervalSeconds*MissedHeartbeatLimit) * time.Second)
	return !now.Before(missedDeadline)
}

func validateLeaseBinding(lease AgentLease, declaration Declaration) error {
	if lease.AgentInstanceID != declaration.AgentInstanceID || lease.TenantID != declaration.TenantID ||
		lease.ProjectID != declaration.ProjectID || lease.TaskID != declaration.TaskID || lease.Role != declaration.Role ||
		lease.PolicyVersion != declaration.PolicyVersion {
		return ErrLeaseBinding
	}
	return nil
}

func validateRenewedLease(previous, renewed AgentLease, now time.Time) error {
	if err := validateLeaseShape(renewed, now); err != nil {
		return err
	}
	if renewed.LeaseID != previous.LeaseID || renewed.AgentInstanceID != previous.AgentInstanceID ||
		renewed.TenantID != previous.TenantID || renewed.ProjectID != previous.ProjectID ||
		renewed.TaskID != previous.TaskID || renewed.Role != previous.Role ||
		!renewed.IssuedAt.Equal(previous.IssuedAt) || renewed.Nonce != previous.Nonce ||
		renewed.PolicyVersion != previous.PolicyVersion || renewed.BudgetAccountID != previous.BudgetAccountID || !renewed.ExpiresAt.After(now) || !sameCapabilities(previous.Capabilities, renewed.Capabilities) {
		return ErrLeaseBinding
	}
	return nil
}

func validateHeartbeatLease(previous, heartbeat AgentLease) error {
	if !heartbeat.ExpiresAt.Equal(previous.ExpiresAt) || heartbeat.PolicyVersion != previous.PolicyVersion ||
		heartbeat.BudgetAccountID != previous.BudgetAccountID || heartbeat.FencingToken != previous.FencingToken || len(heartbeat.Capabilities) != len(previous.Capabilities) {
		return ErrLeaseBinding
	}
	for index := range heartbeat.Capabilities {
		if heartbeat.Capabilities[index] != previous.Capabilities[index] {
			return ErrLeaseBinding
		}
	}
	return nil
}

func sameCapabilities(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func hasCapability(lease AgentLease, expected string) bool {
	for _, capability := range lease.Capabilities {
		if capability == expected {
			return true
		}
	}
	return false
}

func cloneLease(lease AgentLease) AgentLease {
	lease.Capabilities = append([]string(nil), lease.Capabilities...)
	return lease
}

func roleRequiresTask(role Role) bool {
	switch role {
	case RoleModulePlanner, RoleExecutor, RoleModuleAuditor:
		return true
	default:
		return false
	}
}

func safeIdentifier(value string) bool {
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n\x00/\\") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func safeProtocolString(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}
