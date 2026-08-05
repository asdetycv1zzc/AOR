package leaseauthority

import (
	"context"

	"github.com/akimisaka/aor/internal/toolbroker"
	aorerrors "github.com/akimisaka/aor/pkg/errors"
)

type DescriptorToolResolver struct {
	servers map[string]string
}

func NewDescriptorToolResolver(descriptors []toolbroker.ToolDescriptor) (*DescriptorToolResolver, error) {
	if len(descriptors) == 0 {
		return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "runtime tools"})
	}
	servers := make(map[string]string, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.Validate() != nil || descriptor.MCPServerID == "" {
			return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "runtime tool descriptor"})
		}
		key := descriptor.ToolID + "\x00" + descriptor.Version
		if _, duplicate := servers[key]; duplicate {
			return nil, aorerrors.New(aorerrors.CodeInvalidArgument, "", map[string]any{"scope": "duplicate runtime tool"})
		}
		servers[key] = descriptor.MCPServerID
	}
	return &DescriptorToolResolver{servers: servers}, nil
}

func (resolver *DescriptorToolResolver) MCPServerID(ctx context.Context, toolID, version string) (string, error) {
	if resolver == nil || ctx == nil || ctx.Err() != nil || toolID == "" || version == "" {
		return "", agentRuntimeLeaseError()
	}
	serverID, found := resolver.servers[toolID+"\x00"+version]
	if !found {
		return "", agentRuntimeLeaseError()
	}
	return serverID, nil
}

func agentRuntimeLeaseError() error {
	return aorerrors.New(aorerrors.CodePolicyDenied, "", map[string]any{"scope": "runtime tool"})
}

var _ RuntimeToolResolver = (*DescriptorToolResolver)(nil)
