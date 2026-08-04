package servicebootstrap

import (
	"errors"
	"testing"

	"github.com/akimisaka/aor/internal/runtimeconfig"
)

func TestLoadMCPServerConfigRequiresSecureExplicitTransport(t *testing.T) {
	valid := `[{"id":"repo","transport":"streamable-http","endpoint":"https://mcp.example/mcp","authorizationRef":"secret://mcp/repo-token","version":"1.0.0","tools":{"repo.read":{"risk":"LOW","sideEffect":"NONE","filesystemAccess":"READ","requiresApproval":"NEVER","allowedRoles":["EXECUTOR"],"rateLimit":"10/s","timeoutSeconds":10,"maxOutputBytes":1048576}}}]`
	servers, err := loadMCPServerConfig(valid)
	if err != nil || len(servers) != 1 || servers[0].AuthorizationRef == "" {
		t.Fatalf("servers=%#v err=%v", servers, err)
	}
	for _, invalid := range []string{
		`[{"id":"repo","transport":"streamable-http","endpoint":"https://mcp.example/mcp","version":"1"}]`,
		`[{"id":"repo","transport":"stdio","command":"/usr/bin/mcp","authorizationRef":"secret://not-allowed","version":"1"}]`,
		`[{"id":"repo","transport":"stdio","command":"/usr/bin/mcp","version":"1","unknown":true}]`,
		`[{"id":"repo","transport":"stdio","command":"/usr/bin/mcp","version":"1"},{"id":"repo","transport":"stdio","command":"/usr/bin/other","version":"1"}]`,
	} {
		if _, err := loadMCPServerConfig(invalid); !errors.Is(err, runtimeconfig.ErrInvalidConfiguration) {
			t.Fatalf("config %s error=%v", invalid, err)
		}
	}
}
