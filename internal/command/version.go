package command

import (
	"encoding/json"
	"os"

	"github.com/akimisaka/aor/internal/version"
)

// WriteVersion emits the development command identity until its service package is wired.
func WriteVersion(component string) error {
	return json.NewEncoder(os.Stdout).Encode(version.Current(component))
}
