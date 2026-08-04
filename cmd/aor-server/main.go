package main

import (
	"fmt"
	"os"

	"github.com/akimisaka/aor/internal/command"
	"github.com/akimisaka/aor/internal/servicebootstrap"
)

func main() {
	if err := command.Run("aor-server", servicebootstrap.ControlAPI); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
