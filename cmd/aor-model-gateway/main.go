package main

import (
	"fmt"
	"os"

	"github.com/akimisaka/aor/internal/command"
	"github.com/akimisaka/aor/internal/servicebootstrap"
)

func main() {
	if err := command.Run("aor-model-gateway", servicebootstrap.ModelGateway); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
