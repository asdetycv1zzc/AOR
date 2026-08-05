package main

import (
	"fmt"
	"os"

	"github.com/akimisaka/aor/internal/command"
	"github.com/akimisaka/aor/internal/servicebootstrap"
)

func main() {
	factory := command.HandlerFactory(servicebootstrap.ControlAPI)
	switch os.Getenv("AOR_SERVER_MODE") {
	case "", "CONTROL":
	case "KNOWLEDGE_CURATOR":
		factory = servicebootstrap.KnowledgeCuratorAPI
	default:
		fmt.Fprintln(os.Stderr, "invalid AOR_SERVER_MODE")
		os.Exit(1)
	}
	if err := command.Run("aor-server", factory); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
