package main

import (
	"fmt"
	"os"

	"github.com/akimisaka/aor/internal/command"
)

func main() {
	if err := command.Run("aor-server"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
