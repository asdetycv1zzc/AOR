package main

import (
	"fmt"
	"os"

	"github.com/akimisaka/aor/internal/command"
)

func main() {
	if err := command.WriteVersion("aor-tool-broker"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
