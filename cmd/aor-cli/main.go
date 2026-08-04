package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/akimisaka/aor/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(cli.Main(ctx, os.Args[1:], cli.Config{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, LookupEnv: os.LookupEnv,
	}))
}
