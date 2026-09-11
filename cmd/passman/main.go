package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lihongjie0209/passman/internal/cli"
	"github.com/lihongjie0209/passman/internal/runner"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err := cli.New(version).ExecuteContext(ctx)
	if err == nil {
		return
	}
	var exitErr *runner.ExitError
	if errors.As(err, &exitErr) {
		os.Exit(exitErr.Code)
	}
	fmt.Fprintln(os.Stderr, "passman:", err)
	os.Exit(1)
}
