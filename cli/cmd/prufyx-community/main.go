// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/communityapp"
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return communityapp.RunCLI(ctx, args, stdout, stderr, buildidentity.Version)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
