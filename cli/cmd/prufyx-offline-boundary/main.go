// SPDX-License-Identifier: AGPL-3.0-only

// prufyx-offline-boundary is the Go socket positive-control for the optional
// Linux-only offline boundary harness. It performs no product check itself.
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "positive-control" {
		fmt.Fprintln(os.Stderr, "usage: prufyx-offline-boundary positive-control")
		os.Exit(2)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "network positive-control failed")
		os.Exit(1)
	}
	_ = listener.Close()
}
