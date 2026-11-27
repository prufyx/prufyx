// SPDX-License-Identifier: AGPL-3.0-only

//go:build ignore

// A stand-in program for the harness self-test. It imitates a flag parser
// and the faults the harness must refuse. It is the only program the
// self-test runs.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	for _, arg := range os.Args[1:] {
		name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		switch name {
		case "base", "kept":
		case "wrong-token":
			fmt.Fprintln(os.Stderr, "flag provided but not defined: -some-other-flag")
			os.Exit(2)
		case "broken":
			fmt.Fprintln(os.Stderr, "cannot start")
			os.Exit(1)
		case "hang":
			time.Sleep(time.Hour)
		case "flood":
			line := strings.Repeat("x", 1024)
			for i := 0; i < 4096; i++ {
				fmt.Println(line)
			}
			fmt.Fprintln(os.Stderr, "flag provided but not defined: -flood")
			os.Exit(2)
		default:
			fmt.Fprintf(os.Stderr, "flag provided but not defined: -%s\n", name)
			os.Exit(2)
		}
	}
	fmt.Println("probe-ready")
	time.Sleep(time.Hour)
}
