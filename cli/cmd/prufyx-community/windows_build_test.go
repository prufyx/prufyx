// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"os/exec"
	"testing"
)

// TestWindowsCrossBuild keeps the Windows build from silently regressing. It
// needs only the local Go toolchain and the vendored dependencies (about 15 s
// from a cold cache) and never touches the network.
func TestWindowsCrossBuild(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			cmd := exec.Command(goTool, "build", "-o", os.DevNull, ".")
			cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+arch, "CGO_ENABLED=0", "GOFLAGS=-mod=vendor -buildvcs=false", "GOPROXY=off", "GOTOOLCHAIN=local")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("windows/%s build failed: %v\n%s", arch, err, out)
			}
		})
	}
}
