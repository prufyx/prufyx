// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package communityapp

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"testing"
)

func TestSyntheticEtcdWalkthrough(t *testing.T) {
	t.Parallel()
	_, file, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("resolve etcd walkthrough source location")
	}
	cliRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	script := filepath.Join(cliRoot, "examples", "cncf", "etcd", "run.sh")
	if info, err := os.Stat(script); err != nil || info.Mode()&0o111 == 0 {
		t.Fatalf("etcd walkthrough script unavailable: %v", err)
	}
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "prufyx-community")
	env := append(os.Environ(),
		"GOTOOLCHAIN=local",
		"GOWORK=off",
		"GOFLAGS=-mod=vendor -buildvcs=false",
		"GOPROXY=off",
		"GOSUMDB=off",
	)
	build := exec.Command(goPath, "build", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/prufyx-community")
	build.Dir = cliRoot
	build.Env = env
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build etcd walkthrough binary: %v\n%s", err, output)
	}
	run := exec.Command(script, binary)
	run.Dir = cliRoot
	run.Env = env
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("synthetic etcd walkthrough: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
}
