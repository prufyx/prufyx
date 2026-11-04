// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package knowledgegate

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSupervisedPartialDescriptorsKeepRuntime(t *testing.T) {
	program := filepath.Join(t.TempDir(), "cold-runtime")
	build := exec.Command("go", "build", "-mod=vendor", "-o", program, "./testdata/supervised-runtime")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual admission entry fixture: %v %s", err, out)
	}
	for _, warm := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("missing-middle-%t-warm-%t", missing, warm), func(t *testing.T) {
				read, write, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer read.Close()
				defer write.Close()
				fd, err := unix.Dup(int(write.Fd()))
				if err != nil {
					t.Fatal(err)
				}
				if err = unix.SetNonblock(fd, true); err != nil {
					t.Fatal(err)
				}
				ready := os.NewFile(uintptr(fd), "nonblocking readiness")
				defer ready.Close()
				files := []*os.File{ready}
				for i := 4; i <= 8; i++ {
					f, err := os.CreateTemp(t.TempDir(), "fixed-input")
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					files = append(files, f)
				}
				if missing {
					files[2] = nil
				}
				cmd := exec.Command(program)
				if warm {
					cmd.Args = append(cmd.Args, "warm")
					if missing {
						cmd.Args = append(cmd.Args, "missing")
					}
				}
				cmd.ExtraFiles = files
				cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
				out, err := cmd.CombinedOutput()
				if err != nil || !bytes.Equal(out, []byte("runtime-alive\n")) {
					t.Fatalf("runtime lifecycle after partial refusal: %v %s", err, out)
				}
			})
		}
	}
}
