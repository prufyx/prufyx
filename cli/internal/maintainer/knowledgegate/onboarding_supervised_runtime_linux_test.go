// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package knowledgegate

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSupervisedPartialDescriptorsKeepRuntime(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
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
				cmd := exec.Command(program, "-test.run=^TestSupervisedRuntimeWorker$", "-test.count=1")
				cmd.ExtraFiles = files
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SUPERVISED_RUNTIME_WORKER=1", "SUPERVISED_RUNTIME_WARM=" + strconv.FormatBool(warm), "SUPERVISED_RUNTIME_MISSING=" + strconv.FormatBool(missing)}
				out, err := cmd.CombinedOutput()
				if err != nil || !bytes.Equal(out, []byte("runtime-alive\n")) {
					t.Fatalf("runtime lifecycle after partial refusal: %v %s", err, out)
				}
			})
		}
	}
}

// A fresh test worker exercises the real entry point without introducing a
// production package or weakening the production-source authority guard.
func TestSupervisedRuntimeWorker(t *testing.T) {
	if os.Getenv("SUPERVISED_RUNTIME_WORKER") != "1" {
		return
	}
	if err := unix.SetNonblock(3, true); err != nil {
		t.Fatal(err)
	}
	var pollProbe *os.File
	if os.Getenv("SUPERVISED_RUNTIME_WARM") == "true" {
		pollProbe = os.NewFile(3, "runtime poll initialization")
	}
	type identity struct {
		dev, ino uint64
		mode     uint32
		flags    int
		link     string
	}
	protected := map[int]identity{}
	for fd := 3; fd <= 8; fd++ {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			continue
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if err != nil {
			t.Fatal(err)
		}
		protected[fd] = identity{uint64(st.Dev), st.Ino, st.Mode, flags, link}
	}
	if os.Getenv("SUPERVISED_RUNTIME_WARM") == "true" && os.Getenv("SUPERVISED_RUNTIME_MISSING") == "true" && len(protected) == 0 {
		t.Fatal("runtime-owned handle fixture did not occupy missing input slot")
	}
	handled, code := SupervisedApprovalMain([]string{"approval", "sign-supervised"}, os.Stdin, io.Discard, io.Discard)
	if !handled || code != 2 {
		t.Fatalf("malformed request refusal: handled=%v code=%d", handled, code)
	}
	for fd, old := range protected {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			t.Fatalf("refusal closed a runtime-owned handle: %v", err)
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		link, linkErr := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if err != nil || linkErr != nil || old != (identity{uint64(st.Dev), st.Ino, st.Mode, flags, link}) {
			t.Fatal("refusal replaced a runtime-owned object")
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	go func() { time.Sleep(time.Millisecond); _, _ = writer.Write([]byte{'x'}); _ = writer.Close() }()
	var value [1]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil || value[0] != 'x' {
		t.Fatal("runtime pipe/timer failed after refusal")
	}
	runtime.KeepAlive(pollProbe)
	fmt.Println("runtime-alive")
	os.Exit(0)
}
