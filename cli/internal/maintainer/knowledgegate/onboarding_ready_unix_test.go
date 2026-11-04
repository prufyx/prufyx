// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package knowledgegate

import (
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func admissionTestPipe(t *testing.T) (*os.File, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Dup(int(w.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	var original unix.Stat_t
	if err := unix.Fstat(fd, &original); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var current unix.Stat_t
		if unix.Fstat(fd, &current) == nil && current.Dev == original.Dev && current.Ino == original.Ino {
			_ = unix.Close(fd)
		}
		_ = r.Close()
	})
	return r, fd
}

func TestOnboardingReadinessPipeIsolation(t *testing.T) {
	t.Parallel()
	r, fd := admissionTestPipe(t)
	pipe, err := claimOnboardingReadyPipe(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("control pipe is inherited across exec")
	}
	cmd := exec.Command("sh", "-c", "if printf forged >&"+strconv.Itoa(fd)+" 2>/dev/null; then exit 91; fi")
	if err := cmd.Run(); err != nil {
		t.Fatalf("child inherited readiness descriptor: %v", err)
	}
	_ = pipe.Close()
	raw := make([]byte, 16)
	n, _ := r.Read(raw)
	if n != 0 {
		t.Fatalf("source subprocess injected control bytes: %q", raw[:n])
	}
	for _, bad := range []int{-1, 0, 1, 2} {
		if _, err := claimOnboardingReadyPipe(bad); err == nil {
			t.Fatal("nondedicated descriptor admitted")
		}
	}
	if _, err := claimOnboardingReadyPipe(int(r.Fd())); err == nil {
		t.Fatal("read-only control descriptor admitted")
	}
	file, err := os.CreateTemp(t.TempDir(), "not-a-control-pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := claimOnboardingReadyPipe(int(file.Fd())); err == nil {
		t.Fatal("regular control file admitted")
	}
}
