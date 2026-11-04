// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgegate"
	"golang.org/x/sys/unix"
)

// Run before the testing package or any timer has initialized the poller.
func main() {
	if err := unix.SetNonblock(3, true); err != nil {
		panic(err)
	}
	var pollProbe *os.File
	if len(os.Args) > 1 && os.Args[1] == "warm" {
		pollProbe = os.NewFile(3, "runtime poll initialization")
	}
	protected := map[int]string{}
	for fd := 3; fd <= 8; fd++ {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err == nil && flags&unix.FD_CLOEXEC != 0 {
			link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			if err == nil {
				protected[fd] = link
			}
		}
	}
	if len(os.Args) > 2 && os.Args[2] == "missing" && len(protected) == 0 {
		for fd := 3; fd < 16; fd++ {
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			mode, modeErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			link, linkErr := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
			fmt.Fprintf(os.Stderr, "fd=%d flags=%d err=%v mode=%d modeErr=%v link=%s linkErr=%v\n", fd, flags, err, mode, modeErr, link, linkErr)
		}
		panic("runtime-owned handle fixture did not occupy missing input slot")
	}
	handled, code := knowledgegate.SupervisedApprovalMain([]string{"approval", "sign-supervised"}, os.Stdin, io.Discard, io.Discard)
	if !handled || code != 2 {
		fmt.Fprintln(os.Stderr, "expected malformed request refusal")
		os.Exit(1)
	}
	for fd, old := range protected {
		link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if err != nil || link != old {
			panic("refusal closed a runtime-owned handle")
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	defer reader.Close()
	go func() {
		time.Sleep(time.Millisecond)
		_, _ = writer.Write([]byte{'x'})
		_ = writer.Close()
	}()
	var value [1]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil || value[0] != 'x' {
		panic("runtime pipe/timer failed after refusal")
	}
	runtime.KeepAlive(pollProbe)
	fmt.Println("runtime-alive")
}
