// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// This fixture is linked only with byte-identical production claim/type/close
// source. Intercept initialization before the generated testing main.
func init() {
	if os.Getenv("SUPERVISED_RUNTIME_EARLY") != "1" {
		return
	}
	if err := checkRuntime(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("runtime-alive")
	os.Exit(0)
}

// Use raw directory syscalls: os.Open would initialize the poller itself.
func hasPoller() (bool, error) {
	fd, err := unix.Open("/proc/self/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	buf := make([]byte, 8192)
	entries := 0
	for {
		n, err := unix.ReadDirent(fd, buf)
		if err != nil {
			return false, err
		}
		if n == 0 {
			return false, nil
		}
		_, _, names := unix.ParseDirent(buf[:n], -1, nil)
		entries += len(names)
		if entries > 4096 {
			return false, fmt.Errorf("fixture descriptor inventory bound")
		}
		for _, name := range names {
			value, err := strconv.Atoi(name)
			if err != nil || value == fd {
				continue
			}
			link, err := os.Readlink("/proc/self/fd/" + name)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return false, err
			}
			if link == "anon_inode:[eventpoll]" || link == "anon_inode:[eventfd]" {
				return true, nil
			}
		}
	}
}

func checkRuntime() error {
	if present, err := hasPoller(); err != nil || present {
		return fmt.Errorf("cold pre-entry invariant: poller=%v error=%v", present, err)
	}
	if err := unix.SetNonblock(3, true); err != nil {
		return err
	}
	flags, err := unix.FcntlInt(3, unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		return fmt.Errorf("ready descriptor is not nonblocking")
	}
	missing := os.Getenv("SUPERVISED_RUNTIME_MISSING") == "true"
	warm := os.Getenv("SUPERVISED_RUNTIME_WARM") == "true"
	if missing {
		absent := false
		for _, fd := range []int{5, 6} {
			_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
			absent = absent || err == unix.EBADF
		}
		if !absent {
			return fmt.Errorf("cold pre-entry invariant: no middle input slot is absent")
		}
	}
	var probe *os.File
	if warm {
		probe = os.NewFile(3, "explicit poller initialization")
		if present, err := hasPoller(); err != nil || !present {
			return fmt.Errorf("warm pre-entry invariant: poller=%v error=%v", present, err)
		}
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
			return err
		}
		link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if err != nil {
			return err
		}
		protected[fd] = identity{uint64(st.Dev), st.Ino, st.Mode, flags, link}
	}
	if warm && missing && len(protected) == 0 {
		return fmt.Errorf("warm fixture has no runtime-owned object in missing input slots")
	}
	// Immediately recheck the cold invariant after all setup, before entry.
	if !warm {
		if present, err := hasPoller(); err != nil || present {
			return fmt.Errorf("cold invariant changed before entry: poller=%v error=%v", present, err)
		}
	}
	inputs, claimErr := claimSupervisedInputs()
	if inputs != nil {
		inputs.close()
	}
	if missing && claimErr == nil {
		return fmt.Errorf("claim accepted missing input slots")
	}
	if !missing && claimErr != nil {
		return fmt.Errorf("complete input claim: %w", claimErr)
	}
	if !warm && missing {
		if present, err := hasPoller(); err != nil || present {
			return fmt.Errorf("partial refusal initialized the cold poller: poller=%v error=%v", present, err)
		}
	}
	for fd, old := range protected {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return fmt.Errorf("refusal closed runtime-owned handle: %w", err)
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		link, linkErr := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if err != nil || linkErr != nil || old != (identity{uint64(st.Dev), st.Ino, st.Mode, flags, link}) {
			return fmt.Errorf("refusal replaced runtime-owned object")
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer reader.Close()
	go func() { time.Sleep(time.Millisecond); _, _ = writer.Write([]byte{'x'}); _ = writer.Close() }()
	var value [1]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil || value[0] != 'x' {
		return fmt.Errorf("runtime pipe/timer failed after refusal")
	}
	runtime.KeepAlive(probe)
	return nil
}
