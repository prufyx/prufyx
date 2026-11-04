// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package knowledgegate

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func (s *supervisedInputs) read(flags supervisedFlags) (draft, keys, export, daily []byte, err error) {
	if s == nil || s.files[1] == nil {
		err = errors.New("supervised input scope unavailable or already consumed")
		return
	}
	if err = flags.valid(); err != nil {
		return
	}
	var identities [9]unix.Stat_t
	for fd := 0; fd <= 8; fd++ {
		if e := unix.Fstat(fd, &identities[fd]); e != nil {
			err = fmt.Errorf("descriptor %d unavailable", fd)
			return
		}
	}
	inputFlags, inputErr := unix.FcntlInt(0, unix.F_GETFL, 0)
	if inputErr != nil || inputFlags&unix.O_PATH != 0 || identities[0].Mode&unix.S_IFMT != unix.S_IFIFO || inputFlags&unix.O_ACCMODE != unix.O_RDONLY {
		err = errors.New("descriptor 0 must be a read-only key input pipe")
		return
	}
	for fd := 3; fd <= 8; fd++ {
		for other := 0; other < fd; other++ {
			if identities[fd].Dev == identities[other].Dev && identities[fd].Ino == identities[other].Ino {
				err = errors.New("supervised descriptors alias another channel/input")
				return
			}
		}
	}
	readyFlags, e := unix.FcntlInt(3, unix.F_GETFL, 0)
	if e != nil || identities[3].Mode&unix.S_IFMT != unix.S_IFIFO || readyFlags&unix.O_ACCMODE != unix.O_WRONLY {
		err = errors.New("descriptor 3 must be a write-only readiness pipe")
		return
	}
	self, e := os.Stat("/proc/self/exe")
	if e != nil {
		err = e
		return
	}
	exe, e := s.files[1].Stat()
	if e != nil || !os.SameFile(self, exe) {
		err = errors.New("descriptor 4 differs from the running executable")
		return
	}
	limits := []int64{128 << 20, maxOnboardingBytes, maxApprovalBytes * 4, maxOnboardingBytes, maxDailyCommitsFile}
	digests := []string{flags.executable, flags.draft, flags.keys, flags.export, flags.daily}
	var raw [5][]byte
	for i := 0; i < 5; i++ {
		f := s.files[i+1]
		fd := f.Fd()
		st := identities[i+4]
		mode, e := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || mode&unix.O_ACCMODE != unix.O_RDONLY || st.Size <= 0 || st.Size > limits[i] {
			err = fmt.Errorf("descriptor %d is not a bounded read-only regular input", i+4)
			return
		}
		seals, e := unix.FcntlInt(fd, unix.F_GET_SEALS, 0)
		required := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
		if e != nil || seals&required != required {
			err = fmt.Errorf("descriptor %d lacks immutable seals", i+4)
			return
		}
		// An inherited descriptor may share an offset with the parent. Never
		// Seek/Read from that mutable offset, even after sealing its content.
		raw[i], e = io.ReadAll(io.NewSectionReader(f, 0, st.Size+1))
		if e != nil || int64(len(raw[i])) != st.Size || CandidateDigest(raw[i]) != "sha256:"+digests[i] {
			err = fmt.Errorf("descriptor %d byte binding differs", i+4)
			return
		}
	}
	// The executable's launch correspondence is established; no later helper
	// needs this descriptor. The remaining inputs stay owned until return.
	_ = s.files[1].Close()
	s.files[1] = nil
	// Rewrap a nonblocking owned duplicate so Go's pipe deadline support is
	// initialized after validation. The transferred raw fd3 is then closed.
	duplicate, e := unix.FcntlInt(3, unix.F_DUPFD_CLOEXEC, 9)
	if e != nil {
		err = e
		return
	}
	if err = unix.SetNonblock(duplicate, true); err != nil {
		_ = unix.Close(duplicate)
		return
	}
	_ = s.files[0].Close()
	s.files[0] = os.NewFile(uintptr(duplicate), "supervised admission readiness")
	draft, keys, export, daily = raw[1], raw[2], raw[3], raw[4]
	return
}
