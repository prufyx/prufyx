// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package knowledgegate

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// The caller transfers this write-only pipe descriptor to the command. Set
// close-on-exec before any source/Git child can inherit the control channel.
func claimOnboardingReadyPipe(fd int) (*os.File, error) {
	if fd < 3 {
		return nil, errors.New("admission readiness requires a dedicated pipe descriptor >= 3")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != unix.O_WRONLY {
		return nil, errors.New("admission readiness requires a write-only pipe")
	}
	fdflags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, fdflags|unix.FD_CLOEXEC); err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "onboarding-admission-ready"), nil
}
