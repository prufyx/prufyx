// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package knowledgegate

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func claimSupervisedInputs() (*supervisedInputs, error) {
	s := &supervisedInputs{}
	var first error
	// Claim and protect every fixed descriptor before any validation/return.
	// Unsupported Unix platforms still clean up transferred descriptors.
	for i := range s.files {
		fd := i + 3
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			if first == nil {
				first = fmt.Errorf("descriptor %d unavailable", fd)
			}
			continue
		}
		if _, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil && first == nil {
			first = fmt.Errorf("descriptor %d cannot be protected", fd)
		}
		s.files[i] = os.NewFile(uintptr(fd), "supervised onboarding input")
	}
	return s, first
}
