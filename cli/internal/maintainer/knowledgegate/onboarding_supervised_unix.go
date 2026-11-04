// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package knowledgegate

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func claimSupervisedInputs() (*supervisedInputs, error) {
	var captured [6]bool
	var first error
	// Discover and protect the complete inherited set before NewFile may
	// initialize the runtime poller and allocate a missing descriptor number.
	for i := range captured {
		fd := i + 3
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC != 0 {
			if first == nil {
				first = fmt.Errorf("descriptor %d was not transferred", fd)
			}
			// Runtime-created close-on-exec handles were never transferred.
			// Do not claim or close them when an input slot is missing.
			continue
		}
		captured[i] = true
		if _, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil && first == nil {
			first = fmt.Errorf("descriptor %d cannot be protected", fd)
		}
	}
	if first != nil {
		for i, owned := range captured {
			if owned {
				_ = unix.Close(i + 3)
			}
		}
		return nil, first
	}
	inputs := &supervisedInputs{}
	for i := range inputs.files {
		inputs.files[i] = os.NewFile(uintptr(i+3), "supervised onboarding input")
	}
	return inputs, nil
}
