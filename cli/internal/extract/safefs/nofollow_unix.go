// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package safefs

import "syscall"

const noFollow = syscall.O_NOFOLLOW
