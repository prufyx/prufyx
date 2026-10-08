// SPDX-License-Identifier: AGPL-3.0-only

//go:build !unix

package offlineboundary

import "os"

// ownedByCurrentUser has no POSIX owner to compare on this platform.
func ownedByCurrentUser(os.FileInfo) bool { return true }
