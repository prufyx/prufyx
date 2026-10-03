// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package fix

import (
	"errors"

	"golang.org/x/sys/unix"
)

// allowedAttribute: com.apple.provenance is stamped by the system on files
// that were created by a process it tracks, including this process's own
// temporary file, so losing it is not a change.
func allowedAttribute(name string) bool { return name == "com.apple.provenance" }

// compressedFlag is UF_COMPRESSED: the file system compresses the file
// transparently; a new file is compressed again when it is eligible.
const compressedFlag = 0x20

// unpreservable refuses a file with BSD file flags or extended attributes.
func unpreservable(fd int, st *unix.Stat_t) *Refusal {
	if st.Flags&^compressedFlag != 0 {
		return refuse(ReasonUnsafeFile, "the file has BSD file flags that a replacement would drop")
	}
	return unpreservableAttributes(fd)
}

// syncDescriptor flushes to stable storage: on macOS fsync only reaches the
// drive's cache, so F_FULLFSYNC is asked for first. File systems that do
// not support it fall back to fsync.
func syncDescriptor(fd int) error {
	_, err := unix.FcntlInt(uintptr(fd), unix.F_FULLFSYNC, 0)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP) {
		return unix.Fsync(fd)
	}
	return err
}
