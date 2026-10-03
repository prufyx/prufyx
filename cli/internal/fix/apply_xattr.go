// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package fix

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"
)

// extendedAttributes lists the names of the extended attributes of fd.
func extendedAttributes(fd int) ([]string, error) {
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil, nil
		}
		return nil, err
	}
	if size <= 0 {
		return nil, nil
	}
	buffer := make([]byte, size)
	size, err = unix.Flistxattr(fd, buffer)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, name := range bytes.Split(buffer[:size], []byte{0}) {
		if len(name) > 0 {
			names = append(names, string(name))
		}
	}
	return names, nil
}

// unpreservableAttributes refuses a file that carries extended attributes
// a replacement would drop, except the ones allowedAttribute names.
func unpreservableAttributes(fd int) *Refusal {
	names, err := extendedAttributes(fd)
	if err != nil {
		return refuse(ReasonUnsafeFile, "the extended attributes of the file cannot be inspected")
	}
	for _, name := range names {
		if !allowedAttribute(name) {
			return refuse(ReasonUnsafeFile, "the file carries extended attributes or ACLs that a replacement would drop")
		}
	}
	return nil
}
