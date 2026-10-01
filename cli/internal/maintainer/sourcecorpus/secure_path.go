// SPDX-License-Identifier: AGPL-3.0-only

package sourcecorpus

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type fileState struct {
	device, inode, links, uid uint64
	mode                      os.FileMode
	size                      int64
	mtimeNS, ctimeNS          int64
}

func physicalComponents(path string) ([]string, error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return nil, errRejected
	}
	if !filepath.IsAbs(path) {
		for _, part := range strings.Split(path, string(filepath.Separator)) {
			if part == "" || part == "." || part == ".." {
				return nil, errRejected
			}
		}
		cwd, err := os.Getwd()
		if err != nil {
			return nil, errRejected
		}
		cwd, err = filepath.EvalSymlinks(cwd)
		if err != nil {
			return nil, errRejected
		}
		path = cwd + string(filepath.Separator) + path
	}
	if runtime.GOOS == "darwin" {
		if path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
			path = "/private" + path
		} else if path == "/var" || strings.HasPrefix(path, "/var/") {
			path = "/private" + path
		}
	}
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) == 0 {
		return nil, errRejected
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errRejected
		}
	}
	return parts, nil
}

func openPhysical(path string, leafFlags int) (*os.File, error) {
	parts, err := physicalComponents(path)
	if err != nil {
		return nil, errRejected
	}
	current, err := openRootDirectory()
	if err != nil {
		return nil, errRejected
	}
	for i, part := range parts {
		var next *os.File
		if i == len(parts)-1 {
			next, err = openRelative(current, part, leafFlags)
		} else {
			next, err = openRelativeDirectory(current, part)
		}
		_ = current.Close()
		if err != nil {
			return nil, errRejected
		}
		current = next
	}
	return current, nil
}

func stateOf(file *os.File) (fileState, error) {
	info, err := file.Stat()
	if err != nil {
		return fileState{}, errRejected
	}
	return platformFileState(info)
}

func readRegular(file *os.File, maximum int64, private bool) ([]byte, error) {
	before, err := stateOf(file)
	if err != nil || !before.mode.IsRegular() || before.links != 1 || before.size < 1 || before.size > maximum {
		return nil, errRejected
	}
	if private && (before.uid != uint64(os.Geteuid()) || before.mode.Perm() != 0o600) {
		return nil, errRejected
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.size || int64(len(data)) > maximum {
		return nil, errRejected
	}
	after, err := stateOf(file)
	if err != nil || before != after {
		return nil, errRejected
	}
	return data, nil
}

func readPhysicalFile(path string, maximum int64, private bool) ([]byte, error) {
	file, err := openPhysical(path, os.O_RDONLY)
	if err != nil {
		return nil, errRejected
	}
	defer file.Close()
	return readRegular(file, maximum, private)
}

func validatePrivateDirectory(directory *os.File) error {
	state, err := stateOf(directory)
	if err != nil || !state.mode.IsDir() || state.uid != uint64(os.Geteuid()) || state.mode.Perm() != 0o700 {
		return errRejected
	}
	return nil
}

func validateOwnerOnlyDirectory(directory *os.File) error {
	state, err := stateOf(directory)
	if err != nil || !state.mode.IsDir() || state.uid != uint64(os.Geteuid()) || state.mode.Perm()&0o077 != 0 {
		return errRejected
	}
	return nil
}

func readOwnerOnlyRegular(file *os.File, maximum int64) ([]byte, error) {
	before, err := stateOf(file)
	if err != nil || !before.mode.IsRegular() || before.links != 1 || before.uid != uint64(os.Geteuid()) || before.mode.Perm()&0o077 != 0 || before.size < 1 || before.size > maximum {
		return nil, errRejected
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != before.size || int64(len(data)) > maximum {
		return nil, errRejected
	}
	after, err := stateOf(file)
	if err != nil || before != after {
		return nil, errRejected
	}
	return data, nil
}

func readRelativeFile(root *os.File, relative string, maximum int64, private bool) ([]byte, error) {
	parts, err := relativeParts(relative)
	if err != nil {
		return nil, errRejected
	}
	current, err := duplicateFile(root)
	if err != nil {
		return nil, errRejected
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := openRelativeDirectory(current, part)
		_ = current.Close()
		if openErr != nil || validatePrivateDirectory(next) != nil {
			if next != nil {
				_ = next.Close()
			}
			return nil, errRejected
		}
		current = next
	}
	defer current.Close()
	leaf, err := openRelative(current, parts[len(parts)-1], os.O_RDONLY)
	if err != nil {
		return nil, errRejected
	}
	defer leaf.Close()
	return readRegular(leaf, maximum, private)
}

func openRelativeDirPath(root *os.File, relative string) (*os.File, error) {
	parts, err := relativeParts(relative)
	if err != nil {
		return nil, errRejected
	}
	current, err := duplicateFile(root)
	if err != nil {
		return nil, errRejected
	}
	for _, part := range parts {
		next, openErr := openRelativeDirectory(current, part)
		_ = current.Close()
		if openErr != nil || validatePrivateDirectory(next) != nil {
			if next != nil {
				_ = next.Close()
			}
			return nil, errRejected
		}
		current = next
	}
	return current, nil
}

func readObjectAt(root *os.File, objectRoot, objectName string, private bool) ([]byte, error) {
	if !objectNamePattern.MatchString(objectName) {
		return nil, errRejected
	}
	directory, err := openRelativeDirPath(root, objectRoot+"/sha256")
	if err != nil {
		return nil, errRejected
	}
	defer directory.Close()
	leaf := strings.TrimPrefix(objectName, "sha256/")
	file, err := openRelative(directory, leaf, os.O_RDONLY)
	if err != nil {
		return nil, errRejected
	}
	defer file.Close()
	return readRegular(file, maxObjectBytes, private)
}

func relativeParts(value string) ([]string, error) {
	if value == "" || !isASCII(value) || len(value) > maxPathBytes || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\x00") || strings.Contains(value, "//") {
		return nil, errRejected
	}
	parts := strings.Split(value, "/")
	if len(parts) < 1 || len(parts) > maxPathSegments {
		return nil, errRejected
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || !gitPathSegmentPattern.MatchString(part) {
			return nil, errRejected
		}
	}
	return parts, nil
}

func duplicateFile(file *os.File) (*os.File, error) {
	fd, err := duplicateFD(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), file.Name()), nil
}

var errUnsupportedPlatform = errors.New("unsupported secure filesystem platform")
