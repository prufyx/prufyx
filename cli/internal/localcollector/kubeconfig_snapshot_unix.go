// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package localcollector

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func readKubeconfigForSnapshot(path string) ([]byte, error) {
	file, err := openKubeconfigNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !privateKubeconfigFile(before) || before.Size() <= 0 || before.Size() > maxKubeconfigSnapshotBytes {
		return nil, errors.New("invalid kubeconfig")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxKubeconfigSnapshotBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxKubeconfigSnapshotBytes {
		wipeKubeconfigBytes(raw)
		return nil, errors.New("invalid kubeconfig")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateKubeconfigFile(after) || after.Size() != before.Size() || int64(len(raw)) != after.Size() || !kubeconfigTimesMatch(before, after) {
		wipeKubeconfigBytes(raw)
		return nil, errors.New("changed kubeconfig")
	}
	return raw, nil
}

func openKubeconfigNoFollow(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	abs = canonicalKubeconfigTempPath(abs)
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator))
	if len(parts) < 2 || parts[len(parts)-1] == "" {
		return nil, syscall.EINVAL
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	directory := root
	defer func() {
		if directory != root {
			_ = directory.Close()
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, syscall.EINVAL
		}
		fd, err := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		next := os.NewFile(uintptr(fd), part)
		if directory != root {
			_ = directory.Close()
		}
		directory = next
	}
	fd, err := unix.Openat(int(directory.Fd()), parts[len(parts)-1], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "kubeconfig"), nil
}

func privateKubeconfigFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Uid == uint32(os.Getuid()) && stat.Nlink == 1 && info.Mode().Perm()&0o077 == 0
}

func createKubeconfigSnapshot(raw []byte) (string, func() error, error) {
	parent, err := verifiedKubeconfigTempParent()
	if err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(parent, ".prufyx-kubeconfig-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() error { return os.RemoveAll(dir) }
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privateKubeconfigDirectory(info) {
		_ = cleanup()
		return "", nil, errors.New("unsafe snapshot directory")
	}
	path := filepath.Join(dir, "config")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = cleanup()
		return "", nil, err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = cleanup()
		}
	}()
	if _, err := file.Write(raw); err != nil || file.Sync() != nil || file.Close() != nil {
		return "", nil, errors.New("write snapshot")
	}
	info, err = os.Lstat(path)
	if err != nil || !privateKubeconfigFile(info) || info.Size() != int64(len(raw)) {
		return "", nil, errors.New("invalid snapshot")
	}
	check, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(check, raw) {
		wipeKubeconfigBytes(check)
		return "", nil, errors.New("snapshot verification")
	}
	wipeKubeconfigBytes(check)
	ok = true
	return path, cleanup, nil
}

func verifiedKubeconfigTempParent() (string, error) {
	path, err := filepath.Abs(os.TempDir())
	if err != nil {
		return "", err
	}
	path = canonicalKubeconfigTempPath(path)
	if err := validateKubeconfigTempPath(path); err != nil {
		return "", err
	}
	return path, nil
}

func validateKubeconfigTempPath(path string) error {
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	root, err := os.Open("/")
	if err != nil {
		return err
	}
	defer root.Close()
	directory := root
	defer func() {
		if directory != root {
			_ = directory.Close()
		}
	}()
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return syscall.EINVAL
		}
		fd, err := unix.Openat(int(directory.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		next := os.NewFile(uintptr(fd), part)
		if directory != root {
			_ = directory.Close()
		}
		directory = next
		info, err := directory.Stat()
		if err != nil || !privateKubeconfigDirectory(info) && !trustedKubeconfigTempAncestor(info) {
			return errors.New("unsafe temporary directory")
		}
	}
	return nil
}

func privateKubeconfigDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.IsDir() && stat.Uid == uint32(os.Getuid()) && info.Mode().Perm()&0o077 == 0
}

func trustedKubeconfigTempAncestor(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() {
		return false
	}
	if info.Mode().Perm()&0o022 == 0 {
		return stat.Uid == 0 || stat.Uid == uint32(os.Getuid())
	}
	return info.Mode()&os.ModeSticky != 0 && (stat.Uid == 0 || stat.Uid == uint32(os.Getuid()))
}
