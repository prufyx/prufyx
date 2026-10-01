// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin

package currentbundle

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openDirectoryNoFollow(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	for _, pair := range [][2]string{{"/tmp", "/private/tmp"}, {"/var", "/private/var"}} {
		if abs == pair[0] {
			abs = pair[1]
		} else if strings.HasPrefix(abs, pair[0]+string(filepath.Separator)) {
			abs = pair[1] + strings.TrimPrefix(abs, pair[0])
		}
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator))
	directory, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	if len(parts) == 1 && parts[0] == "" {
		return directory, nil
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = directory.Close()
			return nil, syscall.EINVAL
		}
		next, openErr := currentbundleOpenat(directory, part, uintptr(syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
		_ = directory.Close()
		if openErr != nil {
			return nil, openErr
		}
		directory = next
	}
	return directory, nil
}

func openRelativeFile(root *os.File, relative string) (*os.File, error) {
	parts := strings.Split(relative, "/")
	if relative == "" || strings.HasPrefix(relative, "/") || strings.Contains(relative, "\\") {
		return nil, syscall.EINVAL
	}
	directory := root
	var opened []*os.File
	defer func() {
		for _, f := range opened {
			_ = f.Close()
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, syscall.EINVAL
		}
		next, err := currentbundleOpenat(directory, part, uintptr(syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
		if err != nil {
			return nil, err
		}
		opened = append(opened, next)
		directory = next
	}
	leaf := parts[len(parts)-1]
	if leaf == "" || leaf == "." || leaf == ".." {
		return nil, syscall.EINVAL
	}
	return currentbundleOpenat(directory, leaf, uintptr(syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC), 0)
}

func readBoundedRelative(root *os.File, relative string, limit int) ([]byte, error) {
	file, err := openRelativeFile(root, relative)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || !artifactOwnedByCurrentUser(before) || before.Size() <= 0 || before.Size() > int64(limit) || artifactLinkCount(before) != 1 {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(b) == 0 || len(b) > limit {
		return nil, ErrInvalid
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !artifactChangeTimesMatch(before, after) || after.Mode().Perm() != 0600 || !artifactOwnedByCurrentUser(after) || artifactLinkCount(after) != 1 || after.Size() != before.Size() || int64(len(b)) != after.Size() {
		return nil, ErrIntegrity
	}
	return b, nil
}

func artifactOwnedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Getuid())
}

func artifactChangeTimesMatch(before, after os.FileInfo) bool {
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	return beforeOK && afterOK && before.ModTime().Equal(after.ModTime()) && beforeStat.Ctimespec.Sec == afterStat.Ctimespec.Sec && beforeStat.Ctimespec.Nsec == afterStat.Ctimespec.Nsec
}
