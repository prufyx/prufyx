// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var renameAt = unix.Renameat

const maxInventoryOutputBytes = 8 << 20

func rejectSymlinkComponents(name string) error {
	abs, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	current := string(filepath.Separator)
	if volume := filepath.VolumeName(abs); volume != "" {
		current = volume + string(filepath.Separator)
		abs = strings.TrimPrefix(abs, current)
	} else {
		abs = strings.TrimPrefix(abs, current)
	}
	for _, part := range strings.Split(abs, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("unsafe output path")
		}
	}
	return nil
}

func randomName(prefix string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func validateExistingAt(fd int, name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return fmt.Errorf("output must be a regular single-link file")
	}
	return nil
}

func openOutputParent(firstPath, secondPath string) (dirFD int, firstBase, secondBase string, err error) {
	firstAbs, err := filepath.Abs(firstPath)
	if err != nil {
		return -1, "", "", err
	}
	secondAbs, err := filepath.Abs(secondPath)
	if err != nil {
		return -1, "", "", err
	}
	parent := filepath.Dir(firstAbs)
	if filepath.Dir(secondAbs) != parent || filepath.Base(firstAbs) == filepath.Base(secondAbs) {
		return -1, "", "", fmt.Errorf("inventory outputs must be distinct files in one directory")
	}
	if err := rejectSymlinkComponents(parent); err != nil {
		return -1, "", "", err
	}
	dirFD, err = unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, "", "", err
	}
	var st unix.Stat_t
	if err := unix.Fstat(dirFD, &st); err != nil {
		unix.Close(dirFD)
		return -1, "", "", err
	}
	if int(st.Uid) != os.Getuid() || st.Mode&0o022 != 0 {
		unix.Close(dirFD)
		return -1, "", "", fmt.Errorf("output parent must be owned by the current user and not group/world writable")
	}
	return dirFD, filepath.Base(firstAbs), filepath.Base(secondAbs), nil
}

func readRegularAt(dirFD int, name string) ([]byte, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return nil, fmt.Errorf("output must be a regular single-link file")
	}
	if st.Size < 0 || st.Size > maxInventoryOutputBytes {
		return nil, fmt.Errorf("output exceeds the bounded read limit")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxInventoryOutputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInventoryOutputBytes {
		return nil, fmt.Errorf("output exceeds the bounded read limit")
	}
	return raw, nil
}

func readOutputPair(firstPath, secondPath string) ([]byte, []byte, error) {
	dirFD, firstBase, secondBase, err := openOutputParent(firstPath, secondPath)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(dirFD)
	first, err := readRegularAt(dirFD, firstBase)
	if err != nil {
		return nil, nil, err
	}
	second, err := readRegularAt(dirFD, secondBase)
	if err != nil {
		return nil, nil, err
	}
	return first, second, nil
}

func writeTempAt(dirFD int, data []byte) (name string, err error) {
	name, err = randomName(".prufyx-inventory-new-")
	if err != nil {
		return "", err
	}
	fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = unix.Unlinkat(dirFD, name, 0)
		}
	}()
	if err = file.Chmod(0o644); err != nil {
		return "", err
	}
	if _, err = file.Write(data); err != nil {
		return "", err
	}
	if err = file.Sync(); err != nil {
		return "", err
	}
	if err = file.Close(); err != nil {
		return "", err
	}
	complete = true
	return name, nil
}

func moveExistingAt(dirFD int, name, backup string) (bool, error) {
	err := unix.Renameat(dirFD, name, dirFD, backup)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func writeOutputPair(firstPath string, first []byte, secondPath string, second []byte) error {
	dirFD, firstBase, secondBase, err := openOutputParent(firstPath, secondPath)
	if err != nil {
		return err
	}
	defer unix.Close(dirFD)
	if err := validateExistingAt(dirFD, firstBase); err != nil {
		return err
	}
	if err := validateExistingAt(dirFD, secondBase); err != nil {
		return err
	}
	firstTemp, err := writeTempAt(dirFD, first)
	if err != nil {
		return err
	}
	defer func() {
		if firstTemp != "" {
			_ = unix.Unlinkat(dirFD, firstTemp, 0)
		}
	}()
	secondTemp, err := writeTempAt(dirFD, second)
	if err != nil {
		return err
	}
	defer func() {
		if secondTemp != "" {
			_ = unix.Unlinkat(dirFD, secondTemp, 0)
		}
	}()
	firstBackup, _ := randomName(".prufyx-inventory-old-")
	secondBackup, _ := randomName(".prufyx-inventory-old-")
	firstHad, err := moveExistingAt(dirFD, firstBase, firstBackup)
	if err != nil {
		return err
	}
	secondHad, err := moveExistingAt(dirFD, secondBase, secondBackup)
	if err != nil {
		if firstHad {
			_ = unix.Renameat(dirFD, firstBackup, dirFD, firstBase)
		}
		return err
	}
	restore := func() {
		_ = unix.Unlinkat(dirFD, firstBase, 0)
		_ = unix.Unlinkat(dirFD, secondBase, 0)
		if firstHad {
			_ = unix.Renameat(dirFD, firstBackup, dirFD, firstBase)
		}
		if secondHad {
			_ = unix.Renameat(dirFD, secondBackup, dirFD, secondBase)
		}
		_ = unix.Fsync(dirFD)
	}
	if err := renameAt(dirFD, firstTemp, dirFD, firstBase); err != nil {
		restore()
		return err
	}
	firstTemp = ""
	if err := renameAt(dirFD, secondTemp, dirFD, secondBase); err != nil {
		restore()
		return err
	}
	secondTemp = ""
	if firstHad {
		_ = unix.Unlinkat(dirFD, firstBackup, 0)
	}
	if secondHad {
		_ = unix.Unlinkat(dirFD, secondBackup, 0)
	}
	return unix.Fsync(dirFD)
}
