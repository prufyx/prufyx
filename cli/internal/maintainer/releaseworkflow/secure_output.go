// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type outputAsset struct {
	name     string
	required bool
	replace  bool
}

type outputDirectory struct {
	path string
	file *os.File
	dev  uint64
	ino  uint64
}

func canonicalOutputPath(path string) string {
	if runtime.GOOS != "darwin" {
		return path
	}
	for _, alias := range [][2]string{{"/tmp", "/private/tmp"}, {"/var", "/private/var"}} {
		if path == alias[0] {
			return alias[1]
		}
		if strings.HasPrefix(path, alias[0]+"/") {
			return alias[1] + strings.TrimPrefix(path, alias[0])
		}
	}
	return path
}

func outputPathParts(path string) (string, []string, error) {
	abs, err := filepath.Abs(canonicalOutputPath(path))
	if err != nil {
		return "", nil, err
	}
	abs = filepath.Clean(abs)
	volume := filepath.VolumeName(abs)
	root := string(filepath.Separator)
	rest := strings.TrimPrefix(abs, root)
	if volume != "" {
		root = volume + string(filepath.Separator)
		rest = strings.TrimPrefix(abs, root)
	}
	parts := strings.Split(rest, string(filepath.Separator))
	if len(parts) == 0 {
		return "", nil, errors.New("output directory path is invalid")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", nil, errors.New("output directory path is invalid")
		}
	}
	return root, parts, nil
}

func walkOutputDirectory(path string, create bool) (*os.File, error) {
	root, parts, err := outputPathParts(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), root)
	if current == nil {
		_ = unix.Close(fd)
		return nil, errors.New("cannot retain output root")
	}
	for _, part := range parts {
		nextFD, openErr := unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil && create && errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(int(current.Fd()), part, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				current.Close()
				return nil, mkdirErr
			}
			nextFD, openErr = unix.Openat(int(current.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			current.Close()
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), part)
		if next == nil {
			_ = unix.Close(nextFD)
			current.Close()
			return nil, errors.New("cannot retain output directory")
		}
		current.Close()
		current = next
	}
	return current, nil
}

func directoryIdentity(file *os.File) (uint64, uint64, os.FileMode, uint32, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, 0, 0, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, 0, errors.New("output directory identity is unavailable")
	}
	return uint64(stat.Dev), uint64(stat.Ino), info.Mode(), uint32(stat.Uid), nil
}

func privateDirectoryMode(mode os.FileMode) bool {
	return mode.IsDir() && mode.Perm() == 0o700 && mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func openOutputDirectory(repo, raw string) (*outputDirectory, error) {
	if raw == "" {
		return nil, errors.New("output directory is required")
	}
	candidate, err := filepath.Abs(canonicalOutputPath(raw))
	if err != nil {
		return nil, errors.New("cannot resolve output directory")
	}
	candidate = filepath.Clean(candidate)
	repository, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return nil, err
	}
	repository = filepath.Clean(canonicalOutputPath(repository))
	if within(repository, candidate) {
		return nil, errors.New("OUTPUT_DIR must be outside the Git checkout")
	}
	file, err := walkOutputDirectory(candidate, true)
	if err != nil {
		return nil, errors.New("cannot create or open output directory")
	}
	dev, ino, mode, uid, err := directoryIdentity(file)
	if err != nil || !privateDirectoryMode(mode) || uid != uint32(os.Getuid()) {
		file.Close()
		return nil, errors.New("output directory must be owned by the current user with mode 0700")
	}
	directory := &outputDirectory{path: candidate, file: file, dev: dev, ino: ino}
	if err := directory.verifyBinding(); err != nil {
		directory.Close()
		return nil, err
	}
	return directory, nil
}

func (directory *outputDirectory) Close() error {
	if directory == nil || directory.file == nil {
		return nil
	}
	return directory.file.Close()
}

func (directory *outputDirectory) verifyBinding() error {
	if directory == nil || directory.file == nil {
		return errors.New("output directory is unavailable")
	}
	dev, ino, mode, uid, err := directoryIdentity(directory.file)
	if err != nil || dev != directory.dev || ino != directory.ino || !privateDirectoryMode(mode) || uid != uint32(os.Getuid()) {
		return errors.New("output directory changed")
	}
	current, err := walkOutputDirectory(directory.path, false)
	if err != nil {
		return errors.New("output directory path changed")
	}
	defer current.Close()
	currentDev, currentIno, currentMode, currentUID, err := directoryIdentity(current)
	if err != nil || currentDev != directory.dev || currentIno != directory.ino || !privateDirectoryMode(currentMode) || currentUID != uint32(os.Getuid()) {
		return errors.New("output directory path changed")
	}
	return nil
}

func validOutputName(name string) bool {
	return name != "" && name == filepath.Base(name) && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\x00\r\n")
}

func (directory *outputDirectory) statAsset(name string) (unix.Stat_t, bool, error) {
	var stat unix.Stat_t
	if !validOutputName(name) {
		return stat, false, errors.New("release asset name is invalid")
	}
	err := unix.Fstatat(int(directory.file.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return stat, false, nil
	}
	if err != nil {
		return stat, false, err
	}
	return stat, true, nil
}

func safeRegularAsset(stat unix.Stat_t) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && uint32(stat.Uid) == uint32(os.Getuid()) && uint64(stat.Nlink) == 1 && stat.Mode&0o7022 == 0
}

func (directory *outputDirectory) preflight(assets ...outputAsset) error {
	if err := directory.verifyBinding(); err != nil {
		return err
	}
	seen := make(map[string]bool, len(assets))
	for _, asset := range assets {
		if !validOutputName(asset.name) || seen[asset.name] {
			return errors.New("release asset preflight is invalid")
		}
		seen[asset.name] = true
		stat, exists, err := directory.statAsset(asset.name)
		if err != nil {
			return errors.New("cannot inspect release asset")
		}
		if !exists {
			if asset.required {
				return errors.New("required release asset is missing")
			}
			continue
		}
		if !safeRegularAsset(stat) {
			return errors.New("release asset is unsafe")
		}
		if !asset.required && !asset.replace {
			return errors.New("refusing to overwrite release asset")
		}
	}
	return nil
}

func (directory *outputDirectory) preflightExact(assets ...outputAsset) error {
	if err := directory.preflight(assets...); err != nil {
		return err
	}
	allowed := make(map[string]bool, len(assets))
	for _, asset := range assets {
		allowed[asset.name] = true
	}
	fd, err := unix.Openat(int(directory.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("cannot enumerate release output")
	}
	entries := os.NewFile(uintptr(fd), directory.path)
	if entries == nil {
		_ = unix.Close(fd)
		return errors.New("cannot retain release output enumeration")
	}
	defer entries.Close()
	listed, err := entries.ReadDir(-1)
	if err != nil {
		return errors.New("cannot enumerate release output")
	}
	for _, entry := range listed {
		if !allowed[entry.Name()] {
			return errors.New("release output contains unexpected files")
		}
	}
	return nil
}

func (directory *outputDirectory) create(name string, mode uint32, write func(io.Writer) error) error {
	if err := directory.verifyBinding(); err != nil {
		return err
	}
	if !validOutputName(name) {
		return errors.New("release asset name is invalid")
	}
	fd, err := unix.Openat(int(directory.file.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(directory.file.Fd()), name, 0)
		return errors.New("cannot retain release asset")
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = unix.Unlinkat(int(directory.file.Fd()), name, 0)
		}
	}()
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if err := write(file); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Fsync(int(directory.file.Fd())); err != nil {
		return err
	}
	complete = true
	return nil
}

func temporaryAssetName() (string, error) {
	var token [16]byte
	if _, err := io.ReadFull(rand.Reader, token[:]); err != nil {
		return "", err
	}
	return ".prufyx-release-" + hex.EncodeToString(token[:]), nil
}

func (directory *outputDirectory) replace(name string, mode uint32, write func(io.Writer) error) error {
	if err := directory.verifyBinding(); err != nil {
		return err
	}
	if !validOutputName(name) {
		return errors.New("release asset name is invalid")
	}
	var temporary string
	for attempt := 0; attempt < 8; attempt++ {
		candidate, err := temporaryAssetName()
		if err != nil {
			return err
		}
		fd, err := unix.Openat(int(directory.file.Fd()), candidate, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return err
		}
		temporary = candidate
		file := os.NewFile(uintptr(fd), candidate)
		if file == nil {
			_ = unix.Close(fd)
			_ = unix.Unlinkat(int(directory.file.Fd()), candidate, 0)
			return errors.New("cannot retain temporary release asset")
		}
		writeErr := file.Chmod(os.FileMode(mode))
		if writeErr == nil {
			writeErr = write(file)
		}
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
		if writeErr != nil {
			_ = unix.Unlinkat(int(directory.file.Fd()), candidate, 0)
			return writeErr
		}
		break
	}
	if temporary == "" {
		return errors.New("cannot reserve temporary release asset")
	}
	if err := unix.Renameat(int(directory.file.Fd()), temporary, int(directory.file.Fd()), name); err != nil {
		_ = unix.Unlinkat(int(directory.file.Fd()), temporary, 0)
		return err
	}
	return unix.Fsync(int(directory.file.Fd()))
}

func writeBytes(raw []byte) func(io.Writer) error {
	return func(writer io.Writer) error {
		_, err := writer.Write(raw)
		return err
	}
}

type outputFileIdentity struct {
	dev, ino, nlink uint64
	uid             uint32
	mode            os.FileMode
	size            int64
	modified        int64
}

func openedOutputIdentity(file *os.File) (outputFileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return outputFileIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return outputFileIdentity{}, errors.New("release asset identity is unavailable")
	}
	identity := outputFileIdentity{
		dev: uint64(stat.Dev), ino: uint64(stat.Ino), nlink: uint64(stat.Nlink), uid: uint32(stat.Uid),
		mode: info.Mode(), size: info.Size(), modified: info.ModTime().UnixNano(),
	}
	if !identity.mode.IsRegular() || identity.mode&os.ModeSymlink != 0 || identity.uid != uint32(os.Getuid()) || identity.nlink != 1 || identity.mode.Perm()&0o022 != 0 || identity.mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return outputFileIdentity{}, errors.New("release asset is unsafe")
	}
	return identity, nil
}

func (directory *outputDirectory) digest(name string) (string, error) {
	if err := directory.verifyBinding(); err != nil {
		return "", err
	}
	if !validOutputName(name) {
		return "", errors.New("release asset name is invalid")
	}
	fd, err := unix.Openat(int(directory.file.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return "", errors.New("cannot retain release asset")
	}
	defer file.Close()
	before, err := openedOutputIdentity(file)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	after, err := openedOutputIdentity(file)
	if err != nil || before != after {
		return "", errors.New("release asset changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (directory *outputDirectory) assetPath(name string) string {
	return filepath.Join(directory.path, name)
}

func (directory *outputDirectory) createTarGz(name, root, prefix string, epoch time.Time) error {
	return directory.create(name, 0o600, func(writer io.Writer) error {
		return writeTarGz(root, prefix, writer, epoch)
	})
}

func writeTarGz(root, prefix string, destination io.Writer, epoch time.Time) error {
	gzipWriter := gzip.NewWriter(destination)
	gzipWriter.Name = ""
	gzipWriter.Comment = ""
	gzipWriter.ModTime = time.Unix(0, 0)
	gzipWriter.OS = 255
	if err := writeTar(root, prefix, gzipWriter, epoch); err != nil {
		_ = gzipWriter.Close()
		return err
	}
	return gzipWriter.Close()
}
