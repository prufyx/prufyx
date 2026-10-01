// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgepack assembles bounded, deterministic offline knowledge archives.
// It does not verify signatures, trust roots, source evidence, or maintainer review.
package knowledgepack

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MaxPackageBytes = 4 << 20
	MaxPackageFiles = 16
	MaxPackageEntry = 1 << 20
	MaxPackageTotal = 2 << 20
)

var targetSuffix = map[string]string{
	"cert-manager":                "cert-manager.v1.json",
	"cncf":                        "constraints.v1.json",
	"spiffe-x509-svid":            "spiffe-x509-svid-profile.v1.json",
	"cloudevents-structured-json": "cloudevents-structured-json-profile.v1.json",
	"tikv-gcp-v2-wif-backup":      "tikv-gcp-v2-wif-backup-profile.v1.json",
}

var ErrRejected = errors.New("knowledge package rejected")

type identity struct {
	dev, ino uint64
	mode     os.FileMode
	nlink    uint64
	size     int64
	modNano  int64
}

func fileIdentity(info os.FileInfo) (identity, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return identity{}, fmt.Errorf("read file identity: %w", ErrRejected)
	}
	return identity{dev: uint64(st.Dev), ino: uint64(st.Ino), mode: info.Mode(), nlink: uint64(st.Nlink), size: info.Size(), modNano: info.ModTime().UnixNano()}, nil
}

func sameIdentity(left, right identity) bool { return left == right }

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
		if info.Mode()&os.ModeSymlink != 0 && !(runtime.GOOS == "darwin" && (current == "/var" || current == "/tmp" || current == "/etc")) {
			return fmt.Errorf("symlinked path component: %w", ErrRejected)
		}
	}
	return nil
}

func metadataName(name string) bool {
	if name == "metadata/timestamp.json" {
		return true
	}
	if !strings.HasPrefix(name, "metadata/") || !strings.HasSuffix(name, ".json") {
		return false
	}
	stem := strings.TrimSuffix(strings.TrimPrefix(name, "metadata/"), ".json")
	parts := strings.SplitN(stem, ".", 2)
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[0]) > 10 || parts[0][0] == '0' {
		return false
	}
	for _, c := range parts[0] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return parts[1] == "root" || parts[1] == "snapshot" || parts[1] == "targets"
}

func targetName(name, suffix string) bool {
	prefix, ending := "targets/knowledge/", "."+suffix
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ending) {
		return false
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ending)
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func readStable(name string, listed os.FileInfo) ([]byte, error) {
	listedID, err := fileIdentity(listed)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open input member: %w", ErrRejected)
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wrap input member: %w", ErrRejected)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat input member: %w", ErrRejected)
	}
	openedID, err := fileIdentity(opened)
	if err != nil || !sameIdentity(listedID, openedID) {
		return nil, fmt.Errorf("input member changed before reading: %w", ErrRejected)
	}
	limit := listed.Size() + 1
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil || int64(len(data)) != listed.Size() {
		return nil, fmt.Errorf("input member changed while reading: %w", ErrRejected)
	}
	after, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("restat input member: %w", ErrRejected)
	}
	afterID, err := fileIdentity(after)
	if err != nil || !sameIdentity(listedID, afterID) {
		return nil, fmt.Errorf("input member changed while reading: %w", ErrRejected)
	}
	current, err := os.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("input member disappeared: %w", ErrRejected)
	}
	currentID, err := fileIdentity(current)
	if err != nil || !sameIdentity(listedID, currentID) {
		return nil, fmt.Errorf("input member changed after reading: %w", ErrRejected)
	}
	return data, nil
}

func collectMembers(inputDir, profile string) (map[string][]byte, error) {
	suffix, ok := targetSuffix[profile]
	if !ok {
		return nil, fmt.Errorf("unsupported profile: %w", ErrRejected)
	}
	if err := rejectSymlinkComponents(inputDir); err != nil {
		return nil, err
	}
	root, err := os.Lstat(inputDir)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("input is not a real directory: %w", ErrRejected)
	}
	allowedDirs := map[string]bool{"metadata": true, "targets": true, "targets/knowledge": true}
	members := map[string][]byte{}
	inodes := map[[2]uint64]bool{}
	var total int64
	err = filepath.Walk(inputDir, func(name string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("enumerate input: %w", ErrRejected)
		}
		if name == inputDir {
			return nil
		}
		rel, err := filepath.Rel(inputDir, name)
		if err != nil {
			return fmt.Errorf("derive input member: %w", ErrRejected)
		}
		rel = filepath.ToSlash(rel)
		if info.IsDir() {
			if info.Mode()&os.ModeSymlink != 0 || !allowedDirs[rel] {
				return fmt.Errorf("unknown input directory: %w", ErrRejected)
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !isASCII(rel) || path.Clean(rel) != rel || (!metadataName(rel) && !targetName(rel, suffix)) {
			return fmt.Errorf("invalid input member: %w", ErrRejected)
		}
		id, err := fileIdentity(info)
		if err != nil || id.nlink != 1 {
			return fmt.Errorf("linked input member: %w", ErrRejected)
		}
		key := [2]uint64{id.dev, id.ino}
		if inodes[key] {
			return fmt.Errorf("duplicate hard-linked member: %w", ErrRejected)
		}
		inodes[key] = true
		if info.Size() < 1 || info.Size() > MaxPackageEntry || len(members) >= MaxPackageFiles {
			return fmt.Errorf("input member bound exceeded: %w", ErrRejected)
		}
		total += info.Size()
		if total > MaxPackageTotal {
			return fmt.Errorf("package total bound exceeded: %w", ErrRejected)
		}
		data, err := readStable(name, info)
		if err != nil {
			return err
		}
		members[rel] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	rootID, err := fileIdentity(root)
	if err != nil {
		return nil, err
	}
	currentRoot, err := os.Lstat(inputDir)
	if err != nil {
		return nil, fmt.Errorf("input root disappeared: %w", ErrRejected)
	}
	currentRootID, err := fileIdentity(currentRoot)
	if err != nil || !sameIdentity(rootID, currentRootID) {
		return nil, fmt.Errorf("input root changed while reading: %w", ErrRejected)
	}
	if len(members) < 4 || members["metadata/timestamp.json"] == nil {
		return nil, fmt.Errorf("incomplete package: %w", ErrRejected)
	}
	var target string
	for name := range members {
		if targetName(name, suffix) {
			if target != "" {
				return nil, fmt.Errorf("multiple package targets: %w", ErrRejected)
			}
			target = name
		}
	}
	if target == "" {
		return nil, fmt.Errorf("missing package target: %w", ErrRejected)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(members[target]))
	want := strings.TrimSuffix(strings.TrimPrefix(target, "targets/knowledge/"), "."+suffix)
	if digest != want {
		return nil, fmt.Errorf("target digest mismatch: %w", ErrRejected)
	}
	return members, nil
}

func isASCII(value string) bool {
	for _, c := range value {
		if c > 127 {
			return false
		}
	}
	return true
}

// PackageDirectory returns the deterministic archive bytes for an already-signed directory.
func PackageDirectory(inputDir, profile string) ([]byte, error) {
	members, err := collectMembers(inputDir, profile)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	var buffer bytes.Buffer
	w := tar.NewWriter(&buffer)
	for _, name := range names {
		format := tar.FormatUSTAR
		if len(path.Base(name)) > 100 {
			format = tar.FormatGNU
		}
		header := &tar.Header{Name: name, Mode: 0o644, Uid: 0, Gid: 0, Size: int64(len(members[name])), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: format}
		if err := w.WriteHeader(header); err != nil {
			return nil, fmt.Errorf("write archive header: %w", err)
		}
		if _, err := w.Write(members[name]); err != nil {
			return nil, fmt.Errorf("write archive member: %w", err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close archive: %w", err)
	}
	if buffer.Len() > MaxPackageBytes {
		return nil, fmt.Errorf("archive bound exceeded: %w", ErrRejected)
	}
	return buffer.Bytes(), nil
}

// WritePackage creates a new private archive and refuses overwrite.
func WritePackage(inputDir, output, profile string) error {
	raw, err := PackageDirectory(inputDir, profile)
	if err != nil {
		return err
	}
	if filepath.Base(output) == "." || filepath.Base(output) == string(filepath.Separator) || filepath.Base(output) == "" {
		return fmt.Errorf("invalid output: %w", ErrRejected)
	}
	parent := filepath.Dir(output)
	if err := rejectSymlinkComponents(parent); err != nil {
		return err
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0o700 {
		return fmt.Errorf("output parent is not private: %w", ErrRejected)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || int(parentStat.Uid) != os.Getuid() {
		return fmt.Errorf("output parent owner mismatch: %w", ErrRejected)
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open private output parent: %w", ErrRejected)
	}
	defer unix.Close(parentFD)
	var openedParent unix.Stat_t
	if err := unix.Fstat(parentFD, &openedParent); err != nil || int(openedParent.Uid) != os.Getuid() || openedParent.Mode&0o777 != 0o700 {
		return fmt.Errorf("output parent changed: %w", ErrRejected)
	}
	fd, err := unix.Openat(parentFD, filepath.Base(output), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create private output: %w", ErrRejected)
	}
	f := os.NewFile(uintptr(fd), filepath.Base(output))
	if f == nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(parentFD, filepath.Base(output), 0)
		return fmt.Errorf("wrap private output: %w", ErrRejected)
	}
	complete := false
	defer func() {
		_ = f.Close()
		if !complete {
			_ = unix.Unlinkat(parentFD, filepath.Base(output), 0)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("set output mode: %w", ErrRejected)
	}
	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("write output: %w", ErrRejected)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", ErrRejected)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close output: %w", ErrRejected)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync output parent: %w", ErrRejected)
	}
	complete = true
	return nil
}

func Profiles() []string {
	result := make([]string, 0, len(targetSuffix))
	for name := range targetSuffix {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
