// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	trustStateAPIVersion = "prufyx.io/knowledge-trust-state/v1"
	selectionAPIVersion  = "prufyx.io/knowledge-selection/v1"
)

type trustState struct {
	APIVersion                string             `json:"apiVersion"`
	InitialRootDigest         string             `json:"initialRootDigest"`
	RootHistory               []RootHistoryEntry `json:"rootHistory"`
	Root                      RoleReceipt        `json:"root"`
	Timestamp                 RoleReceipt        `json:"timestamp,omitempty"`
	Snapshot                  RoleReceipt        `json:"snapshot,omitempty"`
	Targets                   RoleReceipt        `json:"targets,omitempty"`
	RevisionFloor             string             `json:"revisionFloor,omitempty"`
	RevisionFloorBundleDigest string             `json:"revisionFloorBundleDigest,omitempty"`
	// ProjectFloors is set only by the per-project profile: one rollback
	// floor per project target, in project order.
	ProjectFloors []projectFloor `json:"projectFloors,omitempty"`
}
type digestPointer struct {
	APIVersion string `json:"apiVersion"`
	Digest     string `json:"digest"`
}
type selectionPointer struct {
	APIVersion         string `json:"apiVersion"`
	Revision           string `json:"revision"`
	BundleDigest       string `json:"bundleDigest"`
	TrustReceiptDigest string `json:"trustReceiptDigest"`
	TrustStateDigest   string `json:"trustStateDigest"`
}
type storeFS struct {
	root *os.File
	path string
}

func (s *storeFS) uninitialized() (bool, error) {
	d, e := fdOpenDir(s.root, ".")
	if e != nil {
		return false, e
	}
	defer d.Close()
	names, e := d.Readdirnames(-1)
	if e != nil {
		return false, e
	}
	for _, n := range names {
		if n != ".lock" {
			return false, nil
		}
	}
	return true, nil
}

func (s *storeFS) emptyForProfile(profile profileSpec) (bool, error) {
	if !profile.valid() {
		return false, ErrIntegrity
	}
	d, e := fdOpenDir(s.root, ".")
	if e != nil {
		return false, e
	}
	defer d.Close()
	names, e := d.Readdirnames(-1)
	if e != nil {
		return false, e
	}
	for _, n := range names {
		if n == ".lock" || profile.marked() && n == "profile.json" {
			continue
		}
		return false, nil
	}
	return true, nil
}
func (s *storeFS) remove(rel string) error {
	p, n, e := parentBase(rel)
	if e != nil {
		return e
	}
	d, e := s.openDir(p, false)
	if e != nil {
		return e
	}
	defer d.Close()
	if e = fdUnlink(d, n); e != nil {
		return e
	}
	return fdSync(d)
}
func (s *storeFS) pendingRecoveryShape() bool {
	return s.pendingRecoveryShapeForProfile(certManagerProfile())
}

func (s *storeFS) pendingRecoveryShapeForProfile(profile profileSpec) bool {
	if !profile.valid() {
		return false
	}
	d, e := fdOpenDir(s.root, ".")
	if e != nil {
		return false
	}
	defer d.Close()
	names, e := d.Readdirnames(-1)
	if e != nil {
		return false
	}
	seen := false
	for _, n := range names {
		switch n {
		case ".lock", "clock-floor.json", "trust", "import-pending.json":
			if n == "import-pending.json" {
				seen = true
			}
		case "profile.json":
			if !profile.marked() {
				return false
			}
		default:
			return false
		}
	}
	return seen
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func marshalCanonical(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return append(raw, '\n'), nil
}
func parseRevision(v string) (int64, error) {
	if v == "" || len(v) > 10 || (len(v) > 1 && v[0] == '0') {
		return 0, ErrInvalid
	}
	n, e := strconv.ParseInt(v, 10, 32)
	if e != nil || n < 1 || n > maxRevision || strconv.FormatInt(n, 10) != v {
		return 0, ErrInvalid
	}
	return n, nil
}
func normalizeDigest(v string) (string, error) {
	if len(v) == 64 {
		v = "sha256:" + v
	}
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") {
		return "", ErrInvalid
	}
	if _, e := hex.DecodeString(strings.TrimPrefix(v, "sha256:")); e != nil || strings.ToLower(v) != v {
		return "", ErrInvalid
	}
	return v, nil
}
func parseTime(v string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339, v)
	if e != nil || !strings.HasSuffix(v, "Z") || t.Location() != time.UTC || t.Format(time.RFC3339) != v {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}

func canonicalStorePath(input string) (string, error) {
	abs, e := filepath.Abs(input)
	if e != nil || abs == "/" {
		return "", ErrInvalid
	}
	abs = platformCanonicalPath(abs)
	if filepath.Clean(abs) != abs {
		return "", ErrInvalid
	}
	return abs, nil
}
func ensureStoreRoot(input string) (*storeFS, error) {
	abs, e := canonicalStorePath(input)
	if e != nil {
		return nil, fmt.Errorf("store root: %w", e)
	}
	parts := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	dir, e := fdOpenRoot()
	if e != nil {
		return nil, e
	}
	for i, p := range parts {
		if !validPart(p) {
			dir.Close()
			return nil, ErrInvalid
		}
		next, x := fdOpenDir(dir, p)
		if x != nil && i == len(parts)-1 && errors.Is(x, syscall.ENOENT) {
			if x = fdMkdir(dir, p, 0o700); x == nil {
				x = fdSync(dir)
			}
			if x == nil {
				next, x = fdOpenDir(dir, p)
			}
		}
		dir.Close()
		if x != nil {
			return nil, fmt.Errorf("store path: %w", ErrInvalid)
		}
		dir = next
	}
	if e = checkPrivateDir(dir); e != nil {
		dir.Close()
		return nil, e
	}
	return &storeFS{root: dir, path: abs}, nil
}
func (s *storeFS) Close() error { return s.root.Close() }
func validPart(p string) bool {
	return p != "" && p != "." && p != ".." && !strings.ContainsAny(p, "/\\\x00")
}
func splitRelative(rel string) ([]string, error) {
	if rel == "" || filepath.IsAbs(rel) || filepath.Clean(rel) != rel {
		return nil, ErrInvalid
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	for _, p := range parts {
		if !validPart(p) {
			return nil, ErrInvalid
		}
	}
	return parts, nil
}
func checkPrivateDir(f *os.File) error {
	i, e := f.Stat()
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0o700 || fileNlink(i) < 1 {
		return ErrIntegrity
	}
	return nil
}
func (s *storeFS) openDir(rel string, create bool) (*os.File, error) {
	if rel == "." {
		d, err := fdOpenDir(s.root, ".")
		if err != nil {
			return nil, err
		}
		if err = checkPrivateDir(d); err != nil {
			d.Close()
			return nil, err
		}
		return d, nil
	}
	parts, e := splitRelative(rel)
	if e != nil {
		return nil, e
	}
	base, e := fdOpenDir(s.root, ".")
	if e != nil {
		return nil, e
	}
	for _, p := range parts {
		next, x := fdOpenDir(base, p)
		if x != nil && create && errors.Is(x, syscall.ENOENT) {
			if x = fdMkdir(base, p, 0o700); x == nil {
				x = fdSync(base)
			}
			if x == nil {
				next, x = fdOpenDir(base, p)
			}
		}
		base.Close()
		if x != nil {
			return nil, x
		}
		if x = checkPrivateDir(next); x != nil {
			next.Close()
			return nil, x
		}
		base = next
	}
	return base, nil
}
func parentBase(rel string) (string, string, error) {
	parts, e := splitRelative(rel)
	if e != nil {
		return "", "", e
	}
	if len(parts) == 1 {
		return ".", parts[0], nil
	}
	return strings.Join(parts[:len(parts)-1], "/"), parts[len(parts)-1], nil
}
func readOpenRegular(f *os.File, max int64) ([]byte, error) {
	before, e := f.Stat()
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 || before.Size() < 1 || before.Size() > max || fileNlink(before) != 1 {
		return nil, ErrIntegrity
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) != before.Size() {
		return nil, ErrIntegrity
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || after.Size() != before.Size() || fileNlink(after) != 1 {
		return nil, ErrIntegrity
	}
	return raw, nil
}
func (s *storeFS) read(rel string, max int64) ([]byte, error) {
	p, n, e := parentBase(rel)
	if e != nil {
		return nil, e
	}
	d, e := s.openDir(p, false)
	if e != nil {
		return nil, e
	}
	defer d.Close()
	f, e := fdOpenFile(d, n, syscall.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return readOpenRegular(f, max)
}
func randomTemp() (string, error) {
	var b [16]byte
	if _, e := io.ReadFull(rand.Reader, b[:]); e != nil {
		return "", e
	}
	return ".write-" + hex.EncodeToString(b[:]), nil
}
func (s *storeFS) write(rel string, raw []byte, immutable bool) error {
	if len(raw) == 0 {
		return ErrInvalid
	}
	p, n, e := parentBase(rel)
	if e != nil {
		return e
	}
	d, e := s.openDir(p, true)
	if e != nil {
		return e
	}
	defer d.Close()
	if old, x := fdOpenFile(d, n, syscall.O_RDONLY, 0); x == nil {
		got, rerr := readOpenRegular(old, int64(len(raw)))
		cerr := old.Close()
		if rerr != nil {
			return rerr
		}
		if immutable {
			if bytes.Equal(got, raw) && cerr == nil {
				return nil
			}
			return ErrIntegrity
		}
	} else if !errors.Is(x, syscall.ENOENT) {
		return ErrIntegrity
	}
	tmp, e := randomTemp()
	if e != nil {
		return e
	}
	f, e := fdOpenFile(d, tmp, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL, 0o600)
	if e != nil {
		return e
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = fdUnlink(d, tmp)
		}
	}()
	if n, writeErr := io.Copy(f, bytes.NewReader(raw)); writeErr != nil || n != int64(len(raw)) {
		e = ErrIntegrity
	} else {
		e = nil
	}
	if e == nil {
		e = f.Sync()
	}
	if c := f.Close(); e == nil {
		e = c
	}
	if e != nil {
		return e
	}
	if immutable {
		e = fdRenameNoReplace(d, tmp, n)
	} else {
		e = fdRename(d, tmp, n)
	}
	if e != nil {
		return e
	}
	cleanup = false
	return fdSync(d)
}
func (s *storeFS) lock(wait time.Duration) (*os.File, error) {
	f, e := fdOpenFile(s.root, ".lock", syscall.O_RDWR|syscall.O_CREAT, 0o600)
	if e != nil {
		return nil, e
	}
	i, e := f.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != 0o600 || fileNlink(i) != 1 {
		f.Close()
		return nil, ErrIntegrity
	}
	until := time.Now().Add(wait)
	for {
		e = lockFileExclusiveNonBlocking(f)
		if e == nil {
			return f, nil
		}
		if !lockWouldBlock(e) || time.Now().After(until) {
			f.Close()
			if lockWouldBlock(e) {
				return nil, fmt.Errorf("store lock timeout: %w", ErrInvalid)
			}
			return nil, e
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func unlockStore(f *os.File) error {
	e := unlockFile(f)
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
