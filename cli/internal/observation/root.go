// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	ErrCancelled           = errors.New("observation import cancelled")
	ErrUnsupportedPlatform = errors.New("observation descriptor I/O unsupported on this platform")
)

// Root is an opaque, owned directory capability. It deliberately exposes
// neither a pathname nor its descriptor. Constructors duplicate caller-owned
// descriptors and Close never affects the caller's file.
type Root struct {
	mu       sync.Mutex
	file     *os.File
	identity stableIdentity
	bindings map[string]fileBinding
	closed   bool
}

// fileBinding is the identity and content observed during inventory. A leaf
// capability may only serve a file which is byte-for-byte the same admitted
// entry; pathname lookup is merely the descriptor-relative transport.
type fileBinding struct {
	identity stableIdentity
	digest   [sha256.Size]byte
}

// stableIdentity is the complete native identity used for every directory
// entry and descriptor stability decision. atime is deliberately excluded:
// reading a file may update it. generation is zero on platforms which do not
// expose one.
type stableIdentity struct {
	device, inode, links uint64
	uid, gid             uint32
	rawMode              uint32
	size                 int64
	mtimeSec, mtimeNsec  int64
	ctimeSec, ctimeNsec  int64
	generation           uint64
}

func (i stableIdentity) equal(other stableIdentity) bool { return i == other }
func (i stableIdentity) sameBinding(other stableIdentity) bool {
	return i.device == other.device && i.inode == other.inode && i.rawMode == other.rawMode && i.uid == other.uid && i.gid == other.gid
}
func (i stableIdentity) isDirectory() bool { return i.rawMode&0170000 == 0040000 }
func (i stableIdentity) isRegular() bool   { return i.rawMode&0170000 == 0100000 }

func observationOpenBoundDirectory(parent *os.File, leaf string) (*os.File, stableIdentity, error) {
	entry, err := observationStatAt(parent, leaf)
	if err != nil || !entry.isDirectory() {
		return nil, stableIdentity{}, fmt.Errorf("classify directory entry: %w", ErrInvalid)
	}
	opened, err := observationOpenDirectory(parent, leaf)
	if err != nil {
		return nil, stableIdentity{}, err
	}
	identity, err := observationStableIdentity(opened)
	if err != nil || !entry.equal(identity) {
		_ = opened.Close()
		return nil, stableIdentity{}, fmt.Errorf("directory entry changed while opening: %w", ErrIntegrity)
	}
	return opened, identity, nil
}

func observationOpenBoundFile(parent *os.File, leaf string) (*os.File, stableIdentity, error) {
	entry, err := observationStatAt(parent, leaf)
	if err != nil || !entry.isRegular() || entry.links != 1 {
		return nil, stableIdentity{}, fmt.Errorf("classify regular entry: %w", ErrInvalid)
	}
	opened, err := observationOpenFile(parent, leaf)
	if err != nil {
		return nil, stableIdentity{}, err
	}
	identity, err := observationStableIdentity(opened)
	if err != nil || !entry.equal(identity) {
		_ = opened.Close()
		return nil, stableIdentity{}, fmt.Errorf("file entry changed while opening: %w", ErrIntegrity)
	}
	return opened, identity, nil
}

func observationDigestFile(ctx context.Context, file *os.File, expectedSize int64) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	h := sha256.New()
	buf := make([]byte, 32*1024)
	var total int64
	for {
		if err := checkContext(ctx); err != nil {
			return zero, err
		}
		n, err := file.Read(buf)
		if n > 0 {
			if int64(n) > expectedSize-total {
				return zero, fmt.Errorf("file grew while hashing: %w", ErrIntegrity)
			}
			if _, writeErr := h.Write(buf[:n]); writeErr != nil {
				return zero, writeErr
			}
			total += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return zero, err
		}
	}
	if total != expectedSize {
		return zero, fmt.Errorf("file size changed while hashing: %w", ErrIntegrity)
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

type ImportLimits struct {
	MaxTotalBytes    int64
	MaxFileBytes     int64
	MaxManifestBytes int64
	MaxFiles         int
	MaxDirectories   int
	MaxDepth         int
}

type ImportOptions struct{ Limits ImportLimits }

type normalizedLimits struct {
	total, file, manifest int64
	files, directories    int
	depth                 int
}

func normalizeImportOptions(options ImportOptions) (normalizedLimits, error) {
	l := normalizedLimits{total: maxInputBytes, file: maxFileBytes, manifest: maxManifestBytes, files: maxFiles, directories: maxDirectories, depth: maxPathDepth}
	set64 := func(value int64, hard int64, target *int64) error {
		if value < 0 || value > hard {
			return fmt.Errorf("invalid import limit: %w", ErrInvalid)
		}
		if value != 0 {
			*target = value
		}
		return nil
	}
	setInt := func(value int, hard int, target *int) error {
		if value < 0 || value > hard {
			return fmt.Errorf("invalid import limit: %w", ErrInvalid)
		}
		if value != 0 {
			*target = value
		}
		return nil
	}
	if err := set64(options.Limits.MaxTotalBytes, maxInputBytes, &l.total); err != nil {
		return l, err
	}
	if err := set64(options.Limits.MaxFileBytes, maxFileBytes, &l.file); err != nil {
		return l, err
	}
	if err := set64(options.Limits.MaxManifestBytes, maxManifestBytes, &l.manifest); err != nil {
		return l, err
	}
	if err := setInt(options.Limits.MaxFiles, maxFiles, &l.files); err != nil {
		return l, err
	}
	if err := setInt(options.Limits.MaxDirectories, maxDirectories, &l.directories); err != nil {
		return l, err
	}
	if err := setInt(options.Limits.MaxDepth, maxPathDepth, &l.depth); err != nil {
		return l, err
	}
	if l.manifest > l.file || l.file > l.total || l.files < 1 || l.directories < 1 || l.depth < 1 {
		return l, fmt.Errorf("inconsistent import limits: %w", ErrInvalid)
	}
	return l, nil
}

func validateLeaf(leaf string) error {
	if leaf == "" || leaf == "." || leaf == ".." || len(leaf) > 255 || strings.ContainsAny(leaf, "/\\") || strings.IndexByte(leaf, 0) >= 0 {
		return fmt.Errorf("invalid directory leaf: %w", ErrInvalid)
	}
	return nil
}

// OpenPath is the sole pathname boundary. Relative paths are rejected.
func OpenPath(path string) (*Root, error) {
	if path == "" || !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 {
		return nil, fmt.Errorf("invalid absolute observation root: %w", ErrInvalid)
	}
	if !observationPlatformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	f, _, err := observationOpenRoot(path)
	if err != nil {
		return nil, capabilityError("open observation root", err)
	}
	identity, err := validateRootDirectory(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Root{file: f, identity: identity}, nil
}

// Adopt duplicates root and owns only the duplicate.
func Adopt(root *os.File) (*Root, error) {
	if root == nil {
		return nil, fmt.Errorf("nil observation root: %w", ErrInvalid)
	}
	if !observationPlatformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	dup, err := observationDupFile(root)
	if err != nil {
		return nil, capabilityError("duplicate observation root", err)
	}
	identity, err := validateRootDirectory(dup)
	if err != nil {
		_ = dup.Close()
		return nil, err
	}
	return &Root{file: dup, identity: identity}, nil
}

func OpenAt(parent *os.File, leaf string) (*Root, error) {
	if parent == nil {
		return nil, fmt.Errorf("nil observation parent: %w", ErrInvalid)
	}
	if err := validateLeaf(leaf); err != nil {
		return nil, err
	}
	if !observationPlatformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	owned, err := observationDupFile(parent)
	if err != nil {
		return nil, capabilityError("duplicate observation parent", err)
	}
	defer owned.Close()
	if _, err := validateRootDirectory(owned); err != nil {
		return nil, err
	}
	child, identity, err := observationOpenBoundDirectory(owned, leaf)
	if err != nil {
		return nil, capabilityError("open observation leaf", err)
	}
	validated, err := validateRootDirectory(child)
	if err != nil {
		_ = child.Close()
		return nil, err
	}
	if !validated.equal(identity) {
		_ = child.Close()
		return nil, fmt.Errorf("observation leaf changed while opening: %w", ErrIntegrity)
	}
	return &Root{file: child, identity: identity}, nil
}

func capabilityError(operation string, err error) error {
	if errors.Is(err, ErrUnsupportedPlatform) {
		return fmt.Errorf("%s: %w", operation, ErrUnsupportedPlatform)
	}
	return fmt.Errorf("%s: %w: %v", operation, ErrInvalid, err)
}

func validateRootDirectory(file *os.File) (stableIdentity, error) {
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return stableIdentity{}, fmt.Errorf("observation root is not a directory: %w", ErrInvalid)
	}
	identity, err := observationStableIdentity(file)
	if err != nil {
		return stableIdentity{}, capabilityError("stat observation root", err)
	}
	return identity, nil
}

// ownedSnapshot opens a fresh directory description relative to the retained
// capability, avoiding shared readdir offsets and pathname authority.
func (r *Root) ownedSnapshot() (*os.File, error) {
	if r == nil {
		return nil, fmt.Errorf("nil observation root: %w", ErrInvalid)
	}
	if !observationPlatformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.file == nil {
		return nil, fmt.Errorf("closed observation root: %w", ErrInvalid)
	}
	f, err := observationOpenDirectory(r.file, ".")
	if err != nil {
		return nil, capabilityError("duplicate observation capability", err)
	}
	identity, identityErr := observationStableIdentity(f)
	if identityErr != nil || !identity.sameBinding(r.identity) {
		_ = f.Close()
		return nil, fmt.Errorf("observation capability identity changed: %w", ErrIntegrity)
	}
	return f, nil
}

func (r *Root) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("nil import context: %w", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrCancelled, err)
	}
	return nil
}

func ImportAt(ctx context.Context, parent *os.File, leaf string, options ImportOptions) (CurrentBundle, error) {
	root, err := OpenAt(parent, leaf)
	if err != nil {
		return CurrentBundle{}, err
	}
	defer root.Close()
	return Import(ctx, root, options)
}
