// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/validation"
)

// PermissionPolicy says which file modes Open accepts.
type PermissionPolicy int

const (
	// Strict refuses a file that is readable or writable by group or other:
	// the mode must satisfy perm&0o077 == 0, so 0600 and 0400 are accepted.
	Strict PermissionPolicy = iota
	// RefuseWritable refuses a file that is writable by group or other. A file
	// readable by group or other is accepted and counted in a notice.
	RefuseWritable
)

// Default bounds. A zero Limits field selects the default.
const (
	DefaultFileBytes  int64 = 8 << 20
	DefaultTotalBytes int64 = 32 << 20
	DefaultFiles            = 2048
	DefaultDocuments        = 8192
	DefaultNodes            = 2000000
)

// Limits bounds one Open call. The nesting depth limit is MaxDepth.
type Limits struct {
	FileBytes  int64 // bytes per file or stdin
	TotalBytes int64 // bytes over all files
	Files      int
	Documents  int // YAML documents over all files
	Nodes      int // YAML nodes over all files
}

func (l Limits) withDefaults() Limits {
	if l.FileBytes <= 0 {
		l.FileBytes = DefaultFileBytes
	}
	if l.TotalBytes <= 0 {
		l.TotalBytes = DefaultTotalBytes
	}
	if l.Files <= 0 {
		l.Files = DefaultFiles
	}
	if l.Documents <= 0 {
		l.Documents = DefaultDocuments
	}
	if l.Nodes <= 0 {
		l.Nodes = DefaultNodes
	}
	return l
}

// Options configures Open.
type Options struct {
	Permissions PermissionPolicy
	Limits      Limits
	// Stdin is read for the path "-"; nil means os.Stdin.
	Stdin io.Reader
}

// Errors returned by Open. Use errors.Is.
var (
	// ErrLimit wraps every exceeded bound; the message names the bound.
	ErrLimit = errors.New("input limit exceeded")
	// ErrPermissions reports a file whose mode the policy refuses.
	ErrPermissions = errors.New("input file permissions are refused")
	// ErrInput reports a path that cannot be read as input.
	ErrInput = errors.New("input cannot be read")
)

// ModeResult records how the permission policy treated one file.
type ModeResult string

const (
	// ModePrivate: no group or other access.
	ModePrivate ModeResult = "private"
	// ModeReadableByOthers: group or other can read; accepted by RefuseWritable.
	ModeReadableByOthers ModeResult = "readable-by-others"
	// ModeNotApplicable: stdin has no file mode.
	ModeNotApplicable ModeResult = "not-applicable"
)

// FileRecord describes one input file.
type FileRecord struct {
	Display string
	Digest  string // sha256 of the raw bytes
	Size    int64
	Mode    os.FileMode // permission bits; zero for stdin
	Policy  ModeResult
}

type opener struct {
	opts   Options
	limits Limits
	nodes  int
	docs   int
	total  int64
	seen   map[string]bool
	out    Workspace
}

// Open reads files, directories and stdin ("-") into one Workspace.
//
// A directory is walked recursively in lexical order. Only regular files named
// *.yaml, *.yml or *.json are read; hidden directories are skipped and
// symlinks are never followed. Every component is opened through directory
// descriptors, so replacing a path with a symlink while the walk runs cannot
// lead outside the directory. A file named directly is read whatever its
// extension, but it must still be a regular file and not a symlink.
//
// Documents are ordered by file display path, then document and item index.
func Open(paths []string, opts Options) (Workspace, error) {
	if len(paths) == 0 {
		return Workspace{}, fmt.Errorf("%w: no input paths", ErrInput)
	}
	o := &opener{opts: opts, limits: opts.Limits.withDefaults(), seen: map[string]bool{}}
	o.nodes = o.limits.Nodes
	for _, path := range paths {
		if err := o.openPath(path); err != nil {
			return Workspace{}, err
		}
	}
	return o.finish(), nil
}

func (o *opener) openPath(path string) error {
	if path == "-" {
		if o.seen["-"] {
			return nil
		}
		reader := o.opts.Stdin
		if reader == nil {
			reader = os.Stdin
		}
		return o.consume("-", reader, -1, 0, ModeNotApplicable)
	}
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("%w: empty or invalid path", ErrInput)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInput, path)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%w: %s is a symlink, which is not followed", ErrInput, path)
	case info.IsDir():
		dir, err := validation.OpenInputDirectory(path)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrInput, path)
		}
		defer dir.Close()
		return o.walk(dir, filepath.Clean(path))
	default:
		file, err := validation.OpenInputRegularFile(path)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrInput, path)
		}
		defer file.Close()
		return o.readFile(file, filepath.Clean(path))
	}
}

func (o *opener) walk(dir *os.File, display string) error {
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInput, display)
	}
	sort.Strings(names)
	for _, name := range names {
		child := filepath.Join(display, name)
		if sub, err := validation.OpenEntryDirectory(dir, name); err == nil {
			// Hidden directories (.git, .terraform) are skipped.
			if !strings.HasPrefix(name, ".") {
				err = o.walk(sub, child)
			}
			_ = sub.Close()
			if err != nil {
				return err
			}
			continue
		}
		if !isManifestName(name) {
			continue
		}
		file, err := validation.OpenEntryFile(dir, name)
		if err != nil {
			// A symlink, or an entry replaced since it was listed.
			continue
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			continue
		}
		err = o.readFile(file, child)
		_ = file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func isManifestName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return false
}

func (o *opener) readFile(file *os.File, display string) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInput, display)
	}
	if o.seen[display] {
		return nil
	}
	perm := info.Mode().Perm()
	result := ModePrivate
	switch o.opts.Permissions {
	case RefuseWritable:
		if perm&0o022 != 0 {
			return fmt.Errorf("%w: %s is writable by group or other (mode %04o)", ErrPermissions, display, perm)
		}
	default:
		if perm&0o077 != 0 {
			return fmt.Errorf("%w: %s is accessible by group or other (mode %04o)", ErrPermissions, display, perm)
		}
	}
	if perm&0o044 != 0 {
		result = ModeReadableByOthers
	}
	return o.consume(display, file, info.Size(), perm, result)
}

// consume reads at most FileBytes from reader and decodes it. size is the
// size reported by the filesystem, or -1 when unknown.
func (o *opener) consume(display string, reader io.Reader, size int64, perm os.FileMode, result ModeResult) error {
	if len(o.out.Files) >= o.limits.Files {
		return limitError("files", int64(o.limits.Files))
	}
	if size > o.limits.FileBytes {
		return limitError("bytes per file", o.limits.FileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(reader, o.limits.FileBytes+1))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInput, display)
	}
	if int64(len(raw)) > o.limits.FileBytes {
		return limitError("bytes per file", o.limits.FileBytes)
	}
	o.total += int64(len(raw))
	if o.total > o.limits.TotalBytes {
		return limitError("bytes total", o.limits.TotalBytes)
	}
	o.seen[display] = true
	sum := sha256.Sum256(raw)
	record := FileRecord{Display: display, Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(raw)), Mode: perm, Policy: result}
	o.out.Files = append(o.out.Files, record)
	if len(raw) == 0 {
		return nil
	}
	remaining := o.limits.Documents - o.docs
	if remaining <= 0 {
		remaining = -1 // no document may be added
	}
	nodes := o.nodes
	decoded, err := decodeFile(display, raw, decodeOptions{maxDocuments: remaining, nodes: &nodes})
	if err != nil {
		var reached limitReached
		if errors.As(err, &reached) {
			switch reached.limit {
			case "documents":
				return limitError("documents", int64(o.limits.Documents))
			default:
				return limitError("YAML nodes", int64(o.limits.Nodes))
			}
		}
		return fmt.Errorf("%w: %s", ErrDecode, display)
	}
	o.nodes = nodes
	fileDocs := 0
	for _, document := range decoded.Documents {
		if document.Source.Document+1 > fileDocs {
			fileDocs = document.Source.Document + 1
		}
	}
	for _, omission := range decoded.Omissions {
		if omission.Source.Document+1 > fileDocs {
			fileDocs = omission.Source.Document + 1
		}
	}
	o.docs += fileDocs
	o.out.Documents = append(o.out.Documents, decoded.Documents...)
	o.out.Omissions = append(o.out.Omissions, decoded.Omissions...)
	return nil
}

func limitError(name string, bound int64) error {
	return fmt.Errorf("%w: more than %d %s", ErrLimit, bound, name)
}

func (o *opener) finish() Workspace {
	w := o.out
	sort.SliceStable(w.Files, func(i, j int) bool { return w.Files[i].Display < w.Files[j].Display })
	sort.SliceStable(w.Documents, func(i, j int) bool { return sourceLess(w.Documents[i].Source, w.Documents[j].Source) })
	sort.SliceStable(w.Omissions, func(i, j int) bool { return sourceLess(w.Omissions[i].Source, w.Omissions[j].Source) })
	digest := sha256.New()
	readable := 0
	digests := make([]string, 0, len(w.Files))
	for _, file := range w.Files {
		digests = append(digests, file.Digest)
		if file.Policy == ModeReadableByOthers {
			readable++
		}
	}
	sort.Strings(digests)
	for _, d := range digests {
		digest.Write([]byte(d + "\n"))
	}
	w.Digest = "sha256:" + hex.EncodeToString(digest.Sum(nil))
	if readable > 0 {
		noun := "files are"
		if readable == 1 {
			noun = "file is"
		}
		w.Notices = append(w.Notices, fmt.Sprintf("note: %d input %s readable by other users; use --input-permissions strict to refuse them", readable, noun))
	}
	return w
}

func sourceLess(a, b Source) bool {
	if a.Display != b.Display {
		return a.Display < b.Display
	}
	if a.Document != b.Document {
		return a.Document < b.Document
	}
	return a.Item < b.Item
}
