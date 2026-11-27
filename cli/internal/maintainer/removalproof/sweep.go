// SPDX-License-Identifier: AGPL-3.0-only

package removalproof

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	goscanner "go/scanner"
	"go/token"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// limits bound the sweep. A limit that is hit refuses; nothing is truncated
// into a pass. A unit is the tree of one release or one module. Raising any of
// these is a reviewed change.
type limits struct {
	dirs, depth, files, fileBytes int
	unitBytes, totalBytes         int
	zipBytes, zipContent          int
}

func defaultLimits() limits {
	return limits{dirs: 16384, depth: 24, files: 60000, fileBytes: 2 << 20,
		unitBytes: 64 << 20, totalBytes: 512 << 20, zipBytes: 512 << 20, zipContent: 1 << 30}
}

// ModuleSource supplies the zip of a module version. Its bytes are untrusted:
// they are used only after their hash equals the go.sum entry.
type ModuleSource interface {
	Zip(modulePath, version string, max int) ([]byte, error)
}

// ModuleCache reads zips from the download directory of a Go module cache
// (GOMODCACHE/cache/download).
type ModuleCache struct{ Dir string }

// escapeModule is the module cache spelling of a path or version: an upper
// case letter is written as "!" and the lower case letter.
func escapeModule(s string) (string, error) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '!' || r == '\\' || r > unicode.MaxASCII || r <= ' ':
			return "", errors.New("bad character in module path")
		case unicode.IsUpper(r):
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" || out != path.Clean(out) || strings.HasPrefix(out, "/") || out == ".." || strings.HasPrefix(out, "../") {
		return "", errors.New("bad module path")
	}
	return out, nil
}

// Zip implements ModuleSource.
func (c ModuleCache) Zip(modulePath, version string, max int) ([]byte, error) {
	p, err := escapeModule(modulePath)
	if err != nil {
		return nil, err
	}
	v, err := escapeModule(version)
	if err != nil || strings.Contains(v, "/") {
		return nil, errors.New("bad module version")
	}
	f, err := os.Open(filepath.Join(c.Dir, filepath.FromSlash(p), "@v", v+".zip"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, errors.New("module zip over the size limit")
	}
	return data, nil
}

type modulePackage struct {
	imports []string
	broken  bool
}

type moduleInfo struct {
	prob     *problem
	packages map[string]*modulePackage
	// digests are the SHA-256 of every file of the verified zip.
	digests map[string][32]byte
	// hits are the names the module spells, with the first file.
	hits  map[string]string
	why   string
	bytes int
}

type sweeper struct {
	src     ModuleSource
	want    map[string][]string
	lim     limits
	modules map[string]*moduleInfo // by module, version and expected hash
}

func newSweeper(src ModuleSource, names []string, lim limits) *sweeper {
	want := map[string][]string{}
	for _, n := range names {
		want[norm(n)] = append(want[norm(n)], n)
	}
	return &sweeper{src: src, want: want, lim: lim, modules: map[string]*moduleInfo{}}
}

// module verifies and reads one module, once per run.
func (s *sweeper) module(ref moduleRef) (*moduleInfo, *problem) {
	k := ref.String() + " " + ref.sum
	info := s.modules[k]
	if info == nil {
		info = s.readModule(ref)
		s.modules[k] = info
	}
	return info, info.prob
}

func (s *sweeper) readModule(ref moduleRef) *moduleInfo {
	info := &moduleInfo{packages: map[string]*modulePackage{}, hits: map[string]string{}, digests: map[string][32]byte{}}
	fail := func(code, detail string) *moduleInfo {
		info.prob = &problem{code, ref.String() + detail}
		return info
	}
	data, err := s.src.Zip(ref.path, ref.version, s.lim.zipBytes)
	if err != nil {
		return fail(CodeModuleUnavailable, "")
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fail(CodeModuleUnreadable, "")
	}
	files := map[string]*zip.File{}
	names := make([]string, 0, len(zr.File))
	for _, f := range zr.File {
		if _, dup := files[f.Name]; dup || strings.Contains(f.Name, "\n") {
			return fail(CodeModuleUnreadable, ": bad entry name")
		}
		files[f.Name] = f
		names = append(names, f.Name)
	}
	sort.Strings(names)
	prefix := ref.path + "@" + ref.version + "/"
	sum := sha256.New()
	total := 0
	goFiles := 0
	for _, name := range names {
		rc, err := files[name].Open()
		if err != nil {
			return fail(CodeModuleUnreadable, "")
		}
		content, err := io.ReadAll(io.LimitReader(rc, int64(s.lim.zipContent-total)+1))
		rc.Close()
		if err != nil {
			return fail(CodeModuleUnreadable, "")
		}
		total += len(content)
		if total > s.lim.zipContent {
			return fail(CodeModuleUnreadable, ": content over the size limit")
		}
		digest := sha256.Sum256(content)
		fmt.Fprintf(sum, "%x  %s\n", digest, name)
		rel, ok := strings.CutPrefix(name, prefix)
		if !ok || rel != path.Clean(rel) || strings.HasPrefix(rel, "..") {
			return fail(CodeModuleUnreadable, ": entry outside the module")
		}
		info.digests[rel] = digest
		base := path.Base(rel)
		if !strings.HasSuffix(base, ".go") || strings.HasSuffix(base, "_test.go") {
			continue
		}
		goFiles++
		if info.why == "" {
			info.bytes += len(content)
			switch {
			case goFiles > s.lim.files:
				info.why = "more Go files than the limit"
			case len(content) > s.lim.fileBytes:
				info.why = "a Go file over the size limit: " + rel
			case info.bytes > s.lim.unitBytes:
				info.why = "more bytes than the limit"
			case !s.literals(rel, content, info.hits):
				info.why = "a Go file could not be tokenised: " + rel
			}
		}
		if !goFileName(base) {
			continue
		}
		dir := rootDir(path.Dir(rel))
		imports, ignored, perr := importsOf(rel, content)
		if ignored {
			continue
		}
		pk := info.packages[dir]
		if pk == nil {
			pk = &modulePackage{}
			info.packages[dir] = pk
		}
		if perr != nil {
			pk.broken = true
		}
		pk.imports = append(pk.imports, imports...)
	}
	// The go.sum h1 hash: SHA-256 over the sorted per-file hash lines.
	if got := "h1:" + base64.StdEncoding.EncodeToString(sum.Sum(nil)); got != ref.sum {
		info.packages, info.hits = map[string]*modulePackage{}, map[string]string{}
		return fail(CodeModuleHash, "")
	}
	return info
}

// norm folds the spellings a flag library may treat alike.
func norm(v string) string { return strings.ReplaceAll(strings.ToLower(v), "_", "-") }

func separator(r rune) bool {
	return unicode.IsSpace(r) || strings.ContainsRune(",|\"'`:;=()[]{}<>/", r)
}

// spelled returns the wanted names a string literal spells: the whole literal
// or any of its words, so that struct tags, "name, alias" lists and help text
// count, with or without dashes, a negating "no-" or closing punctuation.
func spelled(v string, want map[string][]string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(norm(v), separator) {
		w = strings.TrimLeft(strings.TrimRight(w, ".!?-"), "-")
		out = append(out, want[w]...)
		if rest, ok := strings.CutPrefix(w, "no-"); ok {
			out = append(out, want[rest]...)
		}
	}
	return out
}

// literals adds to hits the names spelled by the string literals of a file. It
// is false when the file cannot be tokenised.
func (s *sweeper) literals(name string, data []byte, hits map[string]string) bool {
	fset := token.NewFileSet()
	f := fset.AddFile(name, fset.Base(), len(data))
	var sc goscanner.Scanner
	good := true
	sc.Init(f, data, func(token.Position, string) { good = false }, 0)
	for {
		_, tok, lit := sc.Scan()
		if tok == token.EOF {
			return good
		}
		if tok != token.STRING {
			continue
		}
		v, err := strconv.Unquote(lit)
		if err != nil {
			good = false
			continue
		}
		for _, n := range spelled(v, s.want) {
			if _, seen := hits[n]; !seen {
				hits[n] = name
			}
		}
	}
}

// sweep looks for the names in every non-test Go file of the whole tree at sha
// (vendor included) and of every module given.
func (s *sweeper) sweep(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, sha string, modules []moduleRef) (map[string]string, []problem, error) {
	hits := map[string]string{}
	var problems []problem
	why := ""
	stop := func(w string) {
		if why == "" {
			why = w
		}
	}
	dirs, files, size := 0, 0, 0
	// vendored are the digests of the Go files under the root vendor tree,
	// which a vendored build compiles in place of the modules.
	vendored := map[string][32]byte{}
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		dirs++
		if depth > s.lim.depth || dirs > s.lim.dirs {
			stop("tree over the directory limit")
			return nil
		}
		entries, err := r.List(repo, sha, dir)
		if errors.Is(err, extract.ErrNotFound) {
			stop("a directory cannot be listed: " + showDir(dir))
			return nil
		}
		if err != nil {
			return fmt.Errorf("list %q: %w", dir, err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		for _, e := range entries {
			base := path.Base(e.Path)
			if e.Path != path.Clean(e.Path) || strings.HasPrefix(e.Path, "/") || strings.HasPrefix(e.Path, "..") || (dir != "" && !strings.HasPrefix(e.Path, dir+"/")) {
				stop("a listing entry is not a clean path inside its directory")
				continue
			}
			if base == "go.work" {
				problems = append(problems, problem{CodeGoWork, e.Path})
			}
			switch {
			case e.Type == "tree":
				if err := walk(e.Path, depth+1); err != nil {
					return err
				}
			case e.Type == "commit":
				stop("a submodule: " + e.Path)
			case e.Type != "blob":
				stop("an entry of unknown type: " + e.Path)
			case e.Mode == "120000" && strings.HasSuffix(e.Path, ".go"):
				stop("a Go file that is a link: " + e.Path)
			case strings.HasSuffix(e.Path, ".go") && !strings.HasSuffix(e.Path, "_test.go"):
				files++
				if files > s.lim.files || size > s.lim.unitBytes {
					stop("tree over the file or byte limit")
					continue
				}
				data, err := r.Read(repo, sha, e.Path)
				if err != nil {
					return fmt.Errorf("read %s: %w", e.Path, err)
				}
				size += len(data)
				if rel, ok := strings.CutPrefix(e.Path, "vendor/"); ok {
					vendored[rel] = sha256.Sum256(data)
				}
				switch {
				case len(data) > s.lim.fileBytes:
					stop("a Go file over the size limit: " + e.Path)
				case size > s.lim.unitBytes:
					stop("tree over the byte limit")
				case !s.literals(e.Path, data, hits):
					stop("a Go file could not be tokenised: " + e.Path)
				}
			}
		}
		return nil
	}
	if err := walk("", 0); err != nil {
		return nil, nil, err
	}
	if why != "" {
		problems = append(problems, problem{CodeSweepIncomplete, "tree: " + why})
	}
	for _, ref := range modules {
		info, prob := s.module(ref)
		if prob != nil {
			problems = append(problems, *prob)
			continue
		}
		size += info.bytes
		if info.why != "" {
			problems = append(problems, problem{CodeSweepIncomplete, ref.String() + ": " + info.why})
		}
		for n, file := range info.hits {
			if _, seen := hits[n]; !seen {
				hits[n] = ref.String() + "/" + file
			}
		}
	}
	// A vendored file of a verified module must be the module's own bytes.
	paths := make([]string, 0, len(vendored))
	for p := range vendored {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		var owner *moduleRef
		for i := range modules {
			if under(p, modules[i].as) && (owner == nil || len(modules[i].as) > len(owner.as)) {
				owner = &modules[i]
			}
		}
		if owner == nil {
			continue // no module of this binary
		}
		info, prob := s.module(*owner)
		if prob != nil {
			continue // already refused above
		}
		if d, ok := info.digests[strings.TrimPrefix(p, owner.as+"/")]; !ok || d != vendored[p] {
			problems = append(problems, problem{CodeVendorMismatch, "vendor/" + p})
		}
	}
	if size > s.lim.totalBytes {
		problems = append(problems, problem{CodeSweepIncomplete, "tree and modules over the total byte limit"})
	}
	return hits, problems, nil
}
