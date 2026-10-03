// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

type skey struct {
	display string
	doc     int
	item    int
}

func keyOf(s intake.Source) skey { return skey{s.Display, s.Document, s.Item} }

// docRef is one decoded document placed in the repository tree.
type docRef struct {
	doc intake.Document
	rel string // file path relative to the root, with slashes
	dir string // directory of the file, "." for the root
	aux bool
	key skey
}

func (d *docRef) group() string { return groupOf(d.doc.APIVersion) }

// analysis holds everything derived from the workspace once.
type analysis struct {
	opts    Options
	root    string
	self    map[string]bool
	docs    []*docRef
	byDir   map[string][]*docRef
	files   map[string]bool
	dirs    map[string]bool
	subdirs map[string][]string
	// enc lists SOPS-encrypted files, by file and by directory. Only the
	// source of the first encrypted document is kept, never its value.
	enc       map[string]intake.Source
	encByDir  map[string][]string
	omitByDir map[string][]intake.Omission
	symlinks  map[string]bool
	kust      map[string]*docRef
	kustMulti map[string]intake.Source
	sources   map[string][]*docRef
	repoGaps  []Gap
	steps     int
	exhausted bool
}

var kustomizationNames = map[string]bool{"kustomization.yaml": true, "kustomization.yml": true, "Kustomization": true}

func newAnalysis(ws intake.Workspace, opts Options) *analysis {
	a := &analysis{
		opts: opts, self: map[string]bool{},
		byDir: map[string][]*docRef{}, files: map[string]bool{}, dirs: map[string]bool{".": true},
		subdirs: map[string][]string{}, enc: map[string]intake.Source{}, encByDir: map[string][]string{},
		omitByDir: map[string][]intake.Omission{}, symlinks: map[string]bool{}, kust: map[string]*docRef{},
		kustMulti: map[string]intake.Source{}, sources: map[string][]*docRef{},
	}
	for _, u := range opts.SelfRepoURLs {
		a.self[normalizeURL(u)] = true
	}
	a.root = opts.Root
	if a.root == "" {
		a.root = commonDir(ws)
	}
	a.root = filepath.Clean(a.root)
	var outside = map[string]intake.Source{}
	note := func(display string) (string, bool) {
		rel, ok := a.rel(display)
		if !ok {
			outside[display] = intake.Source{Display: display, Item: -1}
			return "", false
		}
		return rel, true
	}
	for _, f := range ws.Files {
		if rel, ok := note(f.Display); ok {
			a.addFile(rel)
		}
	}
	add := func(d intake.Document, aux bool) {
		rel, ok := note(d.Source.Display)
		if !ok {
			return
		}
		a.addFile(rel)
		if isEncrypted(d.Value) {
			if _, done := a.enc[rel]; !done {
				a.enc[rel] = d.Source
				dir := path.Dir(rel)
				a.encByDir[dir] = append(a.encByDir[dir], rel)
			}
			return
		}
		ref := &docRef{doc: d, rel: rel, dir: path.Dir(rel), aux: aux, key: keyOf(d.Source)}
		a.docs = append(a.docs, ref)
		a.byDir[ref.dir] = append(a.byDir[ref.dir], ref)
	}
	for _, d := range ws.Documents {
		add(d, false)
	}
	for _, d := range ws.Auxiliary {
		add(d, true)
	}
	for _, o := range ws.Omissions {
		rel, ok := note(o.Source.Display)
		if !ok {
			continue
		}
		switch o.Reason {
		case intake.ReasonSymlinkNotFollowed:
			a.symlinks[rel] = true
		case intake.ReasonTemplated, intake.ReasonUnparseable:
			a.addFile(rel)
			dir := path.Dir(rel)
			a.omitByDir[dir] = append(a.omitByDir[dir], o)
		}
	}
	sort.SliceStable(a.docs, func(i, j int) bool { return srcLess(a.docs[i].doc.Source, a.docs[j].doc.Source) })
	for dir := range a.encByDir {
		sort.Strings(a.encByDir[dir])
	}
	for dir := range a.dirs {
		if dir != "." {
			parent := path.Dir(dir)
			a.subdirs[parent] = append(a.subdirs[parent], dir)
		}
	}
	for dir := range a.subdirs {
		sort.Strings(a.subdirs[dir])
	}
	for _, d := range a.docs {
		base := path.Base(d.rel)
		if kustomizationNames[base] && (d.aux || d.group() == "kustomize.config.k8s.io") {
			if prev, dup := a.kust[d.dir]; dup {
				a.kustMulti[d.dir] = prev.doc.Source
				continue
			}
			a.kust[d.dir] = d
		}
		if d.group() == "source.toolkit.fluxcd.io" {
			k := sourceKey(d.doc.Kind, d.doc.Namespace, d.doc.Name)
			a.sources[k] = append(a.sources[k], d)
		}
	}
	names := make([]string, 0, len(outside))
	for n := range outside {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a.repoGaps = append(a.repoGaps, Gap{SourceNotFound, outside[n], "file is outside the repository root"})
	}
	return a
}

func (a *analysis) addFile(rel string) {
	a.files[rel] = true
	for dir := path.Dir(rel); !a.dirs[dir]; dir = path.Dir(dir) {
		a.dirs[dir] = true
	}
}

func sourceKey(kind, ns, name string) string { return kind + "/" + ns + "/" + name }

// rel returns the slash path of display relative to the root.
func (a *analysis) rel(display string) (string, bool) {
	r, err := filepath.Rel(a.root, filepath.Clean(display))
	if err != nil {
		return "", false
	}
	r = filepath.ToSlash(r)
	if r == ".." || strings.HasPrefix(r, "../") || r == "." {
		return "", false
	}
	return r, true
}

// commonDir is the deepest directory holding every file of the workspace.
func commonDir(ws intake.Workspace) string {
	var parts []string
	first := true
	consider := func(display string) {
		dir := strings.Split(filepath.ToSlash(filepath.Dir(filepath.Clean(display))), "/")
		if first {
			parts, first = dir, false
			return
		}
		n := 0
		for n < len(parts) && n < len(dir) && parts[n] == dir[n] {
			n++
		}
		parts = parts[:n]
	}
	for _, f := range ws.Files {
		consider(f.Display)
	}
	for _, d := range ws.Documents {
		consider(d.Source.Display)
	}
	for _, d := range ws.Auxiliary {
		consider(d.Source.Display)
	}
	if first || len(parts) == 0 {
		return "."
	}
	joined := strings.Join(parts, "/")
	if joined == "" {
		return "/"
	}
	return filepath.FromSlash(joined)
}

var hostLike = regexp.MustCompile(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+/`)

// resolve turns a reference found in a file of directory base into a path
// inside the root. The second result is empty on success; otherwise it is the
// gap reason and the third result its detail.
func (a *analysis) resolve(base, ref string) (string, string, string) {
	switch {
	case ref == "" || strings.ContainsAny(ref, "\x00\\"):
		return "", SourceNotFound, "empty or invalid path"
	case strings.Contains(ref, "://") || strings.HasPrefix(ref, "git@") || strings.HasPrefix(ref, "/") || filepath.IsAbs(ref):
		return "", RemoteReferenceNotResolved, "remote or absolute reference " + clip(ref)
	}
	joined := path.Clean(path.Join(base, ref))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return "", RemoteReferenceNotResolved, "path leaves the repository " + clip(ref)
	}
	if !a.files[joined] && !a.dirs[joined] && hostLike.MatchString(ref) {
		return "", RemoteReferenceNotResolved, "remote reference " + clip(ref)
	}
	return joined, "", ""
}

// missing explains why a resolved path has no files.
func (a *analysis) missing(p string) string {
	for q := p; q != "." && q != "/"; q = path.Dir(q) {
		if a.symlinks[q] {
			return "symlink is not followed: " + clip(q)
		}
	}
	return "no input file under " + clip(p)
}

// normalizeURL applies the only normalisation allowed for repository URLs:
// lower-case host, no trailing ".git" and "/".
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	var out string
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return strings.ToLower(raw)
		}
		out = u.Scheme + "://"
		if u.User != nil {
			out += u.User.String() + "@"
		}
		out += strings.ToLower(u.Host) + u.EscapedPath()
	} else if i := strings.IndexAny(raw, ":/"); i > 0 {
		out = strings.ToLower(raw[:i]) + raw[i:]
	} else {
		out = strings.ToLower(raw)
	}
	out = strings.TrimRight(out, "/")
	out = strings.TrimSuffix(out, ".git")
	return strings.TrimRight(out, "/")
}

func (a *analysis) isSelf(raw string) bool {
	return len(a.self) > 0 && a.self[normalizeURL(raw)]
}

// isEncrypted reports a SOPS document: the metadata block SOPS adds, or any
// string in SOPS ciphertext form. The content is never read further.
func isEncrypted(v map[string]any) bool {
	if m, ok := v["sops"].(map[string]any); ok {
		if _, mac := m["mac"]; mac {
			return true
		}
		if _, ver := m["version"]; ver {
			return true
		}
		if _, lm := m["lastmodified"]; lm {
			return true
		}
	}
	return hasCiphertext(v, 0)
}

func hasCiphertext(v any, depth int) bool {
	if depth > intake.MaxDepth+2 {
		return false
	}
	switch t := v.(type) {
	case string:
		return strings.HasPrefix(t, "ENC[")
	case map[string]any:
		for _, c := range t {
			if hasCiphertext(c, depth+1) {
				return true
			}
		}
	case []any:
		for _, c := range t {
			if hasCiphertext(c, depth+1) {
				return true
			}
		}
	}
	return false
}
