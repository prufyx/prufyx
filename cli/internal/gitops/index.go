// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
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

// docKind says how a walk treats a document.
type docKind int

const (
	kindOther docKind = iota
	kindKustomization
	kindFlux
	kindArgo
	kindAppSet
	kindHelmRelease
	kindSource
	kindWorkload
	kindChart
)

// docRef is one decoded document placed in the repository tree. The parsed
// fields are filled the first time a walk needs them and never change after,
// so every environment shares one parse.
type docRef struct {
	doc  intake.Document
	rel  string // file path relative to the root, with slashes
	dir  string // directory of the file, "." for the root
	aux  bool
	key  skey
	id   int // index in analysis.docs
	kind docKind

	kustP  *kustSpec
	fluxP  *fluxSpec
	argoP  *argoSpec
	hrP    *hrSpec
	imgP   *imageSpec
	chartP *chartSpec
}

func (d *docRef) group() string { return groupOf(d.doc.APIVersion) }

// analysis holds everything derived from the workspace once.
type analysis struct {
	opts      Options
	root      string
	self      map[string]bool
	revisions map[string]bool
	docs      []*docRef
	byDir     map[string][]*docRef
	byFile    map[string][]*docRef
	candDir   map[string][]*docRef // Flux Kustomizations and Argo CD Applications only
	candFile  map[string][]*docRef
	files     map[string]bool
	dirs      map[string]bool
	subdirs   map[string][]string
	// enc lists SOPS-encrypted files, by file and by directory. Only the
	// source of the first encrypted document is kept, never its value.
	enc        map[string]intake.Source
	encByDir   map[string][]string
	omitByDir  map[string][]intake.Omission
	omitByFile map[string][]intake.Omission
	links      *linkTrie // symlinks intake did not follow, by path component
	kust       map[string]*docRef
	kustMulti  map[string]intake.Source
	kustFiles  map[string][]string // kustomization file names present in a directory
	chartDocs  map[string][]*docRef
	chartExtra map[string]bool // a chart directory holds more than Chart.yaml and values.yaml
	sources    map[string][]*docRef
	repoGaps   []Gap
	nodes      int // inline value and patch nodes still allowed
	disc, work *budget
}

var kustomizationNames = map[string]bool{"kustomization.yaml": true, "kustomization.yml": true, "Kustomization": true}

func newAnalysis(ws intake.Workspace, opts Options) *analysis {
	a := &analysis{
		opts: opts, self: map[string]bool{}, revisions: map[string]bool{},
		byDir: map[string][]*docRef{}, byFile: map[string][]*docRef{}, candDir: map[string][]*docRef{}, candFile: map[string][]*docRef{},
		files: map[string]bool{}, dirs: map[string]bool{".": true},
		subdirs: map[string][]string{}, enc: map[string]intake.Source{}, encByDir: map[string][]string{},
		omitByDir: map[string][]intake.Omission{}, omitByFile: map[string][]intake.Omission{}, links: &linkTrie{},
		kust: map[string]*docRef{}, kustMulti: map[string]intake.Source{}, kustFiles: map[string][]string{},
		chartDocs: map[string][]*docRef{}, chartExtra: map[string]bool{}, sources: map[string][]*docRef{},
		nodes: valuesNodeBudget,
	}
	for _, u := range opts.SelfRepoURLs {
		if n, ok := normalizeURL(u); ok {
			a.self[n] = true
		}
	}
	for _, r := range opts.SelfRevisions {
		a.revisions[r] = true
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
	encrypted := func(rel string, src intake.Source) {
		a.addFile(rel)
		if _, done := a.enc[rel]; !done {
			a.enc[rel] = src
			dir := path.Dir(rel)
			a.encByDir[dir] = append(a.encByDir[dir], rel)
		}
	}
	add := func(d intake.Document, aux bool) {
		rel, ok := note(d.Source.Display)
		if !ok {
			return
		}
		a.addFile(rel)
		if isEncrypted(d.Value) {
			encrypted(rel, d.Source)
			return
		}
		a.docs = append(a.docs, &docRef{doc: d, rel: rel, dir: path.Dir(rel), aux: aux, key: keyOf(d.Source)})
	}
	for _, d := range ws.Documents {
		add(d, false)
	}
	for _, d := range ws.Auxiliary {
		add(d, true)
	}
	for _, s := range ws.Encrypted {
		if rel, ok := note(s.Display); ok {
			encrypted(rel, s)
		}
	}
	for _, o := range ws.Omissions {
		rel, ok := note(o.Source.Display)
		if !ok {
			continue
		}
		switch o.Reason {
		case intake.ReasonSymlinkNotFollowed:
			a.links.add(rel)
		case intake.ReasonTemplated, intake.ReasonUnparseable:
			a.addFile(rel)
			dir := path.Dir(rel)
			a.omitByDir[dir] = append(a.omitByDir[dir], o)
			a.omitByFile[rel] = append(a.omitByFile[rel], o)
		}
	}
	// A file can hold both encrypted and plain documents; the plain ones of
	// an encrypted file are not used either.
	kept := a.docs[:0]
	for _, d := range a.docs {
		if _, enc := a.enc[d.rel]; !enc {
			kept = append(kept, d)
		}
	}
	a.docs = kept
	sort.SliceStable(a.docs, func(i, j int) bool { return srcLess(a.docs[i].doc.Source, a.docs[j].doc.Source) })
	for dir := range a.encByDir {
		sort.Strings(a.encByDir[dir])
	}
	for _, list := range []map[string][]intake.Omission{a.omitByDir, a.omitByFile} {
		for k := range list {
			l := list[k]
			sort.SliceStable(l, func(i, j int) bool { return srcLess(l[i].Source, l[j].Source) })
		}
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
	for f := range a.files {
		dir, base := path.Dir(f), path.Base(f)
		switch {
		case kustomizationNames[base]:
			a.kustFiles[dir] = append(a.kustFiles[dir], base)
		case base == "Chart.yaml":
			a.chartDocs[dir] = a.chartDocs[dir] // marks a chart directory
		}
	}
	for dir := range a.kustFiles {
		sort.Strings(a.kustFiles[dir])
	}
	for dir := range a.chartDocs {
		if len(a.subdirs[dir]) > 0 {
			a.chartExtra[dir] = true
		}
	}
	for f := range a.files {
		dir, base := path.Dir(f), path.Base(f)
		if _, chart := a.chartDocs[dir]; chart && base != "Chart.yaml" && base != "values.yaml" {
			a.chartExtra[dir] = true
		}
	}
	for i, d := range a.docs {
		d.id = i
		d.kind = classify(d)
		a.byDir[d.dir] = append(a.byDir[d.dir], d)
		a.byFile[d.rel] = append(a.byFile[d.rel], d)
		switch d.kind {
		case kindKustomization:
			if prev, dup := a.kust[d.dir]; dup {
				if _, seen := a.kustMulti[d.dir]; !seen {
					a.kustMulti[d.dir] = prev.doc.Source
				}
				continue
			}
			a.kust[d.dir] = d
		case kindFlux, kindArgo:
			a.candDir[d.dir] = append(a.candDir[d.dir], d)
			a.candFile[d.rel] = append(a.candFile[d.rel], d)
		case kindSource:
			k := sourceKey(d.doc.Kind, d.doc.Namespace, d.doc.Name)
			a.sources[k] = append(a.sources[k], d)
		case kindChart:
			a.chartDocs[d.dir] = append(a.chartDocs[d.dir], d)
		}
	}
	// Two files with kustomization names in one directory: the first one by
	// name is used, the directory is reported.
	for dir, names := range a.kustFiles {
		if len(names) > 1 {
			if _, seen := a.kustMulti[dir]; !seen {
				src := intake.Source{Display: path.Join(dir, names[1]), Item: -1}
				if k := a.kust[dir]; k != nil {
					src = k.doc.Source
				}
				a.kustMulti[dir] = src
			}
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

// classify decides once how a document is treated. A document from a file
// named Chart.yaml is a chart whatever its shape.
func classify(d *docRef) docKind {
	base := path.Base(d.rel)
	g := d.group()
	switch {
	case base == "Chart.yaml":
		return kindChart
	case kustomizationNames[base] && (d.aux || g == "kustomize.config.k8s.io"):
		return kindKustomization
	case d.aux:
		return kindOther
	case d.doc.Kind == "Kustomization" && g == "kustomize.toolkit.fluxcd.io":
		return kindFlux
	case d.doc.Kind == "Application" && g == "argoproj.io":
		return kindArgo
	case d.doc.Kind == "ApplicationSet" && g == "argoproj.io":
		return kindAppSet
	case d.doc.Kind == KindHelmRelease && g == "helm.toolkit.fluxcd.io":
		return kindHelmRelease
	case g == "source.toolkit.fluxcd.io":
		return kindSource
	}
	switch d.doc.Kind {
	case "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController", "CronJob":
		return kindWorkload
	}
	return kindOther
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

// target is a reference resolved once. Reason is empty on success.
type target struct {
	path           string
	reason, detail string
}

// resolve turns a reference found in a file of directory base into a path
// inside the root. On failure the target carries the gap reason and detail.
func (a *analysis) resolve(base, ref string) target {
	switch {
	case ref == "" || strings.ContainsAny(ref, "\x00\\"):
		return target{reason: SourceNotFound, detail: "empty or invalid path " + clip(ref)}
	case len(ref) > MaxRefBytes:
		return target{reason: SourceNotFound, detail: "path longer than 4096 bytes"}
	case strings.Contains(ref, "://") || strings.HasPrefix(ref, "git@") || strings.HasPrefix(ref, "/") || filepath.IsAbs(ref):
		return target{reason: RemoteReferenceNotResolved, detail: "remote or absolute reference " + clip(ref)}
	}
	joined := path.Clean(path.Join(base, ref))
	if joined == ".." || strings.HasPrefix(joined, "../") {
		return target{reason: RemoteReferenceNotResolved, detail: "path leaves the repository " + clip(ref)}
	}
	if !a.files[joined] && !a.dirs[joined] {
		if hostLike.MatchString(ref) {
			return target{reason: RemoteReferenceNotResolved, detail: "remote reference " + clip(ref)}
		}
		return target{path: joined, reason: SourceNotFound, detail: a.missing(joined)}
	}
	return target{path: joined}
}

// linkTrie holds symlink paths by component, so that finding a symlink
// among the parents of a path costs one pass over the path.
type linkTrie struct {
	kids map[string]*linkTrie
	link bool
}

func (t *linkTrie) add(p string) {
	for _, c := range strings.Split(p, "/") {
		if t.kids == nil {
			t.kids = map[string]*linkTrie{}
		}
		next := t.kids[c]
		if next == nil {
			next = &linkTrie{}
			t.kids[c] = next
		}
		t = next
	}
	t.link = true
}

// under returns the symlink that p is or lies under, or "".
func (t *linkTrie) under(p string) string {
	for end := 0; t != nil; {
		next := strings.IndexByte(p[end:], '/')
		stop := len(p)
		if next >= 0 {
			stop = end + next
		}
		if t = t.kids[p[end:stop]]; t != nil && t.link {
			return p[:stop]
		}
		if next < 0 {
			return ""
		}
		end = stop + 1
	}
	return ""
}

// missing explains why a resolved path has no files.
func (a *analysis) missing(p string) string {
	if q := a.links.under(p); q != "" {
		return "symlink is not followed: " + clip(q)
	}
	return "no input file under " + clip(p)
}

// resolveCost is the work of resolving ref: one step per 64 bytes.
func resolveCost(ref string) int { return 1 + len(ref)/64 }

// normalizeURL applies the only normalisation allowed for repository URLs:
// the host is lower-cased, then one trailing "/" and one trailing ".git" are
// removed. A URL with a query, a fragment, white space or a control
// character is refused (second result false) and never matches.
func normalizeURL(raw string) (string, bool) {
	if raw == "" || strings.ContainsAny(raw, "?# \t\r\n") || needsEscape(raw) {
		return "", false
	}
	out := raw
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		authority := rest[:end]
		at := strings.LastIndexByte(authority, '@') + 1
		out = raw[:i+3] + authority[:at] + strings.ToLower(authority[at:]) + rest[end:]
	} else if colon := strings.IndexByte(raw, ':'); colon > 0 && !strings.Contains(raw[:colon], "/") {
		userHost := raw[:colon]
		at := strings.LastIndexByte(userHost, '@') + 1
		out = userHost[:at] + strings.ToLower(userHost[at:]) + raw[colon:]
	}
	out = strings.TrimSuffix(out, "/")
	out = strings.TrimSuffix(out, ".git")
	return out, out != ""
}

func (a *analysis) isSelf(raw string) bool {
	n, ok := normalizeURL(raw)
	return ok && a.self[n]
}

// isEncrypted reports a SOPS document: the metadata block SOPS adds, or any
// string in SOPS ciphertext form. The content is never read further.
func isEncrypted(v map[string]any) bool {
	if intake.HasSOPSMetadata(v) {
		return true
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
