// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"path"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// budget is a work budget shared by the walks of one pass.
type budget struct {
	used, limit int
	out         bool
}

// relEntry is a release collected by a walk. It points at the shared parse
// and holds only what differs per environment; finish turns it into a
// Release.
type relEntry struct {
	base    *Release
	hr      *docRef // the HelmRelease document; nil for other kinds
	ns      string  // namespace of the object after transformers
	version string  // chart version after patches
	vals    int     // bytes of the inline values text
	owner   int     // the object that collected the release
}

// visitKey is a directory or document read under one namespace scope: a
// base reached again under another namespace is deployed again, so it is
// read again.
type visitKey struct {
	dir     string
	recurse bool
	ns      string
}

type handleKey struct {
	id int
	ns string
}

// walker is the closure of one root object. In discover mode it only follows
// references to find which roots lie inside other roots: it reads no release,
// image or value and reports no gap.
type walker struct {
	a         *analysis
	b         *budget
	discover  bool
	root      *docRef
	own       string
	at        string // what is being read, for the work-limit gap
	charged   bool
	dirStack  map[string]bool // true: entered through a reference
	visited   map[visitKey]bool
	doneFiles map[visitKey]bool
	handled   map[handleKey]bool
	objStack  map[int]bool
	seen      []bool // by document id
	reached   map[int]bool
	entries   []relEntry
	rels      []Release
	imgs      []ImagePin
	gaps      []Gap
	srcs      map[string][]*docRef
	owner     int
	nextOwner int
	scopeNS   string // namespace set by the nearest enclosing transformer
	relFull   bool
	imgFull   bool
	gapFull   bool
	stopped   bool
}

func newWalker(a *analysis, root *docRef, b *budget, discover bool) *walker {
	return &walker{a: a, b: b, discover: discover, root: root, at: root.rel,
		dirStack: map[string]bool{}, visited: map[visitKey]bool{}, doneFiles: map[visitKey]bool{}, handled: map[handleKey]bool{}, objStack: map[int]bool{},
		seen: make([]bool, len(a.docs)), reached: map[int]bool{}, srcs: map[string][]*docRef{}}
}

func (w *walker) gap(reason string, src intake.Source, detail string) {
	w.addGap(Gap{reason, src, clip(detail)})
}

func (w *walker) addGap(g Gap) {
	if w.discover {
		return
	}
	if len(w.gaps) >= MaxGaps {
		if !w.gapFull {
			w.gapFull = true
			w.gaps = append(w.gaps, Gap{ClosureLimit, g.Source, "more than 4096 gaps; the rest are not listed"})
		}
		return
	}
	if !w.spend(len(g.Detail)) {
		return
	}
	w.gaps = append(w.gaps, g)
}

const resultFull = "result size limit of 16 MiB reached; the rest is not listed"

// spend takes n bytes from the result size budget shared by all
// environments. When it is used up the walk stops and nothing more is added.
func (w *walker) spend(n int) bool {
	if w.a.outFull {
		return false
	}
	w.a.outUsed += n
	if w.a.outUsed > resultBytes {
		w.a.outFull = true
		w.stopped = true
		w.gaps = append(w.gaps, Gap{ClosureLimit, w.root.doc.Source, resultFull})
		return false
	}
	return true
}

// addGaps reports the gaps a parse found, one step each.
func (w *walker) addGaps(gaps []Gap) {
	if w.discover {
		return
	}
	for _, g := range gaps {
		if !w.charge(1) {
			return
		}
		w.addGap(g)
	}
}

// charge takes n steps from the budget of this pass. When the budget is used
// up the walk stops and says where.
func (w *walker) charge(n int) bool {
	if w.stopped {
		return false
	}
	first := !w.charged
	w.charged = true
	if w.a.outFull && first && !w.discover {
		w.stopped = true
		w.gaps = append(w.gaps, Gap{ClosureLimit, w.root.doc.Source, "result size limit of 16 MiB reached before this environment was read; it is not listed"})
		return false
	}
	if w.b.out && first {
		w.stopped = true
		w.gap(ClosureLimit, w.root.doc.Source, "work limit reached before this environment was read; it is not evaluated")
		return false
	}
	w.b.used += n
	if w.b.used > w.b.limit {
		w.b.out = true
		w.stopped = true
		w.gap(ClosureLimit, w.root.doc.Source, "work limit reached while reading "+w.at+"; the rest of this environment is not evaluated")
		return false
	}
	return true
}

// The parsed form of a document is computed once, on first use, and charged
// to the pass that needs it first.

func (w *walker) kustOf(d *docRef) *kustSpec {
	if d.kustP == nil {
		s, cost := w.a.parseKust(d)
		d.kustP = s
		w.charge(cost)
	}
	return d.kustP
}

func (w *walker) fluxOf(d *docRef) *fluxSpec {
	if d.fluxP == nil {
		s, cost := w.a.parseFlux(d)
		d.fluxP = s
		w.charge(cost)
	}
	return d.fluxP
}

func (w *walker) argoOf(d *docRef) *argoSpec {
	if d.argoP == nil {
		s, cost := w.a.parseArgo(d)
		d.argoP = s
		w.charge(cost)
	}
	return d.argoP
}

func (w *walker) hrOf(d *docRef) *hrSpec {
	if d.hrP == nil {
		s, cost := w.a.parseHelmRelease(d)
		d.hrP = s
		w.charge(cost)
	}
	return d.hrP
}

func (w *walker) imagesOf(d *docRef) *imageSpec {
	if d.imgP == nil {
		s, cost := parseWorkload(d)
		d.imgP = s
		w.charge(cost)
	}
	return d.imgP
}

func (w *walker) chartOf(d *docRef) *chartSpec {
	if d.chartP == nil {
		s, cost := w.a.parseChart(d)
		d.chartP = s
		w.charge(cost)
	}
	return d.chartP
}

// nsOf is the namespace of d after the namespace transformers around it.
func (w *walker) nsOf(d *docRef) string {
	if w.scopeNS != "" {
		return w.scopeNS
	}
	return d.doc.Namespace
}

func (w *walker) walk() {
	w.seen[w.root.id] = true
	w.handled[handleKey{w.root.id, ""}] = true
	if w.root.kind == kindFlux {
		w.flux(w.root, 0)
	} else {
		w.argo(w.root, 0)
	}
	if !w.discover {
		w.finish()
	}
}

// enter starts a new object scope: patches and namespace transformers of an
// object apply only to what it collected itself.
func (w *walker) enter(ns string) (int, string) {
	owner, scope := w.owner, w.scopeNS
	w.nextOwner++
	w.owner, w.scopeNS = w.nextOwner, ns
	return owner, scope
}

func (w *walker) flux(d *docRef, hops int) {
	w.seen[d.id] = true
	if d != w.root {
		w.reached[d.id] = true
	}
	if w.objStack[d.id] {
		return
	}
	s := w.fluxOf(d)
	src := d.doc.Source
	if s.fatal != nil {
		w.addGap(*s.fatal)
		return
	}
	ref := s.ref
	if !s.refNsSet {
		ref.ns = w.nsOf(d)
	}
	if d == w.root {
		if ref.kind != "GitRepository" {
			w.gap(RemoteReferenceNotResolved, src, "root sourceRef is a "+ref.kind+", not a GitRepository")
			return
		}
		w.own = ref.key()
		if !w.ownIsSelf(ref) {
			return
		}
	} else if ref.key() != w.own {
		w.gap(RemoteReferenceNotResolved, src, "sourceRef "+ref.key()+" is not the source of the root")
		return
	}
	if s.dir.reason != "" {
		w.gap(s.dir.reason, src, s.dir.detail)
		return
	}
	if s.wholeRepo && !s.bootstrap {
		w.gap(ConstructNotEvaluated, src, "a Kustomization that applies the whole repository is followed only for the Flux bootstrap object flux-system")
		return
	}
	w.objStack[d.id] = true
	owner, scope := w.enter(s.targetNS)
	from := len(w.entries)
	w.visitDir(s.dir.path, hops+1, true, true)
	for _, c := range s.components {
		if !w.charge(1) {
			break
		}
		w.follow(c, src, hops)
	}
	if !w.discover && !w.stopped {
		w.addGaps(s.gaps)
		w.addImages(s.images)
		w.applyPatches(s.patches, from, src)
	}
	w.owner, w.scopeNS = owner, scope
	delete(w.objStack, d.id)
}

// ownIsSelf checks every definition of the root's GitRepository: its URL
// against SelfRepoURLs (when given) and its ref against the checked-out
// revision, with the rule used for Argo CD sources. None, or one that does
// not match, stops the walk.
func (w *walker) ownIsSelf(ref fluxRef) bool {
	src := w.root.doc.Source
	docs := w.a.sources[ref.key()]
	if len(docs) == 0 {
		w.gap(RemoteReferenceNotResolved, src, "GitRepository "+ref.key()+" is not in the input; its URL and revision are unknown")
		return false
	}
	for _, d := range docs {
		if !w.charge(1) {
			return false
		}
		spec := asMap(d.doc.Value["spec"])
		if len(w.a.self) > 0 && !w.a.isSelf(asStr(spec["url"])) {
			w.gap(RemoteReferenceNotResolved, src, "GitRepository "+ref.key()+" is not this repository")
			return false
		}
		if rev, ok := gitRevision(spec["ref"]); !ok {
			w.gap(RemoteReferenceNotResolved, src, "GitRepository "+ref.key()+" has a ref that is not understood")
			return false
		} else if !w.a.revisionIsSelf(rev) && !w.a.revisionIsSelf(strings.TrimPrefix(strings.TrimPrefix(rev, "refs/heads/"), "refs/tags/")) {
			w.gap(RemoteReferenceNotResolved, src, "GitRepository "+ref.key()+" tracks "+rev+", not the checked-out revision")
			return false
		}
	}
	return true
}

// gitRevision is the revision a GitRepository ref selects, in the order of
// precedence Flux uses; "" when there is no ref.
func gitRevision(v any) (string, bool) {
	if v == nil {
		return "", true
	}
	ref, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	for _, field := range []string{"commit", "name", "semver", "tag", "branch"} {
		f, present := ref[field]
		if !present || f == nil {
			continue
		}
		s, ok := scalar(f)
		if !ok {
			return "", false
		}
		if s != "" {
			return s, true
		}
	}
	return "", true
}

// follow goes to a resolved reference: a file or a directory.
func (w *walker) follow(t target, src intake.Source, hops int) {
	switch {
	case t.reason != "":
		w.gap(t.reason, src, t.detail)
	case w.a.files[t.path]:
		w.resourceFile(t.path, hops)
	default:
		w.visitDir(t.path, hops+1, true, true)
	}
}

func (w *walker) visitDir(dir string, hops int, recurse, byRef bool) {
	if !w.charge(1) {
		return
	}
	w.at = dir
	src := w.root.doc.Source
	if hops > MaxDepth {
		w.gap(ClosureLimit, src, "references nested deeper than 32 levels at "+dir)
		return
	}
	if viaRef, on := w.dirStack[dir]; on {
		if viaRef {
			w.gap(ClosureLimit, src, "reference cycle at "+dir)
		} else {
			w.gap(ClosureLimit, src, dir+" is referenced while it is read through a parent directory; it is read once")
		}
		return
	}
	if w.visited[visitKey{dir, recurse, w.scopeNS}] || w.visited[visitKey{dir, true, w.scopeNS}] {
		return
	}
	if !w.a.dirs[dir] {
		w.gap(SourceNotFound, src, w.a.missing(dir))
		return
	}
	w.visited[visitKey{dir, recurse, w.scopeNS}] = true
	w.dirStack[dir] = byRef
	defer delete(w.dirStack, dir)
	if k := w.a.kust[dir]; k != nil {
		if first, multi := w.a.kustMulti[dir]; multi {
			w.gap(SourceNotFound, first, "more than one kustomization file in a directory")
		}
		w.kustomization(k, dir, hops)
		return
	}
	if names := w.a.kustFiles[dir]; len(names) > 0 {
		// A kustomization file that intake could not keep (template syntax,
		// encryption or a shape that is not an object): the directory is not
		// read as a plain directory, which would collect too much.
		for _, n := range names {
			if !w.charge(1) {
				return
			}
			w.fileGaps(path.Join(dir, n))
		}
		w.gap(SourceNotFound, src, "the kustomization file in "+dir+" was not read; the directory is not evaluated")
		return
	}
	if _, chart := w.a.chartDocs[dir]; chart {
		w.chartDir(dir, hops)
		return
	}
	if !w.discover {
		for _, f := range w.a.encByDir[dir] {
			if !w.charge(1) {
				return
			}
			w.gap(Encrypted, w.a.enc[f], "SOPS-encrypted document skipped")
		}
		for _, o := range w.a.omitByDir[dir] {
			if !w.charge(1) {
				return
			}
			w.gap(SourceNotFound, o.Source, "document with template syntax was not read")
		}
	}
	docs := w.a.byDir[dir]
	if w.discover {
		docs = w.a.candDir[dir]
	}
	for _, d := range docs {
		w.handle(d, hops)
		if w.stopped {
			return
		}
	}
	if recurse {
		for _, sub := range w.a.subdirs[dir] {
			w.visitDir(sub, hops, true, false)
			if w.stopped {
				return
			}
		}
	}
}

// chartDir reads a local Helm chart: its Chart.yaml only. The chart is not
// rendered, so its templates are not read.
func (w *walker) chartDir(dir string, hops int) {
	if w.discover {
		return
	}
	for _, d := range w.a.chartDocs[dir] {
		w.handle(d, hops)
		if w.stopped {
			return
		}
	}
	w.fileGaps(path.Join(dir, "Chart.yaml"))
	if w.a.chartExtra[dir] {
		w.gap(ConstructNotEvaluated, w.root.doc.Source, "the local Helm chart in "+dir+" is not rendered; its templates are not read")
	}
}

// fileGaps reports an encrypted file and the documents of a file that intake
// left out because of template syntax.
func (w *walker) fileGaps(f string) {
	if w.discover {
		return
	}
	if src, enc := w.a.enc[f]; enc {
		if !w.charge(1) {
			return
		}
		w.gap(Encrypted, src, "SOPS-encrypted document skipped")
	}
	for _, o := range w.a.omitByFile[f] {
		if !w.charge(1) {
			return
		}
		w.gap(SourceNotFound, o.Source, "document with template syntax was not read")
	}
}

func (w *walker) kustomization(k *docRef, dir string, hops int) {
	w.seen[k.id] = true
	s := w.kustOf(k)
	scope := w.scopeNS
	if s.ns != "" && w.scopeNS == "" {
		// An outer namespace transformer runs later and wins.
		w.scopeNS = s.ns
	}
	from := len(w.entries)
	for _, e := range s.entries {
		if !w.charge(1) {
			break
		}
		w.follow(e, k.doc.Source, hops)
		if w.stopped {
			break
		}
	}
	if !w.discover && !w.stopped {
		w.addGaps(s.gaps)
		w.addImages(s.images)
		w.applyPatches(s.patches, from, k.doc.Source)
	}
	w.scopeNS = scope
}

// resourceFile reads a file named by a kustomization, once per walk.
func (w *walker) resourceFile(f string, hops int) {
	if w.doneFiles[visitKey{f, false, w.scopeNS}] {
		return
	}
	w.doneFiles[visitKey{f, false, w.scopeNS}] = true
	w.at = f
	w.fileGaps(f)
	docs := w.a.byFile[f]
	if w.discover {
		docs = w.a.candFile[f]
	}
	for _, d := range docs {
		w.handle(d, hops)
		if w.stopped {
			return
		}
	}
}

func (w *walker) handle(d *docRef, hops int) {
	if !w.charge(1) || w.handled[handleKey{d.id, w.scopeNS}] {
		return
	}
	w.handled[handleKey{d.id, w.scopeNS}] = true
	w.seen[d.id] = true
	switch d.kind {
	case kindFlux:
		w.flux(d, hops)
		return
	case kindArgo:
		w.reached[d.id] = true
		w.argo(d, hops)
		return
	}
	if w.discover {
		return
	}
	switch d.kind {
	case kindChart:
		w.chart(d, hops)
	case kindAppSet:
		w.gap(GeneratedApplicationsNotEvaluated, d.doc.Source, "ApplicationSet generates Applications that are not evaluated")
	case kindHelmRelease:
		w.helmRelease(d)
	case kindSource:
		k := sourceKey(d.doc.Kind, w.nsOf(d), d.doc.Name)
		w.srcs[k] = append(w.srcs[k], d)
	case kindWorkload:
		s := w.imagesOf(d)
		w.addGaps(s.gaps)
		w.addImages(s.pins)
	}
}

func (w *walker) addRelease(e relEntry) {
	if len(w.entries) >= MaxReleases {
		if !w.relFull {
			w.relFull = true
			w.gap(ClosureLimit, e.base.Source, "more than 4096 releases; the rest are not listed")
		}
		return
	}
	e.owner = w.owner
	w.entries = append(w.entries, e)
}

func (w *walker) addImages(pins []ImagePin) {
	for _, p := range pins {
		if !w.charge(1) {
			return
		}
		if len(w.imgs) >= MaxImages {
			if !w.imgFull {
				w.imgFull = true
				w.gap(ClosureLimit, p.Source, "more than 4096 image pins; the rest are not listed")
			}
			return
		}
		w.imgs = append(w.imgs, p)
	}
}

// maxReleaseName is the longest Helm release name Flux uses unchanged.
const maxReleaseName = 53

func (w *walker) helmRelease(d *docRef) {
	s := w.hrOf(d)
	w.addGaps(s.gaps)
	if !s.ok {
		return
	}
	w.addRelease(relEntry{base: &s.rel, hr: d, ns: w.nsOf(d), version: s.rel.ChartVersion, vals: s.valBytes})
}

func (w *walker) chart(d *docRef, hops int) {
	s := w.chartOf(d)
	w.addGaps(s.gaps)
	for i, dep := range s.deps {
		if !w.charge(1) {
			return
		}
		w.addRelease(relEntry{base: &s.deps[i], version: dep.ChartVersion})
	}
	for _, t := range s.files {
		if !w.charge(1) {
			return
		}
		switch {
		case t.reason != "":
			w.gap(t.reason, d.doc.Source, "file:// dependency: "+t.detail)
		case w.a.files[t.path]:
			w.gap(SourceNotFound, d.doc.Source, "file:// dependency is not a chart directory: "+t.path)
		default:
			w.visitDir(t.path, hops+1, true, true)
		}
		if w.stopped {
			return
		}
	}
}

func (w *walker) argo(d *docRef, hops int) {
	s := w.argoOf(d)
	w.addGaps(s.gaps)
	if w.objStack[d.id] {
		return
	}
	w.objStack[d.id] = true
	owner, scope := w.enter("")
	for _, src := range s.sources {
		if !w.charge(1) {
			break
		}
		w.argoSource(src, hops)
		if w.stopped {
			break
		}
	}
	w.owner, w.scopeNS = owner, scope
	delete(w.objStack, d.id)
}

func (w *walker) argoSource(s *argoSrc, hops int) {
	w.addGaps(s.gaps)
	switch s.kind {
	case argoChart:
		if w.discover {
			return
		}
		_, gap, cost := w.a.argoValues(s)
		if !w.charge(cost) {
			return
		}
		if gap != nil {
			w.addGap(*gap)
		}
		w.addRelease(relEntry{base: &s.rel, version: s.rel.ChartVersion, vals: s.valBytes})
	case argoPath:
		if !s.follow {
			return
		}
		if !w.discover {
			w.addImages(s.images)
		}
		scope := w.scopeNS
		if s.ns != "" {
			w.scopeNS = s.ns
		}
		w.visitDir(s.dir.path, hops+1, s.recurse, true)
		w.scopeNS = scope
	}
}

// finish resolves Flux sources, checks pins and drops what cannot be named.
func (w *walker) finish() {
	w.rels = make([]Release, 0, len(w.entries))
	for _, e := range w.entries {
		if w.a.outFull {
			break
		}
		r := *e.base
		r.ChartVersion = e.version
		var ref fluxRef
		if e.hr != nil {
			hr := e.hr.hrP
			if r.Namespace = hr.targetNS; r.Namespace == "" {
				r.Namespace = e.ns
			}
			if ref = hr.ref; !hr.refNsSet {
				ref.ns = e.ns
			}
		}
		gitDetail := ""
		if ref.kind != "" {
			gitDetail = w.resolveSource(&r, ref, e.hr.hrP.chartRef) // an unresolved release stays, without a repository
		}
		if !fits(r.Chart, r.ChartVersion, r.RepoURL, r.SourceRef, r.Namespace, r.ReleaseName) {
			w.gap(SourceNotFound, r.Source, "release identity longer than 256 bytes")
			continue
		}
		if needsEscape(r.Chart) || needsEscape(r.ChartVersion) || needsEscape(r.RepoURL) || needsEscape(r.SourceRef) ||
			needsEscape(r.Namespace) || needsEscape(r.ReleaseName) {
			w.gap(SourceNotFound, r.Source, "release identity holds control characters")
			continue
		}
		if !w.spend(len(r.Chart) + len(r.ChartVersion) + len(r.RepoURL) + len(r.SourceRef) + len(r.Namespace) + len(r.ReleaseName) + e.vals) {
			break
		}
		switch {
		case ref.kind == "GitRepository":
			if gitDetail != "" {
				w.addGap(Gap{ChartVersionNotPinned, r.Source, gitDetail})
			}
		case !isPinned(r.ChartVersion):
			w.addGap(Gap{ChartVersionNotPinned, r.Source, w.a.pinDetail(r.ChartVersion)})
		}
		w.rels = append(w.rels, r)
	}
	w.entries = nil
	sort.SliceStable(w.rels, func(i, j int) bool {
		a, b := w.rels[i], w.rels[j]
		switch {
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		case a.Chart != b.Chart:
			return a.Chart < b.Chart
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		case a.ReleaseName != b.ReleaseName:
			return a.ReleaseName < b.ReleaseName
		case a.Source != b.Source:
			return srcLess(a.Source, b.Source)
		case a.ChartVersion != b.ChartVersion:
			return a.ChartVersion < b.ChartVersion
		}
		return a.RepoURL < b.RepoURL
	})
	sort.SliceStable(w.imgs, func(i, j int) bool {
		a, b := w.imgs[i], w.imgs[j]
		switch {
		case a.Image != b.Image:
			return a.Image < b.Image
		case a.Tag != b.Tag:
			return a.Tag < b.Tag
		case a.Digest != b.Digest:
			return a.Digest < b.Digest
		}
		return srcLess(a.Source, b.Source)
	})
	w.gaps = sortGaps(w.gaps)
}

// resolveSource fills RepoURL (and, for an OCI chart, Chart and version) from
// the Flux source object. It prefers a source met in this environment and
// accepts one defined elsewhere only when it is the only one of that name.
// For a chart from a GitRepository it returns why the chart is not pinned, or
// "" when the repository is at a fixed tag or commit.
func (w *walker) resolveSource(r *Release, ref fluxRef, chartRef bool) string {
	text := w.a.sourceText(ref)
	key := text.key
	r.SourceRef = key
	docs := w.srcs[key]
	if len(docs) == 0 {
		docs = w.a.sources[key]
	}
	unknownGit := ""
	if ref.kind == "GitRepository" {
		unknownGit = "chart from a Git source whose revision is unknown"
	}
	if len(docs) != 1 {
		detail := text.notFound
		if len(docs) > 1 {
			detail = text.many
		}
		w.addGap(Gap{SourceNotFound, r.Source, detail})
		return unknownGit
	}
	spec := asMap(docs[0].doc.Value["spec"])
	url := asStr(spec["url"])
	switch ref.kind {
	case "HelmRepository":
		r.RepoURL = url
	case "GitRepository":
		r.RepoURL = url
		return gitPin(asMap(spec["ref"]))
	case "OCIRepository":
		if !chartRef {
			w.gap(SourceNotFound, r.Source, "an OCIRepository is not a chart repository here")
			return ""
		}
		trimmed := strings.TrimRight(url, "/")
		i := strings.LastIndexByte(trimmed, '/')
		if !strings.HasPrefix(trimmed, "oci://") || i < len("oci://") {
			w.gap(SourceNotFound, r.Source, "OCIRepository url is not an oci:// chart reference")
			return ""
		}
		r.RepoURL, r.Chart = trimmed[:i], trimmed[i+1:]
		ref := asMap(spec["ref"])
		for _, field := range []string{"tag", "digest", "semver"} {
			if v, ok := scalar(ref[field]); ok && v != "" {
				r.ChartVersion = v
				break
			}
		}
	default:
		w.gap(RemoteReferenceNotResolved, r.Source, "source of kind "+ref.kind+" is not evaluated")
	}
	return ""
}

// gitPin says why a GitRepository reference is not fixed, in the order of
// precedence Flux uses; "" means a commit or a tag.
func gitPin(ref map[string]any) string {
	text := func(k string) string { s, _ := scalar(ref[k]); return s }
	commit, name, semver, tag, branch := text("commit"), text("name"), text("semver"), text("tag"), text("branch")
	switch {
	case commit != "":
		return ""
	case name != "":
		if strings.HasPrefix(name, "refs/tags/") {
			return ""
		}
		return "chart from a Git source at reference " + name
	case semver != "":
		return "chart from a Git source at version range " + semver
	case tag != "":
		return ""
	case branch != "":
		return "chart from a Git source at branch " + branch
	}
	return "chart from a Git source without a fixed tag or commit"
}
