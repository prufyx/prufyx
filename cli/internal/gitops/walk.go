// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"path"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// maxValuesText bounds an inline Argo CD helm.values text that is parsed.
const maxValuesText = 64 << 10

type fluxRef struct{ kind, ns, name string }

func (r fluxRef) key() string { return sourceKey(r.kind, r.ns, r.name) }

type relMeta struct {
	objName, objNs string
	ref            fluxRef // Flux source of a HelmRelease; zero otherwise
	chartRef       bool    // the chart comes from an OCIRepository
}

// walker is the closure of one root object.
type walker struct {
	a        *analysis
	root     *docRef
	own      string
	dirStack map[string]bool
	visited  map[string]bool
	objStack map[skey]bool
	seen     map[skey]bool
	reached  map[skey]bool
	rels     []Release
	metas    []relMeta
	imgs     []ImagePin
	gaps     []Gap
	srcs     map[string][]*docRef
	relFull  bool
	imgFull  bool
	gapFull  bool
	stopped  bool
}

func newWalker(a *analysis, root *docRef) *walker {
	return &walker{a: a, root: root, dirStack: map[string]bool{}, visited: map[string]bool{}, objStack: map[skey]bool{},
		seen: map[skey]bool{}, reached: map[skey]bool{}, srcs: map[string][]*docRef{}}
}

func isFluxKustomization(d *docRef) bool {
	return !d.aux && d.doc.Kind == "Kustomization" && d.group() == "kustomize.toolkit.fluxcd.io"
}

func isArgoApplication(d *docRef) bool {
	return !d.aux && d.doc.Kind == "Application" && d.group() == "argoproj.io"
}

func (w *walker) gap(reason string, src intake.Source, detail string) {
	if len(w.gaps) >= MaxGaps {
		if !w.gapFull {
			w.gapFull = true
			w.gaps = append(w.gaps, Gap{ClosureLimit, src, "more than 4096 gaps; the rest are not listed"})
		}
		return
	}
	w.gaps = append(w.gaps, Gap{reason, src, clip(detail)})
}

// step charges one unit of the shared work budget.
func (w *walker) step() bool {
	if w.stopped {
		return false
	}
	w.a.steps++
	if w.a.steps > workBudget {
		w.a.exhausted = true
		w.stopped = true
		w.gap(ClosureLimit, w.root.doc.Source, "work limit reached; the environment is incomplete")
		return false
	}
	return true
}

func (w *walker) walk() {
	w.seen[w.root.key] = true
	if isFluxKustomization(w.root) {
		w.flux(w.root, 0)
	} else {
		w.argo(w.root, 0)
	}
	w.finish()
}

func (w *walker) flux(d *docRef, hops int) {
	w.seen[d.key] = true
	if d != w.root {
		w.reached[d.key] = true
	}
	if w.objStack[d.key] {
		return
	}
	spec := asMap(d.doc.Value["spec"])
	ref := asMap(spec["sourceRef"])
	r := fluxRef{asStr(ref["kind"]), asStr(ref["namespace"]), asStr(ref["name"])}
	if r.ns == "" {
		r.ns = d.doc.Namespace
	}
	if r.kind == "" || r.name == "" {
		w.gap(SourceNotFound, d.doc.Source, "spec.sourceRef is missing")
		return
	}
	if d == w.root {
		if r.kind != "GitRepository" {
			w.gap(RemoteReferenceNotResolved, d.doc.Source, "root sourceRef is a "+r.kind+", not a GitRepository")
			return
		}
		w.own = r.key()
		if len(w.a.self) > 0 {
			if docs := w.a.sources[r.key()]; len(docs) == 1 && !w.a.isSelf(asStr(get(docs[0].doc.Value, "spec", "url"))) {
				w.gap(RemoteReferenceNotResolved, d.doc.Source, "GitRepository "+r.key()+" is not this repository")
				return
			}
		}
	} else if r.key() != w.own {
		w.gap(RemoteReferenceNotResolved, d.doc.Source, "sourceRef "+r.key()+" is not the source of the root")
		return
	}
	p := "./"
	if v, present := spec["path"]; present {
		s, ok := v.(string)
		if !ok {
			w.gap(SourceNotFound, d.doc.Source, "spec.path is not a string")
			return
		}
		if s != "" {
			p = s
		}
	}
	dir, reason, detail := w.a.resolve(".", p)
	if reason != "" {
		w.gap(reason, d.doc.Source, detail)
		return
	}
	w.objStack[d.key] = true
	from := len(w.rels)
	w.visitDir(dir, hops+1)
	delete(w.objStack, d.key)
	w.applyImages(asList(spec["images"]), d.doc.Source)
	w.applyPatches(asList(spec["patches"]), from, d.doc.Source)
	if len(asList(spec["patchesStrategicMerge"])) > 0 || len(asList(spec["patchesJson6902"])) > 0 {
		w.gap(PatchNotEvaluated, d.doc.Source, "patchesStrategicMerge and patchesJson6902 are not evaluated")
	}
}

func (w *walker) visitDir(dir string, hops int) {
	if !w.step() {
		return
	}
	if hops > MaxDepth {
		w.gap(ClosureLimit, w.root.doc.Source, "references nested deeper than 32 levels at "+clip(dir))
		return
	}
	if w.dirStack[dir] {
		w.gap(ClosureLimit, w.root.doc.Source, "reference cycle at "+clip(dir))
		return
	}
	if w.visited[dir] {
		return
	}
	if !w.a.dirs[dir] {
		w.gap(SourceNotFound, w.root.doc.Source, w.a.missing(dir))
		return
	}
	w.visited[dir] = true
	w.dirStack[dir] = true
	defer delete(w.dirStack, dir)
	if k := w.a.kust[dir]; k != nil {
		if src, multi := w.a.kustMulti[dir]; multi {
			w.gap(SourceNotFound, src, "more than one kustomization file in a directory")
		}
		w.kustomization(k, dir, hops)
		return
	}
	for _, f := range w.a.encByDir[dir] {
		w.gap(Encrypted, w.a.enc[f], "SOPS-encrypted document skipped")
	}
	for _, o := range w.a.omitByDir[dir] {
		w.gap(SourceNotFound, o.Source, "document with template syntax was not read")
	}
	for _, d := range w.a.byDir[dir] {
		w.handle(d, hops)
		if w.stopped {
			return
		}
	}
	for _, sub := range w.a.subdirs[dir] {
		w.visitDir(sub, hops)
		if w.stopped {
			return
		}
	}
}

func (w *walker) kustomization(k *docRef, dir string, hops int) {
	w.seen[k.key] = true
	v := k.doc.Value
	from := len(w.rels)
	var entries []any
	for _, name := range []string{"resources", "bases", "components"} {
		entries = append(entries, asList(v[name])...)
	}
	for _, e := range entries {
		r, ok := e.(string)
		if !ok {
			w.gap(SourceNotFound, k.doc.Source, "a resource entry is not a string")
			continue
		}
		w.resource(k, dir, r, hops)
		if w.stopped {
			return
		}
	}
	w.applyImages(asList(v["images"]), k.doc.Source)
	w.applyPatches(asList(v["patches"]), from, k.doc.Source)
	if len(asList(v["patchesStrategicMerge"])) > 0 || len(asList(v["patchesJson6902"])) > 0 ||
		len(asList(v["replacements"])) > 0 || len(asList(v["transformers"])) > 0 {
		w.gap(PatchNotEvaluated, k.doc.Source, "patchesStrategicMerge, patchesJson6902, replacements and transformers are not evaluated")
	}
	if len(asList(v["helmCharts"])) > 0 {
		w.gap(RemoteReferenceNotResolved, k.doc.Source, "helmCharts are not evaluated")
	}
}

func (w *walker) resource(k *docRef, dir, ref string, hops int) {
	resolved, reason, detail := w.a.resolve(dir, ref)
	if reason != "" {
		w.gap(reason, k.doc.Source, detail)
		return
	}
	switch {
	case w.a.files[resolved]:
		if src, enc := w.a.enc[resolved]; enc {
			w.gap(Encrypted, src, "SOPS-encrypted document skipped")
		}
		for _, o := range w.a.omitByDir[path.Dir(resolved)] {
			if w.a.relOf(o.Source.Display) == resolved {
				w.gap(SourceNotFound, o.Source, "document with template syntax was not read")
			}
		}
		for _, d := range w.a.byDir[path.Dir(resolved)] {
			if d.rel == resolved {
				w.handle(d, hops)
			}
		}
	case w.a.dirs[resolved]:
		w.visitDir(resolved, hops+1)
	default:
		w.gap(SourceNotFound, k.doc.Source, w.a.missing(resolved))
	}
}

func (a *analysis) relOf(display string) string {
	r, _ := a.rel(display)
	return r
}

func (w *walker) handle(d *docRef, hops int) {
	if !w.step() || w.seen[d.key] {
		return
	}
	w.seen[d.key] = true
	switch {
	case d.aux:
		if path.Base(d.rel) == "Chart.yaml" {
			w.chart(d)
		}
	case isFluxKustomization(d):
		w.flux(d, hops)
	case isArgoApplication(d):
		w.reached[d.key] = true
		w.argo(d, hops)
	case d.doc.Kind == "ApplicationSet" && d.group() == "argoproj.io":
		w.gap(GeneratedApplicationsNotEvaluated, d.doc.Source, "ApplicationSet generates Applications that are not evaluated")
	case d.doc.Kind == KindHelmRelease && d.group() == "helm.toolkit.fluxcd.io":
		w.helmRelease(d)
	case d.group() == "source.toolkit.fluxcd.io":
		k := sourceKey(d.doc.Kind, d.doc.Namespace, d.doc.Name)
		w.srcs[k] = append(w.srcs[k], d)
	default:
		w.workload(d)
	}
}

func (w *walker) addRelease(r Release, m relMeta) {
	if len(w.rels) >= MaxReleases {
		if !w.relFull {
			w.relFull = true
			w.gap(ClosureLimit, r.Source, "more than 4096 releases; the rest are not listed")
		}
		return
	}
	w.rels = append(w.rels, r)
	w.metas = append(w.metas, m)
}

func (w *walker) addImage(p ImagePin) {
	if !fits(p.Image, p.Tag, p.Digest) {
		w.gap(SourceNotFound, p.Source, "image reference longer than 256 bytes")
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

func (w *walker) helmRelease(d *docRef) {
	spec := asMap(d.doc.Value["spec"])
	r := Release{Kind: KindHelmRelease, Source: d.doc.Source, Namespace: asStr(spec["targetNamespace"]), ReleaseName: asStr(spec["releaseName"])}
	if r.Namespace == "" {
		r.Namespace = d.doc.Namespace
	}
	if r.ReleaseName == "" {
		r.ReleaseName = d.doc.Name
	}
	meta := relMeta{objName: d.doc.Name, objNs: d.doc.Namespace}
	ref := func(m map[string]any) fluxRef {
		f := fluxRef{asStr(m["kind"]), asStr(m["namespace"]), asStr(m["name"])}
		if f.ns == "" {
			f.ns = d.doc.Namespace
		}
		return f
	}
	if chartSpec := asMap(get(spec, "chart", "spec")); chartSpec != nil {
		r.Chart = asStr(chartSpec["chart"])
		if v, present := chartSpec["version"]; present {
			version, ok := scalar(v)
			if !ok {
				w.gap(SourceNotFound, d.doc.Source, "spec.chart.spec.version is not a string")
				return
			}
			r.ChartVersion = version
		}
		meta.ref = ref(asMap(chartSpec["sourceRef"]))
		if r.Chart == "" || meta.ref.kind == "" || meta.ref.name == "" {
			w.gap(SourceNotFound, d.doc.Source, "chart name or sourceRef is missing")
			return
		}
	} else if cr := asMap(spec["chartRef"]); cr != nil {
		meta.ref, meta.chartRef = ref(cr), true
		if meta.ref.kind != "OCIRepository" || meta.ref.name == "" {
			w.gap(SourceNotFound, d.doc.Source, "chartRef of kind "+clip(meta.ref.kind)+" is not evaluated")
			return
		}
	} else {
		w.gap(SourceNotFound, d.doc.Source, "the chart is not identified")
		return
	}
	if v, present := spec["values"]; present && v != nil {
		if m := asMap(v); m != nil {
			r.Values = m
		} else {
			w.gap(ValuesFromNotResolved, d.doc.Source, "spec.values is not an object")
		}
	}
	if from := asList(spec["valuesFrom"]); len(from) > 0 {
		var names []string
		for _, f := range from {
			fm := asMap(f)
			names = append(names, asStr(fm["kind"])+"/"+asStr(fm["name"]))
			if len(names) == 4 {
				break
			}
		}
		w.gap(ValuesFromNotResolved, d.doc.Source, "valuesFrom: "+strings.Join(names, ", "))
	}
	w.addRelease(r, meta)
}

func (w *walker) workload(d *docRef) {
	spec := asMap(d.doc.Value["spec"])
	var pod map[string]any
	switch d.doc.Kind {
	case "Pod":
		pod = spec
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController":
		pod = asMap(get(spec, "template", "spec"))
	case "CronJob":
		pod = asMap(get(spec, "jobTemplate", "spec", "template", "spec"))
	default:
		return
	}
	for _, field := range []string{"initContainers", "containers"} {
		for _, c := range asList(pod[field]) {
			ref := asStr(asMap(c)["image"])
			if ref == "" {
				continue
			}
			image, tag, digest, ok := splitImage(ref)
			if !ok {
				w.gap(SourceNotFound, d.doc.Source, "image reference is not understood")
				continue
			}
			w.addImage(ImagePin{Image: image, Tag: tag, Digest: digest, Source: d.doc.Source})
		}
	}
}

func (w *walker) chart(d *docRef) {
	deps := d.doc.Value["dependencies"]
	if deps == nil {
		return
	}
	list, ok := deps.([]any)
	if !ok {
		w.gap(SourceNotFound, d.doc.Source, "dependencies is not a list")
		return
	}
	for _, e := range list {
		m := asMap(e)
		name := asStr(m["name"])
		if name == "" {
			w.gap(SourceNotFound, d.doc.Source, "a dependency has no name")
			continue
		}
		repo := asStr(m["repository"])
		if strings.HasPrefix(repo, "file://") {
			continue // a chart inside this repository; its own Chart.yaml is read
		}
		version, _ := scalar(m["version"])
		release := name
		if alias := asStr(m["alias"]); alias != "" {
			release = alias
		}
		w.addRelease(Release{Kind: KindChartDependency, Chart: name, ChartVersion: version, RepoURL: repo, ReleaseName: release, Source: d.doc.Source}, relMeta{})
	}
}

// applyImages records a kustomize-style images list.
func (w *walker) applyImages(list []any, src intake.Source) {
	for _, e := range list {
		m := asMap(e)
		image := asStr(m["newName"])
		if image == "" {
			image = asStr(m["name"])
		}
		if image == "" {
			w.gap(SourceNotFound, src, "an images entry has no name")
			continue
		}
		tag, _ := scalar(m["newTag"])
		w.addImage(ImagePin{Image: image, Tag: tag, Digest: asStr(m["digest"]), Source: src})
	}
}

func (w *walker) argo(d *docRef, hops int) {
	spec := asMap(d.doc.Value["spec"])
	var sources []any
	if l := asList(spec["sources"]); len(l) > 0 {
		sources = l
	} else if s := spec["source"]; s != nil {
		sources = []any{s}
	}
	if len(sources) == 0 {
		w.gap(SourceNotFound, d.doc.Source, "the Application has no source")
		return
	}
	if len(sources) > MaxSources {
		w.gap(ClosureLimit, d.doc.Source, "more than 64 sources; the rest are not evaluated")
		sources = sources[:MaxSources]
	}
	destNS := asStr(get(spec, "destination", "namespace"))
	w.objStack[d.key] = true
	defer delete(w.objStack, d.key)
	for _, s := range sources {
		w.argoSource(d, asMap(s), destNS, hops)
		if w.stopped {
			return
		}
	}
}

func (w *walker) argoSource(d *docRef, s map[string]any, destNS string, hops int) {
	src := d.doc.Source
	if s == nil {
		w.gap(SourceNotFound, src, "a source is not an object")
		return
	}
	repo := asStr(s["repoURL"])
	chart := asStr(s["chart"])
	helm := asMap(s["helm"])
	switch pth, hasPath := s["path"].(string); {
	case chart != "":
		rev, _ := scalar(s["targetRevision"])
		release := asStr(helm["releaseName"])
		if release == "" {
			release = d.doc.Name
		}
		r := Release{Kind: KindApplication, Chart: chart, ChartVersion: rev, RepoURL: repo, Namespace: destNS, ReleaseName: release, Source: src}
		r.Values = w.argoValues(src, helm)
		w.valueFiles(src, helm)
		w.addRelease(r, relMeta{})
	case hasPath:
		if !w.a.isSelf(repo) {
			w.gap(RemoteReferenceNotResolved, src, "repoURL "+clip(repo)+" is not this repository")
			return
		}
		dir, reason, detail := w.a.resolve(".", pth)
		if reason != "" {
			w.gap(reason, src, detail)
			return
		}
		w.valueFiles(src, helm)
		w.argoKustomizeImages(src, asMap(s["kustomize"]))
		w.visitDir(dir, hops+1)
	case s["ref"] != nil:
		if !w.a.isSelf(repo) {
			w.gap(RemoteReferenceNotResolved, src, "ref source repoURL "+clip(repo)+" is not this repository")
		}
	default:
		w.gap(SourceNotFound, src, "a source has neither chart, path nor ref")
	}
}

func (w *walker) valueFiles(src intake.Source, helm map[string]any) {
	if len(asList(helm["valueFiles"])) > 0 || len(asList(helm["fileParameters"])) > 0 {
		w.gap(ValueFilesNotResolved, src, "helm value files are not read")
	}
}

func (w *walker) argoValues(src intake.Source, helm map[string]any) map[string]any {
	obj, hasObj := helm["valuesObject"]
	text, hasText := helm["values"].(string)
	switch {
	case hasObj && hasText && text != "":
		w.gap(ValuesFromNotResolved, src, "helm.values and helm.valuesObject are both set")
		return nil
	case hasObj:
		if m := asMap(obj); m != nil {
			return m
		}
		w.gap(ValuesFromNotResolved, src, "helm.valuesObject is not an object")
	case hasText && strings.TrimSpace(text) != "":
		if len(text) > maxValuesText {
			w.gap(ValuesFromNotResolved, src, "helm.values is longer than 65536 bytes")
			return nil
		}
		docs, err := intake.DecodeDocuments([]byte(text))
		if err != nil || len(docs) != 1 || asMap(docs[0]) == nil {
			w.gap(ValuesFromNotResolved, src, "helm.values is not a single YAML object")
			return nil
		}
		return asMap(docs[0])
	}
	return nil
}

func (w *walker) argoKustomizeImages(src intake.Source, k map[string]any) {
	for _, e := range asList(k["images"]) {
		text, ok := e.(string)
		if !ok {
			continue
		}
		if i := strings.IndexByte(text, '='); i >= 0 {
			text = text[i+1:]
		}
		image, tag, digest, ok := splitImage(text)
		if !ok {
			w.gap(SourceNotFound, src, "a kustomize image entry is not understood")
			continue
		}
		w.addImage(ImagePin{Image: image, Tag: tag, Digest: digest, Source: src})
	}
}

// finish resolves Flux sources, checks pins and drops what cannot be named.
func (w *walker) finish() {
	kept := w.rels[:0]
	for i := range w.rels {
		r, m := w.rels[i], w.metas[i]
		if m.ref.kind != "" {
			w.resolveSource(&r, m) // an unresolved release stays, without a repository
		}
		if !fits(r.Chart, r.ChartVersion, r.RepoURL, r.SourceRef, r.Namespace, r.ReleaseName) {
			w.gap(SourceNotFound, r.Source, "release identity longer than 256 bytes")
			continue
		}
		if !(m.ref.kind == "GitRepository") && !isPinned(r.ChartVersion) {
			detail := "no version is set"
			if r.ChartVersion != "" {
				detail = "version " + r.ChartVersion
			}
			w.gap(ChartVersionNotPinned, r.Source, detail)
		}
		kept = append(kept, r)
	}
	w.rels = kept
	w.metas = nil
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
func (w *walker) resolveSource(r *Release, m relMeta) bool {
	key := m.ref.key()
	r.SourceRef = key
	docs := w.srcs[key]
	if len(docs) == 0 {
		docs = w.a.sources[key]
	}
	if len(docs) != 1 {
		detail := "source " + key + " was not found"
		if len(docs) > 1 {
			detail = "source " + key + " is defined more than once"
		}
		w.gap(SourceNotFound, r.Source, detail)
		return false
	}
	spec := asMap(docs[0].doc.Value["spec"])
	url := asStr(spec["url"])
	switch m.ref.kind {
	case "HelmRepository", "GitRepository":
		r.RepoURL = url
	case "OCIRepository":
		if !m.chartRef {
			w.gap(SourceNotFound, r.Source, "an OCIRepository is not a chart repository here")
			return false
		}
		trimmed := strings.TrimRight(url, "/")
		i := strings.LastIndexByte(trimmed, '/')
		if !strings.HasPrefix(trimmed, "oci://") || i < len("oci://") {
			w.gap(SourceNotFound, r.Source, "OCIRepository url is not an oci:// chart reference")
			return false
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
		w.gap(RemoteReferenceNotResolved, r.Source, "source of kind "+clip(m.ref.kind)+" is not evaluated")
		return false
	}
	return true
}
