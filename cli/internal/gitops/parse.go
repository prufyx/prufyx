// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"strings"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// Every parser here runs at most once per document. Its result is shared by
// all environments and is never changed after it is stored. Each parser
// returns its cost in work steps: one per item read, plus one per 64 bytes of
// text decoded.

type fluxRef struct{ kind, ns, name string }

func (r fluxRef) key() string { return sourceKey(r.kind, r.ns, r.name) }

type kustSpec struct {
	entries []target
	images  []imageRule
	patches []patchResult
	ns      string
	gaps    []Gap
}

type fluxSpec struct {
	fatal      *Gap // the object cannot be followed at all
	ref        fluxRef
	refNsSet   bool
	dir        target
	wholeRepo  bool
	bootstrap  bool
	targetNS   string
	components []target
	images     []imageRule
	patches    []patchResult
	gaps       []Gap
}

type hrSpec struct {
	ok       bool
	rel      Release // Namespace is filled per environment
	targetNS string
	ref      fluxRef
	refNsSet bool
	chartRef bool
	valBytes int
	gaps     []Gap
}

type imageSpec struct {
	pins []ImagePin
	gaps []Gap
}

type chartSpec struct {
	deps  []Release
	files []target
	gaps  []Gap
}

type argoKind int

const (
	argoBad argoKind = iota
	argoChart
	argoPath
	argoRef
)

type argoSrc struct {
	kind     argoKind
	gaps     []Gap
	rel      Release // chart sources
	text     string  // helm.values text, decoded on first use
	object   map[string]any
	decoded  bool
	values   map[string]any
	valBytes int
	valGap   *Gap
	cost     int    // resolving the path
	dir      target // path sources
	follow   bool
	recurse  bool
	ns       string
	images   []imageRule
}

type argoSpec struct {
	sources []*argoSrc
	gaps    []Gap
}

func gapAt(src intake.Source) func(reason, detail string) Gap {
	return func(reason, detail string) Gap { return Gap{reason, src, clip(detail)} }
}

// listField reads an optional list field. bad reports a present field that
// is not a list.
func listField(m map[string]any, name string) (list []any, bad bool) {
	v, present := m[name]
	if !present || v == nil {
		return nil, false
	}
	l, ok := v.([]any)
	return l, !ok
}

// nonEmpty reports a field that is set to something other than an empty
// value.
func nonEmpty(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

func (a *analysis) parseKust(k *docRef) (*kustSpec, int) {
	v, s, cost := k.doc.Value, &kustSpec{}, 1
	g := gapAt(k.doc.Source)
	for _, name := range []string{"resources", "bases", "components"} {
		list, bad := listField(v, name)
		if bad {
			s.gaps = append(s.gaps, g(SourceNotFound, name+" is not a list"))
		}
		for _, e := range list {
			cost++
			r, ok := e.(string)
			if !ok {
				s.gaps = append(s.gaps, g(SourceNotFound, "a "+name+" entry is not a string"))
				continue
			}
			s.entries, cost = append(s.entries, a.resolve(k.dir, r)), cost+resolveCost(r)
		}
	}
	images, bad := listField(v, "images")
	if bad {
		s.gaps = append(s.gaps, g(ConstructNotEvaluated, "images is not a list"))
	}
	var c int
	s.images, c = kustImages(images, k.doc.Source, &s.gaps)
	cost += c
	patches, bad := listField(v, "patches")
	if bad {
		s.gaps = append(s.gaps, g(PatchNotEvaluated, "patches is not a list"))
	}
	for _, p := range patches {
		r, c := a.parsePatch(p)
		s.patches, cost = append(s.patches, r), cost+c
	}
	for _, name := range []string{"patchesStrategicMerge", "patchesJson6902", "replacements", "transformers"} {
		if nonEmpty(v[name]) {
			s.gaps = append(s.gaps, g(PatchNotEvaluated, name+" is not evaluated"))
		}
	}
	if nonEmpty(v["generators"]) {
		s.gaps = append(s.gaps, g(ConstructNotEvaluated, "generators are not evaluated"))
	}
	if nonEmpty(v["helmCharts"]) {
		s.gaps = append(s.gaps, g(RemoteReferenceNotResolved, "helmCharts are not evaluated"))
	}
	if nonEmpty(v["namePrefix"]) || nonEmpty(v["nameSuffix"]) {
		s.gaps = append(s.gaps, g(ConstructNotEvaluated, "namePrefix and nameSuffix are not applied; object names may differ"))
	}
	if ns, present := v["namespace"]; present && ns != nil {
		if str, ok := ns.(string); ok {
			s.ns = str
		} else {
			s.gaps = append(s.gaps, g(ConstructNotEvaluated, "namespace is not a string"))
		}
	}
	return s, cost
}

// imageRule is one entry of a kustomize images transformer: images named
// name get newName, newTag or digest. A digest replaces the tag, a new tag
// replaces the digest.
type imageRule struct {
	name, newName, newTag, digest string
	src                           intake.Source
}

// checkRule refuses a rule whose fields could not be reported as they are.
func checkRule(r imageRule) string {
	if r.name == "" {
		return "an images entry has no name"
	}
	if strings.ContainsAny(r.name, "@") || strings.LastIndexByte(r.name, ':') > strings.LastIndexByte(r.name, '/') {
		return "an images entry name with a tag or digest is not evaluated"
	}
	if detail := badImage(ImagePin{Image: r.name + r.newName, Tag: r.newTag, Digest: r.digest}); detail != "" {
		return detail
	}
	return ""
}

// kustImages reads a kustomize images list.
func kustImages(list []any, src intake.Source, gaps *[]Gap) ([]imageRule, int) {
	g := gapAt(src)
	var rules []imageRule
	for _, e := range list {
		m := asMap(e)
		if m == nil {
			*gaps = append(*gaps, g(ConstructNotEvaluated, "an images entry is not an object"))
			continue
		}
		r := imageRule{name: asStr(m["name"]), newName: asStr(m["newName"]), digest: asStr(m["digest"]), src: src}
		if v, present := m["newTag"]; present && v != nil {
			tag, ok := scalar(v)
			if !ok {
				*gaps = append(*gaps, g(ConstructNotEvaluated, "an images entry newTag is not a string"))
				continue
			}
			r.newTag = tag
		}
		if detail := checkRule(r); detail != "" {
			*gaps = append(*gaps, g(ConstructNotEvaluated, detail))
			continue
		}
		if r.newName != "" || r.newTag != "" || r.digest != "" {
			rules = append(rules, r)
		}
	}
	return rules, len(list)
}

func badImage(p ImagePin) string {
	switch {
	case !fits(p.Image, p.Tag, p.Digest):
		return "image reference longer than 256 bytes"
	case needsEscape(p.Image + p.Tag + p.Digest):
		return "image reference holds control characters"
	}
	return ""
}

func (a *analysis) parseFlux(d *docRef) (*fluxSpec, int) {
	s, cost := &fluxSpec{}, 1
	g := gapAt(d.doc.Source)
	spec := asMap(d.doc.Value["spec"])
	ref := asMap(spec["sourceRef"])
	s.ref = fluxRef{asStr(ref["kind"]), asStr(ref["namespace"]), asStr(ref["name"])}
	s.refNsSet = s.ref.ns != ""
	if s.ref.kind == "" || s.ref.name == "" {
		gap := g(SourceNotFound, "spec.sourceRef is missing")
		s.fatal = &gap
		return s, cost
	}
	p := "./"
	if v, present := spec["path"]; present {
		str, ok := v.(string)
		if !ok {
			gap := g(SourceNotFound, "spec.path is not a string")
			s.fatal = &gap
			return s, cost
		}
		if str != "" {
			p = str
		}
	}
	s.dir, cost = a.resolve(".", p), cost+resolveCost(p)
	s.wholeRepo = s.dir.reason == "" && s.dir.path == "."
	s.bootstrap = d.doc.Name == "flux-system" && d.doc.Namespace == "flux-system" &&
		s.ref.kind == "GitRepository" && s.ref.name == "flux-system" && (s.ref.ns == "" || s.ref.ns == "flux-system")
	if v, present := spec["targetNamespace"]; present && v != nil {
		if str, ok := v.(string); ok {
			s.targetNS = str
		} else {
			s.gaps = append(s.gaps, g(ConstructNotEvaluated, "spec.targetNamespace is not a string"))
		}
	}
	components, bad := listField(spec, "components")
	if bad {
		s.gaps = append(s.gaps, g(SourceNotFound, "spec.components is not a list"))
	}
	for _, e := range components {
		cost++
		r, ok := e.(string)
		if !ok {
			s.gaps = append(s.gaps, g(SourceNotFound, "a components entry is not a string"))
			continue
		}
		if s.dir.reason == "" {
			s.components, cost = append(s.components, a.resolve(s.dir.path, r)), cost+resolveCost(r)
		}
	}
	images, bad := listField(spec, "images")
	if bad {
		s.gaps = append(s.gaps, g(ConstructNotEvaluated, "spec.images is not a list"))
	}
	var c int
	s.images, c = kustImages(images, d.doc.Source, &s.gaps)
	cost += c
	patches, bad := listField(spec, "patches")
	if bad {
		s.gaps = append(s.gaps, g(PatchNotEvaluated, "spec.patches is not a list"))
	}
	for _, p := range patches {
		r, c := a.parsePatch(p)
		s.patches, cost = append(s.patches, r), cost+c
	}
	for _, name := range []string{"patchesStrategicMerge", "patchesJson6902"} {
		if nonEmpty(spec[name]) {
			s.gaps = append(s.gaps, g(PatchNotEvaluated, name+" is not evaluated"))
		}
	}
	return s, cost
}

func (a *analysis) parseHelmRelease(d *docRef) (*hrSpec, int) {
	s := &hrSpec{}
	g := gapAt(d.doc.Source)
	spec := asMap(d.doc.Value["spec"])
	s.rel = Release{Kind: KindHelmRelease, Source: d.doc.Source, ReleaseName: asStr(spec["releaseName"])}
	s.targetNS = asStr(spec["targetNamespace"])
	if s.rel.ReleaseName == "" {
		// Flux names a release [targetNamespace-]name by default.
		s.rel.ReleaseName = d.doc.Name
		if s.targetNS != "" {
			s.rel.ReleaseName = s.targetNS + "-" + d.doc.Name
		}
		if len(s.rel.ReleaseName) > maxReleaseName {
			s.gaps = append(s.gaps, g(ConstructNotEvaluated, "the default release name is longer than 53 characters and is shortened by Flux; it is not computed"))
			s.rel.ReleaseName = ""
		}
	}
	ref := func(m map[string]any) {
		s.ref = fluxRef{asStr(m["kind"]), asStr(m["namespace"]), asStr(m["name"])}
		s.refNsSet = s.ref.ns != ""
	}
	if chartSpec := asMap(get(spec, "chart", "spec")); chartSpec != nil {
		s.rel.Chart = asStr(chartSpec["chart"])
		if v, present := chartSpec["version"]; present {
			version, ok := scalar(v)
			if !ok {
				s.gaps = append(s.gaps, g(SourceNotFound, "spec.chart.spec.version is not a string"))
				return s, 1
			}
			s.rel.ChartVersion = version
		}
		ref(asMap(chartSpec["sourceRef"]))
		if s.rel.Chart == "" || s.ref.kind == "" || s.ref.name == "" {
			s.gaps = append(s.gaps, g(SourceNotFound, "chart name or sourceRef is missing"))
			return s, 1
		}
		if nonEmpty(chartSpec["valuesFiles"]) || nonEmpty(chartSpec["valuesFile"]) {
			s.gaps = append(s.gaps, g(ValueFilesNotResolved, "spec.chart.spec.valuesFiles are not read"))
		}
	} else if cr := asMap(spec["chartRef"]); cr != nil {
		ref(cr)
		s.chartRef = true
		if s.ref.kind != "OCIRepository" || s.ref.name == "" {
			s.gaps = append(s.gaps, g(SourceNotFound, "chartRef of kind "+s.ref.kind+" is not evaluated"))
			return s, 1
		}
	} else {
		s.gaps = append(s.gaps, g(SourceNotFound, "the chart is not identified"))
		return s, 1
	}
	if v, present := spec["values"]; present && v != nil {
		if m := asMap(v); m != nil {
			s.rel.Values, s.valBytes = m, valueBytes(m, 0)
		} else {
			s.gaps = append(s.gaps, g(ValuesFromNotResolved, "spec.values is not an object"))
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
		s.gaps = append(s.gaps, g(ValuesFromNotResolved, "valuesFrom: "+strings.Join(names, ", ")))
	}
	if nonEmpty(spec["postRenderers"]) {
		s.gaps = append(s.gaps, g(PatchNotEvaluated, "spec.postRenderers are not evaluated"))
	}
	s.ok = true
	return s, 1 + s.valBytes/64
}

var podPaths = map[string][]string{
	"Pod":                   nil,
	"Deployment":            {"template", "spec"},
	"StatefulSet":           {"template", "spec"},
	"DaemonSet":             {"template", "spec"},
	"ReplicaSet":            {"template", "spec"},
	"Job":                   {"template", "spec"},
	"ReplicationController": {"template", "spec"},
	"CronJob":               {"jobTemplate", "spec", "template", "spec"},
}

func parseWorkload(d *docRef) (*imageSpec, int) {
	s, cost := &imageSpec{}, 1
	g := gapAt(d.doc.Source)
	spec := asMap(d.doc.Value["spec"])
	pod := spec
	if p := podPaths[d.doc.Kind]; p != nil {
		pod = asMap(get(spec, p...))
	}
	for _, field := range []string{"initContainers", "containers", "ephemeralContainers"} {
		for _, c := range asList(pod[field]) {
			cost++
			ref := asStr(asMap(c)["image"])
			if ref == "" {
				continue
			}
			image, tag, digest, ok := splitImage(ref)
			if !ok {
				s.gaps = append(s.gaps, g(SourceNotFound, "image reference is not understood"))
				continue
			}
			pin := ImagePin{Image: image, Tag: tag, Digest: digest, Source: d.doc.Source}
			if detail := badImage(pin); detail != "" {
				s.gaps = append(s.gaps, g(SourceNotFound, detail))
				continue
			}
			s.pins = append(s.pins, pin)
		}
	}
	return s, cost
}

func (a *analysis) parseChart(d *docRef) (*chartSpec, int) {
	s, cost := &chartSpec{}, 1
	g := gapAt(d.doc.Source)
	list, bad := listField(d.doc.Value, "dependencies")
	if bad {
		s.gaps = append(s.gaps, g(SourceNotFound, "dependencies is not a list"))
	}
	for _, e := range list {
		cost++
		m := asMap(e)
		name := asStr(m["name"])
		if name == "" {
			s.gaps = append(s.gaps, g(SourceNotFound, "a dependency has no name"))
			continue
		}
		repo := asStr(m["repository"])
		if local, ok := strings.CutPrefix(repo, "file://"); ok {
			// A chart inside this repository: its own Chart.yaml is read.
			s.files, cost = append(s.files, a.resolve(d.dir, local)), cost+resolveCost(local)
			continue
		}
		version, _ := scalar(m["version"])
		release := name
		if alias := asStr(m["alias"]); alias != "" {
			release = alias
		}
		s.deps = append(s.deps, Release{Kind: KindChartDependency, Chart: name, ChartVersion: version, RepoURL: repo, ReleaseName: release, Source: d.doc.Source})
	}
	return s, cost
}

func (a *analysis) parseArgo(d *docRef) (*argoSpec, int) {
	s, cost := &argoSpec{}, 1
	g := gapAt(d.doc.Source)
	spec := asMap(d.doc.Value["spec"])
	var sources []any
	if l, bad := listField(spec, "sources"); bad {
		s.gaps = append(s.gaps, g(SourceNotFound, "spec.sources is not a list"))
	} else if len(l) > 0 {
		sources = l
	} else if src := spec["source"]; src != nil {
		sources = []any{src}
	}
	if len(sources) == 0 {
		s.gaps = append(s.gaps, g(SourceNotFound, "the Application has no source"))
		return s, cost
	}
	if len(sources) > MaxSources {
		s.gaps = append(s.gaps, g(ClosureLimit, "more than 64 sources; the rest are not evaluated"))
		sources = sources[:MaxSources]
	}
	destNS := asStr(get(spec, "destination", "namespace"))
	for _, e := range sources {
		cost++
		src := a.parseArgoSource(d, asMap(e), destNS)
		s.sources, cost = append(s.sources, src), cost+src.cost
	}
	return s, cost
}

func (a *analysis) revisionIsSelf(rev string) bool {
	return rev == "" || rev == "HEAD" || a.revisions[rev]
}

func (a *analysis) parseArgoSource(d *docRef, m map[string]any, destNS string) *argoSrc {
	s := &argoSrc{}
	g := gapAt(d.doc.Source)
	add := func(reason, detail string) { s.gaps = append(s.gaps, g(reason, detail)) }
	if m == nil {
		add(SourceNotFound, "a source is not an object")
		return s
	}
	repo := asStr(m["repoURL"])
	chart := asStr(m["chart"])
	rev, revOK := scalar(m["targetRevision"])
	if v, present := m["targetRevision"]; present && v != nil && !revOK {
		add(ConstructNotEvaluated, "targetRevision is not a string")
		return s
	}
	helm := asMap(m["helm"])
	if nonEmpty(m["plugin"]) {
		add(ConstructNotEvaluated, "a config management plugin is not evaluated")
		return s
	}
	if nonEmpty(helm["parameters"]) {
		add(ValuesFromNotResolved, "helm.parameters override values and are not evaluated")
	}
	if nonEmpty(helm["valueFiles"]) || nonEmpty(helm["fileParameters"]) {
		add(ValueFilesNotResolved, "helm value files are not read")
	}
	pth, hasPath := m["path"].(string)
	switch {
	case chart != "":
		s.kind = argoChart
		release := asStr(helm["releaseName"])
		if release == "" {
			release = d.doc.Name
		}
		s.rel = Release{Kind: KindApplication, Chart: chart, ChartVersion: rev, RepoURL: repo, Namespace: destNS, ReleaseName: release, Source: d.doc.Source}
		obj, hasObj := helm["valuesObject"]
		text, hasText := helm["values"].(string)
		switch {
		case hasObj && hasText && text != "":
			add(ValuesFromNotResolved, "helm.values and helm.valuesObject are both set")
		case hasObj:
			if s.object = asMap(obj); s.object == nil {
				add(ValuesFromNotResolved, "helm.valuesObject is not an object")
			}
		case hasText && strings.TrimSpace(text) != "":
			s.text = text
		}
	case hasPath:
		s.kind = argoPath
		if !a.isSelf(repo) {
			add(RemoteReferenceNotResolved, "repoURL "+repo+" is not this repository")
			return s
		}
		if !a.revisionIsSelf(rev) {
			add(RemoteReferenceNotResolved, "targetRevision "+rev+" is not the checked-out revision")
			return s
		}
		s.dir, s.cost = a.resolve(".", pth), resolveCost(pth)
		if s.dir.reason != "" {
			add(s.dir.reason, s.dir.detail)
			return s
		}
		if nonEmpty(helm["values"]) || nonEmpty(helm["valuesObject"]) {
			add(ValuesFromNotResolved, "values of a local chart are not attached to a release")
		}
		dir := asMap(m["directory"])
		if r, present := dir["recurse"]; present {
			b, ok := r.(bool)
			if !ok {
				add(ConstructNotEvaluated, "directory.recurse is not a boolean")
			}
			s.recurse = b
		}
		for _, name := range []string{"include", "exclude", "jsonnet"} {
			if nonEmpty(dir[name]) {
				add(ConstructNotEvaluated, "directory."+name+" is not evaluated")
			}
		}
		k := asMap(m["kustomize"])
		for _, e := range asList(k["images"]) {
			text, ok := e.(string)
			if !ok {
				add(SourceNotFound, "a kustomize image entry is not a string")
				continue
			}
			name := ""
			if i := strings.IndexByte(text, '='); i >= 0 {
				name, text = text[:i], text[i+1:]
			}
			image, tag, digest, ok := splitImage(text)
			if !ok {
				add(ConstructNotEvaluated, "a kustomize image entry is not understood")
				continue
			}
			r := imageRule{name: name, newName: image, newTag: tag, digest: digest, src: d.doc.Source}
			if name == "" || name == image {
				r.name, r.newName = image, ""
			}
			if detail := checkRule(r); detail != "" {
				add(ConstructNotEvaluated, detail)
				continue
			}
			s.images = append(s.images, r)
		}
		s.ns = asStr(k["namespace"])
		if nonEmpty(k["namePrefix"]) || nonEmpty(k["nameSuffix"]) {
			add(ConstructNotEvaluated, "kustomize namePrefix and nameSuffix are not applied; object names may differ")
		}
		if nonEmpty(k["patches"]) {
			add(PatchNotEvaluated, "kustomize patches of the source are not evaluated")
		}
		if nonEmpty(k["components"]) {
			add(ConstructNotEvaluated, "kustomize components of the source are not followed")
		}
		s.follow = true
	case m["ref"] != nil:
		s.kind = argoRef
		if !a.isSelf(repo) {
			add(RemoteReferenceNotResolved, "ref source repoURL "+repo+" is not this repository")
		} else if !a.revisionIsSelf(rev) {
			add(RemoteReferenceNotResolved, "ref source targetRevision "+rev+" is not the checked-out revision")
		}
	default:
		add(SourceNotFound, "a source has neither chart, path nor ref")
	}
	return s
}

// structuralTokens is a cheap upper bound on the YAML nodes in text, the same
// bound intake applies before decoding.
func structuralTokens(text string) int {
	count := 1
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '[', '{', ',', ':', '\n', '\r':
			count++
		case '-':
			if i+1 == len(text) || strings.IndexByte(" \n\r\t", text[i+1]) >= 0 {
				count++
			}
		}
	}
	return count
}

// valueBytes is the text size of a decoded value: keys, scalars and a few
// bytes of punctuation per node.
func valueBytes(v any, depth int) int {
	if depth > intake.MaxDepth+2 {
		return 0
	}
	switch t := v.(type) {
	case map[string]any:
		n := 2
		for k, c := range t {
			n += len(k) + 2 + valueBytes(c, depth+1)
		}
		return n
	case []any:
		n := 2
		for _, c := range t {
			n += 1 + valueBytes(c, depth+1)
		}
		return n
	case string:
		return len(t) + 2
	}
	return 8
}

func countNodes(v any) int {
	n := 1
	switch t := v.(type) {
	case map[string]any:
		for _, c := range t {
			n += countNodes(c)
		}
	case []any:
		for _, c := range t {
			n += countNodes(c)
		}
	}
	return n
}

// decodeText decodes an inline YAML text against the shared node budget. The
// second result is a gap detail when the budget does not allow it.
func (a *analysis) decodeText(text string) ([]any, string, error) {
	if structuralTokens(text) > a.nodes {
		return nil, "the budget of 500000 YAML nodes for inline values and patches is used up", nil
	}
	docs, err := intake.DecodeDocuments([]byte(text))
	if err != nil {
		return nil, "", err
	}
	for _, d := range docs {
		a.nodes -= countNodes(d)
	}
	return docs, "", nil
}

// argoValues decodes a helm.values text once; the decoded map is shared.
func (a *analysis) argoValues(s *argoSrc) (map[string]any, *Gap, int) {
	if s.decoded {
		return s.values, s.valGap, 0
	}
	s.decoded = true
	if s.object != nil {
		s.values, s.rel.Values, s.valBytes = s.object, s.object, valueBytes(s.object, 0)
		return s.values, nil, s.valBytes / 64
	}
	if s.text == "" {
		return nil, nil, 0
	}
	g := gapAt(s.rel.Source)
	cost := 1 + len(s.text)/64
	if len(s.text) > MaxValuesBytes {
		gap := g(ValuesFromNotResolved, "helm.values is longer than 65536 bytes")
		s.valGap = &gap
		return nil, s.valGap, 1
	}
	docs, limit, err := a.decodeText(s.text)
	switch {
	case limit != "":
		gap := g(ClosureLimit, limit+"; helm.values not read")
		s.valGap = &gap
	case err != nil || len(docs) != 1 || asMap(docs[0]) == nil:
		gap := g(ValuesFromNotResolved, "helm.values is not a single YAML object")
		s.valGap = &gap
	default:
		s.values = asMap(docs[0])
		s.rel.Values, s.valBytes = s.values, valueBytes(s.values, 0)
	}
	s.text = ""
	return s.values, s.valGap, cost
}
