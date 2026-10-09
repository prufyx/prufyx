// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The full-tree scan (completeness condition Q2): at every tag the
// extractor reads, every directory of the repository is listed, and every
// YAML or JSON file, every template, jsonnet or cue source, and every Go
// source whose path names "crd" outside the listed paths is read and
// searched for CustomResourceDefinition content. Helm chart dependencies
// and remote kustomize resources (definitions that come from another
// repository) are found as well. Each such file is classified against the
// tag's inventory and its location (the open tree, a default-excluded
// directory such as examples/ or test/, or a reviewed exclusion). Only a
// clean scan lets a disappeared definition count as removed, and only a
// pair whose every tag scans clean is attestable.

// Finding classes.
const (
	// ClassCopy: every definition in the file is in the inventory with the
	// same versions and served flags.
	ClassCopy = "copy"
	// ClassSchemaPatch: a kustomization whose only CustomResourceDefinition
	// references are patch targets, and whose patches only touch version
	// schemas or metadata labels and annotations.
	ClassSchemaPatch = "schema-patch"
	// ClassConflict: a definition of an inventory CRD with other versions
	// or served flags. In the open tree the pair is withheld (at an
	// anchor) or not line-wide; elsewhere it blocks attestation.
	ClassConflict = "conflict"
	// ClassExtra: a definition the inventory does not hold.
	ClassExtra = "extra"
	// ClassReference: the file holds the CustomResourceDefinition kind as a
	// value (a nested object, a kind field, an embedded manifest) but
	// defines none at the top level, and is not a schema-only
	// kustomization.
	ClassReference = "reference"
	// ClassUnread: names the kind and is templated, not strictly
	// decodable, over the bounds, or a submodule.
	ClassUnread = "unread"
	// ClassUnsupported: a source the scan does not parse that names the
	// kind (a template, jsonnet or cue file, Go code that constructs a
	// definition, a packaged Helm chart).
	ClassUnsupported = "unsupported"
	// ClassExternal: a Helm chart dependency or a kustomize resource that
	// comes from another repository; its definitions are not read.
	ClassExternal = "external"
	// ClassExcluded: a CRD-like file under a reviewed exclusion, recorded
	// (with the definitions it holds); it does not block attestation.
	ClassExcluded = "excluded"
	// ClassExcludedUnread: a file under a reviewed exclusion whose content
	// could not be read. It does not block attestation, but a definition
	// cannot be established to be gone while one exists.
	ClassExcludedUnread = "excluded-unread"
)

// Scan bounds.
const (
	// MaxScanFilesPerTag bounds the candidate files read at one tag.
	MaxScanFilesPerTag = 100000
	// MaxScanDirsPerTag bounds the directories listed at one tag.
	MaxScanDirsPerTag = 50000
	// maxKustomizePatches bounds the patch files one kustomization names.
	maxKustomizePatches = 64
	// maxExternalSources bounds the external sources named in one finding.
	maxExternalSources = 16
	// placeholder replaces a template expression inside a line when a
	// checked copy is read.
	placeholder = "TEMPLATED"
	// fileWord stands for the file in a reason recorded for its bytes:
	// a reason never names a path, because the same bytes may lie at many.
	fileWord = "the file"
)

// What a candidate file is, by its name.
const (
	kindNone = iota
	// kindData: YAML or JSON (decoded), or a file named Kustomization.
	kindData
	// kindSource: a template, jsonnet or cue source (searched only).
	kindSource
	// kindGo: Go source whose path names crd (searched only).
	kindGo
	// kindPackagedChart: a .tgz in a directory named charts (not read).
	kindPackagedChart
)

var (
	dataNameRE   = regexp.MustCompile(`(?i)\.(ya?ml|json)$`)
	sourceNameRE = regexp.MustCompile(`(?i)\.(tmpl|tpl|gotmpl|jsonnet|libsonnet|cue|j2|jinja|jinja2)$`)
	crdPathRE    = regexp.MustCompile(`(?i)crd`)
	// wordRE is the bare kind name, anywhere.
	wordRE = regexp.MustCompile(`CustomResourceDefinition`)
	// kindValueRE is the kind as the value of a kind key, on the same line
	// or the next one: what makes undecodable bytes CRD-like (a mention in
	// a comment or a description is not).
	kindValueRE = regexp.MustCompile(`["']?\bkind["']?[ \t]*:[ \t]*(\r?\n[ \t-]*)?["']?CustomResourceDefinition\b`)
	// embeddedKindRE is a manifest line naming the kind, inside a string.
	embeddedKindRE = regexp.MustCompile(`(?m)^[ \t-]*["']?kind["']?[ \t]*:[ \t]*["']?CustomResourceDefinition\b`)
	// goConstructRE is Go code that builds a definition, its spec or a
	// version as a composite literal with fields.
	goConstructRE = regexp.MustCompile(`CustomResourceDefinition(Spec|Version|Names)?\{\s*[A-Z][A-Za-z0-9]*\s*:`)
	// sourceKeysRE marks a file that may name another repository: a Helm
	// chart's dependencies or a kustomization's resources.
	sourceKeysRE = regexp.MustCompile(`(?m)^(dependencies|resources|components|bases)[ \t]*:`)
	patchPathRE  = regexp.MustCompile(`^/(spec/versions/(0|[1-9][0-9]{0,2})/schema|metadata/(annotations|labels))(/[^\x00-\x1f]*)?$`)
	templateRE   = regexp.MustCompile(`\{\{.*?\}\}`)
	valueExprRE  = regexp.MustCompile(`^(\s*[^\s#{][^:{]*:)\s*\{\{[^{}]*\}\}\s*$`)
)

func indentOf(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

// NotRead are the files the scan does not read, recorded in every scan.
var NotRead = []string{
	"files that are not YAML, JSON, template, jsonnet, cue or Go sources, or packaged Helm charts",
	"Go sources whose path does not contain crd, Go test files (_test.go), and Go sources under a default-excluded directory or a reviewed exclusion",
	"symbolic links (the install-surface guard does not follow them either), shell scripts, CI configuration and Go code that opens a path at run time",
}

// ScanRecord is what the full-tree scan found at one commit.
type ScanRecord struct {
	// Complete is false when the scan could not be finished (a bound).
	Complete bool   `json:"complete"`
	Problem  string `json:"problem,omitempty"`
	// Files is the number of candidate files read; DefaultFiles and
	// ExcludedFiles are the ones of them under a default-excluded
	// directory and under a reviewed exclusion.
	Files         int `json:"files"`
	DefaultFiles  int `json:"defaultFiles"`
	ExcludedFiles int `json:"excludedFiles"`
	// Exclusions are the default segments and reviewed entries that hold
	// a candidate file, sorted.
	Exclusions []string `json:"exclusions"`
	// NotRead are the kinds of files the scan does not read.
	NotRead []string `json:"notRead"`
	// Copies are the files of class copy, sorted.
	Copies []string `json:"copies"`
	// Findings are the files of every other class, sorted by path.
	Findings []Finding `json:"findings"`
}

// Finding is one file outside the listed paths with CRD-like content, or
// one that names another repository's definitions.
type Finding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Class  string `json:"class"`
	// Location is "" in the open tree, "default: <name>" under a
	// default-excluded directory, "void: <entry>" under a reviewed
	// exclusion that does not hold at the release, or the reviewed
	// exclusion entry.
	Location string   `json:"location,omitempty"`
	CRDs     []string `json:"crds,omitempty"`
	// Served are the members the file's definitions serve.
	Served []string `json:"served,omitempty"`
	Detail string   `json:"detail,omitempty"`
}

// blocks reports whether a finding keeps the scan from being clean.
func (f Finding) blocks() bool {
	switch f.Class {
	case ClassSchemaPatch, ClassExcluded, ClassExcludedUnread:
		return false
	}
	return true
}

// opaque reports whether a finding's content is not known: a definition
// may hide in it.
func (f Finding) opaque() bool {
	switch f.Class {
	case ClassUnread, ClassUnsupported, ClassExternal, ClassReference, ClassExcludedUnread:
		return true
	}
	return false
}

// defaultLike reports a finding in a place the project does not normally
// install from by its name: a default-excluded directory, or an unread file
// under a reviewed exclusion that also lies in one (a test-fixture entry
// such as test/e2e/manifests/; the reviewer's evidence only adds to what
// the directory name says). A void entry is not default-like: the files may
// be installed.
func (f Finding) defaultLike() bool {
	return strings.HasPrefix(f.Location, "default: ") || (f.Class == ClassExcludedUnread && defaultSegment(f.Path) != "")
}

// unreadable reports a finding that may serve, to the users of a release,
// a version the inventory does not show: a templated, unreadable or
// unsupported CRD source in the open tree or among declared copies, or a
// declared copy (a chart template) that serves other versions. A file
// under a default-excluded directory only blocks attestation.
func (f Finding) unreadable() bool {
	if strings.HasPrefix(f.Location, "default: ") || strings.HasPrefix(f.Location, voidPrefix) {
		return false
	}
	switch f.Class {
	case ClassUnread, ClassUnsupported, ClassConflict:
		return true
	}
	return false
}

// Clean reports a complete scan with nothing but copies, schema-only
// kustomizations and reviewed exclusions.
func (s *ScanRecord) Clean() bool {
	if s == nil || !s.Complete {
		return false
	}
	for _, f := range s.Findings {
		if f.blocks() {
			return false
		}
	}
	return true
}

// conflicts returns the conflict findings in the open tree.
func (s *ScanRecord) conflicts() []Finding {
	var out []Finding
	if s == nil {
		return nil
	}
	for _, f := range s.Findings {
		if f.Class == ClassConflict && f.Location == "" {
			out = append(out, f)
		}
	}
	return out
}

// unreadable returns the findings that may serve versions the inventory
// does not show.
func (s *ScanRecord) unreadable() []Finding {
	var out []Finding
	if s == nil {
		return nil
	}
	for _, f := range s.Findings {
		if f.unreadable() {
			out = append(out, f)
		}
	}
	return out
}

// holds reports whether the scan cannot exclude a definition of name: an
// incomplete scan, a file that defines it, or a file outside the
// default-excluded directories whose content is not known. An unreadable
// test or example file there only blocks attestation: a definition the
// project installs does not move into one in a form the scan cannot read,
// and a removed definition is never a rule.
func (s *ScanRecord) holds(name string) bool {
	if s == nil || !s.Complete {
		return true
	}
	for _, f := range s.Findings {
		if slicesContains(f.CRDs, name) || (f.opaque() && !f.defaultLike()) {
			return true
		}
	}
	return false
}

// blobInfo is what one file's bytes say. It never depends on the path the
// bytes were found at (the same blob may lie at many paths, and is read
// once): every path-dependent decision is taken in classify.
type blobInfo struct {
	sha256 string
	// words counts the bare kind name.
	words int
	// unread is why the bytes could not be decoded ("" when they could or
	// were not decoded).
	unread string
	// decoded is set when the bytes were decoded.
	decoded bool
	// kindLike: the bytes hold the kind as the value of a kind key.
	kindLike bool
	crds     []CRD
	// kinds counts the mappings whose kind is CustomResourceDefinition,
	// at any depth; embedded is set when a string value holds a manifest
	// line naming the kind.
	kinds    int
	embedded bool
	// kust is the bytes read as a kustomization (nil when they are not a
	// single mapping of kind Kustomization or none).
	kust *kustomization
	// chartDeps are the dependencies of the bytes read as a Helm
	// Chart.yaml that come from another repository.
	chartDeps []string
	// template is the result of reading the bytes as a checked copy, with
	// template directives removed (nil when the bytes hold no template
	// syntax or no kind name).
	template *templateRead
	// goConstruct: Go code that builds a definition.
	goConstruct bool
}

// templateRead is a templated file read as a copy.
type templateRead struct {
	unread string
	crds   []CRD
}

// kustomization is a decoded kustomization file's patch references and
// remote sources.
type kustomization struct {
	// crdTargets counts the patch entries whose target kind is
	// CustomResourceDefinition; patchPaths are their files (relative to
	// the kustomization's directory).
	crdTargets int
	patchPaths []string
	// problem is why a CRD patch entry cannot be checked ("" when every
	// one names a local file).
	problem string
	// remote are the resources, components and bases from another
	// repository.
	remote []string
}

type scanFile struct {
	path, oid string
	kind      int
	at        place
}

// fileKind decides what a tree entry is to the scan.
func fileKind(p string, at place) int {
	name := path.Base(p)
	switch {
	case dataNameRE.MatchString(name) || name == "Kustomization":
		return kindData
	case sourceNameRE.MatchString(name):
		return kindSource
	case strings.HasSuffix(name, ".go"):
		if (at.kind != locTree && !at.void) || strings.HasSuffix(name, "_test.go") || !crdPathRE.MatchString(p) {
			return kindNone
		}
		return kindGo
	case strings.HasSuffix(strings.ToLower(name), ".tgz") && path.Base(path.Dir(p)) == "charts":
		return kindPackagedChart
	}
	return kindNone
}

// scan walks the whole tree at commit. Reader errors abort (the mirror
// must hold every file); bounds make the record incomplete.
func (x *Extractor) scan(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, commit string, inv *Inventory) (*ScanRecord, error) {
	x.mu.Lock()
	if s, ok := x.scans[commit]; ok {
		x.mu.Unlock()
		return s, nil
	}
	x.mu.Unlock()
	rec := &ScanRecord{Complete: true, Exclusions: []string{}, NotRead: append([]string{}, NotRead...), Copies: []string{}, Findings: []Finding{}}
	declared := x.declaredFiles(inv)
	hits := map[string]bool{}
	var blobs []extract.TreeEntry
	var commits []string
	dirs := []string{""}
	listed := 0
	for len(dirs) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if listed++; listed > MaxScanDirsPerTag {
			rec.Complete, rec.Problem = false, fmt.Sprintf("more than %d directories", MaxScanDirsPerTag)
			return x.storeScan(commit, rec), nil
		}
		dir := dirs[0]
		dirs = dirs[1:]
		entries, err := r.List(repo, commit, dir)
		if err != nil {
			return nil, fmt.Errorf("scan listing %q at %s: %w", dir, commit, err)
		}
		for _, e := range entries {
			switch e.Type {
			case "tree":
				dirs = append(dirs, e.Path)
			case "commit":
				commits = append(commits, e.Path)
			case "blob":
				blobs = append(blobs, e)
			}
		}
	}
	// The install-surface guard: a reviewed exclusion that something
	// installing refers to does not hold at this tag.
	voids, voided, err := x.guard(ctx, r, repo, commit, blobs, commits)
	if err != nil {
		return nil, err
	}
	tg := x.target.withVoided(voided)
	rec.Findings = append(rec.Findings, voids...)
	var files []scanFile
	for _, p := range commits {
		at := tg.placeOf(p)
		if at.kind != locTree {
			hits[at.entry] = true
		}
		rec.Findings = append(rec.Findings, placed(Finding{Path: p, Class: ClassUnread, Detail: "a submodule: its files are not in this repository"}, at))
	}
	for _, e := range blobs {
		if e.Mode == "120000" || declared[e.Path] {
			continue
		}
		at := tg.placeOf(e.Path)
		kind := fileKind(e.Path, at)
		if kind == kindNone {
			continue
		}
		if at.kind != locTree {
			hits[at.entry] = true
		}
		if kind == kindPackagedChart {
			rec.Findings = append(rec.Findings, placed(Finding{Path: e.Path, Class: ClassUnsupported, Detail: "a packaged Helm chart: its files are not read"}, at))
			continue
		}
		files = append(files, scanFile{path: e.Path, oid: e.SHA, kind: kind, at: at})
	}
	if len(files) > MaxScanFilesPerTag {
		rec.Complete, rec.Problem = false, fmt.Sprintf("%d candidate files, over the bound of %d", len(files), MaxScanFilesPerTag)
		return x.storeScan(commit, rec), nil
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	rec.Files = len(files)
	for _, f := range files {
		switch f.at.kind {
		case locDefault:
			rec.DefaultFiles++
		case locReviewed:
			rec.ExcludedFiles++
		}
	}
	infos := make([]*blobInfo, len(files))
	errs := make([]error, len(files))
	x.parallel(len(files), func(i int) {
		infos[i], errs[i] = x.blob(r, repo, commit, files[i])
	})
	for i, f := range files {
		if errs[i] != nil {
			return nil, errs[i]
		}
		fd, found, err := x.classify(r, repo, commit, f, infos[i], inv)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		if fd.Class == ClassCopy {
			rec.Copies = append(rec.Copies, f.path)
			continue
		}
		rec.Findings = append(rec.Findings, fd)
	}
	for h := range hits {
		rec.Exclusions = append(rec.Exclusions, h)
	}
	sort.Strings(rec.Exclusions)
	sort.Slice(rec.Findings, func(i, j int) bool { return rec.Findings[i].Path < rec.Findings[j].Path })
	return x.storeScan(commit, rec), nil
}

// placed records a finding's location. Under a reviewed exclusion that
// does not declare copies a finding is recorded, never blocking: excluded
// when its content is known, excluded-unread otherwise. Under one that
// declares copies every class keeps its effect.
func placed(f Finding, at place) Finding {
	if at.kind == locTree {
		return f
	}
	f.Location = at.entry
	if at.kind != locReviewed || at.copies {
		return f
	}
	switch f.Class {
	case ClassCopy, ClassSchemaPatch:
	case ClassUnread, ClassUnsupported:
		f.Class = ClassExcludedUnread
	default:
		f.Class = ClassExcluded
	}
	return f
}

func (x *Extractor) storeScan(commit string, rec *ScanRecord) *ScanRecord {
	x.mu.Lock()
	defer x.mu.Unlock()
	if s, ok := x.scans[commit]; ok {
		return s
	}
	x.scans[commit] = rec
	return rec
}

// declaredFiles are the files the inventory read: the scan does not read
// them again.
func (x *Extractor) declaredFiles(inv *Inventory) map[string]bool {
	out := map[string]bool{}
	if inv != nil {
		for _, f := range inv.Files {
			out[f.Path] = true
		}
	}
	for _, p := range x.target.Paths {
		if !p.Dir {
			out[p.Path] = true
		}
	}
	return out
}

// blob reads one file (or reuses an earlier read of the same blob id) and
// summarises it. The summary depends only on the bytes and the kind of
// file, so the cache is keyed by both and any read of the blob may fill it.
func (x *Extractor) blob(r extract.PinnedReader, repo extract.RepoRef, commit string, f scanFile) (*blobInfo, error) {
	key := fmt.Sprintf("%d:%s", f.kind, f.oid)
	x.mu.Lock()
	info, ok := x.blobs[key]
	x.mu.Unlock()
	if ok && f.oid != "" {
		if _, reused := extract.Reuse(r, repo, commit, f.path, f.oid); reused {
			return info, nil
		}
	}
	data, err := r.Read(repo, commit, f.path)
	if err != nil {
		return nil, fmt.Errorf("scan reading %s at %s: %w", f.path, commit, err)
	}
	info = summarize(f.kind, data)
	if f.oid != "" {
		x.mu.Lock()
		if prev, ok := x.blobs[key]; ok {
			info = prev
		} else {
			x.blobs[key] = info
		}
		x.mu.Unlock()
	}
	return info, nil
}

// summarize decides what a file's bytes hold. It is a function of the
// bytes and the file kind only.
func summarize(kind int, data []byte) *blobInfo {
	sum := sha256.Sum256(data)
	info := &blobInfo{sha256: "sha256:" + hex.EncodeToString(sum[:])}
	info.words = len(wordRE.FindAllIndex(data, -1))
	switch kind {
	case kindSource:
		return info
	case kindGo:
		info.goConstruct = info.words > 0 && goConstructRE.Match(data)
		return info
	}
	if info.words == 0 && !sourceKeysRE.Match(data) {
		return info
	}
	info.decoded = true
	info.kindLike = kindValueRE.Match(data)
	_, crds, values, err := parseValues(fileWord, data)
	if err != nil {
		if pr, ok := asProblem(err); ok {
			info.unread = pr.msg
		} else {
			info.unread = err.Error()
		}
		if info.words > 0 && bytes.Contains(data, []byte(templateMarker)) {
			info.template = readTemplate(data)
		}
		return info
	}
	for i := range crds {
		crds[i].Path = ""
	}
	info.crds = crds
	for _, v := range values {
		countKinds(v, info)
	}
	if len(values) == 1 {
		if obj, ok := values[0].(map[string]any); ok {
			info.kust = readKustomization(obj)
			info.chartDeps = externalChartDeps(obj)
		}
	}
	return info
}

// countKinds counts kind: CustomResourceDefinition at any depth and notes
// manifests embedded in strings.
func countKinds(v any, info *blobInfo) {
	switch t := v.(type) {
	case map[string]any:
		if k, _ := t["kind"].(string); k == crdKind {
			info.kinds++
		}
		for _, c := range t {
			countKinds(c, info)
		}
	case []any:
		for _, c := range t {
			countKinds(c, info)
		}
	case string:
		if embeddedKindRE.MatchString(t) {
			info.embedded = true
		}
	}
}

// readTemplate reads a templated file as a copy: lines that hold only a
// template directive are removed and every other template expression is
// replaced by a placeholder. Anything left that is not a complete
// definition is unread.
func readTemplate(data []byte) *templateRead {
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "{{") && strings.HasSuffix(t, "}}") && strings.Count(t, "{{") == 1 {
			continue
		}
		kept = append(kept, line)
	}
	var b strings.Builder
	for i, line := range kept {
		// A key whose whole value is an expression followed by more
		// indented lines (labels: {{- include ... | nindent 4 }}) keeps
		// its literal children: the expression adds entries to them.
		if m := valueExprRE.FindStringSubmatch(line); m != nil && i+1 < len(kept) && indentOf(kept[i+1]) > indentOf(line) && strings.TrimSpace(kept[i+1]) != "" {
			line = m[1]
		}
		line = templateRE.ReplaceAllString(line, placeholder)
		// A closing "}}" alone is text (a brace in a description); an
		// opening "{{" left over starts an expression that spans lines.
		if strings.Contains(line, "{{") {
			return &templateRead{unread: "a template expression spans lines"}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	_, crds, err := parseFile(fileWord, []byte(b.String()))
	if err != nil {
		msg := err.Error()
		if pr, ok := asProblem(err); ok {
			msg = pr.msg
		}
		return &templateRead{unread: "with template directives removed, " + msg}
	}
	for i := range crds {
		crds[i].Path = ""
	}
	return &templateRead{crds: crds}
}

// remoteSource reports a kustomize resource or chart repository that lies
// in another repository.
func remoteSource(s string) bool {
	s = strings.TrimSpace(s)
	switch {
	case s == "" || strings.HasPrefix(s, "file://"):
		return false
	case strings.Contains(s, "://"), strings.HasPrefix(s, "git@"), strings.HasPrefix(s, "github.com/"), strings.HasPrefix(s, "gitlab.com/"), strings.HasPrefix(s, "bitbucket.org/"), strings.Contains(s, "?ref="), strings.HasPrefix(s, "@"), strings.HasPrefix(s, "oci:"):
		return true
	}
	return false
}

// externalChartDeps lists the dependencies of a Chart.yaml mapping that
// come from another repository (a repository other than a local file://
// path or none).
func externalChartDeps(obj map[string]any) []string {
	deps, ok := obj["dependencies"].([]any)
	if !ok {
		return nil
	}
	if _, chart := obj["apiVersion"]; !chart {
		return nil
	}
	var out []string
	for _, d := range deps {
		m, ok := d.(map[string]any)
		if !ok {
			out = append(out, "a dependency that is not a mapping")
			continue
		}
		repo, _ := m["repository"].(string)
		if !remoteSource(repo) {
			continue
		}
		name, _ := m["name"].(string)
		version, _ := m["version"].(string)
		out = append(out, fmt.Sprintf("%s %s from %s", name, version, repo))
	}
	sort.Strings(out)
	return out
}

func isKustomizationName(base string) bool {
	return base == "kustomization.yaml" || base == "kustomization.yml" || base == "Kustomization"
}

// classify places a candidate file against the inventory of its tag and
// its location. found is false when the file holds nothing CRD-like and
// names no other repository.
func (x *Extractor) classify(r extract.PinnedReader, repo extract.RepoRef, commit string, f scanFile, info *blobInfo, inv *Inventory) (Finding, bool, error) {
	fd := Finding{Path: f.path, SHA256: info.sha256}
	base := path.Base(f.path)
	isKust := isKustomizationName(base)
	isChart := base == "Chart.yaml"
	switch f.kind {
	case kindSource:
		if info.words == 0 {
			return fd, false, nil
		}
		fd.Class, fd.Detail = ClassUnsupported, "a template, jsonnet or cue source that names the CustomResourceDefinition kind: it is not read"
		return placed(fd, f.at), true, nil
	case kindGo:
		if !info.goConstruct {
			return fd, false, nil
		}
		fd.Class, fd.Detail = ClassUnsupported, "Go code that constructs a CustomResourceDefinition: definitions built in code are not read"
		return placed(fd, f.at), true, nil
	}
	if !info.decoded {
		return fd, false, nil
	}
	var external []string
	switch {
	case isChart:
		external = info.chartDeps
	case isKust && info.kust != nil:
		external = info.kust.remote
	}
	switch {
	case info.unread != "" && f.at.copies && info.template != nil:
		// A checked copy that is templated: read without its directives.
	case info.unread != "" && (info.kindLike || isChart || isKust):
		fd.Class, fd.Detail = ClassUnread, info.unread
		return placed(fd, f.at), true, nil
	case info.unread != "":
		return fd, false, nil
	case len(external) > 0:
		if len(external) > maxExternalSources {
			external = append(external[:maxExternalSources:maxExternalSources], fmt.Sprintf("and %d more", len(external)-maxExternalSources))
		}
		what := "a Helm chart dependency"
		if !isChart {
			what = "a kustomize resource"
		}
		fd.Class, fd.Detail = ClassExternal, fmt.Sprintf("%s from another repository, whose definitions are not read: %s", what, strings.Join(external, "; "))
		return placed(fd, f.at), true, nil
	}
	crds := info.crds
	if info.unread != "" {
		// Only a templated checked copy reaches here.
		if info.template.unread != "" {
			// A checked copy that cannot be read is never accepted.
			fd.Class, fd.Detail = ClassUnread, info.template.unread
			return placed(fd, f.at), true, nil
		}
		crds = info.template.crds
	}
	if info.words == 0 {
		return fd, false, nil
	}
	if len(crds) == 0 {
		if info.kinds == 0 && !info.embedded {
			// The kind name only appears in text (a comment, a
			// description, a key).
			return fd, false, nil
		}
		if isKust && info.kust != nil && !info.embedded {
			why, err := x.checkKustomization(r, repo, commit, f.path, info)
			if err != nil {
				return fd, false, err
			}
			if why == "" {
				fd.Class = ClassSchemaPatch
				return placed(fd, f.at), true, nil
			}
			fd.Class, fd.Detail = ClassReference, why
			return placed(fd, f.at), true, nil
		}
		fd.Class, fd.Detail = ClassReference, "holds the CustomResourceDefinition kind but defines none at the top level"
		return placed(fd, f.at), true, nil
	}
	fd = compareDefinitions(fd, crds, inv)
	if f.at.copies && fd.Class == ClassExtra {
		// The reviewer states these are copies: the claim is checked.
		fd.Detail = "a declared copy that defines a CustomResourceDefinition the listed paths do not hold"
	}
	return placed(fd, f.at), true, nil
}

// compareDefinitions classifies the definitions of one file against the
// inventory: copy, extra or conflict.
func compareDefinitions(fd Finding, crds []CRD, inv *Inventory) Finding {
	byName := map[string]*CRD{}
	if inv != nil {
		for i := range inv.CRDs {
			byName[inv.CRDs[i].Name] = &inv.CRDs[i]
		}
	}
	fd.Class = ClassCopy
	for i := range crds {
		c := &crds[i]
		fd.CRDs = append(fd.CRDs, c.Name)
		for _, v := range c.Versions {
			if v.Served {
				fd.Served = append(fd.Served, member(c.Group, v.Name, c.Kind))
			}
		}
		known, ok := byName[c.Name]
		switch {
		case !ok:
			if fd.Class == ClassCopy {
				fd.Class = ClassExtra
			}
		case !sameServing(known, c):
			fd.Class = ClassConflict
			fd.Detail = fmt.Sprintf("%s: versions %s here, %s in %s", c.Name, servingString(c), servingString(known), known.Path)
		}
	}
	sort.Strings(fd.CRDs)
	sort.Strings(fd.Served)
	if fd.Class == ClassCopy {
		fd.CRDs, fd.Served = nil, nil
	}
	return fd
}

// sameServing reports equal group, kind and version list with equal served
// flags (order-insensitive).
func sameServing(a, b *CRD) bool {
	return a.Group == b.Group && a.Kind == b.Kind && servingString(a) == servingString(b)
}

func servingString(c *CRD) string {
	var parts []string
	for _, v := range c.Versions {
		s := v.Name + ":unserved"
		if v.Served {
			s = v.Name + ":served"
		}
		parts = append(parts, s)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// readKustomization reads a decoded mapping as a kustomization: its
// CustomResourceDefinition patch entries and its remote sources. It
// returns nil when the mapping is of another kind.
func readKustomization(obj map[string]any) *kustomization {
	if kind, _ := obj["kind"].(string); kind != "" && kind != "Kustomization" {
		return nil
	}
	k := &kustomization{}
	for _, field := range []string{"resources", "components", "bases"} {
		items, _ := obj[field].([]any)
		for _, it := range items {
			if s, ok := it.(string); ok && remoteSource(s) {
				k.remote = append(k.remote, s)
			}
		}
	}
	sort.Strings(k.remote)
	for _, field := range []string{"patches", "patchesJson6902"} {
		raw, present := obj[field]
		if !present {
			continue
		}
		items, ok := raw.([]any)
		if !ok {
			k.problem = field + " is not a list"
			return k
		}
		for _, it := range items {
			entry, ok := it.(map[string]any)
			if !ok {
				k.problem = field + " entry is not a mapping"
				return k
			}
			target, _ := entry["target"].(map[string]any)
			if kind, _ := target["kind"].(string); kind != crdKind {
				continue
			}
			k.crdTargets++
			pp, _ := entry["path"].(string)
			if _, inline := entry["patch"]; inline || pp == "" {
				k.problem = "a CustomResourceDefinition patch is inline or names no file"
				return k
			}
			k.patchPaths = append(k.patchPaths, pp)
		}
	}
	if _, smp := obj["patchesStrategicMerge"]; smp {
		k.problem = "strategic merge patches are not checked"
	}
	if len(k.patchPaths) > maxKustomizePatches {
		k.problem = "too many patch files"
	}
	return k
}

// checkKustomization returns "" when every CustomResourceDefinition
// reference of the file is a checked patch target and every patch only
// changes version schemas or metadata labels and annotations.
func (x *Extractor) checkKustomization(r extract.PinnedReader, repo extract.RepoRef, commit, p string, info *blobInfo) (string, error) {
	k := info.kust
	switch {
	case k.problem != "":
		return k.problem, nil
	case k.crdTargets == 0 || k.crdTargets != info.kinds:
		return "names the CustomResourceDefinition kind outside patch targets", nil
	}
	dir := path.Dir(p)
	for _, rel := range k.patchPaths {
		full := path.Join(dir, rel)
		if !cleanRepoPath(full) || strings.HasPrefix(rel, "/") {
			return fmt.Sprintf("patch %s is outside the repository", rel), nil
		}
		data, err := r.Read(repo, commit, full)
		if err != nil {
			if isNotFound(err) {
				return fmt.Sprintf("patch %s does not exist", full), nil
			}
			return "", err
		}
		if why := schemaOnlyPatch(data); why != "" {
			return fmt.Sprintf("patch %s: %s", full, why), nil
		}
	}
	return "", nil
}

// schemaOnlyPatch accepts a JSON 6902 patch whose every operation path
// (and from) lies under a version's schema or metadata labels/annotations.
func schemaOnlyPatch(data []byte) string {
	if strings.Contains(string(data), templateMarker) {
		return "templated"
	}
	_, values, err := decodeStrict(data)
	if err != nil || len(values) != 1 {
		return "not a single strictly decodable document"
	}
	ops, ok := values[0].([]any)
	if !ok || len(ops) == 0 {
		return "not a JSON 6902 operation list"
	}
	for i, o := range ops {
		op, ok := o.(map[string]any)
		if !ok {
			return fmt.Sprintf("operation %d is not a mapping", i)
		}
		name, _ := op["op"].(string)
		switch name {
		case "add", "remove", "replace", "test", "copy", "move":
		default:
			return fmt.Sprintf("operation %d has op %q", i, name)
		}
		for key := range op {
			switch key {
			case "op", "path", "value", "from":
			default:
				return fmt.Sprintf("operation %d has key %q", i, key)
			}
		}
		for _, key := range []string{"path", "from"} {
			v, present := op[key]
			if !present {
				if key == "path" {
					return fmt.Sprintf("operation %d has no path", i)
				}
				continue
			}
			s, _ := v.(string)
			if !patchPathRE.MatchString(s) {
				return fmt.Sprintf("operation %d %s %q is outside version schemas and metadata labels and annotations", i, key, s)
			}
		}
	}
	return ""
}

// parallel runs fn(0..n-1) on at most x.concurrency goroutines.
func (x *Extractor) parallel(n int, fn func(int)) {
	workers := max(x.concurrency, 1)
	if workers == 1 || n < 2 {
		for i := 0; i < n; i++ {
			fn(i)
		}
		return
	}
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < min(workers, n); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
}
