// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

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
	// ClassTemplatedCopy: a templated file outside a reviewed copies
	// exclusion that is a copy once its template directives are removed;
	// its directives are only a whole-file condition and directives in
	// metadata, and its expressions lie in metadata and spec.conversion.
	ClassTemplatedCopy = "templated-copy"
	// ClassSchemaPatch: a kustomization whose only CustomResourceDefinition
	// references are patch targets, and whose patches only touch version
	// schemas, conversion settings or metadata labels and annotations.
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
	// ClassUnread: names the kind and is templated (in a form whose
	// rendered versions cannot be determined, or that is not a copy), not
	// strictly decodable, over the bounds, or a submodule.
	ClassUnread = "unread"
	// ClassUnsupported: a source the scan does not parse that names the
	// kind (a template, jsonnet or cue file, a packaged Helm chart).
	ClassUnsupported = "unsupported"
	// ClassGoDefined: Go code that builds a definition as a composite
	// literal; its served versions are not read.
	ClassGoDefined = "go-defined"
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
	// ClassPrePatchCopy: a file under a reviewed pre-patch exclusion that
	// the kustomization it names renders into the listed paths: with that
	// kustomization's patches applied (version schemas, conversion
	// settings, metadata, and unserved versions added), its definitions
	// are the listed ones. See checkPrePatch.
	ClassPrePatchCopy = "pre-patch-copy"
	// ClassPrePatch: the kustomization of a reviewed pre-patch exclusion
	// whose rendering checkPrePatch accepted.
	ClassPrePatch = "pre-patch"
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
	// maxGzipLiterals bounds the gzip-compressed string literals read in
	// one Go source; maxGzipBytes bounds the bytes one of them, and all of
	// them together, decompress to.
	maxGzipLiterals = 1000
	maxGzipBytes    = 16 << 20
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
	// gzipLiteralRE is an interpreted Go string literal that starts with
	// the gzip magic bytes, as go generate writes compressed manifests
	// ([]byte("\x1f\x8b...")).
	gzipLiteralRE = regexp.MustCompile(`"\\x1f\\x8b(?:[^"\\\n]|\\.)*"`)
	// sourceKeysRE marks a file that may name another repository: a Helm
	// chart's dependencies or a kustomization's resources.
	sourceKeysRE = regexp.MustCompile(`(?m)^(dependencies|resources|components|bases)[ \t]*:`)
	patchPathRE  = regexp.MustCompile(`^/(spec/versions/(0|[1-9][0-9]{0,2})/schema|spec/conversion|metadata/(annotations|labels))(/[^\x00-\x1f]*)?$|^/spec/preserveUnknownFields$`)
	templateRE   = regexp.MustCompile(`\{\{.*?\}\}`)
	valueExprRE  = regexp.MustCompile(`^(\s*[^\s#{][^:{]*:)\s*\{\{[^{}]*\}\}\s*$`)
	// templatedKindRE is a top-level apiVersion or kind whose value is a
	// template expression (on the same line or the next).
	templatedKindRE = regexp.MustCompile(`(?m)^["']?(?:apiVersion|kind)["']?[ \t]*:(?:[^\n]*\{\{|[ \t]*\r?\n[ \t]+[^\n]*\{\{)`)
	// assignRE is a template variable assignment ($x := ..., $x = ...).
	assignRE = regexp.MustCompile(`\$[A-Za-z0-9_]*\s*:?=`)
	// releaseRefRE is an action whose output is a release or chart name
	// (one line, never a document separator).
	releaseRefRE = regexp.MustCompile(`^\.(Release\.(Name|Namespace|Service|Revision)|Chart\.(Name|Version))$`)
	// quotedRE is a field reference piped to quote, which renders one
	// double-quoted line (line breaks escaped).
	quotedRE = regexp.MustCompile(`^\$?(\.[A-Za-z_][A-Za-z0-9_]*)+\s*\|\s*quote$`)
	// indentedRE is a pipeline that ends in indent or nindent by at least
	// one column, so no line of its output that a newline starts reaches
	// column 0 (indent pads only after a newline: another line break in the
	// text a template or value renders, which is not read, is not bounded).
	indentedRE = regexp.MustCompile(`\|\s*n?indent\s+[1-9][0-9]*\s*$`)
	// templateCommentRE is a template comment as the template lexer reads
	// one: "/*" right after the opening delimiter (or "{{- "), "*/" right
	// before the closing one (or " -}}").
	templateCommentRE = regexp.MustCompile(`^\{\{(- )?/\*(?s:.*)\*/( -)?\}\}$`)
)

func indentOf(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

// NotRead are the files the scan does not read, recorded in every scan.
var NotRead = []string{
	"files that are not YAML, JSON, template, jsonnet, cue or Go sources, or packaged Helm charts",
	"Go sources whose path does not contain crd, Go test files (_test.go), and Go sources under a default-excluded directory or a reviewed exclusion (of those the install-surface guard reads only the //go:embed directives)",
	"definitions held in Go sources as encoded bytes other than gzip-compressed string literals (base64, byte-slice literals, other compressions)",
	"symbolic links (the install-surface guard does not follow them either), CI configuration, shell scripts other than .sh and .bash files, build files other than Dockerfiles, Containerfiles, Earthfiles and nix files (Bazel, Tilt, ko configuration), a container build or nix file that copies its whole context or a source directory above an excluded path and selects files while it runs, and Go code that opens a path at run time",
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
	case ClassSchemaPatch, ClassCRDPatch, ClassKustomizeConfig, ClassLegacyCopy, ClassTemplatedCopy, ClassPrePatchCopy, ClassPrePatch, ClassExcluded, ClassExcludedUnread:
		return false
	}
	return true
}

// opaque reports whether a finding's content is not known: a definition
// may hide in it.
func (f Finding) opaque() bool {
	switch f.Class {
	case ClassUnread, ClassUnsupported, ClassGoDefined, ClassExternal, ClassReference, ClassExcludedUnread:
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
// a version the inventory does not show: a templated, unreadable,
// unsupported or Go-defined CRD source in the open tree or among declared
// copies, or a declared copy (a chart template) that serves other
// versions. A file under a default-excluded directory only blocks
// attestation.
func (f Finding) unreadable() bool {
	if strings.HasPrefix(f.Location, "default: ") || strings.HasPrefix(f.Location, voidPrefix) {
		return false
	}
	switch f.Class {
	case ClassUnread, ClassUnsupported, ClassGoDefined, ClassConflict:
		return true
	}
	return false
}

// Clean reports a complete scan with nothing but copies (v1, v1beta1,
// templated or pre-patch), schema-only kustomizations, kubebuilder patch
// fragments and transformer configurations, accepted pre-patch
// kustomizations, and reviewed exclusions.
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
	// template is the result of reading the bytes with their template
	// directives removed (nil when the bytes hold no template syntax or no
	// kind name).
	template *templateRead
	// legacy are the definitions of bytes that hold
	// apiextensions.k8s.io/v1beta1 definitions, all strictly read (nil
	// otherwise); legacyProblem is why such bytes could not be read.
	legacy        []CRD
	legacyProblem string
	// fragment is the bytes read as kubebuilder patch fragments (nil when
	// they are not strictly decodable or were decoded as definitions).
	fragment *fragmentRead
	// configProblem is why the bytes are not a kustomize transformer
	// configuration whose field specs of the kind only reach conversion
	// settings or metadata ("" when they are one).
	configProblem string
	// goConstruct: Go code that builds a definition.
	goConstruct bool
	// gzip is what the gzip-compressed string literals of a Go source hold
	// (nil when it has none).
	gzip *gzipRead
}

// gzipRead is what the gzip-compressed string literals of one Go source
// hold, decompressed and read like YAML files.
type gzipRead struct {
	// unread is why a literal could not be read ("" when every one was).
	unread string
	crds   []CRD
	// kinds counts the mappings of kind CustomResourceDefinition.
	kinds int
}

// readGzipLiterals decompresses the gzip string literals of a Go source
// and reads each as a YAML or JSON file. It is a function of the bytes.
func readGzipLiterals(data []byte) *gzipRead {
	lits := gzipLiteralRE.FindAll(data, -1)
	if len(lits) == 0 {
		return nil
	}
	g := &gzipRead{}
	if len(lits) > maxGzipLiterals {
		g.unread = fmt.Sprintf("more than %d gzip-compressed string literals", maxGzipLiterals)
		return g
	}
	total := 0
	for i, lit := range lits {
		raw, err := strconv.Unquote(string(lit))
		if err != nil {
			g.unread = fmt.Sprintf("gzip-compressed string literal %d is not a Go string", i+1)
			return g
		}
		zr, err := gzip.NewReader(strings.NewReader(raw))
		if err != nil {
			g.unread = fmt.Sprintf("gzip-compressed string literal %d: %v", i+1, err)
			return g
		}
		out, err := io.ReadAll(io.LimitReader(zr, maxGzipBytes+1))
		if err != nil {
			g.unread = fmt.Sprintf("gzip-compressed string literal %d: %v", i+1, err)
			return g
		}
		if total += len(out); len(out) > maxGzipBytes || total > maxGzipBytes {
			g.unread = fmt.Sprintf("gzip-compressed string literals decompress to more than %d bytes", maxGzipBytes)
			return g
		}
		sub := summarize(kindData, out)
		if sub.unread != "" {
			if sub.words > 0 {
				g.unread = fmt.Sprintf("gzip-compressed string literal %d: %s", i+1, sub.unread)
				return g
			}
			continue
		}
		g.crds = append(g.crds, sub.crds...)
		g.kinds += sub.kinds
		if sub.embedded {
			g.kinds++
		}
	}
	return g
}

// templateRead is a templated file read with its template directives
// removed (see readTemplate).
type templateRead struct {
	// unread is why the rendered versions cannot be determined ("" when
	// they can).
	unread string
	crds   []CRD
	// kindTemplated: a document's apiVersion or kind is a template
	// expression, so what it is cannot be known; such a file is a finding.
	kindTemplated bool
}

// kustomization is a decoded kustomization file's patch references and
// remote sources.
type kustomization struct {
	// configs are the transformer configuration files it names
	// (configurations); configBad is why the list cannot be followed.
	configs   []string
	configBad string
	// crdTargets counts the patch entries whose target kind is
	// CustomResourceDefinition; patchPaths are their files (relative to
	// the kustomization's directory).
	crdTargets int
	patchPaths []string
	// inline counts the entries among them whose patch is given inline as
	// a string; inlineBad is why one of those strings is not a JSON 6902
	// list that only touches version schemas, conversion settings or
	// metadata labels and annotations ("" when each is one).
	inline    int
	inlineBad string
	// problem is why a CRD patch entry cannot be checked ("" when every
	// one names a local file or is an inline string).
	problem string
	// open is why some patch or replacement could select a definition
	// without naming the kind literally ("" when none can): such an entry
	// is never read, so it blocks.
	open string
	// remote are the resources, components and bases from another
	// repository; local are the other resources and bases.
	remote []string
	local  []string
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
	for i := range files {
		if errs[i] != nil {
			return nil, errs[i]
		}
	}
	defDirs := definitionDirs(files, infos, inv)
	for i, f := range files {
		fd, found, err := x.classify(r, repo, commit, f, infos[i], inv, defDirs)
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
	for _, e := range tg.Exclude {
		if e.PrePatch == "" {
			continue
		}
		if err := x.checkPrePatch(r, repo, commit, tg, e, rec, inv); err != nil {
			return nil, err
		}
	}
	cfg, err := x.scanConfigs(r, repo, commit, files, infos, defDirs, tg, rec.Findings)
	if err != nil {
		return nil, err
	}
	rec.Findings = append(rec.Findings, cfg...)
	for h := range hits {
		rec.Exclusions = append(rec.Exclusions, h)
	}
	sort.Strings(rec.Exclusions)
	sort.Slice(rec.Findings, func(i, j int) bool { return rec.Findings[i].Path < rec.Findings[j].Path })
	return x.storeScan(commit, rec), nil
}

// placed records a finding's location. Under a reviewed exclusion that
// does not declare copies or pre-patch copies a finding is recorded, never
// blocking: excluded when its content is known, excluded-unread otherwise.
// Under one that declares them every class keeps its effect.
func placed(f Finding, at place) Finding {
	if at.kind == locTree {
		return f
	}
	f.Location = at.entry
	if at.kind != locReviewed || at.copies || at.prePatch != "" {
		return f
	}
	switch f.Class {
	case ClassCopy, ClassTemplatedCopy, ClassSchemaPatch, ClassCRDPatch, ClassKustomizeConfig, ClassLegacyCopy:
	case ClassUnread, ClassUnsupported, ClassGoDefined:
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
			// A file read from another repository is not a path of this
			// repository's tree.
			if f.Repo == "" {
				out[f.Path] = true
			}
		}
	}
	for _, p := range x.target.allListedPaths() {
		if !p.Dir {
			out[p.Path] = true
		}
	}
	// The files of the other install channels are read by the inventory.
	if inv != nil {
		for _, ch := range inv.Channels {
			for _, f := range ch.Files {
				out[f.Path] = true
			}
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
		if !info.goConstruct {
			info.gzip = readGzipLiterals(data)
		}
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
		if info.words > 0 && info.template == nil {
			summarizeUnread(data, info)
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
		if len(crds) == 0 && info.kinds > 0 {
			info.configProblem = transformerConfig(values[0])
		}
	} else {
		info.configProblem = "not a single document"
	}
	return info
}

// summarizeUnread reads bytes the v1 reader refused, without template
// syntax, as v1beta1 definitions or as kubebuilder patch fragments.
func summarizeUnread(data []byte, info *blobInfo) {
	crds, err := parseLegacy(data)
	switch {
	case err != nil:
		info.legacyProblem = err.Error()
		if pr, ok := asProblem(err); ok {
			info.legacyProblem = pr.msg
		}
	case crds != nil:
		info.legacy = crds
		return
	}
	if len(data) > MaxFileBytes || bytes.Contains(data, []byte(templateMarker)) {
		return
	}
	if _, values, err := decodeStrict(data); err == nil {
		info.fragment = readFragments(values)
	}
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

// templateUnread starts the reason a templated file is not read.
const templateUnread = "with template directives, its rendered versions cannot be determined: "

// templateLine is a line of a templated file kept after its directive-only
// lines are removed, and whether it lies in a top-level metadata block.
type templateLine struct {
	text string
	meta bool
}

// templateAction returns the action of one template delimiter pair
// ("{{- if .x }}" is "if .x") and whether it trims the whitespace after
// it.
func templateAction(expr string) (action string, after bool) {
	inner := strings.TrimSuffix(strings.TrimPrefix(expr, "{{"), "}}")
	if len(inner) >= 2 && inner[0] == '-' && strings.ContainsRune(" \t\r\n", rune(inner[1])) {
		inner = inner[1:]
	}
	if n := len(inner); n >= 2 && inner[n-1] == '-' && strings.ContainsRune(" \t\r\n", rune(inner[n-2])) {
		inner, after = inner[:n-1], true
	}
	return strings.TrimSpace(inner), after
}

// directiveWord names a directive by its first word, with its article.
func directiveWord(word string) string {
	switch {
	case word == "":
		return "an empty"
	case strings.ContainsRune("aeiouAEIOU", rune(word[0])):
		return "an " + strconv.Quote(word)
	}
	return "a " + strconv.Quote(word)
}

// templateComment reports a template comment (expr is the whole action
// with its delimiters).
func templateComment(expr string) bool {
	return templateCommentRE.MatchString(expr) && strings.Count(expr, "*/") == 1
}

// boundedOutput returns why the output of an action that renders text may
// reach column 0 or span lines ("" when it cannot): it must be a release or
// chart name outside a with block (where the dot is another value), a field
// reference piped to quote, or a pipeline that ends in indent or nindent.
func boundedOutput(action string, inWith bool) string {
	switch {
	case indentedRE.MatchString(action), quotedRE.MatchString(action):
		return ""
	case releaseRefRE.MatchString(action) && !inWith:
		return ""
	}
	return "a template expression whose output may span lines (only a release or chart name, a quoted field, or a pipeline ending in indent or nindent is read)"
}

// trimsNothing reports that the first line of rest that is not blank
// starts at column 0: trimming the whitespace before it removes only line
// breaks and blank lines.
func trimsNothing(rest []string) bool {
	for _, line := range rest {
		if strings.TrimSpace(line) != "" {
			return strings.TrimLeft(line, " \t\r\v\f") == line
		}
	}
	return false
}

// readTemplate reads a templated file whose rendered definitions are
// determined by its literal lines. It is checked line by line before it
// is decoded:
//   - a line that holds only one template directive is removed, and is
//     accepted only as a template comment (anywhere), as the condition
//     around the whole file (an if on the first line that is not blank or
//     a comment, whose end is the last line that is not blank), or as an
//     if, with, end, include or toYaml directive inside a top-level
//     metadata block (from a metadata: line at column 0 to the next line
//     at column 0 that is not blank or a comment). Every if and with in a
//     metadata block ends inside it. An else, range, define, template or
//     block, a variable assignment, and a directive anywhere else make the
//     file unread;
//   - a directive that trims the line break after it is accepted only on
//     the last line, or on the first line that is not blank when the next
//     line that is not blank starts at column 0 (nothing is joined and no
//     indentation is lost), and an expression inside a line may not trim
//     the line break before or after it: either joins two lines;
//   - an expression inside a line is accepted only in a top-level metadata
//     block or in the conversion block of a top-level spec, and is replaced
//     by a placeholder; a key whose whole value is an expression followed
//     by more indented lines (labels: {{- include ... | nindent 4 }})
//     keeps its literal children, in metadata only;
//   - an expression left open across lines makes the file unread;
//   - every action is well formed (its text holds no "{{" or "}}"), a
//     comment is one as the template lexer reads it, and an action that
//     renders text is bounded (boundedOutput); a directive-only include or
//     toYaml line must end in indent or nindent.
//
// The decoded documents are then walked: a placeholder in a document's
// apiVersion or kind, in a definition's metadata.name, or anywhere in its
// spec but spec.conversion makes the file unread. What is left must decode
// as apiextensions.k8s.io/v1 definitions like any other file.
func readTemplate(data []byte) *templateRead {
	tr := &templateRead{kindTemplated: templatedKindRE.Match(data)}
	refuse := func(why string) *templateRead {
		tr.unread = templateUnread + why
		tr.crds = nil
		return tr
	}
	if len(data) > MaxFileBytes {
		return refuse(fmt.Sprintf("the file is over the %d-byte bound", MaxFileBytes))
	}
	lines := strings.Split(string(data), "\n")
	first, last := -1, -1
	for i, line := range lines {
		if strings.TrimSpace(line) != "" {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	var kept []templateLine
	// metaStarts and convStarts are the kept lines (1-based) that open a
	// metadata or a spec.conversion block.
	var metaStarts, convStarts []int
	depth, metaDepth := 0, 0
	wrapper, seen := false, false
	// withs holds, for each open if or with, whether it is a with: inside
	// one the dot is another value, so .Release is not the release.
	var withs []bool
	inMeta, inSpec, inConv := false, false, false
	specIndent, convIndent := -1, 0
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "{{") && templateRE.FindString(t) == t {
			if strings.Contains(t[2:], "{{") {
				return refuse("a template action is not well formed")
			}
			action, after := templateAction(t)
			if after && i != last && !(i == first && trimsNothing(lines[i+1:])) {
				return refuse("a directive trims the line break after it")
			}
			if templateComment(t) {
				continue
			}
			if assignRE.MatchString(action) {
				return refuse("a template variable is assigned")
			}
			word := ""
			if f := strings.Fields(action); len(f) > 0 {
				word = f[0]
			}
			first := !seen
			seen = true
			switch {
			case word == "if" && first && depth == 0:
				wrapper, depth = true, 1
				withs = append(withs, false)
			case word == "end" && wrapper && depth == 1:
				if i != last {
					return refuse("the condition around the whole file ends before its last line")
				}
				if inMeta && metaDepth != depth {
					return refuse("a condition in metadata does not end inside it")
				}
				inMeta, depth, withs = false, 0, nil
			case !inMeta:
				return refuse(directiveWord(word) + " directive outside metadata")
			case word == "if" || word == "with":
				depth++
				withs = append(withs, word == "with")
			case word == "end":
				if depth <= metaDepth {
					return refuse("an end in metadata closes a condition opened outside it")
				}
				depth--
				withs = withs[:len(withs)-1]
			case word == "include" || word == "toYaml":
				if !indentedRE.MatchString(action) {
					return refuse(directiveWord(word) + " directive whose output does not end in indent or nindent")
				}
			default:
				return refuse(directiveWord(word) + " directive")
			}
			continue
		}
		if t == "" {
			kept = append(kept, templateLine{text: line, meta: inMeta})
			continue
		}
		comment := strings.HasPrefix(t, "#")
		if !comment {
			seen = true
			indent := indentOf(line)
			switch {
			case indent == 0:
				if inMeta && depth != metaDepth {
					return refuse("a condition in metadata does not end inside it")
				}
				inMeta, inSpec, inConv = false, false, false
				switch strings.TrimRight(line, " \t\r") {
				case "metadata:":
					inMeta, metaDepth = true, depth
					metaStarts = append(metaStarts, len(kept)+1)
				case "spec:":
					inSpec, specIndent = true, -1
				}
			case inSpec:
				if specIndent < 0 {
					specIndent = indent
				}
				if inConv && indent <= convIndent {
					inConv = false
				}
				if indent == specIndent && strings.TrimRight(line, " \t\r") == strings.Repeat(" ", indent)+"conversion:" {
					inConv, convIndent = true, indent
					convStarts = append(convStarts, len(kept)+1)
				}
			}
		}
		if strings.Contains(line, "{{") {
			if !inMeta && !inConv {
				return refuse("a template expression outside metadata and spec.conversion")
			}
			if strings.HasPrefix(t, "{{-") || strings.HasSuffix(t, "-}}") {
				return refuse("a template expression trims a line break")
			}
			// An action whose text holds "}}" ends early: the rest of it is
			// left over.
			if strings.Contains(templateRE.ReplaceAllString(line, ""), "}}") {
				return refuse("a template action is not well formed")
			}
			for _, expr := range templateRE.FindAllString(line, -1) {
				if strings.Contains(expr[2:], "{{") {
					return refuse("a template action is not well formed")
				}
				if templateComment(expr) {
					continue
				}
				action, _ := templateAction(expr)
				word := ""
				if f := strings.Fields(action); len(f) > 0 {
					word = f[0]
				}
				switch {
				case assignRE.MatchString(action):
					return refuse("a template variable is assigned")
				case slicesContains([]string{"if", "else", "end", "range", "with", "define", "template", "block", "break", "continue"}, word):
					return refuse(directiveWord(word) + " directive inside a line")
				case inConv && (strings.Contains(action, "indent") || strings.Contains(action, "toYaml")):
					return refuse("a template expression in spec.conversion that may span lines")
				}
				if why := boundedOutput(action, slices.Contains(withs, true)); why != "" {
					return refuse(why)
				}
			}
		}
		kept = append(kept, templateLine{text: line, meta: inMeta})
	}
	if inMeta && depth != metaDepth {
		return refuse("a condition in metadata does not end inside it")
	}
	if depth != 0 {
		return refuse("a condition does not end")
	}
	var b strings.Builder
	for i, k := range kept {
		line := k.text
		// A key whose whole value is an expression followed by more
		// indented lines (labels: {{- include ... | nindent 4 }}) keeps
		// its literal children: the expression adds entries to them.
		if m := valueExprRE.FindStringSubmatch(line); m != nil && i+1 < len(kept) && indentOf(kept[i+1].text) > indentOf(line) && strings.TrimSpace(kept[i+1].text) != "" {
			if !k.meta {
				return refuse("a key outside metadata whose value is an expression has more lines under it")
			}
			line = m[1]
		}
		line = templateRE.ReplaceAllString(line, placeholder)
		// A closing "}}" alone is text (a brace in a description); an
		// opening "{{" left over starts an expression that spans lines.
		if strings.Contains(line, "{{") {
			return refuse("a template expression spans lines")
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	text := []byte(b.String())
	nodes, values, err := decodeStrict(text)
	if err != nil {
		return refuse("with them removed, the file is not decodable within the strict YAML subset")
	}
	if why := templatedFields(nodes, values, metaStarts, convStarts, tr); why != "" {
		return refuse(why)
	}
	_, crds, err := parseFile(fileWord, text)
	if err != nil {
		msg := err.Error()
		if pr, ok := asProblem(err); ok {
			msg = pr.msg
		}
		return refuse("with them removed, " + msg)
	}
	for i := range crds {
		crds[i].Path = ""
	}
	tr.crds = crds
	return tr
}

// templatedFields checks the decoded documents of a templated file: every
// line that opened a metadata or spec.conversion block is that key of a
// document, no apiVersion or kind is a placeholder, and in a definition a
// placeholder lies only in metadata (not its name) and spec.conversion.
func templatedFields(nodes []*yaml.Node, values []any, metaStarts, convStarts []int, tr *templateRead) string {
	metas, convs := map[int]bool{}, map[int]bool{}
	for _, root := range nodes {
		if key := keyNode(root, "metadata"); key != nil && key.Column == 1 {
			metas[key.Line] = true
		}
		spec, _ := child(root, "spec")
		if key := keyNode(spec, "conversion"); key != nil {
			convs[key.Line] = true
		}
	}
	for _, l := range metaStarts {
		if !metas[l] {
			return "a metadata line is not the metadata of a document"
		}
	}
	for _, l := range convStarts {
		if !convs[l] {
			return "a conversion line is not the spec.conversion of a document"
		}
	}
	for _, v := range values {
		obj, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if templated(obj["apiVersion"]) || templated(obj["kind"]) {
			tr.kindTemplated = true
			return "a document's apiVersion or kind is a template expression"
		}
		if kind, _ := obj["kind"].(string); kind != crdKind {
			continue
		}
		for _, key := range sortedKeys(obj) {
			val := obj[key]
			switch {
			case strings.Contains(key, placeholder):
				return "a top-level key is a template expression"
			case key == "metadata":
				if meta, _ := val.(map[string]any); templated(meta["name"]) {
					return "metadata.name is a template expression"
				}
			case key == "spec":
				spec, ok := val.(map[string]any)
				if !ok && templated(val) {
					return "spec holds a template expression"
				}
				for _, sk := range sortedKeys(spec) {
					if sk != "conversion" && (strings.Contains(sk, placeholder) || templated(spec[sk])) {
						return "spec." + sk + " holds a template expression"
					}
				}
			case templated(val):
				return key + " holds a template expression"
			}
		}
	}
	return ""
}

// keyNode returns the key node of key in a mapping node.
func keyNode(n *yaml.Node, key string) *yaml.Node {
	_, k := child(n, key)
	return k
}

// templated reports a placeholder anywhere in a decoded value.
func templated(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.Contains(t, placeholder)
	case map[string]any:
		for k, c := range t {
			if strings.Contains(k, placeholder) || templated(c) {
				return true
			}
		}
	case []any:
		for _, c := range t {
			if templated(c) {
				return true
			}
		}
	}
	return false
}

// prePatchRefused starts the note added to a pre-patch kustomization whose
// rendering the scan does not accept.
const prePatchRefused = "; not a pre-patch rendering the scan accepts: "

// checkPrePatch checks the claim of a reviewed pre-patch exclusion at one
// tag: the files under the entry are the definitions the kustomization it
// names (e.PrePatch) renders into the listed paths, before its patches
// apply. It is accepted only in this exact shape:
//   - the kustomization, strictly decoded, holds exactly the keys resources
//     and patches; its one resource is a local path that resolves to the
//     entry directory, and each patch entry holds exactly a target (group
//     apiextensions.k8s.io, version v1, kind CustomResourceDefinition and a
//     literal name, whose only regular expression characters are dots and
//     which, anchored as kustomize anchors it, matches no other definition
//     of the resources) and a path to a file inside the kustomization's
//     directory;
//   - the entry directory's kustomization.yaml, strictly decoded, holds
//     exactly the key resources, each a file in that directory; they are
//     every file under the entry that names the kind, and each holds
//     apiextensions.k8s.io/v1 definitions only, strictly read;
//   - every operation of every patch file is one schemaOnlyPatch accepts,
//     or adds to /spec/versions/- a version that the definition does not
//     yet list, with served: false and storage: false as booleans (and
//     only a name and a schema besides); a patch target that no resource
//     defines refuses the entry;
//   - with the patches applied, the definitions are those of the inventory
//     (same names; group, kind, versions and served flags).
//
// Then the resource files are pre-patch copies and the kustomization is
// class pre-patch, neither blocking attestation. Otherwise nothing
// changes: the files keep their classes (a definition that differs from
// the listed paths stays a conflict) and a kustomization that is a
// reference says why the rendering was refused.
func (x *Extractor) checkPrePatch(r extract.PinnedReader, repo extract.RepoRef, commit string, tg Target, e Exclusion, rec *ScanRecord, inv *Inventory) error {
	// The files under the entry that name the kind.
	present := map[string]bool{}
	for _, p := range rec.Copies {
		if exclusionMatches(e.Path, p) {
			present[p] = true
		}
	}
	for _, f := range rec.Findings {
		if exclusionMatches(e.Path, f.Path) {
			present[f.Path] = true
		}
	}
	if len(present) == 0 {
		return nil
	}
	acc, why, err := x.readPrePatch(r, repo, commit, tg, e, present, inv)
	if err != nil {
		return err
	}
	if why != "" {
		for i := range rec.Findings {
			if f := &rec.Findings[i]; f.Path == e.PrePatch && f.Class == ClassReference {
				f.Detail += prePatchRefused + why
			}
		}
		return nil
	}
	var copies []string
	for _, p := range rec.Copies {
		if acc.files[p] == nil {
			copies = append(copies, p)
		}
	}
	rec.Copies = append([]string{}, copies...)
	var out []Finding
	for _, f := range rec.Findings {
		if acc.files[f.Path] == nil && f.Path != e.PrePatch {
			out = append(out, f)
		}
	}
	for p, pf := range acc.files {
		fd := namedCopy(Finding{Path: p, SHA256: pf.sha256, Location: e.Path}, ClassPrePatchCopy, pf.crds, "with the patches of "+e.PrePatch+" applied ("+pf.ops+"), a copy of the listed paths")
		out = append(out, fd)
	}
	kf := Finding{Path: e.PrePatch, SHA256: acc.sha256, Class: ClassPrePatch, Detail: fmt.Sprintf("renders %s into the listed paths with patches that only change version schemas, conversion settings and metadata labels and annotations, or add unserved versions", e.Path)}
	if at := tg.placeOf(e.PrePatch); at.kind != locTree {
		kf.Location = at.entry
	}
	rec.Findings = append(out, kf)
	return nil
}

// prePatchFile is one resource file of an accepted pre-patch rendering:
// its definitions with the patches applied and what the patches did.
type prePatchFile struct {
	sha256 string
	crds   []CRD
	ops    string
}

// prePatchRead is an accepted pre-patch rendering: its resource files by
// path, and the kustomization's sha256.
type prePatchRead struct {
	files  map[string]*prePatchFile
	sha256 string
}

// readPrePatch reads a pre-patch rendering (see checkPrePatch). It returns
// why it is refused ("" when it is accepted); reader errors other than a
// missing file abort.
func (x *Extractor) readPrePatch(r extract.PinnedReader, repo extract.RepoRef, commit string, tg Target, e Exclusion, present map[string]bool, inv *Inventory) (*prePatchRead, string, error) {
	acc := &prePatchRead{files: map[string]*prePatchFile{}}
	entryDir := strings.TrimSuffix(e.Path, "/")
	read := func(p string) ([]byte, string, error) {
		data, err := r.Read(repo, commit, p)
		switch {
		case isNotFound(err):
			return nil, fmt.Sprintf("%s does not exist", p), nil
		case err != nil:
			return nil, "", err
		case len(data) > MaxFileBytes:
			return nil, fmt.Sprintf("%s is over the %d-byte bound", p, MaxFileBytes), nil
		}
		return data, "", nil
	}
	// The patches kustomization.
	data, why, err := read(e.PrePatch)
	if why != "" || err != nil {
		return nil, why, err
	}
	sum := sha256.Sum256(data)
	acc.sha256 = "sha256:" + hex.EncodeToString(sum[:])
	kdir := path.Dir(e.PrePatch)
	obj, why := strictMapping(data, "resources", "patches")
	if why != "" {
		return nil, e.PrePatch + " " + why, nil
	}
	res, ok := obj["resources"].([]any)
	if rel, _ := firstString(res); !ok || len(res) != 1 || rel == "" || remoteSource(rel) || strings.HasPrefix(rel, "/") || path.Join(kdir, rel) != entryDir {
		return nil, fmt.Sprintf("%s does not have exactly one resource, the entry directory %s", e.PrePatch, entryDir), nil
	}
	patches, ok := obj["patches"].([]any)
	if !ok || len(patches) == 0 || len(patches) > maxKustomizePatches {
		return nil, fmt.Sprintf("%s patches is not a list of 1 to %d entries", e.PrePatch, maxKustomizePatches), nil
	}
	type patchRef struct{ name, file string }
	var refs []patchRef
	for i, it := range patches {
		ref, why := prePatchEntry(it, kdir)
		if why != "" {
			return nil, fmt.Sprintf("%s patch %d %s", e.PrePatch, i+1, why), nil
		}
		refs = append(refs, patchRef{ref[0], ref[1]})
	}
	// The resources kustomization of the entry directory.
	ekust := entryDir + "/kustomization.yaml"
	data, why, err = read(ekust)
	if why != "" || err != nil {
		return nil, why, err
	}
	eobj, why := strictMapping(data, "resources")
	if why != "" {
		return nil, ekust + " " + why, nil
	}
	items, ok := eobj["resources"].([]any)
	if !ok || len(items) == 0 {
		return nil, ekust + " resources is not a list of files", nil
	}
	listed := map[string]bool{}
	var paths []string
	for _, it := range items {
		s, _ := it.(string)
		full := path.Join(entryDir, s)
		if s == "" || strings.Contains(s, "/") || remoteSource(s) || !cleanRepoPath(full) || path.Dir(full) != entryDir || listed[full] {
			return nil, fmt.Sprintf("%s resource %q is not a file of the directory", ekust, s), nil
		}
		listed[full] = true
		paths = append(paths, full)
	}
	sort.Strings(paths)
	for _, p := range sortedSet(present) {
		if !listed[p] {
			return nil, fmt.Sprintf("%s names the CustomResourceDefinition kind and is not a resource of %s", p, ekust), nil
		}
	}
	// The definitions before the patches, by name.
	byName := map[string]*CRD{}
	fileOf := map[string]string{}
	var names []string
	for _, p := range paths {
		if !present[p] {
			return nil, fmt.Sprintf("resource %s of %s does not define a CustomResourceDefinition", p, ekust), nil
		}
		if at := tg.placeOf(p); at.entry != e.Path {
			return nil, fmt.Sprintf("resource %s lies under another exclusion", p), nil
		}
		data, why, err := read(p)
		if why != "" || err != nil {
			return nil, why, err
		}
		frec, crds, err := parseFile(fileWord, data)
		if err != nil || frec.OtherDocuments > 0 || len(crds) == 0 {
			return nil, fmt.Sprintf("resource %s is not strictly read as apiextensions.k8s.io/v1 definitions only", p), nil
		}
		acc.files[p] = &prePatchFile{sha256: frec.SHA256}
		for i := range crds {
			c := crds[i]
			c.Path = ""
			if byName[c.Name] != nil {
				return nil, fmt.Sprintf("%s is defined twice among the resources", c.Name), nil
			}
			byName[c.Name], fileOf[c.Name] = &c, p
			names = append(names, c.Name)
		}
	}
	sort.Strings(names)
	// The patches, in order.
	added := map[string][]string{}
	schemaOps := map[string]int{}
	for _, ref := range refs {
		c := byName[ref.name]
		if c == nil {
			return nil, fmt.Sprintf("a patch targets %s, which no resource defines", ref.name), nil
		}
		target := regexp.MustCompile(`^(?:` + ref.name + `)$`)
		for _, n := range names {
			if n != ref.name && target.MatchString(n) {
				return nil, fmt.Sprintf("the patch target %s also selects %s", ref.name, n), nil
			}
		}
		data, why, err := read(ref.file)
		if why != "" || err != nil {
			return nil, why, err
		}
		ops, why := patchOps(data)
		if why != "" {
			return nil, fmt.Sprintf("patch %s: %s", ref.file, why), nil
		}
		for i, o := range ops {
			if schemaOnlyOp(i, o) == "" {
				schemaOps[ref.name]++
				continue
			}
			v, why := unservedVersionOp(o)
			if why != "" {
				return nil, fmt.Sprintf("patch %s operation %d %s", ref.file, i, why), nil
			}
			if _, listed := c.version(v); listed {
				return nil, fmt.Sprintf("patch %s operation %d adds version %s, which %s already lists", ref.file, i, v, ref.name), nil
			}
			c.Versions = append(c.Versions, CRDVersion{Name: v})
			added[ref.name] = append(added[ref.name], v)
		}
	}
	// The patched definitions are the listed ones.
	if inv == nil {
		return nil, "no inventory", nil
	}
	known := map[string]*CRD{}
	for i := range inv.CRDs {
		known[inv.CRDs[i].Name] = &inv.CRDs[i]
	}
	for _, n := range names {
		k := known[n]
		switch {
		case k == nil:
			return nil, fmt.Sprintf("the listed paths do not define %s", n), nil
		case !sameServing(k, byName[n]):
			return nil, fmt.Sprintf("%s: versions %s once patched, %s in %s", n, servingString(byName[n]), servingString(k), k.Path), nil
		}
	}
	for _, c := range inv.CRDs {
		if byName[c.Name] == nil {
			return nil, fmt.Sprintf("the listed paths define %s, which no resource does", c.Name), nil
		}
	}
	for p, pf := range acc.files {
		var parts []string
		for _, n := range names {
			if fileOf[n] != p {
				continue
			}
			pf.crds = append(pf.crds, *byName[n])
			var did []string
			if vs := added[n]; len(vs) > 0 {
				did = append(did, "adds unserved "+strings.Join(vs, ", "))
			}
			switch k := schemaOps[n]; {
			case k == 1:
				did = append(did, "1 schema-only operation")
			case k > 1:
				did = append(did, fmt.Sprintf("%d schema-only operations", k))
			}
			if len(did) == 0 {
				did = append(did, "no patch")
			}
			parts = append(parts, n+": "+strings.Join(did, ", "))
		}
		pf.ops = strings.Join(parts, "; ")
	}
	return acc, "", nil
}

// strictMapping decodes a file as one strict mapping with exactly the
// given keys.
func strictMapping(data []byte, keys ...string) (map[string]any, string) {
	if strings.Contains(string(data), templateMarker) {
		return nil, "is templated"
	}
	_, values, err := decodeStrict(data)
	if err != nil || len(values) != 1 {
		return nil, "is not a single strictly decodable document"
	}
	obj, ok := values[0].(map[string]any)
	if !ok {
		return nil, "is not a mapping"
	}
	for _, k := range sortedKeys(obj) {
		if !slices.Contains(keys, k) {
			return nil, fmt.Sprintf("has key %q (only %s are read)", k, strings.Join(keys, " and "))
		}
	}
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			return nil, fmt.Sprintf("has no %s", k)
		}
	}
	return obj, ""
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstString(items []any) (string, bool) {
	if len(items) == 0 {
		return "", false
	}
	s, ok := items[0].(string)
	return s, ok
}

// literalNameRE is a definition name whose only regular expression
// characters are its dots.
var literalNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)+$`)

// prePatchEntry checks one patch entry of a pre-patch kustomization and
// returns the definition it targets and its file.
func prePatchEntry(v any, kdir string) ([2]string, string) {
	var out [2]string
	entry, ok := v.(map[string]any)
	if !ok {
		return out, "is not a mapping"
	}
	for _, k := range sortedKeys(entry) {
		if k != "target" && k != "path" {
			return out, fmt.Sprintf("has key %q (only target and path are read)", k)
		}
	}
	target, ok := entry["target"].(map[string]any)
	if !ok {
		return out, "has no target mapping"
	}
	for _, k := range sortedKeys(target) {
		switch k {
		case "group", "version", "kind", "name":
		default:
			return out, fmt.Sprintf("target has key %q", k)
		}
	}
	group, _ := target["group"].(string)
	version, _ := target["version"].(string)
	kind, _ := target["kind"].(string)
	name, _ := target["name"].(string)
	switch {
	case group != crdGroup || version != "v1" || kind != crdKind:
		return out, fmt.Sprintf("target is not group %s, version v1, kind %s", crdGroup, crdKind)
	case len(name) > maxNameBytes || !literalNameRE.MatchString(name) || regexp.QuoteMeta(name) != strings.ReplaceAll(name, ".", `\.`):
		return out, fmt.Sprintf("target name %q is not a literal definition name", name)
	}
	rel, _ := entry["path"].(string)
	full := path.Join(kdir, rel)
	if rel == "" || strings.HasPrefix(rel, "/") || remoteSource(rel) || !cleanRepoPath(full) || !strings.HasPrefix(full, kdir+"/") {
		return out, fmt.Sprintf("path %q is not a file inside %s", rel, kdir)
	}
	return [2]string{name, full}, ""
}

// unservedVersionOp reads a JSON 6902 operation that adds an unserved,
// unstored version at the end of spec.versions and returns its name.
func unservedVersionOp(v any) (string, string) {
	op, _ := v.(map[string]any)
	for _, k := range sortedKeys(op) {
		if k != "op" && k != "path" && k != "value" {
			return "", fmt.Sprintf("has key %q", k)
		}
	}
	if o, _ := op["op"].(string); o != "add" {
		return "", fmt.Sprintf("is op %q outside version schemas, conversion settings and metadata labels and annotations", o)
	}
	if p, _ := op["path"].(string); p != "/spec/versions/-" {
		return "", fmt.Sprintf("adds at %q, outside version schemas, conversion settings, metadata labels and annotations and the end of spec.versions", p)
	}
	value, ok := op["value"].(map[string]any)
	if !ok {
		return "", "adds a version that is not a mapping"
	}
	for _, k := range sortedKeys(value) {
		switch k {
		case "name", "served", "storage", "schema":
		default:
			return "", fmt.Sprintf("adds a version with key %q", k)
		}
	}
	name, _ := value["name"].(string)
	served, sok := value["served"].(bool)
	stored, tok := value["storage"].(bool)
	switch {
	case !versionRE.MatchString(name) || len(name) > maxVersionNameByte:
		return "", fmt.Sprintf("adds a version named %q", value["name"])
	case !sok || !tok || served || stored:
		return "", fmt.Sprintf("adds version %s without served: false and storage: false", name)
	}
	return name, ""
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
// names no other repository. dirs are the declared definition kustomization
// directories of the tag.
func (x *Extractor) classify(r extract.PinnedReader, repo extract.RepoRef, commit string, f scanFile, info *blobInfo, inv *Inventory, dirs map[string]bool) (Finding, bool, error) {
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
		switch g := info.gzip; {
		case info.goConstruct:
			fd.Class, fd.Detail = ClassGoDefined, "a CustomResourceDefinition built in Go code: its served versions are not read"
		case g == nil:
			return fd, false, nil
		case g.unread != "":
			fd.Class, fd.Detail = ClassUnread, g.unread
		case len(g.crds) > 0:
			// Definitions compressed into the source (velero install):
			// compared definition by definition like a YAML file.
			fd = compareDefinitions(fd, g.crds, inv)
		case g.kinds > 0:
			fd.Class, fd.Detail = ClassReference, "gzip-compressed string literals hold the CustomResourceDefinition kind but define none at the top level"
		default:
			return fd, false, nil
		}
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
	tpl := info.template
	switch {
	case info.unread != "" && tpl != nil && tpl.unread == "" && len(tpl.crds) > 0:
		// A templated file whose definitions its literal lines determine:
		// read without its directives.
	case info.unread != "" && tpl != nil && tpl.unread != "" && (f.at.copies || info.kindLike || isChart || isKust || tpl.kindTemplated):
		// A declared copy that cannot be read is never accepted.
		fd.Class, fd.Detail = ClassUnread, tpl.unread
		return placed(fd, f.at), true, nil
	case info.unread != "" && info.legacy != nil:
		// apiextensions.k8s.io/v1beta1 definitions, strictly read: they
		// are compared with the inventory below.
	case info.unread != "" && info.fragment != nil && info.fragment.problem == "":
		fd.Class, fd.Detail = fragmentClass(f.path, info.fragment, inv, dirs, info.unread)
		return placed(fd, f.at), true, nil
	case info.unread != "" && (info.kindLike || isChart || isKust):
		fd.Class, fd.Detail = ClassUnread, info.unread
		switch {
		case info.legacyProblem != "":
			fd.Detail = info.legacyProblem
		case info.fragment != nil && underDefinitionDir(f.path, dirs):
			fd.Detail += "; not a patch fragment the scan accepts: " + info.fragment.problem
		}
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
	fromTemplate := false
	switch {
	case info.legacy != nil:
		crds = info.legacy
	case info.unread != "":
		// Only a templated file read without its directives reaches here
		// undecoded.
		fromTemplate, crds = true, tpl.crds
	}
	if isKust && info.kust != nil && info.kust.open != "" && !info.embedded && underDefinitionDir(f.path, dirs) {
		fd.Class, fd.Detail = ClassReference, info.kust.open
		return placed(fd, f.at), true, nil
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
			why, err := x.checkKustomization(r, repo, commit, f.path, info, inv)
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
		if !isKust && !info.embedded && underDefinitionDir(f.path, dirs) {
			// Every mapping of the kind in an accepted configuration is
			// one of its checked field specs: the reader refuses any other
			// key, entry or value.
			why := info.configProblem
			if why == "" {
				fd.Class, fd.Detail = ClassKustomizeConfig, "a kustomize transformer configuration whose field specs of the kind only reach conversion settings and metadata labels and annotations"
				return placed(fd, f.at), true, nil
			}
			fd.Detail += "; not a transformer configuration the scan accepts: " + why
		}
		return placed(fd, f.at), true, nil
	}
	fd = compareDefinitions(fd, crds, inv)
	switch {
	case fromTemplate && f.at.copies:
		// A declared copy keeps its class: copy, or the conflict or extra
		// definition the reviewer's claim does not hold for.
	case fromTemplate && fd.Class == ClassCopy:
		fd = namedCopy(fd, ClassTemplatedCopy, crds, "with its template directives removed (a condition around the whole file, directives in metadata) and its expressions in metadata and spec.conversion read as placeholders, a copy of the listed paths")
	case fromTemplate:
		// Nobody claims an unreviewed template is a copy: one that is not
		// is never taken for a conflict or an extra definition.
		what := "it defines a CustomResourceDefinition the listed paths do not hold"
		if fd.Class == ClassConflict {
			what = fd.Detail
		}
		fd.Class, fd.Detail = ClassUnread, "with template directives removed, it is not a copy of the listed paths: "+what
	case info.legacy != nil && fd.Class == ClassCopy:
		fd.Class, fd.Detail = ClassLegacyCopy, "apiextensions.k8s.io/v1beta1 definitions with the versions and served flags of the listed paths"
	case info.legacy != nil && fd.Class == ClassConflict:
		fd.Detail = "apiextensions.k8s.io/v1beta1 copy: " + fd.Detail
	}
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
	fd.CRDs, fd.Served = definitionsOf(crds)
	for i := range crds {
		c := &crds[i]
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
	if fd.Class == ClassCopy {
		fd.CRDs, fd.Served = nil, nil
	}
	return fd
}

// definitionsOf returns the names of definitions and the members they
// serve, sorted.
func definitionsOf(crds []CRD) (names, served []string) {
	for i := range crds {
		c := &crds[i]
		names = append(names, c.Name)
		for _, v := range c.Versions {
			if v.Served {
				served = append(served, member(c.Group, v.Name, c.Kind))
			}
		}
	}
	sort.Strings(names)
	sort.Strings(served)
	return names, served
}

// namedCopy records a copy read in another form than a v1 manifest: a
// finding of class that does not block, naming its definitions and the
// members they serve.
func namedCopy(fd Finding, class string, crds []CRD, detail string) Finding {
	fd.Class, fd.Detail = class, detail
	fd.CRDs, fd.Served = definitionsOf(crds)
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
			s, ok := it.(string)
			switch {
			case !ok:
			case remoteSource(s):
				k.remote = append(k.remote, s)
			case field != "components":
				k.local = append(k.local, s)
			}
		}
	}
	sort.Strings(k.remote)
	sort.Strings(k.local)
	if raw, present := obj["configurations"]; present {
		items, ok := raw.([]any)
		if !ok {
			k.configBad = "configurations is not a list"
		}
		for _, it := range items {
			if s, ok := it.(string); ok && s != "" && !remoteSource(s) {
				k.configs = append(k.configs, s)
			} else {
				k.configBad = "a configurations entry is not a local file"
			}
		}
		sort.Strings(k.configs)
	}
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
			if _, present := entry["target"]; !present {
				// A strategic merge fragment: checked through its file.
				continue
			}
			target, _ := entry["target"].(map[string]any)
			if kind, _ := target["kind"].(string); kind != crdKind {
				if !literalOtherKind(kind) && k.open == "" {
					k.open = fmt.Sprintf("a %s entry selects without naming a kind other than %s", field, crdKind)
				}
				continue
			}
			k.crdTargets++
			pp, _ := entry["path"].(string)
			_, hasPath := entry["path"]
			if raw, inline := entry["patch"]; inline {
				// An inline string is read like a patch file; one that is
				// not a JSON 6902 list (a strategic merge patch) is not
				// checked, nor is an inline mapping.
				text, ok := raw.(string)
				if !ok || hasPath {
					k.problem = "a CustomResourceDefinition patch is inline or names no file"
					return k
				}
				k.inline++
				if why := schemaOnlyPatch([]byte(text)); why != "" && k.inlineBad == "" {
					k.inlineBad = fmt.Sprintf("inline patch %d: %s", k.inline, why)
				}
				continue
			}
			if pp == "" {
				k.problem = "a CustomResourceDefinition patch is inline or names no file"
				return k
			}
			k.patchPaths = append(k.patchPaths, pp)
		}
	}
	if raw, present := obj["replacements"]; present && k.open == "" {
		items, ok := raw.([]any)
		if !ok {
			k.open = "replacements is not a list"
		}
		for _, it := range items {
			if why := replacementOpen(it); why != "" {
				k.open = why
				break
			}
		}
	}
	if _, smp := obj["patchesStrategicMerge"]; smp {
		k.problem = "strategic merge patches are not checked"
	}
	if len(k.patchPaths)+k.inline > maxKustomizePatches {
		k.problem = "too many patch files"
	}
	return k
}

// literalOtherKind reports a selector kind that, as an anchored regular
// expression, matches only one kind and not the definition kind.
func literalOtherKind(kind string) bool {
	return kind != "" && kind != crdKind && regexp.QuoteMeta(kind) == kind
}

// replacementOpen returns why a replacements entry (inline, or a file
// that is not read) could change a definition ("" when every target
// selects a literal kind other than the definition kind).
func replacementOpen(v any) string {
	e, ok := v.(map[string]any)
	if !ok {
		return "a replacements entry is not a mapping"
	}
	targets, ok := e["targets"].([]any)
	if !ok || len(targets) == 0 {
		return "a replacements entry without inline targets is not checked"
	}
	for _, t := range targets {
		tm, _ := t.(map[string]any)
		sel, _ := tm["select"].(map[string]any)
		if kind, _ := sel["kind"].(string); !literalOtherKind(kind) {
			return "a replacements target selects without naming a kind other than " + crdKind
		}
	}
	return ""
}

// checkKustomization returns "" when every CustomResourceDefinition
// reference of the file is a checked patch target and every patch only
// changes version schemas, conversion settings or metadata labels and
// annotations: a JSON 6902 list (in a file, or inline as a string), or a
// strategic merge patch fragment file of definitions the inventory holds.
func (x *Extractor) checkKustomization(r extract.PinnedReader, repo extract.RepoRef, commit, p string, info *blobInfo, inv *Inventory) (string, error) {
	k := info.kust
	switch {
	case k.open != "":
		return k.open, nil
	case k.problem != "":
		return k.problem, nil
	case k.crdTargets == 0 || k.crdTargets != info.kinds:
		return "names the CustomResourceDefinition kind outside patch targets", nil
	case k.inlineBad != "":
		return k.inlineBad, nil
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
			if fragmentPatch(data, inv) {
				continue
			}
			return fmt.Sprintf("patch %s: %s", full, why), nil
		}
	}
	return "", nil
}

// fragmentPatch reports a strategic merge patch fragment (no template
// syntax, strictly decoded) of definitions the inventory holds.
func fragmentPatch(data []byte, inv *Inventory) bool {
	if len(data) > MaxFileBytes || strings.Contains(string(data), templateMarker) {
		return false
	}
	_, values, err := decodeStrict(data)
	if err != nil {
		return false
	}
	fr := readFragments(values)
	return fr.problem == "" && knownNames(fr.names, inv) == ""
}

// schemaOnlyPatch accepts a JSON 6902 patch whose every operation path
// (and from) lies under a version's schema, the conversion settings
// (spec/conversion, spec/preserveUnknownFields) or metadata
// labels/annotations.
func schemaOnlyPatch(data []byte) string {
	ops, why := patchOps(data)
	if why != "" {
		return why
	}
	for i, o := range ops {
		if why := schemaOnlyOp(i, o); why != "" {
			return why
		}
	}
	return ""
}

// patchOps decodes a JSON 6902 patch: a single strictly decodable document
// that is a list of operations, without template syntax.
func patchOps(data []byte) ([]any, string) {
	if strings.Contains(string(data), templateMarker) {
		return nil, "templated"
	}
	_, values, err := decodeStrict(data)
	if err != nil || len(values) != 1 {
		return nil, "not a single strictly decodable document"
	}
	ops, ok := values[0].([]any)
	if !ok || len(ops) == 0 {
		return nil, "not a JSON 6902 operation list"
	}
	return ops, ""
}

// schemaOnlyOp checks operation i of a JSON 6902 patch: a known op whose
// path (and from) lies under a version's schema, the conversion settings or
// metadata labels and annotations.
func schemaOnlyOp(i int, o any) string {
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
	for _, key := range sortedKeys(op) {
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
			return fmt.Sprintf("operation %d %s %q is outside version schemas, conversion settings and metadata labels and annotations", i, key, s)
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
