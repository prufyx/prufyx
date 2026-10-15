// SPDX-License-Identifier: AGPL-3.0-only

// Package helmvalues is the helm.values extractor: for one reviewed Helm
// chart it compares the chart's source at the first release of two
// consecutive release lines and derives the upgrades Helm itself refuses:
//
//   - the later chart's kubeVersion is a single lower bound above the
//     earlier one's: a require_component_version rule on Kubernetes;
//   - the later chart's values schema requires a key that its defaults no
//     longer set: a require_set_member rule on the values-path set fact;
//   - the later chart's values schema closes an object to a key the earlier
//     chart's values or schema used: a forbid_set_member rule.
//
// Everything else it reads (defaults removed or changed, values the
// templates no longer reference) is a soft fact: it is recorded in the
// pair's proof and is never a rule. Rules are anchor-only chart rules:
// their subject is the chart, from the first release of one line to the
// first release of the next.
package helmvalues

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
)

// Identity.
const (
	// IDPrefix is followed by the project slug and the chart name.
	IDPrefix = "helm.values."
	Version  = "1.1.0"
	// SourceDir is this package's directory under the module's internal/.
	SourceDir = "extract/helmvalues"
)

// source is the package's code and its reviewed target table; both are
// covered by the code digest.
//
//go:embed *.go targets.json
var source embed.FS

// KubernetesComponent is the component a kubeVersion rule bounds.
const KubernetesComponent = "pkg:github/kubernetes/kubernetes"

// Reason codes.
const (
	ReasonKubeVersion = "HELM_CHART_KUBE_VERSION_UNMET"
	ReasonRequired    = "HELM_VALUES_REQUIRED_KEY_UNSET"
	ReasonNotAllowed  = "HELM_VALUES_KEY_NOT_ALLOWED"
)

const (
	maxIDBytes     = 128
	maxNext        = 256
	maxTagsPerLine = 64
	maxRuleMembers = constraintengine.MaxForbiddenMembers
	// maxTemplateFiles bounds the files read under templates/.
	maxTemplateFiles = 2000
	// globalKey is the values key Helm shares with every subchart.
	globalKey = "global"
)

// Extractor implements chartrun.Extractor for one target.
type Extractor struct {
	target Target

	mu sync.Mutex
	// lines is the release lines of the last Pairs call, by line key.
	lines map[string]*releaseLine
	// lineOf maps a tag name to its line key.
	lineOf map[string]string
}

// New returns the extractor of a target.
func New(t Target) *Extractor {
	return &Extractor{target: t, lines: map[string]*releaseLine{}, lineOf: map[string]string{}}
}

// ID implements chartrun.Extractor.
func (x *Extractor) ID() string { return x.target.ExtractorID() }

// Version implements chartrun.Extractor.
func (x *Extractor) Version() string { return Version }

// SourceFiles implements chartrun.Extractor: the package's code and its target table.
func (x *Extractor) SourceFiles() (string, fs.FS) { return SourceDir, source }

// DependencySources implements chartrun.DependencySource: the shared values
// reader and member encoding are part of this extractor's code.
func (x *Extractor) DependencySources() []extract.SourceSet {
	dir, files := helmvaluespath.Source()
	return []extract.SourceSet{{Dir: dir, Files: files}}
}

// Applies implements chartrun.Extractor.
func (x *Extractor) Applies(repo extract.RepoRef) bool { return repo.Key == x.target.Repo }

// Target returns the extractor's target.
func (x *Extractor) Target() Target { return x.target }

// releaseLine is one major.minor line and its final release tags, lowest
// patch first. The anchor is the first tag.
type releaseLine struct {
	Major, Minor int
	Tags         []extract.Tag
	Versions     []string
	// Problem is set when the line has too many tags.
	Problem string
}

func (l *releaseLine) key() string { return fmt.Sprintf("%d.%d", l.Major, l.Minor) }

func (x *Extractor) tagRE() *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(x.target.TagPrefix) + `(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
}

// releaseLines groups the final release tags of the index by line.
func (x *Extractor) releaseLines(index extract.ReleaseIndex) []*releaseLine {
	type rel struct {
		v   [3]int
		tag extract.Tag
	}
	re := x.tagRE()
	var rels []rel
	for _, t := range index.Tags {
		if !extract.IsCommitSHA(t.Commit) {
			continue
		}
		m := re.FindStringSubmatch(t.Name)
		if m == nil {
			continue
		}
		var r rel
		for i := 0; i < 3; i++ {
			r.v[i], _ = strconv.Atoi(m[i+1])
		}
		r.tag = t
		rels = append(rels, r)
	}
	sort.Slice(rels, func(i, j int) bool {
		a, b := rels[i].v, rels[j].v
		for k := 0; k < 3; k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return rels[i].tag.Name < rels[j].tag.Name
	})
	byKey := map[string]*releaseLine{}
	var out []*releaseLine
	for _, r := range rels {
		k := fmt.Sprintf("%d.%d", r.v[0], r.v[1])
		l := byKey[k]
		if l == nil {
			l = &releaseLine{Major: r.v[0], Minor: r.v[1]}
			byKey[k] = l
			out = append(out, l)
		}
		l.Tags = append(l.Tags, r.tag)
		l.Versions = append(l.Versions, fmt.Sprintf("%d.%d.%d", r.v[0], r.v[1], r.v[2]))
	}
	for _, l := range out {
		if len(l.Tags) > maxTagsPerLine {
			l.Problem = fmt.Sprintf("the line has %d release tags, over the bound of %d", len(l.Tags), maxTagsPerLine)
		}
	}
	return out
}

// Pairs implements chartrun.Extractor: every two consecutive release lines
// whose earlier line is at or after MinFrom, each named by its first final
// release. A tag with a pre-release or build suffix never counts.
func (x *Extractor) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	lines := x.releaseLines(index)
	x.mu.Lock()
	x.lines, x.lineOf = map[string]*releaseLine{}, map[string]string{}
	for _, l := range lines {
		x.lines[l.key()] = l
		for _, t := range l.Tags {
			x.lineOf[t.Name] = l.key()
		}
	}
	x.mu.Unlock()
	var out []extract.VersionPair
	for i := 1; i < len(lines); i++ {
		from, to := lines[i-1], lines[i]
		if from.Major < x.target.MinFrom[0] || (from.Major == x.target.MinFrom[0] && from.Minor < x.target.MinFrom[1]) {
			continue
		}
		out = append(out, extract.VersionPair{
			Repo: index.Repo,
			From: from.Versions[0], FromTag: from.Tags[0].Name, FromCommit: from.Tags[0].Commit,
			To: to.Versions[0], ToTag: to.Tags[0].Name, ToCommit: to.Tags[0].Commit,
		})
	}
	return out
}

// lineFor returns the line of an anchor tag, or a one-tag line when the
// tag was not seen by Pairs.
func (x *Extractor) lineFor(tag, commit, version string) *releaseLine {
	x.mu.Lock()
	defer x.mu.Unlock()
	if k, ok := x.lineOf[tag]; ok {
		if l := x.lines[k]; l != nil && l.Tags[0].Name == tag && l.Tags[0].Commit == commit {
			return l
		}
	}
	return &releaseLine{Tags: []extract.Tag{{Name: tag, Commit: commit}}, Versions: []string{version}}
}

// side is one chart release as read.
type side struct {
	tag, commit, version string
	// problem is why the release cannot be read completely.
	problem string
	meta    chartMeta
	values  any
	schema  schemaNode
	// subcharts are the top-level values keys Helm fills with subchart
	// values; opaqueSubcharts is set when a packaged subchart's name is
	// not read.
	subcharts       []string
	opaqueSubcharts bool
	templates       TemplateRefs
	chartYAML       string
	valuesYAML      string
	schemaJSON      string
	chartYAMLLines  int
}

func (s *side) fail(format string, args ...any) *side {
	s.problem = fmt.Sprintf(format, args...)
	return s
}

func isNotFound(err error) bool { return errors.Is(err, extract.ErrNotFound) }

// readSide reads the chart at one commit. version is the chart version the
// tag names; "" skips the check (an inventory of one commit). A reader
// error that is not a missing path aborts the run.
func (x *Extractor) readSide(r extract.PinnedReader, repo extract.RepoRef, tag, commit, version string, templates bool) (*side, error) {
	t := x.target
	s := &side{tag: tag, commit: commit, version: version,
		chartYAML: t.ChartPath + "/Chart.yaml", valuesYAML: t.ChartPath + "/values.yaml", schemaJSON: t.ChartPath + "/values.schema.json"}
	entries, err := r.List(repo, commit, t.ChartPath)
	if isNotFound(err) {
		return s.fail("the chart directory %s does not exist", t.ChartPath), nil
	}
	if err != nil {
		return nil, err
	}
	present := map[string]string{}
	for _, e := range entries {
		present[path.Base(e.Path)] = e.Type
	}
	if present["Chart.yaml"] != "blob" {
		return s.fail("%s is not a file", s.chartYAML), nil
	}
	data, err := r.Read(repo, commit, s.chartYAML)
	if err != nil {
		return nil, err
	}
	s.chartYAMLLines = lineCount(data)
	if s.meta, err = parseChartYAML(data); err != nil {
		return s.fail("%s: %v", s.chartYAML, err), nil
	}
	if s.meta.Name != t.Chart.Name {
		return s.fail("%s names chart %q, not %q", s.chartYAML, s.meta.Name, t.Chart.Name), nil
	}
	if version != "" && s.meta.Version != version {
		return s.fail("%s declares version %s, the tag names %s", s.chartYAML, s.meta.Version, version), nil
	}
	if present["values.yaml"] != "blob" {
		return s.fail("%s is not a file", s.valuesYAML), nil
	}
	if data, err = r.Read(repo, commit, s.valuesYAML); err != nil {
		return nil, err
	}
	_, s.values, err = helmvaluespath.DecodeYAML(data)
	if err != nil {
		return s.fail("%s: %v", s.valuesYAML, err), nil
	}
	if s.values != nil {
		if _, ok := s.values.(map[string]any); !ok {
			return s.fail("%s is not a mapping", s.valuesYAML), nil
		}
	}
	switch present["values.schema.json"] {
	case "":
	case "blob":
		if data, err = r.Read(repo, commit, s.schemaJSON); err != nil {
			return nil, err
		}
		if s.schema, err = decodeSchema(data); err != nil {
			return s.fail("%s: %v", s.schemaJSON, err), nil
		}
	default:
		return s.fail("%s is not a file", s.schemaJSON), nil
	}
	s.subcharts = append([]string(nil), s.meta.Dependencies...)
	switch present["requirements.yaml"] {
	case "":
	case "blob":
		if data, err = r.Read(repo, commit, t.ChartPath+"/requirements.yaml"); err != nil {
			return nil, err
		}
		_, v, err := helmvaluespath.DecodeYAML(data)
		if err != nil {
			return s.fail("requirements.yaml: %v", err), nil
		}
		m, _ := v.(map[string]any)
		deps, err := dependencyKeys(m["dependencies"])
		if err != nil {
			return s.fail("requirements.yaml: %v", err), nil
		}
		s.subcharts = append(s.subcharts, deps...)
	default:
		return s.fail("requirements.yaml is not a file"), nil
	}
	if present["charts"] == "tree" {
		if err := x.readSubcharts(r, repo, s); err != nil {
			return nil, err
		}
		if s.problem != "" {
			return s, nil
		}
	}
	sort.Strings(s.subcharts)
	s.subcharts = compactStrings(s.subcharts)
	if templates && present["templates"] == "tree" {
		files, err := listFiles(r, repo, commit, t.ChartPath+"/templates", maxTemplateFiles)
		if err != nil {
			if isBound(err) {
				return s.fail("templates: %v", err), nil
			}
			return nil, err
		}
		for _, f := range files {
			data, err := r.Read(repo, commit, f)
			if err != nil {
				return nil, err
			}
			s.templates.scanTemplate(strings.TrimPrefix(f, t.ChartPath+"/"), data)
		}
	}
	s.templates.finish()
	return s, nil
}

// readSubcharts adds the names of the subcharts vendored under charts/: a
// directory's Chart.yaml name, and marks a packaged archive opaque.
func (x *Extractor) readSubcharts(r extract.PinnedReader, repo extract.RepoRef, s *side) error {
	dir := x.target.ChartPath + "/charts"
	entries, err := r.List(repo, s.commit, dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		switch {
		case e.Type == "tree":
			data, err := r.Read(repo, s.commit, e.Path+"/Chart.yaml")
			if isNotFound(err) {
				s.opaqueSubcharts = true
				continue
			}
			if err != nil {
				return err
			}
			m, err := parseChartYAML(data)
			if err != nil {
				s.opaqueSubcharts = true
				continue
			}
			s.subcharts = append(s.subcharts, m.Name)
		case e.Type == "blob" && (strings.HasSuffix(e.Path, ".tgz") || strings.HasSuffix(e.Path, ".tar.gz")):
			// A packaged subchart is read by name only: an archive named
			// <dependency>-<version>.tgz is a declared dependency, whose
			// values key is already known; any other archive is opaque.
			if !declaredArchive(path.Base(e.Path), s.meta.Dependencies) {
				s.opaqueSubcharts = true
			}
		}
	}
	return nil
}

var archiveVersionRE = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]*)?\.(tgz|tar\.gz)$`)

func declaredArchive(name string, deps []string) bool {
	for _, d := range deps {
		if strings.HasPrefix(name, d+"-") && archiveVersionRE.MatchString(strings.TrimPrefix(name, d+"-")) {
			return true
		}
	}
	return false
}

type boundError struct{ msg string }

func (b *boundError) Error() string { return b.msg }

func isBound(err error) bool {
	var b *boundError
	return errors.As(err, &b)
}

// listFiles lists every file under dir, recursively, in path order.
func listFiles(r extract.PinnedReader, repo extract.RepoRef, commit, dir string, limit int) ([]string, error) {
	var out []string
	var visit func(d string, depth int) error
	visit = func(d string, depth int) error {
		if depth > 16 {
			return &boundError{"directories nest deeper than 16"}
		}
		entries, err := r.List(repo, commit, d)
		if err != nil {
			return err
		}
		for _, e := range entries {
			p := e.Path
			switch e.Type {
			case "tree":
				if err := visit(p, depth+1); err != nil {
					return err
				}
			case "blob":
				out = append(out, p)
				if len(out) > limit {
					return &boundError{fmt.Sprintf("more than %d files", limit)}
				}
			}
		}
		return nil
	}
	if err := visit(dir, 0); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func lineCount(data []byte) int {
	n := strings.Count(string(data), "\n")
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n
}

// subchartKey reports whether a path's first key is filled by a subchart
// or shared with them: the parent schema validates such keys against
// values the parent's own files do not show.
func (s *side) subchartKey(p []string) bool {
	if len(p) == 0 {
		return false
	}
	if p[0] == globalKey {
		return true
	}
	for _, d := range s.subcharts {
		if d == p[0] {
			return true
		}
	}
	return false
}

// singleCommit reports the pair an inventory asks for: both sides are one
// commit, named "inventory".
func singleCommit(pair extract.VersionPair) bool {
	a, b := pair.FromCommit, pair.ToCommit
	return a == b && pair.FromTag == "inventory"
}

// Extract implements chartrun.Extractor.
func (x *Extractor) Extract(ctx context.Context, r extract.PinnedReader, pair extract.VersionPair) (chartrun.Extraction, error) {
	inventory := singleCommit(pair)
	fromVersion, toVersion := pair.From, pair.To
	if inventory {
		fromVersion, toVersion = "", ""
	}
	from, err := x.readSide(r, pair.Repo, pair.FromTag, pair.FromCommit, fromVersion, true)
	if err != nil {
		return chartrun.Extraction{}, err
	}
	to := from
	if !inventory {
		if to, err = x.readSide(r, pair.Repo, pair.ToTag, pair.ToCommit, toVersion, true); err != nil {
			return chartrun.Extraction{}, err
		}
	}
	proof := &PairProof{Target: x.target.Project, Chart: x.target.Chart, From: sideRecord(from), To: sideRecord(to)}
	if !inventory {
		fromLine, toLine := x.lineFor(pair.FromTag, pair.FromCommit, pair.From), x.lineFor(pair.ToTag, pair.ToCommit, pair.To)
		if proof.Lines, err = x.linesRecord(ctx, r, pair.Repo, fromLine, toLine); err != nil {
			return chartrun.Extraction{}, err
		}
	}
	for _, s := range []*side{from, to} {
		if s.problem != "" {
			return chartrun.Extraction{}, &extract.Withheld{Reason: fmt.Sprintf("%s at %s: %s", x.target.Chart.Name, s.tag, s.problem), Proof: proof}
		}
	}
	if inventory {
		return chartrun.Extraction{Proof: proof}, nil
	}
	var candidates []chartrun.Candidate
	kube, c := x.kubeVersion(pair, from, to)
	proof.KubeVersion = kube
	if c != nil {
		candidates = append(candidates, *c)
	}
	req, c := x.required(pair, from, to)
	proof.Required = req
	if c != nil {
		candidates = append(candidates, *c)
	}
	rem, c := x.removed(pair, from, to)
	proof.Removed = rem
	if c != nil {
		candidates = append(candidates, *c)
	}
	proof.Soft = softFacts(from, to)
	proof.Completeness = completeness(proof)
	for _, c := range candidates {
		proof.Rules = append(proof.Rules, c.Rule.ID)
	}
	if proof.Rules == nil {
		proof.Rules = []string{}
	}
	return chartrun.Extraction{Candidates: candidates, Proof: proof}, nil
}

// linesRecord reads every other final release of both lines (Chart.yaml,
// values.yaml and the schema) and records whether each reads completely.
// A rule is about the anchors only, so a release that does not read is
// recorded and never withholds the pair.
func (x *Extractor) linesRecord(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, lines ...*releaseLine) (*LinesRecord, error) {
	rec := &LinesRecord{}
	for i, l := range lines {
		lr := LineRecord{Line: l.key(), Problem: l.Problem, Releases: []LineTag{}}
		for j, t := range l.Tags {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			lt := LineTag{Tag: t.Name, Commit: t.Commit, Version: l.Versions[j], Anchor: j == 0}
			if j > 0 && l.Problem == "" {
				s, err := x.readSide(r, repo, t.Name, t.Commit, l.Versions[j], false)
				if err != nil {
					return nil, err
				}
				lt.Problem = s.problem
			}
			lr.Releases = append(lr.Releases, lt)
		}
		if i == 0 {
			rec.From = lr
		} else {
			rec.To = lr
		}
	}
	return rec, nil
}

func slug(v string) string { return strings.ReplaceAll(v, ".", "-") }

func (x *Extractor) ruleID(pair extract.VersionPair, kind string) (string, error) {
	id := fmt.Sprintf("%s.helm-values.%s.%s-to-%s.%s", x.target.Project, x.target.Chart.Name, slug(pair.From), slug(pair.To), kind)
	if len(id) > maxIDBytes {
		return "", fmt.Errorf("rule id %s is %d bytes, over %d", id, len(id), maxIDBytes)
	}
	return id, nil
}

func (x *Extractor) subject(pair extract.VersionPair) chartrun.Subject {
	chart := x.target.Chart
	return chartrun.Subject{Component: x.target.Component, Chart: &chart, From: pair.From, To: pair.To}
}

// kubeVersion derives the Kubernetes lower bound rule.
func (x *Extractor) kubeVersion(pair extract.VersionPair, from, to *side) (*KubeRecord, *chartrun.Candidate) {
	rec := &KubeRecord{From: parseKubeVersion(from.meta.KubeVersion), To: parseKubeVersion(to.meta.KubeVersion)}
	switch {
	case rec.To.Shape == "absent":
		rec.Outcome = "no rule: the later chart declares no kubeVersion"
		return rec, nil
	case rec.To.Shape == "other":
		rec.Outcome = "no rule: the later kubeVersion is not a single lower bound"
		return rec, nil
	case !rec.To.PreRelease:
		rec.Outcome = "no rule: the later kubeVersion has no -0 suffix, so Helm also refuses cluster versions with a vendor suffix at or above the bound, which a declared X.Y.Z version cannot show"
		return rec, nil
	}
	fromMin := "0.0.0"
	if rec.From.Shape == "minimum" {
		fromMin = rec.From.Minimum
	}
	if compareVersions(rec.To.Minimum, fromMin) <= 0 {
		rec.Outcome = "no rule: the later lower bound is not above the earlier one"
		return rec, nil
	}
	id, err := x.ruleID(pair, "kube-version")
	if err != nil {
		rec.Outcome = "no rule: " + err.Error()
		return rec, nil
	}
	rec.Outcome = "rule"
	sources := []extract.SourceRef{{ID: "chart-yaml-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: to.chartYAML, StartLine: to.meta.KubeVersionLine, EndLine: to.meta.KubeVersionLine}}
	if from.meta.KubeVersionLine > 0 {
		sources = append([]extract.SourceRef{{ID: "chart-yaml-" + slug(pair.From), Repo: pair.Repo, Commit: pair.FromCommit, Path: from.chartYAML, StartLine: from.meta.KubeVersionLine, EndLine: from.meta.KubeVersionLine}}, sources...)
	}
	t := x.target
	return rec, &chartrun.Candidate{
		Project: t.Project,
		Description: fmt.Sprintf("The %s chart %s (%s) declares kubeVersion %q, so Helm refuses to install or upgrade it on Kubernetes below %s; chart %s declared %s. Derived from Chart.yaml at both release tags. Helm's --skip-schema-validation does not bypass this check; a cluster version is compared by its X.Y.Z.",
			t.Chart.Name, pair.To, t.Name, rec.To.Constraint, rec.To.Minimum, pair.From, kubeLabel(rec.From)),
		RequiredFacts: []extract.Fact{},
		Rule: chartrun.Rule{
			ID: id, Operator: "require_component_version", Subject: x.subject(pair),
			Dependency: &chartrun.Dependency{Side: "proposed", Component: KubernetesComponent, Comparison: "gte", Version: rec.To.Minimum},
			ReasonCode: ReasonKubeVersion,
			NextAction: boundNext(fmt.Sprintf("upgrade Kubernetes to %s or later before upgrading the %s chart to %s; Helm refuses the chart on an older cluster", rec.To.Minimum, t.Chart.Name, pair.To)),
		},
		Sources: sources,
	}
}

func kubeLabel(k KubeMinimum) string {
	if k.Shape == "absent" {
		return "no kubeVersion"
	}
	return fmt.Sprintf("kubeVersion %q", k.Constraint)
}

func boundNext(s string) string {
	if len(s) <= maxNext {
		return s
	}
	return s[:maxNext]
}

// Required-key classes.
const (
	ClassRule            = "rule"
	ClassDefault         = "default"
	ClassNullDefault     = "null-default"
	ClassAlready         = "already-required"
	ClassInactive        = "inactive-ancestor"
	ClassEmptyAncestor   = "empty-ancestor"
	ClassSubchart        = "subchart"
	ClassUnexpressible   = "unexpressible" // its member would be over the 128-byte bound
	ClassOverBound       = "over-bound"
	ClassOpaqueSubcharts = "packaged-subchart"
)

// requirement classifies one required key at one side: whether the
// defaults alone satisfy it.
func requirement(s *side, p []string) string {
	if s.subchartKey(p) {
		return ClassSubchart
	}
	if s.opaqueSubcharts {
		return ClassOpaqueSubcharts
	}
	for i := 1; i < len(p); i++ {
		v, ok := helmvaluespath.ValueAt(s.values, p[:i])
		if !ok || v == nil {
			return ClassInactive
		}
		m, isMap := v.(map[string]any)
		if !isMap {
			return ClassInactive
		}
		if len(m) == 0 {
			return ClassEmptyAncestor
		}
	}
	if v, ok := helmvaluespath.ValueAt(s.values, p); ok {
		if v == nil {
			return ClassNullDefault
		}
		return ClassDefault
	}
	return ClassRule
}

// required derives the require_set_member rule: keys the later schema
// requires, under ancestors its defaults set, with no default of their own,
// that the earlier chart's defaults satisfied (or did not require).
func (x *Extractor) required(pair extract.VersionPair, from, to *side) (*RequiredRecord, *chartrun.Candidate) {
	rec := &RequiredRecord{Keys: []KeyClass{}, Opaque: []OpaqueNode{}}
	if to.schema == nil {
		rec.Outcome = "no rule: the later chart has no values.schema.json"
		return rec, nil
	}
	walk := walkSchema(to.schema)
	rec.Opaque = append(rec.Opaque, walk.Opaque...)
	fromRequired := map[string]bool{}
	if from.schema != nil {
		for _, p := range walkSchema(from.schema).Required {
			fromRequired[strings.Join(p, "\x00")] = true
		}
	}
	var members []string
	for _, p := range walk.Required {
		class := requirement(to, p)
		if class == ClassRule && fromRequired[strings.Join(p, "\x00")] && requirement(from, p) == ClassRule {
			class = ClassAlready
		}
		m, ok := helmvaluespath.Member(p)
		if class == ClassRule && !ok {
			class = ClassUnexpressible
		}
		rec.Keys = append(rec.Keys, KeyClass{Path: helmvaluespath.DisplayPath(p), Class: class})
		if class == ClassRule {
			members = append(members, m)
		}
	}
	if len(members) == 0 {
		rec.Outcome = "no rule: no required key lost its default"
		return rec, nil
	}
	members = sortedUnique(members)
	if len(members) > maxRuleMembers {
		for i := range rec.Keys {
			if rec.Keys[i].Class == ClassRule {
				rec.Keys[i].Class = ClassOverBound
			}
		}
		rec.Outcome = fmt.Sprintf("no rule: %d keys, over the bound of %d members per rule", len(members), maxRuleMembers)
		return rec, nil
	}
	id, err := x.ruleID(pair, "required-values")
	if err != nil {
		rec.Outcome = "no rule: " + err.Error()
		return rec, nil
	}
	rec.Outcome = "rule"
	t := x.target
	return rec, &chartrun.Candidate{
		Project:       t.Project,
		Description:   fmt.Sprintf("The values schema of the %s chart %s (%s) requires %d key(s) that its default values do not set, which chart %s's defaults satisfied: Helm refuses the upgrade unless the supplied values set each one. Derived from values.schema.json and values.yaml at both release tags; keys under subchart or global values are not checked. Helm's --skip-schema-validation bypasses the check.", t.Chart.Name, pair.To, t.Name, len(members), pair.From),
		RequiredFacts: []extract.Fact{x.valuesFact()},
		Rule: chartrun.Rule{
			ID: id, Operator: constraintengine.OperatorRequireSetMember, Subject: x.subject(pair),
			SetCondition: &extract.SetCondition{Side: "proposed", Component: t.Component, FactID: t.FactID(), Members: members},
			ReasonCode:   ReasonRequired,
			NextAction:   boundNext(fmt.Sprintf("set every listed key in the values supplied for the %s chart %s; its values schema requires each and the chart sets no default", t.Chart.Name, pair.To)),
		},
		Sources: []extract.SourceRef{
			{ID: "values-schema-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: to.schemaJSON},
			{ID: "values-yaml-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: to.valuesYAML},
		},
	}
}

func (x *Extractor) valuesFact() extract.Fact {
	t := x.target
	return extract.Fact{
		Side: "proposed", ID: t.FactID(), Component: t.Component, Type: string(constraintengine.FactSet),
		Description: fmt.Sprintf("Key paths (through mappings only) of the values supplied for the %s chart whose value is not null, before the chart's defaults are merged: keys joined by \".\" when every key is over [A-Za-z0-9_/-] and the first starts with a letter or digit, otherwise the documented escaped form \"k..\" followed by the keys joined by \"..\", each byte outside [A-Za-z0-9/-] written as _ and two upper-case hex digits. Complete only when every values source of the release is read.", t.Chart.Name),
	}
}

// Removed-key classes.
const (
	ClassRejected       = "rejected"
	ClassStillDefaulted = "still-defaulted"
	ClassWasRejected    = "already-rejected"
	ClassOpaque         = "opaque"
)

// removed derives the forbid_set_member rule: values keys the earlier
// chart used (in its defaults or its schema) that the later schema refuses
// as unknown keys of a closed object.
func (x *Extractor) removed(pair extract.VersionPair, from, to *side) (*RemovedRecord, *chartrun.Candidate) {
	rec := &RemovedRecord{Keys: []KeyClass{}, Counts: map[string]int{}}
	if to.schema == nil {
		rec.Outcome = "no rule: the later chart has no values.schema.json"
		return rec, nil
	}
	cands := map[string][]string{}
	for _, p := range helmvaluespath.ValuePaths(from.values) {
		cands[strings.Join(p, "\x00")] = p
	}
	if from.schema != nil {
		for _, p := range schemaPaths(from.schema) {
			cands[strings.Join(p, "\x00")] = p
		}
	}
	keys := make([]string, 0, len(cands))
	for k := range cands {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rec.Candidates = len(keys)
	prefixes := map[string]bool{}
	var members []string
	for _, k := range keys {
		p := cands[k]
		class, shown := "", ""
		switch {
		case to.subchartKey(p) || from.subchartKey(p):
			class = ClassSubchart
		case to.opaqueSubcharts:
			class = ClassOpaqueSubcharts
		default:
			prefix, ok, reason := rejection(to.schema, p)
			switch {
			case !ok && strings.HasPrefix(reason, "opaque"):
				class, shown = ClassOpaque, reason
			case !ok && reason == "every key is declared":
				class = "declared"
			case !ok && strings.HasPrefix(reason, "open"):
				class = "open"
			case !ok:
				class, shown = ClassOpaque, reason
			default:
				pk := strings.Join(prefix, "\x00")
				if prefixes[pk] {
					class = "same-prefix"
					break
				}
				prefixes[pk] = true
				shown = helmvaluespath.DisplayPath(prefix)
				m, expressible := helmvaluespath.Member(prefix)
				switch {
				case present(to.values, prefix):
					class = ClassStillDefaulted
				case from.schema != nil && wasRejected(from.schema, prefix):
					class = ClassWasRejected
				case !expressible:
					class = ClassUnexpressible
				default:
					class = ClassRejected
					members = append(members, m)
				}
			}
		}
		rec.Counts[class]++
		if class != "declared" && class != "open" && class != "same-prefix" {
			rec.Keys = append(rec.Keys, KeyClass{Path: helmvaluespath.DisplayPath(p), Class: class, Detail: shown})
		}
	}
	if len(members) == 0 {
		rec.Outcome = "no rule: the later schema refuses no key the earlier chart used"
		return rec, nil
	}
	members = sortedUnique(members)
	if len(members) > maxRuleMembers {
		rec.Outcome = fmt.Sprintf("no rule: %d keys, over the bound of %d members per rule", len(members), maxRuleMembers)
		return rec, nil
	}
	id, err := x.ruleID(pair, "removed-values")
	if err != nil {
		rec.Outcome = "no rule: " + err.Error()
		return rec, nil
	}
	rec.Outcome = "rule"
	t := x.target
	sources := []extract.SourceRef{{ID: "values-yaml-" + slug(pair.From), Repo: pair.Repo, Commit: pair.FromCommit, Path: from.valuesYAML}}
	if from.schema != nil {
		sources = append(sources, extract.SourceRef{ID: "values-schema-" + slug(pair.From), Repo: pair.Repo, Commit: pair.FromCommit, Path: from.schemaJSON})
	}
	sources = append(sources, extract.SourceRef{ID: "values-schema-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: to.schemaJSON})
	return rec, &chartrun.Candidate{
		Project:       t.Project,
		Description:   fmt.Sprintf("The values schema of the %s chart %s (%s) no longer admits %d key(s) that chart %s's values or schema used: each lies in an object the schema closes (additionalProperties false), so Helm refuses supplied values that set one. Derived from values.yaml and values.schema.json at both release tags; keys under subchart or global values are not checked. Helm's --skip-schema-validation bypasses the check.", t.Chart.Name, pair.To, t.Name, len(members), pair.From),
		RequiredFacts: []extract.Fact{x.valuesFact()},
		Rule: chartrun.Rule{
			ID: id, Operator: constraintengine.OperatorForbidSetMember, Subject: x.subject(pair),
			SetCondition: &extract.SetCondition{Side: "proposed", Component: t.Component, FactID: t.FactID(), Members: members},
			ReasonCode:   ReasonNotAllowed,
			NextAction:   boundNext(fmt.Sprintf("remove or rename every listed key in the values supplied for the %s chart %s; its values schema no longer admits them", t.Chart.Name, pair.To)),
		},
		Sources: sources,
	}
}

// wasRejected reports whether the earlier schema already refused prefix:
// a user could not have set it, so the later refusal changes nothing.
func wasRejected(s schemaNode, prefix []string) bool {
	got, ok, _ := rejection(s, prefix)
	return ok && len(got) <= len(prefix)
}

// schemaPaths lists every key path the schema declares through properties
// of readable objects.
func schemaPaths(root schemaNode) [][]string {
	var out [][]string
	var visit func(n schemaNode, p []string)
	visit = func(n schemaNode, p []string) {
		if n.opaqueReason(len(p) == 0) != "" {
			return
		}
		props, _ := n["properties"].(map[string]any)
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			q := helmvaluespath.AppendPath(p, k)
			out = append(out, q)
			if child, _, reason := n.property(k); reason == "" && !child.leaf() {
				visit(child, q)
			}
		}
	}
	visit(root, nil)
	return out
}

func sortedUnique(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return compactStrings(out)
}

// softFacts records what changed that Helm does not refuse: defaults the
// later chart removed or changed, and values the later templates no longer
// reference. They are never rules.
func softFacts(from, to *side) *SoftRecord {
	rec := &SoftRecord{DefaultsRemoved: []string{}, DefaultsChanged: []string{}, ReferencesRemoved: []string{}}
	removed := map[string]bool{}
	for _, p := range helmvaluespath.ValuePaths(from.values) {
		if len(p) > 1 && removed[strings.Join(p[:len(p)-1], "\x00")] {
			removed[strings.Join(p, "\x00")] = true
			continue
		}
		v, ok := helmvaluespath.ValueAt(to.values, p)
		if !ok || v == nil {
			removed[strings.Join(p, "\x00")] = true
			rec.DefaultsRemoved = append(rec.DefaultsRemoved, helmvaluespath.DisplayPath(p))
			continue
		}
		old, _ := helmvaluespath.ValueAt(from.values, p)
		if scalar(old) && scalar(v) && fmt.Sprint(old) != fmt.Sprint(v) {
			rec.DefaultsChanged = append(rec.DefaultsChanged, helmvaluespath.DisplayPath(p))
		}
	}
	toRefs := map[string]bool{}
	for _, p := range to.templates.Paths {
		toRefs[p] = true
	}
	for _, p := range from.templates.Paths {
		if !toRefs[p] {
			rec.ReferencesRemoved = append(rec.ReferencesRemoved, p)
		}
	}
	return rec
}

func scalar(v any) bool {
	switch v.(type) {
	case map[string]any, []any, nil:
		return false
	}
	return true
}

// completeness accounts for every key the derivation considered: each
// required key and each earlier key has exactly one class.
func completeness(p *PairProof) *Completeness {
	c := &Completeness{}
	if p.Required != nil {
		c.RequiredKeys = len(p.Required.Keys)
		c.SchemaOpaque = len(p.Required.Opaque)
	}
	if p.Removed != nil {
		c.EarlierKeys = p.Removed.Candidates
		for _, n := range p.Removed.Counts {
			c.EarlierKeysClassified += n
		}
	}
	if earlier, later := p.From, p.To; earlier != nil && later != nil {
		c.TemplatesRefused = len(earlier.Templates.Refused) + len(later.Templates.Refused)
	}
	return c
}
