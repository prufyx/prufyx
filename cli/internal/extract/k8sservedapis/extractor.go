// SPDX-License-Identifier: AGPL-3.0-only

// Package k8sservedapis is the k8s.served-api-removal extractor. For each
// consecutive minor release pair v1.(L-1).0 -> v1.L.0 of
// kubernetes/kubernetes it parses every generated API lifecycle file at the
// earlier tag commit, collects the group/version/kinds whose
// APILifecycleRemoved() is 1.L, and checks them against the OpenAPI
// specifications of both tags: each removal must be declared at the earlier
// release and absent at the later one, and no declared kind may disappear
// without a lifecycle removal. Any disagreement, or any file that cannot be
// parsed completely, withholds the whole pair. See
// docs/extractors/k8s.served-api-removal.md for the public specification.
package k8sservedapis

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
)

// Identity.
const (
	ID      = "k8s.served-api-removal"
	Version = "1.0.0"
	// SourceDir is this package's directory under the module's internal/.
	SourceDir = "extract/k8sservedapis"
)

//go:embed *.go
var source embed.FS

// Repo is the only repository this extractor reads.
const Repo = "github.com/kubernetes/kubernetes"

// MinFromMinor is the first source minor (of major 1) this version reads:
// v1.19.0 is the first release tag whose tree holds
// staging/src/k8s.io/api/**/zz_generated.prerelease-lifecycle.go (v1.18.0
// holds none). The first evaluated pair is therefore v1.19.0 -> v1.20.0;
// earlier lines are not emitted.
const MinFromMinor = 19

const (
	project    = "kubernetes"
	purl       = "pkg:github/kubernetes/kubernetes"
	reasonCode = "KUBERNETES_SERVED_API_REMOVED"
	specPath   = "api/openapi-spec/swagger.json"
	apiRoot    = "staging/src/k8s.io/api"
)

// versionRoots are the directories whose children are API version
// directories directly (the other lifecycle-bearing staging repositories).
var versionRoots = []string{
	"staging/src/k8s.io/apiextensions-apiserver/pkg/apis/apiextensions",
	"staging/src/k8s.io/kube-aggregator/pkg/apis/apiregistration",
}

// metaKinds are auxiliary kinds that carry no lifecycle declaration and leave
// the specification without any API version being removed: the options and
// watch envelopes registered in every group version, and the subresource
// bodies Eviction and EphemeralContainers, whose registration moved between
// releases. A kind outside this list that leaves a beta or stable version of
// the specification without a lifecycle removal withholds the pair.
var metaKinds = map[string]bool{"DeleteOptions": true, "WatchEvent": true, "Eviction": true, "EphemeralContainers": true}

// Extractor implements extract.Extractor. It caches the parsed lifecycle
// files and specification per commit; both are pure functions of pinned
// bytes.
type Extractor struct {
	mu    sync.Mutex
	files map[string]*lifecycleSet
	specs map[string]map[gvk]bool
}

// New returns an extractor. The concurrency argument is accepted for the
// common constructor shape; reads are sequential.
func New(_ int) *Extractor {
	return &Extractor{files: map[string]*lifecycleSet{}, specs: map[string]map[gvk]bool{}}
}

// ID implements extract.Extractor.
func (x *Extractor) ID() string { return ID }

// Version implements extract.Extractor.
func (x *Extractor) Version() string { return Version }

// SourceFiles implements extract.CodeSource.
func (x *Extractor) SourceFiles() (string, fs.FS) { return SourceDir, source }

// Applies implements extract.Extractor.
func (x *Extractor) Applies(repo extract.RepoRef) bool { return repo.Key == Repo }

var releaseTagRE = regexp.MustCompile(`^v(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.0$`)

// Pairs implements extract.Extractor: every v1.(L-1).0 -> v1.L.0 where both
// tags exist with a pinned commit and L-1 >= MinFromMinor. Only final .0
// release tags match.
func (x *Extractor) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	tags := map[int]extract.Tag{}
	for _, t := range index.Tags {
		m := releaseTagRE.FindStringSubmatch(t.Name)
		if m == nil || m[1] != "1" || !extract.IsCommitSHA(t.Commit) {
			continue
		}
		minor, _ := strconv.Atoi(m[2])
		tags[minor] = t
	}
	var minors []int
	for minor := range tags {
		if _, ok := tags[minor-1]; ok && minor-1 >= MinFromMinor {
			minors = append(minors, minor)
		}
	}
	sort.Ints(minors)
	var out []extract.VersionPair
	for _, minor := range minors {
		from, to := tags[minor-1], tags[minor]
		out = append(out, extract.VersionPair{
			Repo: index.Repo,
			From: strings.TrimPrefix(from.Name, "v"), FromTag: from.Name, FromCommit: from.Commit,
			To: strings.TrimPrefix(to.Name, "v"), ToTag: to.Name, ToCommit: to.Commit,
		})
	}
	return out
}

// lifecycleSet is every lifecycle file of one commit.
type lifecycleSet struct {
	Files []lifecycleFile
}

// problem marks an error that withholds a pair rather than aborting a run.
type problem struct{ msg string }

func (p problem) Error() string { return p.msg }

func asProblem(err error) (problem, bool) {
	var p problem
	if errors.As(err, &p) {
		return p, true
	}
	return problem{}, false
}

func (x *Extractor) lifecycle(r extract.PinnedReader, repo extract.RepoRef, commit string) (*lifecycleSet, error) {
	x.mu.Lock()
	set := x.files[commit]
	x.mu.Unlock()
	if set != nil {
		return set, nil
	}
	set, err := discover(r, repo, commit)
	if err != nil {
		return nil, err
	}
	x.mu.Lock()
	x.files[commit] = set
	x.mu.Unlock()
	return set, nil
}

// discover lists the API trees and parses every lifecycle file found.
func discover(r extract.PinnedReader, repo extract.RepoRef, commit string) (*lifecycleSet, error) {
	list := func(dir string) ([]extract.TreeEntry, error) {
		es, err := r.List(repo, commit, dir)
		if errors.Is(err, extract.ErrNotFound) {
			return nil, problem{"directory " + dir + " does not exist"}
		}
		return es, err
	}
	var dirs []string // version directories holding a lifecycle file
	scan := func(parent string) error {
		es, err := list(parent)
		if err != nil {
			return err
		}
		for _, e := range es {
			if e.Type != "tree" || !versionDirRE.MatchString(path.Base(e.Path)) {
				continue
			}
			inner, err := list(e.Path)
			if err != nil {
				return err
			}
			for _, f := range inner {
				if f.Type == "blob" && path.Base(f.Path) == lifecyclePkg {
					dirs = append(dirs, e.Path)
				}
			}
		}
		return nil
	}
	groups, err := list(apiRoot)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.Type == "tree" && !versionDirRE.MatchString(path.Base(g.Path)) {
			if err := scan(g.Path); err != nil {
				return nil, err
			}
		}
	}
	for _, root := range versionRoots {
		if err := scan(root); err != nil {
			return nil, err
		}
	}
	sort.Strings(dirs)
	set := &lifecycleSet{}
	seen := map[string]string{}
	for _, dir := range dirs {
		version := path.Base(dir)
		lp := dir + "/" + lifecyclePkg
		src, err := r.Read(repo, commit, lp)
		if err != nil {
			return nil, err
		}
		removed, err := parseLifecycle(lp, version, src)
		if err != nil {
			return nil, problem{err.Error()}
		}
		rp := dir + "/register.go"
		reg, err := r.Read(repo, commit, rp)
		if errors.Is(err, extract.ErrNotFound) {
			return nil, problem{"no register.go beside " + lp + " to name its API group"}
		}
		if err != nil {
			return nil, err
		}
		group, err := parseGroupName(rp, reg)
		if err != nil {
			return nil, problem{err.Error()}
		}
		key := group + "/" + version
		if prev, dup := seen[key]; dup {
			return nil, problem{fmt.Sprintf("%s and %s both declare %s", prev, lp, key)}
		}
		seen[key] = lp
		set.Files = append(set.Files, lifecycleFile{Path: lp, Group: group, Version: version, Removed: removed})
	}
	return set, nil
}

func (x *Extractor) spec(r extract.PinnedReader, repo extract.RepoRef, commit string) (map[gvk]bool, error) {
	x.mu.Lock()
	s := x.specs[commit]
	x.mu.Unlock()
	if s != nil {
		return s, nil
	}
	src, err := r.Read(repo, commit, specPath)
	if errors.Is(err, extract.ErrNotFound) {
		return nil, problem{"the OpenAPI specification " + specPath + " does not exist"}
	}
	if err != nil {
		return nil, err
	}
	s, err = parseSpec(specPath, src)
	if err != nil {
		return nil, problem{err.Error()}
	}
	x.mu.Lock()
	x.specs[commit] = s
	x.mu.Unlock()
	return s, nil
}

// Proof types: what the manifest records for each pair.

type kindLine struct {
	Kind      string `json:"kind"`
	StartLine int    `json:"startLine"`
	EndLine   int    `json:"endLine"`
}

type factUse struct {
	Fact         string   `json:"fact"`
	Kinds        []string `json:"kinds"`
	Replacements []string `json:"replacements"`
}

type removalProof struct {
	Group        string     `json:"group"`
	Version      string     `json:"version"`
	Kinds        []string   `json:"kinds"`
	ListKinds    []string   `json:"listKinds"`
	Path         string     `json:"path"`
	KindLines    []kindLine `json:"kindLines"`
	Replacements []string   `json:"replacements"`
	Facts        []factUse  `json:"facts"`
	NoFactKinds  []string   `json:"noFactKinds"`
}

type pairProof struct {
	FromTag        string         `json:"fromTag"`
	ToTag          string         `json:"toTag"`
	TargetLine     string         `json:"targetLine"`
	LifecycleFiles int            `json:"lifecycleFiles"`
	RemovedDecls   int            `json:"removedDecls"`
	SpecKindsFrom  int            `json:"specKindsFrom"`
	SpecKindsTo    int            `json:"specKindsTo"`
	Removals       []removalProof `json:"removals"`
	// AlphaDeclared and AlphaGone record, for information only, the alpha
	// kinds whose lifecycle declares removal in this line and the alpha
	// kinds that left the specification. Alpha versions are not served by
	// default and are neither cross-checked nor emitted.
	AlphaDeclared []string `json:"alphaDeclared"`
	AlphaGone     []string `json:"alphaGone"`
	// Unobserved are declared removals of kinds that neither specification
	// lists; ListInconsistencies are List types declared for another release
	// than their item kind.
	Unobserved          []string `json:"unobserved"`
	ListInconsistencies []string `json:"listInconsistencies"`
	Mismatches          []string `json:"mismatches,omitempty"`
}

func versionRank(v string) [3]int {
	m := regexp.MustCompile(`^v([0-9]+)(?:(alpha|beta)([0-9]+))?$`).FindStringSubmatch(v)
	if m == nil {
		return [3]int{-1, 0, 0}
	}
	major, _ := strconv.Atoi(m[1])
	n, _ := strconv.Atoi(m[3])
	stab := 2 // GA
	switch m[2] {
	case "alpha":
		stab = 0
	case "beta":
		stab = 1
	}
	return [3]int{stab, major, n}
}

func versionLess(a, b string) bool {
	x, y := versionRank(a), versionRank(b)
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return a < b
}

var alphaRE = regexp.MustCompile(`^v[0-9]+alpha[0-9]+$`)

func sortedGVKs(m map[gvk]bool) []gvk {
	out := make([]gvk, 0, len(m))
	for g := range m {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return gvkLess(out[i], out[j]) })
	return out
}

var servedReplacementRE = regexp.MustCompile(`^v[0-9]+(beta[0-9]+)?$`)

// Extract implements extract.Extractor.
func (x *Extractor) Extract(_ context.Context, r extract.PinnedReader, pair extract.VersionPair) (extract.Extraction, error) {
	if !x.Applies(pair.Repo) {
		return extract.Extraction{}, fmt.Errorf("repository %s", pair.Repo.Key)
	}
	m := releaseTagRE.FindStringSubmatch(pair.ToTag)
	if m == nil || m[1] != "1" {
		return extract.Extraction{}, fmt.Errorf("pair %s: unsupported target tag", pair.Key())
	}
	line, _ := strconv.Atoi(m[2])
	proof := pairProof{FromTag: pair.FromTag, ToTag: pair.ToTag, TargetLine: "1." + m[2], Removals: []removalProof{}, AlphaDeclared: []string{}, AlphaGone: []string{}, Unobserved: []string{}, ListInconsistencies: []string{}}
	withhold := func(err error) (extract.Extraction, error) {
		if p, ok := asProblem(err); ok {
			return extract.Extraction{}, &extract.Withheld{Reason: p.msg, Proof: proof}
		}
		return extract.Extraction{}, err
	}
	set, err := x.lifecycle(r, pair.Repo, pair.FromCommit)
	if err != nil {
		return withhold(err)
	}
	proof.LifecycleFiles = len(set.Files)
	if len(set.Files) == 0 {
		return withhold(problem{"no lifecycle files at " + pair.FromTag + ": an absence of removals cannot be told from an unreadable tree"})
	}
	from, err := x.spec(r, pair.Repo, pair.FromCommit)
	if err != nil {
		return withhold(err)
	}
	to, err := x.spec(r, pair.Repo, pair.ToCommit)
	if err != nil {
		return withhold(err)
	}
	proof.SpecKindsFrom, proof.SpecKindsTo = len(from), len(to)
	defer func() {
		sort.Strings(proof.AlphaDeclared)
		sort.Strings(proof.AlphaGone)
		sort.Strings(proof.Unobserved)
		sort.Strings(proof.ListInconsistencies)
	}()

	// The removals declared for this line, all kinds.
	declared := map[gvk]bool{}
	type loc struct {
		file *lifecycleFile
		decl removedDecl
	}
	locs := map[gvk]loc{}
	for i := range set.Files {
		f := &set.Files[i]
		proof.RemovedDecls += len(f.Removed)
		for _, d := range f.Removed {
			if d.Major == 1 && d.Minor == line {
				g := gvk{f.Group, f.Version, d.Kind}
				if alphaRE.MatchString(f.Version) {
					proof.AlphaDeclared = append(proof.AlphaDeclared, g.String())
					continue
				}
				declared[g] = true
				locs[g] = loc{f, d}
			}
		}
	}
	// A List type only wraps its item kind, so the item kind's declaration
	// is authoritative for it. A List declared for another release than its
	// item kind is an upstream inconsistency; it is recorded, and the List
	// follows the item kind.
	for i := range set.Files {
		f := &set.Files[i]
		byKind := map[string]removedDecl{}
		for _, d := range f.Removed {
			byKind[d.Kind] = d
		}
		for _, d := range f.Removed {
			base, isList := strings.CutSuffix(d.Kind, "List")
			item, ok := byKind[base]
			if !isList || !ok || alphaRE.MatchString(f.Version) || (item.Major == d.Major && item.Minor == d.Minor) {
				continue
			}
			proof.ListInconsistencies = append(proof.ListInconsistencies, fmt.Sprintf("%s declares %s removed in %d.%d but %s in %d.%d", gvk{f.Group, f.Version, d.Kind}, d.Kind, d.Major, d.Minor, base, item.Major, item.Minor))
			g := gvk{f.Group, f.Version, d.Kind}
			if d.Major == 1 && d.Minor == line {
				delete(declared, g)
				delete(locs, g)
			}
			if item.Major == 1 && item.Minor == line {
				declared[g] = true
				locs[g] = loc{f, d}
			}
		}
	}
	// A declared kind that neither specification lists is not a served
	// resource (a review envelope, a template type): it cannot be checked
	// and is recorded, never emitted.
	for _, g := range sortedGVKs(declared) {
		if !from[g] && !to[g] {
			proof.Unobserved = append(proof.Unobserved, g.String())
			delete(declared, g)
			delete(locs, g)
		}
	}
	// Cross-check against both specifications, in both directions.
	var mism []string
	sortProof := func() {
		sort.Strings(proof.AlphaDeclared)
		sort.Strings(proof.AlphaGone)
		sort.Strings(proof.Unobserved)
		sort.Strings(proof.ListInconsistencies)
	}
	for g := range declared {
		if !from[g] {
			mism = append(mism, fmt.Sprintf("%s is declared removed in %s but is not in the %s specification", g, proof.TargetLine, pair.FromTag))
		}
		if to[g] {
			mism = append(mism, fmt.Sprintf("%s is declared removed in %s but is still in the %s specification", g, proof.TargetLine, pair.ToTag))
		}
	}
	for _, g := range sortedGVKs(from) {
		if alphaRE.MatchString(g.Version) {
			if !to[g] {
				proof.AlphaGone = append(proof.AlphaGone, g.String())
			}
			continue
		}
		if !to[g] && !declared[g] && !metaKinds[g.Kind] {
			mism = append(mism, fmt.Sprintf("%s is in the %s specification and gone from %s, but no lifecycle file removes it in %s", g, pair.FromTag, pair.ToTag, proof.TargetLine))
		}
	}
	sortProof()
	if len(mism) > 0 {
		sort.Strings(mism)
		proof.Mismatches = mism
		return extract.Extraction{}, &extract.Withheld{Reason: fmt.Sprintf("the lifecycle declarations and the OpenAPI specifications disagree (%d differences, first: %s)", len(mism), mism[0]), Proof: proof}
	}

	// Group the removals by group/version.
	type gv struct{ group, version string }
	byGV := map[gv][]gvk{}
	for g := range declared {
		k := gv{g.Group, g.Version}
		byGV[k] = append(byGV[k], g)
	}
	keys := make([]gv, 0, len(byGV))
	for k := range byGV {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].group != keys[j].group {
			return keys[i].group < keys[j].group
		}
		return keys[i].version < keys[j].version
	})
	type built struct {
		rp   removalProof
		uses []useSpan
	}
	var all []built
	for _, k := range keys {
		items := byGV[k]
		sort.Slice(items, func(i, j int) bool { return gvkLess(items[i], items[j]) })
		rp := removalProof{Group: k.group, Version: k.version, Kinds: []string{}, ListKinds: []string{}, Replacements: []string{}, Facts: []factUse{}, NoFactKinds: []string{}, KindLines: []kindLine{}}
		for _, g := range items {
			l := locs[g]
			rp.Path = l.file.Path
			rp.KindLines = append(rp.KindLines, kindLine{Kind: g.Kind, StartLine: l.decl.StartLine, EndLine: l.decl.EndLine})
			if strings.HasSuffix(g.Kind, "List") && declared[gvk{g.Group, g.Version, strings.TrimSuffix(g.Kind, "List")}] {
				rp.ListKinds = append(rp.ListKinds, g.Kind)
			} else {
				rp.Kinds = append(rp.Kinds, g.Kind)
			}
		}
		rp.Replacements = replacements(to, k.group, k.version, rp.Kinds)
		perFact := map[string]*factUse{}
		var order []string
		for _, kind := range rp.Kinds {
			f, ok := factFor(line, k.group, k.version, kind)
			if !ok {
				rp.NoFactKinds = append(rp.NoFactKinds, kind)
				continue
			}
			if perFact[f.Fact] == nil {
				perFact[f.Fact] = &factUse{Fact: f.Fact}
				order = append(order, f.Fact)
			}
			perFact[f.Fact].Kinds = append(perFact[f.Fact].Kinds, kind)
		}
		sort.Strings(order)
		var uses []useSpan
		for _, fact := range order {
			u := perFact[fact]
			u.Replacements = replacements(to, k.group, k.version, u.Kinds)
			rp.Facts = append(rp.Facts, *u)
			uses = append(uses, spanFor(rp, u))
		}
		all = append(all, built{rp, uses})
		proof.Removals = append(proof.Removals, rp)
	}
	var out []extract.Candidate
	for _, b := range all {
		for _, u := range b.uses {
			out = append(out, candidate(pair, line, b.rp, u, len(b.uses) > 1))
		}
	}
	return extract.Extraction{Candidates: out, Proof: proof}, nil
}

// replacements are the stable and beta versions of group served at the later
// release for every one of kinds.
func replacements(to map[gvk]bool, group, removed string, kinds []string) []string {
	versions := map[string]bool{}
	for g := range to {
		if g.Group == group && g.Version != removed && servedReplacementRE.MatchString(g.Version) {
			versions[g.Version] = true
		}
	}
	out := []string{}
	for v := range versions {
		all := true
		for _, k := range kinds {
			if !to[gvk{group, v, k}] {
				all = false
			}
		}
		if all {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return versionLess(out[i], out[j]) })
	return out
}

// useSpan is one rule: a group version, the kinds of one adapter fact and the
// lifecycle lines declaring them.
type useSpan struct {
	use       factUse
	slug      string
	startLine int
	endLine   int
}

func spanFor(rp removalProof, u *factUse) useSpan {
	want := map[string]bool{}
	for _, k := range u.Kinds {
		want[k] = true
		want[k+"List"] = true
	}
	s := useSpan{use: *u, startLine: 1 << 30}
	for _, kl := range rp.KindLines {
		if want[kl.Kind] {
			s.startLine, s.endLine = min(s.startLine, kl.StartLine), max(s.endLine, kl.EndLine)
		}
	}
	for _, f := range adapterFacts {
		if f.Fact == u.Fact {
			s.slug = f.Slug
		}
	}
	return s
}

func slug(s string) string {
	return strings.NewReplacer(".", "-", "_", "-").Replace(strings.ToLower(s))
}

func groupSlug(group string) string {
	if group == "" {
		return "core"
	}
	return slug(group)
}

func groupVersion(group, version string) string {
	if group == "" {
		return version
	}
	return group + "/" + version
}

func joinKinds(kinds []string) string {
	switch len(kinds) {
	case 1:
		return kinds[0]
	case 2:
		return kinds[0] + " or " + kinds[1]
	}
	return strings.Join(kinds[:len(kinds)-1], ", ") + " or " + kinds[len(kinds)-1]
}

func candidate(pair extract.VersionPair, line int, rp removalProof, u useSpan, split bool) extract.Candidate {
	fromSlug, toSlug := slug(pair.From), slug(pair.To)
	gvName := groupVersion(rp.Group, rp.Version)
	id := fmt.Sprintf("kubernetes.served-api-removal.%s-%s", groupSlug(rp.Group), rp.Version)
	if split {
		id += "-" + u.slug
	}
	id += fmt.Sprintf(".%s-to-%s", fromSlug, toSlug)
	lifeID := fmt.Sprintf("lifecycle-%s-%s-%s", groupSlug(rp.Group), rp.Version, fromSlug)
	if split {
		lifeID += "-" + u.slug
	}
	kinds := joinKinds(u.use.Kinds)
	next := "Remove the named manifests or replace them with a kind and version the target release serves, then reassess the complete target apply set. Validate CRDs, stored objects, clients and API-server configuration separately."
	if n := len(u.use.Replacements); n > 0 {
		next = fmt.Sprintf("Migrate the named manifests to %s, then reassess the complete target apply set. Validate CRDs, stored objects, clients and API-server configuration separately.", groupVersion(rp.Group, u.use.Replacements[n-1]))
	}
	yes := true
	bounds := []constraintengine.RangeBound{
		{Bound: "from.gte", Basis: constraintengine.BasisPreviousMinorLine, SourceID: lifeID},
		{Bound: "from.lt", Basis: constraintengine.BasisRemovedInRelease, SourceID: lifeID},
		{Bound: "to.gte", Basis: constraintengine.BasisRemovedInRelease, SourceID: lifeID},
		{Bound: "to.lt", Basis: constraintengine.BasisTargetSeries, SourceID: lifeID},
	}
	nextMinor := fmt.Sprintf("1.%d.0", line+1)
	return extract.Candidate{
		Project:     project,
		Description: fmt.Sprintf("Kubernetes 1.%d stops serving %s through %s. Derived from the API lifecycle declarations at %s and the OpenAPI specifications of both release tags. This exact rendered apply-set check does not validate general manifest schema, CRDs, persisted objects, runtime clients, or API server configuration.", line, kinds, gvName, pair.FromTag),
		RequiredFacts: []extract.Fact{{
			Side: "proposed", ID: u.use.Fact, Component: purl, Type: string(constraintengine.FactBool),
			Description: fmt.Sprintf("Whether the complete non-paginated caller-selected official-upstream target apply set contains %s at %s.", kinds, gvName),
		}},
		Rule: extract.Rule{
			ID:       id,
			Operator: "forbid_predicate_value",
			Subject:  extract.Subject{Component: purl, From: pair.From, To: pair.To},
			Range: &constraintengine.VersionRange{
				From:   constraintengine.VersionBound{Gte: pair.From, Lt: pair.To},
				To:     constraintengine.VersionBound{Gte: pair.To, Lt: nextMinor},
				Bounds: bounds,
			},
			Condition:  &extract.Condition{Side: "proposed", Component: purl, FactID: u.use.Fact, BoolValue: &yes},
			ReasonCode: reasonCode,
			NextAction: next,
		},
		Sources: []extract.SourceRef{
			{ID: lifeID, Repo: pair.Repo, Commit: pair.FromCommit, Path: rp.Path, StartLine: u.startLine, EndLine: u.endLine},
			{ID: "openapi-" + fromSlug, Repo: pair.Repo, Commit: pair.FromCommit, Path: specPath},
			{ID: "openapi-" + toSlug, Repo: pair.Repo, Commit: pair.ToCommit, Path: specPath},
		},
	}
}
