// SPDX-License-Identifier: AGPL-3.0-only

// Package k8sfeaturegates is the k8s.feature-gate-removal extractor. For
// each consecutive minor release pair vX.(Y-1).0 -> vX.Y.0 of
// kubernetes/kubernetes it parses the complete feature-gate registry at
// both tag commits and derives, for each of kube-apiserver,
// kube-controller-manager, kube-scheduler, kubelet and kube-proxy, a
// forbid_set_member rule over the component's feature-gate set listing the
// gates the earlier release declares and the later one does not declare
// anywhere. See registry.go for what "complete" means and
// docs/extractors/k8s.feature-gate-removal.md for the public specification.
package k8sfeaturegates

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
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
	ID      = "k8s.feature-gate-removal"
	Version = "1.0.0"
	// SourceDir is this package's directory under the module's internal/.
	SourceDir = "extract/k8sfeaturegates"
)

//go:embed *.go
var source embed.FS

// Repo is the only repository this extractor reads.
const Repo = "github.com/kubernetes/kubernetes"

// MinTargetMinor is the first target minor (of major 1) this version
// evaluates. Earlier registries were not checked against this parser.
const MinTargetMinor = 23

const (
	project        = "kubernetes"
	purl           = "pkg:github/kubernetes/kubernetes"
	reasonCode     = "KUBERNETES_FEATURE_GATE_REMOVED"
	maxMembers     = constraintengine.MaxForbiddenMembers
	maxDeclFiles   = 3 // with one registry source per declaring file and the error source, at most 7 of 8 sources
	defaultWorkers = 8
)

// Component is one component whose feature-gate set a rule reads.
type Component struct {
	Slug string // rule id part
	Name string // public name
	Fact string // set fact id
}

// Components lists the five components in a fixed order. Their fact ids
// are those the component-configuration adapter declares.
var Components = []Component{
	{"kube-apiserver", "kube-apiserver", "component.kubernetes.kube_apiserver_feature_gates_set"},
	{"kube-controller-manager", "kube-controller-manager", "component.kubernetes.kube_controller_manager_feature_gates_set"},
	{"kube-scheduler", "kube-scheduler", "component.kubernetes.kube_scheduler_feature_gates_set"},
	{"kubelet", "kubelet", "component.kubernetes.kubelet_feature_gates_set"},
	{"kube-proxy", "kube-proxy", "component.kubernetes.kube_proxy_feature_gates_set"},
}

// Extractor implements extract.Extractor. It caches parsed files by git
// blob id and registries by commit; both are pure functions of pinned bytes.
type Extractor struct {
	concurrency int

	mu         sync.Mutex
	summaries  map[string]*fileSummary
	registries map[string]*registry
}

// New returns an extractor reading with the given number of concurrent
// reads (0 means the default).
func New(concurrency int) *Extractor {
	if concurrency <= 0 {
		concurrency = defaultWorkers
	}
	return &Extractor{concurrency: concurrency, summaries: map[string]*fileSummary{}, registries: map[string]*registry{}}
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

// Pairs implements extract.Extractor: every vX.(Y-1).0 -> vX.Y.0 where both
// tags exist with a pinned commit and Y >= MinTargetMinor for major 1. Only
// final .0 release tags match; pre-releases and patch releases never do.
func (x *Extractor) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	type mm struct{ major, minor int }
	tags := map[mm]extract.Tag{}
	for _, t := range index.Tags {
		m := releaseTagRE.FindStringSubmatch(t.Name)
		if m == nil || !extract.IsCommitSHA(t.Commit) {
			continue
		}
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		tags[mm{major, minor}] = t
	}
	var out []extract.VersionPair
	for k, to := range tags {
		if k.minor == 0 || (k.major == 1 && k.minor < MinTargetMinor) || k.major != 1 {
			continue
		}
		from, ok := tags[mm{k.major, k.minor - 1}]
		if !ok {
			continue
		}
		out = append(out, extract.VersionPair{
			Repo: index.Repo,
			From: strings.TrimPrefix(from.Name, "v"), FromTag: from.Name, FromCommit: from.Commit,
			To: strings.TrimPrefix(to.Name, "v"), ToTag: to.Name, ToCommit: to.Commit,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := releaseTagRE.FindStringSubmatch(out[i].ToTag), releaseTagRE.FindStringSubmatch(out[j].ToTag)
		ai, _ := strconv.Atoi(a[2])
		bi, _ := strconv.Atoi(b[2])
		return ai < bi
	})
	return out
}

func (x *Extractor) cached(oid string) *fileSummary {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.summaries[oid]
}

func (x *Extractor) store(oid string, s *fileSummary) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.summaries[oid] = s
}

func (x *Extractor) registry(ctx context.Context, r extract.PinnedReader, repo extract.RepoRef, commit string) (*registry, error) {
	x.mu.Lock()
	reg := x.registries[commit]
	x.mu.Unlock()
	if reg != nil {
		// Built earlier in this run; its reads are already logged
		// against this commit.
		return reg, nil
	}
	reg, err := x.buildRegistry(ctx, r, repo, commit)
	if err != nil {
		return nil, err
	}
	x.mu.Lock()
	x.registries[commit] = reg
	x.mu.Unlock()
	return reg, nil
}

// Extract implements extract.Extractor.
func (x *Extractor) Extract(ctx context.Context, r extract.PinnedReader, pair extract.VersionPair) (extract.Extraction, error) {
	if !x.Applies(pair.Repo) {
		return extract.Extraction{}, fmt.Errorf("repository %s", pair.Repo.Key)
	}
	from, err := x.registry(ctx, r, pair.Repo, pair.FromCommit)
	if err != nil {
		return extract.Extraction{}, err
	}
	to, err := x.registry(ctx, r, pair.Repo, pair.ToCommit)
	if err != nil {
		return extract.Extraction{}, err
	}
	proof := pairProof{From: summarizeFrom(from), To: summarizeTo(to), Components: componentNames()}
	switch {
	case len(from.DeclProblems) > 0:
		return extract.Extraction{}, &extract.Withheld{Reason: "the declared registry at " + pair.FromTag + " is not complete: " + from.DeclProblems[0], Proof: proof}
	case len(to.Problems) > 0:
		return extract.Extraction{}, &extract.Withheld{Reason: "absence cannot be proven at " + pair.ToTag + ": " + to.Problems[0], Proof: proof}
	case len(to.DeclProblems) > 0:
		return extract.Extraction{}, &extract.Withheld{Reason: "the declared registry at " + pair.ToTag + " is not complete: " + to.DeclProblems[0], Proof: proof}
	}

	var removed []*gateDecl
	for name, g := range from.Declared {
		if to.All[name] {
			continue
		}
		if !constraintengine.ValidSetMember(name) {
			proof.Unrepresentable = append(proof.Unrepresentable, name)
			continue
		}
		removed = append(removed, g)
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].Name < removed[j].Name })
	sort.Strings(proof.Unrepresentable)
	proof.Removed = make([]gateDecl, 0, len(removed))
	for _, g := range removed {
		proof.Removed = append(proof.Removed, *g)
	}
	if len(removed) == 0 {
		return extract.Extraction{Proof: proof}, nil
	}
	pass := passMember(to, removed)
	var out []extract.Candidate
	for part, chunk := range chunks(removed) {
		for _, comp := range Components {
			out = append(out, candidate(pair, comp, part+1, chunk, to, pass))
		}
	}
	return extract.Extraction{Candidates: out, Proof: proof}, nil
}

// chunks splits removed gates (sorted by name) into rules of at most
// maxMembers gates declared in at most maxDeclFiles files, greedily in name
// order.
func chunks(removed []*gateDecl) [][]*gateDecl {
	var out [][]*gateDecl
	var cur []*gateDecl
	files := map[string]bool{}
	for _, g := range removed {
		if len(cur) > 0 && (len(cur) == maxMembers || (!files[g.Declared.Path] && len(files) == maxDeclFiles)) {
			out = append(out, cur)
			cur, files = nil, map[string]bool{}
		}
		cur = append(cur, g)
		files[g.Declared.Path] = true
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

// passMember is the first gate (by name) declared at the target release
// that is not removed: a complete set holding only it must pass.
func passMember(to *registry, removed []*gateDecl) []string {
	gone := map[string]bool{}
	for _, g := range removed {
		gone[g.Name] = true
	}
	var names []string
	for name := range to.Declared {
		if !gone[name] && constraintengine.ValidSetMember(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil
	}
	return names[:1]
}

func versionSlug(v string) string { return strings.ReplaceAll(v, ".", "-") }

func candidate(pair extract.VersionPair, comp Component, part int, chunk []*gateDecl, to *registry, pass []string) extract.Candidate {
	members := make([]string, 0, len(chunk))
	byFile := map[string][2]int{}
	for _, g := range chunk {
		members = append(members, g.Name)
		span, ok := byFile[g.Declared.Path]
		if !ok {
			span = [2]int{g.Declared.Line, g.Declared.Line}
		}
		span[0], span[1] = min(span[0], g.Declared.Line), max(span[1], g.Declared.Line)
		byFile[g.Declared.Path] = span
	}
	sort.Strings(members)
	paths := make([]string, 0, len(byFile))
	for p := range byFile {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	var sources []extract.SourceRef
	for i, p := range paths {
		letter := string(rune('a' + i))
		sources = append(sources, extract.SourceRef{ID: "gate-declarations-" + versionSlug(pair.From) + "-" + letter, Repo: pair.Repo, Commit: pair.FromCommit, Path: p, StartLine: byFile[p][0], EndLine: byFile[p][1]})
		if _, ok := to.files[p]; ok {
			sources = append(sources, extract.SourceRef{ID: "gate-registry-" + versionSlug(pair.To) + "-" + letter, Repo: pair.Repo, Commit: pair.ToCommit, Path: p})
		}
	}
	sources = append(sources, extract.SourceRef{ID: "unrecognized-gate-" + versionSlug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: to.ErrorLine.Path, StartLine: to.ErrorLine.Line, EndLine: to.ErrorLine.Line})
	id := fmt.Sprintf("kubernetes.feature-gate-removal.%s.%s-to-%s.%d", comp.Slug, versionSlug(pair.From), versionSlug(pair.To), part)
	gates := "gate"
	if len(members) > 1 {
		gates = "gates"
	}
	return extract.Candidate{
		Project:     project,
		Description: fmt.Sprintf("Kubernetes %s no longer declares the %d listed feature %s that %s declared; %s refuses to start when a feature-gate setting names an unrecognised gate. Derived from the complete feature-gate registries at both release tags.", pair.To, len(members), gates, pair.From, comp.Name),
		RequiredFacts: []extract.Fact{{
			Side: "proposed", ID: comp.Fact, Component: purl, Type: string(constraintengine.FactSet),
			Description: fmt.Sprintf("Feature gates the %s sets, from --feature-gates and a configuration featureGates map.", comp.Name),
		}},
		Rule: extract.Rule{
			ID:           id,
			Operator:     constraintengine.OperatorForbidSetMember,
			Subject:      extract.Subject{Component: purl, From: pair.From, To: pair.To},
			SetCondition: &extract.SetCondition{Side: "proposed", Component: purl, FactID: comp.Fact, Members: members},
			ReasonCode:   reasonCode,
			NextAction:   fmt.Sprintf("remove the listed feature gates from every %s feature-gate setting (--feature-gates or featureGates) before upgrading to %s", comp.Name, pair.To),
		},
		Sources:     sources,
		PassMembers: pass,
	}
}

func componentNames() []string {
	out := make([]string, 0, len(Components))
	for _, c := range Components {
		out = append(out, c.Name)
	}
	return out
}
