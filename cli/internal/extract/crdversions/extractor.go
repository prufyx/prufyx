// SPDX-License-Identifier: AGPL-3.0-only

// Package crdversions is the crd.version-removal extractor family. For one
// catalog project and each pair of consecutive final .0 release tags it
// parses every CustomResourceDefinition manifest under the project's listed
// paths at both tag commits and derives, per CRD, a forbid_set_member rule
// over the project's custom-resource version set listing the versions the
// earlier release serves and the later one no longer serves (absent, or
// served: false). Storage-version changes are recorded in the proof, never
// emitted. Any listed path that is missing, any file that is templated or
// not strictly decodable, any CRD of another API version and any CRD that
// disappears from the listed paths withholds the pair. See
// docs/extractors/crd.version-removal.md for the public specification.
package crdversions

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
	// IDPrefix is followed by the project slug: one extractor id per
	// project, since a run reads one repository.
	IDPrefix = "crd.version-removal."
	Version  = "1.0.0"
	// SourceDir is this package's directory under the module's internal/.
	SourceDir = "extract/crdversions"
)

//go:embed *.go
var source embed.FS

const (
	reasonCode = "CRD_VERSION_NOT_SERVED"
	maxIDBytes = 128
	maxNext    = 256
)

// Extractor implements extract.Extractor for one target. It caches each
// commit's inventory; it is a pure function of pinned bytes.
type Extractor struct {
	target Target

	mu    sync.Mutex
	cache map[string]inventoryResult
}

type inventoryResult struct {
	inv *Inventory
	err error
}

// New returns the extractor of a target.
func New(t Target) *Extractor {
	return &Extractor{target: t, cache: map[string]inventoryResult{}}
}

// ID implements extract.Extractor.
func (x *Extractor) ID() string { return x.target.ExtractorID() }

// Version implements extract.Extractor.
func (x *Extractor) Version() string { return Version }

// SourceFiles implements extract.CodeSource.
func (x *Extractor) SourceFiles() (string, fs.FS) { return SourceDir, source }

// Applies implements extract.Extractor.
func (x *Extractor) Applies(repo extract.RepoRef) bool { return repo.Key == x.target.Repo }

// Pairs implements extract.Extractor: every two consecutive final release
// tags <prefix>X.Y.0 (consecutive in version order, so a major release
// follows the last minor of the previous major) whose earlier tag is at or
// after MinFrom. Release candidates and patch releases never form a pair.
func (x *Extractor) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(x.target.TagPrefix) + `(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})\.0$`)
	type rel struct {
		major, minor int
		tag          extract.Tag
	}
	var rels []rel
	for _, t := range index.Tags {
		m := re.FindStringSubmatch(t.Name)
		if m == nil || !extract.IsCommitSHA(t.Commit) {
			continue
		}
		major, _ := strconv.Atoi(m[1])
		minor, _ := strconv.Atoi(m[2])
		rels = append(rels, rel{major, minor, t})
	}
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].major != rels[j].major {
			return rels[i].major < rels[j].major
		}
		return rels[i].minor < rels[j].minor
	})
	var out []extract.VersionPair
	for i := 1; i < len(rels); i++ {
		from, to := rels[i-1], rels[i]
		if from.major < x.target.MinFrom[0] || (from.major == x.target.MinFrom[0] && from.minor < x.target.MinFrom[1]) {
			continue
		}
		out = append(out, extract.VersionPair{
			Repo: index.Repo,
			From: strings.TrimPrefix(from.tag.Name, x.target.TagPrefix), FromTag: from.tag.Name, FromCommit: from.tag.Commit,
			To: strings.TrimPrefix(to.tag.Name, x.target.TagPrefix), ToTag: to.tag.Name, ToCommit: to.tag.Commit,
		})
	}
	return out
}

// Inventory is every CRD under the listed paths at one commit: the proof
// of what each tag serves and stores.
type Inventory struct {
	Tag      string       `json:"tag"`
	Commit   string       `json:"commit"`
	Complete bool         `json:"complete"`
	Problem  string       `json:"problem,omitempty"`
	Paths    []PathRecord `json:"paths"`
	Files    []FileRecord `json:"files"`
	CRDs     []CRD        `json:"crds"`
}

// PathRecord is one listed path and what was found there.
type PathRecord struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // "file" or "directory"
	// Files is the number of files read for it; Ignored the directory
	// entries whose names do not match (files) or that are not files.
	Files   int `json:"files"`
	Ignored int `json:"ignored"`
}

func (x *Extractor) inventory(r extract.PinnedReader, repo extract.RepoRef, tag, commit string) (*Inventory, error) {
	x.mu.Lock()
	res, ok := x.cache[commit]
	x.mu.Unlock()
	if ok {
		if res.inv != nil {
			cp := *res.inv
			cp.Tag = tag
			return &cp, res.err
		}
		return nil, res.err
	}
	inv, err := readInventory(r, repo, x.target, commit)
	if inv != nil {
		inv.Tag = tag
		inv.Complete = err == nil
		if p, ok := asProblem(err); ok {
			inv.Problem = p.msg
		}
	}
	if _, isProblem := asProblem(err); err == nil || isProblem {
		x.mu.Lock()
		x.cache[commit] = inventoryResult{inv, err}
		x.mu.Unlock()
	}
	return inv, err
}

// readInventory reads every listed path at commit. On a problem it returns
// the partial inventory with the problem.
func readInventory(r extract.PinnedReader, repo extract.RepoRef, t Target, commit string) (*Inventory, error) {
	inv := &Inventory{Commit: commit, Paths: []PathRecord{}, Files: []FileRecord{}, CRDs: []CRD{}}
	var files []string
	for _, p := range t.Paths {
		if !p.Dir {
			inv.Paths = append(inv.Paths, PathRecord{Path: p.Path, Kind: "file", Files: 1})
			files = append(files, p.Path)
			continue
		}
		entries, err := r.List(repo, commit, p.Path)
		if errors.Is(err, extract.ErrNotFound) {
			return inv, problemf("listed directory %s does not exist", p.Path)
		}
		if err != nil {
			return inv, err
		}
		pr := PathRecord{Path: p.Path, Kind: "directory"}
		for _, e := range entries {
			name := path.Base(e.Path)
			if e.Type != "blob" || !p.Match.MatchString(name) {
				pr.Ignored++
				continue
			}
			if e.Mode == "120000" {
				return inv, problemf("%s is a symbolic link", e.Path)
			}
			pr.Files++
			files = append(files, e.Path)
		}
		inv.Paths = append(inv.Paths, pr)
		if pr.Files == 0 {
			return inv, problemf("listed directory %s holds no CRD manifest file", p.Path)
		}
	}
	sort.Strings(files)
	byName := map[string]string{}
	byKind := map[string]string{}
	for i, f := range files {
		if i > 0 && files[i-1] == f {
			return inv, problemf("%s is listed twice", f)
		}
		data, err := r.Read(repo, commit, f)
		if errors.Is(err, extract.ErrNotFound) {
			return inv, problemf("listed file %s does not exist", f)
		}
		if err != nil {
			return inv, err
		}
		rec, crds, err := parseFile(f, data)
		inv.Files = append(inv.Files, rec)
		if err != nil {
			return inv, err
		}
		for _, c := range crds {
			if prev, dup := byName[c.Name]; dup {
				return inv, problemf("CustomResourceDefinition %s is defined in both %s and %s", c.Name, prev, c.Path)
			}
			gk := c.Group + "/" + c.Kind
			if prev, dup := byKind[gk]; dup {
				return inv, problemf("kind %s is defined by both %s and %s", gk, prev, c.Name)
			}
			byName[c.Name], byKind[gk] = c.Path, c.Name
			inv.CRDs = append(inv.CRDs, c)
			if len(inv.CRDs) > MaxCRDsPerTag {
				return inv, problemf("more than %d CustomResourceDefinitions", MaxCRDsPerTag)
			}
		}
	}
	if len(inv.CRDs) == 0 {
		return inv, problemf("no CustomResourceDefinition under the listed paths: an absence of removals cannot be told from a moved manifest")
	}
	sort.Slice(inv.CRDs, func(i, j int) bool { return inv.CRDs[i].Name < inv.CRDs[j].Name })
	return inv, nil
}

// Removal is one version served at the earlier tag and not served at the
// later one.
type Removal struct {
	CRD     string `json:"crd"`
	Member  string `json:"member"`
	Version string `json:"version"`
	// Reason is "absent" (no longer listed) or "unserved" (served: false).
	Reason   string `json:"reason"`
	FromPath string `json:"fromPath"`
	// FromStartLine..FromEndLine is the version's entry at the earlier tag.
	FromStartLine int    `json:"fromStartLine"`
	FromEndLine   int    `json:"fromEndLine"`
	ToPath        string `json:"toPath"`
	// ToLine is the served: false line at the later tag, 0 when absent.
	ToLine int `json:"toServedLine"`
}

// StorageChange records a CRD whose storage version differs between the
// tags. It is never a removal by itself.
type StorageChange struct {
	CRD  string `json:"crd"`
	From string `json:"from"`
	To   string `json:"to"`
}

// PairProof is recorded in the run manifest for every pair.
type PairProof struct {
	Target         string          `json:"target"`
	FactID         string          `json:"factId"`
	From           *Inventory      `json:"from"`
	To             *Inventory      `json:"to"`
	Removals       []Removal       `json:"removals"`
	StorageChanges []StorageChange `json:"storageChanges"`
}

// Extract implements extract.Extractor.
func (x *Extractor) Extract(_ context.Context, r extract.PinnedReader, pair extract.VersionPair) (extract.Extraction, error) {
	if !x.Applies(pair.Repo) {
		return extract.Extraction{}, fmt.Errorf("repository %s", pair.Repo.Key)
	}
	proof := PairProof{Target: x.target.Project, FactID: x.target.FactID(), Removals: []Removal{}, StorageChanges: []StorageChange{}}
	withhold := func(err error) (extract.Extraction, error) {
		if p, ok := asProblem(err); ok {
			return extract.Extraction{}, &extract.Withheld{Reason: p.msg, Proof: proof}
		}
		return extract.Extraction{}, err
	}
	from, err := x.inventory(r, pair.Repo, pair.FromTag, pair.FromCommit)
	proof.From = from
	if err != nil {
		if p, ok := asProblem(err); ok {
			err = problemf("at %s: %s", pair.FromTag, p.msg)
		}
		return withhold(err)
	}
	to, err := x.inventory(r, pair.Repo, pair.ToTag, pair.ToCommit)
	proof.To = to
	if err != nil {
		if p, ok := asProblem(err); ok {
			err = problemf("at %s: %s", pair.ToTag, p.msg)
		}
		return withhold(err)
	}
	later := map[string]*CRD{}
	for i := range to.CRDs {
		later[to.CRDs[i].Name] = &to.CRDs[i]
	}
	type crdRemovals struct {
		from, to *CRD
		removed  []Removal
	}
	var all []crdRemovals
	for i := range from.CRDs {
		f := &from.CRDs[i]
		t, ok := later[f.Name]
		if !ok {
			return withhold(problemf("CustomResourceDefinition %s at %s is not under the listed paths at %s: a removed definition cannot be told from a moved one", f.Name, pair.FromTag, pair.ToTag))
		}
		if t.Kind != f.Kind || t.Group != f.Group {
			return withhold(problemf("CustomResourceDefinition %s names %s/%s at %s and %s/%s at %s", f.Name, f.Group, f.Kind, pair.FromTag, t.Group, t.Kind, pair.ToTag))
		}
		if f.StorageVersion != t.StorageVersion {
			proof.StorageChanges = append(proof.StorageChanges, StorageChange{CRD: f.Name, From: f.StorageVersion, To: t.StorageVersion})
		}
		cr := crdRemovals{from: f, to: t}
		for _, v := range f.Versions {
			if !v.Served {
				continue
			}
			rm := Removal{CRD: f.Name, Member: member(f.Group, v.Name, f.Kind), Version: v.Name, FromPath: f.Path, FromStartLine: v.StartLine, FromEndLine: v.EndLine, ToPath: t.Path}
			lv, present := t.version(v.Name)
			switch {
			case !present:
				rm.Reason = "absent"
			case !lv.Served:
				rm.Reason, rm.ToLine = "unserved", lv.ServedLine
			default:
				continue
			}
			cr.removed = append(cr.removed, rm)
			proof.Removals = append(proof.Removals, rm)
		}
		if len(cr.removed) > 0 {
			all = append(all, cr)
		}
	}
	var out []extract.Candidate
	for _, cr := range all {
		c, err := x.candidate(pair, cr.from, cr.to, cr.removed)
		if err != nil {
			return withhold(err)
		}
		out = append(out, c)
	}
	return extract.Extraction{Candidates: out, Proof: proof}, nil
}

func slug(s string) string {
	return strings.NewReplacer(".", "-", "_", "-").Replace(strings.ToLower(s))
}

// versionRank orders Kubernetes version names: GA above beta above alpha,
// then by major and stability number; other names sort lowest.
func versionRank(v string) [3]int {
	m := regexp.MustCompile(`^v([0-9]+)(?:(alpha|beta)([0-9]+))?$`).FindStringSubmatch(v)
	if m == nil {
		return [3]int{-1, 0, 0}
	}
	major, _ := strconv.Atoi(m[1])
	n, _ := strconv.Atoi(m[3])
	stab := 2
	switch m[2] {
	case "alpha":
		stab = 0
	case "beta":
		stab = 1
	}
	return [3]int{stab, major, n}
}

func higher(a, b string) bool {
	x, y := versionRank(a), versionRank(b)
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return a > b
}

// replacement is the highest version the later CRD serves, "" when none.
func replacement(t *CRD) string {
	best := ""
	for _, v := range t.Versions {
		if v.Served && (best == "" || higher(v.Name, best)) {
			best = v.Name
		}
	}
	return best
}

func (x *Extractor) candidate(pair extract.VersionPair, f, t *CRD, removed []Removal) (extract.Candidate, error) {
	tg := x.target
	members := make([]string, 0, len(removed))
	versions := make([]string, 0, len(removed))
	start, end := 1<<30, 0
	var toSources []extract.SourceRef
	absent := false
	for _, rm := range removed {
		members = append(members, rm.Member)
		versions = append(versions, rm.Version)
		start, end = min(start, rm.FromStartLine), max(end, rm.FromEndLine)
		if rm.Reason == "absent" {
			absent = true
		} else {
			toSources = append(toSources, extract.SourceRef{ID: "served-false-" + rm.Version + "-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: t.Path, StartLine: rm.ToLine, EndLine: rm.ToLine})
		}
	}
	sort.Strings(members)
	sort.Slice(versions, func(i, j int) bool { return higher(versions[j], versions[i]) })
	if absent || len(toSources) > 7 {
		toSources = []extract.SourceRef{{ID: "crd-" + slug(pair.To), Repo: pair.Repo, Commit: pair.ToCommit, Path: t.Path}}
	}
	sources := append([]extract.SourceRef{{ID: "crd-versions-" + slug(pair.From), Repo: pair.Repo, Commit: pair.FromCommit, Path: f.Path, StartLine: start, EndLine: end}}, toSources...)
	id := fmt.Sprintf("%s.crd-version-removal.%s.%s-to-%s", tg.Project, slug(f.Name), slug(pair.From), slug(pair.To))
	if len(id) > maxIDBytes {
		return extract.Candidate{}, problemf("rule id for %s would be %d bytes, over %d", f.Name, len(id), maxIDBytes)
	}
	repl := replacement(t)
	next := fmt.Sprintf("migrate %s objects before upgrading to %s", f.Kind, pair.To)
	var pass []string
	if repl != "" {
		next = fmt.Sprintf("change apiVersion of %s to %s/%s before upgrading to %s", f.Kind, f.Group, repl, pair.To)
		pass = []string{member(f.Group, repl, f.Kind)}
	}
	if len(next) > maxNext {
		return extract.Candidate{}, problemf("next action for %s would be %d bytes, over %d", f.Name, len(next), maxNext)
	}
	vs := "version " + versions[0]
	if len(versions) > 1 {
		vs = "versions " + strings.Join(versions, ", ")
	}
	return extract.Candidate{
		Project:     tg.Project,
		Description: fmt.Sprintf("%s %s no longer serves %s of %s (CustomResourceDefinition %s), which %s served. Derived from the complete CustomResourceDefinition manifests at both release tags. Storage versions, stored objects, conversion and schema changes are not checked.", tg.Name, pair.To, vs, f.Kind, f.Name, pair.From),
		RequiredFacts: []extract.Fact{{
			Side: "proposed", ID: tg.FactID(), Component: tg.Component, Type: string(constraintengine.FactSet),
			Description: fmt.Sprintf("Custom-resource versions (group/version/Kind) of the %s custom resources in the complete target apply set.", tg.Name),
		}},
		Rule: extract.Rule{
			ID:           id,
			Operator:     constraintengine.OperatorForbidSetMember,
			Subject:      extract.Subject{Component: tg.Component, From: pair.From, To: pair.To},
			SetCondition: &extract.SetCondition{Side: "proposed", Component: tg.Component, FactID: tg.FactID(), Members: members},
			ReasonCode:   reasonCode,
			NextAction:   next,
		},
		Sources:     sources,
		PassMembers: pass,
	}, nil
}
