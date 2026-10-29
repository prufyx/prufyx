// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// The gate's own dry run of a project an onboarding batch lists (O6): the
// extractor compiled into the gate, built from the head's target bytes, runs
// the newest release pair the target names against upstream, through a
// source that stops the project at its own request budget. Nothing it
// derives enters the pack; it shows that the proposal was made on these
// bytes (no scan finding the proposal did not see), that the table's groups
// are the project's own (each group's cited file is read back at the pair's
// later release) and, for kind attest, that the target attests that pair.

const (
	// OnboardingRESTBudget is the GitHub REST requests one project's dry run
	// may use; OnboardingReadBudget its file reads. Over either the project,
	// and with it the batch, is refused.
	OnboardingRESTBudget = 250
	OnboardingReadBudget = 3000
	// OnboardingListBudget is the directory listings one project's dry run
	// may make. A listing is answered from the subtree one request fetched
	// (the full-tree scan lists every directory of a tag, a vendored tree
	// holds hundreds), so it is bounded apart from file reads and the REST
	// requests it really costs stay under OnboardingRESTBudget.
	OnboardingListBudget = 10000
)

var errOnboardingBudget = errors.New("the dry run's request budget for this project ran out")

// budgetSource passes reads to src until the project's budget is used: the
// REST requests src counts since the project started, checked before every
// read or listing, the number of reads, and (apart) the number of listings.
type budgetSource struct {
	src   Source
	stats statsSource
	start int64
	mu    sync.Mutex
	reads int
	lists int
	over  bool
}

func (b *budgetSource) spend() error { return b.spendIn(&b.reads, OnboardingReadBudget) }

// spendIn counts one call against counter n, whose limit is limit; the REST
// limit applies to every kind of call.
func (b *budgetSource) spendIn(n *int, limit int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.over || *n >= limit || b.stats.Stats().APIRequests-b.start >= OnboardingRESTBudget {
		b.over = true
		return errOnboardingBudget
	}
	*n++
	return nil
}

func (b *budgetSource) used() int64 { return b.stats.Stats().APIRequests - b.start }

func (b *budgetSource) Read(repo extract.RepoRef, commit, p string) ([]byte, error) {
	if err := b.spend(); err != nil {
		return nil, err
	}
	return b.src.Read(repo, commit, p)
}

func (b *budgetSource) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	if err := b.spendIn(&b.lists, OnboardingListBudget); err != nil {
		return nil, err
	}
	return b.src.List(repo, commit, dir)
}

func (b *budgetSource) Tags(repo extract.RepoRef) ([]extract.Tag, error) {
	if err := b.spend(); err != nil {
		return nil, err
	}
	return b.src.Tags(repo)
}

// newestPairOnly is a target's extractor that names only the newest pair
// of those the extractor names: the greatest later version, then the
// greatest earlier one.
type newestPairOnly struct {
	*crdversions.Extractor
	chosen *extract.VersionPair
}

func (n *newestPairOnly) Pairs(index extract.ReleaseIndex) []extract.VersionPair {
	pairs := n.Extractor.Pairs(index)
	if len(pairs) == 0 {
		return nil
	}
	best := pairs[0]
	for _, p := range pairs[1:] {
		if c := compareVersions(p.To, best.To); c > 0 || (c == 0 && compareVersions(p.From, best.From) > 0) {
			best = p
		}
	}
	n.chosen = &best
	return []extract.VersionPair{best}
}

// compareVersions orders dotted numeric versions; a part that is not a
// number compares as text after every number.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) || i < len(pb); i++ {
		if i >= len(pa) {
			return -1
		}
		if i >= len(pb) {
			return 1
		}
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		switch {
		case ea == nil && eb == nil && na != nb:
			if na < nb {
				return -1
			}
			return 1
		case ea == nil && eb != nil:
			return -1
		case ea != nil && eb == nil:
			return 1
		case ea != nil && eb != nil && pa[i] != pb[i]:
			return strings.Compare(pa[i], pb[i])
		}
	}
	return 0
}

// groupSourceRE is a table citation: a file at a full commit of a GitHub
// repository.
var groupSourceRE = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)/blob/([0-9a-f]{40})/(.+)$`)

// onboardingDryRun runs O6 for one project and returns the REST requests it
// used.
func onboardingDryRun(ctx context.Context, src Source, concurrency int, target crdversions.Target, index customresources.Index, row customresources.Project, p OnboardingProject, now time.Time) (int64, error) {
	stats, ok := src.(statsSource)
	if src == nil || !ok {
		return 0, errors.New("no upstream source that counts its requests is configured (use --source github); an onboarding batch is admitted only on the gate's own dry run")
	}
	b := &budgetSource{src: src, stats: stats, start: stats.Stats().APIRequests}
	used, err := dryRun(ctx, b, concurrency, target, index, row, p, now)
	if err == nil && b.used() > OnboardingRESTBudget {
		err = fmt.Errorf("the dry run used %d GitHub REST requests, over the budget of %d", b.used(), OnboardingRESTBudget)
	}
	if errors.Is(err, errOnboardingBudget) || b.over {
		err = fmt.Errorf("the dry run's budget of %d GitHub REST requests, %d reads and %d listings ran out: refused, never admitted on a partial run", OnboardingRESTBudget, OnboardingReadBudget, OnboardingListBudget)
	}
	return used, err
}

func dryRun(ctx context.Context, b *budgetSource, concurrency int, target crdversions.Target, index customresources.Index, row customresources.Project, p OnboardingProject, now time.Time) (int64, error) {
	repo, err := extract.ParseRepo(target.Repo)
	if err != nil {
		return 0, err
	}
	ex := &newestPairOnly{Extractor: crdversions.NewConcurrent(target, max(concurrency, 1)).WithIndex(index)}
	out, err := extract.Run(ctx, ex, crdversions.ReleaseTags(ex, b), b, extract.Options{Repo: repo, DerivedAt: now.UTC().Truncate(time.Second)})
	if err != nil {
		return b.used(), fmt.Errorf("the dry run failed: %v", logSafe(err.Error()))
	}
	if ex.chosen == nil || len(out.Manifest.Pairs) != 1 {
		return b.used(), errors.New("the target names no release pair")
	}
	want := p.Proof.Pair
	pr := out.Manifest.Pairs[0]
	if pr.FromTag != want.FromTag || pr.FromCommit != want.FromCommit || pr.ToTag != want.ToTag || pr.ToCommit != want.ToCommit {
		return b.used(), fmt.Errorf("the newest pair is %s (%s) -> %s (%s), not the pair the proposal was made on", logSafe(pr.FromTag), pr.FromCommit, logSafe(pr.ToTag), pr.ToCommit)
	}
	if pr.Status != extract.PairDerived {
		return b.used(), fmt.Errorf("the newest pair is %s: %s", pr.Status, logSafe(pr.Reason))
	}
	var proof crdversions.PairProof
	raw, err := json.Marshal(pr.Proof)
	if err != nil || json.Unmarshal(raw, &proof) != nil || proof.Lines == nil {
		return b.used(), errors.New("the dry run recorded no line scan for the pair")
	}
	seen := map[string]bool{}
	for _, f := range p.Proof.Scan {
		seen[onboardingFindingKey(f)] = true
	}
	var surprises []string
	for _, line := range []crdversions.LineRecord{proof.Lines.From, proof.Lines.To} {
		for _, tag := range line.Tags {
			for _, f := range tag.ScanFindings {
				if !seen[onboardingFindingKey(OnboardingFinding{Class: f.Class, Path: f.Path, SHA256: f.SHA256})] {
					surprises = append(surprises, fmt.Sprintf("%s %s at %s", f.Class, logSafe(f.Path), logSafe(tag.Tag)))
				}
			}
		}
	}
	if len(surprises) > 0 {
		return b.used(), fmt.Errorf("the scan finds %d files the proposal did not list%s", len(surprises), listDetail(surprises))
	}
	switch p.Kind {
	case OnboardingKindAttest:
		if pr.Attestation == nil || pr.Attestation.Status != extract.PairAttested {
			reason := "no attestation"
			if pr.Attestation != nil {
				reason = pr.Attestation.Reason
			}
			return b.used(), fmt.Errorf("the target does not attest its newest pair: %s", logSafe(reason))
		}
	case OnboardingKindNew:
		if err := checkRowKinds(proof.To, row); err != nil {
			return b.used(), err
		}
		if err := checkGroupSources(b, target, row, pr.ToCommit); err != nil {
			return b.used(), err
		}
	}
	return b.used(), nil
}

// checkRowKinds requires every kind the new row lists for a group to be
// defined by the newest release (inv, the pair's later inventory). Otherwise
// a row could claim a kind of a shared group that the group's existing owner
// really ships, and extraction of that owner would drop its definitions as
// foreign. It does not check the kinds against the sharing project's own
// pack evidence: that is not loaded here, and this check already refuses the
// claim the new project cannot back with a definition of its own.
func checkRowKinds(inv *crdversions.Inventory, row customresources.Project) error {
	if inv == nil {
		return errors.New("the dry run recorded no inventory of the newest release")
	}
	defined := map[[2]string]bool{}
	for _, c := range inv.CRDs {
		defined[[2]string{c.Group, c.Kind}] = true
	}
	for _, g := range row.Groups {
		if g.Kinds == nil {
			continue
		}
		for _, k := range g.Kinds {
			if !defined[[2]string{g.Name, k}] {
				return fmt.Errorf("the row lists kind %s of %s, which the newest release does not define", logSafe(k), logSafe(g.Name))
			}
		}
	}
	return nil
}

// checkGroupSources reads back, at the pair's later release, the file each
// of the project's table groups cites: it must lie in the target's own
// repository, under a listed path, and declare the group.
func checkGroupSources(src extract.PinnedReader, target crdversions.Target, row customresources.Project, commit string) error {
	repo, err := extract.ParseRepo(target.Repo)
	if err != nil {
		return err
	}
	for _, g := range row.Groups {
		m := groupSourceRE.FindStringSubmatch(g.Source)
		if m == nil || "github.com/"+m[1] != target.Repo {
			return fmt.Errorf("the group %s cites %s, not a file of %s", logSafe(g.Name), logSafe(g.Source), target.Repo)
		}
		if m[2] != commit {
			return fmt.Errorf("the group %s cites commit %s; it must cite the newest pair's later release %s", logSafe(g.Name), m[2], commit)
		}
		file := m[3]
		if !validOnboardingPath(file) || !underListedPath(target, file) {
			return fmt.Errorf("the group %s cites %s, which is not under a listed path of the target", logSafe(g.Name), logSafe(file))
		}
		raw, err := src.Read(repo, commit, file)
		if err != nil {
			return fmt.Errorf("the group %s: %s cannot be read: %v", logSafe(g.Name), logSafe(file), logSafe(err.Error()))
		}
		if !declaresGroup(raw, g.Name) {
			return fmt.Errorf("the group %s: %s does not declare it", logSafe(g.Name), logSafe(file))
		}
	}
	return nil
}

func underListedPath(target crdversions.Target, file string) bool {
	for _, ps := range target.Paths {
		if file == ps.Path || (ps.Dir && strings.HasPrefix(file, ps.Path+"/")) {
			return true
		}
	}
	return false
}

// declaresGroup reports whether a CRD manifest holds the line
// "group: <name>" (optionally quoted), as a CustomResourceDefinition's
// spec.group is written.
func declaresGroup(raw []byte, group string) bool {
	re := regexp.MustCompile(`(?m)^[ \t]*group:[ \t]*["']?` + regexp.QuoteMeta(group) + `["']?[ \t]*\r?$`)
	return re.Match(raw)
}
