// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"path"
	"sort"
)

func (a *analysis) run() Repo {
	repo := Repo{Gaps: append([]Gap(nil), a.repoGaps...)}
	var candidates []*docRef
	for _, d := range a.docs {
		if d.kind == kindFlux || d.kind == kindArgo {
			candidates = append(candidates, d)
		}
	}
	// Discovery: find which candidates sit inside another candidate's
	// closure; only the others are roots. It has its own budget, so a
	// costly search never leaves the environments without work.
	disc := &budget{limit: discoveryBudget}
	a.disc = disc
	inside := map[int]bool{}
	whole := map[int]bool{}
	for _, c := range candidates {
		w := newWalker(a, c, disc, true)
		if c.kind == kindFlux {
			if s := w.fluxOf(c); s.fatal == nil && s.wholeRepo && !s.bootstrap {
				// Applies the whole repository: not a root, and it does not
				// make the real roots inside it.
				whole[c.id] = true
				continue
			}
		}
		if disc.out {
			break
		}
		w.walk()
		for k := range w.reached {
			inside[k] = true
		}
	}
	if disc.out {
		repo.Gaps = append(repo.Gaps, Gap{ClosureLimit, intakeNone(), "work limit reached while finding environment roots; some environments may belong inside others"})
	}
	var roots []*docRef
	for _, c := range candidates {
		switch {
		case inside[c.id]:
		case whole[c.id]:
			repo.Gaps = append(repo.Gaps, Gap{ConstructNotEvaluated, c.doc.Source, "a Kustomization that applies the whole repository is not an environment root; only the Flux bootstrap object flux-system is"})
		default:
			roots = append(roots, c)
		}
	}
	if len(roots) > MaxEnvironments {
		repo.Gaps = append(repo.Gaps, Gap{ClosureLimit, roots[MaxEnvironments].doc.Source, "more than 256 environments; the rest are not listed"})
		roots = roots[:MaxEnvironments]
	}
	work := &budget{limit: workBudget}
	a.work = work
	covered := make([]bool, len(a.docs))
	for _, r := range roots {
		w := newWalker(a, r, work, false)
		w.walk()
		for i, seen := range w.seen {
			covered[i] = covered[i] || seen
		}
		repo.Environments = append(repo.Environments, Environment{
			Name: envName(r), Root: r.doc.Source, Releases: w.rels, Images: w.imgs, Gaps: w.gaps,
		})
	}
	uniqueNames(repo.Environments, roots)
	sort.SliceStable(repo.Environments, func(i, j int) bool {
		return srcLess(repo.Environments[i].Root, repo.Environments[j].Root)
	})
	for _, f := range sortedKeys(a.enc) {
		repo.Gaps = append(repo.Gaps, Gap{Encrypted, a.enc[f], "SOPS-encrypted document skipped"})
	}
	orphans := map[string]bool{}
	for _, d := range a.docs {
		switch {
		case d.kind == kindAppSet:
			repo.Gaps = append(repo.Gaps, Gap{GeneratedApplicationsNotEvaluated, d.doc.Source, "ApplicationSet generates Applications that are not evaluated"})
		case covered[d.id]:
		case d.kind == kindFlux || d.kind == kindArgo:
			if !inside[d.id] {
				continue
			}
			repo.Gaps = append(repo.Gaps, Gap{ClosureLimit, d.doc.Source, "not reachable from any root; possible cycle"})
		case d.kind == kindHelmRelease, d.kind == kindChart:
			if !orphans[d.rel] {
				orphans[d.rel] = true
				repo.Gaps = append(repo.Gaps, Gap{SourceNotFound, d.doc.Source, "not reachable from any environment root"})
			}
		}
	}
	if work.out {
		repo.Gaps = append(repo.Gaps, Gap{ClosureLimit, intakeNone(), "work limit reached while reading environments; the result is incomplete"})
	}
	repo.Gaps = sortGaps(repo.Gaps)
	if len(repo.Gaps) > MaxGaps {
		repo.Gaps = append(repo.Gaps[:MaxGaps-1], Gap{ClosureLimit, intakeNone(), "more than 4096 gaps; the rest are not listed"})
	}
	return repo
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// envName names an environment after its root: the path a Flux Kustomization
// manages, or the namespace and name of an Argo CD Application.
func envName(r *docRef) string {
	if r.kind == kindFlux {
		p := asStr(asMap(r.doc.Value["spec"])["path"])
		p = path.Clean("/" + p)[1:]
		if p == "" {
			p = "."
		}
		return clip(p)
	}
	if r.doc.Namespace != "" {
		return clip(r.doc.Namespace + "/" + r.doc.Name)
	}
	return clip(r.doc.Name)
}

// uniqueNames adds the root file to names that two roots share.
func uniqueNames(envs []Environment, roots []*docRef) {
	count := map[string]int{}
	for _, e := range envs {
		count[e.Name]++
	}
	for i := range envs {
		if count[envs[i].Name] > 1 {
			envs[i].Name = clip(envs[i].Name + " (" + roots[i].rel + ")")
		}
	}
}
