// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"path"
	"sort"
)

func (a *analysis) run() Repo {
	var candidates []*docRef
	for _, d := range a.docs {
		if isFluxKustomization(d) || isArgoApplication(d) {
			candidates = append(candidates, d)
		}
	}
	// First pass: find which candidates sit inside another candidate's
	// closure. Only the others are roots.
	inside := map[skey]bool{}
	for _, c := range candidates {
		w := newWalker(a, c)
		w.walk()
		for k := range w.reached {
			inside[k] = true
		}
	}
	var roots []*docRef
	for _, c := range candidates {
		if !inside[c.key] {
			roots = append(roots, c)
		}
	}
	repo := Repo{Gaps: append([]Gap(nil), a.repoGaps...)}
	if len(roots) > MaxEnvironments {
		repo.Gaps = append(repo.Gaps, Gap{ClosureLimit, roots[MaxEnvironments].doc.Source, "more than 256 environments; the rest are not listed"})
		roots = roots[:MaxEnvironments]
	}
	covered := map[skey]bool{}
	for _, r := range roots {
		w := newWalker(a, r)
		w.walk()
		for k := range w.seen {
			covered[k] = true
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
		case d.doc.Kind == "ApplicationSet" && d.group() == "argoproj.io":
			repo.Gaps = append(repo.Gaps, Gap{GeneratedApplicationsNotEvaluated, d.doc.Source, "ApplicationSet generates Applications that are not evaluated"})
		case covered[d.key]:
		case isFluxKustomization(d) || isArgoApplication(d):
			if !inside[d.key] {
				continue
			}
			repo.Gaps = append(repo.Gaps, Gap{ClosureLimit, d.doc.Source, "not reachable from any root; possible cycle"})
		case d.doc.Kind == KindHelmRelease && d.group() == "helm.toolkit.fluxcd.io", d.aux && path.Base(d.rel) == "Chart.yaml":
			if !orphans[d.rel] {
				orphans[d.rel] = true
				repo.Gaps = append(repo.Gaps, Gap{SourceNotFound, d.doc.Source, "not reachable from any environment root"})
			}
		}
	}
	if a.exhausted {
		repo.Gaps = append(repo.Gaps, Gap{ClosureLimit, intakeNone(), "work limit reached; the result is incomplete"})
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
	if isFluxKustomization(r) {
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
