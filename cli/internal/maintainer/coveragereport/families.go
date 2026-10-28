// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"sort"
	"sync"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues"
	"github.com/prufyx/prufyx/cli/internal/extract/k8sservedapis"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// FamilyHelmValuesSchema is the chart values family. Its pairs are pairs of
// chart lines, not of the project's release lines in the lines snapshot, and
// no attestation exists for it, so a project registered in it is never
// complete.
const FamilyHelmValuesSchema = "helm.values_schema"

// lineSpace tells which lines a family's pairs are pairs of.
type lineSpace int

const (
	// projectLines: the lines of the lines snapshot.
	projectLines lineSpace = iota
	// chartLines: chart lines, which the snapshot does not hold. They are
	// never mapped onto the project's lines.
	chartLines
)

// registration is one family a project is registered in: the extractor that
// derives its facts and the first line a pair may start from.
type registration struct {
	family      string
	extractorID string
	version     string
	component   string
	minFrom     [2]int
	space       lineSpace
	digest      func() (string, error)
}

var (
	regOnce sync.Once
	regs    map[string][]registration

	digestMu    sync.Mutex
	digestCache = map[string]string{}
)

// cachedDigest memoises an extractor's shipped code digest by extractor id.
func cachedDigest(id string, compute func() (string, error)) func() (string, error) {
	return func() (string, error) {
		digestMu.Lock()
		defer digestMu.Unlock()
		if d, ok := digestCache[id]; ok {
			return d, nil
		}
		d, err := compute()
		if err != nil {
			return "", err
		}
		digestCache[id] = d
		return d, nil
	}
}

func buildRegistrations() map[string][]registration {
	out := map[string][]registration{}
	k8s := k8sservedapis.New(0)
	out["kubernetes"] = append(out["kubernetes"], registration{
		family:      lineattest.FamilyKubernetesRemovedServedGVK,
		extractorID: k8s.ID(),
		version:     k8s.Version(),
		component:   "pkg:github/kubernetes/kubernetes",
		minFrom:     [2]int{1, k8sservedapis.MinFromMinor},
		space:       projectLines,
		digest: cachedDigest(k8s.ID(), func() (string, error) {
			dir, files := k8s.SourceFiles()
			set, err := extract.CodeFiles(extract.FrameworkSource(), extract.SourceSet{Dir: dir, Files: files})
			if err != nil {
				return "", err
			}
			return extract.CodeDigest(set), nil
		}),
	})
	for _, t := range crdversions.Targets {
		ex := crdversions.New(t)
		out[t.Project] = append(out[t.Project], registration{
			family:      lineattest.FamilyCustomResourceVersions,
			extractorID: ex.ID(),
			version:     ex.Version(),
			component:   t.Component,
			minFrom:     t.MinFrom,
			space:       projectLines,
			digest: cachedDigest(ex.ID(), func() (string, error) {
				dir, files := ex.SourceFiles()
				set, err := extract.CodeFiles(extract.FrameworkSource(), extract.SourceSet{Dir: dir, Files: files})
				if err != nil {
					return "", err
				}
				return extract.CodeDigest(set), nil
			}),
		})
	}
	for _, t := range helmvalues.Targets {
		list := out[t.Project]
		found := false
		for i := range list {
			if list[i].family == FamilyHelmValuesSchema {
				found = true
			}
		}
		if found {
			continue
		}
		out[t.Project] = append(list, registration{family: FamilyHelmValuesSchema, space: chartLines})
	}
	for slug := range out {
		sort.Slice(out[slug], func(i, j int) bool { return out[slug][i].family < out[slug][j].family })
	}
	return out
}

// registrations returns the families a project is registered in, sorted by
// family id. A project outside every extractor table has none.
func registrations(slug string) []registration {
	regOnce.Do(func() { regs = buildRegistrations() })
	return regs[slug]
}

// registeredFamilies lists every family some project is registered in.
func registeredFamilies() []string {
	return []string{lineattest.FamilyCustomResourceVersions, FamilyHelmValuesSchema, lineattest.FamilyKubernetesRemovedServedGVK}
}

// CRDProjectCount counts the distinct projects among the reviewed
// crd.custom_resource_versions targets.
func CRDProjectCount() int {
	return len(CRDProjectComponents())
}

// CRDProjectComponents maps every project with a reviewed
// crd.custom_resource_versions target to the component of that target.
func CRDProjectComponents() map[string]string {
	out := map[string]string{}
	for _, t := range crdversions.Targets {
		SetTargetComponent(out, t.Project, t.Component)
	}
	return out
}

// SetTargetComponent records the component of one target for its project.
// A project whose targets name more than one distinct component keeps the
// empty component, which Compute never attributes (fail closed). The target
// loader already rejects duplicate projects and duplicate components, so this
// is defence in depth, not a path the shipped targets take.
func SetTargetComponent(m map[string]string, project, component string) {
	if prev, seen := m[project]; seen && prev != component {
		m[project] = ""
		return
	}
	m[project] = component
}
