// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"regexp"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

var simpleName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type patchTarget struct{ name, ns string }

// applyPatches applies the patches of a kustomization or Flux Kustomization
// to the releases collected since index from. Only a patch whose whole effect
// is to set spec.chart.spec.version of one named HelmRelease is evaluated;
// every other patch is a PATCH_NOT_EVALUATED gap.
func (w *walker) applyPatches(patches []any, from int, src intake.Source) {
	if len(patches) == 0 {
		return
	}
	byName := map[string][]int{}
	for i := from; i < len(w.rels); i++ {
		if w.rels[i].Kind == KindHelmRelease && !w.metas[i].chartRef {
			byName[w.metas[i].objName] = append(byName[w.metas[i].objName], i)
		}
	}
	for _, p := range patches {
		target, version, ok := parsePatch(p)
		if !ok {
			w.gap(PatchNotEvaluated, src, "patch is not a single-version change of one HelmRelease")
			continue
		}
		matched := false
		for _, i := range byName[target.name] {
			if target.ns == "" || w.metas[i].objNs == target.ns {
				w.rels[i].ChartVersion = version
				matched = true
			}
		}
		if !matched {
			w.gap(PatchNotEvaluated, src, "patch target "+target.name+" was not found")
		}
	}
}

func onlyKeys(m map[string]any, keys ...string) bool {
	if len(m) > len(keys) {
		return false
	}
	for k := range m {
		found := false
		for _, allowed := range keys {
			if k == allowed {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// parsePatch accepts an inline JSON6902 replace/add of
// /spec/chart/spec/version and an inline strategic-merge patch that holds
// nothing else, both aimed at one HelmRelease chosen by name.
func parsePatch(entry any) (patchTarget, string, bool) {
	var none patchTarget
	m := asMap(entry)
	text, isText := m["patch"].(string)
	if m == nil || !isText || len(text) > MaxPatchBytes || !onlyKeys(m, "patch", "target") {
		return none, "", false
	}
	var target patchTarget
	hasTarget := false
	if t, present := m["target"]; present {
		tm := asMap(t)
		if tm == nil || !onlyKeys(tm, "group", "version", "kind", "name", "namespace") {
			return none, "", false
		}
		if asStr(tm["kind"]) != KindHelmRelease || !simpleName.MatchString(asStr(tm["name"])) {
			return none, "", false
		}
		target = patchTarget{asStr(tm["name"]), asStr(tm["namespace"])}
		hasTarget = true
	}
	docs, err := intake.DecodeDocuments([]byte(text))
	if err != nil || len(docs) != 1 {
		return none, "", false
	}
	switch d := docs[0].(type) {
	case []any:
		if !hasTarget || len(d) != 1 {
			return none, "", false
		}
		op := asMap(d[0])
		if op == nil || !onlyKeys(op, "op", "path", "value") || len(op) != 3 {
			return none, "", false
		}
		if verb := asStr(op["op"]); (verb != "replace" && verb != "add") || asStr(op["path"]) != "/spec/chart/spec/version" {
			return none, "", false
		}
		version, ok := scalar(op["value"])
		return target, version, ok
	case map[string]any:
		if !onlyKeys(d, "apiVersion", "kind", "metadata", "spec") || asStr(d["kind"]) != KindHelmRelease ||
			groupOf(asStr(d["apiVersion"])) != "helm.toolkit.fluxcd.io" {
			return none, "", false
		}
		md := asMap(d["metadata"])
		spec := asMap(d["spec"])
		chart := asMap(spec["chart"])
		inner := asMap(chart["spec"])
		if md == nil || !onlyKeys(md, "name", "namespace") || spec == nil || len(spec) != 1 || chart == nil || len(chart) != 1 ||
			inner == nil || len(inner) != 1 {
			return none, "", false
		}
		named := patchTarget{asStr(md["name"]), asStr(md["namespace"])}
		if !simpleName.MatchString(named.name) || (hasTarget && (named.name != target.name || (target.ns != "" && named.ns != "" && named.ns != target.ns))) {
			return none, "", false
		}
		if !hasTarget {
			target = named
		}
		version, ok := scalar(inner["version"])
		return target, version, ok
	}
	return none, "", false
}
