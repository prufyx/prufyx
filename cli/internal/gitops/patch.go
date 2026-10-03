// SPDX-License-Identifier: AGPL-3.0-only

package gitops

import (
	"regexp"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

var simpleName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

type patchTarget struct{ name, ns string }

// patchResult is one patch, parsed once. When reason is set the patch is not
// evaluated and reason and detail form the gap.
type patchResult struct {
	target         patchTarget
	version        string
	reason, detail string
}

const patchNotSingle = "patch is not a single-version change of one HelmRelease"

// applyPatches applies the patches of a kustomization or Flux Kustomization
// to the releases this object collected itself since index from: releases
// that a nested Flux Kustomization or Argo CD Application collected belong to
// that object and are not patched. Only a patch whose whole effect is to set
// spec.chart.spec.version of one named HelmRelease is evaluated; every other
// patch is a PATCH_NOT_EVALUATED gap.
func (w *walker) applyPatches(patches []patchResult, from int, src intake.Source) {
	if len(patches) == 0 {
		return
	}
	byName := map[string][]int{}
	for i := from; i < len(w.entries); i++ {
		if !w.charge(1) {
			return
		}
		if e := w.entries[i]; e.owner == w.owner && e.hr != nil && !e.hr.hrP.chartRef {
			byName[e.hr.doc.Name] = append(byName[e.hr.doc.Name], i)
		}
	}
	for _, p := range patches {
		if !w.charge(1) {
			return
		}
		if p.reason != "" {
			w.gap(p.reason, src, p.detail)
			continue
		}
		matched := false
		for _, i := range byName[p.target.name] {
			// The namespace transformer of the same object runs after its
			// patches, so a target namespace may name either namespace.
			if e := &w.entries[i]; p.target.ns == "" || e.ns == p.target.ns || e.hr.doc.Namespace == p.target.ns {
				e.version = p.version
				matched = true
			}
		}
		if !matched {
			w.gap(PatchNotEvaluated, src, "patch target "+p.target.name+" was not found among the releases of this object")
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
// nothing else, both aimed at one HelmRelease chosen by name. It runs once
// per patch; the text is decoded against the shared node budget.
func (a *analysis) parsePatch(entry any) (patchResult, int) {
	bad := patchResult{reason: PatchNotEvaluated, detail: patchNotSingle}
	m := asMap(entry)
	text, isText := m["patch"].(string)
	if m == nil || !isText || !onlyKeys(m, "patch", "target") {
		return bad, 1
	}
	if len(text) > MaxPatchBytes {
		return patchResult{reason: PatchNotEvaluated, detail: "patch is longer than 4096 bytes"}, 1
	}
	var target patchTarget
	hasTarget := false
	if t, present := m["target"]; present {
		tm := asMap(t)
		if tm == nil || !onlyKeys(tm, "group", "version", "kind", "name", "namespace") {
			return bad, 1
		}
		if asStr(tm["kind"]) != KindHelmRelease || !simpleName.MatchString(asStr(tm["name"])) {
			return bad, 1
		}
		target = patchTarget{asStr(tm["name"]), asStr(tm["namespace"])}
		hasTarget = true
	}
	cost := 1 + len(text)/64
	docs, limit, err := a.decodeText(text)
	if limit != "" {
		return patchResult{reason: ClosureLimit, detail: limit + "; patch not read"}, cost
	}
	if err != nil || len(docs) != 1 {
		return bad, cost
	}
	switch d := docs[0].(type) {
	case []any:
		if !hasTarget || len(d) != 1 {
			return bad, cost
		}
		op := asMap(d[0])
		if op == nil || !onlyKeys(op, "op", "path", "value") || len(op) != 3 {
			return bad, cost
		}
		if verb := asStr(op["op"]); (verb != "replace" && verb != "add") || asStr(op["path"]) != "/spec/chart/spec/version" {
			return bad, cost
		}
		version, ok := scalar(op["value"])
		if !ok {
			return bad, cost
		}
		return patchResult{target: target, version: version}, cost
	case map[string]any:
		if !onlyKeys(d, "apiVersion", "kind", "metadata", "spec") || asStr(d["kind"]) != KindHelmRelease ||
			groupOf(asStr(d["apiVersion"])) != "helm.toolkit.fluxcd.io" {
			return bad, cost
		}
		md := asMap(d["metadata"])
		spec := asMap(d["spec"])
		chart := asMap(spec["chart"])
		inner := asMap(chart["spec"])
		if md == nil || !onlyKeys(md, "name", "namespace") || spec == nil || len(spec) != 1 || chart == nil || len(chart) != 1 ||
			inner == nil || len(inner) != 1 {
			return bad, cost
		}
		named := patchTarget{asStr(md["name"]), asStr(md["namespace"])}
		if !simpleName.MatchString(named.name) || (hasTarget && (named.name != target.name || (target.ns != "" && named.ns != "" && named.ns != target.ns))) {
			return bad, cost
		}
		if !hasTarget {
			target = named
		}
		version, ok := scalar(inner["version"])
		if !ok {
			return bad, cost
		}
		return patchResult{target: target, version: version}, cost
	}
	return bad, cost
}
