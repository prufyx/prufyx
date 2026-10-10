// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/k8sremovals"
)

// apiPair renders "group/version Kind" ("version Kind" for the core group).
func apiPair(group, version, kind string) string {
	if group == "" {
		return version + " " + kind
	}
	return group + "/" + version + " " + kind
}

// minorOf parses "major.minor" (a patch suffix is ignored); ok is false for
// anything else.
func minorOf(line string) (major, minor int, ok bool) {
	parts := strings.Split(line, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	m, err1 := strconv.Atoi(parts[0])
	n, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || m < 0 || n < 0 {
		return 0, 0, false
	}
	return m, n, true
}

// lineOf is the "major.minor" line of a version.
func lineOf(version string) string {
	m, n, ok := minorOf(version)
	if !ok {
		return version
	}
	return fmt.Sprintf("%d.%d", m, n)
}

// lineLess orders lines numerically.
func lineLess(a, b string) bool {
	am, an, _ := minorOf(a)
	bm, bn, _ := minorOf(b)
	return am < bm || am == bm && an < bn
}

// previousLine is the line one minor below.
func previousLine(line string) string {
	m, n, ok := minorOf(line)
	if !ok || n == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d", m, n-1)
}

// sortLines sorts lines numerically.
func sortLines(lines []string) {
	sort.SliceStable(lines, func(i, j int) bool { return lineLess(lines[i], lines[j]) })
}

// KubernetesClaims derives the checkable claims of the removal table for
// the given cluster lines. For a removal that takes effect at line L
// (kinds K of group G stop being served at version V):
//
//   - every line >= L does not serve G/V K (Kubernetes never serves a
//     removed version again);
//   - line L-1 serves G/V K (the rule's own from range: what L-1 served);
//   - line L serves every version the table names as still served there.
//
// Nothing is claimed about a removed version on lines below L-1: the table
// does not record when a version was introduced.
func KubernetesClaims(lines []string) []APIClaim {
	have := make(map[string]bool, len(lines))
	for _, line := range lines {
		have[line] = true
	}
	var out []APIClaim
	add := func(line, api, expect, source string) {
		if !have[line] {
			return
		}
		id := fmt.Sprintf("k8s.%s.%s.%s", line, strings.ReplaceAll(strings.ReplaceAll(api, "/", "_"), " ", "_"), expect)
		out = append(out, APIClaim{ID: id, Line: line, API: api, Expect: expect, Source: source})
	}
	table := k8sremovals.ByTargetMinor()
	for removalLine, removals := range table {
		for _, removal := range removals {
			for _, kind := range removal.Kinds {
				api := apiPair(removal.Group, removal.Removed, kind)
				for _, line := range lines {
					if !lineLess(line, removalLine) {
						add(line, api, ExpectNotServed, "k8sremovals:"+removal.Fact)
					}
				}
				add(previousLine(removalLine), api, ExpectServed, "k8sremovals:"+removal.Fact+":from")
				for _, served := range removal.Served {
					add(removalLine, apiPair(removal.Group, served, kind), ExpectServed, "k8sremovals:"+removal.Fact+":served")
				}
			}
		}
	}
	// The 1.32 flow-control removal is handled outside the table.
	for _, rv := range k8sremovals.RemovedVersions() {
		if _, inTable := table[rv.Line]; inTable {
			continue
		}
		for _, kind := range rv.Kinds {
			api := apiPair(rv.Group, rv.Version, kind)
			for _, line := range lines {
				if !lineLess(line, rv.Line) {
					add(line, api, ExpectNotServed, "k8sremovals:RemovedVersions:"+rv.Line)
				}
			}
			add(previousLine(rv.Line), api, ExpectServed, "k8sremovals:RemovedVersions:"+rv.Line+":from")
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return lineLess(out[i].Line, out[j].Line)
		}
		if out[i].API != out[j].API {
			return out[i].API < out[j].API
		}
		return out[i].Expect < out[j].Expect
	})
	// Drop exact duplicates (two removals can name the same kind).
	dedup := out[:0]
	for i, c := range out {
		if i > 0 && out[i-1].ID == c.ID {
			continue
		}
		dedup = append(dedup, c)
	}
	return dedup
}

// knownRemovals is every "group/version Kind" the removal table names,
// keyed by the line it stops being served.
func knownRemovals() map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, rv := range k8sremovals.AdmissionRemovedVersions() {
		if out[rv.Line] == nil {
			out[rv.Line] = map[string]bool{}
		}
		for _, kind := range rv.Kinds {
			out[rv.Line][apiPair(rv.Group, rv.Version, kind)] = true
		}
	}
	return out
}

// removedMembers lists the "group/version/Kind" members a pair removes:
// served at From and not served (or absent) at To.
func removedMembers(pair CRDPair) []string {
	served := func(rel CRDRelease) map[string]bool {
		out := map[string]bool{}
		for _, crd := range rel.CRDs {
			for _, v := range crd.Versions {
				if v.Served {
					out[crd.Group+"/"+v.Name+"/"+crd.Kind] = true
				}
			}
		}
		return out
	}
	from, to := served(pair.From), served(pair.To)
	var out []string
	for m := range from {
		if !to[m] {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}
