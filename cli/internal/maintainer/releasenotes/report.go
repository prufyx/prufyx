// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Options labels the two trees and carries the merged pull requests.
type Options struct {
	FromLabel string
	ToLabel   string
	// PRs is nil with a non-empty PRNote when the pull requests are unknown.
	PRs    []PR
	PRNote string
}

// Render writes the Markdown for the changes from one snapshot to the next.
func Render(from, to *Snapshot, o Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Changes from `%s` to `%s`, computed by `prufyx-maintainer release-notes` from the data files of the two trees. No figure or list below is typed by hand.\n\n", o.FromLabel, o.ToLabel)
	for _, m := range from.Missing {
		fmt.Fprintf(&b, "- `%s` does not exist in `%s`; it counts as empty there.\n", m, o.FromLabel)
	}
	for _, m := range to.Missing {
		fmt.Fprintf(&b, "- `%s` does not exist in `%s`; it counts as empty there.\n", m, o.ToLabel)
	}
	if len(from.Missing)+len(to.Missing) > 0 {
		b.WriteString("\n")
	}
	summary(&b, from, to, o)
	projects(&b, from, to)
	onboarding(&b, from, to)
	rules(&b, from, to)
	lines(&b, from, to, o)
	pullRequests(&b, o)
	b.WriteString("### How to read these figures\n\n")
	b.WriteString("A catalogued project is not tested coverage: a catalogue entry says Prufyx holds retained public sources for the project, and only an executable check can block an upgrade. ")
	b.WriteString("Decided means a valid rule or attestation covers every version of both release lines, so the answer is BLOCKED or UNKNOWN, never a whole-upgrade PASS; decided is not safe. ")
	b.WriteString("An exact-pair rule decides only the versions it names. A line attestation says which rules were derived for a release line, not that an upgrade into it is safe. The metrics are defined in `cli/docs/coverage-report.md`.\n")
	return b.String()
}

func delta(a, b int) string {
	if d := b - a; d > 0 {
		return "+" + strconv.Itoa(d)
	} else if d < 0 {
		return strconv.Itoa(d)
	}
	return "0"
}

func row(b *strings.Builder, name string, a, c int, ok bool) {
	if !ok {
		fmt.Fprintf(b, "| %s | n/a | n/a | n/a |\n", name)
		return
	}
	fmt.Fprintf(b, "| %s | %d | %d | %s |\n", name, a, c, delta(a, c))
}

func countOf(s *Snapshot, k string) (int, bool) { v, ok := s.Counts[k]; return v, ok }

func lineTotal(s *Snapshot, onlyK8s bool) int {
	n := 0
	for c, set := range s.Lines {
		if onlyK8s && c != kubernetesPackage {
			continue
		}
		n += len(set)
	}
	return n
}

func summary(b *strings.Builder, from, to *Snapshot, o Options) {
	fmt.Fprintf(b, "### Summary\n\n| Measure | %s | %s | Change |\n| --- | --- | --- | --- |\n", o.FromLabel, o.ToLabel)
	for _, m := range []struct{ name, key string }{
		{"Projects catalogued with retained public sources", "selectedSourceProjects"},
		{"  of them source-only, no check", "selectedSourceOnlyProjects"},
		{"Projects with at least one executable check", "executableProjects"},
		{"CNCF source rules, active", "cncfSourceRules"},
		{"CNCF projects with a rule", "cncfRuleProjects"},
		{"Rules for non-CNCF projects", "communityProjectSourceRules"},
		{"Non-CNCF projects with a rule", "communityProjectRuleProjects"},
	} {
		a, aok := countOf(from, m.key)
		c, cok := countOf(to, m.key)
		row(b, m.name, a, c, aok && cok)
	}
	row(b, "Line attestations", lineTotal(from, false), lineTotal(to, false), true)
	row(b, "Kubernetes minors with a line attestation", lineTotal(from, true), lineTotal(to, true), true)
	fd, td := from.Depth, to.Depth
	both := fd != nil && td != nil
	get := func(f func(*Depth) int) (int, int) {
		if !both {
			return 0, 0
		}
		return f(fd), f(td)
	}
	for _, m := range []struct {
		name string
		f    func(*Depth) int
	}{
		{"Projects with a release-line snapshot (README coverage block)", func(d *Depth) int { return d.Projects }},
		{"Upgrades between consecutive release lines", func(d *Depth) int { return d.Pairs }},
		{"Decided for the whole release-line pair (A+B)", func(d *Depth) int { return d.Decided }},
		{"Rule for one exact version pair only (S)", func(d *Depth) int { return d.Exact }},
		{"Gap, no valid rule (G)", func(d *Depth) int { return d.Gap }},
	} {
		a, c := get(m.f)
		row(b, m.name, a, c, both)
	}
	b.WriteString("\n")
	if both {
		fmt.Fprintf(b, "The release-line figures are the README coverage block, generated on %s (%s) and %s (%s) by `scripts/readme-coverage.sh`; the block comes from `prufyx-maintainer coverage report`.\n\n", fd.GeneratedOn, o.FromLabel, td.GeneratedOn, o.ToLabel)
	} else {
		b.WriteString("The release-line figures (A+B, S, G) are n/a because the README coverage block is missing or reworded in one of the trees.\n\n")
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func projects(b *strings.Builder, from, to *Snapshot) {
	var added, removed, gained []string
	for _, id := range sortedKeys(to.Projects) {
		state := "source-only, no check"
		if to.Executable[id] {
			state = "executable check"
		}
		name := to.Projects[id]
		if _, ok := from.Projects[id]; !ok {
			added = append(added, fmt.Sprintf("- `%s` (%s): %s", id, name, state))
		} else if to.Executable[id] && !from.Executable[id] {
			gained = append(gained, fmt.Sprintf("- `%s` (%s)", id, name))
		}
	}
	for _, id := range sortedKeys(from.Projects) {
		if _, ok := to.Projects[id]; !ok {
			removed = append(removed, fmt.Sprintf("- `%s`", id))
		}
	}
	list(b, "### Projects added to the catalogue", added, "No project was added.")
	list(b, "### Catalogued projects that gained their first executable check", gained, "None.")
	if len(removed) > 0 {
		list(b, "### Projects removed from the catalogue", removed, "")
	}
}

func list(b *strings.Builder, heading string, items []string, empty string) {
	fmt.Fprintf(b, "%s (%d)\n\n", heading, len(items))
	if len(items) == 0 {
		fmt.Fprintf(b, "%s\n\n", empty)
		return
	}
	b.WriteString(strings.Join(items, "\n") + "\n\n")
}

func onboarding(b *strings.Builder, from, to *Snapshot) {
	var items []string
	approved, projects := 0, 0
	for _, id := range sortedKeys(to.Onboarding) {
		if _, ok := from.Onboarding[id]; ok {
			continue
		}
		ps := to.Onboarding[id]
		decision := "no project entries"
		if len(ps) > 0 {
			decision = ps[0].Decision
		}
		items = append(items, fmt.Sprintf("- batch `%s`, decision `%s`:", id, decision))
		for _, p := range ps {
			items = append(items, fmt.Sprintf("  - `%s` (%s, %s): proof pair %s to %s", p.Slug, p.Catalog, p.Kind, p.FromTag, p.ToTag))
		}
		if decision == "approve" {
			approved++
			projects += len(ps)
		}
	}
	fmt.Fprintf(b, "### Onboarding batches (%d approved, %d project entries)\n\n", approved, projects)
	if len(items) == 0 {
		b.WriteString("No onboarding batch was added.\n\n")
		return
	}
	b.WriteString(strings.Join(items, "\n") + "\n\n")
	b.WriteString("Only approved batches are counted. A project entry names the project and the proof pair of versions the batch rests on.\n\n")
}

func rules(b *strings.Builder, from, to *Snapshot) {
	keys := map[projectKey]bool{}
	for k := range from.Rules {
		keys[k] = true
	}
	for k := range to.Rules {
		keys[k] = true
	}
	sorted := make([]projectKey, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Catalogue != sorted[j].Catalogue {
			return sorted[i].Catalogue < sorted[j].Catalogue
		}
		return sorted[i].Project < sorted[j].Project
	})
	var rows []string
	totalAdded, totalRemoved := 0, 0
	for _, k := range sorted {
		add, rem := 0, 0
		for id := range to.Rules[k] {
			if !from.Rules[k][id] {
				add++
			}
		}
		for id := range from.Rules[k] {
			if !to.Rules[k][id] {
				rem++
			}
		}
		if add+rem == 0 {
			continue
		}
		totalAdded += add
		totalRemoved += rem
		rows = append(rows, fmt.Sprintf("| %s | `%s` | %d | %d | %d |", k.Catalogue, k.Project, add, rem, len(to.Rules[k])))
	}
	fmt.Fprintf(b, "### Rules by project (%d added, %d removed)\n\n", totalAdded, totalRemoved)
	if len(rows) == 0 {
		b.WriteString("No rule was added or removed.\n\n")
	} else {
		b.WriteString("| Catalogue | Project | Added | Removed | Rules now |\n| --- | --- | --- | --- | --- |\n" + strings.Join(rows, "\n") + "\n\n")
		b.WriteString("Counts include rules that are withdrawn; withdrawn rules are not used and are listed below.\n\n")
	}
	var wd []string
	for _, id := range sortedKeys(to.Withdrawn) {
		if !from.Withdrawn[id] {
			wd = append(wd, fmt.Sprintf("- `%s`", id))
		}
	}
	list(b, "### Rules newly withdrawn", wd, "None.")
}

// lineLess orders release lines such as "1.9" before "1.10".
func lineLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, ex := strconv.Atoi(pa[i])
		y, ey := strconv.Atoi(pb[i])
		if ex == nil && ey == nil && x != y {
			return x < y
		}
		if (ex != nil || ey != nil) && pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

func sortedLines(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return lineLess(out[i], out[j]) })
	return out
}

func lines(b *strings.Builder, from, to *Snapshot, o Options) {
	comps := map[string]bool{}
	for c := range from.Lines {
		comps[c] = true
	}
	for c := range to.Lines {
		comps[c] = true
	}
	var items []string
	for _, c := range sortedKeys(comps) {
		var add, rem []string
		for _, l := range sortedLines(to.Lines[c]) {
			if !from.Lines[c][l] {
				add = append(add, l)
			}
		}
		for _, l := range sortedLines(from.Lines[c]) {
			if !to.Lines[c][l] {
				rem = append(rem, l)
			}
		}
		if len(add)+len(rem) == 0 {
			continue
		}
		s := fmt.Sprintf("- `%s`: %d now", strings.TrimPrefix(c, "pkg:github/"), len(to.Lines[c]))
		if len(add) > 0 {
			s += "; new lines " + strings.Join(add, ", ")
		}
		if len(rem) > 0 {
			s += "; removed lines " + strings.Join(rem, ", ")
		}
		items = append(items, s)
	}
	list(b, "### Line attestations by project", items, "No line attestation was added or removed.")
	k := to.Lines[kubernetesPackage]
	if len(k) == 0 {
		b.WriteString("### Kubernetes minors\n\nNo Kubernetes line attestation in this tree.\n\n")
		return
	}
	var add []string
	for _, l := range sortedLines(k) {
		if !from.Lines[kubernetesPackage][l] {
			add = append(add, l)
		}
	}
	newText := "none"
	if len(add) > 0 {
		newText = strings.Join(add, ", ")
	}
	all := sortedLines(k)
	fmt.Fprintf(b, "### Kubernetes minors\n\nLines with a line attestation (%d): %s. New since `%s`: %s.\n\n", len(all), strings.Join(all, ", "), o.FromLabel, newText)
}

func pullRequests(b *strings.Builder, o Options) {
	if o.PRs == nil && o.PRNote != "" {
		fmt.Fprintf(b, "### Merged pull requests\n\n%s\n\n", o.PRNote)
		return
	}
	items := make([]string, 0, len(o.PRs))
	for _, p := range o.PRs {
		if p.Number > 0 {
			items = append(items, fmt.Sprintf("- #%d %s", p.Number, p.Title))
		} else {
			items = append(items, "- "+p.Title)
		}
	}
	list(b, "### Merged pull requests", items, "No pull request was merged.")
}
