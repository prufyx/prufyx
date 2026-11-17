// SPDX-License-Identifier: AGPL-3.0-only

package releasenotes

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/coveragereport"
)

// pairChange is one release-line pair whose decided state changed.
type pairChange struct {
	From, To string
	Was, Is  string // status, "-" when the pair did not exist
}

// projectDiff is what changed for one project present in both counts.
type projectDiff struct {
	Name         string
	PairsAdded   int
	PairsRemoved int
	Gained       []pairChange
	Lost         []pairChange
	RulesFrom    int
	RulesTo      int
}

// CountsDiff is the difference of two counts files. All lists are sorted.
type CountsDiff struct {
	Added    []string
	Removed  []string
	Projects []projectDiff // only projects with a change
}

func decided(s string) bool { return s == coveragereport.StatusA || s == coveragereport.StatusB }

func projectName(p coveragereport.Project) string {
	if p.Catalog != "" {
		return p.Project + " (" + p.Catalog + ")"
	}
	return p.Project
}

func index(c *Counts) map[string]coveragereport.Project {
	m := make(map[string]coveragereport.Project, len(c.Report.Projects))
	for _, p := range c.Report.Projects {
		m[projectKeyOf(p)] = p
	}
	return m
}

func sortedProjectKeys(m map[string]coveragereport.Project) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := m[keys[i]], m[keys[j]]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.Catalog < b.Catalog
	})
	return keys
}

func sortChanges(c []pairChange) {
	sort.Slice(c, func(i, j int) bool {
		return c[i].From+"\x00"+c[i].To < c[j].From+"\x00"+c[j].To
	})
}

// DiffCounts compares the previous counts with the current ones.
func DiffCounts(prev, cur *Counts) CountsDiff {
	var d CountsDiff
	pm, cm := index(prev), index(cur)
	for _, k := range sortedProjectKeys(cm) {
		pp, ok := pm[k]
		cp := cm[k]
		if !ok {
			d.Added = append(d.Added, projectName(cp))
			continue
		}
		pd := projectDiff{Name: projectName(cp), RulesFrom: pp.ValidRules, RulesTo: cp.ValidRules}
		pairs := map[string]string{}
		for _, p := range pp.Pairs {
			pairs[p.From+"\x00"+p.To] = p.Status
		}
		seen := map[string]bool{}
		for _, p := range cp.Pairs {
			key := p.From + "\x00" + p.To
			seen[key] = true
			was, existed := pairs[key]
			if !existed {
				pd.PairsAdded++
				was = "-"
			}
			if decided(p.Status) && !decided(was) {
				pd.Gained = append(pd.Gained, pairChange{p.From, p.To, was, p.Status})
			} else if !decided(p.Status) && decided(was) {
				pd.Lost = append(pd.Lost, pairChange{p.From, p.To, was, p.Status})
			}
		}
		for _, p := range pp.Pairs {
			if !seen[p.From+"\x00"+p.To] {
				pd.PairsRemoved++
				if decided(p.Status) {
					pd.Lost = append(pd.Lost, pairChange{p.From, p.To, p.Status, "-"})
				}
			}
		}
		sortChanges(pd.Gained)
		sortChanges(pd.Lost)
		if pd.PairsAdded+pd.PairsRemoved+len(pd.Gained)+len(pd.Lost) > 0 || pd.RulesFrom != pd.RulesTo {
			d.Projects = append(d.Projects, pd)
		}
	}
	for _, k := range sortedProjectKeys(pm) {
		if _, ok := cm[k]; !ok {
			d.Removed = append(d.Removed, projectName(pm[k]))
		}
	}
	return d
}

// signed formats a difference.
func signed(a, b int) string { return delta(a, b) }

// renderCountsDiff writes the since-previous-release section. Every number
// comes from the two counts files.
func renderCountsDiff(b *strings.Builder, prev, cur *Counts, pin PreviousPin) {
	d := DiffCounts(prev, cur)
	fmt.Fprintf(b, "### Coverage since the previous release\n\n")
	fmt.Fprintf(b, "previous = tag `%s`, commit %s, counts sha256 `%s`; current counts sha256 `%s`.\n\n", pin.Tag, pin.Commit, pin.CountsSha256, cur.Sha256)
	b.WriteString("The counts carry the number of valid rules per project, not rule ids, so rules added are the per-project change of that number.\n\n")
	b.WriteString(fmt.Sprintf("Projects added (%d): %s\n\n", len(d.Added), joinOrNone(d.Added)))
	b.WriteString(fmt.Sprintf("Projects removed (%d): %s\n\n", len(d.Removed), joinOrNone(d.Removed)))
	var pairsAdded, pairsRemoved, gained, lost int
	for _, p := range d.Projects {
		pairsAdded += p.PairsAdded
		pairsRemoved += p.PairsRemoved
		gained += len(p.Gained)
		lost += len(p.Lost)
	}
	fmt.Fprintf(b, "In projects present in both releases: upgrade pairs added %d, removed %d, decided pairs gained %d, lost %d. Valid rules in all projects: %d -> %d (%s).\n\n",
		pairsAdded, pairsRemoved, gained, lost, totalRules(prev), totalRules(cur), signed(totalRules(prev), totalRules(cur)))
	if len(d.Projects) == 0 {
		b.WriteString("No project present in both releases changed.\n\n")
		return
	}
	b.WriteString("| Project | Pairs added | Pairs removed | Decided gained | Decided lost | Valid rules |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, p := range d.Projects {
		fmt.Fprintf(b, "| `%s` | %d | %d | %d | %d | %d -> %d (%s) |\n", p.Name, p.PairsAdded, p.PairsRemoved, len(p.Gained), len(p.Lost), p.RulesFrom, p.RulesTo, signed(p.RulesFrom, p.RulesTo))
	}
	b.WriteString("\n")
	for _, p := range d.Projects {
		for _, c := range p.Gained {
			fmt.Fprintf(b, "- `%s` gained a decision: %s -> %s (%s -> %s)\n", p.Name, c.From, c.To, c.Was, c.Is)
		}
		for _, c := range p.Lost {
			fmt.Fprintf(b, "- `%s` lost a decision: %s -> %s (%s -> %s)\n", p.Name, c.From, c.To, c.Was, c.Is)
		}
	}
	if gained+lost > 0 {
		b.WriteString("\n")
	}
}

func totalRules(c *Counts) int {
	n := 0
	for _, p := range c.Report.Projects {
		n += p.ValidRules
	}
	return n
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	q := make([]string, len(s))
	for i, v := range s {
		q[i] = "`" + v + "`"
	}
	return strings.Join(q, ", ")
}
