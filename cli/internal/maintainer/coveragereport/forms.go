// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"strings"
)

// FamilyServedAPI is the family whose sole decision of a pair is shown in its
// own form (k8s served-API), apart from A/B.
const FamilyServedAPI = "kubernetes.removed_served_gvk"

// Groups of the forms table.
const (
	GroupFleet     = "fleet"
	GroupCommunity = "community"
)

// Forms counts pairs by form. Every pair is counted once, under its strongest
// form, in this order: AB > K8s > S > L > G. Only AB is called decided. L is
// listed, not judged: the changelog family names the change, no verdict.
type Forms struct {
	AB  int `json:"ab"`
	K8s int `json:"k8s"`
	S   int `json:"s"`
	L   int `json:"l"`
	G   int `json:"g"`
}

func (f Forms) total() int { return f.AB + f.K8s + f.S + f.L + f.G }

// answered reports whether any pair has an answer of some form (not a gap).
func (f Forms) answered() bool { return f.AB+f.K8s+f.S+f.L > 0 }

func (f *Forms) add(o Forms) {
	f.AB += o.AB
	f.K8s += o.K8s
	f.S += o.S
	f.L += o.L
	f.G += o.G
}

// FormsRow is one project's row.
type FormsRow struct {
	Project string `json:"project"`
	Group   string `json:"group"`
	Pairs   int    `json:"pairs"`
	Forms
	// GapReason is a typed reason derived from the project row; empty when
	// the project has no gap.
	GapReason string `json:"gapReason,omitempty"`
}

// FormsGroup totals one group per form. There is no total over the groups.
type FormsGroup struct {
	Projects           int `json:"projects"`
	Pairs              int `json:"pairs"`
	ProjectsWithAnswer int `json:"projectsWithAnswer"`
	Forms
}

// FormsTable is the by-form view of a report: one row per project.
type FormsTable struct {
	Rows      []FormsRow `json:"rows"`
	Fleet     FormsGroup `json:"fleet"`
	Community FormsGroup `json:"community"`
}

// Typed gap reasons of the forms table.
const (
	GapReasonNoRule   = "NO_RULE_OR_ATTESTATION"
	GapReasonNotWhole = "NOT_DECIDED_FOR_THIS_PAIR"
)

// FormOf returns the form of one pair; an unknown status, or a changelog
// mark on a pair that is not a gap, is an error.
func FormOf(p Pair) (string, error) {
	switch p.Status {
	case StatusA, StatusB:
		if p.Changelog {
			return "", fmt.Errorf("pair %s->%s: changelog mark on status %s", p.From, p.To, p.Status)
		}
		if len(p.Families) == 1 && p.Families[0] == FamilyServedAPI {
			return "k8s", nil
		}
		return "ab", nil
	case StatusS:
		if p.Changelog {
			return "", fmt.Errorf("pair %s->%s: changelog mark on status S", p.From, p.To)
		}
		return "s", nil
	case StatusG:
		if p.Changelog {
			return "l", nil
		}
		return "g", nil
	}
	return "", fmt.Errorf("pair %s->%s: unknown status %q", p.From, p.To, p.Status)
}

// FormsOf builds the forms table from a report. It fails closed on a pair it
// cannot classify and on a project name that could break a table row.
func FormsOf(r Report) (FormsTable, error) {
	t := FormsTable{Rows: make([]FormsRow, 0, len(r.Projects))}
	for _, p := range r.Projects {
		if p.Project == "" || strings.ContainsAny(p.Project, "|\n\r") {
			return FormsTable{}, fmt.Errorf("forms: unusable project name %q", p.Project)
		}
		row := FormsRow{Project: p.Project, Group: GroupFleet, Pairs: len(p.Pairs)}
		if p.Catalog == CatalogCommunity {
			row.Group = GroupCommunity
		}
		for _, pr := range p.Pairs {
			f, err := FormOf(pr)
			if err != nil {
				return FormsTable{}, fmt.Errorf("forms: project %q: %w", p.Project, err)
			}
			switch f {
			case "ab":
				row.AB++
			case "k8s":
				row.K8s++
			case "s":
				row.S++
			case "l":
				row.L++
			default:
				row.G++
			}
		}
		if row.G > 0 {
			row.GapReason = GapReasonNotWhole
			if !p.Covered {
				row.GapReason = GapReasonNoRule
			}
		}
		g := &t.Fleet
		if row.Group == GroupCommunity {
			g = &t.Community
		}
		g.Projects++
		g.Pairs += row.Pairs
		g.Forms.add(row.Forms)
		if row.Forms.answered() {
			g.ProjectsWithAnswer++
		}
		t.Rows = append(t.Rows, row)
	}
	return t, nil
}

// renderFormsTable renders the per-project table: fleet rows first, then the
// community group, marked. It has no total row.
func renderFormsTable(t FormsTable) string {
	var b strings.Builder
	b.WriteString("| Project | Group | Upgrades | A/B decided | k8s served-API | S exact-pair rule | L listed, not judged | G gap | G reason |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, group := range []string{GroupFleet, GroupCommunity} {
		for _, r := range t.Rows {
			if r.Group != group {
				continue
			}
			name, label := r.Project, "release-line fleet"
			if group == GroupCommunity {
				name, label = r.Project+" (community)", "community, outside the release-line fleet"
			}
			reason := "-"
			if r.GapReason != "" {
				reason = r.GapReason
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %d | %d | %s |\n", name, label, r.Pairs, r.AB, r.K8s, r.S, r.L, r.G, reason)
		}
	}
	return b.String()
}
