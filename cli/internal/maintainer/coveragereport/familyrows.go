// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"fmt"
	"slices"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// Fact families of the chart evidence. Their pairs are decided only when a
// rule or attestation of that family exists; until then each row renders
// "none yet".
const (
	FamilyChartAPISurface   = "chart.api_surface"
	FamilyChartKubeRange    = "chart.declared_kubernetes_range"
	familyKeyCRD            = "crd"
	familyKeyChartAPI       = "chart_api_surface"
	familyKeyChartKubeRange = "chart_declared_kubernetes_range"
	familyKeyHelmValues     = "helm_values_schema"
)

// familyDef is one evidence family of the README: a stable key, the label the
// row prints and the fact families whose decided pairs it counts.
type familyDef struct {
	key, label string
	families   []string
}

// evidenceFamilies is the fixed list of rows, in print order. A row exists
// even when nothing is decided by it.
var evidenceFamilies = []familyDef{
	{familyKeyCRD, "CRD versions", []string{lineattest.FamilyCustomResourceVersions}},
	{familyKeyChartAPI, "Chart install API surface", []string{FamilyChartAPISurface}},
	{familyKeyChartKubeRange, "Chart declared Kubernetes range", []string{FamilyChartKubeRange}},
	{familyKeyHelmValues, "Helm values schema", []string{FamilyHelmValuesSchema}},
}

// FamilyCount is what one family decides in one group.
type FamilyCount struct {
	Projects int `json:"projects"`
	Pairs    int `json:"pairs"`
}

// FamilyRow is one evidence family's decided pairs. A pair decided by several
// families is in each of their rows; the rows are never added together.
type FamilyRow struct {
	Family    string      `json:"family"`
	Label     string      `json:"label"`
	Fleet     FamilyCount `json:"fleet"`
	Community FamilyCount `json:"community"`
}

// familyRowsOf counts, per family, the decided pairs (status A or B) whose
// deciding families include it. A project marked with no Kubernetes surface
// is never counted.
func familyRowsOf(r Report) []FamilyRow {
	rows := make([]FamilyRow, len(evidenceFamilies))
	for i, d := range evidenceFamilies {
		rows[i] = FamilyRow{Family: d.key, Label: d.label}
	}
	for _, p := range r.Projects {
		if p.KubernetesSurface == KubernetesSurfaceNone {
			continue
		}
		for i, d := range evidenceFamilies {
			n := 0
			for _, pr := range p.Pairs {
				if pr.Status != StatusA && pr.Status != StatusB {
					continue
				}
				if slices.ContainsFunc(pr.Families, func(f string) bool { return slices.Contains(d.families, f) }) {
					n++
				}
			}
			if n == 0 {
				continue
			}
			c := &rows[i].Fleet
			if p.Catalog == CatalogCommunity {
				c = &rows[i].Community
			}
			c.Projects++
			c.Pairs += n
		}
	}
	return rows
}

// familyScopeText is the fixed scope sentence of the family rows. It has no
// free text and no number.
const familyScopeText = "Each row below counts the upgrades decided by one evidence family; a family with nothing decided says none yet. The rows are not added together: an upgrade decided by two families is in both rows and counted once in the forms above, and an upgrade of a project with no Kubernetes surface is a permanent gap, never decided."

func renderFamilyRows(rows []FamilyRow) string {
	cell := func(c FamilyCount) string {
		if c.Pairs == 0 {
			return "none yet"
		}
		return fmt.Sprintf("%d upgrades in %d projects", c.Pairs, c.Projects)
	}
	var b strings.Builder
	b.WriteString("| Evidence family (decided upgrades) | Release-line fleet | Community group |\n| --- | --- | --- |\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.Label, cell(r.Fleet), cell(r.Community))
	}
	return b.String()
}
