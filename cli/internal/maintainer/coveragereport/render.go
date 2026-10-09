// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JSON returns the canonical report bytes: indented, sorted, newline-ended.
func (r Report) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func pct(v float64) string { return fmt.Sprintf("%.1f%%", v*100) }

func totalsRow(name string, t Totals) string {
	return fmt.Sprintf("| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d | %s | %s |\n",
		name, t.Projects, t.C1, t.C3, t.C5, t.A, t.B, t.S, t.G, t.Pairs, pct(t.VCMean), pct(t.SPairs))
}

// Markdown returns the human summary. It repeats the JSON facts and adds
// nothing the JSON does not hold.
func (r Report) Markdown() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Coverage report\n\n")
	fmt.Fprintf(&b, "- Evaluated at: %s\n- Window: last %d lines per project (%d consecutive pairs)\n", r.Now, r.Window, r.Window-1)
	fmt.Fprintf(&b, "- Pack: `%s` (revision %s, schema %s)\n", r.Pack.Digest, r.Pack.Revision, r.Pack.Schema)
	captured := r.Lines.CapturedOn
	if captured == "" {
		captured = "not stated"
	}
	fmt.Fprintf(&b, "- Lines snapshot: `%s` (captured %s)\n", r.Lines.Digest, captured)
	fmt.Fprintf(&b, "- Projects with a valid rule or attestation in the pack: %d\n\n", r.PackProjects)

	b.WriteString("## Fleet\n\n")
	b.WriteString("| Scope | Projects | C1 | C3 | C5 | A | B | S | G | Pairs | VC mean | S share |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	b.WriteString(totalsRow("all", r.Fleet))
	b.WriteString(totalsRow("priority", r.Priority))
	if r.CommunityCatalog != nil {
		b.WriteString(totalsRow("community catalog (not in the fleet; no CNCF status asserted)", *r.CommunityCatalog))
	}
	b.WriteString("\nA: attested. B: bounded. S: exact-pair rule only (shown, not counted in VC). G: nothing. VC is (A+B)/pairs.\n\n")

	b.WriteString("## By family\n\n")
	if len(r.Families) == 0 {
		b.WriteString("No pair is decided by a family.\n\n")
	} else {
		b.WriteString("| Family | A | B |\n|---|---|---|\n")
		for _, f := range r.Families {
			fmt.Fprintf(&b, "| %s | %d | %d |\n", f.Family, f.A, f.B)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Projects\n\n")
	b.WriteString("| Project | Window | A | B | S | G | VC | Covered | Expiring 14 d |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, p := range r.Projects {
		window := "-"
		if n := len(p.Window); n > 0 {
			window = p.Window[0] + " to " + p.Window[n-1]
		}
		covered := "no"
		if p.Covered {
			covered = "yes"
		}
		name := p.Project
		if p.Catalog == CatalogCommunity {
			name += " (community catalog)"
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %.2f | %s | %d |\n", name, window, p.A, p.B, p.S, p.G, p.VC, covered, p.Expiring)
	}
	if len(r.WithoutLines) > 0 {
		b.WriteString("\n## Projects without lines\n\nThese projects have a valid rule or attestation but no lines in the snapshot; their pairs are unknown and are not counted.\n\n")
		for _, p := range r.WithoutLines {
			fmt.Fprintf(&b, "- %s\n", p)
		}
	}
	return []byte(b.String())
}
