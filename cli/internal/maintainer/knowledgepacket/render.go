// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// JSON returns the artifact: indented, stable key order, trailing newline.
// The digests are computed over the compact form of the same data.
func (p *Packet) JSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func cell(s string) string {
	s = strings.NewReplacer("|", "\\|", "`", "'", "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
	if s == "" {
		return "-"
	}
	return s
}

func code(s string) string { return "`" + strings.ReplaceAll(s, "`", "'") + "`" }

// Markdown returns the step summary: the loudest findings first, then the
// table, the deltas and the digests. No timestamps; the order is stable.
func (p *Packet) Markdown() string {
	var b strings.Builder
	s := p.Summary
	fmt.Fprintf(&b, "# Knowledge signing packet\n\n")
	fmt.Fprintf(&b, "Candidate commit %s, previous revision %d (source %s).\n\n", code(p.SourceCommit), p.PreviousRevision.Revision, code(p.PreviousRevision.SourceCommit))
	fmt.Fprintf(&b, "Approve only if UNVERIFIED=0, NON-DATA=0, TRUST-PATH=0, DIRECT=0 and DECREASES=0, or each one is understood.\n\n")
	fmt.Fprintf(&b, "DATA=%d VERIFIED=%d UNVERIFIED=%d NON-DATA=%d TRUST-PATH=%d DIRECT=%d DECREASES=%d\n\n",
		s.DataPRs, s.Verified, s.Unverified, s.NonData, s.TrustPath, s.DirectCommits, s.Decreases)
	if len(p.Entries) == 0 && len(p.DirectCommits) == 0 {
		b.WriteString("No merged pull request in the range.\n\n")
	}
	for _, e := range p.Entries {
		if e.Class == ClassTrustPath {
			fmt.Fprintf(&b, "TRUST-PATH CHANGE: PR #%d (%s): %s\n\n", e.Number, code(e.MergeCommit[:12]), cell(e.ClassReason))
		}
	}
	for _, e := range p.Entries {
		if e.Class == ClassNonData {
			fmt.Fprintf(&b, "NON-DATA CHANGE IN RANGE: PR #%d (%s): %s; files: %s\n\n", e.Number, code(e.MergeCommit[:12]), cell(e.ClassReason), cell(strings.Join(e.Files, ", ")))
		}
	}
	for _, c := range p.DirectCommits {
		fmt.Fprintf(&b, "DIRECT COMMIT on main without a merge: %s\n\n", code(c))
	}
	for _, e := range p.Entries {
		if e.Class != ClassData {
			continue
		}
		for _, m := range []struct {
			name string
			m    Marker
		}{{"gate", e.Gate}, {"data review", e.Review}} {
			if m.m.Status != Verified {
				fmt.Fprintf(&b, "UNVERIFIED %s: PR #%d head %s: %s", m.name, e.Number, code(e.Head[:12]), cell(m.m.Reason))
				if m.m.Line != "" {
					fmt.Fprintf(&b, "; first line seen: %s", code(m.m.Line))
				}
				b.WriteString("\n\n")
			}
		}
	}
	for _, d := range p.Deltas.Readme {
		if d.Decrease {
			fmt.Fprintf(&b, "DECREASE: %s: %s -> %s\n\n", cell(d.Label), cell(d.Before), cell(d.After))
		}
	}
	b.WriteString("## Pull requests\n\n| PR | Class | Gate | Review | Merge | Head | Author |\n| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, e := range p.Entries {
		fmt.Fprintf(&b, "| #%d | %s | %s | %s | %s | %s | %s |\n", e.Number, e.Class, e.Gate.Status, e.Review.Status, code(e.MergeCommit[:12]), code(e.Head[:12]), cell(e.Author))
	}
	b.WriteString("\n## Rule and attestation deltas\n\n| File | Before | After | Added | Removed | Changed |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, d := range p.Deltas.Rules {
		fmt.Fprintf(&b, "| %s | %d | %d | %s | %s | %s |\n", code(d.Path), d.Before, d.After, cell(strings.Join(d.Added, "; ")), cell(strings.Join(d.Removed, "; ")), cell(strings.Join(d.Changed, "; ")))
	}
	b.WriteString("\n## Projects\n\n")
	fmt.Fprintf(&b, "Added: %s\n\nRemoved: %s\n", cell(strings.Join(p.Deltas.Projects.Added, ", ")), cell(strings.Join(p.Deltas.Projects.Removed, ", ")))
	b.WriteString("\n## Data files\n\n")
	if len(p.Deltas.DataFiles) == 0 {
		b.WriteString("None changed.\n")
	}
	for _, c := range p.Deltas.DataFiles {
		fmt.Fprintf(&b, "- %s %s\n", c.Status, code(c.Path))
	}
	b.WriteString("\n## README numbers\n\n")
	if len(p.Deltas.Readme) == 0 {
		b.WriteString("Unchanged.\n")
	} else {
		b.WriteString("| Label | Before | After | Decrease |\n| --- | --- | --- | --- |\n")
		for _, d := range p.Deltas.Readme {
			fmt.Fprintf(&b, "| %s | %s | %s | %t |\n", cell(d.Label), cell(d.Before), cell(d.After), d.Decrease)
		}
	}
	fmt.Fprintf(&b, "\n## Digests\n\ncontentDigest %s\n\npacketDigest %s\n", code(p.ContentDigest), code(p.PacketDigest))
	return b.String()
}
