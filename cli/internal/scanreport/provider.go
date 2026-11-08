// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/providerfacts"
)

// ProviderLines words a provider section for the human and Markdown
// renderers. The text is what the provider announces, attributed to the
// provider; it never says SAFE or supported without the source and date.
func ProviderLines(section *providerfacts.Section, verbose bool) []string {
	if section == nil {
		return nil
	}
	lines := []string{fmt.Sprintf("PROVIDER FACTS (advisory, %s declared, evaluated at %s, knowledge revision %s)", section.Provider, section.Now, section.KnowledgeRevision)}
	for _, l := range section.Lines {
		for _, f := range l.Findings {
			scope := f.Line
			if scope == "" {
				scope = l.Role
			} else {
				scope += " (" + l.Role + ")"
			}
			lines = append(lines, fmt.Sprintf("  %s %s %s: %s", f.Severity, f.Rule, scope, f.Text))
			if f.Next != "" {
				lines = append(lines, "    Next: "+f.Next)
			}
			if verbose {
				for _, s := range f.Sources {
					lines = append(lines, fmt.Sprintf("    source: %s lines %d-%d at %s sha256 %s", s.URL, s.StartLine, s.EndLine, s.Revision, s.ContentDigest))
				}
			}
		}
	}
	for _, n := range section.Notes {
		lines = append(lines, "  "+n)
	}
	return lines
}
