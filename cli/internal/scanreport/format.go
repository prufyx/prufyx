// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

// Formats lists the output formats of the scan command.
func Formats() []string { return []string{"human", "json", "sarif", "markdown"} }

// RenderOptions selects the optional sections of the human and Markdown
// formats.
type RenderOptions struct {
	ShowPasses bool
	Verbose    bool
}

// Render renders the report in one of Formats. The format changes only the
// bytes: the report, its verdict and the exit code are the same for all.
func Render(report Report, format string, options RenderOptions) ([]byte, error) {
	switch format {
	case "json":
		return MarshalJSON(report)
	case "sarif":
		return SARIF(report)
	case "markdown":
		return Markdown(report, MarkdownOptions(options)), nil
	}
	return Human(report, HumanOptions(options)), nil
}
