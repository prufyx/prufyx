// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import "fmt"

// Formats lists the output formats of the scan command.
func Formats() []string { return []string{"human", "json", "sarif", "markdown"} }

// RenderOptions selects the optional sections of the human and Markdown
// formats.
type RenderOptions struct {
	ShowPasses bool
	Verbose    bool
	// OnlyBlocked lists only BLOCKED findings in the human and Markdown
	// formats and says how many other items are hidden. JSON and SARIF are
	// always complete.
	OnlyBlocked bool
}

// Render renders the report in one of Formats. The format changes only the
// bytes: the report, its verdict and the exit code are the same for all.
func Render(report Report, format string, options RenderOptions) ([]byte, error) {
	if options.OnlyBlocked && (format == "human" || format == "markdown") {
		return renderOnlyBlocked(report, format, options)
	}
	switch format {
	case "json":
		return MarshalJSON(report)
	case "sarif":
		return SARIF(report)
	case "markdown":
		return Markdown(report, MarkdownOptions{ShowPasses: options.ShowPasses, Verbose: options.Verbose}), nil
	}
	return Human(report, HumanOptions{ShowPasses: options.ShowPasses, Verbose: options.Verbose}), nil
}

// renderOnlyBlocked renders a copy of the report without the items that are
// not BLOCKED findings (gaps, notices, unsupported combinations, leads and
// passes) and ends with one line counting what was left out. The report, the
// headline, the verdict and the summary are unchanged.
func renderOnlyBlocked(report Report, format string, options RenderOptions) ([]byte, error) {
	gaps := len(report.Gaps)
	other := len(report.Notices) + len(report.Unsupported) + len(report.Leads)
	report.Gaps, report.Notices, report.Unsupported, report.Leads, report.Passes = nil, nil, nil, nil, nil
	var body []byte
	if format == "markdown" {
		body = Markdown(report, MarkdownOptions{Verbose: options.Verbose})
		body = append(body, '\n')
	} else {
		body = Human(report, HumanOptions{Verbose: options.Verbose})
	}
	return append(body, fmt.Sprintf(labelOnlyBlocked+"\n", gaps, other)...), nil
}
