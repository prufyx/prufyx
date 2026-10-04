// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// MarkdownOptions selects the optional Markdown sections, like the human
// renderer's.
type MarkdownOptions struct {
	ShowPasses bool
	Verbose    bool
}

// Markdown renders the report as GitHub-flavoured Markdown for a pull
// request comment or a change ticket: the headline, the problems per path,
// what was not checked, one-way changes, unsupported combinations and
// unverified leads, the summary, a table of the cited sources and the
// provenance needed to replay the scan. The text of the report is escaped,
// and file paths and object names sit in code spans. The same report always
// renders to the same bytes.
func Markdown(report Report, options MarkdownOptions) []byte {
	var out bytes.Buffer
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }
	line("# %s", mdText(report.Headline))
	var quotes []string
	if policy := report.TrustPolicy; policy != nil {
		if policy.ExcludedRules > 0 {
			quotes = append(quotes, fmt.Sprintf(labelTrustExcluded, strings.Join(policy.RequiredBasis, ", "), policy.ExcludedRules))
		}
		if policy.ExcludedLeadRules > 0 {
			quotes = append(quotes, fmt.Sprintf(labelTrustLeads, policy.ExcludedLeadRules))
		}
	}
	consensus := 0
	for _, finding := range report.Findings {
		if finding.Basis == "consensus" {
			consensus++
		}
	}
	if consensus > 0 {
		quotes = append(quotes, fmt.Sprintf(labelConsensus, consensus))
	}
	if len(quotes) > 0 {
		line("")
		for index, quote := range quotes {
			if index > 0 {
				line(">")
			}
			line("> %s", mdText(quote))
		}
	}

	if len(report.Findings) > 0 {
		line("")
		line("## "+labelMDProblems, len(report.Findings))
		for _, path := range report.Paths {
			findings := findingsOf(report.Findings, path.Component)
			if len(findings) == 0 {
				continue
			}
			line("")
			line("### %s", mdText(fmt.Sprintf(labelPath, path.Component, path.From, path.To, pathSummary(path))))
			writeFindingTable(&out, findings)
		}
		var rest []Finding
		for _, finding := range report.Findings {
			if !hasPath(report.Paths, finding.Component) {
				rest = append(rest, finding)
			}
		}
		if len(rest) > 0 {
			line("")
			writeFindingTable(&out, rest)
		}
	}

	if options.Verbose && len(report.Paths) > 0 {
		line("")
		line("## " + labelMDHops)
		for _, path := range report.Paths {
			line("")
			line("### %s", mdText(fmt.Sprintf(labelPath, path.Component, path.From, path.To, pathSummary(path))))
			if len(path.Hops) == 0 {
				continue
			}
			line("")
			line("| %s | %s |", labelMDHopHeader, labelMDStatusHeader)
			line("| --- | --- |")
			for _, hop := range path.Hops {
				status := hop.Status
				if len(hop.Reasons) > 0 {
					status += " (" + strings.Join(hop.Reasons, ", ") + ")"
				}
				line("| %s | %s |", mdText(hop.From.String()+" -> "+hop.To.String()), mdText(status))
			}
		}
	}

	if len(report.Gaps) > 0 {
		line("")
		line("## "+labelNotChecked, len(report.Gaps))
		line("")
		line("| %s | %s | %s |", labelMDAreaHeader, labelMDDetailHeader, labelMDActionHeader)
		line("| --- | --- | --- |")
		for _, gap := range report.Gaps {
			line("| %s | %s | %s |", mdText(gapScope(gap)), mdText(gap.Detail), mdText(gap.Action))
		}
	}
	if len(report.Notices) > 0 {
		line("")
		line("## "+labelNotices, len(report.Notices))
		line("")
		line("| %s | %s | %s |", labelMDAreaHeader, labelMDRuleHeader, labelMDDetailHeader)
		line("| --- | --- | --- |")
		for _, notice := range report.Notices {
			text := fmt.Sprintf(labelNoticeMessage, notice.Text)
			if !notice.Established {
				text = fmt.Sprintf(labelNoticeNotEstab, notice.Reason, notice.Text)
			}
			line("| %s | %s | %s |", mdText(notice.Component+" "+hopLabel(notice.Hop)), mdCode(notice.RuleID), mdText(text))
		}
	}
	if len(report.Unsupported) > 0 {
		line("")
		line("## "+labelUnsupported, len(report.Unsupported))
		line("")
		line("| %s | %s | %s |", labelMDAreaHeader, labelMDRuleHeader, labelMDDetailHeader)
		line("| --- | --- | --- |")
		for _, entry := range report.Unsupported {
			line("| %s | %s | %s |", mdText(entry.Component+" "+hopLabel(entry.Hop)), mdCode(entry.RuleID), mdText(fmt.Sprintf(labelUnsupportedMsg, entry.Reason, entry.Fix)))
		}
	}
	if len(report.Leads) > 0 {
		line("")
		line("## "+labelLeads, len(report.Leads))
		line("")
		line("| %s | %s | %s |", labelMDAreaHeader, labelMDRuleHeader, labelMDDetailHeader)
		line("| --- | --- | --- |")
		for _, lead := range report.Leads {
			line("| %s | %s | %s |", mdText(lead.Component+" "+hopLabel(lead.Hop)), mdCode(lead.RuleID), mdText(fmt.Sprintf(labelLeadMessage, lead.Text)))
		}
	}
	if options.ShowPasses && len(report.Passes) > 0 {
		line("")
		line("## "+labelPassed, len(report.Passes))
		line("")
		for _, pass := range report.Passes {
			line("- %s %s", mdText(pass.Component+" "+hopLabel(pass.Hop)), mdCode(pass.RuleID))
		}
	}

	if sources := markdownSources(report); len(sources) > 0 {
		line("")
		line("## " + labelMDSources)
		line("")
		line("| %s | %s | %s | %s |", labelMDRulesHeader, labelMDSourceHeader, labelMDLinesHeader, labelMDRevisionHeader)
		line("| --- | --- | --- | --- |")
		for _, source := range sources {
			codes := make([]string, len(source.rules))
			for i, rule := range source.rules {
				codes[i] = mdCode(rule)
			}
			line("| %s | <%s> | %d-%d | %s |", strings.Join(codes, "<br>"), mdURL(source.evidence.URL), source.evidence.StartLine, source.evidence.EndLine, mdCode(shortRevision(source.evidence.Revision)))
		}
	}

	line("")
	checked := fmt.Sprintf(labelChecked, count(report.Summary.Hops, labelHopOne, labelHops), count(report.Summary.DocumentsRead, labelDocumentOne, labelDocuments), count(report.Summary.ComponentsDetected, labelComponentOne, labelComponents), report.Summary.ComponentsCovered)
	switch {
	case report.Summary.Passes == 1:
		checked += labelPassCountOne
	case report.Summary.Passes > 1:
		checked += fmt.Sprintf(labelPassCount, report.Summary.Passes)
	}
	line("%s", mdText(checked))
	if len(report.Omissions) > 0 {
		line("")
		line("%s", mdText(fmt.Sprintf(labelNotEvaluated, strings.Join(report.Omissions, "; "))))
	}
	for _, note := range report.Notes {
		line("")
		line("%s", mdText(note))
	}
	line("")
	line("%s", mdText(labelEvidence))

	p := report.Provenance
	network := labelMDNoNetwork
	if p.NetworkUsed {
		network = labelMDNetwork
	}
	provenance := []string{
		fmt.Sprintf(labelMDEvaluatedAt, p.EvaluatedAt),
		fmt.Sprintf(labelMDInput, p.InputDigest),
	}
	if p.ConfigDigest != "" {
		provenance = append(provenance, fmt.Sprintf(labelMDConfig, p.ConfigDigest))
	}
	provenance = append(provenance,
		fmt.Sprintf(labelMDKnowledge, p.KnowledgeOrigin, p.KnowledgeRevision, p.KnowledgeDigest),
		fmt.Sprintf(labelMDEngine, p.EngineContractDigest),
		fmt.Sprintf(labelMDBuild, p.Build.Version),
		network,
	)
	body := strings.Join(provenance, "\n")
	fence := strings.Repeat("`", max(3, longestRun(body, '`')+1))
	line("")
	line("<details>")
	line("<summary>%s</summary>", labelMDDetails)
	line("")
	line("%s", fence)
	line("%s", body)
	line("%s", fence)
	line("")
	line("</details>")
	return out.Bytes()
}

func findingsOf(findings []Finding, component string) []Finding {
	var out []Finding
	for _, finding := range findings {
		if finding.Component == component {
			out = append(out, finding)
		}
	}
	return out
}

func writeFindingTable(out *bytes.Buffer, findings []Finding) {
	fmt.Fprintf(out, "\n| %s | %s | %s | %s |\n| --- | --- | --- | --- |\n", labelMDHopHeader, labelMDProblemHeader, labelMDWhereHeader, labelMDFixHeader)
	for _, finding := range findings {
		var where []string
		for index, location := range finding.Locations {
			if index == maxLocations {
				where = append(where, mdText(fmt.Sprintf(labelMDMore, len(finding.Locations)-maxLocations)))
				break
			}
			where = append(where, markdownLocation(location))
		}
		fmt.Fprintf(out, "| %s | %s | %s | %s |\n", mdText(hopLabel(finding.Hop)), mdText(finding.Title), strings.Join(where, "<br>"), mdText(finding.Fix))
	}
}

// markdownLocation is "file:line" or "file#document[/item]" in a code span,
// then the kind and the namespace/name in a second code span. Digests print
// as a short prefix.
func markdownLocation(location Location) string {
	place := short(location.File) + "#" + strconv.Itoa(location.Document)
	if location.Item >= 0 {
		place += "/" + strconv.Itoa(location.Item)
	}
	if location.Line > 0 {
		place = short(location.File) + ":" + strconv.Itoa(location.Line)
	}
	name := short(location.Name)
	if name == "" {
		name = labelNoName
	}
	if location.Namespace != "" {
		name = short(location.Namespace) + "/" + name
	}
	return mdCode(place) + " " + mdCode(location.Kind+" "+name)
}

type markdownSource struct {
	evidence constraintengine.SourceEvidence
	rules    []string
}

// markdownSources lists every cited source once, in order of first
// appearance, with the rules that cite it.
func markdownSources(report Report) []markdownSource {
	var out []markdownSource
	position := map[string]int{}
	add := func(ruleID string, citations []constraintengine.SourceEvidence) {
		for _, source := range citations {
			key := citationKey(source)
			at, seen := position[key]
			if !seen {
				position[key] = len(out)
				out = append(out, markdownSource{evidence: source, rules: []string{ruleID}})
				continue
			}
			if !contains(out[at].rules, ruleID) {
				out[at].rules = append(out[at].rules, ruleID)
			}
		}
	}
	for _, f := range report.Findings {
		add(f.RuleID, f.Citations)
	}
	for _, u := range report.Unsupported {
		add(u.RuleID, u.Citations)
	}
	for _, n := range report.Notices {
		add(n.RuleID, n.Citations)
	}
	for _, l := range report.Leads {
		add(l.RuleID, l.Citations)
	}
	return out
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func shortRevision(revision string) string {
	if len(revision) > 12 {
		return revision[:12]
	}
	return revision
}

// mdText escapes text for Markdown, in a paragraph or a table cell: control
// characters and line breaks become spaces; backslash, backtick, emphasis,
// link and HTML characters, the table pipe, "&" and "@" (which would
// mention a user) are escaped; a leading "#", "-", "+", "=", ">" or list
// number is escaped so the text cannot start a heading, list or quote.
func mdText(text string) string {
	var out strings.Builder
	text = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text))
	for index, r := range text {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '<', '|', '~', '&':
			out.WriteByte('\\')
			out.WriteRune(r)
		case '@':
			out.WriteString("&#64;")
		case '#', '-', '+', '=', '>':
			if index == 0 {
				out.WriteByte('\\')
			}
			out.WriteRune(r)
		case '.', ')':
			if index > 0 && isDigits(text[:index]) && (index+1 == len(text) || text[index+1] == ' ') {
				out.WriteByte('\\')
			}
			out.WriteRune(r)
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

func isDigits(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// mdCode puts text in a code span that the text cannot close, with the
// table pipe escaped.
func mdCode(text string) string {
	text = strings.ReplaceAll(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text), "|", "\\|")
	if text == "" {
		return "` `"
	}
	fence := strings.Repeat("`", longestRun(text, '`')+1)
	pad := ""
	if strings.HasPrefix(text, "`") || strings.HasSuffix(text, "`") || strings.HasPrefix(text, " ") && strings.HasSuffix(text, " ") {
		pad = " "
	}
	return fence + pad + text + pad + fence
}

func longestRun(text string, r rune) int {
	best, run := 0, 0
	for _, c := range text {
		if c == r {
			run++
			best = max(best, run)
		} else {
			run = 0
		}
	}
	return best
}

// mdURL percent-encodes the characters that would end an autolink or a
// table cell.
func mdURL(url string) string {
	return strings.NewReplacer("|", "%7C", "<", "%3C", ">", "%3E", " ", "%20", "\n", "%0A", "\r", "%0D").Replace(url)
}
