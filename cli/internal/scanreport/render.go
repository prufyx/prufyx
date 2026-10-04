// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// HumanOptions selects the optional human sections.
type HumanOptions struct {
	ShowPasses bool
	Verbose    bool
}

// maxLocations is how many locations a finding prints before collapsing.
const maxLocations = 5

// MarshalJSON renders the report as one line of JSON and a newline.
func MarshalJSON(report Report) ([]byte, error) {
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// DecodeJSON reads a report strictly: unknown members and trailing data are
// errors.
func DecodeJSON(raw []byte) (Report, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, err
	}
	if decoder.More() {
		return Report{}, fmt.Errorf("trailing data after the report")
	}
	return report, nil
}

// Human renders the report for a terminal. The headline comes first. No
// colour is used.
func Human(report Report, options HumanOptions) []byte {
	var out bytes.Buffer
	line := func(format string, args ...any) { fmt.Fprintf(&out, format+"\n", args...) }
	line("%s", report.Headline)
	if policy := report.TrustPolicy; policy != nil {
		if policy.ExcludedRules > 0 {
			line(labelTrustExcluded, strings.Join(policy.RequiredBasis, ", "), policy.ExcludedRules)
		}
		if policy.ExcludedLeadRules > 0 {
			line(labelTrustLeads, policy.ExcludedLeadRules)
		}
	}
	consensus := 0
	for _, finding := range report.Findings {
		if finding.Basis == "consensus" {
			consensus++
		}
	}
	if consensus > 0 {
		line(labelConsensus, consensus)
	}

	for _, path := range report.Paths {
		line("")
		line(labelPath, path.Component, path.From, path.To, pathSummary(path))
		if options.Verbose {
			for _, hop := range path.Hops {
				status := hop.Status
				if len(hop.Reasons) > 0 {
					status += " (" + strings.Join(hop.Reasons, ", ") + ")"
				}
				line(labelHopStatus, hop.Index, hop.From.String(), hop.To.String(), status)
			}
		}
		for _, finding := range report.Findings {
			if finding.Component == path.Component {
				writeFinding(&out, finding, options, sharedCitations(report.Findings))
			}
		}
	}
	for _, finding := range report.Findings {
		if !hasPath(report.Paths, finding.Component) {
			writeFinding(&out, finding, options, sharedCitations(report.Findings))
		}
	}

	if len(report.Gaps) > 0 {
		line("")
		line(labelNotChecked, len(report.Gaps))
		for _, gap := range report.Gaps {
			line("  %s   %s - %s", gapScope(gap), gap.Detail, gap.Action)
		}
	}
	if len(report.Notices) > 0 {
		line("")
		line(labelNotices, len(report.Notices))
		for _, notice := range report.Notices {
			if notice.Established {
				line("  %s %s   "+labelNoticeRule, notice.Component, hopLabel(notice.Hop), notice.RuleID)
				line("    "+labelNoticeBefore, notice.Text)
			} else {
				line("  %s %s   "+labelNoticeUnresolved, notice.Component, hopLabel(notice.Hop), notice.RuleID, notice.Reason)
				line("    "+labelNoticeNext, notice.Text)
			}
		}
	}
	if len(report.Unsupported) > 0 {
		line("")
		line(labelUnsupported, len(report.Unsupported))
		for _, entry := range report.Unsupported {
			line("  %s %s   "+labelUnsupportedRule, entry.Component, hopLabel(entry.Hop), entry.RuleID, entry.Reason)
			line("    "+labelFix, entry.Fix)
		}
	}
	if len(report.Leads) > 0 {
		line("")
		line(labelLeads, len(report.Leads))
		for _, lead := range report.Leads {
			line("  %s %s   "+labelLeadRule, lead.Component, hopLabel(lead.Hop), lead.RuleID)
			line("    "+labelLeadCheck, lead.Text)
		}
	}
	if options.ShowPasses && len(report.Passes) > 0 {
		line("")
		line(labelPassed, len(report.Passes))
		for _, pass := range report.Passes {
			line("  %s %s   %s", pass.Component, hopLabel(pass.Hop), pass.RuleID)
		}
	}
	if options.Verbose {
		if shared := sharedCitationList(report.Findings); len(shared) > 0 {
			line("")
			line(labelSharedSources)
			for _, source := range shared {
				line("  "+labelSource, source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest)
			}
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
	line("%s", checked)
	if len(report.Omissions) > 0 {
		line(labelNotEvaluated, strings.Join(report.Omissions, "; "))
	}
	for _, note := range report.Notes {
		line("%s", note)
	}
	line("%s", labelEvidence)
	p := report.Provenance
	line(labelProvenance, p.EvaluatedAt, p.InputDigest, p.KnowledgeOrigin, p.KnowledgeRevision, p.KnowledgeDigest)
	if store := p.KnowledgeStore; store != nil {
		line(labelKnowledgeStore, store.Path, store.Layout, store.TargetPath, store.TrustReceiptDigest)
		for _, project := range store.Projects {
			if project.Status != "present" {
				line(labelKnowledgeProjectAbsent, project.Project)
				continue
			}
			line(labelKnowledgeProject, project.Project, project.TargetPath, project.Revision, project.Digest)
		}
	}
	return out.Bytes()
}

func count(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return fmt.Sprintf(many, n)
}

func pathSummary(path Path) string {
	if path.Gap != "" {
		return fmt.Sprintf(labelNoPath, path.Gap)
	}
	hops := count(len(path.Hops), labelHopOne, labelHops)
	if path.Policy == "" {
		return fmt.Sprintf(labelNoPolicy, hops)
	}
	return fmt.Sprintf(labelPolicy, hops, path.Policy)
}

func hasPath(paths []Path, component string) bool {
	for _, path := range paths {
		if path.Component == component {
			return true
		}
	}
	return false
}

func hopLabel(hop HopRef) string {
	if hop.WholeUpgrade {
		return labelWholeUpgrade + " " + hop.From + " -> " + hop.To
	}
	return hop.From + " -> " + hop.To
}

func gapScope(gap Gap) string {
	if gap.Hop == nil {
		return gap.Component
	}
	return gap.Component + " " + hopLabel(*gap.Hop)
}

func writeFinding(out *bytes.Buffer, finding Finding, options HumanOptions, shared map[string]bool) {
	label := "  " + hopLabel(finding.Hop)
	indent := strings.Repeat(" ", len(label)+3)
	fmt.Fprintf(out, "%s   %s\n", label, finding.Title)
	for index, location := range finding.Locations {
		if index == maxLocations {
			fmt.Fprintf(out, "%s"+labelMore+"\n", indent, len(finding.Locations)-maxLocations)
			break
		}
		fmt.Fprintf(out, "%s%s\n", indent, locationText(location))
	}
	fmt.Fprintf(out, "%s"+labelFix+"\n", indent, finding.Fix)
	if !options.Verbose {
		return
	}
	if finding.Basis == "mechanical" {
		fmt.Fprintf(out, "%s"+labelEvidenceMech+"\n", indent, finding.Extractor)
	} else {
		fmt.Fprintf(out, "%s%s\n", indent, labelEvidenceReviewed)
	}
	for _, source := range finding.Citations {
		if !shared[citationKey(source)] {
			fmt.Fprintf(out, "%s"+labelSource+"\n", indent, source.URL, source.StartLine, source.EndLine, source.Revision, source.ContentDigest)
		}
	}
}

func citationKey(source constraintengine.SourceEvidence) string {
	return source.URL + "\x00" + strconv.Itoa(source.StartLine) + "\x00" + strconv.Itoa(source.EndLine) + "\x00" + source.ContentDigest
}

// sharedCitations marks citations that more than one finding carries; they
// print once, in a footer.
func sharedCitations(findings []Finding) map[string]bool {
	seen, shared := map[string]int{}, map[string]bool{}
	for _, finding := range findings {
		inFinding := map[string]bool{}
		for _, source := range finding.Citations {
			key := citationKey(source)
			if !inFinding[key] {
				inFinding[key] = true
				seen[key]++
			}
		}
	}
	for key, n := range seen {
		if n > 1 {
			shared[key] = true
		}
	}
	return shared
}

func sharedCitationList(findings []Finding) []constraintengine.SourceEvidence {
	shared := sharedCitations(findings)
	printed := map[string]bool{}
	var out []constraintengine.SourceEvidence
	for _, finding := range findings {
		for _, source := range finding.Citations {
			key := citationKey(source)
			if shared[key] && !printed[key] {
				printed[key] = true
				out = append(out, source)
			}
		}
	}
	return out
}

// locationText is "file:line" when the line is known, else "file#document"
// with "/item" for a List item, then the kind and namespace/name. Digests
// print as a short prefix.
func locationText(location Location) string {
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
	return place + "  " + location.Kind + " " + name
}

const digestPrefix = "sha256:"

// short prints a redacted digest as its first twelve hex characters.
func short(value string) string {
	if strings.HasPrefix(value, digestPrefix) && len(value) == len(digestPrefix)+64 {
		return value[:len(digestPrefix)+12]
	}
	return value
}

// RedactValue is the digest that replaces a path, name or namespace.
func RedactValue(value string) string {
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return digestPrefix + hex.EncodeToString(sum[:])
}

// Redact replaces every file path, object name and namespace in the report,
// and the knowledge database path, with its digest. Gaps, notes and
// omissions never carry them.
func Redact(report *Report) {
	for f := range report.Findings {
		for l := range report.Findings[f].Locations {
			location := &report.Findings[f].Locations[l]
			location.File, location.Namespace, location.Name = RedactValue(location.File), RedactValue(location.Namespace), RedactValue(location.Name)
		}
	}
	for o := range report.Omitted {
		report.Omitted[o].File = RedactValue(report.Omitted[o].File)
	}
	if store := report.Provenance.KnowledgeStore; store != nil {
		redacted := *store
		redacted.Path = RedactValue(store.Path)
		report.Provenance.KnowledgeStore = &redacted
	}
}
