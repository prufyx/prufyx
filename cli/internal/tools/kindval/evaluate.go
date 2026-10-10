// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Runs is everything the clusters recorded, keyed by line.
type Runs struct {
	Snapshots map[string]Snapshot
	Verdicts  map[string]VerdictRun
	CRD       []CRDRun
}

// gapNotServed is the scan gap that names a manifest API the target does
// not serve (scanreport.ReasonAPIVersionNotServed).
const gapNotServed = "API_VERSION_NOT_SERVED"

// Scan exit codes (scanreport.ExitPass, ExitBlocked, ExitUnknown).
const (
	exitPass    = 0
	exitBlocked = 10
	exitUnknown = 11
)

// Evaluate compares the claims with the runs.
func Evaluate(claims Claims, runs Runs, now time.Time) Results {
	res := Results{Schema: ResultsSchema, GeneratedAt: now.UTC().Format(time.RFC3339)}
	lines := make([]string, 0, len(runs.Snapshots))
	for line := range runs.Snapshots {
		lines = append(lines, line)
	}
	sortLines(lines)
	for _, line := range lines {
		s := runs.Snapshots[line]
		res.Lines = append(res.Lines, LineSummary{Line: line, ServerVersion: s.ServerVersion, Image: s.Image, Served: len(s.Served)})
	}
	evaluateAPIClaims(&res, claims.Kubernetes, runs.Snapshots)
	evaluateDiffs(&res, lines, runs.Snapshots)
	evaluateVerdicts(&res, runs.Verdicts)
	evaluateCRDs(&res, claims.CustomResources, runs.CRD)
	sort.SliceStable(res.Findings, func(i, j int) bool {
		if rank(res.Findings[i].Severity) != rank(res.Findings[j].Severity) {
			return rank(res.Findings[i].Severity) < rank(res.Findings[j].Severity)
		}
		return res.Findings[i].ID < res.Findings[j].ID
	})
	for _, c := range res.Claims {
		res.Totals.Claims++
		switch c.Status {
		case StatusConfirmed:
			res.Totals.Confirmed++
		case StatusRefuted:
			res.Totals.Refuted++
		default:
			res.Totals.Unevaluated++
		}
	}
	for _, v := range res.Verdicts {
		res.Totals.Verdicts++
		if v.Status == StatusConfirmed {
			res.Totals.VerdictsOK++
		} else if v.Status == StatusRefuted {
			res.Totals.VerdictsBad++
		}
	}
	for _, f := range res.Findings {
		switch f.Severity {
		case SeverityHigh:
			res.Totals.High++
		case SeverityMedium:
			res.Totals.Medium++
		default:
			res.Totals.Info++
		}
	}
	if res.Claims == nil {
		res.Claims = []ClaimResult{}
	}
	if res.Verdicts == nil {
		res.Verdicts = []VerdictResult{}
	}
	if res.Diffs == nil {
		res.Diffs = []LineDiff{}
	}
	if res.Findings == nil {
		res.Findings = []Finding{}
	}
	return res
}

func rank(severity string) int {
	switch severity {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	}
	return 2
}

func (r *Results) finding(severity, id, format string, args ...any) {
	r.Findings = append(r.Findings, Finding{Severity: severity, ID: id, Message: fmt.Sprintf(format, args...)})
}

func servedSet(s Snapshot) map[string]bool {
	out := make(map[string]bool, len(s.Served))
	for _, api := range s.Served {
		out[api] = true
	}
	return out
}

func evaluateAPIClaims(res *Results, claims []APIClaim, snapshots map[string]Snapshot) {
	sets := map[string]map[string]bool{}
	for _, c := range claims {
		cr := ClaimResult{ID: c.ID, Kind: "kubernetes-api", Line: c.Line, Subject: c.API, Expect: c.Expect, Status: StatusUnevaluated, Detail: c.Source}
		s, ok := snapshots[c.Line]
		if !ok {
			cr.Detail = "no snapshot of line " + c.Line
			res.Claims = append(res.Claims, cr)
			continue
		}
		if sets[c.Line] == nil {
			sets[c.Line] = servedSet(s)
		}
		cr.Observed = ExpectNotServed
		if sets[c.Line][c.API] {
			cr.Observed = ExpectServed
		}
		if cr.Observed == c.Expect {
			cr.Status = StatusConfirmed
		} else {
			// Either way the table is wrong about this line: it would block
			// a manifest the server accepts, or it names a previous line that
			// never served the version (or a kept version the line dropped).
			cr.Status = StatusRefuted
			res.finding(SeverityMedium, c.ID, "line %s (%s): knowledge says %s is %s, the API server says %s (%s)", c.Line, s.ServerVersion, c.API, c.Expect, cr.Observed, c.Source)
		}
		res.Claims = append(res.Claims, cr)
	}
}

func evaluateDiffs(res *Results, lines []string, snapshots map[string]Snapshot) {
	known := knownRemovals()
	for i := 1; i < len(lines); i++ {
		prev, next := lines[i-1], lines[i]
		if previousLine(next) != prev {
			continue
		}
		before, after := servedSet(snapshots[prev]), servedSet(snapshots[next])
		d := LineDiff{From: prev, To: next, Removed: []string{}, Added: []string{}, UnknownRemovals: []string{}}
		for api := range before {
			if !after[api] {
				d.Removed = append(d.Removed, api)
				if !known[next][api] {
					d.UnknownRemovals = append(d.UnknownRemovals, api)
				}
			}
		}
		for api := range after {
			if !before[api] {
				d.Added = append(d.Added, api)
			}
		}
		sort.Strings(d.Removed)
		sort.Strings(d.Added)
		sort.Strings(d.UnknownRemovals)
		for _, api := range d.UnknownRemovals {
			severity := SeverityMedium
			if strings.Contains(strings.Fields(api)[0], "alpha") {
				severity = SeverityInfo
			}
			res.finding(severity, "diff."+next+"."+caseID(api), "line %s no longer serves %s (served by %s); the removal table has no entry for it", next, api, prev)
		}
		res.Diffs = append(res.Diffs, d)
	}
}

func evaluateVerdicts(res *Results, verdicts map[string]VerdictRun) {
	lines := make([]string, 0, len(verdicts))
	for line := range verdicts {
		lines = append(lines, line)
	}
	sortLines(lines)
	for _, line := range lines {
		run, ok := verdicts[line]
		if !ok {
			continue
		}
		prevRun, ok := verdicts[previousLine(line)]
		if !ok {
			continue
		}
		prevCases := map[string]VerdictCase{}
		for _, c := range prevRun.Cases {
			prevCases[c.ID] = c
		}
		for _, c := range run.Cases {
			if c.Scan == nil {
				continue
			}
			pc, ok := prevCases[c.ID]
			if !ok {
				continue
			}
			vr := VerdictResult{ID: c.ID + "." + run.Line, API: c.API, From: c.Scan.From, To: c.Scan.To, ServerFrom: pc.Server.Outcome, ServerTo: c.Server.Outcome, ScanExit: c.Scan.Exit, ScanGaps: c.Scan.Gaps}
			if vr.ScanGaps == nil {
				vr.ScanGaps = []string{}
			}
			if c.Scan.Error != "" {
				vr.Status = StatusUnevaluated
				vr.Detail = c.Scan.Error
				res.finding(SeverityInfo, "verdict."+vr.ID, "%s -> %s, %s: the scan gave no report: %s", vr.From, vr.To, c.API, c.Scan.Error)
				res.Verdicts = append(res.Verdicts, vr)
				continue
			}
			hasGap := false
			for _, g := range c.Scan.Gaps {
				hasGap = hasGap || g == gapNotServed
			}
			switch {
			case vr.ServerTo == OutcomeNotServed && vr.ServerFrom != OutcomeNotServed:
				vr.Expected = "BLOCKED (exit 10) with " + gapNotServed
				switch {
				case c.Scan.Exit == exitBlocked && hasGap:
					vr.Status = StatusConfirmed
				case c.Scan.Exit == exitPass:
					vr.Status = StatusRefuted
					res.finding(SeverityHigh, "verdict."+vr.ID, "%s -> %s: the scan PASSES %s, which %s serves and %s rejects", vr.From, vr.To, c.API, vr.From, vr.To)
				case c.Scan.Exit == exitBlocked:
					vr.Status = StatusConfirmed
					vr.Detail = "blocked without the " + gapNotServed + " gap"
				case c.Scan.Exit == exitUnknown && hasGap:
					// The report names the API as not served by the target (the
					// gap the GitHub Action fails on), but no published rule
					// decides the hop, so the verdict stays UNKNOWN.
					vr.Status = StatusConfirmed
					vr.Detail = "UNKNOWN with the " + gapNotServed + " gap: no published rule decides the hop"
					res.finding(SeverityInfo, "verdict."+vr.ID, "%s -> %s: the scan names %s as not served by %s but answers UNKNOWN (exit 11), not BLOCKED: no published removal rule for the %s line", vr.From, vr.To, c.API, vr.To, lineOf(vr.To))
				default:
					vr.Status = StatusRefuted
					res.finding(SeverityMedium, "verdict."+vr.ID, "%s -> %s: the scan answers %s (exit %d) for %s, which %s serves and %s rejects; a removal rule is missing", vr.From, vr.To, c.Scan.Verdict, c.Scan.Exit, c.API, vr.From, vr.To)
				}
			case vr.ServerTo == OutcomeNotServed:
				vr.Expected = "not PASS (removed before " + vr.From + ")"
				if c.Scan.Exit == exitPass {
					vr.Status = StatusRefuted
					res.finding(SeverityHigh, "verdict."+vr.ID, "%s -> %s: the scan PASSES %s, which neither line serves", vr.From, vr.To, c.API)
				} else {
					vr.Status = StatusConfirmed
				}
			default:
				vr.Expected = "not BLOCKED"
				if c.Scan.Exit == exitBlocked {
					vr.Status = StatusRefuted
					res.finding(SeverityMedium, "verdict."+vr.ID, "%s -> %s: the scan BLOCKS %s, which %s still serves (%s)", vr.From, vr.To, c.API, vr.To, c.Server.Outcome)
				} else {
					vr.Status = StatusConfirmed
				}
			}
			res.Verdicts = append(res.Verdicts, vr)
		}
	}
}

func evaluateCRDs(res *Results, pairs []CRDPair, runs []CRDRun) {
	results := map[string]CRDPairResult{}
	lineOfPair := map[string]string{}
	for _, run := range runs {
		for _, p := range run.Pairs {
			results[p.ID] = p
			lineOfPair[p.ID] = run.Line
		}
	}
	for _, pair := range pairs {
		removed := removedMembers(pair)
		pr, ok := results[pair.ID]
		if !ok || pr.Error != "" {
			detail := "no run of the pair"
			if ok {
				detail = pr.Error
			}
			for _, m := range removed {
				res.Claims = append(res.Claims, ClaimResult{ID: pair.ID + "." + m, Kind: "custom-resource", Subject: m, Expect: "removed", Status: StatusUnevaluated, Detail: detail})
			}
			if len(removed) == 0 {
				res.Claims = append(res.Claims, ClaimResult{ID: pair.ID + ".quiet", Kind: "custom-resource", Subject: pair.Project + " " + pair.From.Tag + " -> " + pair.To.Tag, Expect: "no removal", Status: StatusUnevaluated, Detail: detail})
			}
			res.finding(SeverityInfo, "crd."+pair.ID, "pair %s was not evaluated: %s", pair.ID, detail)
			continue
		}
		line := lineOfPair[pair.ID]
		evaluateRelease(res, pair, "from", pair.From, pr.From, line)
		evaluateRelease(res, pair, "to", pair.To, pr.To, line)
		toProbe := map[string]string{}
		for _, o := range pr.To.Objects {
			toProbe[o.Member] = o.Outcome
		}
		fromProbe := map[string]string{}
		for _, o := range pr.From.Objects {
			fromProbe[o.Member] = o.Outcome
		}
		for _, m := range removed {
			cr := ClaimResult{ID: pair.ID + "." + m, Kind: "custom-resource", Line: line, Subject: m, Expect: "removed", Detail: pair.From.Tag + " -> " + pair.To.Tag}
			before, after := fromProbe[m], toProbe[m]
			switch {
			case before == "" || after == "":
				cr.Status = StatusUnevaluated
				cr.Detail = "the member was not probed on both releases"
			case before == OutcomeNotServed:
				cr.Status, cr.Observed = StatusRefuted, "not served at "+pair.From.Tag
				res.finding(SeverityMedium, cr.ID, "%s %s does not serve %s, which the knowledge says it served", pair.Project, pair.From.Tag, m)
			case after != OutcomeNotServed:
				cr.Status, cr.Observed = StatusRefuted, "served at "+pair.To.Tag+" ("+after+")"
				res.finding(SeverityHigh, cr.ID, "%s %s still serves %s, which the knowledge says it removed", pair.Project, pair.To.Tag, m)
			default:
				cr.Status, cr.Observed = StatusConfirmed, "served at "+pair.From.Tag+" ("+before+"), not served at "+pair.To.Tag
			}
			res.Claims = append(res.Claims, cr)
		}
		// Every version served at From that the knowledge keeps at To must
		// still be served there: a missed removal otherwise.
		kept := 0
		removedSet := map[string]bool{}
		for _, m := range removed {
			removedSet[m] = true
		}
		var missed []string
		for _, crd := range pair.From.CRDs {
			for _, v := range crd.Versions {
				m := crd.Group + "/" + v.Name + "/" + crd.Kind
				if !v.Served || removedSet[m] {
					continue
				}
				kept++
				if toProbe[m] == OutcomeNotServed {
					missed = append(missed, m)
				}
			}
		}
		if len(removed) == 0 || kept > 0 {
			cr := ClaimResult{ID: pair.ID + ".kept", Kind: "custom-resource", Line: line, Subject: pair.Project + " " + pair.From.Tag + " -> " + pair.To.Tag, Expect: fmt.Sprintf("%d version(s) still served", kept), Status: StatusConfirmed}
			if len(missed) > 0 {
				cr.Status = StatusRefuted
				cr.Observed = "not served at " + pair.To.Tag + ": " + strings.Join(missed, ", ")
				res.finding(SeverityHigh, cr.ID, "%s %s no longer serves %s, which the knowledge does not record as removed", pair.Project, pair.To.Tag, strings.Join(missed, ", "))
			}
			res.Claims = append(res.Claims, cr)
		}
		if pr.InPlace.Attempted && !pr.InPlace.Succeeded {
			res.finding(SeverityInfo, "crd."+pair.ID+".in-place", "%s: applying the %s definitions over %s was refused by the API server: %s", pair.Project, pair.To.Tag, pair.From.Tag, pr.InPlace.Message)
		}
	}
}

// evaluateRelease compares the definitions the knowledge expects of one
// release with what the cluster holds after installing it.
func evaluateRelease(res *Results, pair CRDPair, side string, expected CRDRelease, got CRDReleaseState, line string) {
	have := map[string]CRDDef{}
	for _, d := range got.CRDs {
		have[d.Name] = d
	}
	for _, exp := range expected.CRDs {
		id := pair.ID + "." + side + "." + exp.Name
		cr := ClaimResult{ID: id, Kind: "custom-resource-definition", Line: line, Subject: exp.Name + "@" + expected.Tag, Expect: describeVersions(exp.Versions), Status: StatusUnevaluated}
		if got.Error != "" {
			cr.Detail = got.Error
			res.Claims = append(res.Claims, cr)
			continue
		}
		actual, ok := have[exp.Name]
		if !ok {
			cr.Status, cr.Observed = StatusRefuted, "absent"
			res.finding(SeverityMedium, id, "%s %s: the cluster holds no %s after installing the manifests", pair.Project, expected.Tag, exp.Name)
			res.Claims = append(res.Claims, cr)
			continue
		}
		cr.Observed = describeVersions(actual.Versions)
		if cr.Observed == cr.Expect {
			cr.Status = StatusConfirmed
		} else {
			cr.Status = StatusRefuted
			res.finding(SeverityMedium, id, "%s %s: %s declares %s in the knowledge, the cluster holds %s", pair.Project, expected.Tag, exp.Name, cr.Expect, cr.Observed)
		}
		res.Claims = append(res.Claims, cr)
	}
	for name := range have {
		known := false
		for _, exp := range expected.CRDs {
			known = known || exp.Name == name
		}
		if !known {
			res.finding(SeverityInfo, pair.ID+"."+side+"."+name, "%s %s: the manifests define %s, which the knowledge does not list", pair.Project, expected.Tag, name)
		}
	}
}

// describeVersions renders versions as "v1beta1(served,storage) v1(served)".
func describeVersions(versions []CRDVersion) string {
	sorted := append([]CRDVersion(nil), versions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	parts := make([]string, 0, len(sorted))
	for _, v := range sorted {
		flags := []string{}
		if v.Served {
			flags = append(flags, "served")
		}
		if v.Storage {
			flags = append(flags, "storage")
		}
		parts = append(parts, v.Name+"("+strings.Join(flags, ",")+")")
	}
	return strings.Join(parts, " ")
}

// Summary renders the human summary of the results.
func Summary(res Results) string {
	var b strings.Builder
	b.WriteString("# KIND-VAL results\n\n")
	fmt.Fprintf(&b, "Generated %s.\n\n", res.GeneratedAt)
	b.WriteString("| Line | Server | Served APIs | API claims | Verdict checks | CRD claims |\n|---|---|---|---|---|---|\n")
	for _, l := range res.Lines {
		var ok, bad, vok, vbad, cok, cbad int
		for _, c := range res.Claims {
			if c.Line != l.Line {
				continue
			}
			if c.Kind == "kubernetes-api" {
				count(&ok, &bad, c.Status)
			} else {
				count(&cok, &cbad, c.Status)
			}
		}
		for _, v := range res.Verdicts {
			if lineOf(v.To) == l.Line {
				count(&vok, &vbad, v.Status)
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %s | %s |\n", l.Line, l.ServerVersion, l.Served, cell(ok, bad), cell(vok, vbad), cell(cok, cbad))
	}
	t := res.Totals
	fmt.Fprintf(&b, "\nClaims: %d confirmed, %d refuted, %d unevaluated. Verdict checks: %d agree, %d disagree. Findings: %d HIGH, %d MEDIUM, %d INFO.\n", t.Confirmed, t.Refuted, t.Unevaluated, t.VerdictsOK, t.VerdictsBad, t.High, t.Medium, t.Info)
	if len(res.Diffs) > 0 {
		b.WriteString("\n## Served-API changes between consecutive lines\n\n")
		for _, d := range res.Diffs {
			fmt.Fprintf(&b, "- %s -> %s: %d removed, %d added, %d removed without a table entry\n", d.From, d.To, len(d.Removed), len(d.Added), len(d.UnknownRemovals))
			for _, api := range d.Removed {
				fmt.Fprintf(&b, "  - removed: %s\n", api)
			}
		}
	}
	if len(res.Findings) > 0 {
		b.WriteString("\n## Findings\n\n")
		for _, f := range res.Findings {
			fmt.Fprintf(&b, "- %s %s: %s\n", f.Severity, f.ID, f.Message)
		}
	}
	return b.String()
}

func count(ok, bad *int, status string) {
	switch status {
	case StatusConfirmed:
		*ok++
	case StatusRefuted:
		*bad++
	}
}

func cell(ok, bad int) string {
	if ok+bad == 0 {
		return "-"
	}
	return fmt.Sprintf("%d ok / %d bad", ok, bad)
}
