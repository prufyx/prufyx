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

// Provenance is what every claim result carries about the run.
type Provenance struct {
	Prufyx    Binary
	LogDigest string
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

// evaluator carries the runs and the results being built.
type evaluator struct {
	runs Runs
	prov Provenance
	res  *Results
	sets map[string]map[string]bool
	// cases by line then case id
	cases map[string]map[string]VerdictCase
	// pair results by pair id, and the crd run line and image of each
	pairs     map[string]CRDPairResult
	pairImage map[string]string
}

// Evaluate compares the claims with the runs.
func Evaluate(claims Claims, runs Runs, prov Provenance, now time.Time) Results {
	res := &Results{Schema: ResultsSchema, GeneratedAt: now.UTC().Format(time.RFC3339), Prufyx: prov.Prufyx, LogDigest: prov.LogDigest, Lines: []LineSummary{}, Claims: []ClaimResult{}, Diffs: []LineDiff{}, Findings: []Finding{}}
	ev := evaluator{runs: runs, prov: prov, res: res, sets: map[string]map[string]bool{}, cases: map[string]map[string]VerdictCase{}, pairs: map[string]CRDPairResult{}, pairImage: map[string]string{}}
	lines := make([]string, 0, len(runs.Snapshots))
	for line, s := range runs.Snapshots {
		lines = append(lines, line)
		ev.sets[line] = servedSet(s)
	}
	sortLines(lines)
	for _, line := range lines {
		s := runs.Snapshots[line]
		res.Lines = append(res.Lines, LineSummary{Line: line, ServerVersion: s.ServerVersion, Image: s.Image, Served: len(s.Served)})
	}
	for line, run := range runs.Verdicts {
		ev.cases[line] = map[string]VerdictCase{}
		for _, c := range run.Cases {
			ev.cases[line][c.ID] = c
		}
	}
	for _, run := range runs.CRD {
		for _, p := range run.Pairs {
			ev.pairs[p.ID] = p
			ev.pairImage[p.ID] = run.Image
		}
	}
	for _, c := range claims.Claims {
		res.Claims = append(res.Claims, ev.claim(c))
	}
	ev.diffs(lines, claims)
	sort.SliceStable(res.Findings, func(i, j int) bool {
		if rank(res.Findings[i].Severity) != rank(res.Findings[j].Severity) {
			return rank(res.Findings[i].Severity) < rank(res.Findings[j].Severity)
		}
		return res.Findings[i].ID < res.Findings[j].ID
	})
	for _, c := range res.Claims {
		res.Totals.Claims++
		switch c.Outcome {
		case OutcomeConfirmed:
			res.Totals.Confirmed++
		case OutcomeRefuted:
			res.Totals.Refuted++
		case OutcomeError:
			res.Totals.Error++
		default:
			res.Totals.Undetermined++
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
	return *res
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

func (e *evaluator) finding(severity, id, format string, args ...any) {
	e.res.Findings = append(e.res.Findings, Finding{Severity: severity, ID: id, Message: fmt.Sprintf(format, args...)})
}

func servedSet(s Snapshot) map[string]bool {
	out := make(map[string]bool, len(s.Served))
	for _, api := range s.Served {
		out[api] = true
	}
	return out
}

func imageDigest(image string) string {
	if i := strings.Index(image, "@"); i >= 0 {
		return image[i+1:]
	}
	return image
}

// claim evaluates one claim.
func (e *evaluator) claim(c Claim) ClaimResult {
	cr := ClaimResult{ID: c.ID, Kind: c.Kind, Outcome: OutcomeUndetermined, PrufyxCommit: e.prov.Prufyx.Commit, LogDigest: e.prov.LogDigest, Evidence: c.Evidence}
	switch c.Kind {
	case KindServedAPI:
		e.servedAPI(c, &cr)
	case KindK8sRemoval:
		e.k8sRemoval(c, &cr)
	case KindCRDVersion:
		e.crdVersion(c, &cr)
	case KindCRDRemoval:
		e.crdRemoval(c, &cr)
	case KindCRDPair:
		e.crdPair(c, &cr)
	default:
		cr.Detail = "not evaluated by kind-val"
	}
	return cr
}

func (e *evaluator) servedAPI(c Claim, cr *ClaimResult) {
	s, ok := e.runs.Snapshots[c.Subject.Line]
	if !ok {
		cr.Detail = "no snapshot of line " + c.Subject.Line
		return
	}
	cr.NodeImageDigest = imageDigest(s.Image)
	api := apiPair(c.Subject.Group, c.Subject.Version, c.Subject.Kind)
	observed := ExpectNotServed
	if e.sets[c.Subject.Line][api] {
		observed = ExpectServed
	}
	cr.Detail = fmt.Sprintf("%s by %s", strings.ReplaceAll(observed, "_", " "), s.ServerVersion)
	if observed == c.Expect {
		cr.Outcome = OutcomeConfirmed
		return
	}
	// Either way the knowledge is wrong about this line: it would block a
	// manifest the server accepts, or it names a line that does not serve
	// a version it says is served.
	cr.Outcome = OutcomeRefuted
	e.finding(SeverityMedium, c.ID, "line %s (%s): the claim says %s is %s, the API server says %s", c.Subject.Line, s.ServerVersion, api, c.Expect, observed)
}

// k8sRemoval checks a hop: the from line serves the API, the to line does
// not (discovery and dry run), and the scan blocks the manifest.
func (e *evaluator) k8sRemoval(c Claim, cr *ClaimResult) {
	from, _ := lineSubject(c.Subject.From)
	to, _ := lineSubject(c.Subject.To)
	api := apiPair(c.Subject.Group, c.Subject.Version, c.Subject.Kind)
	toSnap, okTo := e.runs.Snapshots[to]
	_, okFrom := e.runs.Snapshots[from]
	if !okFrom || !okTo {
		cr.Detail = fmt.Sprintf("no snapshot of line %s or %s", from, to)
		return
	}
	cr.NodeImageDigest = imageDigest(toSnap.Image)
	id := caseID(api)
	fromCase, okFromCase := e.cases[from][id]
	toCase, okToCase := e.cases[to][id]
	if !okFromCase || !okToCase || toCase.Scan == nil {
		cr.Detail = "the corpus has no dry run of the API on both lines, or no scan for the hop"
		return
	}
	servedFrom, servedTo := e.sets[from][api], e.sets[to][api]
	var problems []string
	if !servedFrom || fromCase.Server.Outcome == ServerNotServed {
		problems = append(problems, fmt.Sprintf("%s does not serve %s", from, api))
	}
	if servedTo || toCase.Server.Outcome != ServerNotServed {
		problems = append(problems, fmt.Sprintf("%s still serves %s", to, api))
	}
	if len(problems) > 0 {
		cr.Outcome = OutcomeRefuted
		cr.Detail = strings.Join(problems, "; ")
		e.finding(SeverityMedium, c.ID, "%s -> %s: %s", from, to, cr.Detail)
		return
	}
	sc := toCase.Scan
	if sc.Error != "" {
		cr.Outcome = OutcomeError
		cr.Detail = "the scan gave no report: " + sc.Error
		e.finding(SeverityInfo, c.ID, "%s -> %s, %s: %s", sc.From, sc.To, api, cr.Detail)
		return
	}
	hasGap := false
	for _, g := range sc.Gaps {
		hasGap = hasGap || g == gapNotServed
	}
	hasRule := c.Subject.RuleID == ""
	for _, r := range sc.Rules {
		hasRule = hasRule || r == c.Subject.RuleID
	}
	cr.Detail = fmt.Sprintf("both servers agree; scan %s -> %s: %s (exit %d)", sc.From, sc.To, sc.Verdict, sc.Exit)
	switch {
	case sc.Exit == exitBlocked && hasGap && hasRule:
		cr.Outcome = OutcomeConfirmed
	case sc.Exit == exitBlocked && hasGap:
		cr.Outcome = OutcomeRefuted
		cr.Detail += "; rule " + c.Subject.RuleID + " did not match"
		e.finding(SeverityMedium, c.ID, "%s -> %s: the scan blocks %s but not through rule %s (matched: %s)", sc.From, sc.To, api, c.Subject.RuleID, strings.Join(sc.Rules, ", "))
	case sc.Exit == exitBlocked:
		cr.Outcome = OutcomeConfirmed
		cr.Detail += "; blocked without the " + gapNotServed + " gap"
	case sc.Exit == exitPass:
		cr.Outcome = OutcomeRefuted
		e.finding(SeverityHigh, c.ID, "%s -> %s: the scan PASSES %s, which %s serves and %s rejects", sc.From, sc.To, api, from, to)
	case sc.Exit == exitUnknown && hasGap:
		// The report names the API as not served by the target (the gap
		// the GitHub Action fails on), but no published rule decides the
		// hop, so the verdict stays UNKNOWN.
		cr.Outcome = OutcomeRefuted
		cr.Detail += "; UNKNOWN with the " + gapNotServed + " gap: no published rule decides the hop"
		e.finding(SeverityMedium, c.ID, "%s -> %s: the scan names %s as not served by %s but answers UNKNOWN (exit 11), not BLOCKED: no published removal rule for the %s line", sc.From, sc.To, api, to, to)
	default:
		cr.Outcome = OutcomeRefuted
		e.finding(SeverityMedium, c.ID, "%s -> %s: the scan answers %s (exit %d) for %s, which %s serves and %s rejects; the removal is not known", sc.From, sc.To, sc.Verdict, sc.Exit, api, from, to)
	}
}

// pairFor finds the run of the pair a claim's project and releases name.
func (e *evaluator) pairFor(project, fromTag, toTag string, cr *ClaimResult) (CRDPairResult, bool) {
	id := pairID(project, fromTag, toTag)
	pr, ok := e.pairs[id]
	if !ok {
		cr.Detail = "no run of " + id
		return pr, false
	}
	cr.NodeImageDigest = imageDigest(e.pairImage[id])
	if pr.Error != "" || pr.From.Error != "" || pr.To.Error != "" {
		cr.Outcome = OutcomeError
		cr.Detail = strings.TrimSpace(pr.Error + " " + pr.From.Error + " " + pr.To.Error)
		return pr, false
	}
	return pr, true
}

// releaseStateFor finds the installed state of one release of a project in
// any pair run (as From or To): the first pair, in id order, whose install
// of the release completed; else the error of a pair that tried it.
func (e *evaluator) releaseStateFor(project, tag string, cr *ClaimResult) (CRDReleaseState, bool) {
	ids := make([]string, 0, len(e.pairs))
	for id := range e.pairs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var failed string
	for _, id := range ids {
		pr := e.pairs[id]
		if pr.Project != project {
			continue
		}
		var state CRDReleaseState
		switch tag {
		case pr.FromTag:
			state = pr.From
		case pr.ToTag:
			state = pr.To
		default:
			continue
		}
		cr.NodeImageDigest = imageDigest(e.pairImage[id])
		switch {
		case state.Error != "":
			failed = state.Error
		case len(state.Files) == 0:
			// The pair stopped before this release was installed.
			failed = strings.TrimSpace(pr.Error + " " + pr.From.Error)
			if failed == "" {
				failed = "the pair " + id + " did not install " + tag
			}
		default:
			return state, true
		}
	}
	if failed != "" {
		cr.Outcome = OutcomeError
		cr.Detail = failed
		return CRDReleaseState{}, false
	}
	cr.Detail = fmt.Sprintf("release %s %s was not installed by any pair", project, tag)
	return CRDReleaseState{}, false
}

func objectOutcome(state CRDReleaseState, m string) string {
	for _, o := range state.Objects {
		if o.Member == m {
			return o.Outcome
		}
	}
	return ""
}

func (e *evaluator) crdVersion(c Claim, cr *ClaimResult) {
	s := c.Subject
	state, ok := e.releaseStateFor(s.Project, s.Release.Tag, cr)
	if !ok {
		return
	}
	var def *CRDDef
	for i := range state.CRDs {
		if state.CRDs[i].Name == s.CRD {
			def = &state.CRDs[i]
		}
	}
	if def == nil {
		cr.Outcome = OutcomeRefuted
		cr.Detail = "the cluster holds no " + s.CRD + " after installing " + s.Release.Tag
		e.finding(SeverityMedium, c.ID, "%s %s: %s", s.Project, s.Release.Tag, cr.Detail)
		return
	}
	var got *CRDVersion
	for i := range def.Versions {
		if def.Versions[i].Name == s.Version {
			got = &def.Versions[i]
		}
	}
	m := member(s.Group, s.Version, s.Kind)
	probe := objectOutcome(state, m)
	if got == nil {
		cr.Outcome = OutcomeRefuted
		cr.Detail = fmt.Sprintf("%s does not declare %s at %s", s.CRD, s.Version, s.Release.Tag)
		e.finding(SeverityMedium, c.ID, "%s %s: %s", s.Project, s.Release.Tag, cr.Detail)
		return
	}
	cr.Detail = fmt.Sprintf("%s at %s declares %s served=%t storage=%t; dry-run object %s", s.CRD, s.Release.Tag, s.Version, got.Served, got.Storage, orUnprobed(probe))
	flagsOK := got.Served == *s.Served && got.Storage == *s.Storage
	probeOK := probe == "" || (probe == ServerNotServed) == !*s.Served
	if flagsOK && probeOK {
		cr.Outcome = OutcomeConfirmed
		return
	}
	cr.Outcome = OutcomeRefuted
	severity := SeverityMedium
	if *s.Served && (!got.Served || probe == ServerNotServed) {
		severity = SeverityHigh // the knowledge keeps a version the release dropped
	}
	e.finding(severity, c.ID, "%s %s: the claim says %s served=%t storage=%t; %s", s.Project, s.Release.Tag, m, *s.Served, *s.Storage, cr.Detail)
}

func (e *evaluator) crdRemoval(c Claim, cr *ClaimResult) {
	s := c.Subject
	from, _ := releaseSubject(s.From)
	to, _ := releaseSubject(s.To)
	pr, ok := e.pairFor(s.Project, from.Tag, to.Tag, cr)
	if !ok {
		return
	}
	m := member(s.Group, s.Version, s.Kind)
	before, after := objectOutcome(pr.From, m), objectOutcome(pr.To, m)
	cr.Detail = fmt.Sprintf("%s: %s at %s, %s at %s", m, orUnprobed(before), from.Tag, orUnprobed(after), to.Tag)
	switch {
	case before == "" || after == "":
		cr.Detail = "the member was not probed on both releases"
	case before == ServerNotServed:
		cr.Outcome = OutcomeRefuted
		e.finding(SeverityMedium, c.ID, "%s %s does not serve %s, which the claim says it served", s.Project, from.Tag, m)
	case after != ServerNotServed:
		cr.Outcome = OutcomeRefuted
		e.finding(SeverityHigh, c.ID, "%s %s still serves %s, which the claim says it removed", s.Project, to.Tag, m)
	default:
		cr.Outcome = OutcomeConfirmed
	}
	if pr.InPlace.Attempted && !pr.InPlace.Succeeded {
		cr.Detail += "; in-place update of the definitions refused: " + pr.InPlace.Message
	}
	for _, name := range pr.InPlace.Leftover {
		if strings.HasSuffix(name, "."+s.Group) && strings.HasPrefix(name, strings.ToLower(s.Kind)) {
			cr.Detail += "; " + to.Tag + " no longer defines " + name + ": a plain apply leaves the definition in place and its objects stay accepted"
			e.finding(SeverityInfo, c.ID+".leftover", "%s %s no longer defines %s; applying its manifests over %s leaves the definition (and %s) accepted until it is deleted", s.Project, to.Tag, name, from.Tag, m)
		}
	}
}

func orUnprobed(outcome string) string {
	if outcome == "" {
		return "unprobed"
	}
	return outcome
}

// crdPair checks that every version served after From is still served
// after To.
func (e *evaluator) crdPair(c Claim, cr *ClaimResult) {
	s := c.Subject
	from, _ := releaseSubject(s.From)
	to, _ := releaseSubject(s.To)
	pr, ok := e.pairFor(s.Project, from.Tag, to.Tag, cr)
	if !ok {
		return
	}
	var kept, missed []string
	for _, o := range pr.From.Objects {
		if o.Outcome == ServerNotServed {
			continue
		}
		if objectOutcome(pr.To, o.Member) == ServerNotServed {
			missed = append(missed, o.Member)
		} else {
			kept = append(kept, o.Member)
		}
	}
	cr.Detail = fmt.Sprintf("%d version(s) served at %s still served at %s", len(kept), from.Tag, to.Tag)
	if len(missed) > 0 {
		cr.Outcome = OutcomeRefuted
		cr.Detail += "; no longer served: " + strings.Join(missed, ", ")
		e.finding(SeverityHigh, c.ID, "%s %s no longer serves %s, which no claim records as removed", s.Project, to.Tag, strings.Join(missed, ", "))
		return
	}
	cr.Outcome = OutcomeConfirmed
	if pr.InPlace.Attempted && !pr.InPlace.Succeeded {
		cr.Detail += "; in-place update of the definitions refused: " + pr.InPlace.Message
		e.finding(SeverityInfo, "crd."+pr.ID+".in-place", "%s: applying the %s definitions over %s was refused by the API server: %s", s.Project, to.Tag, from.Tag, pr.InPlace.Message)
	}
}

// diffs compares consecutive lines and reports every removed API that
// neither the removal table nor a claim names.
func (e *evaluator) diffs(lines []string, claims Claims) {
	known := knownRemovals()
	for _, c := range claims.Claims {
		if c.Kind == KindServedAPI && c.Expect == ExpectNotServed {
			if known[c.Subject.Line] == nil {
				known[c.Subject.Line] = map[string]bool{}
			}
			known[c.Subject.Line][apiPair(c.Subject.Group, c.Subject.Version, c.Subject.Kind)] = true
		}
	}
	for i := 1; i < len(lines); i++ {
		prev, next := lines[i-1], lines[i]
		if previousLine(next) != prev {
			continue
		}
		before, after := e.sets[prev], e.sets[next]
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
			e.finding(severity, "diff."+next+"."+caseID(api), "line %s no longer serves %s (served by %s); no claim names it", next, api, prev)
		}
		e.res.Diffs = append(e.res.Diffs, d)
	}
}

// Summary renders the human summary of the results.
func Summary(res Results) string {
	var b strings.Builder
	b.WriteString("# KIND-VAL results\n\n")
	fmt.Fprintf(&b, "Generated %s; prufyx %s.\n\n", res.GeneratedAt, orUnknown(res.Prufyx.Commit))
	b.WriteString("| Line | Server | Served APIs | Served-API claims | Removal (verdict) claims | CRD claims |\n|---|---|---|---|---|---|\n")
	byDigest := map[string]*[6]int{}
	for i := range res.Lines {
		byDigest[imageDigest(res.Lines[i].Image)] = &[6]int{}
	}
	for _, c := range res.Claims {
		counts, ok := byDigest[c.NodeImageDigest]
		if !ok {
			continue
		}
		col := 4
		switch c.Kind {
		case KindServedAPI:
			col = 0
		case KindK8sRemoval:
			col = 2
		}
		switch c.Outcome {
		case OutcomeConfirmed:
			counts[col]++
		case OutcomeRefuted:
			counts[col+1]++
		}
	}
	for _, l := range res.Lines {
		counts := byDigest[imageDigest(l.Image)]
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %s | %s |\n", l.Line, l.ServerVersion, l.Served, cell(counts[0], counts[1]), cell(counts[2], counts[3]), cell(counts[4], counts[5]))
	}
	t := res.Totals
	fmt.Fprintf(&b, "\nClaims: %d confirmed, %d refuted, %d undetermined, %d error. Findings: %d HIGH, %d MEDIUM, %d INFO.\n", t.Confirmed, t.Refuted, t.Undetermined, t.Error, t.High, t.Medium, t.Info)
	if len(res.Diffs) > 0 {
		b.WriteString("\n## Served-API changes between consecutive lines\n\n")
		for _, d := range res.Diffs {
			fmt.Fprintf(&b, "- %s -> %s: %d removed, %d added, %d removed without a claim\n", d.From, d.To, len(d.Removed), len(d.Added), len(d.UnknownRemovals))
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

func orUnknown(s string) string {
	if s == "" {
		return "(commit not given)"
	}
	return s
}

func cell(ok, bad int) string {
	if ok+bad == 0 {
		return "-"
	}
	return fmt.Sprintf("%d ok / %d bad", ok, bad)
}
