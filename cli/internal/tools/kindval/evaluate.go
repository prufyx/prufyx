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
	singles   map[string]CRDReleaseResult
	singleImg map[string]string
	// imageProblem maps a configured node image digest to why the nodes
	// that ran it are not proven to run it.
	imageProblem map[string]string
	// claimed is, by pair id, every member a crd-removal claim names.
	claimed map[string]map[string]bool
	// serversOnly decides k8s-removal claims on the API servers without the
	// scan (the controls: they check the clusters, not the scanner).
	serversOnly bool
}

// claimedRemovals indexes the members the crd-removal claims name, by
// pair id.
func claimedRemovals(claims []Claim) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, c := range claims {
		if c.Kind != KindCRDRemoval {
			continue
		}
		from, _ := releaseSubject(c.Subject.From)
		to, _ := releaseSubject(c.Subject.To)
		id := pairID(c.Subject.Project, from.Tag, to.Tag)
		if out[id] == nil {
			out[id] = map[string]bool{}
		}
		out[id][member(c.Subject.Group, c.Subject.Version, c.Subject.Kind)] = true
	}
	return out
}

// runLines is the lines of the snapshots, in order.
func runLines(runs Runs) []string {
	lines := make([]string, 0, len(runs.Snapshots))
	for line := range runs.Snapshots {
		lines = append(lines, line)
	}
	sortLines(lines)
	return lines
}

// newEvaluator indexes the runs for the given claims; its findings go to
// res.
func newEvaluator(runs Runs, prov Provenance, res *Results, claims []Claim) *evaluator {
	ev := &evaluator{runs: runs, prov: prov, res: res, sets: map[string]map[string]bool{}, cases: map[string]map[string]VerdictCase{}, pairs: map[string]CRDPairResult{}, pairImage: map[string]string{}, singles: map[string]CRDReleaseResult{}, singleImg: map[string]string{}, imageProblem: map[string]string{}}
	for line, s := range runs.Snapshots {
		ev.sets[line] = servedSet(s)
	}
	for _, line := range runLines(runs) {
		ev.checkImage(runs.Snapshots[line].Image, runs.Snapshots[line].ObservedImageDigests)
	}
	for _, run := range runs.CRD {
		ev.checkImage(run.Image, run.ObservedImageDigests)
	}
	for line, run := range runs.Verdicts {
		ev.cases[line] = map[string]VerdictCase{}
		for _, c := range run.Cases {
			ev.cases[line][c.ID] = c
		}
	}
	for _, run := range runs.CRD {
		for _, p := range run.Pairs {
			// A pair run again after a failure: the complete run decides.
			if prev, ok := ev.pairs[p.ID]; ok && pairFailed(p) && !pairFailed(prev) {
				continue
			}
			ev.pairs[p.ID] = p
			ev.pairImage[p.ID] = run.Image
		}
	}
	for _, run := range runs.CRD {
		for _, r := range run.Releases {
			// Run again after a failure: the complete run decides.
			if prev, ok := ev.singles[r.ID]; ok && singleFailed(r) && !singleFailed(prev) {
				continue
			}
			ev.singles[r.ID] = r
			ev.singleImg[r.ID] = run.Image
		}
	}
	ev.claimed = claimedRemovals(claims)
	return ev
}

// evaluate evaluates one claim. A verdict from a node whose image is not
// proven to be the configured digest is no verdict.
func (e *evaluator) evaluate(c Claim) ClaimResult {
	cr := e.claim(c)
	if problem := e.imageProblem[cr.NodeImageDigest]; problem != "" && (cr.Outcome == OutcomeConfirmed || cr.Outcome == OutcomeRefuted) {
		cr.Outcome, cr.Reason = OutcomeError, ReasonImageDigestMismatch
		cr.Detail += "; " + problem
	}
	return cr
}

// Evaluate compares the claims with the runs. A v2 claims file carries
// controls: they are evaluated apart, and a group of claims whose controls
// did not all come out as expected is void (see applyControls).
func Evaluate(claims Claims, runs Runs, prov Provenance, now time.Time) Results {
	v2 := claims.Schema == ClaimsSchemaV2
	res := &Results{Schema: ResultsSchema, GeneratedAt: now.UTC().Format(time.RFC3339), Prufyx: prov.Prufyx, LogDigest: prov.LogDigest, Lines: []LineSummary{}, Claims: []ClaimResult{}, Diffs: []LineDiff{}, Findings: []Finding{}}
	plain, controls := claims.Claims, []Claim(nil)
	if v2 {
		res.Schema = ResultsSchemaV2
		plain = nil
		for _, c := range claims.Claims {
			if c.Control == "" {
				plain = append(plain, c)
			} else {
				controls = append(controls, c)
			}
		}
	}
	ev := newEvaluator(runs, prov, res, plain)
	lines := runLines(runs)
	for _, line := range lines {
		s := runs.Snapshots[line]
		res.Lines = append(res.Lines, LineSummary{Line: line, ServerVersion: s.ServerVersion, Image: s.Image, Served: len(s.Served)})
	}
	// owner maps each finding to the claim that raised it (ownerMissed:
	// the missed-removal check of the custom-resource pairs; ownerNone: the
	// served-API differences), so a voided claim takes its findings along.
	var owner []int
	own := func(who int) {
		for len(owner) < len(res.Findings) {
			owner = append(owner, who)
		}
	}
	for i, c := range plain {
		res.Claims = append(res.Claims, ev.evaluate(c))
		own(i)
	}
	ev.missedRemovals(plain)
	own(ownerMissed)
	ev.diffs(lines, plain)
	own(ownerNone)
	if v2 {
		applyControls(res, plain, controls, runs, prov, owner)
	} else {
		for i := range res.Claims {
			res.Claims[i].Reason, res.Claims[i].Verdict = "", ""
		}
	}
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

// groupKey is the control group of a claim: its kind and the line it is
// decided on (the custom-resource kinds are decided on one line: "").
func groupKey(c Claim) (kind, line string) {
	switch c.Kind {
	case KindServedAPI:
		return c.Kind, c.Subject.Line
	case KindK8sRemoval:
		to, _ := lineSubject(c.Subject.To)
		return c.Kind, to
	}
	return c.Kind, ""
}

// Finding owners that are not a claim (see Evaluate).
const (
	ownerNone   = -1
	ownerMissed = -2
)

// expectedOutcome is the outcome a control must have.
func expectedOutcome(control string) string {
	if control == ControlTrue {
		return OutcomeConfirmed
	}
	return OutcomeRefuted
}

// controlGroup is the controls of one kind on one line.
type controlGroup struct {
	summary ControlSummary
	failed  []ControlResult
}

// applyControls evaluates the controls with an evaluator of their own (its
// findings are discarded) and voids every claim whose group has a control
// that did not come out as expected: nothing a void group shows is
// evidence. A decided claim whose group has no control while its kind has
// some is undetermined. It then sets the verdicts and the control totals.
func applyControls(res *Results, plain, controls []Claim, runs Runs, prov Provenance, owner []int) {
	cev := newEvaluator(runs, prov, &Results{}, controls)
	cev.serversOnly = true
	groups := map[[2]string]*controlGroup{}
	res.Controls = []ControlResult{}
	for _, c := range controls {
		cr := cev.evaluate(c)
		kind, line := groupKey(c)
		ctl := ControlResult{ID: c.ID, Kind: c.Kind, Line: line, Expected: c.Control, Outcome: cr.Outcome, Reason: cr.Reason, Detail: cr.Detail}
		ctl.OK = cr.Outcome == expectedOutcome(c.Control)
		res.Controls = append(res.Controls, ctl)
		g := groups[[2]string{kind, line}]
		if g == nil {
			g = &controlGroup{summary: ControlSummary{Kind: kind, Line: line, State: ControlStateOK}}
			groups[[2]string{kind, line}] = g
		}
		if c.Control == ControlTrue {
			g.summary.True++
		} else {
			g.summary.False++
		}
		if !ctl.OK {
			g.summary.State = ControlStateFailed
			g.failed = append(g.failed, ctl)
		}
	}
	sort.Slice(res.Controls, func(i, j int) bool { return res.Controls[i].ID < res.Controls[j].ID })
	for _, g := range groups {
		sort.Slice(g.failed, func(i, j int) bool { return g.failed[i].ID < g.failed[j].ID })
	}

	// A group needs a true and a false control: one expectation alone
	// cannot tell a working harness from one that answers the same thing
	// to everything (a hop whose removals no upstream guide documents has
	// false removal controls only).
	for _, g := range groups {
		if g.summary.State == ControlStateOK && (g.summary.True == 0 || g.summary.False == 0) {
			g.summary.State = ControlStateIncomplete
		}
	}
	// A claim is decided by its own group and, for a k8s-removal claim, by
	// the served-API groups of both its lines too: it reads their snapshots
	// and dry runs.
	deps := func(c Claim) [][2]string {
		kind, line := groupKey(c)
		out := [][2]string{{kind, line}}
		if c.Kind == KindK8sRemoval {
			from, _ := lineSubject(c.Subject.From)
			out = append(out, [2]string{KindServedAPI, from}, [2]string{KindServedAPI, line})
		}
		return out
	}
	withEntries := controlKindsWithEntries()
	absent := map[[2]string]bool{}
	voided := map[int]bool{}
	voidedGroup := map[[2]string]bool{}
	// failedBy is, for a canary-failed claim, the failed groups it depends on.
	failedBy := map[int][][2]string{}
	for i := range res.Claims {
		cr := &res.Claims[i]
		kind, line := groupKey(plain[i])
		if !withEntries[kind] {
			absent[[2]string{kind, ""}] = true
			continue
		}
		var failed, missing []string
		for _, k := range deps(plain[i]) {
			g := groups[k]
			where := "on line " + k[1]
			if k[1] == "" {
				where = "in this run"
			}
			switch {
			case g == nil:
				absent[k] = true
				missing = append(missing, "no control of kind "+k[0]+" ran "+where)
			case g.summary.State == ControlStateIncomplete:
				missing = append(missing, "the controls of kind "+k[0]+" "+where+" all have one expectation")
			case len(g.failed) > 0:
				failedBy[i] = append(failedBy[i], k)
				for _, f := range g.failed {
					failed = append(failed, fmt.Sprintf("%s (expected %s, got %s)", f.ID, expectedOutcome(f.Expected), f.Outcome))
				}
			}
		}
		switch {
		case len(failed) > 0:
			voided[i], voidedGroup[[2]string{kind, line}] = true, true
			cr.Outcome, cr.Reason = OutcomeError, ReasonCanaryFailed
			cr.Detail = "canary failed: " + strings.Join(failed, ", ") + "; was: " + cr.Detail
		case len(missing) > 0 && (cr.Outcome == OutcomeConfirmed || cr.Outcome == OutcomeRefuted):
			voided[i], voidedGroup[[2]string{kind, line}] = true, true
			cr.Outcome, cr.Reason = OutcomeUndetermined, ReasonControlsAbsent
			cr.Detail += "; " + strings.Join(missing, "; ")
		}
	}

	// A served-API difference reads the snapshots of both its lines: it is
	// kept only when the served-API groups of both are ok. voidDiff maps the
	// later line of a dropped difference to its earlier line.
	voidDiff := map[string]string{}
	keptDiffs := res.Diffs[:0]
	for _, d := range res.Diffs {
		ok := true
		for _, l := range []string{d.From, d.To} {
			g := groups[[2]string{KindServedAPI, l}]
			ok = ok && g != nil && g.summary.State == ControlStateOK
		}
		if ok {
			keptDiffs = append(keptDiffs, d)
		} else {
			voidDiff[d.To] = d.From
		}
	}
	res.Diffs = keptDiffs
	// failedServed is the failed served-API groups of the lines of a diff.
	failedServed := func(lines ...string) [][2]string {
		var out [][2]string
		for _, l := range lines {
			k := [2]string{KindServedAPI, l}
			if g := groups[k]; g != nil && len(g.failed) > 0 {
				out = append(out, k)
			}
		}
		return out
	}

	// A voided claim is no evidence: the findings it raised go with it, the
	// missed-removal findings go with a voided crd-removal group, and the
	// findings of a dropped difference go with it. The canary finding of
	// every failed group they depend on lists what was dropped.
	dropped := map[[2]string][]string{}
	kept := res.Findings[:0]
	for i, f := range res.Findings {
		who := ownerNone
		if i < len(owner) {
			who = owner[i]
		}
		var keys [][2]string
		switch {
		case who >= 0 && voided[who]:
			keys = failedBy[who]
		case who == ownerMissed && voidedGroup[[2]string{KindCRDRemoval, ""}]:
			keys = [][2]string{{KindCRDRemoval, ""}}
		case who == ownerNone && diffOf(f.ID, voidDiff) != "":
			next := diffOf(f.ID, voidDiff)
			keys = failedServed(voidDiff[next], next)
		default:
			kept = append(kept, f)
			continue
		}
		for _, k := range keys {
			dropped[k] = append(dropped[k], f.Severity+" "+f.ID)
		}
	}
	res.Findings = kept
	nexts := make([]string, 0, len(voidDiff))
	for next := range voidDiff {
		nexts = append(nexts, next)
	}
	sortLines(nexts)
	for _, next := range nexts {
		prev := voidDiff[next]
		for _, k := range failedServed(prev, next) {
			dropped[k] = append(dropped[k], "diff "+prev+" -> "+next)
		}
	}

	// Every group with controls is summarised, with or without claims.
	keys := make([][2]string, 0, len(groups)+len(absent))
	for k := range groups {
		keys = append(keys, k)
	}
	for k := range absent {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] != keys[j][1] && (keys[i][1] == "" || keys[j][1] != "" && lineLess(keys[i][1], keys[j][1]))
	})
	res.Totals.Controls = []ControlSummary{}
	for _, k := range keys {
		g := groups[k]
		if g == nil {
			res.Totals.Controls = append(res.Totals.Controls, ControlSummary{Kind: k[0], Line: k[1], State: ControlStateAbsent})
			continue
		}
		var msgs []string
		for _, f := range g.failed {
			g.summary.Failed = append(g.summary.Failed, f.ID)
			msgs = append(msgs, fmt.Sprintf("%s expected %s, got %s (%s): %s", f.ID, expectedOutcome(f.Expected), f.Outcome, orNone(f.Reason), f.Detail))
		}
		res.Totals.Controls = append(res.Totals.Controls, g.summary)
		if len(msgs) > 0 {
			id, where := "canary-failed/"+k[0], "in this run"
			if k[1] != "" {
				id, where = id+"/"+k[1], "on line "+k[1]
			}
			msg := fmt.Sprintf("the controls of %s %s did not come out as expected, so no claim of the group is evidence: %s", k[0], where, strings.Join(msgs, "; "))
			if d := dropped[k]; len(d) > 0 {
				msg += "; findings of the voided claims dropped: " + strings.Join(d, ", ")
			}
			res.Findings = append(res.Findings, Finding{Severity: SeverityHigh, ID: id, Message: msg})
		}
	}

	// Verdicts: only a confirmed outcome is confirmed by execution.
	res.Totals.Verdicts = &VerdictTotals{}
	for i := range res.Claims {
		cr := &res.Claims[i]
		switch cr.Outcome {
		case OutcomeConfirmed:
			cr.Verdict, cr.Reason = VerdictConfirmed, ""
			res.Totals.Verdicts.ConfirmedByExecution++
		case OutcomeRefuted:
			cr.Verdict = VerdictRefuted
			res.Totals.Verdicts.Refuted++
		case OutcomeError:
			cr.Verdict = VerdictError
			res.Totals.Verdicts.Error++
		default:
			cr.Verdict = VerdictUndetermined
			res.Totals.Verdicts.Undetermined++
		}
	}
}

// diffOf is the later line of the dropped difference a finding id belongs
// to ("diff.<next>.<case>"), or "".
func diffOf(id string, voidDiff map[string]string) string {
	for next := range voidDiff {
		if strings.HasPrefix(id, "diff."+next+".") {
			return next
		}
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "no reason"
	}
	return s
}
func pairFailed(p CRDPairResult) bool {
	return p.Error != "" || p.From.Error != "" || p.To.Error != "" || len(p.To.Files) == 0
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

// checkImage records why the configured digest of a node image is not
// proven: it is not a digest at all, or the observed digests of the node
// container are missing or do not include it.
func (e *evaluator) checkImage(image string, observed []string) {
	configured := imageDigest(image)
	if !strings.Contains(image, "@sha256:") {
		e.imageProblem[configured] = "node image " + image + " is not pinned by @sha256: digest"
		return
	}
	for _, o := range observed {
		if imageDigest(o) == configured {
			return
		}
	}
	if len(observed) == 0 {
		e.imageProblem[configured] = "no observed digest of the node image " + configured
		return
	}
	e.imageProblem[configured] = "observed node image digest " + strings.Join(observed, ",") + " differs from the configured " + configured
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
		cr.Detail, cr.Reason = "not evaluated by kind-val", ReasonNotEvaluated
	}
	return cr
}

func (e *evaluator) servedAPI(c Claim, cr *ClaimResult) {
	s, ok := e.runs.Snapshots[c.Subject.Line]
	if !ok {
		cr.Detail, cr.Reason = "no snapshot of line "+c.Subject.Line, ReasonNoSnapshot
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
	cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
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
		cr.Detail, cr.Reason = fmt.Sprintf("no snapshot of line %s or %s", from, to), ReasonNoSnapshot
		return
	}
	cr.NodeImageDigest = imageDigest(toSnap.Image)
	id := caseID(api)
	fromCase, okFromCase := e.cases[from][id]
	toCase, okToCase := e.cases[to][id]
	if !okFromCase || !okToCase || (toCase.Scan == nil && !e.serversOnly) {
		cr.Detail, cr.Reason = "the corpus has no dry run of the API on both lines, or no scan for the hop", ReasonNoCorpusCase
		return
	}
	if fromCase.Server.Outcome == ServerError || toCase.Server.Outcome == ServerError {
		cr.Outcome, cr.Reason = OutcomeError, ReasonServerNoAnswer
		cr.Detail = "the API server gave no answer to a dry run: " + strings.TrimSpace(fromCase.Server.Message+" "+toCase.Server.Message)
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
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
		cr.Detail = strings.Join(problems, "; ")
		e.finding(SeverityMedium, c.ID, "%s -> %s: %s", from, to, cr.Detail)
		return
	}
	if e.serversOnly {
		cr.Outcome, cr.Detail = OutcomeConfirmed, "both servers agree (controls are decided on the API servers only)"
		return
	}
	sc := toCase.Scan
	if sc.Error != "" {
		cr.Outcome, cr.Reason = OutcomeError, ReasonScanNoReport
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
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
		cr.Detail += "; rule " + c.Subject.RuleID + " did not match"
		e.finding(SeverityMedium, c.ID, "%s -> %s: the scan blocks %s but not through rule %s (matched: %s)", sc.From, sc.To, api, c.Subject.RuleID, strings.Join(sc.Rules, ", "))
	case sc.Exit == exitBlocked:
		cr.Outcome = OutcomeConfirmed
		cr.Detail += "; blocked without the " + gapNotServed + " gap"
	case sc.Exit == exitPass:
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
		e.finding(SeverityHigh, c.ID, "%s -> %s: the scan PASSES %s, which %s serves and %s rejects", sc.From, sc.To, api, from, to)
	case sc.Exit == exitUnknown && hasGap:
		// The report names the API as not served by the target (the gap
		// the GitHub Action fails on), but no published rule decides the
		// hop, so the verdict stays UNKNOWN.
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
		cr.Detail += "; UNKNOWN with the " + gapNotServed + " gap: no published rule decides the hop"
		e.finding(SeverityMedium, c.ID, "%s -> %s: the scan names %s as not served by %s but answers UNKNOWN (exit 11), not BLOCKED: no published removal rule for the %s line", sc.From, sc.To, api, to, to)
	default:
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
		e.finding(SeverityMedium, c.ID, "%s -> %s: the scan answers %s (exit %d) for %s, which %s serves and %s rejects; the removal is not known", sc.From, sc.To, sc.Verdict, sc.Exit, api, from, to)
	}
}

// pairFor finds the run of the pair a claim's project and releases name.
func (e *evaluator) pairFor(project, fromTag, toTag string, cr *ClaimResult) (CRDPairResult, bool) {
	id := pairID(project, fromTag, toTag)
	pr, ok := e.pairs[id]
	if !ok {
		cr.Detail, cr.Reason = "no run of "+id, ReasonNoRun
		return pr, false
	}
	cr.NodeImageDigest = imageDigest(e.pairImage[id])
	if pr.Error != "" || pr.From.Error != "" || pr.To.Error != "" {
		cr.Outcome, cr.Reason = OutcomeError, ReasonInstallFailed
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
	var failed, failedReason string
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
			failed, failedReason = state.Error, ReasonInstallFailed
		case len(state.Files) == 0:
			// The pair stopped before this release was installed.
			failed, failedReason = strings.TrimSpace(pr.Error+" "+pr.From.Error), ReasonInstallFailed
			if failed == "" {
				failedReason = ReasonReleaseNotInstalled
				failed = "the pair " + id + " did not install " + tag
			}
		default:
			return state, true
		}
	}
	if failed != "" {
		cr.Outcome, cr.Reason = OutcomeError, failedReason
		cr.Detail = failed
		return CRDReleaseState{}, false
	}
	if r, ok := e.singles[singleID(project, tag)]; ok {
		cr.NodeImageDigest = imageDigest(e.singleImg[r.ID])
		switch {
		case r.Unavailable != "":
			cr.Detail, cr.Reason = fmt.Sprintf("release %s %s cannot be installed from the claim's evidence: %s", project, tag, r.Unavailable), ReasonReleaseUnavailable
		case r.Error != "" || r.State.Error != "":
			cr.Outcome, cr.Reason = OutcomeError, ReasonInstallFailed
			cr.Detail = strings.TrimSpace(r.Error + " " + r.State.Error)
		case len(r.State.Files) == 0:
			cr.Detail, cr.Reason = fmt.Sprintf("release %s %s was not installed", project, tag), ReasonReleaseNotInstalled
		default:
			return r.State, true
		}
		return CRDReleaseState{}, false
	}
	cr.Detail, cr.Reason = fmt.Sprintf("release %s %s was not installed by any pair or on its own", project, tag), ReasonNoRun
	return CRDReleaseState{}, false
}

func singleFailed(r CRDReleaseResult) bool {
	return r.Unavailable != "" || r.Error != "" || r.State.Error != ""
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
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonCRDMissing
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
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonVersionNotDeclared
		cr.Detail = fmt.Sprintf("%s does not declare %s at %s", s.CRD, s.Version, s.Release.Tag)
		e.finding(SeverityMedium, c.ID, "%s %s: %s", s.Project, s.Release.Tag, cr.Detail)
		return
	}
	if probe == ServerError {
		cr.Outcome, cr.Reason = OutcomeError, ReasonServerNoAnswer
		cr.Detail = fmt.Sprintf("%s: the API server gave no answer to the dry-run object", m)
		return
	}
	cr.Detail = fmt.Sprintf("%s at %s declares %s served=%t storage=%t; dry-run object %s", s.CRD, s.Release.Tag, s.Version, got.Served, got.Storage, orUnprobed(probe))
	flagsOK := got.Served == *s.Served && got.Storage == *s.Storage
	probeOK := probe == "" || (probe == ServerNotServed) == !*s.Served
	if flagsOK && probeOK {
		cr.Outcome = OutcomeConfirmed
		return
	}
	cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
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
	case before == ServerError || after == ServerError:
		cr.Outcome, cr.Reason = OutcomeError, ReasonServerNoAnswer
		cr.Detail = m + ": the API server gave no answer to a dry-run object"
	case before == "" || after == "":
		cr.Detail, cr.Reason = "the member was not probed on both releases", ReasonNotProbed
	case before == ServerNotServed:
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
		e.finding(SeverityMedium, c.ID, "%s %s does not serve %s, which the claim says it served", s.Project, from.Tag, m)
	case after != ServerNotServed:
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
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
	for _, o := range append(append([]ObjectTry{}, pr.From.Objects...), pr.To.Objects...) {
		if o.Outcome == ServerError {
			cr.Outcome, cr.Reason = OutcomeError, ReasonServerNoAnswer
			cr.Detail = o.Member + ": the API server gave no answer to a dry-run object"
			return
		}
	}
	var kept, missed, claimed []string
	for _, o := range pr.From.Objects {
		if o.Outcome == ServerNotServed {
			continue
		}
		switch {
		case objectOutcome(pr.To, o.Member) != ServerNotServed:
			kept = append(kept, o.Member)
		case e.claimed[pr.ID][o.Member]:
			claimed = append(claimed, o.Member)
		default:
			missed = append(missed, o.Member)
		}
	}
	cr.Detail = fmt.Sprintf("%d version(s) served at %s still served at %s", len(kept), from.Tag, to.Tag)
	if len(missed)+len(claimed) > 0 {
		// The pair is not quiet. Versions a crd-removal claim of the pair
		// names are that claim's business; the others are unexplained.
		cr.Outcome, cr.Reason = OutcomeRefuted, ReasonDisagreement
		if len(claimed) > 0 {
			cr.Detail += "; no longer served, named by removal claims: " + strings.Join(claimed, ", ")
		}
		if len(missed) > 0 {
			cr.Detail += "; no longer served, named by no claim: " + strings.Join(missed, ", ")
			e.missedFinding(c.ID, pr, missed)
		}
		return
	}
	cr.Outcome = OutcomeConfirmed
	if pr.InPlace.Attempted && !pr.InPlace.Succeeded {
		cr.Detail += "; in-place update of the definitions refused: " + pr.InPlace.Message
		e.finding(SeverityInfo, "crd."+pr.ID+".in-place", "%s: applying the %s definitions over %s was refused by the API server: %s", s.Project, to.Tag, from.Tag, pr.InPlace.Message)
	}
}

// missedRemovals reports, for every pair run that has removal claims, a
// version served after From and not after To that no removal claim of the
// pair names (a pair with a crd-pair claim is already checked by it). A
// definition the later release no longer defines is the usual cause.
func (e *evaluator) missedRemovals(claims []Claim) {
	quiet := map[string]bool{}
	for _, c := range claims {
		if c.Kind == KindCRDPair {
			from, _ := releaseSubject(c.Subject.From)
			to, _ := releaseSubject(c.Subject.To)
			quiet[pairID(c.Subject.Project, from.Tag, to.Tag)] = true
		}
	}
	ids := make([]string, 0, len(e.pairs))
	for id := range e.pairs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		pr := e.pairs[id]
		if quiet[id] || e.claimed[id] == nil || pairFailed(pr) {
			continue
		}
		var missed []string
		for _, o := range pr.From.Objects {
			if o.Outcome != ServerNotServed && o.Outcome != ServerError && objectOutcome(pr.To, o.Member) == ServerNotServed && !e.claimed[id][o.Member] {
				missed = append(missed, o.Member)
			}
		}
		if len(missed) > 0 {
			e.missedFinding("crd."+id+".missed", pr, missed)
		}
	}
}

// missedFinding reports versions the later release no longer serves that
// no claim names. A version of a definition the release still defines is
// HIGH: objects of it are refused after the upgrade. A version of a
// definition the release no longer defines is MEDIUM: a plain apply keeps
// the old definition, so its objects stay accepted until it is deleted.
func (e *evaluator) missedFinding(id string, pr CRDPairResult, missed []string) {
	leftover := map[string]bool{}
	for _, name := range pr.InPlace.Leftover {
		leftover[name] = true
	}
	var dropped, undefined []string
	for _, m := range missed {
		parts := strings.Split(m, "/")
		name := strings.ToLower(parts[2]) + "s." + parts[0]
		if leftover[name] || leftoverFor(pr, parts[0], parts[2]) {
			undefined = append(undefined, m)
		} else {
			dropped = append(dropped, m)
		}
	}
	if len(dropped) > 0 {
		e.finding(SeverityHigh, id, "%s %s no longer serves %s, which no claim records as removed", pr.Project, pr.ToTag, strings.Join(dropped, ", "))
	}
	if len(undefined) > 0 {
		e.finding(SeverityMedium, id+".undefined", "%s %s no longer defines the custom resource of %s, which no claim records; a plain apply keeps the old definition and its objects stay accepted until it is deleted", pr.Project, pr.ToTag, strings.Join(undefined, ", "))
	}
}

// leftoverFor reports whether a definition From had for the group and kind
// is among the definitions To no longer defines.
func leftoverFor(pr CRDPairResult, group, kind string) bool {
	for _, d := range pr.From.CRDs {
		if d.Group != group || d.Kind != kind {
			continue
		}
		for _, name := range pr.InPlace.Leftover {
			if name == d.Name {
				return true
			}
		}
	}
	return false
}

// diffs compares consecutive lines and reports every removed API that
// neither the removal table nor a claim names.
func (e *evaluator) diffs(lines []string, claims []Claim) {
	known := knownRemovals()
	for _, c := range claims {
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
	if res.Schema == ResultsSchemaV2 {
		b.WriteString("\n## Controls\n\n")
		for _, c := range res.Totals.Controls {
			fmt.Fprintf(&b, "- %s %s: %s (%d true, %d false)", c.Kind, orAll(c.Line), c.State, c.True, c.False)
			if len(c.Failed) > 0 {
				fmt.Fprintf(&b, "; failed: %s", strings.Join(c.Failed, ", "))
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func orAll(line string) string {
	if line == "" {
		return "(all lines)"
	}
	return line
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
