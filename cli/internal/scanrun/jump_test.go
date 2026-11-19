// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // a test commit id, not a security use
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// Jumps through several minor lines of the test-only Strimzi reviews: lines
// 0.50 (quiet) and 0.51 (lists the line-wide rule of crdLineRule). Never
// published.

func jumpCommit(version string) string {
	sum := sha1.Sum([]byte("commit " + version)) //nolint:gosec // see import
	return hex.EncodeToString(sum[:])
}

func jumpReleases(versions ...string) []lineattest.Release {
	var out []lineattest.Release
	for _, v := range versions {
		out = append(out, lineattest.Release{Version: v, Commit: jumpCommit(v)})
	}
	return out
}

// jumpAtt is a review of the custom-resource versions of line (test only).
func jumpAtt(line string, from, to []lineattest.Release, until string, ids ...string) lineattest.LineAttestation {
	a := crdLineAttestation(constraintengine.BasisReviewed, ids...)
	a.Line, a.Releases = line, &lineattest.Releases{From: from, To: to}
	if until != "" {
		a.Evidence.ValidUntil = until
	}
	if err := a.Validate(); err != nil {
		panic(err)
	}
	return a
}

// jumpKnowledge holds the reviews of lines 0.50 and 0.51 and the line-wide
// rule, with mutations of either review.
func jumpKnowledge(t *testing.T, mutate func(a50, a51 *lineattest.LineAttestation), extraRules ...string) attestedCRD {
	t.Helper()
	a50 := jumpAtt("0.50", jumpReleases("0.49.0", "0.49.1"), jumpReleases("0.50.0", "0.50.1"), "")
	a51 := jumpAtt("0.51", jumpReleases("0.50.0", "0.50.1"), jumpReleases("0.51.0"), "", crdLineRuleID)
	if mutate != nil {
		mutate(&a50, &a51)
	}
	k := attestedCRD{crdKnowledge: newCRDKnowledge(t, append([]string{crdLineRule}, extraRules...)...)}
	k.attestations = lineattest.NewIndex([]lineattest.LineAttestation{a50, a51})
	return k
}

func jumpScan(t *testing.T, k Knowledge, doc string, extra ...string) Result {
	t.Helper()
	return crdScan(t, k, []string{settingsDoc, doc}, append([]string{"--from", "strimzi=0.49.0", "--to", "strimzi=0.51.0", "--resource-scope-complete"}, extra...)...)
}

func strimziJump(t *testing.T, report scanreport.Report) (scanreport.Path, *scanreport.Jump) {
	t.Helper()
	for _, path := range report.Paths {
		if path.Component == "strimzi" {
			return path, path.Jump
		}
	}
	t.Fatal("no strimzi path")
	return scanreport.Path{}, nil
}

func jumpText(report scanreport.Report) string {
	return string(scanreport.Human(report, scanreport.HumanOptions{Verbose: true}))
}

// QA m10 shape: the blocker sits on the last hop of a jump. The jump is
// BLOCKED and cites that hop's rule; it was UNKNOWN (one direct hop that no
// rule overlapped) before.
func TestJumpBlockedCitesTheBlockingHop(t *testing.T) {
	t.Parallel()
	result := jumpScan(t, jumpKnowledge(t, nil), kafkaV1beta2Doc)
	path, jump := strimziJump(t, result.Report)
	if result.Exit != 10 || result.Report.Verdict != scanreport.VerdictBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != crdLineRuleID {
		t.Fatalf("exit %d verdict %s findings %+v gaps %v", result.Exit, result.Report.Verdict, result.Report.Findings, gapReasons(result.Report))
	}
	if len(path.Hops) != 2 || path.Hops[0].To.Version != "0.50.1" || path.Hops[1].From.Version != "0.50.1" || result.Report.Findings[0].Hop.Index != 2 {
		t.Fatalf("path %+v finding hop %+v", path.Hops, result.Report.Findings[0].Hop)
	}
	if jump == nil || jump.Status != scanreport.JumpBlocked || !reflect.DeepEqual(jump.DecidedBy, []int{2}) || len(jump.Hops) != 2 {
		t.Fatalf("jump %+v", jump)
	}
	if h := jump.Hops[0]; h.Status != scanreport.JumpHopPass || h.From != "0.49.0" || h.To != "0.50.1" {
		t.Fatalf("hop 1 %+v", h)
	}
	if h := jump.Hops[1]; h.Status != scanreport.JumpHopBlocked || !reflect.DeepEqual(h.RuleIDs, []string{crdLineRuleID}) {
		t.Fatalf("hop 2 %+v", h)
	}
	if len(jump.Releases) != 1 || jump.Releases[0] != (scanreport.JumpRelease{Line: "0.50", Version: "0.50.1", Commit: jumpCommit("0.50.1")}) {
		t.Fatalf("releases %+v", jump.Releases)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(jsonOf(t, result.Report)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	schema := readSchema(t)
	conform(t, schema, schema, value, "jump report")
	text := jumpText(result.Report)
	for _, want := range []string{"BLOCKED on the stepwise path (hop 2 decides); a direct skip was not evaluated", "hop 1 0.49.0 -> 0.50.1: PASS", "hop 2 0.50.1 -> 0.51.0: BLOCKED " + crdLineRuleID, jumpCommit("0.50.1")} {
		if !strings.Contains(text, want) {
			t.Fatalf("text lacks %q:\n%s", want, text)
		}
	}
}

// The review of the middle line is missing: the first hop is named
// undecided, and the blocker of the last hop still decides.
func TestJumpBlockedBesideAnUndecidedHop(t *testing.T) {
	t.Parallel()
	k := jumpKnowledge(t, nil)
	k.attestations = lineattest.NewIndex([]lineattest.LineAttestation{jumpAtt("0.51", jumpReleases("0.50.0", "0.50.1"), jumpReleases("0.51.0"), "", crdLineRuleID)})
	result := jumpScan(t, k, kafkaV1beta2Doc)
	_, jump := strimziJump(t, result.Report)
	if result.Exit != 10 || jump == nil || jump.Status != scanreport.JumpBlocked || !reflect.DeepEqual(jump.DecidedBy, []int{2}) {
		t.Fatalf("exit %d jump %+v", result.Exit, jump)
	}
	if h := jump.Hops[0]; h.Status != scanreport.JumpHopUndecided || !reflect.DeepEqual(h.Reasons, []string{scanreport.ReasonLineNotAttested}) {
		t.Fatalf("hop 1 %+v", h)
	}
	if len(jump.Missing) < 1 || jump.Missing[0].Hop != 1 || !strings.Contains(jump.Missing[0].Evidence, "LINE_NOT_ATTESTED") || jump.Missing[0].Action == "" {
		t.Fatalf("missing %+v", jump.Missing)
	}
	if !hasGap(result.Report, "LINE_NOT_ATTESTED", "no review of the custom-resource versions of line 0.50") {
		t.Fatalf("gaps %v", gapReasons(result.Report))
	}
}

// One undecided hop and no blocker: UNKNOWN, with every hop listed and the
// undecided one named with the action. Never a bare UNKNOWN.
func TestJumpUnknownNamesTheUndecidedHop(t *testing.T) {
	t.Parallel()
	k := jumpKnowledge(t, nil)
	k.attestations = lineattest.NewIndex([]lineattest.LineAttestation{jumpAtt("0.51", jumpReleases("0.50.0", "0.50.1"), jumpReleases("0.51.0"), "", crdLineRuleID)})
	result := jumpScan(t, k, kafkaV1Doc)
	_, jump := strimziJump(t, result.Report)
	if result.Exit != 11 || jump == nil || jump.Status != scanreport.JumpUnknown || len(jump.Hops) != 2 || len(jump.DecidedBy) != 0 {
		t.Fatalf("exit %d jump %+v", result.Exit, jump)
	}
	for _, h := range jump.Hops {
		if h.Status != scanreport.JumpHopUndecided || len(h.Reasons) == 0 {
			t.Fatalf("hop %+v", h)
		}
	}
	if len(jump.Missing) != 2 || jump.Missing[0].Hop != 1 || jump.Missing[1].Hop != 2 || jump.Missing[0].Action == "" || jump.Missing[1].Action == "" {
		t.Fatalf("missing %+v", jump.Missing)
	}
	text := jumpText(result.Report)
	for _, want := range []string{"UNKNOWN, at least one hop of the stepwise path is not decided; every hop is listed", "hop 1 ", "hop 2 ", "missing for hop 1", "missing for hop 2"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text lacks %q:\n%s", want, text)
		}
	}
}

// Every hop decided PASS on one object set: STEPWISE_PASS, scoped, and the
// report stays UNKNOWN (exit 11): a jump never covers the component.
func TestJumpStepwisePass(t *testing.T) {
	t.Parallel()
	result := jumpScan(t, jumpKnowledge(t, nil), kafkaV1Doc)
	path, jump := strimziJump(t, result.Report)
	if jump == nil || jump.Status != scanreport.JumpStepwisePass || !reflect.DeepEqual(jump.DecidedBy, []int{1, 2}) || len(jump.Missing) != 0 {
		t.Fatalf("jump %+v", jump)
	}
	if result.Exit != 11 || result.Report.Verdict != scanreport.VerdictUnknown || len(result.Report.Findings) != 0 {
		t.Fatalf("exit %d verdict %s", result.Exit, result.Report.Verdict)
	}
	if jump.ObjectSetDigest == "" {
		t.Fatal("no object-set digest")
	}
	for _, h := range jump.Hops {
		if h.ObjectSetDigest != jump.ObjectSetDigest || h.Status != scanreport.JumpHopPass {
			t.Fatalf("hop %+v", h)
		}
	}
	if path.Policy != "" {
		t.Fatalf("policy %q: no reviewed policy exists", path.Policy)
	}
	text := jumpText(result.Report)
	for _, want := range []string{"STEPWISE_PASS", "not a statement about a direct jump", "as they are today", "a direct skip of a release line", "path goes through 0.50.1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text lacks %q:\n%s", want, text)
		}
	}
	for _, line := range strings.Split(strings.ToLower(text), "\n") {
		if strings.Contains(line, "direct") && (strings.Contains(line, "safe") || strings.Contains(line, "compatible")) {
			t.Fatalf("direct and safe wording: %q", line)
		}
	}
	// Replay: the recorded jump recomputes to itself.
	raw, _ := json.Marshal(jump)
	var back scanreport.Jump
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if status, by := scanreport.ComposeJump(back.Hops, back.ObjectSetDigest); status != back.Status || !reflect.DeepEqual(by, back.DecidedBy) {
		t.Fatalf("replay %s %v", status, by)
	}
}

// The jump never changes what the report says about the same scan: the
// verdict, exit code, findings and gaps are those of the report without it.
func TestJumpDoesNotChangeVerdictOrExit(t *testing.T) {
	t.Parallel()
	for _, doc := range []string{kafkaV1Doc, kafkaV1beta2Doc} {
		result := jumpScan(t, jumpKnowledge(t, nil), doc)
		stripped := result.Report
		stripped.Paths = append([]scanreport.Path(nil), result.Report.Paths...)
		for i := range stripped.Paths {
			stripped.Paths[i].Jump = nil
		}
		if scanreport.Exit(stripped) != scanreport.Exit(result.Report) || stripped.Verdict != result.Report.Verdict || result.Exit != scanreport.Exit(result.Report) {
			t.Fatalf("exit/verdict differ with the jump: %d %d %s", scanreport.Exit(stripped), scanreport.Exit(result.Report), result.Report.Verdict)
		}
	}
}

// Wrong PASS stays zero: each of these mutations must leave the jump below
// STEPWISE_PASS.
func TestJumpNeverWrongPass(t *testing.T) {
	t.Parallel()
	staleUntil := "2026-09-30T00:00:00Z"
	cases := map[string]struct {
		mutate func(a50, a51 *lineattest.LineAttestation)
		extra  []string
		doc    string
		// incomplete leaves --resource-scope-complete out.
		incomplete bool
	}{
		"stale middle review": {mutate: func(a50, _ *lineattest.LineAttestation) { a50.Evidence.ValidUntil = staleUntil }},
		"stale last review":   {mutate: func(_, a51 *lineattest.LineAttestation) { a51.Evidence.ValidUntil = staleUntil }},
		"no common release": {mutate: func(a50, a51 *lineattest.LineAttestation) {
			a50.Releases.To = jumpReleases("0.50.0")
			a51.Releases.From = jumpReleases("0.50.1")
		}},
		"commit differs": {mutate: func(_, a51 *lineattest.LineAttestation) {
			a51.Releases.From = []lineattest.Release{{Version: "0.50.0", Commit: strings.Repeat("a", 40)}, {Version: "0.50.1", Commit: strings.Repeat("b", 40)}}
		}},
		"start release not read": {mutate: func(a50, _ *lineattest.LineAttestation) { a50.Releases.From = jumpReleases("0.49.1") }},
		"target release not read": {mutate: func(_, a51 *lineattest.LineAttestation) {
			a51.Releases.To = jumpReleases("0.51.1")
		}},
		"set not declared complete": {incomplete: true},
		"basis left out":            {extra: []string{"--require-basis", "mechanical"}},
		"foreign object group":      {doc: kafkaV1Doc + "---\n" + unownedGroupDoc},
	}
	for name, tc := range cases {
		doc := tc.doc
		if doc == "" {
			doc = kafkaV1Doc
		}
		args := []string{"--from", "strimzi=0.49.0", "--to", "strimzi=0.51.0"}
		if !tc.incomplete {
			args = append(args, "--resource-scope-complete")
		}
		args = append(args, tc.extra...)
		result := crdScan(t, jumpKnowledge(t, tc.mutate), []string{settingsDoc, doc}, args...)
		_, jump := strimziJump(t, result.Report)
		if jump != nil && jump.Status == scanreport.JumpStepwisePass {
			t.Errorf("%s: STEPWISE_PASS %+v", name, jump)
		}
		if result.Report.Verdict == scanreport.VerdictPass || result.Exit == 0 {
			t.Errorf("%s: verdict %s exit %d", name, result.Report.Verdict, result.Exit)
		}
		if jump != nil && jump.Status == scanreport.JumpUnknown && (len(jump.Hops) != 2 || len(jump.Missing) == 0) {
			t.Errorf("%s: bare unknown %+v", name, jump)
		}
	}
}

// A policy that allows a direct hop, a jump across a major line and an
// adjacent upgrade are not decomposed: the plan is the one the run had.
func TestJumpNotDecomposed(t *testing.T) {
	t.Parallel()
	direct := jumpPolicyKnowledge{Knowledge: jumpKnowledge(t, nil), status: crdPolicy(t, "direct")}
	result := jumpScan(t, direct, kafkaV1Doc)
	path, jump := strimziJump(t, result.Report)
	if jump != nil || len(path.Hops) != 1 || result.Exit == 0 {
		t.Fatalf("direct policy: hops %d jump %+v exit %d", len(path.Hops), jump, result.Exit)
	}
	// Across a major line the last minor of the old major is unknown.
	result = crdScan(t, jumpKnowledge(t, nil), []string{settingsDoc, kafkaV1Doc}, "--from", "strimzi=0.51.0", "--to", "strimzi=1.2.0", "--resource-scope-complete")
	if _, jump := strimziJump(t, result.Report); jump != nil || result.Exit == 0 {
		t.Fatalf("major: jump %+v exit %d", jump, result.Exit)
	}
	// One minor line: the single hop is not a jump.
	result = crdScan(t, jumpKnowledge(t, nil), []string{settingsDoc, kafkaV1Doc}, "--from", "strimzi=0.50.1", "--to", "strimzi=0.51.0", "--resource-scope-complete")
	if _, jump := strimziJump(t, result.Report); jump != nil {
		t.Fatalf("adjacent: jump %+v", jump)
	}
	// A reviewed sequential_minor policy decomposes the same way and names
	// itself.
	sequential := jumpPolicyKnowledge{Knowledge: jumpKnowledge(t, nil), status: crdPolicy(t, "sequential_minor")}
	result = jumpScan(t, sequential, kafkaV1beta2Doc)
	path, jump = strimziJump(t, result.Report)
	if jump == nil || jump.Status != scanreport.JumpBlocked || path.Policy != "sequential_minor" || result.Exit != 10 {
		t.Fatalf("sequential_minor: policy %q jump %+v exit %d", path.Policy, jump, result.Exit)
	}
}

// Wholly deterministic: the same scan twice is the same report.
func TestJumpDeterministic(t *testing.T) {
	t.Parallel()
	a := jumpScan(t, jumpKnowledge(t, nil), kafkaV1beta2Doc)
	b := jumpScan(t, jumpKnowledge(t, func(a50, a51 *lineattest.LineAttestation) {}), kafkaV1beta2Doc)
	ja, _ := json.Marshal(a.Report.Paths)
	jb, _ := json.Marshal(b.Report.Paths)
	if string(ja) != string(jb) {
		t.Fatal("reports differ")
	}
}

func crdPolicy(t *testing.T, policy string) upgradepath.Status {
	t.Helper()
	records, err := upgradepath.Parse([]byte(fmt.Sprintf(`[{"component":%q,"policy":%q,"evidence":{"state":"active",%s,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}}]`, crdComponent, policy, basisFields("", currentReviewed), currentReviewed, currentUntil, testSource)))
	if err != nil {
		t.Fatal(err)
	}
	instant, _ := time.Parse(time.RFC3339, testNow)
	return upgradepath.NewIndex(records).Lookup(crdComponent, instant)
}

// jumpPolicyKnowledge answers one component's path policy.
type jumpPolicyKnowledge struct {
	Knowledge
	status upgradepath.Status
}

func (k jumpPolicyKnowledge) PathPolicyFor(string, time.Time) upgradepath.Status { return k.status }

// jumpLeadRule is a lead rule over the line-wide range of crdLineRule: it
// overlaps the hop into 0.51 and decides nothing.
var jumpLeadRule = strings.NewReplacer(crdLineRuleID, "strimzi.synthetic-lead.kafkatopics.0-50-0-to-0-51-0",
	`"kafka.strimzi.io/v1beta2/Kafka"`, `"kafka.strimzi.io/v1beta2/KafkaTopic"`,
	`"state":"active",`, `"state":"active","basis":"lead","derivedAt":"2026-09-23T00:00:00Z",`).Replace(crdLineRule)

// A notice or lead rule that overlaps a hop decides nothing: the hop is never
// a pass, so the jump is never STEPWISE_PASS even when the review of every
// line decides its own rules. A decided notice makes the hop ATTENTION and
// cites the rule.
func TestJumpNoticeOrLeadNeverPasses(t *testing.T) {
	t.Parallel()
	// A lead rule over the hop, through a real scan.
	result := jumpScan(t, jumpKnowledge(t, nil, jumpLeadRule), kafkaV1Doc)
	_, jump := strimziJump(t, result.Report)
	if jump == nil || jump.Status != scanreport.JumpUnknown || jump.Hops[1].Status != scanreport.JumpHopUndecided || len(jump.Hops[1].Reasons) == 0 || len(jump.Missing) == 0 {
		t.Fatalf("lead: %+v", jump)
	}
	if result.Exit == 0 || result.Report.Verdict == scanreport.VerdictPass {
		t.Fatalf("lead: verdict %s exit %d", result.Report.Verdict, result.Exit)
	}
	// The composition over hop decisions: every hop's review decided PASS.
	pass := &scanreport.FamilyResult{Family: lineattest.FamilyCustomResourceVersions, Status: scanreport.FamilyPass}
	compose := func(neutral ...neutralRule) scanreport.Jump {
		run := &customResourceRun{knowledge: jumpKnowledge(t, nil), report: &scanreport.Report{}, slug: "strimzi", component: crdComponent, now: parseNow(t)}
		path := scanreport.Path{Component: "strimzi", Hops: []scanreport.Hop{
			{Index: 1, From: scanreport.Endpoint{Version: "0.49.0"}, To: scanreport.Endpoint{Version: "0.50.1"}},
			{Index: 2, From: scanreport.Endpoint{Version: "0.50.1"}, To: scanreport.Endpoint{Version: "0.51.0"}},
		}}
		run.composeJump(&path, upgradepath.Plan{}, []hopDecision{
			{family: pass, setDigest: "sha256:1"},
			{family: pass, setDigest: "sha256:1", neutral: neutral},
		})
		return *path.Jump
	}
	if j := compose(); j.Status != scanreport.JumpStepwisePass {
		t.Fatalf("control: %+v", j)
	}
	j := compose(neutralRule{id: "strimzi.synthetic-notice", text: "review the objects", noticed: true})
	if j.Status != scanreport.JumpAttention || j.Hops[1].Status != scanreport.JumpHopAttention || len(j.Hops[1].Entries) != 1 || !strings.HasPrefix(j.Hops[1].Entries[0], "strimzi.synthetic-notice: ") {
		t.Fatalf("notice: %+v", j)
	}
	for _, mixed := range [][]neutralRule{
		{{id: "strimzi.synthetic-lead"}},
		{{id: "strimzi.synthetic-notice", noticed: true}, {id: "strimzi.synthetic-lead"}},
	} {
		j := compose(mixed...)
		if j.Status == scanreport.JumpStepwisePass || j.Status == scanreport.JumpAttention || j.Hops[1].Status != scanreport.JumpHopUndecided || len(j.Missing) != 1 {
			t.Fatalf("lead among the rules: %+v", j)
		}
	}
}

// Objects of the same names with other content are another object set: the
// digest differs, so a jump whose hops carried them would not compose.
func TestObjectSetDigestCoversContent(t *testing.T) {
	t.Parallel()
	digest := func(doc string) string {
		workspace, err := intake.Decode("input", []byte(settingsDoc+"---\n"+doc))
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := cncfprepare.PrepareCustomResourceVersions(workspace, "strimzi", "0.50.1", "0.51.0", true)
		if err != nil {
			t.Fatal(err)
		}
		return objectSetDigest(prepared.Fact, prepared, true, workspace)
	}
	a := digest(kafkaV1Doc)
	b := digest(kafkaV1Doc + "spec:\n  replicas: 3\n")
	if a == b || a != digest(kafkaV1Doc) {
		t.Fatalf("digests %s %s", a, b)
	}
	hops := []scanreport.JumpHop{
		{Index: 1, From: "0.49.0", To: "0.50.1", Status: scanreport.JumpHopPass, ObjectSetDigest: a},
		{Index: 2, From: "0.50.1", To: "0.51.0", Status: scanreport.JumpHopPass, ObjectSetDigest: b},
	}
	jump := scanreport.NewJump(hops, a, nil, nil)
	if jump.Status != scanreport.JumpUnknown || len(jump.Hops) != 2 || len(jump.Missing) != 1 || jump.Missing[0].Hop != 2 {
		t.Fatalf("jump on different object sets: %+v", jump)
	}
}
