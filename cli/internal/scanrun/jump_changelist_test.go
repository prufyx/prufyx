// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Jumps of a component of the change-list families (etcd, with test-only
// records; never published): the records of lines 3.5 and 3.6 list the
// change lists of every final release of the line.

const (
	clComponent = "pkg:github/etcd-io/etcd"
	clSlug      = "etcd"
)

func clCommit(version string) string { return jumpCommit("etcd " + version) }

func clRelease(versions ...string) []lineattest.Release {
	var out []lineattest.Release
	for _, v := range versions {
		out = append(out, lineattest.Release{Version: v, Commit: clCommit(v)})
	}
	return out
}

func clRecord(family, line string, from, to []string) lineattest.LineAttestation {
	a := lineattest.LineAttestation{
		Component: clComponent, Line: line, FactFamily: family, Completeness: lineattest.Completeness, RuleIDs: []string{},
		Releases: &lineattest.Releases{From: clRelease(from...), To: clRelease(to...)},
		Evidence: lineattest.Evidence{
			Basis: constraintengine.BasisMechanical, ReviewedAt: "2026-09-25T00:00:00Z", ValidUntil: "2026-12-20T00:00:00Z", DerivedAt: "2026-09-25T00:00:00Z",
			Extractor: &constraintengine.Extractor{ID: "changelog.listed.etcd", Version: "1.0.0", CodeDigest: "sha256:" + strings.Repeat("c", 64)},
		},
	}
	for i, v := range to {
		a.Evidence.Sources = append(a.Evidence.Sources, constraintengine.SourceEvidence{
			ID: "changelog-" + v, URL: "https://github.com/etcd-io/etcd/blob/" + clCommit(v) + "/CHANGELOG/CHANGELOG-" + line + ".md",
			Revision: clCommit(v), ContentDigest: "sha256:" + strings.Repeat("0", 63) + string(rune('1'+i)), StartLine: 10 + i, EndLine: 20 + i,
		})
	}
	if err := a.Validate(); err != nil {
		panic(err)
	}
	return a
}

func clRecords() (r35, r36 lineattest.LineAttestation) {
	return clRecord(lineattest.FamilyChangelogListedEntries, "3.5", []string{"3.4.0", "3.4.1"}, []string{"3.5.0", "3.5.1"}),
		clRecord(lineattest.FamilyChangelogListedEntries, "3.6", []string{"3.5.0", "3.5.1"}, []string{"3.6.0", "3.6.1"})
}

type clKnowledge struct {
	Knowledge
	index lineattest.Index
}

func (k clKnowledge) AttestationsFor(component, line, family string, now time.Time) []lineattest.Status {
	if component == clComponent && (family == lineattest.FamilyChangelogListedEntries || family == lineattest.FamilyChangelogAttestedEntries) {
		return k.index.AttestationsFor(component, line, family, now)
	}
	return k.Knowledge.AttestationsFor(component, line, family, now)
}

func clScan(t *testing.T, records ...lineattest.LineAttestation) Result {
	t.Helper()
	k := clKnowledge{Knowledge: newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"}), index: lineattest.NewIndex(records)}
	_, paths := files(t, map[string]string{"cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: m}\n"})
	return mustScan(t, k, args(paths, "--from", "etcd=3.4.0", "--to", "etcd=3.6.0")...)
}

func clJump(t *testing.T, report scanreport.Report) (scanreport.Path, *scanreport.Jump) {
	t.Helper()
	for _, path := range report.Paths {
		if path.Component == clSlug {
			return path, path.Jump
		}
	}
	return scanreport.Path{}, nil
}

// requireClUnchanged: the answer for the component is what it was without a
// jump: UNKNOWN, exit 11, the component not covered.
func requireClUnchanged(t *testing.T, result Result) {
	t.Helper()
	if result.Exit != scanreport.ExitUnknown || result.Report.Verdict != scanreport.VerdictUnknown || len(result.Report.Findings) != 0 ||
		!hasComponentGap(result.Report, clSlug, scanreport.ReasonComponentNotCovered, "") {
		t.Fatalf("exit %d verdict %s findings %d gaps %v", result.Exit, result.Report.Verdict, len(result.Report.Findings), gapReasons(result.Report))
	}
}

func TestChangeListJumpAttention(t *testing.T) {
	t.Parallel()
	r35, r36 := clRecords()
	result := clScan(t, r35, r36)
	requireClUnchanged(t, result)
	_, jump := clJump(t, result.Report)
	if jump == nil || jump.Status != scanreport.JumpAttention || len(jump.Hops) != 2 || len(jump.DecidedBy) != 2 {
		t.Fatalf("jump %+v", jump)
	}
	// The intermediate end is read from the records' own windows.
	if h := jump.Hops[0]; h.From != "3.4.0" || h.To != "3.5.1" || h.Status != scanreport.JumpHopAttention || len(h.Entries) != 2 {
		t.Fatalf("hop 1 %+v", h)
	}
	if h := jump.Hops[1]; h.From != "3.5.1" || h.To != "3.6.0" || h.Status != scanreport.JumpHopAttention || len(h.Entries) != 1 {
		t.Fatalf("hop 2 %+v", h)
	}
	if len(jump.Releases) != 1 || jump.Releases[0] != (scanreport.JumpRelease{Line: "3.5", Version: "3.5.1", Commit: clCommit("3.5.1")}) {
		t.Fatalf("releases %+v", jump.Releases)
	}
	// The exact wording and citation; the release after the hop's end is not cited.
	want := "the change list of 3.6.0 lists changes for etcd; read them before upgrading (https://github.com/etcd-io/etcd/blob/" + clCommit("3.6.0") +
		"/CHANGELOG/CHANGELOG-3.6.md, commit " + clCommit("3.6.0") + ", digest sha256:" + strings.Repeat("0", 63) + "1, lines 10-20)"
	if jump.Hops[1].Entries[0] != want {
		t.Fatalf("entry %q", jump.Hops[1].Entries[0])
	}
	text := string(scanreport.Human(result.Report, scanreport.HumanOptions{Verbose: true}))
	for _, bad := range []string{"STEPWISE_PASS", "affects you", "safe"} {
		if strings.Contains(text, bad) {
			t.Fatalf("text has %q:\n%s", bad, text)
		}
	}
	if !strings.Contains(text, "ATTENTION on the stepwise path") || !strings.Contains(text, "hop 2 3.5.1 -> 3.6.0: ATTENTION") {
		t.Fatalf("text:\n%s", text)
	}
}

func TestChangeListJumpMissingRecord(t *testing.T) {
	t.Parallel()
	r35, r36 := clRecords()
	// No record of the middle line: that hop is undecided and named, the
	// other hop still shows its change list, and no intermediate is guessed.
	result := clScan(t, r36)
	requireClUnchanged(t, result)
	path, jump := clJump(t, result.Report)
	if jump == nil || jump.Status != scanreport.JumpAttention || len(jump.Releases) != 0 {
		t.Fatalf("jump %+v", jump)
	}
	if h := jump.Hops[0]; h.Status != scanreport.JumpHopUndecided || len(h.Reasons) == 0 || h.To != "3.5" {
		t.Fatalf("hop 1 %+v", h)
	}
	if h := jump.Hops[1]; h.Status != scanreport.JumpHopAttention || h.From != "3.5" || len(h.Entries) != 1 {
		t.Fatalf("hop 2 %+v", h)
	}
	if len(jump.Missing) != 1 || jump.Missing[0].Hop != 1 || jump.Missing[0].Action == "" || len(path.Hops) != 2 {
		t.Fatalf("missing %+v", jump.Missing)
	}
	// Only the first of the two lines has no record.
	result = clScan(t, r35)
	_, jump = clJump(t, result.Report)
	if jump == nil || jump.Status != scanreport.JumpAttention || jump.Hops[1].Status != scanreport.JumpHopUndecided || jump.Hops[0].Status != scanreport.JumpHopAttention {
		t.Fatalf("jump %+v", jump)
	}
}

func TestChangeListJumpNoRecordIsUnknownNeverPass(t *testing.T) {
	t.Parallel()
	result := clScan(t)
	requireClUnchanged(t, result)
	path, jump := clJump(t, result.Report)
	if jump == nil || jump.Status != scanreport.JumpUnknown || len(jump.Hops) != 2 || len(jump.Missing) != 2 || len(path.Hops) != 2 {
		t.Fatalf("jump %+v", jump)
	}
	for _, h := range jump.Hops {
		if h.Status != scanreport.JumpHopUndecided || len(h.Entries) != 0 || len(h.Reasons) == 0 {
			t.Fatalf("hop %+v", h)
		}
	}
}

// R4: a record that fails validation never gives ATTENTION.
func TestChangeListJumpMalformedRecordIsUndecided(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(a *lineattest.LineAttestation){
		"source at another commit": func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].Revision = strings.Repeat("e", 40) },
		"digest not a digest":      func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].ContentDigest = "abc" },
		"span reversed": func(a *lineattest.LineAttestation) {
			a.Evidence.Sources[0].StartLine, a.Evidence.Sources[0].EndLine = 9, 3
		},
		"span from zero":            func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].StartLine = 0 },
		"source id not an entry":    func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].ID = "crds-3-5-0" },
		"source of another release": func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].ID = "changelog-3.9.9" },
		"release without a source":  func(a *lineattest.LineAttestation) { a.Evidence.Sources = a.Evidence.Sources[:1] },
		"duplicate source":          func(a *lineattest.LineAttestation) { a.Evidence.Sources[1] = a.Evidence.Sources[0] },
		"no sources":                func(a *lineattest.LineAttestation) { a.Evidence.Sources = nil },
		"no releases":               func(a *lineattest.LineAttestation) { a.Releases = nil },
		"empty url":                 func(a *lineattest.LineAttestation) { a.Evidence.Sources[0].URL = "" },
		"expired":                   func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "2026-10-01T00:00:00Z" },
		"another component":         func(a *lineattest.LineAttestation) { a.Component = "pkg:github/prometheus/prometheus" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r35, r36 := clRecords()
			mutate(&r35)
			result := clScan(t, r35, r36)
			requireClUnchanged(t, result)
			_, jump := clJump(t, result.Report)
			if jump == nil {
				t.Fatal("no jump")
			}
			for _, h := range jump.Hops {
				if h.Status == scanreport.JumpHopAttention && len(h.Entries) > 0 && strings.Contains(strings.Join(h.Entries, ""), "CHANGELOG-3.5.md") {
					t.Fatalf("malformed record cited: %+v", h)
				}
			}
			if h := jump.Hops[0]; h.Status != scanreport.JumpHopUndecided || len(h.Entries) != 0 || len(h.Reasons) == 0 {
				t.Fatalf("hop 1 %+v", h)
			}
		})
	}
}

// No version of the line named by the hop falls in its window: not cited.
func TestChangeListJumpWindowAndNoPass(t *testing.T) {
	t.Parallel()
	r35, r36 := clRecords()
	result := clScan(t, r35, r36)
	_, jump := clJump(t, result.Report)
	joined := strings.Join(jump.Hops[1].Entries, " ")
	if strings.Contains(joined, "3.6.1") || strings.Contains(joined, "3.5.") {
		t.Fatalf("hop 2 cites outside its window: %s", joined)
	}
	for _, h := range jump.Hops {
		if h.Status == scanreport.JumpHopPass {
			t.Fatalf("pass hop %+v", h)
		}
	}
	// Compose never yields a pass for hops with entries, whatever the input.
	if status, _ := scanreport.ComposeJump(jump.Hops, jump.ObjectSetDigest); status == scanreport.JumpStepwisePass {
		t.Fatal("stepwise pass")
	}
}

// R5: records change the table only; verdict and exit are those of a scan
// without records.
func TestChangeListJumpVerdictAndExitUnchanged(t *testing.T) {
	t.Parallel()
	r35, r36 := clRecords()
	with, without := clScan(t, r35, r36), clScan(t)
	if with.Exit != without.Exit || with.Report.Verdict != without.Report.Verdict || len(with.Report.Gaps) < 1 ||
		!hasComponentGap(with.Report, clSlug, scanreport.ReasonComponentNotCovered, "") {
		t.Fatalf("with %d %s, without %d %s", with.Exit, with.Report.Verdict, without.Exit, without.Report.Verdict)
	}
}

// A hop of one line, or of adjacent lines, and a custom-resource component
// get no change-list jump.
func TestChangeListJumpNotForOtherUpgrades(t *testing.T) {
	t.Parallel()
	r35, r36 := clRecords()
	k := clKnowledge{Knowledge: newKnowledge(t, knowledgeOptions{lines: allLines, policy: "current"}), index: lineattest.NewIndex([]lineattest.LineAttestation{r35, r36})}
	_, paths := files(t, map[string]string{"cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: m}\n"})
	for _, versions := range [][2]string{{"3.5.0", "3.6.0"}, {"3.5.0", "3.5.1"}} {
		result := mustScan(t, k, args(paths, "--from", "etcd="+versions[0], "--to", "etcd="+versions[1])...)
		// The undecided single hop is the not-covered path of any component;
		// it carries no change-list entries or attestation.
		path, jump := clJump(t, result.Report)
		if jump != nil && (len(path.Hops) != 1 || jump.Hops[0].Status != scanreport.JumpHopUndecided || len(jump.Hops[0].Entries) != 0 || jump.Hops[0].Attestation != nil) {
			t.Fatalf("%v: %+v", versions, jump)
		}
	}
	if family, _ := lineattest.LookupFamily(lineattest.FamilyCustomResourceVersions); family.Admits(clComponent) {
		t.Fatal("etcd is a custom-resource component")
	}
}

// A multi-minor jump of a change-list component has one path, not the
// change-list path and the not-covered path side by side.
func TestChangeListJumpOnePathPerComponent(t *testing.T) {
	t.Parallel()
	r35, r36 := clRecords()
	result := clScan(t, r35, r36)
	count := 0
	for _, path := range result.Report.Paths {
		if path.Component == clSlug {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d paths for %s", count, clSlug)
	}
}
