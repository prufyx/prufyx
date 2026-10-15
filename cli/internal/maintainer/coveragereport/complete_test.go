// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

var allNow = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

const (
	allReviewed = "2026-10-01T00:00:00Z"
	allUntil    = "2026-12-15T00:00:00Z"
	allCaptured = "2026-10-08"
)

func shippedID(t *testing.T, slug, family string) registration {
	t.Helper()
	for _, r := range registrations(slug) {
		if r.family == family {
			return r
		}
	}
	t.Fatalf("%s is not registered in %s", slug, family)
	return registration{}
}

func srcFor(url string) []constraintengine.SourceEvidence {
	return []constraintengine.SourceEvidence{{ID: "src-a", URL: fmt.Sprintf("https://github.com/%s/blob/%s/path/file.yaml", url, rev), Revision: rev, ContentDigest: "sha256:" + strings.Repeat("a", 64), StartLine: 1, EndLine: 10}}
}

// scenario describes one project, its snapshot and its attestations.
type scenario struct {
	slug       string
	family     string
	component  string
	repo       string
	lines      []string
	releases   map[string][]string
	capturedOn string
	// skip lists attested lines that get no attestation.
	skip map[string]bool
	// mutate changes an attestation before it is written.
	mutate   func(a *lineattest.LineAttestation)
	declared string
	// noSnapshotReleases drops the releases from the snapshot only.
	noSnapshotReleases bool
	extra              []string // extra pack entries (rules)
	ruleIDs            []string // rules every attestation lists
}

func (s scenario) attestation(t *testing.T, line, previous string) lineattest.LineAttestation {
	t.Helper()
	reg := shippedID(t, s.slug, s.family)
	digest, err := reg.digest()
	if err != nil {
		t.Fatal(err)
	}
	ids := s.ruleIDs
	if ids == nil {
		ids = []string{}
	}
	a := lineattest.LineAttestation{
		Component: s.component, Line: line, FactFamily: s.family, Completeness: lineattest.Completeness, RuleIDs: ids,
		Evidence: lineattest.Evidence{
			Basis:      constraintengine.BasisMechanical,
			Extractor:  &constraintengine.Extractor{ID: reg.extractorID, Version: reg.version, CodeDigest: digest},
			DerivedAt:  allReviewed,
			ReviewedAt: allReviewed,
			ValidUntil: allUntil,
			Sources:    srcFor(s.repo),
		},
	}
	if f, _ := lineattest.LookupFamily(s.family); f.ReleaseScoped() {
		rel := func(vs []string) []lineattest.Release {
			var out []lineattest.Release
			for _, v := range vs {
				out = append(out, lineattest.Release{Version: v, Commit: rev})
			}
			return out
		}
		a.Releases = &lineattest.Releases{From: rel(s.releases[previous]), To: rel(s.releases[line])}
	}
	if s.mutate != nil {
		s.mutate(&a)
	}
	return a
}

func (s scenario) report(t *testing.T) Report {
	t.Helper()
	var atts []lineattest.LineAttestation
	for i := 1; i < len(s.lines); i++ {
		prev, ok := previousLine(s.lines[i])
		if !ok || prev != s.lines[i-1] || s.skip[s.lines[i]] {
			continue
		}
		atts = append(atts, s.attestation(t, s.lines[i], prev))
	}
	section := ""
	if len(atts) > 0 {
		raw, err := lineattest.Marshal(atts)
		if err != nil {
			t.Fatal(err)
		}
		section = `,"lineAttestations":` + string(raw)
	}
	packBytes := []byte(`{"schema":"test","revision":"synthetic","entries":[` + strings.Join(s.extra, ",") + `]` + section + `}`)
	file := LinesFile{Schema: LinesSchema, CapturedOn: s.capturedOn, Projects: map[string]ProjectLines{}}
	if len(s.lines) > 0 {
		pl := ProjectLines{Lines: s.lines, Releases: s.releases}
		if s.noSnapshotReleases {
			pl.Releases = nil
		}
		file.Projects[s.slug] = pl
	} else {
		file.Projects["other"] = ProjectLines{Lines: []string{"1.0", "1.1"}}
	}
	linesBytes, err := MarshalLines(file)
	if err != nil {
		t.Fatal(err)
	}
	in := Input{Pack: packBytes, Lines: linesBytes, Now: allNow, All: true}
	if s.declared != "" {
		in.Declared = []byte(s.declared)
	}
	report, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func (s scenario) project(t *testing.T) Project {
	t.Helper()
	report := s.report(t)
	for _, p := range report.Projects {
		if p.Project == s.slug {
			return p
		}
	}
	t.Fatalf("no row for %s", s.slug)
	return Project{}
}

func k8sScenario(lines ...string) scenario {
	return scenario{slug: "kubernetes", family: lineattest.FamilyKubernetesRemovedServedGVK, component: "pkg:github/kubernetes/kubernetes", repo: "kubernetes/kubernetes", lines: lines, capturedOn: allCaptured}
}

func strimziScenario(lines ...string) scenario {
	return scenario{slug: "strimzi", family: lineattest.FamilyCustomResourceVersions, component: "pkg:github/strimzi/strimzi-kafka-operator", repo: "strimzi/strimzi-kafka-operator", lines: lines, capturedOn: allCaptured,
		releases: map[string][]string{"0.49": {"0.49.0", "0.49.1"}, "0.50": {"0.50.0"}, "0.51": {"0.51.0", "0.51.1"}}}
}

func declJSON(records ...string) string {
	return `{"schema":"` + DeclaredSchema + `","declarations":[` + strings.Join(records, ",") + `]}`
}

func declRecord(project, family, from, to, reason, until string) string {
	return fmt.Sprintf(`{"project":%q,"family":%q,"from":%q,"to":%q,"reason":%q,"note":"reviewed","declaredAt":"2026-10-01T00:00:00Z","validUntil":%q}`, project, family, from, to, reason, until)
}

func assertComplete(t *testing.T, p Project, want bool, reason string) {
	t.Helper()
	if p.Complete != want {
		t.Fatalf("complete = %v, want %v (counts %+v, reasons %v)", p.Complete, want, p.Counts, p.Reasons)
	}
	if reason != "" {
		for _, r := range p.Reasons {
			if r == reason {
				return
			}
		}
		t.Fatalf("reasons %v lack %q", p.Reasons, reason)
	}
	if want && len(p.Reasons) != 0 {
		t.Fatalf("complete with reasons %v", p.Reasons)
	}
}

func TestCompleteFixtures(t *testing.T) {
	good := k8sScenario("1.19", "1.20", "1.21")
	p := good.project(t)
	assertComplete(t, p, true, "")
	if p.Counts != (Counts{LinesTotal: 3, Decided: 2}) {
		t.Fatalf("counts = %+v", p.Counts)
	}
	if len(p.FamilyCounts) != 1 || p.FamilyCounts[0].Counts != p.Counts {
		t.Fatalf("family counts = %+v", p.FamilyCounts)
	}
	// A release-scoped family is compared with the snapshot's releases.
	assertComplete(t, strimziScenario("0.49", "0.50", "0.51").project(t), true, "")
	if got := good.report(t).CompleteProjects(); strings.Join(got, ",") != "kubernetes" {
		t.Fatalf("complete projects = %v", got)
	}
}

// Clause (a): the lines come from a fresh, complete, untruncated snapshot.
func TestCompleteClauseA(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *scenario)
		reason string
	}{
		{"stale snapshot", func(s *scenario) { s.capturedOn = "2026-09-23" }, whySnapshotStale},
		{"undated snapshot", func(s *scenario) { s.capturedOn = "" }, whySnapshotUndated},
		{"snapshot from the future", func(s *scenario) { s.capturedOn = "2026-10-09" }, whySnapshotFuture},
		{"truncated snapshot", func(s *scenario) { s.lines = []string{"1.20", "1.21", "1.22"} }, whySnapshotTruncated},
		{"hole inside a major", func(s *scenario) { s.lines = []string{"1.19", "1.20", "1.22"} }, whySnapshotHole},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := k8sScenario("1.19", "1.20", "1.21")
			c.mutate(&s)
			assertComplete(t, s.project(t), false, c.reason)
		})
	}
	// The date counts from its midnight: 13.5 days old is fresh, 14.5 is stale.
	s := k8sScenario("1.19", "1.20", "1.21")
	s.capturedOn = "2026-09-25"
	assertComplete(t, s.project(t), true, "")
	s.capturedOn = "2026-09-24"
	assertComplete(t, s.project(t), false, whySnapshotStale)
	// A project that is not in the snapshot has no row and is never listed.
	absent := k8sScenario()
	report := absent.report(t)
	for _, p := range report.Projects {
		if p.Project == "kubernetes" {
			t.Fatal("absent project has a row")
		}
	}
	if len(report.CompleteProjects()) != 0 {
		t.Fatalf("complete projects = %v", report.CompleteProjects())
	}
	// A project without a registered family is never complete.
	raw, _ := MarshalLines(LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{"nothing-registered": {Lines: []string{"1.0", "1.1", "1.2"}}}})
	r, err := Compute(Input{Pack: pack(nil, nil), Lines: raw, Now: allNow, All: true})
	if err != nil {
		t.Fatal(err)
	}
	assertComplete(t, r.Projects[0], false, whyNoFamily)
	if r.Projects[0].LinesTotal != 3 {
		t.Fatalf("unregistered project window = %d lines, want all 3", r.Projects[0].LinesTotal)
	}
}

// Clause (b): each pair has an attestation for exactly its hop and releases.
func TestCompleteClauseB(t *testing.T) {
	cases := []struct {
		name string
		s    scenario
	}{
		{"missing attestation", func() scenario {
			s := k8sScenario("1.19", "1.20", "1.21")
			s.skip = map[string]bool{"1.21": true}
			return s
		}()},
		{"new major has no previous line", k8sScenario("1.19", "1.20", "2.0")},
		{"attestation names the wrong from line", func() scenario {
			s := k8sScenario("1.19", "1.20", "1.21")
			s.mutate = func(a *lineattest.LineAttestation) {
				if a.Line == "1.21" {
					a.Line = "1.22"
				}
			}
			return s
		}()},
		{"releases differ from the snapshot", func() scenario {
			s := strimziScenario("0.49", "0.50", "0.51")
			s.mutate = func(a *lineattest.LineAttestation) {
				if a.Line == "0.50" {
					a.Releases.From = a.Releases.From[:1]
				}
			}
			return s
		}()},
		{"attestation names a release the snapshot lacks", func() scenario {
			s := strimziScenario("0.49", "0.50", "0.51")
			s.mutate = func(a *lineattest.LineAttestation) {
				if a.Line == "0.50" {
					a.Releases.To = append(a.Releases.To, lineattest.Release{Version: "0.50.1", Commit: rev})
				}
			}
			return s
		}()},
		{"snapshot lists no releases", func() scenario { s := strimziScenario("0.49", "0.50", "0.51"); s.noSnapshotReleases = true; return s }()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.s.project(t)
			assertComplete(t, p, false, whyUndeclared)
			if p.Undeclared == 0 {
				t.Fatalf("undeclared = 0 (%+v)", p.Counts)
			}
		})
	}
}

func mechanicalRule(t *testing.T, id string, evidence string) string {
	t.Helper()
	return fmt.Sprintf(`{"project":"kubernetes","rule":{"id":%q,"operator":"forbid_predicate_value","subject":{"component":%q,"from":"1.19.0","to":"1.20.0"},%s,"condition":{"side":"proposed","component":%q,"factId":"component.kubernetes.cronjob_v1beta1_removed_gvk_present","boolValue":true},"evidence":%s}}`,
		id, k8s, rangeJSON("1.19.0", "1.20.0", "1.20.0", "1.21.0"), k8s, evidence)
}

// Clause (c): every cited source pins a 40-hex commit and a path.
func TestCompleteClauseC(t *testing.T) {
	reg := shippedID(t, "kubernetes", lineattest.FamilyKubernetesRemovedServedGVK)
	digest, err := reg.digest()
	if err != nil {
		t.Fatal(err)
	}
	evidence := func(source string, until string, extractor string) string {
		return fmt.Sprintf(`{"state":"active","basis":"mechanical","extractor":%s,"derivedAt":%q,"reviewedAt":%q,"validUntil":%q,"sources":[%s]}`, extractor, allReviewed, allReviewed, until, source)
	}
	goodExtractor := fmt.Sprintf(`{"id":%q,"version":%q,"codeDigest":%q}`, reg.extractorID, reg.version, digest)
	goodSource := fmt.Sprintf(`{"id":"src-a","url":"https://github.com/kubernetes/kubernetes/blob/%s/api/file.go","revision":%q,"contentDigest":"sha256:%s","startLine":1,"endLine":2}`, rev, rev, strings.Repeat("a", 64))
	badRevision := strings.ReplaceAll(goodSource, rev, "abc123")
	cases := []struct {
		name     string
		evidence string
		complete bool
	}{
		{"rule with pinned commit and path", evidence(goodSource, allUntil, goodExtractor), true},
		{"rule source without a 40-hex commit", evidence(badRevision, allUntil, goodExtractor), false},
		{"rule without sources", evidence("", allUntil, goodExtractor), false},
		{"rule with another extractor digest", evidence(goodSource, allUntil, fmt.Sprintf(`{"id":%q,"version":%q,"codeDigest":"sha256:%s"}`, reg.extractorID, reg.version, strings.Repeat("b", 64))), false},
		{"rule expiring within 14 days", evidence(goodSource, "2026-10-22T12:00:00Z", goodExtractor), false},
		{"reviewed rule", `{"state":"active","reviewedAt":"2026-10-01T00:00:00Z","validUntil":"2026-12-15T00:00:00Z"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := k8sScenario("1.19", "1.20", "1.21")
			s.extra = []string{mechanicalRule(t, "rule-one", c.evidence)}
			s.skip = map[string]bool{"1.21": true}
			// Only the pair into 1.20 lists the rule; 1.21 is declared unknown.
			s.declared = declJSON(declRecord("kubernetes", lineattest.FamilyKubernetesRemovedServedGVK, "1.20", "1.21", ReasonScanNotClean, "2026-12-15T00:00:00Z"))
			s.mutate = func(a *lineattest.LineAttestation) { a.RuleIDs = []string{"rule-one"} }
			assertComplete(t, s.project(t), c.complete, "")
		})
	}
	sources := func(s ...constraintengine.SourceEvidence) []constraintengine.SourceEvidence { return s }
	good := constraintengine.SourceEvidence{URL: "https://github.com/o/r/blob/" + rev + "/a/b.yaml", Revision: rev}
	for name, c := range map[string]struct {
		in   []constraintengine.SourceEvidence
		want bool
	}{
		"good":          {sources(good), true},
		"none":          {nil, false},
		"short commit":  {sources(constraintengine.SourceEvidence{URL: "https://github.com/o/r/blob/abc/a/b.yaml", Revision: "abc"}), false},
		"upper commit":  {sources(constraintengine.SourceEvidence{URL: "https://github.com/o/r/blob/" + strings.ToUpper(rev) + "/a", Revision: strings.Repeat("A", 40)}), false},
		"no path":       {sources(constraintengine.SourceEvidence{URL: "https://github.com/o/r/blob/" + rev + "/", Revision: rev}), false},
		"url not at it": {sources(constraintengine.SourceEvidence{URL: "https://github.com/o/r/blob/main/a", Revision: rev}), false},
		"one bad":       {sources(good, constraintengine.SourceEvidence{URL: "https://github.com/o/r/blob/x/a", Revision: "x"}), false},
	} {
		if got := sourcesCited(c.in); got != c.want {
			t.Errorf("%s: sourcesCited = %v, want %v", name, got, c.want)
		}
	}
}

// Clause (d): current, mechanical, from the shipped extractor, beyond the
// expiry horizon.
func TestCompleteClauseD(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(a *lineattest.LineAttestation)
		complete bool
	}{
		{"valid", func(a *lineattest.LineAttestation) {}, true},
		{"another code digest", func(a *lineattest.LineAttestation) {
			a.Evidence.Extractor.CodeDigest = "sha256:" + strings.Repeat("b", 64)
		}, false},
		{"another extractor version", func(a *lineattest.LineAttestation) { a.Evidence.Extractor.Version = "0.0.1" }, false},
		{"another extractor id", func(a *lineattest.LineAttestation) { a.Evidence.Extractor.ID = "other.extractor" }, false},
		{"reviewed basis", func(a *lineattest.LineAttestation) {
			a.Evidence.Basis, a.Evidence.Extractor, a.Evidence.DerivedAt = constraintengine.BasisReviewed, nil, ""
		}, false},
		{"expires in 13 days", func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "2026-10-21T12:00:00Z" }, false},
		{"expires in exactly 14 days", func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "2026-10-22T12:00:00Z" }, false},
		{"expires in 14 days and a second", func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "2026-10-22T12:00:01Z" }, true},
		{"expired", func(a *lineattest.LineAttestation) { a.Evidence.ValidUntil = "2026-10-05T00:00:00Z" }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := k8sScenario("1.19", "1.20", "1.21")
			s.mutate = c.mutate
			assertComplete(t, s.project(t), c.complete, "")
		})
	}
}

// Clause (e): every pair is decided or declared unknown; declared unknown
// needs a reviewed, current, valid record.
func TestCompleteClauseEAndDeclared(t *testing.T) {
	fam := lineattest.FamilyKubernetesRemovedServedGVK
	valid := declRecord("kubernetes", fam, "1.20", "1.21", ReasonGoDefinedCRDs, "2026-12-15T00:00:00Z")
	cases := []struct {
		name         string
		declared     string
		complete     bool
		invalid      int
		decided      int
		declaredN    int
		undeclaredN  int
		skipAttested bool
	}{
		{"nothing declared", "", false, 0, 1, 0, 1, true},
		{"valid declaration fills the pair", declJSON(valid), true, 0, 1, 1, 0, true},
		{"declaration never replaces an attestation", declJSON(valid), true, 0, 2, 0, 0, false},
		{"declaration expiring within 14 days is ignored", declJSON(declRecord("kubernetes", fam, "1.20", "1.21", ReasonScanNotClean, "2026-10-22T12:00:00Z")), false, 0, 1, 0, 1, true},
		{"expired declaration is ignored", declJSON(declRecord("kubernetes", fam, "1.20", "1.21", ReasonScanNotClean, "2026-10-05T00:00:00Z")), false, 0, 1, 0, 1, true},
		{"to is not the next snapshot line", declJSON(declRecord("kubernetes", fam, "1.20", "1.22", ReasonScanNotClean, "2026-12-15T00:00:00Z")), false, 1, 1, 0, 1, true},
		{"family not registered for the project", declJSON(declRecord("kubernetes", lineattest.FamilyCustomResourceVersions, "1.20", "1.21", ReasonScanNotClean, "2026-12-15T00:00:00Z")), false, 1, 1, 0, 1, true},
		{"declaration of a pair the snapshot lacks", declJSON(valid, declRecord("kubernetes", fam, "1.21", "1.22", ReasonScanNotClean, "2026-12-15T00:00:00Z")), false, 1, 1, 1, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := k8sScenario("1.19", "1.20", "1.21")
			if c.skipAttested {
				s.skip = map[string]bool{"1.21": true}
			}
			s.declared = c.declared
			p := s.project(t)
			assertComplete(t, p, c.complete, "")
			if p.InvalidDeclarations != c.invalid || p.Decided != c.decided || p.DeclaredUnknown != c.declaredN || p.Undeclared != c.undeclaredN {
				t.Fatalf("counts = %+v invalid %d, want decided %d declared %d undeclared %d invalid %d", p.Counts, p.InvalidDeclarations, c.decided, c.declaredN, c.undeclaredN, c.invalid)
			}
		})
	}
	// A new major is declared, never attested.
	s := k8sScenario("1.19", "1.20", "2.0")
	s.declared = declJSON(declRecord("kubernetes", fam, "1.20", "2.0", ReasonScanNotClean, "2026-12-15T00:00:00Z"))
	assertComplete(t, s.project(t), true, "")
}

func TestParseDeclared(t *testing.T) {
	fam := lineattest.FamilyKubernetesRemovedServedGVK
	ok := declRecord("kubernetes", fam, "1.20", "1.21", ReasonTagDeleted, "2026-12-15T00:00:00Z")
	if _, err := ParseDeclared(EmbeddedDeclared()); err != nil {
		t.Fatalf("embedded file: %v", err)
	}
	if f, _ := ParseDeclared(EmbeddedDeclared()); len(f.Declarations) != 0 {
		t.Fatal("the shipped file declares nothing yet")
	}
	for _, reason := range []string{ReasonGoDefinedCRDs, ReasonTemplatedOnly, ReasonOtherRepository, ReasonTagDeleted, ReasonSharedGroup, ReasonScanNotClean} {
		if _, err := ParseDeclared([]byte(declJSON(declRecord("kubernetes", fam, "1.20", "1.21", reason, "2026-12-15T00:00:00Z")))); err != nil {
			t.Errorf("reason %s rejected: %v", reason, err)
		}
	}
	bad := map[string]string{
		"bad reason":        declJSON(declRecord("kubernetes", fam, "1.20", "1.21", "blocked:because", "2026-12-15T00:00:00Z")),
		"unknown family":    declJSON(declRecord("kubernetes", "other.family", "1.20", "1.21", ReasonTagDeleted, "2026-12-15T00:00:00Z")),
		"unknown member":    strings.Replace(declJSON(ok), `"note"`, `"extra":1,"note"`, 1),
		"unknown schema":    strings.Replace(declJSON(ok), "v1", "v2", 1),
		"trailing data":     declJSON(ok) + "{}",
		"null list":         `{"schema":"` + DeclaredSchema + `"}`,
		"duplicate":         declJSON(ok, ok),
		"unsorted":          declJSON(declRecord("kubernetes", fam, "1.21", "1.22", ReasonTagDeleted, "2026-12-15T00:00:00Z"), ok),
		"window over 90d":   declJSON(declRecord("kubernetes", fam, "1.20", "1.21", ReasonTagDeleted, "2027-01-15T00:00:00Z")),
		"until before from": declJSON(declRecord("kubernetes", fam, "1.20", "1.21", ReasonTagDeleted, "2026-09-01T00:00:00Z")),
		"to before from":    declJSON(declRecord("kubernetes", fam, "1.21", "1.20", ReasonTagDeleted, "2026-12-15T00:00:00Z")),
		"long note":         strings.Replace(declJSON(ok), `"reviewed"`, `"`+strings.Repeat("x", 513)+`"`, 1),
		"bad slug":          declJSON(declRecord("Bad Slug", fam, "1.20", "1.21", ReasonTagDeleted, "2026-12-15T00:00:00Z")),
	}
	for name, raw := range bad {
		if _, err := ParseDeclared([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Compute refuses the whole report on a bad declared file.
	file, _ := MarshalLines(LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{"kubernetes": {Lines: []string{"1.19", "1.20"}}}})
	if _, err := Compute(Input{Pack: pack(nil, nil), Lines: file, Now: allNow, All: true, Declared: []byte(bad["bad reason"])}); err == nil {
		t.Fatal("report accepted a bad declared file")
	}
}

// A helm project is never complete: its pairs are chart-line pairs that the
// snapshot cannot hold, and nothing attests them.
func TestHelmValuesNeverComplete(t *testing.T) {
	file, _ := MarshalLines(LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{"opentelemetry": {Lines: []string{"1.0", "1.1", "1.2"}}}})
	declared := declJSON(declRecord("opentelemetry", FamilyHelmValuesSchema, "1.0", "1.1", ReasonTemplatedOnly, "2026-12-15T00:00:00Z"), declRecord("opentelemetry", FamilyHelmValuesSchema, "1.1", "1.2", ReasonTemplatedOnly, "2026-12-15T00:00:00Z"))
	report, err := Compute(Input{Pack: pack(nil, nil), Lines: file, Now: allNow, All: true, Declared: []byte(declared)})
	if err != nil {
		t.Fatal(err)
	}
	p := report.Projects[0]
	assertComplete(t, p, false, whyChartLines)
	var helm *FamilyCounts
	for i := range p.FamilyCounts {
		if p.FamilyCounts[i].Family == FamilyHelmValuesSchema {
			helm = &p.FamilyCounts[i]
		}
	}
	if helm == nil || helm.Decided != 0 || helm.DeclaredUnknown != 0 || helm.Undeclared != helm.LinesTotal-1 {
		t.Fatalf("helm counts = %+v", helm)
	}
	if p.InvalidDeclarations != 2 {
		t.Fatalf("declarations of a chart-line family are ignored and counted, got %d", p.InvalidDeclarations)
	}
}

func TestAllWindowVersusDefault(t *testing.T) {
	var all []string
	for m := 19; m <= 30; m++ {
		all = append(all, fmt.Sprintf("1.%d", m))
	}
	file, _ := MarshalLines(LinesFile{Schema: LinesSchema, CapturedOn: allCaptured, Projects: map[string]ProjectLines{"kubernetes": {Lines: append([]string{"1.17", "1.18"}, all...)}}})
	def, err := Compute(Input{Pack: pack(nil, nil), Lines: file, Now: allNow})
	if err != nil {
		t.Fatal(err)
	}
	every, err := Compute(Input{Pack: pack(nil, nil), Lines: file, Now: allNow, All: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(def.Projects[0].Window); got != 6 || def.Window != 6 || def.WindowAll {
		t.Fatalf("default window = %d lines, window %d", got, def.Window)
	}
	// ALL starts at the Kubernetes minFrom (1.19), not at the first line.
	if w := every.Projects[0].Window; len(w) != 12 || w[0] != "1.19" || every.Window != 0 || !every.WindowAll {
		t.Fatalf("ALL window = %v, window %d all %v", w, every.Window, every.WindowAll)
	}
	if every.Projects[0].LinesTotal != 12 || len(every.Projects[0].Pairs) != 11 {
		t.Fatalf("ALL counts = %+v", every.Projects[0].Counts)
	}
	rawDefault, _ := def.JSON()
	for _, key := range []string{"linesTotal", "windowAll", "complete", "linesSnapshot", "declared", "incompleteReasons", "familyCounts"} {
		if bytes.Contains(rawDefault, []byte(`"`+key+`"`)) {
			t.Errorf("default report holds %q", key)
		}
	}
	rawAll, _ := every.JSON()
	if bytes.Contains(rawAll, []byte("\n  \"window\":")) || !bytes.Contains(rawAll, []byte(`"windowAll": true`)) {
		t.Fatal("ALL report must carry windowAll and no window")
	}
	var parsed struct {
		LinesSnapshot struct {
			Digest     string
			CapturedOn string
			AgeDays    int
		}
	}
	if err := json.Unmarshal(rawAll, &parsed); err != nil || parsed.LinesSnapshot.Digest == "" || parsed.LinesSnapshot.CapturedOn != allCaptured {
		t.Fatalf("linesSnapshot: %v %+v", err, parsed)
	}
	if !strings.Contains(string(every.Markdown()), "complete is relative to the external lines snapshot captured 2026-10-08") {
		t.Fatal("markdown lacks the snapshot statement")
	}
	if _, err := Compute(Input{Pack: pack(nil, nil), Lines: file, Now: allNow, All: true, Window: 6}); err == nil {
		t.Fatal("ALL with a window size accepted")
	}
}

// The default report is byte-identical to the one the tool produced before
// the ALL window existed.
func TestDefaultReportByteIdentical(t *testing.T) {
	report, err := Compute(Input{Pack: read(t, "testdata/pack-cncf-2026-09-13.4-reduced.json"), Lines: read(t, "testdata/lines-2026-10-08.json"), Now: baselineNow})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := report.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, read(t, "testdata/default-report-2026-10-08.json")) {
		t.Fatal("default JSON changed")
	}
	if !bytes.Equal(report.Markdown(), read(t, "testdata/default-report-2026-10-08.md")) {
		t.Fatal("default Markdown changed")
	}
}

func TestLinesReleases(t *testing.T) {
	file, err := LinesFromTags(map[string][]byte{"demo": []byte("a\trefs/tags/v1.2.1\na\trefs/tags/v1.2.0\na\trefs/tags/v1.2.0^{}\na\trefs/tags/v1.2.10\na\trefs/tags/v1.3.0-rc.1\na\trefs/tags/v1.3.0\n"), "linkerd": []byte("stable-2.14.1\n")}, nil, allCaptured)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(file.Projects["demo"].Releases["1.2"], ","); got != "1.2.0,1.2.1,1.2.10" {
		t.Fatalf("releases of 1.2 = %s", got)
	}
	if got := strings.Join(file.Projects["demo"].Releases["1.3"], ","); got != "1.3.0" {
		t.Fatalf("releases of 1.3 = %s", got)
	}
	if file.Projects["linkerd"].Releases != nil {
		t.Fatal("a project with its own tag scheme lists no releases")
	}
	valid := `{"schema":"` + LinesSchema + `","projects":{"p":{"lines":["1.2"],"releases":%s}}}`
	for _, c := range []struct {
		name, releases string
		ok             bool
	}{
		{"good", `{"1.2":["1.2.0","1.2.1"]}`, true},
		{"not a listed line", `{"1.3":["1.3.0"]}`, false},
		{"other line", `{"1.2":["1.3.0"]}`, false},
		{"descending", `{"1.2":["1.2.1","1.2.0"]}`, false},
		{"duplicate", `{"1.2":["1.2.0","1.2.0"]}`, false},
		{"empty list", `{"1.2":[]}`, false},
		{"not a version", `{"1.2":["v1.2.0"]}`, false},
	} {
		if _, err := ParseLines([]byte(fmt.Sprintf(valid, c.releases))); (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}
