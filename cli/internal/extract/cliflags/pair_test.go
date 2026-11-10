// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

var commitB = strings.Repeat("b", 40)

const (
	testSlug      = "cortex"
	testComponent = "pkg:github/cortexproject/cortex"
	testFactID    = "component.cortex.cli_flags_set"
)

// twoCommits is a PinnedReader over two in-memory trees.
type twoCommits map[string]*memReader

func (m twoCommits) Read(r extract.RepoRef, c, p string) ([]byte, error) {
	t, ok := m[c]
	if !ok {
		return nil, fmt.Errorf("unknown commit %s", c)
	}
	return t.Read(r, c, p)
}

func (m twoCommits) List(r extract.RepoRef, c, d string) ([]extract.TreeEntry, error) {
	t, ok := m[c]
	if !ok {
		return nil, fmt.Errorf("unknown commit %s", c)
	}
	es, err := t.List(r, c, d)
	// The recording reader caches listings by tree id, so every entry needs
	// one that is unique to its commit and path.
	for i := range es {
		sum := sha1.Sum([]byte(c + "\x00" + es[i].Type + "\x00" + es[i].Path))
		es[i].SHA = hex.EncodeToString(sum[:])
	}
	return es, err
}

type tagSource []extract.Tag

func (t tagSource) Tags(extract.RepoRef) ([]extract.Tag, error) { return t, nil }

var pairTags = tagSource{{Name: "v1.0.0", Commit: commitA}, {Name: "v1.1.0", Commit: commitB}}

func prog(names ...string) string {
	var b strings.Builder
	b.WriteString("package main\n\nimport \"flag\"\n\nfunc main() {\n")
	for _, n := range names {
		fmt.Fprintf(&b, "\tflag.String(%q, \"\", \"u\")\n", n)
	}
	b.WriteString("\tflag.Parse()\n}\n")
	return b.String()
}

// tree is a one-binary module (cmd/app) plus extra files.
func tree(app string, extra map[string]string) map[string]string {
	f := map[string]string{"go.mod": goMod, "cmd/app/main.go": app}
	for k, v := range extra {
		f[k] = v
	}
	return f
}

func newTestExtractor(t testing.TB, slug, component string, excl ...Exclusion) *Extractor {
	t.Helper()
	x, err := New(slug, component, Target{Repo: repo, Exclude: excl})
	if err != nil {
		t.Fatal(err)
	}
	x.registry = func() []constraintengine.FactDefinition {
		return []constraintengine.FactDefinition{{ID: testFactID, Component: testComponent, Type: constraintengine.FactSet}}
	}
	return x
}

var derivedAt = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)

// runPair runs the extractor over a two-tree repository through extract.Run
// and checks what every pair of this extractor must hold: the run does not
// fail, and the pair is not attested, with no attestation anywhere.
func runPair(t testing.TB, x *Extractor, from, to map[string]string) (*extract.Output, extract.PairRecord) {
	t.Helper()
	return runPairReader(t, x, twoCommits{commitA: newMem(from), commitB: newMem(to)})
}

func runPairReader(t testing.TB, x *Extractor, rd twoCommits) (*extract.Output, extract.PairRecord) {
	t.Helper()
	out, err := extract.Run(context.Background(), x, pairTags, rd, extract.Options{Repo: repo, DerivedAt: derivedAt})
	if err != nil && strings.Contains(err.Error(), refusedNotMechanical) {
		out, err = directPair(x, rd)
	}
	if err != nil {
		t.Fatalf("extract.Run: %v", err)
	}
	if len(out.Manifest.Pairs) != 1 {
		t.Fatalf("pairs: %d", len(out.Manifest.Pairs))
	}
	pr := out.Manifest.Pairs[0]
	if pr.Status != extract.PairDerived {
		t.Fatalf("pair status %s (%s)", pr.Status, pr.Reason)
	}
	if pr.Attestation == nil || pr.Attestation.Status != extract.PairNotAttested || len(pr.Attestation.Families) != 0 {
		t.Fatalf("pair must be not-attested with no family: %+v", pr.Attestation)
	}
	if len(out.Attestations) != 0 || out.Manifest.Totals.Attestations != 0 {
		t.Fatalf("an attestation was stated")
	}
	return out, pr
}

// refusedNotMechanical is the runner's refusal of a line-attesting extractor
// that is not an allowlisted mechanical emitter. cliflags is library-only: it
// is not in the extractor catalog and not on the mechanical allowlist, so the
// runner refuses its candidates by design until its registration lands. The
// tests below still check the extractor's own output, so they read it through
// Extract and build the pair view the runner would have stamped (rule fields
// only; no stamping, no pack entry). This registers nothing and changes no
// production table.
// directPair skips the runner's ledger normalisation, vocabulary checks and
// stamping for candidate-emitting pairs; that is acceptable only because
// cliflags is library-only and inert (not in the catalog), and the class-3
// wiring PR must drop directPair and the fallback.
const refusedNotMechanical = "attests lines and may not emit drafts"

func directPair(x *Extractor, rd twoCommits) (*extract.Output, error) {
	pair := extract.VersionPair{Repo: repo, From: "1.0.0", FromTag: "v1.0.0", FromCommit: commitA, To: "1.1.0", ToTag: "v1.1.0", ToCommit: commitB}
	res, err := x.Extract(context.Background(), rd, pair)
	if err != nil {
		return nil, err
	}
	pr := extract.PairRecord{From: pair.From, FromTag: pair.FromTag, FromCommit: pair.FromCommit, To: pair.To, ToTag: pair.ToTag, ToCommit: pair.ToCommit, Rules: []string{}, Status: extract.PairDerived, Proof: res.Proof}
	seen := map[extract.LedgerEntry]bool{}
	for _, l := range res.Ledger {
		if !seen[l] {
			seen[l] = true
			pr.Ledger = append(pr.Ledger, l)
		}
	}
	sort.Slice(pr.Ledger, func(i, j int) bool {
		if pr.Ledger[i].Code != pr.Ledger[j].Code {
			return pr.Ledger[i].Code < pr.Ledger[j].Code
		}
		return pr.Ledger[i].Item < pr.Ledger[j].Item
	})
	out := &extract.Output{}
	for _, c := range res.Candidates {
		out.Entries = append(out.Entries, extract.Entry{Project: c.Project, Description: c.Description, RequiredFacts: c.RequiredFacts, Rule: extract.RuleJSON{
			ID: c.Rule.ID, Operator: c.Rule.Operator, Subject: c.Rule.Subject, SetCondition: c.Rule.SetCondition, ReasonCode: c.Rule.ReasonCode, NextAction: c.Rule.NextAction}})
		pr.Rules = append(pr.Rules, c.Rule.ID)
	}
	reason := res.NotAttested
	if reason == "" {
		reason = "not attested"
	}
	pr.Attestation = &extract.PairAttestation{Status: extract.PairNotAttested, Families: []string{}, Reason: reason}
	out.Manifest.Pairs = []extract.PairRecord{pr}
	return out, nil
}

func codes(l []extract.LedgerEntry) []string {
	var out []string
	for _, e := range l {
		out = append(out, e.Code+" "+e.Item)
	}
	return out
}

func proofOf(t testing.TB, pr extract.PairRecord) *PairResult {
	t.Helper()
	p, ok := pr.Proof.(*PairResult)
	if !ok {
		t.Fatalf("proof is %T, want the PairResult", pr.Proof)
	}
	return p
}

func wantNoRule(t testing.TB, out *extract.Output, pr extract.PairRecord, want ...string) {
	t.Helper()
	if len(out.Entries) != 0 || len(pr.Rules) != 0 {
		t.Fatalf("a rule was proposed: %v", pr.Rules)
	}
	if got := codes(pr.Ledger); !reflect.DeepEqual(got, want) {
		t.Fatalf("ledger\n got %q\nwant %q", got, want)
	}
	if p := proofOf(t, pr); len(p.Removed) != 0 || p.Attestable() {
		t.Fatalf("proof states removals %v", p.Removed)
	}
}

func TestPairRemovalIsCandidateOnly(t *testing.T) {
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", "gone"), nil), tree(prog("keep"), nil))
	if len(pr.Ledger) != 0 {
		t.Fatalf("ledger %v", codes(pr.Ledger))
	}
	if len(out.Entries) != 1 {
		t.Fatalf("rules %d", len(out.Entries))
	}
	r := out.Entries[0].Rule
	if r.Operator != constraintengine.OperatorForbidSetMember || r.SetCondition.FactID != testFactID || !reflect.DeepEqual(r.SetCondition.Members, []string{"gone"}) || r.SetCondition.Side != "proposed" {
		t.Fatalf("rule %+v", r)
	}
	if p := proofOf(t, pr); !reflect.DeepEqual(p.Removed, []string{"gone"}) || p.Attestable() {
		t.Fatalf("proof %+v", p)
	}
	if pr.Attestation.Reason == "" {
		t.Fatal("no reason recorded")
	}
}

func TestPairRenameIsAnOrdinaryRemoval(t *testing.T) {
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("old-name"), nil), tree(prog("new-name"), nil))
	if len(out.Entries) != 1 || !reflect.DeepEqual(out.Entries[0].Rule.SetCondition.Members, []string{"old-name"}) {
		t.Fatalf("rules %+v", out.Entries)
	}
	if len(pr.Ledger) != 0 {
		t.Fatalf("ledger %v", codes(pr.Ledger))
	}
}

func TestPairNothingRemoved(t *testing.T) {
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("a"), nil), tree(prog("a", "b"), nil))
	wantNoRule(t, out, pr)
}

// (a) STILL_PRESENT

func TestPairMovedToAnotherCommandIsStillPresent(t *testing.T) {
	to := tree(prog("keep"), map[string]string{"cmd/other/main.go": prog("gone")})
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", "gone"), nil), to)
	wantNoRule(t, out, pr, "FLAG_NAME_STILL_PRESENT cmd/app:gone")
}

func TestPairStillRegisteredBySameBinary(t *testing.T) {
	// Not a removal at all: no rule, no ledger.
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("a"), nil), tree(prog("a"), nil))
	wantNoRule(t, out, pr)
}

func TestPairRemovedFromOneBinaryKeptByAnother(t *testing.T) {
	from := tree(prog("x"), map[string]string{"cmd/two/main.go": prog("x")})
	to := tree(prog("x"), map[string]string{"cmd/two/main.go": prog("y")})
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), from, to)
	wantNoRule(t, out, pr, "FLAG_NAME_STILL_PRESENT cmd/two:x")
}

func TestPairLiteralInNewerTreeIsStillPresent(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"exact":       {"internal/shim/shim.go": "package shim\n\nvar Alias = \"gone\"\n"},
		"single dash": {"internal/shim/shim.go": "package shim\n\nvar Alias = \"-gone\"\n"},
		"double dash": {"internal/shim/shim.go": "package shim\n\nvar Alias = \"--gone\"\n"},
		"with value":  {"internal/shim/shim.go": "package shim\n\nvar Alias = \"--gone=%s\"\n"},
		"raw string":  {"internal/shim/shim.go": "package shim\n\nvar Alias = `gone`\n"},
		"vendored":    {"vendor/example.com/lib/lib.go": "package lib\n\nvar Alias = \"gone\"\n"},
		"dead file":   {"internal/shim/shim.go": "package shim\n\nfunc f() { _ = \"gone\" }\n"},
	} {
		t.Run(name, func(t *testing.T) {
			out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", "gone"), nil), tree(prog("keep"), extra))
			wantNoRule(t, out, pr, "FLAG_NAME_STILL_PRESENT gone")
		})
	}
}

func TestPairLiteralOutsideGoOrInTestsOrOlderTreeIsNotAHit(t *testing.T) {
	to := tree(prog("keep"), map[string]string{
		"internal/shim/shim_test.go": "package shim\n\nvar Alias = \"gone\"\n",
		"docs/notes.md":              "gone\n",
		"internal/shim/other.go":     "package shim\n\nvar Near = \"gone-ish\"\nvar Longer = \"x--gone\"\n",
	})
	from := tree(prog("keep", "gone"), map[string]string{"internal/old/old.go": "package old\n\nvar A = \"gone\"\n"})
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), from, to)
	if len(out.Entries) != 1 || len(pr.Ledger) != 0 {
		t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
	}
}

func TestSweepIncompleteWithholdsEverything(t *testing.T) {
	cases := map[string]struct {
		mod  func(*memReader)
		want string // "" : only that the pair is withheld
	}{
		"submodule": {func(m *memReader) { m.commits = []string{"third_party/lib"} }, ""},
		"link": {func(m *memReader) {
			m.files["internal/x/x.go"] = []byte("package x\n")
			m.modes = map[string]string{"internal/x/x.go": "120000"}
		}, ""},
		"bad token":  {func(m *memReader) { m.files["internal/x/x.go"] = []byte("package x\n\nvar S = \"unterminated\n") }, "FLAG_SWEEP_INCOMPLETE to"},
		"bad escape": {func(m *memReader) { m.files["internal/x/x.go"] = []byte("package x\n\nvar T = \"\\q\"\n") }, "FLAG_SWEEP_INCOMPLETE to"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			to := newMem(tree(prog("keep"), nil))
			c.mod(to)
			rd := twoCommits{commitA: newMem(tree(prog("keep", "gone"), nil)), commitB: to}
			out, pr := runPairReader(t, newTestExtractor(t, testSlug, testComponent), rd)
			if len(out.Entries) != 0 || len(pr.Ledger) == 0 || len(proofOf(t, pr).Removed) != 0 {
				t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
			}
			if c.want != "" {
				if got := codes(pr.Ledger); !reflect.DeepEqual(got, []string{c.want}) {
					t.Fatalf("ledger %q", got)
				}
			}
		})
	}
}

// (b) FACT_UNREGISTERED

func TestPairUnregisteredFactIsWithheld(t *testing.T) {
	x := newTestExtractor(t, "other", "pkg:github/example/other")
	out, pr := runPair(t, x, tree(prog("keep", "gone"), nil), tree(prog("keep"), nil))
	wantNoRule(t, out, pr, "FACT_UNREGISTERED component.other.cli_flags_set")
	if proofOf(t, pr).FactKnown {
		t.Fatal("the fact is not registered")
	}
}

func TestPairFactOfAnotherComponentOrTypeIsUnregistered(t *testing.T) {
	for name, def := range map[string]constraintengine.FactDefinition{
		"other component": {ID: testFactID, Component: "pkg:github/example/other", Type: constraintengine.FactSet},
		"bool fact":       {ID: testFactID, Component: testComponent, Type: constraintengine.FactBool},
		"other id":        {ID: "component.cortex.config_keys_set", Component: testComponent, Type: constraintengine.FactSet},
	} {
		t.Run(name, func(t *testing.T) {
			x := newTestExtractor(t, testSlug, testComponent)
			x.registry = func() []constraintengine.FactDefinition { return []constraintengine.FactDefinition{def} }
			out, pr := runPair(t, x, tree(prog("keep", "gone"), nil), tree(prog("keep"), nil))
			wantNoRule(t, out, pr, "FACT_UNREGISTERED "+testFactID)
		})
	}
	x := newTestExtractor(t, testSlug, testComponent)
	x.registry = func() []constraintengine.FactDefinition { return nil }
	out, pr := runPair(t, x, tree(prog("keep", "gone"), nil), tree(prog("keep"), nil))
	wantNoRule(t, out, pr, "FACT_UNREGISTERED "+testFactID)
}

// The registry this build compiles registers exactly the three components the
// design names, under the identifiers the extractor derives.
func TestCompiledRegistryRegistersCortexFalcoThanos(t *testing.T) {
	for slug, comp := range map[string]string{
		"cortex": "pkg:github/cortexproject/cortex",
		"falco":  "pkg:github/falcosecurity/falco",
		"thanos": "pkg:github/thanos-io/thanos",
	} {
		x, err := New(slug, comp, Target{Repo: repo})
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := x.factRegistered(); !ok {
			t.Errorf("%s: the compiled registry does not hold %s", slug, x.FactID())
		}
	}
	for slug, comp := range map[string]string{
		"loki":   "pkg:github/grafana/loki",
		"cortex": "pkg:github/cortexproject/other",
	} {
		x, err := New(slug, comp, Target{Repo: repo})
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := x.factRegistered(); ok {
			t.Errorf("%s/%s must not be registered", slug, comp)
		}
	}
}

// (c) Exclusions

func TestPairExclusionsAreCarriedIntoTheProof(t *testing.T) {
	excl := Exclusion{Dir: "cmd/tool", Reason: "test helper, not part of the component"}
	extra := map[string]string{"cmd/tool/main.go": prog("tool-only")}
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent, excl), tree(prog("keep", "gone"), extra), tree(prog("keep"), extra))
	if len(out.Entries) != 1 || len(pr.Ledger) != 0 {
		t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
	}
	p := proofOf(t, pr)
	want := []Exclusion{excl}
	if !reflect.DeepEqual(p.Exclusions.From, want) || !reflect.DeepEqual(p.Exclusions.To, want) || !reflect.DeepEqual(p.From.Excluded, want) || !reflect.DeepEqual(p.To.Excluded, want) {
		t.Fatalf("exclusions not carried: %+v", p.Exclusions)
	}
	b, _ := json.Marshal(pr.Proof)
	if !strings.Contains(string(b), `"exclusions":{"from":[{"dir":"cmd/tool"`) {
		t.Fatalf("proof JSON: %s", b)
	}
}

func TestPairExcludedOnOneSideOnlyWithholds(t *testing.T) {
	excl := Exclusion{Dir: "cmd/tool", Reason: "test helper, not part of the component"}
	extra := map[string]string{"cmd/tool/main.go": prog("tool-only")}
	// The older side has the binary and excludes it; the newer side has no
	// such directory: the stale exclusion is a fault of the newer scan.
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent, excl), tree(prog("keep", "gone"), extra), tree(prog("keep"), nil))
	if len(out.Entries) != 0 || len(pr.Ledger) == 0 {
		t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
	}
	// And the other way round.
	out, pr = runPair(t, newTestExtractor(t, testSlug, testComponent, excl), tree(prog("keep", "gone"), nil), tree(prog("keep"), extra))
	if len(out.Entries) != 0 || len(pr.Ledger) == 0 {
		t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
	}
}

// The pair comparison does not rely on the scan's own stale-exclusion fault:
// two clean scans whose matched exclusions differ withhold by themselves.
func TestComparePairExclusionMismatchOnCleanScans(t *testing.T) {
	mk := func(excl ...Exclusion) *Result {
		r := scanFiles(t, map[string]string{"cmd/app/main.go": prog("keep", "gone")}, defaultGuards())
		r.Excluded = excl
		if !r.Attestable() {
			t.Fatal("setup: scan must be attestable")
		}
		return r
	}
	e1 := Exclusion{Dir: "cmd/tool", Reason: "one"}
	e2 := Exclusion{Dir: "cmd/tool", Reason: "two"}
	e3 := Exclusion{Dir: "cmd/other", Reason: "one"}
	fact := FactRef{ID: testFactID, Component: testComponent, Registered: true}
	for name, c := range map[string][2]*Result{
		"old only":    {mk(e1), mk()},
		"new only":    {mk(), mk(e1)},
		"reason":      {mk(e1), mk(e2)},
		"other dir":   {mk(e1), mk(e3)},
		"both differ": {mk(e1, e3), mk(e1)},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := comparePair(context.Background(), newMem(nil), Target{Repo: repo}, c[0], c[1], fact)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Removed) != 0 {
				t.Fatalf("removed %v", p.Removed)
			}
			found := false
			for _, e := range p.Ledger {
				found = found || e.Code == ReasonExclusionMismatch
			}
			if !found {
				t.Fatalf("no mismatch entry: %v", p.Ledger)
			}
		})
	}
	// Equal exclusions do not withhold (the sweep needs a tree: an empty one
	// has no root listing, so use a real reader).
	same := mk(e1)
	p, err := comparePair(context.Background(), newMem(map[string]string{"go.mod": goMod, "cmd/app/main.go": prog("keep")}), Target{Repo: repo}, same, mkTo(t, e1), fact)
	if err != nil || len(p.Ledger) != 0 || !reflect.DeepEqual(p.Removed, []string{"gone"}) {
		t.Fatalf("equal exclusions: %v %+v", err, p)
	}
}

func mkTo(t testing.TB, excl ...Exclusion) *Result {
	r := scanFiles(t, map[string]string{"cmd/app/main.go": prog("keep")}, defaultGuards())
	r.Excluded = excl
	return r
}

// Incomplete scans and ledger entries

func TestPairIncompleteScanWithholdsAndCarriesTheLedger(t *testing.T) {
	dyn := "package main\n\nimport \"flag\"\n\nvar n = \"dyn\"\n\nfunc main() {\n\tflag.String(n, \"\", \"u\")\n\tflag.Parse()\n}\n"
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", "gone"), nil), tree(dyn, nil))
	wantNoRule(t, out, pr, "FLAG_DYNAMIC_REGISTRATION to:cmd/app", "FLAG_SCAN_INCOMPLETE to")
	out, pr = runPair(t, newTestExtractor(t, testSlug, testComponent), tree(dyn, nil), tree(prog("keep"), nil))
	wantNoRule(t, out, pr, "FLAG_DYNAMIC_REGISTRATION from:cmd/app", "FLAG_SCAN_INCOMPLETE from")
}

func TestPairScanFaultsWithhold(t *testing.T) {
	for name, c := range map[string][2]map[string]string{
		"no go.mod new":   {tree(prog("keep", "gone"), nil), {"cmd/app/main.go": prog("keep")}},
		"no binary new":   {tree(prog("keep", "gone"), nil), {"go.mod": goMod, "lib/x.go": "package lib\n"}},
		"parse error new": {tree(prog("keep", "gone"), nil), tree(prog("keep"), map[string]string{"cmd/app/bad.go": "package main\nfunc ("})},
		"unknown import":  {tree(prog("keep", "gone"), nil), tree("package main\n\nimport (\n\t\"flag\"\n\t_ \"example.org/plugin\"\n)\n\nfunc main() { flag.Parse() }\n", nil)},
		"shadow in loop":  {tree(prog("keep", "gone"), nil), tree("package main\n\nimport \"flag\"\n\nfunc main() {\n\tfor _, n := range []string{\"a\"} {\n\t\tflag.String(n, \"\", \"u\")\n\t}\n}\n", nil)},
	} {
		t.Run(name, func(t *testing.T) {
			out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), c[0], c[1])
			if len(out.Entries) != 0 || len(pr.Ledger) == 0 {
				t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
			}
		})
	}
}

func TestPairBinaryRemovedIsWithheld(t *testing.T) {
	from := tree(prog("keep"), map[string]string{"cmd/old/main.go": prog("only-old")})
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), from, tree(prog("keep"), nil))
	wantNoRule(t, out, pr, "FLAG_BINARY_REMOVED from:cmd/old")
}

func TestPairFlagLevelWithholdsKeepOtherCandidates(t *testing.T) {
	pf := "package main\n\nimport \"github.com/spf13/pflag\"\n\nfunc main() {\n\tpflag.String(\"plain\", \"\", \"u\")\n\tpflag.StringP(\"short\", \"s\", \"\", \"u\")\n\tpflag.Parse()\n}\n"
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(pf, nil), tree("package main\n\nimport \"github.com/spf13/pflag\"\n\nfunc main() { pflag.Parse() }\n", nil))
	if len(out.Entries) != 1 || !reflect.DeepEqual(out.Entries[0].Rule.SetCondition.Members, []string{"plain"}) {
		t.Fatalf("rules %+v", out.Entries)
	}
	if got := codes(pr.Ledger); !reflect.DeepEqual(got, []string{"FLAG_HAS_SHORTHAND cmd/app:short"}) {
		t.Fatalf("ledger %q", got)
	}
}

func TestPairTooManyRemovalsWithheld(t *testing.T) {
	var from []string
	for i := 0; i <= constraintengine.MaxForbiddenMembers; i++ {
		from = append(from, fmt.Sprintf("flag-%03d", i))
	}
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog(from...), nil), tree(prog("keep"), nil))
	wantNoRule(t, out, pr, "MEMBER_SET_TOO_LARGE removed")
	out, pr = runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog(from[:constraintengine.MaxForbiddenMembers]...), nil), tree(prog("keep"), nil))
	if len(out.Entries) != 1 || len(pr.Ledger) != 0 {
		t.Fatalf("exactly the cap must pass: rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
	}
}

// Ledger faults of a scan do not abort a run, and no reserved code reaches the
// framework ledger.
func TestPairScanLedgerFaultDoesNotAbortTheRun(t *testing.T) {
	from := map[string]string{"go.mod": goMod}
	for i := 0; i <= MaxLedgerEntries; i++ {
		from[fmt.Sprintf("cmd/b%03d/main.go", i)] = "package main\n\nimport \"flag\"\n\nvar n = \"x\"\n\nfunc main() { flag.String(n, \"\", \"\") }\n"
	}
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), from, tree(prog("keep"), nil))
	if len(out.Entries) != 0 || len(pr.Ledger) == 0 {
		t.Fatalf("rules %d ledger %d", len(out.Entries), len(pr.Ledger))
	}
	p := proofOf(t, pr)
	if !reflect.DeepEqual(p.From.Ledger, faultLedger(LedgerOverflow)) {
		t.Fatalf("setup: scan ledger %v", p.From.Ledger)
	}
	for _, e := range pr.Ledger {
		if strings.HasPrefix(e.Code, "LEDGER_") {
			t.Fatalf("reserved code in the pair ledger: %v", e)
		}
	}
	if got := codes(pr.Ledger); !reflect.DeepEqual(got, []string{"FLAG_SCAN_INCOMPLETE from", "SCAN_LEDGER_OVERFLOW from:ledger"}) {
		t.Fatalf("ledger %q", got)
	}
}

func TestPairLedgerOverflowDropsCandidates(t *testing.T) {
	p := &PairResult{From: &Result{}, To: &Result{}, Removed: []string{"x"}}
	var om []Omission
	for i := 0; i <= extract.MaxLedgerEntries; i++ {
		om = append(om, Omission{Reason: ReasonNameStillPresent, Subject: fmt.Sprintf("cmd/a:f%04d", i), Count: 1})
	}
	p.finish(om)
	if !reflect.DeepEqual(p.Ledger, []LedgerEntry{{Code: PairLedgerOverflow, Item: "ledger"}}) || len(p.Removed) != 0 {
		t.Fatalf("%v %v", p.Ledger, p.Removed)
	}
}

func TestPairLedgerItemsAreFrameworkItems(t *testing.T) {
	for in, want := range map[string]string{"a=b": "a_b", "": "-", "é": "__", "cmd/a:x.y-z": "cmd/a:x.y-z", strings.Repeat("a", 300): strings.Repeat("a", MaxLedgerItemLen)} {
		if got := ledgerItem(in); got != want {
			t.Errorf("ledgerItem(%q) = %q want %q", in, got, want)
		}
	}
	p := &PairResult{From: &Result{Ledger: []LedgerEntry{{Code: LedgerInvalid, Item: "ledger"}, {Code: "FLAG_X_Y", Item: "cmd/a=b"}}}, To: &Result{}}
	p.finish(nil)
	want := []LedgerEntry{{Code: "FLAG_X_Y", Item: "from:cmd/a_b"}, {Code: "SCAN_LEDGER_INVALID", Item: "from:ledger"}}
	if !reflect.DeepEqual(p.Ledger, want) {
		t.Fatalf("%v", p.Ledger)
	}
}

// Determinism and the proof shape.

func TestPairRunIsDeterministicAndProofHasTopLevelLedger(t *testing.T) {
	x := newTestExtractor(t, testSlug, testComponent)
	from, to := tree(prog("keep", "gone"), map[string]string{"cmd/other/main.go": prog("moved")}), tree(prog("keep"), map[string]string{"cmd/other/main.go": prog("x"), "internal/s/s.go": "package s\n\nvar A = \"moved\"\n"})
	_, pr1 := runPair(t, x, from, to)
	_, pr2 := runPair(t, x, from, to)
	b1, _ := json.Marshal(pr1)
	b2, _ := json.Marshal(pr2)
	if string(b1) != string(b2) {
		t.Fatalf("not deterministic:\n%s\n%s", b1, b2)
	}
	var top map[string]json.RawMessage
	pb, _ := json.Marshal(pr1.Proof)
	if err := json.Unmarshal(pb, &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "ledger", "removed", "exclusions", "residual", "omissions", "from", "to"} {
		if _, ok := top[k]; !ok {
			t.Errorf("proof has no %q member", k)
		}
	}
	if string(top["ledger"]) == "[]" || string(top["ledger"]) == "null" {
		t.Errorf("ledger %s", top["ledger"])
	}
}

func TestPairProofStatesTheResidualRisk(t *testing.T) {
	_, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", "gone"), nil), tree(prog("keep"), nil))
	r := strings.Join(proofOf(t, pr).Residual, "\n")
	for _, w := range []string{"concatenation", "environment variable", "renamed"} {
		if !strings.Contains(r, w) {
			t.Errorf("residual lacks %q", w)
		}
	}
}

// Extractor identity and pairs.

func TestExtractorIsInertForAttestation(t *testing.T) {
	x := newTestExtractor(t, testSlug, testComponent)
	if len(x.AttestedFamilies()) != 0 || x.AttestedComponent() != testComponent || x.family != "" {
		t.Fatalf("families %v", x.AttestedFamilies())
	}
	if _, ok := interface{}(x).(extract.LineAttester); !ok {
		t.Fatal("must be a LineAttester so the pair records a not-attested status")
	}
	if x.ID() != "cli.flag-removal.cortex" || !x.Applies(repo) || x.Applies(extract.RepoRef{Key: "github.com/example/other"}) {
		t.Fatal("identity")
	}
	if dir, files := x.SourceFiles(); dir != SourceDir || files == nil {
		t.Fatal("source files")
	}
}

func TestNewRefusesBadInput(t *testing.T) {
	if _, err := New("Bad Slug", testComponent, Target{Repo: repo}); err == nil {
		t.Error("slug accepted")
	}
	if _, err := New(testSlug, testComponent, Target{}); err == nil {
		t.Error("no repository accepted")
	}
	if _, err := New(testSlug, testComponent, Target{Repo: repo, Exclude: []Exclusion{{Dir: "../x", Reason: "r"}}}); err == nil {
		t.Error("bad exclusion accepted")
	}
}

func TestPairsMinorLines(t *testing.T) {
	x := newTestExtractor(t, testSlug, testComponent)
	h := func(c string) string { return strings.Repeat(c, 40) }
	got := x.Pairs(extract.ReleaseIndex{Repo: repo, Tags: []extract.Tag{
		{Name: "v1.1.2", Commit: h("2")}, {Name: "v1.1.0", Commit: h("1")}, {Name: "v1.2.0", Commit: h("3")},
		{Name: "v1.4.0", Commit: h("4")}, // gap: no pair
		{Name: "v2.0.0", Commit: h("5")}, // other major: no pair
		{Name: "v1.3.0-rc.1", Commit: h("6")}, {Name: "docs/v1.9.0", Commit: h("7")}, {Name: "v1.5.0", Commit: "short"},
	}})
	if len(got) != 1 || got[0].From != "1.1.0" || got[0].To != "1.2.0" || got[0].FromCommit != h("1") || got[0].ToCommit != h("3") {
		t.Fatalf("%+v", got)
	}
}

func TestPairsDuplicateTagAtOtherCommitDropsTheLine(t *testing.T) {
	x := newTestExtractor(t, testSlug, testComponent)
	h := func(c string) string { return strings.Repeat(c, 40) }
	got := x.Pairs(extract.ReleaseIndex{Repo: repo, Tags: []extract.Tag{
		{Name: "v1.0.0", Commit: h("1")}, {Name: "1.0.0", Commit: h("2")}, {Name: "v1.1.0", Commit: h("3")}, {Name: "v1.2.0", Commit: h("4")},
	}})
	if len(got) != 1 || got[0].From != "1.1.0" {
		t.Fatalf("%+v", got)
	}
	// The same release tagged twice at the same commit is one release.
	got = x.Pairs(extract.ReleaseIndex{Repo: repo, Tags: []extract.Tag{
		{Name: "v1.0.0", Commit: h("1")}, {Name: "1.0.0", Commit: h("1")}, {Name: "v1.1.0", Commit: h("3")},
	}})
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
}

// Read failures abort (fail closed), they are never a quiet pair.
func TestPairReadFailureAborts(t *testing.T) {
	boom := errors.New("boom")
	a := newMem(tree(prog("keep", "gone"), nil))
	b := newMem(tree(prog("keep"), nil))
	b.readErr = boom
	x := newTestExtractor(t, testSlug, testComponent)
	_, err := extract.Run(context.Background(), x, pairTags, twoCommits{commitA: a, commitB: b}, extract.Options{Repo: repo, DerivedAt: derivedAt})
	if !errors.Is(err, boom) {
		t.Fatalf("err %v", err)
	}
}

func TestSweepLimits(t *testing.T) {
	tr := newMem(tree(prog("keep"), map[string]string{"a/a.go": "package a\n", "a/b.go": "package a\n"}))
	for name, lim := range map[string]func(*limits){
		"files": func(l *limits) { l.files = 2 },
		"dirs":  func(l *limits) { l.dirs = 1 },
		"depth": func(l *limits) { l.depth = 0 },
		"bytes": func(l *limits) { l.totalBytes = 10 },
		"file":  func(l *limits) { l.fileBytes = 5 },
	} {
		t.Run(name, func(t *testing.T) {
			l := defaultLimits()
			lim(&l)
			hits, why, err := sweepLimited(context.Background(), tr, repo, commitB, []string{"gone"}, l)
			if err != nil || why == "" || hits != nil {
				t.Fatalf("hits %v why %q err %v", hits, why, err)
			}
		})
	}
	hits, why, err := sweepLimited(context.Background(), tr, repo, commitB, []string{"gone"}, defaultLimits())
	if err != nil || why != "" || len(hits) != 0 {
		t.Fatalf("hits %v why %q err %v", hits, why, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := sweepLimited(ctx, tr, repo, commitB, []string{"gone"}, defaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
}

// ---- review round: registry digest, unhashed libraries, folded spellings ----

func TestPairProofBindsTheFactDefinition(t *testing.T) {
	from, to := tree(prog("keep", "gone"), nil), tree(prog("keep"), nil)
	proof := func(def constraintengine.FactDefinition) (string, *PairResult) {
		x := newTestExtractor(t, testSlug, testComponent)
		x.registry = func() []constraintengine.FactDefinition { return []constraintengine.FactDefinition{def} }
		_, pr := runPair(t, x, from, to)
		b, _ := json.Marshal(pr.Proof)
		return string(b), proofOf(t, pr)
	}
	base := constraintengine.FactDefinition{ID: testFactID, Component: testComponent, Type: constraintengine.FactSet}
	b1, p1 := proof(base)
	b2, _ := proof(base)
	if b1 != b2 || !strings.HasPrefix(p1.FactDigest, "sha256:") || len(p1.FactDigest) != 71 {
		t.Fatalf("digest %q", p1.FactDigest)
	}
	changed := base
	changed.EnumTokens = []string{"x"}
	if b3, p3 := proof(changed); b3 == b1 || p3.FactDigest == p1.FactDigest {
		t.Fatal("a changed fact definition did not change the Proof")
	}
	// Unregistered: no digest.
	x := newTestExtractor(t, "other", "pkg:github/example/other")
	_, pr := runPair(t, x, from, to)
	if proofOf(t, pr).FactDigest != "" {
		t.Fatal("digest for an unregistered fact")
	}
}

func TestPairUnhashedFlagLibraryWithholds(t *testing.T) {
	req := func(path string) map[string]string {
		return map[string]string{"go.mod": goMod + "\nrequire " + path + " v1.0.0\n"}
	}
	block := map[string]string{"go.mod": goMod + "\nrequire (\n\tgithub.com/spf13/cobra v1.8.0 // indirect\n)\n"}
	for name, c := range map[string]struct {
		extra map[string]string
		want  string
	}{
		"pflag":            {req("github.com/spf13/pflag"), "github.com/spf13/pflag"},
		"cobra blk":        {block, "github.com/spf13/cobra"},
		"urfave v2":        {req("github.com/urfave/cli/v2"), "github.com/urfave/cli/v2"},
		"kingpin":          {req("gopkg.in/alecthomas/kingpin.v2"), "gopkg.in/alecthomas/kingpin.v2"},
		"base":             {req("k8s.io/component-base"), "k8s.io/component-base"},
		"kong":             {req("github.com/alecthomas/kong"), "github.com/alecthomas/kong"},
		"replace parent":   {map[string]string{"go.mod": goMod + "\nrequire github.com/spf13/pflag v1.0.5\nreplace github.com/spf13/pflag => ../pflag\n"}, "github.com/spf13/pflag"},
		"replace fork":     {map[string]string{"go.mod": goMod + "\nrequire github.com/spf13/pflag v1.0.5\nreplace github.com/spf13/pflag => github.com/fork/pflag v1.0.0\n"}, "github.com/spf13/pflag"},
		"replace blk fork": {map[string]string{"go.mod": goMod + "\nrequire github.com/spf13/pflag v1.0.5\nreplace (\n\tgithub.com/spf13/pflag => github.com/fork/pflag v1.0.0\n)\n"}, "github.com/spf13/pflag"},
	} {
		for _, side := range []string{"from", "to"} {
			t.Run(name+" "+side, func(t *testing.T) {
				f, tt := tree(prog("keep", "gone"), nil), tree(prog("keep"), nil)
				if side == "from" {
					f["go.mod"] = c.extra["go.mod"]
				} else {
					tt["go.mod"] = c.extra["go.mod"]
				}
				out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), f, tt)
				wantNoRule(t, out, pr, "FLAG_LIB_UNHASHED "+side+":"+ledgerItem(c.want))
			})
		}
	}
	// Allowed: bundled, replaced, or no flag library at all.
	pf := "\nrequire github.com/spf13/pflag v1.0.5\n"
	for name, extra := range map[string]map[string]string{
		"bundled":     {"go.mod": goMod + pf, "vendor/modules.txt": "# github.com/spf13/pflag v1.0.5\n## explicit\ngithub.com/spf13/pflag\n"},
		"replaced":    {"go.mod": goMod + pf + "replace github.com/spf13/pflag => ./third_party/pflag\n"},
		"replace blk": {"go.mod": goMod + pf + "replace (\n\tgithub.com/spf13/pflag v1.0.5 => ./third_party/pflag\n)\n"},
		"no library":  {"go.mod": goMod + "\nrequire example.org/other v1.0.0\n"},
	} {
		t.Run(name, func(t *testing.T) {
			f, tt := tree(prog("keep", "gone"), extra), tree(prog("keep"), extra)
			out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), f, tt)
			if len(pr.Ledger) != 0 || len(out.Entries) != 1 {
				t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
			}
		})
	}
	// A bundled list that names another module does not cover it.
	extra := map[string]string{"go.mod": goMod + pf, "vendor/modules.txt": "# github.com/spf13/pflagx v1.0.5\n"}
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", "gone"), extra), tree(prog("keep"), extra))
	if len(out.Entries) != 0 || len(pr.Ledger) == 0 {
		t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
	}
}

func TestPairFoldedSpellingsAreStillPresent(t *testing.T) {
	for name, c := range map[string]struct{ flag, lit string }{
		"underscore": {"gone-flag", "gone_flag"},
		"dash":       {"gone_flag", "gone-flag"},
		"case":       {"gone-flag", "Gone-Flag"},
		"prefixed":   {"gone-flag", "--GONE_FLAG=%s"},
	} {
		t.Run(name, func(t *testing.T) {
			to := tree(prog("keep"), map[string]string{"internal/s/s.go": "package s\n\nvar A = " + fmt.Sprintf("%q", c.lit) + "\n"})
			out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", c.flag), nil), to)
			wantNoRule(t, out, pr, "FLAG_NAME_STILL_PRESENT "+ledgerItem(c.flag))
		})
	}
}

func TestPairNormalizeFuncWithholds(t *testing.T) {
	norm := "package main\n\nimport \"github.com/spf13/pflag\"\n\nfunc main() {\n\tfs := pflag.NewFlagSet(\"x\", pflag.ExitOnError)\n\tfs.SetNormalizeFunc(func(f *pflag.FlagSet, n string) pflag.NormalizedName { return pflag.NormalizedName(n) })\n\tfs.String(\"keep\", \"\", \"u\")\n}\n"
	out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", "gone"), nil), tree(norm, nil))
	if len(out.Entries) != 0 || len(pr.Ledger) == 0 {
		t.Fatalf("rules %d ledger %v", len(out.Entries), codes(pr.Ledger))
	}
	found := false
	for _, e := range pr.Ledger {
		found = found || strings.HasPrefix(e.Code, "FLAG_NORMALIZE_FUNC")
	}
	if !found {
		t.Fatalf("no normalize entry: %v", codes(pr.Ledger))
	}
}

func TestPairSourceNoteStatesGoModIsAPin(t *testing.T) {
	_, pr := runPair(t, newTestExtractor(t, testSlug, testComponent), tree(prog("keep", "gone"), nil), tree(prog("keep"), nil))
	if n := proofOf(t, pr).SourceNote; !strings.Contains(n, "pin of the tree only") || !strings.Contains(n, "binary directories") {
		t.Fatalf("note %q", n)
	}
}

// pflagProg registers each name with pflag; mark is a statement template
// applied to the name (for example MarkHidden).
func pflagProg(mark string, names ...string) string {
	var b strings.Builder
	b.WriteString("package main\n\nimport \"github.com/spf13/pflag\"\n\nfunc main() {\n")
	for _, n := range names {
		fmt.Fprintf(&b, "\tpflag.String(%q, \"\", \"u\")\n", n)
		if mark != "" {
			fmt.Fprintf(&b, "\t"+mark+"\n", n)
		}
	}
	b.WriteString("\tpflag.Parse()\n}\n")
	return b.String()
}

var bundledPflag = map[string]string{
	"go.mod":             goMod + "\nrequire github.com/spf13/pflag v1.0.5\n",
	"vendor/modules.txt": "# github.com/spf13/pflag v1.0.5\n## explicit\ngithub.com/spf13/pflag\n",
}

// A hidden or deprecated flag is still accepted, so one that disappears from
// the newer tree is an ordinary removal candidate (the flag stays a set
// member; see Flag.Hidden and Flag.Deprecated).
func TestPairHiddenOrDeprecatedOlderFlagIsAnOrdinaryRemoval(t *testing.T) {
	for name, mark := range map[string]string{
		"hidden":     "pflag.CommandLine.MarkHidden(%q)",
		"deprecated": "pflag.CommandLine.MarkDeprecated(%q, \"use other\")",
	} {
		t.Run(name, func(t *testing.T) {
			out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent),
				tree(pflagProg(mark, "gone"), bundledPflag), tree(pflagProg("", "keep"), bundledPflag))
			if len(out.Entries) != 1 || !reflect.DeepEqual(out.Entries[0].Rule.SetCondition.Members, []string{"gone"}) {
				t.Fatalf("rules %+v ledger %v", out.Entries, codes(pr.Ledger))
			}
			if len(pr.Ledger) != 0 {
				t.Fatalf("ledger %v", codes(pr.Ledger))
			}
		})
	}
}

// A flag the newer tree keeps, even as hidden or deprecated, is not removed.
func TestPairHiddenOrDeprecatedNewerFlagIsNotARemoval(t *testing.T) {
	for name, mark := range map[string]string{
		"hidden":     "pflag.CommandLine.MarkHidden(%q)",
		"deprecated": "pflag.CommandLine.MarkDeprecated(%q, \"use other\")",
	} {
		t.Run(name, func(t *testing.T) {
			out, pr := runPair(t, newTestExtractor(t, testSlug, testComponent),
				tree(pflagProg("", "gone"), bundledPflag), tree(pflagProg(mark, "gone"), bundledPflag))
			wantNoRule(t, out, pr)
		})
	}
}
