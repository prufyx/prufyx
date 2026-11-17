// SPDX-License-Identifier: AGPL-3.0-only

package changelogcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/changelogattest"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

var (
	pilotFixture = filepath.Join("testdata", "pilot-prometheus")
	shippedDisp  = filepath.Join("..", "changelogattest", "dispositions", "prometheus.json")
	shippedTSV   = filepath.Join("..", "changelogattest", "dispositions", "prometheus.review.tsv")
	pilotTable   = changelogentries.Reviewed
)

func prom(t *testing.T) changelogentries.Target {
	t.Helper()
	tg, err := changelogentries.Lookup(pilotTable, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func attestArgs(t *testing.T, from, to, disp string) []string {
	tg := prom(t)
	return []string{"attest", "--component", tg.Component, "--repo", tg.Repo.Key, "--path", tg.Path, "--form", tg.Form,
		"--from-tag", from, "--to-tag", to, "--dispositions", disp, "--fixture", pilotFixture}
}

type attestOut struct {
	Schema             string `json:"schema"`
	DispositionsDigest string `json:"dispositionsDigest"`
	Pair               map[string]string
	Attestation        *struct {
		Basis      string   `json:"basis"`
		Line       string   `json:"line"`
		FactFamily string   `json:"factFamily"`
		RuleIDs    []string `json:"ruleIds"`
		Releases   struct {
			From, To []struct{ Version, Commit string }
		} `json:"releases"`
		Scope string `json:"scope"`
		Proof struct {
			Window       []string `json:"window"`
			Dispositions []struct {
				Tag         string `json:"tag"`
				Disposition string `json:"disposition"`
			} `json:"dispositions"`
		} `json:"proof"`
	} `json:"attestation"`
	Withheld *struct{ Code, Detail string } `json:"withheld"`
}

func runAttest(t *testing.T, from, to, disp string) (attestOut, []byte) {
	t.Helper()
	out := runOK(t, pilotTable, attestArgs(t, from, to, disp))
	if !bytes.HasSuffix(out, []byte("}\n")) || bytes.Count(out, []byte("\n")) != 1 {
		t.Fatal("the manifest must be one line")
	}
	var m attestOut
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m.Schema != AttestationSchema || (m.Attestation == nil) == (m.Withheld == nil) {
		t.Fatalf("schema or exactly-one rule: %+v", m)
	}
	return m, out
}

type pilotItem struct {
	Digest     string `json:"digest"`
	Occurrence int    `json:"occurrence"`
	StartLine  int    `json:"startLine"`
}

// items reads the items of one tag through the entries command.
func items(t *testing.T, tag string) []pilotItem {
	t.Helper()
	out := runOK(t, pilotTable, args(prom(t), tag, pilotFixture))
	var m struct {
		Entry struct {
			Items []pilotItem `json:"items"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(out, &m); err != nil || len(m.Entry.Items) == 0 {
		t.Fatalf("%s: %v", tag, err)
	}
	return m.Entry.Items
}

type mark struct {
	ItemDigest  string `json:"itemDigest"`
	Occurrence  int    `json:"occurrence"`
	Tag         string `json:"tag"`
	Kind        string `json:"kind"`
	RuleID      string `json:"ruleId,omitempty"`
	ReasonClass string `json:"reasonClass,omitempty"`
	State       string `json:"state"`
	ReviewedAt  string `json:"reviewedAt"`
	ProposedBy  string `json:"proposedBy"`
}

func neutral(tag string, it pilotItem) mark {
	return mark{ItemDigest: it.Digest, Occurrence: it.Occurrence, Tag: tag, Kind: "not-operator-facing",
		ReasonClass: "bugfix-no-contract-change", State: "reviewed", ReviewedAt: "2026-11-17T12:00:00Z", ProposedBy: "person"}
}

func writeDisp(t *testing.T, component string, marks []mark) string {
	t.Helper()
	if marks == nil {
		marks = []mark{}
	}
	b, err := json.Marshal(map[string]any{"component": component, "marks": marks})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "d.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// syntheticAll marks every item of the given tags not-operator-facing. It is
// a test input that proves the accepting path only: it is never shipped and
// says nothing about what those items are.
func syntheticAll(t *testing.T, tags ...string) []mark {
	var ms []mark
	for _, tag := range tags {
		for _, it := range items(t, tag) {
			ms = append(ms, neutral(tag, it))
		}
	}
	return ms
}

func TestAttestPositiveOnPinnedFixtures(t *testing.T) {
	marks := syntheticAll(t, "v3.15.0", "v3.15.1")
	disp := writeDisp(t, "prometheus", marks)
	m, out := runAttest(t, "v3.14.0", "v3.15.0", disp)
	a := m.Attestation
	if a == nil {
		t.Fatalf("withheld: %+v", m.Withheld)
	}
	if a.Basis != "mechanical" || a.Line != "3.15" || a.FactFamily != lineattest.FamilyChangelogAttestedEntries || len(a.RuleIDs) != 0 {
		t.Fatalf("attestation: %+v", a)
	}
	if strings.Join(a.Proof.Window, ",") != "v3.15.0,v3.15.1" || len(a.Proof.Dispositions) != len(marks) {
		t.Fatalf("window or dispositions: %v %d", a.Proof.Window, len(a.Proof.Dispositions))
	}
	if len(a.Releases.From) != 1 || a.Releases.From[0].Version != "3.14.0" || len(a.Releases.To) != 2 || a.Releases.To[1].Version != "3.15.1" {
		t.Fatalf("releases: %+v", a.Releases)
	}
	if !strings.Contains(a.Scope, "tags v3.15.0..v3.15.1") {
		t.Fatalf("scope: %q", a.Scope)
	}
	if !strings.HasPrefix(m.DispositionsDigest, "sha256:") || len(m.DispositionsDigest) != 71 {
		t.Fatalf("digest: %q", m.DispositionsDigest)
	}
	// Deterministic: equal inputs give equal bytes.
	if _, again := runAttest(t, "v3.14.0", "v3.15.0", disp); !bytes.Equal(out, again) {
		t.Fatal("two runs differ")
	}
}

func TestAttestNegativeOneMarkRemoved(t *testing.T) {
	marks := syntheticAll(t, "v3.15.0", "v3.15.1")
	for _, drop := range []int{0, len(marks) / 2, len(marks) - 1} {
		rest := append(append([]mark{}, marks[:drop]...), marks[drop+1:]...)
		m, _ := runAttest(t, "v3.14.0", "v3.15.0", writeDisp(t, "prometheus", rest))
		if m.Attestation != nil || m.Withheld.Code != "ITEM_UNRESOLVED" {
			t.Fatalf("drop %d: %+v", drop, m)
		}
	}
}

func TestAttestNegativeBadMarks(t *testing.T) {
	marks := syntheticAll(t, "v3.15.0", "v3.15.1")
	cases := map[string][]mark{}
	// A mark for an item that is not in the window.
	stray := neutral("v3.15.0", pilotItem{Digest: strings.Repeat("a", 64), Occurrence: 1})
	cases["stray mark"] = append(append([]mark{}, marks...), stray)
	// A mark whose tag is not the tag of the item.
	wrong := append([]mark{}, marks...)
	wrong[0].Tag = "v3.15.1"
	cases["wrong tag"] = wrong
	// A rule mark: no pack rule is given, so it can cite nothing.
	rule := append([]mark{}, marks...)
	rule[0].Kind, rule[0].ReasonClass, rule[0].RuleID = "rule", "", "some-rule"
	cases["rule mark without a rule"] = rule
	for name, ms := range cases {
		m, _ := runAttest(t, "v3.14.0", "v3.15.0", writeDisp(t, "prometheus", ms))
		if m.Attestation != nil || m.Withheld.Code != "ITEM_UNRESOLVED" {
			t.Fatalf("%s: %+v", name, m)
		}
	}
}

func TestAttestRefusesPairsThatAreNotOneMinorHop(t *testing.T) {
	disp := writeDisp(t, "prometheus", syntheticAll(t, "v3.15.0", "v3.15.1"))
	for _, p := range [][2]string{{"v3.13.0", "v3.15.0"}, {"v3.15.0", "v3.14.0"}, {"v3.15.0", "v3.15.1"}} {
		m, _ := runAttest(t, p[0], p[1], disp)
		if m.Attestation != nil || m.Withheld.Code != "NOT_PREVIOUS_MINOR" {
			t.Fatalf("%v: %+v", p, m)
		}
	}
}

// The shipped reviewed file leaves every operator-facing item unmarked, so
// the pairs those items belong to are withheld, never attested.
func TestShippedDispositionsWithholdTheirPairs(t *testing.T) {
	m, _ := runAttest(t, "v3.14.0", "v3.15.0", shippedDisp)
	if m.Attestation != nil || m.Withheld.Code != "ITEM_UNRESOLVED" {
		t.Fatalf("3.14 -> 3.15: %+v", m)
	}
	m, _ = runAttest(t, "v3.13.0", "v3.14.0", shippedDisp)
	// The newest tag's changelog does not carry the 3.13.3 entry, so the
	// amendment check cannot read it: withheld before any item is judged.
	if m.Attestation != nil || m.Withheld.Code != "ENTRY_MISSING" {
		t.Fatalf("3.13 -> 3.14: %+v", m)
	}
}

type review struct {
	tag, disposition string
	line, occ        int
}

func readReview(t *testing.T) map[string]review {
	t.Helper()
	raw, err := os.ReadFile(shippedTSV)
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if rows[0] != "tag\tline\titemDigest\toccurrence\tdisposition\treason" {
		t.Fatalf("header: %q", rows[0])
	}
	out := map[string]review{}
	for _, r := range rows[1:] {
		f := strings.Split(r, "\t")
		if len(f) != 6 || strings.TrimSpace(f[5]) == "" {
			t.Fatalf("row without a reason: %q", r)
		}
		var rv review
		rv.tag, rv.disposition = f[0], f[4]
		fmt.Sscan(f[1], &rv.line)
		fmt.Sscan(f[3], &rv.occ)
		if _, dup := out[f[0]+"/"+f[2]]; dup {
			t.Fatalf("duplicate row %s", r)
		}
		out[f[0]+"/"+f[2]] = rv
	}
	return out
}

// Every item of every tag of both windows has exactly one review row with a
// reason, and the dispositions file marks exactly the rows reviewed as not
// operator-facing, with the class the row names.
func TestShippedDispositionsMatchTheReview(t *testing.T) {
	raw, err := os.ReadFile(shippedDisp)
	if err != nil {
		t.Fatal(err)
	}
	d, err := changelogattest.LoadDispositions(raw, "prometheus")
	if err != nil {
		t.Fatal(err)
	}
	rows := readReview(t)
	marked := map[string]changelogattest.Mark{}
	for _, m := range d.Marks {
		if m.Kind != changelogattest.KindNotOperatorFacing || m.ProposedBy != changelogattest.ProposedByPerson {
			t.Fatalf("mark %+v", m)
		}
		marked[m.Tag+"/"+m.ItemDigest] = m
	}
	seen, blockers := 0, map[string]int{}
	for _, tag := range []string{"v3.13.1", "v3.13.2", "v3.13.3", "v3.13.4", "v3.13.5", "v3.14.0", "v3.15.0", "v3.15.1"} {
		for _, it := range items(t, tag) {
			key := tag + "/" + it.Digest
			rv, ok := rows[key]
			if !ok || rv.occ != it.Occurrence || rv.line != it.StartLine {
				t.Fatalf("%s line %d has no matching review row", tag, it.StartLine)
			}
			seen++
			m, isMarked := marked[key]
			switch {
			case rv.disposition == "operator-facing" && !isMarked:
				blockers[tag]++
			case rv.disposition == "not-operator-facing:"+m.ReasonClass && isMarked:
			default:
				t.Fatalf("%s line %d: review %q and mark %v disagree", tag, it.StartLine, rv.disposition, isMarked)
			}
		}
	}
	if seen != len(rows) || len(marked)+blockers["v3.13.1"]+blockers["v3.13.2"]+blockers["v3.13.3"]+blockers["v3.13.4"]+
		blockers["v3.13.5"]+blockers["v3.14.0"]+blockers["v3.15.0"]+blockers["v3.15.1"] != seen {
		t.Fatalf("rows %d, items %d, marks %d", len(rows), seen, len(marked))
	}
	// The items that block 3.14 -> 3.15 and 3.13 -> 3.14.
	if blockers["v3.15.0"] != 14 || blockers["v3.15.1"] != 1 || blockers["v3.14.0"] != 10 || blockers["v3.13.5"] != 2 {
		t.Fatalf("blockers: %v", blockers)
	}
}

func TestAttestRefusals(t *testing.T) {
	good := attestArgs(t, "v3.14.0", "v3.15.0", shippedDisp)
	with := func(flag, val string) []string {
		out := append([]string{}, good...)
		for i, a := range out {
			if a == flag {
				out[i+1] = val
			}
		}
		return out
	}
	without := func(flag string) []string {
		var out []string
		for i := 0; i < len(good); i++ {
			if good[i] == flag {
				i++
				continue
			}
			out = append(out, good[i])
		}
		return out
	}
	other := writeDisp(t, "alertmanager", nil)
	unknownField := filepath.Join(t.TempDir(), "u.json")
	if err := os.WriteFile(unknownField, []byte(`{"component":"prometheus","marks":[],"extra":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	proposed := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(proposed, []byte(`{"component":"prometheus","marks":[{"itemDigest":"`+strings.Repeat("a", 64)+
		`","occurrence":1,"tag":"v3.15.0","kind":"not-operator-facing","reasonClass":"docs","state":"proposed","reviewedAt":"2026-11-17T12:00:00Z","proposedBy":"model"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no subcommand flag":           {"attest"},
		"missing dispositions":         without("--dispositions"),
		"missing from-tag":             without("--from-tag"),
		"both sources":                 append(append([]string{}, good...), "--mirror-state", t.TempDir()),
		"no source":                    without("--fixture"),
		"repeated flag":                append(append([]string{}, good...), "--to-tag", "v3.15.1"),
		"extra argument":               append(append([]string{}, good...), "x"),
		"unknown flag":                 append(append([]string{}, good...), "--classifier", "x"),
		"repo disagrees":               with("--repo", "github.com/prometheus/alertmanager"),
		"path disagrees":               with("--path", "docs/CHANGELOG.md"),
		"unreviewed component":         with("--component", "nothing"),
		"from-tag not recorded":        with("--from-tag", "v3.99.0"),
		"to-tag not recorded":          with("--to-tag", "v3.99.0"),
		"dispositions missing":         with("--dispositions", filepath.Join(t.TempDir(), "absent.json")),
		"dispositions is a directory":  with("--dispositions", t.TempDir()),
		"dispositions of another comp": with("--dispositions", other),
		"dispositions unknown field":   with("--dispositions", unknownField),
		"dispositions unreviewed mark": with("--dispositions", proposed),
		"component without file form":  {"attest", "--component", "vault", "--repo", "github.com/hashicorp/vault", "--path", "", "--form", changelogentries.FormPostTag, "--from-tag", "a", "--to-tag", "b", "--dispositions", shippedDisp, "--fixture", pilotFixture},
	}
	for name, a := range cases {
		t.Run(name, func(t *testing.T) { runRefused(t, pilotTable, a) })
	}
}
