// SPDX-License-Identifier: AGPL-3.0-only

package extract

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// ledgerToy derives no rule and claims a quiet-line attestation for its
// pair, with whatever ledger the test sets. Without a ledger the claim is
// stamped, so a test that sees "not attested" has seen the framework refuse.
type ledgerToy struct {
	toyExtractor
	ledger []LedgerEntry
	claim  bool
}

func (ledgerToy) AttestedFamilies() []string {
	return []string{lineattest.FamilyKubernetesRemovedServedGVK}
}
func (ledgerToy) AttestedComponent() string { return attestComponent }
func (x ledgerToy) Extract(_ context.Context, r PinnedReader, p VersionPair) (Extraction, error) {
	if _, err := r.Read(p.Repo, p.FromCommit, "decl.go"); err != nil {
		return Extraction{}, err
	}
	e := Extraction{Proof: map[string]any{}, Ledger: x.ledger}
	if x.claim {
		e.Attestations = []AttestationCandidate{{Component: attestComponent, Line: "2.0", FactFamily: lineattest.FamilyKubernetesRemovedServedGVK,
			Sources: []SourceRef{{ID: "toy-declaration", Repo: p.Repo, Commit: p.FromCommit, Path: "decl.go", StartLine: 3, EndLine: 3}}}}
	}
	return e, nil
}

func runLedgerToy(x ledgerToy) (*Output, error) {
	root, err := os.MkdirTemp("", "ledger-toy")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	writeFixture(root)
	fr := FixtureReader{Root: root}
	r, _ := ParseRepo(testRepo)
	return Run(context.Background(), x, fr, fr, Options{Repo: r, DerivedAt: toyTime})
}

// writeFixture mirrors toyFixture without a *testing.T.
func writeFixture(root string) {
	dir := filepath.Join(root, filepath.FromSlash(testRepo))
	for commit, files := range map[string]map[string]string{
		testCommit: {"decl.go": "package decl\n\nconst Old = \"old\"\n", "other.go": "package decl\n"},
		testNext:   {"decl.go": "package decl\n"},
	} {
		for name, data := range files {
			p := filepath.Join(dir, "commits", commit, name)
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.WriteFile(p, []byte(data), 0o644)
		}
	}
	_ = os.WriteFile(filepath.Join(dir, "tags.json"), []byte(`{"v1.0.0":"`+testCommit+`","v2.0.0":"`+testNext+`"}`), 0o644)
}

func validLedger() []LedgerEntry {
	return []LedgerEntry{{Code: "FIELD_UNENCODABLE", Item: "spec.versions[v1].schema.a"}, {Code: "FIELD_UNENCODABLE", Item: "spec.b"}, {Code: "MEMBER_CHARSET", Item: "x.y"}}
}

// --- scenarios: each returns nil when the guard works ---

func scenarioCode() error {
	got := normalizeLedger([]LedgerEntry{{Code: "bad code", Item: "a"}})
	return wantFault("bad code", got, LedgerInvalid)
}

func scenarioItem() error {
	for _, item := range []string{"has space", "", "quote\"d", "line\nbreak", strings.Repeat("a", MaxLedgerItemLen+1), "é"} {
		if err := wantFault(fmt.Sprintf("item %q", item), normalizeLedger([]LedgerEntry{{Code: "CODE_OK", Item: item}}), LedgerInvalid); err != nil {
			return err
		}
	}
	return nil
}

func scenarioReserved() error {
	return wantFault("reserved code", normalizeLedger([]LedgerEntry{{Code: LedgerOverflow, Item: "a"}}), LedgerInvalid)
}

func scenarioCap() error {
	var in []LedgerEntry
	for i := 0; i <= MaxLedgerEntries; i++ {
		in = append(in, LedgerEntry{Code: "CODE_OK", Item: fmt.Sprintf("item%d", i)})
	}
	if err := wantFault("cap+1 entries", normalizeLedger(in), LedgerOverflow); err != nil {
		return err
	}
	if got := normalizeLedger(in[:MaxLedgerEntries]); len(got) != MaxLedgerEntries {
		return fmt.Errorf("exactly the cap must be kept whole, got %d entries", len(got))
	}
	return nil
}

func scenarioSort() error {
	got := normalizeLedger([]LedgerEntry{{Code: "B_CODE", Item: "a"}, {Code: "A_CODE", Item: "z"}, {Code: "A_CODE", Item: "b"}})
	want := []LedgerEntry{{Code: "A_CODE", Item: "b"}, {Code: "A_CODE", Item: "z"}, {Code: "B_CODE", Item: "a"}}
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("not sorted: %v", got)
	}
	return nil
}

func scenarioDedupe() error {
	e := LedgerEntry{Code: "A_CODE", Item: "b"}
	if got := normalizeLedger([]LedgerEntry{e, e, e}); len(got) != 1 {
		return fmt.Errorf("duplicates kept: %v", got)
	}
	return nil
}

func scenarioAttestVeto() error {
	// A ledger together with attestation candidates is refused outright.
	if _, err := runLedgerToy(ledgerToy{ledger: validLedger(), claim: true}); err == nil {
		return fmt.Errorf("ledger with attestation candidates accepted")
	}
	out, err := runLedgerToy(ledgerToy{ledger: validLedger()})
	if err != nil {
		return err
	}
	pa := out.Manifest.Pairs[0].Attestation
	if pa == nil || pa.Status != PairNotAttested || len(pa.Families) != 0 || len(out.Attestations) != 0 || out.Manifest.Totals.Attestations != 0 {
		return fmt.Errorf("pair with ledger attested: %+v, %d attestations", pa, len(out.Attestations))
	}
	return nil
}

func scenarioRecordedScan() error {
	p := PairRecord{From: "1.0.0", To: "2.0.0", Ledger: normalizeLedger(validLedger()), Attestation: &PairAttestation{Status: PairAttested, Line: "2.0", Families: []string{lineattest.FamilyKubernetesRemovedServedGVK}}}
	if CheckPairLedger(p) == nil {
		return fmt.Errorf("record with ledger and attestation accepted")
	}
	return nil
}

func wantFault(what string, got []LedgerEntry, code string) error {
	if len(got) != 1 || got[0].Code != code || got[0].Item != LedgerFrameworkItem {
		return fmt.Errorf("%s: want one %s entry, got %v", what, code, got)
	}
	return nil
}

// scenarios maps each guard to its scenario; the named tests below run the
// scenario, TestLedgerMutations turns the guard off and requires failure.
var ledgerScenarios = map[string]struct {
	run func() error
	off func()
}{
	"TestLedgerCodeVocabulary":      {scenarioCode, func() { ledgerGuards.noCodeCheck = true }},
	"TestLedgerItemCharsetAndLen":   {scenarioItem, func() { ledgerGuards.noItemCheck = true }},
	"TestLedgerReservedCodes":       {scenarioReserved, func() { ledgerGuards.noReserved = true }},
	"TestLedgerEntryCap":            {scenarioCap, func() { ledgerGuards.noCap = true }},
	"TestLedgerSorted":              {scenarioSort, func() { ledgerGuards.noSort = true }},
	"TestLedgerDeduplicated":        {scenarioDedupe, func() { ledgerGuards.noDedupe = true }},
	"TestLedgerNeverYieldsAttested": {scenarioAttestVeto, func() { ledgerGuards.noAttestVeto = true }},
	"TestLedgerRecordedScan":        {scenarioRecordedScan, func() { ledgerGuards.noRecordedScan = true }},
}

func TestLedgerCodeVocabulary(t *testing.T)    { mustPass(t, "TestLedgerCodeVocabulary") }
func TestLedgerItemCharsetAndLen(t *testing.T) { mustPass(t, "TestLedgerItemCharsetAndLen") }
func TestLedgerReservedCodes(t *testing.T)     { mustPass(t, "TestLedgerReservedCodes") }
func TestLedgerEntryCap(t *testing.T)          { mustPass(t, "TestLedgerEntryCap") }
func TestLedgerSorted(t *testing.T)            { mustPass(t, "TestLedgerSorted") }
func TestLedgerDeduplicated(t *testing.T)      { mustPass(t, "TestLedgerDeduplicated") }
func TestLedgerRecordedScan(t *testing.T)      { mustPass(t, "TestLedgerRecordedScan") }

func TestLedgerNeverYieldsAttested(t *testing.T) {
	mustPass(t, "TestLedgerNeverYieldsAttested")
	// Control: the same claim without a ledger is stamped, so the veto above
	// is the framework refusing, not the toy failing to claim.
	out, err := runLedgerToy(ledgerToy{claim: true})
	if err != nil {
		t.Fatal(err)
	}
	if pa := out.Manifest.Pairs[0].Attestation; pa == nil || pa.Status != PairAttested || len(out.Attestations) != 1 {
		t.Fatalf("control did not attest: %+v", pa)
	}
	// Each framework fault (invalid, overflow) is a non-empty ledger too.
	bad := []LedgerEntry{{Code: "lower", Item: "a"}}
	out, err = runLedgerToy(ledgerToy{ledger: bad})
	if err != nil {
		t.Fatal(err)
	}
	if pa := out.Manifest.Pairs[0].Attestation; pa.Status != PairNotAttested || pa.Reason != "the item ledger is invalid" || len(out.Attestations) != 0 {
		t.Fatalf("invalid ledger: %+v", pa)
	}
}

func mustPass(t *testing.T, name string) {
	t.Helper()
	if err := ledgerScenarios[name].run(); err != nil {
		t.Fatal(err)
	}
}

// TestLedgerMutations disables each guard in turn and requires the test
// named for it to fail.
func TestLedgerMutations(t *testing.T) {
	for name, s := range ledgerScenarios {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { ledgerGuards = ledgerGuardSet{} })
			if err := s.run(); err != nil {
				t.Fatalf("scenario fails with all guards on: %v", err)
			}
			s.off()
			if s.run() == nil {
				t.Fatalf("%s still passes with its guard off", name)
			}
		})
	}
}

// TestLedgerNeverAttestedProperty generates ledgers, valid and not, and
// requires that a non-empty one never yields an attested pair or an
// attestation, and that what is recorded is canonical.
func TestLedgerNeverAttestedProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	codes := []string{"A_CODE", "B_CODE", "bad", "X", strings.Repeat("A", 49), "OK_CODE"}
	items := []string{"a", "a.b", "a[0].b", "has space", "", strings.Repeat("a", 201), "x/y:z", "\x00"}
	for i := 0; i < 200; i++ {
		var l []LedgerEntry
		for n := rng.IntN(6); n > 0; n-- {
			l = append(l, LedgerEntry{Code: codes[rng.IntN(len(codes))], Item: items[rng.IntN(len(items))]})
		}
		if rng.IntN(10) == 0 {
			for j := 0; j <= MaxLedgerEntries; j++ {
				l = append(l, LedgerEntry{Code: "OK_CODE", Item: fmt.Sprintf("i%d", j)})
			}
		}
		if len(l) > 0 {
			if _, err := runLedgerToy(ledgerToy{ledger: l, claim: true}); err == nil {
				t.Fatalf("ledger %v with a claim accepted", l)
			}
		}
		out, err := runLedgerToy(ledgerToy{ledger: l})
		if err != nil {
			t.Fatalf("ledger %v: %v", l, err)
		}
		p := out.Manifest.Pairs[0]
		if len(l) == 0 {
			continue
		}
		if len(p.Ledger) == 0 || p.Attestation == nil || p.Attestation.Status != PairNotAttested || len(out.Attestations) != 0 || out.Manifest.Totals.Attestations != 0 {
			t.Fatalf("ledger %v yielded %+v", l, p)
		}
		if len(p.Ledger) > MaxLedgerEntries {
			t.Fatalf("ledger above the cap recorded: %d", len(p.Ledger))
		}
		if err := CheckPairLedger(p); err != nil {
			t.Fatalf("recorded pair fails its own check: %v", err)
		}
	}
}

func TestLedgerDeterministicUnderShuffle(t *testing.T) {
	base := validLedger()
	base = append(base, base[0], LedgerEntry{Code: "AAA", Item: "z"})
	want, err := runLedgerToy(ledgerToy{ledger: base})
	if err != nil {
		t.Fatal(err)
	}
	wantFiles, err := want.Files()
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(3, 4))
	for i := 0; i < 20; i++ {
		l := append([]LedgerEntry(nil), base...)
		rng.Shuffle(len(l), func(a, b int) { l[a], l[b] = l[b], l[a] })
		got, err := runLedgerToy(ledgerToy{ledger: l})
		if err != nil {
			t.Fatal(err)
		}
		gotFiles, err := got.Files()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotFiles[FileManifest], wantFiles[FileManifest]) {
			t.Fatalf("shuffle %d changed the manifest", i)
		}
	}
	if n := want.Manifest.Totals.LedgerItems; n != 4 {
		t.Fatalf("totals.ledgerItems = %d, want 4", n)
	}
}

// TestEmptyLedgerLeavesNoTrace: with no ledger, neither the pair nor the
// totals carry any new key, so the output of every existing extractor keeps
// its bytes (apart from the code digest, which covers this package).
func TestEmptyLedgerLeavesNoTrace(t *testing.T) {
	out, err := runToy(t, toyExtractor{members: []string{"old"}, startLine: 3, endLine: 3}, toyFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	files, err := out.Files()
	if err != nil {
		t.Fatal(err)
	}
	if s := string(files[FileManifest]); strings.Contains(s, `"ledger"`) || strings.Contains(s, "ledgerItems") {
		t.Fatalf("manifest of a run without a ledger mentions it:\n%s", s)
	}
}

// TestLedgerRoundTripAndHandEdit writes a ledger-bearing run, verifies it,
// then hand-edits the manifest to attest the pair.
func TestLedgerRoundTripAndHandEdit(t *testing.T) {
	root := toyFixture(t)
	x := ledgerToy{ledger: validLedger()}
	fr := FixtureReader{Root: root}
	out, err := Run(context.Background(), x, fr, fr, Options{Repo: repoRef(t), DerivedAt: toyTime})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "out")
	if err := out.Write(dir); err != nil {
		t.Fatal(err)
	}
	problems, err := Verify(context.Background(), x, fr, fr, dir, nil)
	if err != nil || len(problems) != 0 {
		t.Fatalf("verify: %v, %v", problems, err)
	}
	m, err := ReadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.Pairs[0].Ledger, normalizeLedger(validLedger())) || m.Totals.LedgerItems != 3 {
		t.Fatalf("ledger lost in the round trip: %+v", m.Pairs[0].Ledger)
	}
	p := filepath.Join(dir, FileManifest)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"status": "not-attested"`, `"status": "attested"`, 1)
	if edited == string(raw) {
		t.Fatal("manifest has no not-attested status to edit")
	}
	if err := os.WriteFile(p, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	problems, err = Verify(context.Background(), x, fr, fr, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "attested although its ledger is not empty") || !strings.Contains(joined, "manifest.json: differs from the re-derivation") {
		t.Fatalf("hand-edited record not refused: %v", problems)
	}
}

func TestCheckPairLedger(t *testing.T) {
	att := &PairAttestation{Status: PairAttested, Families: []string{"f"}}
	notAtt := &PairAttestation{Status: PairNotAttested, Families: []string{}}
	cases := []struct {
		name    string
		p       PairRecord
		wantErr bool
	}{
		{"no ledger, attested", PairRecord{Attestation: att}, false},
		{"ledger, not attested", PairRecord{Ledger: normalizeLedger(validLedger()), Attestation: notAtt}, false},
		{"ledger, non-attester", PairRecord{Ledger: normalizeLedger(validLedger())}, false},
		{"ledger, attested", PairRecord{Ledger: normalizeLedger(validLedger()), Attestation: att}, true},
		{"ledger, not-attested with families", PairRecord{Ledger: normalizeLedger(validLedger()), Attestation: &PairAttestation{Status: PairNotAttested, Families: []string{"f"}}}, true},
		{"ledger unsorted", PairRecord{Ledger: []LedgerEntry{{Code: "B_CODE", Item: "a"}, {Code: "A_CODE", Item: "a"}}, Attestation: notAtt}, true},
		{"ledger duplicate", PairRecord{Ledger: []LedgerEntry{{Code: "A_CODE", Item: "a"}, {Code: "A_CODE", Item: "a"}}, Attestation: notAtt}, true},
		{"ledger bad charset", PairRecord{Ledger: []LedgerEntry{{Code: "A_CODE", Item: "a b"}}, Attestation: notAtt}, true},
		{"framework fault", PairRecord{Ledger: faultLedger(LedgerOverflow), Attestation: notAtt}, false},
		{"framework fault, attested", PairRecord{Ledger: faultLedger(LedgerOverflow), Attestation: att}, true},
		{"forged framework code", PairRecord{Ledger: []LedgerEntry{{Code: LedgerInvalid, Item: "other"}}, Attestation: notAtt}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := CheckPairLedger(c.p); (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

// vocabToy closes the ledger vocabulary.
type vocabToy struct {
	ledgerToy
	codes []string
}

func (v vocabToy) LedgerCodes() []string { return v.codes }

func TestLedgerReservedPrefixIsAnError(t *testing.T) {
	for _, code := range []string{LedgerInvalid, LedgerOverflow, "LEDGER_OTHER"} {
		if _, err := runLedgerToy(ledgerToy{ledger: []LedgerEntry{{Code: code, Item: "a"}}}); err == nil {
			t.Fatalf("reserved code %s accepted", code)
		}
	}
	// Overflow stays a fault entry, not an error.
	var in []LedgerEntry
	for i := 0; i <= MaxLedgerEntries; i++ {
		in = append(in, LedgerEntry{Code: "CODE_OK", Item: fmt.Sprintf("i%d", i)})
	}
	out, err := runLedgerToy(ledgerToy{ledger: in})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Manifest.Pairs[0].Ledger; len(got) != 1 || got[0].Code != LedgerOverflow {
		t.Fatalf("overflow = %v", got)
	}
}

func TestLedgerItemRejectsEquals(t *testing.T) {
	if err := wantFault("equals", normalizeLedger([]LedgerEntry{{Code: "CODE_OK", Item: "a=b"}}), LedgerInvalid); err != nil {
		t.Fatal(err)
	}
	if got := normalizeLedger([]LedgerEntry{{Code: "CODE_OK", Item: strings.Repeat("a", MaxLedgerItemLen)}}); len(got) != 1 || got[0].Code != "CODE_OK" {
		t.Fatalf("max-length item refused: %v", got)
	}
}

func TestLedgerDeclaredVocabulary(t *testing.T) {
	l := []LedgerEntry{{Code: "FIELD_UNENCODABLE", Item: "a"}}
	// Not implemented: open vocabulary.
	out, err := runLedgerToy(ledgerToy{ledger: l})
	if err != nil || out.Manifest.Pairs[0].Ledger[0].Code != "FIELD_UNENCODABLE" {
		t.Fatalf("open vocabulary: %v, %v", out, err)
	}
	// Implemented and listing the code: kept.
	out, err = runLedgerToy2(vocabToy{ledgerToy{ledger: l}, []string{"FIELD_UNENCODABLE"}})
	if err != nil || out.Manifest.Pairs[0].Ledger[0].Code != "FIELD_UNENCODABLE" {
		t.Fatalf("listed code: %v, %v", out, err)
	}
	// Implemented and not listing it: LEDGER_INVALID, pair not attested.
	for _, codes := range [][]string{{"OTHER_CODE"}, nil} {
		out, err = runLedgerToy2(vocabToy{ledgerToy{ledger: l}, codes})
		if err != nil {
			t.Fatal(err)
		}
		p := out.Manifest.Pairs[0]
		if err := wantFault("unknown code", p.Ledger, LedgerInvalid); err != nil || p.Attestation.Status != PairNotAttested {
			t.Fatalf("unknown code: %v %+v", err, p)
		}
	}
	// A malformed or reserved declared vocabulary is an error.
	for _, bad := range []string{"lower", LedgerInvalid} {
		if _, err := runLedgerToy2(vocabToy{ledgerToy{ledger: l}, []string{bad}}); err == nil {
			t.Fatalf("vocabulary code %q accepted", bad)
		}
	}
}

func runLedgerToy2(x Extractor) (*Output, error) {
	root, err := os.MkdirTemp("", "ledger-toy")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	writeFixture(root)
	fr := FixtureReader{Root: root}
	r, _ := ParseRepo(testRepo)
	return Run(context.Background(), x, fr, fr, Options{Repo: r, DerivedAt: toyTime})
}
