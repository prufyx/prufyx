// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// Line attestations of the custom-resource version family: the synthetic
// Argo CD fixture of the CRD extractor attests line 90.1 (two removals)
// and line 90.2 (quiet). Argo CD's set fact is registered, so its rules are
// admitted.

var argoFixture = extract.FixtureReader{Root: filepath.Join("..", "..", "extract", "crdversions", "testdata", "fixture")}

const argoComponent = "pkg:github/argoproj/argo-cd"

func crdAttestationID(line string) string {
	return evidencerepin.LineAttestationRecordID(argoComponent, lineattest.FamilyCustomResourceVersions, line)
}

// argoDerivation runs the CRD extractor for Argo CD over its synthetic
// fixture and returns its entries and attestations as JSON values.
func argoDerivation(t *testing.T, at time.Time) ([]map[string]any, []map[string]any) {
	t.Helper()
	tg, ok := crdversions.TargetFor("argo-cd")
	if !ok || !tg.Attest {
		t.Fatal("argo-cd does not attest")
	}
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	out, err := extract.Run(context.Background(), crdversions.New(tg), argoFixture, argoFixture, extract.Options{Repo: repo, DerivedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	decode := func(v any) []map[string]any {
		raw, err := extract.Canonical(v)
		if err != nil {
			t.Fatal(err)
		}
		var out []map[string]any
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if err := dec.Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	entries, atts := decode(out.Entries), decode(out.Attestations)
	if len(entries) != 2 || len(atts) != 2 {
		t.Fatalf("%d entries, %d attestations", len(entries), len(atts))
	}
	return entries, atts
}

func attestationOfLine(atts []map[string]any, line string) map[string]any {
	for _, a := range atts {
		if a["line"] == line {
			return deepCopy(a).(map[string]any)
		}
	}
	return nil
}

// crdAttestedTrees returns a base whose CNCF pack holds the derived Argo CD
// rules and the attestation of line 90.1, and a head that also holds
// whatever records edit returns (the base's 90.1 attestation is passed in).
func crdAttestedTrees(t *testing.T, edit func(base90_1 map[string]any, derived []map[string]any) []map[string]any) (Tree, Tree) {
	t.Helper()
	return crdAttestedTreesWith(t, true, edit)
}

// crdAttestedTreesWith is crdAttestedTrees; without regenerate, the head's
// derived files are left as they are (for a head pack that does not load).
func crdAttestedTreesWith(t *testing.T, regenerateHead bool, edit func(base90_1 map[string]any, derived []map[string]any) []map[string]any) (Tree, Tree) {
	t.Helper()
	entries, atts := argoDerivation(t, gateNow.Add(-time.Hour))
	base, head := trees(t)
	set := func(tr Tree, records []map[string]any) {
		apply := editPack
		if tr == head && !regenerateHead {
			apply = func(t *testing.T, tr Tree, rel string, edit func(p *packDoc)) {
				p := readPack(t, tr, rel)
				edit(p)
				p.write(t, tr, rel)
			}
		}
		apply(t, tr, cncfRulesPath, func(p *packDoc) {
			p.entries = append(p.entries, entries...)
			p.sortByID()
			sortRecords(records)
			raw, err := json.Marshal(records)
			if err != nil {
				t.Fatal(err)
			}
			p.fields["lineAttestations"] = raw
			p.fields["schema"] = json.RawMessage(`"` + attestedPackSchema + `"`)
		})
	}
	set(base, []map[string]any{attestationOfLine(atts, "90.1")})
	set(head, edit(attestationOfLine(atts, "90.1"), atts))
	return base, head
}

// sortRecords puts attestation records of one component and family in
// line order.
func sortRecords(records []map[string]any) {
	slices.SortFunc(records, func(a, b map[string]any) int {
		x, y := a["line"].(string), b["line"].(string)
		switch {
		case lineattest.LineLess(x, y):
			return -1
		case lineattest.LineLess(y, x):
			return 1
		}
		return 0
	})
}

// A mechanical attestation of a quiet custom-resource line is admitted
// only by re-deriving it, byte for byte, with the extractor the gate runs:
// no person, no approval.
func TestGateMechanicalCRDAttestation(t *testing.T) {
	add := func(tamper func(a map[string]any)) (Tree, Tree) {
		return crdAttestedTrees(t, func(base90_1 map[string]any, derived []map[string]any) []map[string]any {
			a := attestationOfLine(derived, "90.2")
			if tamper != nil {
				tamper(a)
			}
			return []map[string]any{base90_1, a}
		})
	}
	base, head := add(nil)
	r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
	requireAdmittedButUnsplit(t, r)
	c := change(t, r, crdAttestationID("90.2"))
	if c.Proof != ProofRederived || c.Basis != "mechanical" || c.Kinds[0] != KindNew || c.Class != ClassLoosening {
		t.Fatalf("change %+v", c)
	}
	if len(r.Changes) != 1 {
		t.Fatalf("changes %+v", r.Changes)
	}

	// The scheduled run re-derives both stored attestations.
	r = runGate(t, Options{Base: head, Head: head, Source: argoFixture, RederiveAll: true})
	requireAdmittedButUnsplit(t, r)
	if c, _ := check(r, "rederive-all"); !strings.Contains(c.Detail, "2 of them line attestations") {
		t.Fatalf("rederive-all %+v", c)
	}

	firstRelease := func(a map[string]any, side string) map[string]any {
		return a["releases"].(map[string]any)[side].([]any)[0].(map[string]any)
	}
	for name, tc := range map[string]struct {
		tamper func(a map[string]any)
		opts   func(o *Options)
		want   string
	}{
		"release added": {func(a map[string]any) {
			rel := a["releases"].(map[string]any)
			rel["to"] = append(rel["to"].([]any), map[string]any{"version": "90.2.1", "commit": "0000000000000000000000000000000000902001"})
		}, nil, "differs from what extractor"},
		"release commit": {func(a map[string]any) { firstRelease(a, "from")["commit"] = "0000000000000000000000000000000000909999" }, nil, "differs from what extractor"},
		"release dropped": {func(a map[string]any) {
			rel := a["releases"].(map[string]any)
			rel["from"] = rel["from"].([]any)[:1]
		}, nil, "differs from what extractor"},
		"cited span": {func(a map[string]any) {
			a["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["endLine"] = json.Number("2")
		}, nil, "differs from what extractor"},
		"other project's extractor": {func(a map[string]any) {
			a["evidence"].(map[string]any)["extractor"].(map[string]any)["id"] = "crd.version-removal.istio"
		}, nil, "re-derivation failed"},
		"extractor version": {func(a map[string]any) {
			a["evidence"].(map[string]any)["extractor"].(map[string]any)["version"] = "2.0.0"
		}, nil, "this gate runs"},
		"no source":            {nil, func(o *Options) { o.Source = nil }, "no upstream source"},
		"derived too long ago": {nil, func(o *Options) { o.Now = gateNow.Add(48 * time.Hour) }, "outside [now-24h, now+5m]"},
	} {
		t.Run(name, func(t *testing.T) {
			base, head := add(tc.tamper)
			o := Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin}
			if tc.opts != nil {
				tc.opts(&o)
			}
			r := runGate(t, o)
			requireFail(t, r, tc.want)
			if c := change(t, r, crdAttestationID("90.2")); c.OK {
				t.Fatalf("admitted %+v", c)
			}
		})
	}

	// An attestation that hides a removal is refused twice over: the pack
	// holds a rule it does not list, and the extractor derives another
	// record.
	t.Run("rule left out", func(t *testing.T) {
		base, head := crdAttestedTreesWith(t, false, func(base90_1 map[string]any, _ []map[string]any) []map[string]any {
			base90_1["ruleIds"] = base90_1["ruleIds"].([]any)[:1]
			return []map[string]any{base90_1}
		})
		r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
		requireFail(t, r, "differs from what extractor")
		requireFail(t, r, "rulecheck/cncf/lineAttestations")
	})

	// A line the extractor does not attest (here: no release exists) is
	// refused, whatever the record says.
	t.Run("line not attested upstream", func(t *testing.T) {
		base, head := add(func(a map[string]any) {
			a["line"] = "90.3"
			a["releases"] = map[string]any{
				"from": []any{map[string]any{"version": "90.2.0", "commit": "0000000000000000000000000000000000902000"}},
				"to":   []any{map[string]any{"version": "90.3.0", "commit": "0000000000000000000000000000000000903000"}},
			}
		})
		r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
		requireFail(t, r, "does not attest this line")
	})

	// An owner approval never admits a mechanical attestation.
	t.Run("approval does not admit a mechanical attestation", func(t *testing.T) {
		key := newApprovalKey(t)
		base, head := add(func(a map[string]any) {
			a["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["startLine"] = json.Number("2")
		})
		key.pinBoth(t, base, head, "airstand")
		id := crdAttestationID("90.2")
		writeFile(t, approvalPath(head, id), key.sign(t, crdRecordApproval(id, "90.2", ApprovalBaseAbsent, recordDigest(t, head, id))))
		r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
		requireFail(t, r, "differs from what extractor")
		if c := change(t, r, id); c.OK || c.Proof == ProofApproval {
			t.Fatalf("admitted %+v", c)
		}
	})
}

func crdRecordApproval(id, line, base, digest string) ApprovalRecord {
	r := recordApproval(id, line, base, digest)
	r.Scope = argoComponent + " " + lineattest.FamilyCustomResourceVersions + " " + line
	return r
}

// reviewed turns a derived attestation into a reviewed one.
func reviewedCRD(a map[string]any) map[string]any {
	ev := a["evidence"].(map[string]any)
	delete(ev, "extractor")
	delete(ev, "derivedAt")
	ev["basis"] = "reviewed"
	ev["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
	ev["validUntil"] = gateNow.Add(50 * 24 * time.Hour).Format(time.RFC3339)
	return a
}

// A reviewed attestation of the family needs an owner approval and the
// cross-check against the extractor of its own component.
func TestGateReviewedCRDAttestation(t *testing.T) {
	key := newApprovalKey(t)
	setup := func(t *testing.T, edit func(a map[string]any)) (Tree, Tree, string) {
		base, head := crdAttestedTrees(t, func(base90_1 map[string]any, derived []map[string]any) []map[string]any {
			a := reviewedCRD(attestationOfLine(derived, "90.2"))
			if edit != nil {
				edit(a)
			}
			return []map[string]any{base90_1, a}
		})
		key.pinBoth(t, base, head, "airstand")
		id := crdAttestationID("90.2")
		writeFile(t, approvalPath(head, id), key.sign(t, crdRecordApproval(id, "90.2", ApprovalBaseAbsent, recordDigest(t, head, id))))
		return base, head, id
	}
	base, head, id := setup(t, nil)
	r := runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin})
	requireAdmittedButUnsplit(t, r)
	if c := change(t, r, id); c.Proof != ProofApproval || c.Basis != "reviewed" {
		t.Fatalf("change %+v", c)
	}
	// A release the extractor does not read upstream is refused, even
	// approved.
	base, head, _ = setup(t, func(a map[string]any) {
		rel := a["releases"].(map[string]any)
		rel["to"] = append(rel["to"].([]any), map[string]any{"version": "90.2.1", "commit": "0000000000000000000000000000000000902001"})
	})
	requireFail(t, runGate(t, Options{Base: base, Head: head, Source: argoFixture, Author: DefaultBotLogin}), "does not read upstream")
	// Without the upstream source there is no cross-check.
	base, head, _ = setup(t, nil)
	requireFail(t, runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin}), "no upstream source")
}

// The cross-check on its own: the extractor of the attestation's component
// is run; a set rule decides only through the identical set condition.
func TestCrossCheckCRDAttestation(t *testing.T) {
	out, floor, err := runAttester(context.Background(), argoFixture, extractcli.Catalog(), 0, lineattest.FamilyCustomResourceVersions, argoComponent, gateNow)
	if err != nil || floor != "" {
		t.Fatalf("run: %v floor %q", err, floor)
	}
	if out.Manifest.Extractor.ID != "crd.version-removal.argo-cd" {
		t.Fatalf("extractor %s", out.Manifest.Extractor.ID)
	}
	if _, _, err := runAttester(context.Background(), argoFixture, extractcli.Catalog(), 0, lineattest.FamilyCustomResourceVersions, "pkg:github/kedacore/keda", gateNow); err == nil {
		t.Fatal("a component outside the family found an extractor")
	}
	entries, atts := argoDerivation(t, gateNow.Add(-time.Hour))
	base, _ := trees(t)
	editPack(t, base, cncfRulesPath, func(p *packDoc) {
		p.entries = append(p.entries, entries...)
		p.sortByID()
		raw, _ := json.Marshal([]map[string]any{attestationOfLine(atts, "90.1")})
		p.fields["lineAttestations"] = raw
		p.fields["schema"] = json.RawMessage(`"` + attestedPackSchema + `"`)
	})
	pack, err := loadPack(base, DefaultLayout().Packs[0])
	if err != nil {
		t.Fatal(err)
	}
	parse := func(m map[string]any) lineattest.LineAttestation {
		raw, _ := json.Marshal([]map[string]any{m})
		got, err := lineattest.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return got[0]
	}
	if err := crossCheckAttestation(out, floor, parse(reviewedCRD(attestationOfLine(atts, "90.1"))), pack); err != nil {
		t.Fatalf("listed derived rules refused: %v", err)
	}
	quiet := parse(reviewedCRD(attestationOfLine(atts, "90.2")))
	if err := crossCheckAttestation(out, floor, quiet, pack); err != nil {
		t.Fatalf("quiet line refused: %v", err)
	}
	// Line 90.1 attested quiet: upstream removes two versions.
	hidden := reviewedCRD(attestationOfLine(atts, "90.1"))
	hidden["ruleIds"] = []any{}
	if err := crossCheckAttestation(out, floor, parse(hidden), pack); err == nil || !strings.Contains(err.Error(), "no rule the attestation lists decides it the same way") {
		t.Fatalf("hidden removal: %v", err)
	}
	// A rule over the same set with other members does not decide it.
	other := pack.Entries["argo-cd.crd-version-removal.widgets-fixture-argoproj-io.90-0-0-to-90-1-0"]
	var e map[string]any
	if err := json.Unmarshal(other.Raw, &e); err != nil {
		t.Fatal(err)
	}
	ruleOf(e)["setCondition"].(map[string]any)["members"] = []any{"fixture.argoproj.io/v9/Widget"}
	shape, _ := json.Marshal(ruleOf(e))
	listed, err := readRuleShape(shape)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := entryRule(other.Raw)
	want, _ := readRuleShape(original)
	if listed.decides(want) || !want.decides(want) {
		t.Fatal("set condition comparison")
	}
	// Releases outside the run are refused.
	extra := reviewedCRD(attestationOfLine(atts, "90.2"))
	extra["releases"].(map[string]any)["from"].([]any)[0].(map[string]any)["commit"] = "0000000000000000000000000000000000909999"
	if err := crossCheckAttestation(out, floor, parse(extra), pack); err == nil || !strings.Contains(err.Error(), "does not read upstream") {
		t.Fatalf("release not read: %v", err)
	}
}
