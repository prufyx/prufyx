// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func renewApply(t *testing.T, pack, run string, renew bool) (*extractpack.Report, error) {
	t.Helper()
	return extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, RenewAttestations: renew, Admit: admitAll})
}

// attMember returns the pack's lineAttestations member.
func attMember(t *testing.T, pack string) []byte {
	t.Helper()
	raw, _ := os.ReadFile(pack)
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p.Members[lineattest.PackMember]
}

// editAtts rewrites every attestation of the pack through f.
func editAtts(t *testing.T, pack string, f func(m map[string]any)) []byte {
	t.Helper()
	raw, _ := os.ReadFile(pack)
	p, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	var atts []map[string]any
	if err := json.Unmarshal(p.Members[lineattest.PackMember], &atts); err != nil || len(atts) == 0 {
		t.Fatalf("no attestations: %v", err)
	}
	for _, m := range atts {
		f(m)
	}
	p.Members[lineattest.PackMember], _ = json.Marshal(atts)
	out, err := p.Render()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, out, 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

func evOf(m map[string]any) map[string]any { return m["evidence"].(map[string]any) }

// earlierBuild makes the attestation look derived by an earlier build of the
// extractor, three days before the run.
func earlierBuild(m map[string]any) {
	ev := evOf(m)
	ev["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("0", 64)
	ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"
}

// renewSetup applies the argo-cd run (rules and attestations), then lets edit
// age the pack's attestations, and returns the pack, the run and the
// attestation section the run brings.
func renewSetup(t *testing.T, edit func(m map[string]any)) (pack, run string, want, pre []byte) {
	t.Helper()
	run = runDir(t, cases[3], derivedAt)
	pack = prunedPack(t, "cncf", run)
	if _, err := apply(t, pack, run, false); err != nil {
		t.Fatal(err)
	}
	want = attMember(t, pack)
	pre = editAtts(t, pack, edit)
	return
}

func sameJSON(a, b []byte) bool {
	var ba, bb bytes.Buffer
	return json.Compact(&ba, a) == nil && json.Compact(&bb, b) == nil && bytes.Equal(ba.Bytes(), bb.Bytes())
}

func TestRenewReplacesInPlace(t *testing.T) {
	pack, run, want, pre := renewSetup(t, earlierBuild)
	rep, err := renewApply(t, pack, run, true)
	if err != nil {
		t.Fatal(err)
	}
	var n []json.RawMessage
	_ = json.Unmarshal(want, &n)
	if len(rep.AttRenewed) != len(n) || len(rep.AttAdded) != 0 || len(rep.AttUnchanged) != 0 || len(rep.Added) != 0 || !rep.Changed {
		t.Fatalf("report %+v", rep)
	}
	after, _ := os.ReadFile(pack)
	if bytes.Equal(after, pre) {
		t.Fatal("a renewal-only run did not write the pack")
	}
	if got := attMember(t, pack); !sameJSON(got, want) {
		t.Fatalf("section is not the run's, canonical order:\n%s\n%s", got, want)
	}
	// The rules were not touched: the entries are the ones before.
	var a, b map[string]json.RawMessage
	_ = json.Unmarshal(after, &a)
	_ = json.Unmarshal(pre, &b)
	if !sameJSON(a["entries"], b["entries"]) {
		t.Fatal("a renewal changed the rules")
	}
	// A second run finds the renewed records identical.
	again, err := renewApply(t, pack, run, true)
	if err != nil || again.Changed || len(again.AttRenewed) != 0 || len(again.AttUnchanged) != len(n) {
		t.Fatalf("second: %+v %v", again, err)
	}
}

func TestRenewIdenticalRerunIsUnchanged(t *testing.T) {
	run := runDir(t, cases[3], derivedAt)
	pack := prunedPack(t, "cncf", run)
	if _, err := apply(t, pack, run, false); err != nil {
		t.Fatal(err)
	}
	pre, _ := os.ReadFile(pack)
	rep, err := renewApply(t, pack, run, true)
	if err != nil || rep.Changed || len(rep.AttRenewed) != 0 || len(rep.AttUnchanged) == 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	assertUnchanged(t, pack, pre)
}

func TestRenewRefusals(t *testing.T) {
	for _, c := range []struct {
		name  string
		renew bool
		edit  func(m map[string]any)
	}{
		{"flag absent", false, earlierBuild},
		{"same build, different content", true, func(m map[string]any) { evOf(m)["validUntil"] = "2027-01-01T00:00:00Z" }},
		{"other extractor id", true, func(m map[string]any) {
			earlierBuild(m)
			evOf(m)["extractor"].(map[string]any)["id"] = "crd.version-removal.other"
		}},
		{"reviewed existing", true, func(m map[string]any) {
			earlierBuild(m)
			ev := evOf(m)
			ev["basis"] = "reviewed"
			delete(ev, "extractor")
			delete(ev, "derivedAt")
		}},
		{"releases not an extension", true, func(m map[string]any) {
			earlierBuild(m)
			if rel, ok := m["releases"].(map[string]any); ok {
				rel["from"].([]any)[0].(map[string]any)["commit"] = strings.Repeat("a", 40)
			}
		}},
		{"ruleIds differ", true, func(m map[string]any) {
			earlierBuild(m)
			if ids, _ := m["ruleIds"].([]any); len(ids) > 0 {
				m["ruleIds"] = ids[1:]
			} else {
				m["ruleIds"] = []any{"x.rule"}
			}
		}},
		{"derivedAt equal", true, func(m map[string]any) {
			earlierBuild(m)
			ev := evOf(m)
			ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-04T00:00:00Z", "2026-10-04T00:00:00Z", "2026-11-04T00:00:00Z"
		}},
		{"derivedAt later than the run's", true, func(m map[string]any) {
			earlierBuild(m)
			ev := evOf(m)
			ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z", "2026-12-01T00:00:00Z"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			pack, run, _, pre := renewSetup(t, c.edit)
			if _, err := renewApply(t, pack, run, c.renew); !errors.Is(err, extractpack.ErrCollision) {
				t.Fatalf("err = %v, want a collision", err)
			}
			assertUnchanged(t, pack, pre)
		})
	}
}

// A renewal never combines with the other modes.
func TestRenewFlagCombinationsRefused(t *testing.T) {
	pack, run, _, pre := renewSetup(t, earlierBuild)
	for _, o := range []extractpack.Options{
		{Withdraw: true}, {RulesOnly: true}, {QuietOnly: true},
	} {
		o.PackPath, o.RunDir, o.RenewAttestations, o.Admit = pack, run, true, admitAll
		if _, err := extractpack.Apply(o); err == nil || !strings.Contains(err.Error(), "--renew-attestations") {
			t.Fatalf("%+v: %v", o, err)
		}
		assertUnchanged(t, pack, pre)
	}
}

// A merge step that renews more than a renewal may change is stopped by the
// final audit, whatever it reports.
func TestRenewFinalAuditRefusesAMisbehavingStep(t *testing.T) {
	pack, run, _, pre := renewSetup(t, earlierBuild)
	restore := extractpack.SetSteps(func(base *extractpack.Pack, r *extractpack.Run, rep *extractpack.Report) (*extractpack.Pack, map[string]bool, error) {
		head, allowed, err := extractpack.RealMerge(base, r, rep)
		if err != nil || len(rep.AttRenewed) == 0 {
			t.Fatalf("real merge: %+v %v", rep, err)
		}
		// Move a release of the renewed record to another commit: the old
		// release is gone, so this is not an extension.
		var atts []map[string]any
		_ = json.Unmarshal(head.Members[lineattest.PackMember], &atts)
		for _, m := range atts {
			if rel, ok := m["releases"].(map[string]any); ok {
				rel["from"].([]any)[0].(map[string]any)["commit"] = strings.Repeat("b", 40)
			}
		}
		head.Members[lineattest.PackMember], _ = json.Marshal(atts)
		return head, allowed, nil
	}, nil)
	defer restore()
	_, err := renewApply(t, pack, run, true)
	if !errors.Is(err, extractpack.ErrForeignChange) {
		t.Fatalf("err = %v, want ErrForeignChange", err)
	}
	assertUnchanged(t, pack, pre)
}

// olderRelease makes an attestation with releases look derived three days
// before the run by the same build, from one release fewer in "to" (the run
// then sees one new upstream patch tag). Attestations without releases stay as
// they are. extra is applied to each one changed.
func olderRelease(extra func(m map[string]any)) func(m map[string]any) {
	return func(m map[string]any) {
		rel, ok := m["releases"].(map[string]any)
		if !ok {
			return
		}
		to := rel["to"].([]any)
		rel["to"] = to[:len(to)-1]
		ev := evOf(m)
		ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"
		if extra != nil {
			extra(m)
		}
	}
}

func TestRenewSameBuildReleaseExtension(t *testing.T) {
	// Accepted: the same build, the releases only grew, nothing else differs.
	pack, run, want, _ := renewSetup(t, olderRelease(nil))
	rep, err := renewApply(t, pack, run, true)
	if err != nil || len(rep.AttRenewed) == 0 || len(rep.AttAdded) != 0 || !rep.Changed {
		t.Fatalf("report %+v err %v", rep, err)
	}
	if got := attMember(t, pack); !sameJSON(got, want) {
		t.Fatalf("section is not the run's:\n%s\n%s", got, want)
	}

	for _, c := range []struct {
		name string
		edit func(m map[string]any)
	}{
		{"extension and ruleIds differ", olderRelease(func(m map[string]any) { m["ruleIds"] = []any{"x.rule"} })},
		{"extension and completeness differ", olderRelease(func(m map[string]any) { m["completeness"] = "OTHER" })},
		{"extension and other extractor id", olderRelease(func(m map[string]any) {
			evOf(m)["extractor"].(map[string]any)["id"] = "crd.version-removal.other"
		})},
		{"other build, a from release rewritten", olderRelease(func(m map[string]any) {
			evOf(m)["extractor"].(map[string]any)["version"] = "0.0.0-other"
			rel := m["releases"].(map[string]any)
			rel["from"].([]any)[0].(map[string]any)["commit"] = strings.Repeat("a", 40)
		})},
		{"shrink: the pack holds a release the run lacks", olderRelease(func(m map[string]any) {
			rel := m["releases"].(map[string]any)
			rel["to"] = append(rel["to"].([]any), map[string]any{"version": "99.0.0", "commit": strings.Repeat("c", 40)})
		})},
		{"same build, same releases, later stamp", func(m map[string]any) {
			if _, ok := m["releases"].(map[string]any); !ok {
				return
			}
			ev := evOf(m)
			ev["derivedAt"], ev["reviewedAt"], ev["validUntil"] = "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			pack, run, _, pre := renewSetup(t, c.edit)
			if _, err := renewApply(t, pack, run, true); !errors.Is(err, extractpack.ErrCollision) {
				t.Fatalf("err = %v, want a collision", err)
			}
			assertUnchanged(t, pack, pre)
		})
	}
}
