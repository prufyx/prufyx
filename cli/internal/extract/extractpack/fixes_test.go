// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

var stateRE = regexp.MustCompile(`"state"\s*:\s*"active"`)

// editEntry returns a copy of a raw entry with its description changed.
func editEntry(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["description"] = "edited by a faulty step"
	out, _ := json.Marshal(m)
	return out
}

// The final audit is what stands between a faulty merge or withdraw step and
// the file. These tests make each step misbehave and require the apply to be
// refused by the audit (ErrForeignChange) with the pack untouched; a change
// that stops Apply from calling the audit, in either mode, fails one of them.
func TestApplyAuditsAFaultyMergeStep(t *testing.T) {
	c := cases[0]
	run := runDir(t, c, derivedAt)
	for name, fault := range map[string]func(t *testing.T, head *extractpack.Pack){
		"edits a foreign rule": func(t *testing.T, head *extractpack.Pack) { head.Entries[0] = editEntry(t, head.Entries[0]) },
		"drops a foreign rule": func(t *testing.T, head *extractpack.Pack) { head.Entries = head.Entries[1:] },
		"changes a member": func(t *testing.T, head *extractpack.Pack) {
			head.Members["revision"] = json.RawMessage(`"tampered"`)
		},
	} {
		pack := prunedPack(t, "cncf", run)
		pre, _ := os.ReadFile(pack)
		restore := extractpack.SetSteps(func(b *extractpack.Pack, r *extractpack.Run, rep *extractpack.Report) (*extractpack.Pack, map[string]bool, error) {
			head, allowed, err := extractpack.RealMerge(b, r, rep)
			if err == nil {
				fault(t, head)
			}
			return head, allowed, err
		}, nil)
		_, err := apply(t, pack, run, false)
		restore()
		if !errors.Is(err, extractpack.ErrForeignChange) {
			t.Fatalf("%s: %v", name, err)
		}
		assertUnchanged(t, pack, pre)
	}
}

func TestApplyAuditsAFaultyWithdrawStep(t *testing.T) {
	c := cases[0]
	first := runDir(t, c, derivedAt.Add(-24*time.Hour))
	pack := prunedPack(t, "cncf", first)
	if _, err := apply(t, pack, first, false); err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(t, first)
	later := runDir(t, c, derivedAt)
	trimRun(t, later, map[string]bool{ids[0]: true}, false)
	pre, _ := os.ReadFile(pack)
	for name, fault := range map[string]func(t *testing.T, head *extractpack.Pack){
		"edits a rule it does not withdraw": func(t *testing.T, head *extractpack.Pack) { head.Entries[0] = editEntry(t, head.Entries[0]) },
		"withdraws another rule too": func(t *testing.T, head *extractpack.Pack) {
			for i, e := range head.Entries {
				if strings.Contains(string(e), ids[1]) {
					head.Entries[i] = json.RawMessage(stateRE.ReplaceAllString(string(e), `"state":"withdrawn"`))
				}
			}
		},
	} {
		restore := extractpack.SetSteps(nil, func(b *extractpack.Pack, r *extractpack.Run, rep *extractpack.Report) (*extractpack.Pack, map[string]bool, error) {
			head, allowed, err := extractpack.RealWithdraw(b, r, rep)
			if err == nil {
				fault(t, head)
			}
			return head, allowed, err
		})
		_, err := apply(t, pack, later, true)
		restore()
		if !errors.Is(err, extractpack.ErrForeignChange) {
			t.Fatalf("%s: %v", name, err)
		}
		assertUnchanged(t, pack, pre)
	}
}

// ---- withdraw is bounded by the rule's age, code and commits ----------------

func firstThenLater(t *testing.T, laterAt time.Time) (pack, later string, dropped string, pre []byte) {
	t.Helper()
	c := cases[0]
	first := runDir(t, c, derivedAt)
	pack = prunedPack(t, "cncf", first)
	if _, err := apply(t, pack, first, false); err != nil {
		t.Fatal(err)
	}
	dropped = ruleIDs(t, first)[0]
	later = runDir(t, c, laterAt)
	trimRun(t, later, map[string]bool{dropped: true}, false)
	pre, _ = os.ReadFile(pack)
	return
}

func editManifest(t *testing.T, dir string, edit func(m map[string]any)) {
	t.Helper()
	var m map[string]any
	readJSON(t, filepath.Join(dir, "manifest.json"), &m)
	edit(m)
	writeCanon(t, filepath.Join(dir, "manifest.json"), m)
}

func TestWithdrawRefusesARunOlderThanTheRule(t *testing.T) {
	// The reviewer's probe: a run derived 30 days before the rule.
	pack, later, _, pre := firstThenLater(t, derivedAt.Add(-30*24*time.Hour))
	if _, err := apply(t, pack, later, true); !errors.Is(err, extractpack.ErrStale) {
		t.Fatalf("%v", err)
	}
	assertUnchanged(t, pack, pre)
	// Control: the same run, one second newer than the rule, withdraws.
	pack, later, dropped, _ := firstThenLater(t, derivedAt)
	rep, err := apply(t, pack, later, true)
	if err != nil || len(rep.Withdrawn) != 1 || rep.Withdrawn[0] != dropped {
		t.Fatalf("control: %+v %v", rep, err)
	}
}

func TestWithdrawRefusesARunBuiltByOtherCode(t *testing.T) {
	pack, later, _, pre := firstThenLater(t, derivedAt.Add(time.Hour))
	editManifest(t, later, func(m map[string]any) {
		m["extractor"].(map[string]any)["codeDigest"] = "sha256:" + strings.Repeat("0", 64)
	})
	if _, err := apply(t, pack, later, true); !errors.Is(err, extractpack.ErrStale) || !strings.Contains(err.Error(), "other code") {
		t.Fatalf("%v", err)
	}
	assertUnchanged(t, pack, pre)
}

func TestWithdrawRefusesARunThatReadOtherCommits(t *testing.T) {
	for _, side := range []string{"fromCommit", "toCommit"} {
		pack, later, _, pre := firstThenLater(t, derivedAt.Add(time.Hour))
		editManifest(t, later, func(m map[string]any) {
			for _, p := range m["pairs"].([]any) {
				p.(map[string]any)[side] = strings.Repeat("ab", 20)
			}
		})
		if _, err := apply(t, pack, later, true); !errors.Is(err, extractpack.ErrStale) || !strings.Contains(err.Error(), "did not read") {
			t.Fatalf("%s: %v", side, err)
		}
		assertUnchanged(t, pack, pre)
	}
}

// A run for another repository covers none of this pack's rules, even when the
// versions coincide: nothing is withdrawn (and nothing is refused).
func TestWithdrawChecksTheSubjectComponent(t *testing.T) {
	pack, later, _, pre := firstThenLater(t, derivedAt.Add(time.Hour))
	editManifest(t, later, func(m map[string]any) { m["repo"] = "github.com/other/thing" })
	rep, err := apply(t, pack, later, true)
	if err != nil || rep.Changed || len(rep.Withdrawn) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	assertUnchanged(t, pack, pre)
}

// ---- damaged runs, by the message that names the check -----------------------

func TestApplyDamagedRunChecksByName(t *testing.T) {
	c := cases[0]
	for name, tc := range map[string]struct {
		edit func(t *testing.T, dir string)
		want string
	}{
		"a withheld pair lists rules": {func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				m["pairs"].([]any)[0].(map[string]any)["status"] = "withheld"
			})
		}, "withheld pair lists rules"},
		"a candidate of another extractor": {func(t *testing.T, dir string) {
			var entries []map[string]any
			readJSON(t, filepath.Join(dir, "candidates.json"), &entries)
			entries[0]["rule"].(map[string]any)["evidence"].(map[string]any)["extractor"].(map[string]any)["id"] = "some.other-extractor"
			raw := writeCanon(t, filepath.Join(dir, "candidates.json"), entries)
			editManifest(t, dir, func(m map[string]any) { m["outputs"].(map[string]any)["candidates.json"] = digestOf(raw) })
		}, "not an active mechanical rule of"},
		"the manifest lists a rule the candidates lack": {func(t *testing.T, dir string) {
			editManifest(t, dir, func(m map[string]any) {
				p := m["pairs"].([]any)[0].(map[string]any)
				p["rules"] = append(p["rules"].([]any), "kubernetes.not-in-candidates")
			})
		}, "the manifest lists"},
	} {
		run := runDir(t, c, derivedAt)
		tc.edit(t, run)
		pack := prunedPack(t, "cncf", run)
		pre, _ := os.ReadFile(pack)
		_, err := apply(t, pack, run, false)
		if !errors.Is(err, extractpack.ErrRun) || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", name, err)
		}
		assertUnchanged(t, pack, pre)
	}
}

// A rule that cites no source cannot be tied to the run's commits, so it is
// not withdrawn by a run.
func TestWithdrawRefusesARuleWithoutSources(t *testing.T) {
	pack, later, dropped, _ := firstThenLater(t, derivedAt.Add(time.Hour))
	pre := mustModifyPack(t, pack, func(entries []map[string]any) []map[string]any {
		for _, e := range entries {
			if e["rule"].(map[string]any)["id"] == dropped {
				e["rule"].(map[string]any)["evidence"].(map[string]any)["sources"] = []any{}
			}
		}
		return entries
	})
	if _, err := apply(t, pack, later, true); !errors.Is(err, extractpack.ErrStale) || !strings.Contains(err.Error(), "no source") {
		t.Fatalf("%v", err)
	}
	assertUnchanged(t, pack, pre)
}
