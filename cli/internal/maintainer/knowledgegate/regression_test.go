// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression tests for attacks on the gate found in review. Each builds a
// change an automation account could propose and requires the gate to stop
// it (fail, or refuse the input) and never report it eligible for
// automatic merging.

func cloneTree(t *testing.T, src Tree) Tree {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(src.Root)); err != nil {
		t.Fatal(err)
	}
	return Tree{Root: dst}
}

// tryGate runs the gate and reports whether it stopped the change: an
// error (refused input) or a failing result.
func tryGate(t *testing.T, opts Options) (*Report, bool) {
	t.Helper()
	if opts.Layout.Packs == nil {
		opts.Layout = DefaultLayout()
	}
	if opts.Now.IsZero() {
		opts.Now = gateNow
	}
	r, err := Verify(context.Background(), opts)
	if err != nil {
		t.Logf("gate refused the input: %v", err)
		return nil, true
	}
	if r.AutoMerge.Eligible && !r.Passed() {
		t.Fatal("eligible without passing")
	}
	return r, !r.Passed()
}

// writePackRaw writes a pack whose entry id is replaced by custom bytes.
func writePackRaw(t *testing.T, tr Tree, rel string, p *packDoc, id string, custom []byte) {
	t.Helper()
	var parts [][]byte
	for _, e := range p.entries {
		if ruleID(e) == id {
			parts = append(parts, custom)
			continue
		}
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, raw)
	}
	p.fields["entries"] = json.RawMessage("[" + string(bytes.Join(parts, []byte(","))) + "]")
	raw, err := json.Marshal(p.fields)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(rel)), append(raw, '\n'))
}

// An entry carrying both "rule" and "Rule": struct decoding (the engine)
// takes the last, a map keeps both. The first change adds it as an
// apparently withdrawn rule; the second only swaps the member order so the
// engine reads an active rule while the canonical bytes stay the same.
func TestRegressionCaseVariantRuleSwap(t *testing.T) {
	base, head := trees(t)
	p := readPack(t, head, cncfRulesPath)
	ids := p.activeReviewed()
	src := p.find(t, ids[0])
	newID := ids[0] + "-zz"
	active := deepCopy(ruleOf(src)).(map[string]any)
	active["id"] = newID
	ev := active["evidence"].(map[string]any)
	ev["reviewedAt"] = gateNow.Add(-2 * time.Hour).Format(time.RFC3339)
	ev["validUntil"] = gateNow.Add(60 * 24 * time.Hour).Format(time.RFC3339)
	withdrawn := deepCopy(active).(map[string]any)
	withdrawn["evidence"].(map[string]any)["state"] = "withdrawn"
	entry := deepCopy(src).(map[string]any)
	entry["rule"] = map[string]any{"id": newID}
	p.entries = append(p.entries, entry)
	p.sortByID()
	mk := func(firstKey string, first any, secondKey string, second any) []byte {
		rest, _ := json.Marshal(map[string]any{"description": entry["description"], "project": entry["project"], "requiredFacts": entry["requiredFacts"]})
		a, _ := json.Marshal(first)
		b, _ := json.Marshal(second)
		return []byte(strings.TrimSuffix(string(rest), "}") + `,"` + firstKey + `":` + string(a) + `,"` + secondKey + `":` + string(b) + "}")
	}
	writePackRaw(t, head, cncfRulesPath, p, newID, mk("rule", active, "Rule", withdrawn))
	if _, blocked := tryGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin}); !blocked {
		t.Fatal("an entry with case-variant members was admitted")
	}
	// The swap on top of such a pack (as if it had merged).
	base2, head2 := cloneTree(t, head), cloneTree(t, head)
	writePackRaw(t, head2, cncfRulesPath, p, newID, mk("Rule", withdrawn, "rule", active))
	if _, blocked := tryGate(t, Options{Base: base2, Head: head2, Author: DefaultBotLogin}); !blocked {
		t.Fatal("swapping case-variant members was not stopped")
	}
	// A repeated member deep inside an entry is refused as well.
	base3, head3 := trees(t)
	raw, err := os.ReadFile(filepath.Join(head3.Root, cncfRulesPath))
	if err != nil {
		t.Fatal(err)
	}
	dup := bytes.Replace(raw, []byte(`"state": "active"`), []byte(`"state": "withdrawn", "state": "active"`), 1)
	if bytes.Equal(dup, raw) {
		t.Fatal("no active state in the shipped pack")
	}
	writeFile(t, filepath.Join(head3.Root, cncfRulesPath), dup)
	if _, blocked := tryGate(t, Options{Base: base3, Head: head3, Author: DefaultBotLogin}); !blocked {
		t.Fatal("a repeated member was admitted")
	}
}
