// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func TestClientPinChangeIsMadeAlone(t *testing.T) {
	t.Parallel()
	const old, moved = "v0.1.0-beta.0", "v0.1.0-beta.3"
	pinFile := func(tr Tree) string { return filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath)) }
	other := func(rel string) func(t *testing.T, base, head Tree) {
		return func(t *testing.T, base, head Tree) {
			writeClientPin(t, head, moved)
			writeFile(t, filepath.Join(head.Root, filepath.FromSlash(rel)), []byte("changed\n"))
		}
	}
	for name, tc := range map[string]struct {
		edit func(t *testing.T, base, head Tree)
		ok   bool
	}{
		"the pin alone":        {func(t *testing.T, _, head Tree) { writeClientPin(t, head, moved) }, true},
		"pin and a test":       {other("cli/internal/cncfcheck/pinproof_test.go"), false},
		"pin and the workflow": {other(".github/workflows/ci.yml"), false},
		"pin and data":         {other("cli/internal/cncfcheck/data/other.json"), false},
		"pin and a document":   {other("cli/docs/knowledge-publisher.md"), false},
		"pin and a deletion": {func(t *testing.T, base, head Tree) {
			writeClientPin(t, head, moved)
			writeFile(t, filepath.Join(base.Root, "cli", "gone.txt"), []byte("x\n"))
		}, false},
		"pin renamed": {func(t *testing.T, _, head Tree) {
			raw, err := os.ReadFile(pinFile(head))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, pinFile(head)+".old", raw)
			if err := os.Remove(pinFile(head)); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			base, head := trees(t)
			writeClientPin(t, base, old)
			writeClientPin(t, head, old)
			tc.edit(t, base, head)
			r := runGate(t, Options{Base: base, Head: head})
			c, ok := check(r, checkClientPinOnly)
			if !ok || c.OK != tc.ok {
				t.Fatalf("check %+v, present %v, want ok=%v", c, ok, tc.ok)
			}
			if tc.ok {
				requirePass(t, r)
			} else {
				requireFail(t, r, "may change nothing else")
			}
		})
	}
	t.Run("a change without the pin has no check", func(t *testing.T) {
		t.Parallel()
		base, head := trees(t)
		writeClientPin(t, base, old)
		writeClientPin(t, head, old)
		writeFile(t, filepath.Join(head.Root, "cli", "docs", "note.md"), []byte("x\n"))
		if c, ok := check(runGate(t, Options{Base: base, Head: head}), checkClientPinOnly); ok {
			t.Fatalf("check %+v", c)
		}
	})
}

// While the head holds a pinned rule, the pin may not fall below the release
// that reads the lease, whether or not the change touches the rule.
func TestPinnedLeaseHoldsTheClientPin(t *testing.T) {
	t.Parallel()
	const floor, name = cncfcheck.PinnedLeaseMinClientVersion, "pinned-client-pin/cncf"
	pinPath := func(tr Tree) string { return filepath.Join(tr.Root, filepath.FromSlash(OldestClientPinPath)) }
	set := func(version string) func(t *testing.T, tr Tree) {
		return func(t *testing.T, tr Tree) { writeClientPin(t, tr, version) }
	}
	raw := func(content string) func(t *testing.T, tr Tree) {
		return func(t *testing.T, tr Tree) { writeFile(t, pinPath(tr), []byte(content)) }
	}
	missing := func(t *testing.T, tr Tree) {
		if err := os.Remove(pinPath(tr)); err != nil {
			t.Fatal(err)
		}
	}
	for label, tc := range map[string]struct {
		head      func(t *testing.T, tr Tree)
		withdrawn bool
		want      string // empty: admitted
	}{
		"unchanged":           {set(floor), false, ""},
		"raised":              {set("v0.1.0"), false, ""},
		"lowered":             {set("v0.1.0-beta.1"), false, "the head still supports client v0.1.0-beta.1"},
		"lowered, withdrawn":  {set("v0.1.0-beta.0"), true, "the head still supports client v0.1.0-beta.0"},
		"removed":             {missing, false, "the head's oldest supported client pin"},
		"unparsable":          {raw("junk\n"), false, "the head's oldest supported client pin"},
		"no ref line":         {raw("version=" + floor + "\n"), false, "the head's oldest supported client pin"},
		"not a version":       {set("latest"), false, "the head's oldest supported client pin"},
		"refused by workflow": {set("v0.2.0+build"), false, "the head's oldest supported client pin"},
	} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			base, head := trees(t)
			ids := pinnableIDs(t, readPack(t, base, cncfRulesPath))
			for _, tr := range []Tree{base, head} {
				writeClientPin(t, tr, floor)
				pinInTree(t, tr, ids[:1], func(e map[string]any) {
					if tc.withdrawn {
						evidenceOf(e)["state"] = "withdrawn"
					}
				})
			}
			tc.head(t, head)
			r := runGate(t, Options{Base: base, Head: head})
			c, ok := check(r, name)
			if !ok || c.OK != (tc.want == "") || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("check %+v, present %v, want %q", c, ok, tc.want)
			}
			if tc.want != "" {
				requireFail(t, r, tc.want)
			}
		})
	}
	t.Run("a pack without a pinned rule has no check", func(t *testing.T) {
		t.Parallel()
		base, head := trees(t)
		writeClientPin(t, base, floor)
		writeClientPin(t, head, "v0.1.0-beta.0")
		if c, ok := check(runGate(t, Options{Base: base, Head: head}), name); ok {
			t.Fatalf("check %+v", c)
		}
	})
}
