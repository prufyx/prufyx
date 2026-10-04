// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// opsKind is a test kind that declares the operations and byte edits its
// parameters say, for the first document. An item without explicit offsets
// gets the edit the locator computes, so a kind can be made to agree or to
// disagree with its declaration.
type opsKind struct{}

func init() { Register(opsKind{}) }

type opItem struct {
	Op          string          `json:"op"`
	Path        []any           `json:"path"`
	NewKey      string          `json:"newKey"`
	Scalar      json.RawMessage `json:"scalar"`
	Replacement string          `json:"replacement"`
	// Match, when set, limits the operation to a target whose value prints as it.
	Match string `json:"match"`
	// Explicit offsets override the computed edit.
	Explicit bool `json:"explicit"`
	Start    int  `json:"start"`
	End      int  `json:"end"`
}

func (opsKind) ID() string { return "test_ops" }

func (opsKind) Validate(params Params) (any, error) {
	var items []opItem
	if err := decodeParams(params, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func (opsKind) Plan(intake.Document, []byte, any) ([]Edit, error) { return nil, nil }

func (opsKind) PlanOperations(doc intake.Document, src []byte, parsed any) ([]Planned, error) {
	if doc.Source.Document != 0 {
		return nil, nil
	}
	locator, err := NewLocator(src)
	if err != nil {
		return nil, err
	}
	var out []Planned
	for _, item := range parsed.([]opItem) {
		path, err := setParams{Path: item.Path}.path()
		if err != nil {
			return nil, err
		}
		var op Operation
		var edit Edit
		file := doc.Source.Display
		// Like a real kind: nothing to do when the target is gone or already set.
		current, found := valueAt(doc.Value, path)
		if !found && item.Op != "rename" {
			continue
		}
		if item.Op == "set" {
			var want any
			dec := json.NewDecoder(strings.NewReader(string(item.Scalar)))
			dec.UseNumber()
			if dec.Decode(&want) == nil && sameScalar(current, want) {
				continue
			}
		}
		if item.Op == "rename" && !found {
			continue
		}
		if item.Match != "" && fmt.Sprint(current) != item.Match {
			continue
		}
		switch item.Op {
		case "rename":
			op = RenameKey{Path: path, NewKey: item.NewKey}
			if span, err := locator.Locate(0, path, PartKey); err == nil {
				edit = span.Edit(file, item.Replacement)
			}
		case "set":
			var scalar any
			dec := json.NewDecoder(strings.NewReader(string(item.Scalar)))
			dec.UseNumber()
			if err := dec.Decode(&scalar); err != nil {
				return nil, err
			}
			op = SetValue{Path: path, Scalar: scalar}
			if span, err := locator.Locate(0, path, PartValue); err == nil {
				edit = span.Edit(file, item.Replacement)
			}
		case "remove_key":
			op = RemoveKey{Path: path}
			if edit, err = locator.RemoveKeyEdit(file, 0, path); err != nil && !item.Explicit {
				return nil, err
			}
		case "remove_element":
			op = RemoveElement{Path: path}
			if edit, err = locator.RemoveElementEdit(file, 0, path); err != nil && !item.Explicit {
				return nil, err
			}
		}
		if item.Explicit {
			edit = Edit{File: file, StartByte: item.Start, EndByte: item.End, Replacement: item.Replacement}
		}
		out = append(out, Planned{Op: op, Edit: edit})
	}
	return out, nil
}

func opsRequest(items ...opItem) Request {
	params, err := json.Marshal(items)
	if err != nil {
		panic(err)
	}
	return Request{Kind: "test_ops", Params: params}
}

// at returns explicit offsets covering the first occurrence of needle.
func at(t *testing.T, src, needle string) (int, int) {
	t.Helper()
	start := strings.Index(src, needle)
	if start < 0 {
		t.Fatalf("%q not in %q", needle, src)
	}
	return start, start + len(needle)
}

func explicit(t *testing.T, item opItem, src, needle, replacement string) opItem {
	t.Helper()
	item.Explicit = true
	item.Start, item.End = at(t, src, needle)
	item.Replacement = replacement
	return item
}

func planOps(src string, items ...opItem) (FilePlan, string, error) {
	plan, err := Plan(display, []byte(src), []Request{opsRequest(items...)}, Options{})
	if err != nil {
		return plan, "", err
	}
	after, err := ApplyInMemory([]byte(src), plan, Options{})
	return plan, string(after), err
}

func wantReason(t *testing.T, err error, want Reason) {
	t.Helper()
	if ReasonOf(err) != want {
		t.Fatalf("got %v, want %s", err, want)
	}
}

const opsSource = "top:\n  a: 1\n  b: 2\n  c: three\nlist:\n- x\n- y\n- z\n"

// The framework computes the expected decoded result from the declared
// operation. A kind whose byte edit disagrees with its declaration is
// refused, for every operation.
func TestOperationProofIsIndependentOfTheKind(t *testing.T) {
	src := opsSource
	t.Run("agreeing edits are accepted", func(t *testing.T) {
		for name, item := range map[string]opItem{
			"rename":         {Op: "rename", Path: []any{"top", "b"}, NewKey: "bee", Replacement: "bee"},
			"set":            {Op: "set", Path: []any{"top", "b"}, Scalar: json.RawMessage(`5`), Replacement: "5"},
			"set string":     {Op: "set", Path: []any{"top", "c"}, Scalar: json.RawMessage(`"x"`), Replacement: `"x"`},
			"remove key":     {Op: "remove_key", Path: []any{"top", "b"}},
			"remove element": {Op: "remove_element", Path: []any{"list", 1}, Match: "y"},
		} {
			if _, after, err := planOps(src, item); err != nil || after == src {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})

	t.Run("rename", func(t *testing.T) {
		declared := opItem{Op: "rename", Path: []any{"top", "b"}, NewKey: "bee", Replacement: "bee"}
		// The edit renames another key than the declared one.
		other := explicit(t, declared, src, "c", "bee")
		other.Start, other.End = at(t, src, "c:")
		other.End--
		_, _, err := planOps(src, other)
		wantReason(t, err, ReasonDecodeMismatch)
		// The edit writes another name than the declared one.
		wrong := declared
		wrong.Replacement = "bee2"
		_, _, err = planOps(src, wrong)
		wantReason(t, err, ReasonDecodeMismatch)
		// The edit writes the declared name as an escape-free quoted key but
		// the declared key differs only in case.
		cased := declared
		cased.NewKey = "Bee"
		_, _, err = planOps(src, cased)
		wantReason(t, err, ReasonDecodeMismatch)
		// A declared rename that the bytes do not carry out.
		unchanged := declared
		unchanged.Replacement = "b"
		_, _, err = planOps(src, unchanged)
		wantReason(t, err, ReasonDecodeMismatch)
	})

	t.Run("set value", func(t *testing.T) {
		declared := opItem{Op: "set", Path: []any{"top", "b"}, Scalar: json.RawMessage(`5`), Replacement: "5"}
		wrong := declared
		wrong.Replacement = "6"
		_, _, err := planOps(src, wrong)
		wantReason(t, err, ReasonDecodeMismatch)
		// A number declared, a string written.
		typed := declared
		typed.Replacement = `"5"`
		_, _, err = planOps(src, typed)
		wantReason(t, err, ReasonDecodeMismatch)
		// A boolean declared, text written.
		boolean := opItem{Op: "set", Path: []any{"top", "b"}, Scalar: json.RawMessage(`true`), Replacement: `"true"`}
		_, _, err = planOps(src, boolean)
		wantReason(t, err, ReasonDecodeMismatch)
		// Declared null, written text.
		null := opItem{Op: "set", Path: []any{"top", "b"}, Scalar: json.RawMessage(`null`), Replacement: `"null"`}
		_, _, err = planOps(src, null)
		wantReason(t, err, ReasonDecodeMismatch)
		// Declared at one path, written at another.
		elsewhere := explicit(t, declared, src, "three", "5")
		_, _, err = planOps(src, elsewhere)
		wantReason(t, err, ReasonDecodeMismatch)
		// Declared change, bytes rewritten to themselves.
		same := declared
		same.Replacement = "2"
		_, _, err = planOps(src, same)
		wantReason(t, err, ReasonDecodeMismatch)
		// Number text must match exactly: declared 5.0, written 5.
		text := declared
		text.Scalar = json.RawMessage(`5.0`)
		_, _, err = planOps(src, text)
		wantReason(t, err, ReasonDecodeMismatch)
		// A different quote style decodes to the same text and is accepted.
		_, after, err := planOps(src, opItem{Op: "set", Path: []any{"top", "c"}, Scalar: json.RawMessage(`"x"`), Replacement: `'x'`})
		if err != nil || !strings.Contains(after, "c: 'x'") {
			t.Fatalf("%v %q", err, after)
		}
	})

	t.Run("remove key", func(t *testing.T) {
		declared := opItem{Op: "remove_key", Path: []any{"top", "b"}}
		// The edit deletes the lines of another key.
		_, _, err := planOps(src, explicit(t, declared, src, "  c: three\n", ""))
		wantReason(t, err, ReasonDecodeMismatch)
		// The edit deletes the right key and one more.
		_, _, err = planOps(src, explicit(t, declared, src, "  b: 2\n  c: three\n", ""))
		wantReason(t, err, ReasonDecodeMismatch)
		// The edit deletes a comment only: the key is still there.
		commented := "top:\n  a: 1\n  # note\n  b: 2\n"
		_, _, err = planOps(commented, explicit(t, declared, commented, "  # note\n", ""))
		wantReason(t, err, ReasonDecodeMismatch)
		// The edit deletes the key's lines in another place of the file.
		doubled := "top:\n  a: 1\n  b: 2\nother:\n  b: 2\n  c: 1\n"
		item := explicit(t, declared, doubled, "  b: 2\n", "")
		item.Start += len("top:\n  a: 1\n  b: 2\nother:\n") - len("top:\n  a: 1\n")
		item.End = item.Start + len("  b: 2\n")
		_, _, err = planOps(doubled, item)
		wantReason(t, err, ReasonDecodeMismatch)
	})

	t.Run("remove element", func(t *testing.T) {
		declared := opItem{Op: "remove_element", Path: []any{"list", 1}, Match: "y"}
		_, _, err := planOps(src, explicit(t, declared, src, "- z\n", ""))
		wantReason(t, err, ReasonDecodeMismatch)
		_, _, err = planOps(src, explicit(t, declared, src, "- y\n- z\n", ""))
		wantReason(t, err, ReasonDecodeMismatch)
		// Declared element 1 but the edit removes a key.
		_, _, err = planOps(src, explicit(t, declared, src, "  c: three\n", ""))
		wantReason(t, err, ReasonDecodeMismatch)
	})

	t.Run("the kind cannot supply the expectation through plain edits", func(t *testing.T) {
		// A plain token edit cannot delete anything.
		start, end := at(t, src, "  b: 2\n")
		_, _, err := planOps(src) // no operations at all is fine
		if err != nil {
			t.Fatal(err)
		}
		_, err = Plan(display, []byte(src), []Request{rawRequest(rawEdit{Start: start, End: end, Replacement: ""})}, Options{})
		wantReason(t, err, ReasonInvalidEdit)
	})
}

// Even when the decoded result is right, a removal must be exactly the
// entry's lines: a comment that belongs elsewhere must stay.
func TestRemovalMustCoverExactlyTheEntryLines(t *testing.T) {
	src := "top:\n  a: 1\n  b: 2\n  # about c\n  c: 3\n"
	declared := opItem{Op: "remove_key", Path: []any{"top", "b"}}
	_, after, err := planOps(src, declared)
	if err != nil || after != "top:\n  a: 1\n  # about c\n  c: 3\n" {
		t.Fatalf("%v %q", err, after)
	}
	// The comment of the next key goes with it: the data is right, the span is not.
	_, _, err = planOps(src, explicit(t, declared, src, "  b: 2\n  # about c\n", ""))
	wantReason(t, err, ReasonInvalidEdit)
	// The comment above the entry goes with it.
	withHead := "top:\n  a: 1\n  # about b\n  b: 2\n  c: 3\n"
	_, _, err = planOps(withHead, explicit(t, declared, withHead, "  # about b\n  b: 2\n", ""))
	wantReason(t, err, ReasonInvalidEdit)
	// Fewer lines than the entry owns (a trailing deeper comment stays behind).
	owned := "top:\n  b:\n    x: 1\n    # tail\n  c: 3\n"
	_, _, err = planOps(owned, explicit(t, declared, owned, "  b:\n    x: 1\n", ""))
	wantReason(t, err, ReasonInvalidEdit)
	_, after, err = planOps(owned, declared)
	if err != nil || after != "top:\n  c: 3\n" {
		t.Fatalf("%v %q", err, after)
	}
}

func TestRemovalEditShape(t *testing.T) {
	src := opsSource
	declared := opItem{Op: "remove_key", Path: []any{"top", "b"}}
	t.Run("not whole lines", func(t *testing.T) {
		for _, needle := range []string{"b: 2\n", "  b: 2", "  b: "} {
			_, _, err := planOps(src, explicit(t, declared, src, needle, ""))
			wantReason(t, err, ReasonInvalidEdit)
		}
	})
	t.Run("with a replacement", func(t *testing.T) {
		_, _, err := planOps(src, explicit(t, declared, src, "  b: 2\n", "  b: 2\n"))
		wantReason(t, err, ReasonInvalidEdit)
	})
	t.Run("start of a file with a byte order mark", func(t *testing.T) {
		bom := "\uFEFFa: 1\nb: 2\n"
		_, _, err := planOps(bom, opItem{Op: "remove_key", Path: []any{"a"}, Explicit: true, Start: 0, End: 3 + len("a: 1\n")})
		wantReason(t, err, ReasonInvalidEdit)
		// The first line of such a file is not removed (the diff cannot show it).
		_, _, err = planOps(bom, opItem{Op: "remove_key", Path: []any{"a"}})
		wantReason(t, err, ReasonSpanNotIsolated)
		_, after, err := planOps(bom, opItem{Op: "remove_key", Path: []any{"b"}})
		if err != nil || after != "\uFEFFa: 1\n" {
			t.Fatalf("%v %q", err, after)
		}
	})
	t.Run("declared path of the wrong kind", func(t *testing.T) {
		_, _, err := planOps(src, opItem{Op: "remove_key", Path: []any{"list", 0}, Explicit: true, Start: 0, End: 1})
		wantReason(t, err, ReasonInvalidEdit)
		_, _, err = planOps(src, opItem{Op: "remove_element", Path: []any{"top", "a"}, Explicit: true, Start: 0, End: 1})
		wantReason(t, err, ReasonInvalidEdit)
		_, _, err = planOps(src, opItem{Op: "rename", Path: []any{"list", 0}, NewKey: "k", Explicit: true, Start: 0, End: 1, Replacement: "k"})
		wantReason(t, err, ReasonInvalidEdit)
	})
	t.Run("declared values", func(t *testing.T) {
		for _, key := range []string{"", "<<", "a\nb", "{{x}}", "${x}", strings.Repeat("k", MaxReplacementBytes+1)} {
			_, _, err := planOps(src, opItem{Op: "rename", Path: []any{"top", "b"}, NewKey: key, Explicit: true, Start: 0, End: 1, Replacement: "k"})
			wantReason(t, err, ReasonInvalidEdit)
		}
		for _, scalar := range []string{`"a\nb"`, `"{{x}}"`, `"\u0001"`} {
			_, _, err := planOps(src, opItem{Op: "set", Path: []any{"top", "b"}, Scalar: json.RawMessage(scalar), Explicit: true, Start: 0, End: 1, Replacement: "k"})
			wantReason(t, err, ReasonInvalidEdit)
		}
		// Only a plain decimal number is a number.
		for _, scalar := range []string{`1e3`, `1E3`, `-2.5e-1`} {
			_, _, err := planOps(src, opItem{Op: "set", Path: []any{"top", "b"}, Scalar: json.RawMessage(scalar), Explicit: true, Start: 0, End: 1, Replacement: "k"})
			if err == nil {
				t.Fatalf("%s accepted", scalar)
			}
		}
		// A scalar that is not a scalar.
		_, _, err := planOps(src, opItem{Op: "set", Path: []any{"top", "b"}, Scalar: json.RawMessage(`[1]`), Explicit: true, Start: 0, End: 1, Replacement: "k"})
		wantReason(t, err, ReasonInvalidEdit)
	})
	t.Run("document that does not exist is not reachable by a kind", func(t *testing.T) {
		// Operations always belong to the document the kind was called for;
		// an edit in another document fails the proof.
		two := "a: 1\nb: 2\n---\na: 1\nb: 2\n"
		item := opItem{Op: "remove_key", Path: []any{"a"}, Explicit: true}
		item.Start = strings.Index(two, "---") + len("---\n")
		item.End = item.Start + len("a: 1\n")
		_, _, err := planOps(two, item)
		wantReason(t, err, ReasonDecodeMismatch)
	})
}

func TestOperationConflicts(t *testing.T) {
	src := "top:\n  a: 1\n  b:\n    x: 1\n    y: 2\n  c: 3\nlist:\n- p\n- q\n- r\n- s\n"
	t.Run("a removal and a change inside the removed entry", func(t *testing.T) {
		_, _, err := planOps(src,
			opItem{Op: "remove_key", Path: []any{"top", "b"}},
			opItem{Op: "set", Path: []any{"top", "b", "x"}, Scalar: json.RawMessage(`5`), Replacement: "5"})
		wantReason(t, err, ReasonConflictingEdits)
		_, _, err = planOps(src,
			opItem{Op: "remove_key", Path: []any{"top", "b"}},
			opItem{Op: "rename", Path: []any{"top", "b", "x"}, NewKey: "z", Replacement: "z"})
		wantReason(t, err, ReasonConflictingEdits)
		_, _, err = planOps(src,
			opItem{Op: "remove_key", Path: []any{"top", "b"}},
			opItem{Op: "rename", Path: []any{"top", "b"}, NewKey: "z", Replacement: "z"})
		wantReason(t, err, ReasonConflictingEdits)
		_, _, err = planOps(src,
			opItem{Op: "remove_key", Path: []any{"top", "b", "x"}},
			opItem{Op: "remove_key", Path: []any{"top", "b"}})
		wantReason(t, err, ReasonConflictingEdits)
	})
	t.Run("a removal and a plain token edit inside the removed entry", func(t *testing.T) {
		plan, err := Plan(display, []byte(src), []Request{
			opsRequest(opItem{Op: "remove_key", Path: []any{"top", "b"}}),
			setRequest("value", "1", "9", "top", "b", "x"),
		}, Options{})
		wantReason(t, err, ReasonConflictingEdits)
		_ = plan
	})
	t.Run("the same operation twice merges", func(t *testing.T) {
		plan, after, err := planOps(src,
			opItem{Op: "remove_key", Path: []any{"top", "b"}},
			opItem{Op: "remove_key", Path: []any{"top", "b"}})
		if err != nil || len(plan.Edits) != 1 || strings.Contains(after, "b:") {
			t.Fatalf("%v %+v %q", err, plan.Edits, after)
		}
	})
	t.Run("several elements of one list are addressed by their original indexes", func(t *testing.T) {
		_, after, err := planOps(src,
			opItem{Op: "remove_element", Path: []any{"list", 0}, Match: "p"},
			opItem{Op: "remove_element", Path: []any{"list", 2}, Match: "r"})
		if err != nil || !strings.HasSuffix(after, "list:\n- q\n- s\n") {
			t.Fatalf("%v %q", err, after)
		}
	})
	t.Run("a removal beside value changes and renames below other entries", func(t *testing.T) {
		_, after, err := planOps(src,
			opItem{Op: "remove_key", Path: []any{"top", "a"}},
			opItem{Op: "set", Path: []any{"top", "b", "y"}, Scalar: json.RawMessage(`"two"`), Replacement: `"two"`},
			opItem{Op: "rename", Path: []any{"top", "b"}, NewKey: "bee", Replacement: "bee"},
			opItem{Op: "remove_element", Path: []any{"list", 3}, Match: "s"})
		want := "top:\n  bee:\n    x: 1\n    y: \"two\"\n  c: 3\nlist:\n- p\n- q\n- r\n"
		if err != nil || after != want {
			t.Fatalf("%v\n%q\nwant\n%q", err, after, want)
		}
	})
	t.Run("a plain token edit and an operation in one file", func(t *testing.T) {
		plan, err := Plan(display, []byte(src), []Request{
			setRequest("value", "3", "4", "top", "c"),
			opsRequest(opItem{Op: "remove_key", Path: []any{"top", "a"}}),
			setRequest("key", "", "Q", "list", 0), // no key at that path: ignored by the kind
		}, Options{})
		if err != nil {
			// The third request addresses an index with a key rename, which the
			// test kind skips; the plan must still be valid.
			t.Fatal(err)
		}
		after, err := ApplyInMemory([]byte(src), plan, Options{})
		if err != nil || !strings.Contains(string(after), "c: 4") || strings.Contains(string(after), "a: 1") {
			t.Fatalf("%v %q", err, after)
		}
	})
	t.Run("operations jointly emptying a container", func(t *testing.T) {
		two := "args:\n- --flag\n- value\nother: 1\n"
		_, _, err := planOps(two,
			opItem{Op: "remove_element", Path: []any{"args", 0}, Match: "--flag"},
			opItem{Op: "remove_element", Path: []any{"args", 1}, Match: "value"})
		wantReason(t, err, ReasonInvalidEdit)
		_, _, err = planOps("a: 1\nb: 2\n",
			opItem{Op: "remove_key", Path: []any{"a"}},
			opItem{Op: "remove_key", Path: []any{"b"}})
		wantReason(t, err, ReasonInvalidEdit)
		// Removing a nested container's last entry empties its parent too.
		_, _, err = planOps("a:\n  b:\n    c: 1\nz: 1\n", opItem{Op: "remove_key", Path: []any{"a", "b", "c"}})
		wantReason(t, err, ReasonInvalidEdit)
	})
	t.Run("renaming onto a sibling", func(t *testing.T) {
		for _, name := range []string{"b", "C"} {
			item := opItem{Op: "rename", Path: []any{"top", "a"}, NewKey: name, Replacement: name}
			_, _, err := planOps("top:\n  a: 1\n  b: 2\n  c: 3\n", item)
			if name == "C" {
				// The strict decoder refuses keys that differ only in case.
				wantReason(t, err, ReasonDecodeMismatch)
				continue
			}
			wantReason(t, err, ReasonDecodeMismatch)
		}
		// A removed sibling's name is still taken for the proof (conservative).
		_, _, err := planOps("top:\n  a: 1\n  b: 2\n  c: 3\n",
			opItem{Op: "remove_key", Path: []any{"top", "b"}},
			opItem{Op: "rename", Path: []any{"top", "a"}, NewKey: "b", Replacement: "b"})
		wantReason(t, err, ReasonDecodeMismatch)
	})
}

// A plan carrying operations is re-derived at apply and cannot be forged.
func TestOperationPlansAreNotTrusted(t *testing.T) {
	src := []byte(opsSource)
	plan, err := Plan(display, src, []Request{opsRequest(opItem{Op: "remove_key", Path: []any{"top", "b"}})}, Options{})
	if err != nil || len(plan.Edits) != 1 {
		t.Fatalf("%v %+v", err, plan)
	}
	forged := plan
	forged.Edits = []Edit{{File: display, StartByte: plan.Edits[0].StartByte, EndByte: plan.Edits[0].EndByte + len("  c: three\n")}}
	if _, err := ApplyInMemory(src, forged, Options{}); err == nil {
		t.Fatal("a forged removal applied")
	}
	forged = plan
	forged.Diff = "--- a/x\n+++ b/x\n"
	if _, err := ApplyInMemory(src, forged, Options{}); err == nil {
		t.Fatal("a forged diff applied")
	}
	after, err := ApplyInMemory(src, plan, Options{})
	if err != nil || string(after) != strings.Replace(opsSource, "  b: 2\n", "", 1) {
		t.Fatalf("%v %q", err, after)
	}
}

func TestOperationsRefuseSecrets(t *testing.T) {
	src := "kind: Secret\nstringData:\n  a: 1\n  b: 2\n"
	_, err := Plan(display, []byte(src), []Request{opsRequest(opItem{Op: "remove_key", Path: []any{"stringData", "a"}})}, Options{})
	wantReason(t, err, ReasonSecretDocument)
	nested := "- kind: Secret\n  data: {a: 1}\n---\nx:\n  a: 1\n  b: 2\n"
	_, err = Plan(display, []byte(nested), []Request{opsRequest(opItem{Op: "remove_key", Path: []any{"x", "a"}})}, Options{})
	wantReason(t, err, ReasonSecretDocument)
}

// A kind that makes an edit non-idempotent is refused for operations too.
type opGrowKind struct{}

func init() { Register(opGrowKind{}) }

func (opGrowKind) ID() string                                        { return "test_op_grow" }
func (opGrowKind) Validate(Params) (any, error)                      { return nil, nil }
func (opGrowKind) Plan(intake.Document, []byte, any) ([]Edit, error) { return nil, nil }
func (opGrowKind) PlanOperations(doc intake.Document, src []byte, _ any) ([]Planned, error) {
	if doc.Source.Document != 0 {
		return nil, nil
	}
	if ks, ok := doc.Value["list"].([]any); ok && len(ks) > 1 {
		locator, err := NewLocator(src)
		if err != nil {
			return nil, err
		}
		// Removes the first element every time: not idempotent.
		edit, err := locator.RemoveElementEdit(doc.Source.Display, 0, Path{Key("list"), Index(0)})
		if err != nil {
			return nil, err
		}
		return []Planned{{Op: RemoveElement{Path: Path{Key("list"), Index(0)}}, Edit: edit}}, nil
	}
	return nil, nil
}

func TestRemovalMustBeIdempotent(t *testing.T) {
	src := "list:\n- a\n- b\n- c\nz: 1\n"
	_, err := Plan(display, []byte(src), []Request{{Kind: "test_op_grow"}}, Options{})
	wantReason(t, err, ReasonNotIdempotent)
	plan, err := Plan(display, []byte(src), []Request{{Kind: "test_op_grow"}}, Options{SkipIdempotenceCheck: true})
	if err != nil || len(plan.Edits) != 1 {
		t.Fatalf("%v %+v", err, plan)
	}
}

// A plan with removals goes through the on-disk apply like any other: the
// file is rewritten whole-line-exact, atomically, keeping its mode.
func TestApplyWritesRemovals(t *testing.T) {
	const source = "values:\n  keep: 1\n  drop:\n    deep: 2\n  # about last\n  last: 3\nargs:\n- --a\n- --b\n"
	root := t.TempDir()
	file := filepath.Join(root, "values.yaml")
	writeMode(t, file, source, 0o640)
	requests := []Request{
		{Kind: "remove_key", Params: Params(`{"path":["values","drop"]}`)},
		{Kind: "rename_key", Params: Params(`{"path":["values","last"],"newKey":"final"}`)},
		{Kind: "set_value", Params: Params(`{"path":["values","keep"],"value":"one"}`)},
	}
	plan, err := Plan("values.yaml", []byte(source), requests, Options{})
	if err != nil {
		t.Fatal(err)
	}
	results := Apply([]Target{{Path: file, Plan: plan}}, ApplyOptions{Roots: []string{root}})
	if results[0].Err != nil || !results[0].Written {
		t.Fatalf("%+v", results[0])
	}
	got, _ := os.ReadFile(file)
	want := "values:\n  keep: \"one\"\n  # about last\n  final: 3\nargs:\n- --a\n- --b\n"
	if string(got) != want {
		t.Fatalf("%q\nwant\n%q", got, want)
	}
	info, _ := os.Lstat(file)
	if info.Mode() != 0o640 {
		t.Fatalf("mode %v", info.Mode())
	}
	if results[0].Diff != plan.Diff || !strings.Contains(results[0].Diff, "-  drop:\n-    deep: 2\n") {
		t.Fatalf("diff %q", results[0].Diff)
	}
	// Applied again, nothing is left to do.
	again, err := Plan("values.yaml", got, requests, Options{})
	if err != nil || len(again.Edits) != 0 {
		t.Fatalf("%v %+v", err, again.Edits)
	}
}

// Declared operations that are malformed, or whose edits are not on the token
// they claim, are refused for their own reasons.
func TestOperationEditsMustBeTokens(t *testing.T) {
	src := opsSource
	key, _ := at(t, src, "b: 2")
	t.Run("empty declared paths", func(t *testing.T) {
		for _, item := range []opItem{
			{Op: "remove_key", Path: []any{}, Explicit: true, Start: 0, End: 5},
			{Op: "remove_element", Path: []any{}, Explicit: true, Start: 0, End: 5},
			{Op: "rename", Path: []any{}, NewKey: "k", Explicit: true, Start: 0, End: 3, Replacement: "k"},
			{Op: "set", Path: []any{}, Scalar: json.RawMessage(`1`), Explicit: true, Start: 0, End: 3, Replacement: "1"},
		} {
			_, _, err := planOps(src, item)
			wantReason(t, err, ReasonInvalidEdit)
		}
	})
	t.Run("edits that start inside a token or cover part of one", func(t *testing.T) {
		for _, item := range []opItem{
			{Op: "rename", Path: []any{"top", "b"}, NewKey: "bee", Explicit: true, Start: key + 1, End: key + 1 + 1, Replacement: "e"},
			{Op: "set", Path: []any{"top", "c"}, Scalar: json.RawMessage(`"x"`), Explicit: true, Start: strings.Index(src, "three") + 1, End: strings.Index(src, "three") + 3, Replacement: `"x"`},
			{Op: "set", Path: []any{"top", "c"}, Scalar: json.RawMessage(`"x"`), Explicit: true, Start: strings.Index(src, "three"), End: strings.Index(src, "three") + 2, Replacement: `"x"`},
			{Op: "set", Path: []any{"top", "c"}, Scalar: json.RawMessage(`"x"`), Explicit: true, Start: strings.Index(src, "  c:"), End: strings.Index(src, "three") + 5, Replacement: `"x"`},
		} {
			_, _, err := planOps(src, item)
			wantReason(t, err, ReasonSpanNotIsolated)
		}
	})
	t.Run("plain spellings that other YAML readers take for something else", func(t *testing.T) {
		for _, text := range []string{"on", "off", "yes", "No", "y", "~", "NULL", "True", "1_000", "0x10", "0b11", "012", "1e3", "2001-01-02", "1:30"} {
			_, _, err := planOps(src, opItem{Op: "set", Path: []any{"top", "c"}, Scalar: json.RawMessage(`"` + text + `"`), Replacement: text})
			wantReason(t, err, ReasonInvalidEdit)
			_, _, err = planOps(src, opItem{Op: "rename", Path: []any{"top", "c"}, NewKey: text, Replacement: text})
			wantReason(t, err, ReasonInvalidEdit)
			// Quoted, the same text is fine.
			if _, after, err := planOps(src, opItem{Op: "set", Path: []any{"top", "c"}, Scalar: json.RawMessage(`"` + text + `"`), Replacement: `"` + text + `"`}); err != nil || !strings.Contains(after, `c: "`+text+`"`) {
				t.Fatalf("%s: %v %q", text, err, after)
			}
		}
		// true, false and null are the same for both readings.
		for scalar, text := range map[string]string{"true": "true", "false": "false", "null": "null"} {
			if _, _, err := planOps(src, opItem{Op: "set", Path: []any{"top", "c"}, Scalar: json.RawMessage(scalar), Replacement: text}); err != nil {
				t.Fatalf("%s: %v", scalar, err)
			}
		}
	})
	t.Run("two operations with the same edit are not merged", func(t *testing.T) {
		_, _, err := planOps(src,
			opItem{Op: "remove_key", Path: []any{"top", "b"}},
			opItem{Op: "remove_key", Path: []any{"top", "c"}, Explicit: true, Start: strings.Index(src, "  b: 2\n"), End: strings.Index(src, "  b: 2\n") + len("  b: 2\n")})
		wantReason(t, err, ReasonConflictingEdits)
	})
	t.Run("a plain edit and an operation with the same edit are not merged", func(t *testing.T) {
		_, err := Plan(display, []byte(src), []Request{
			setRequest("key", "", "bee", "top", "b"),
			opsRequest(opItem{Op: "rename", Path: []any{"top", "b"}, NewKey: "bee", Replacement: "bee"}),
		}, Options{})
		wantReason(t, err, ReasonConflictingEdits)
	})
	t.Run("renames at two depths", func(t *testing.T) {
		_, after, err := planOps(src,
			opItem{Op: "rename", Path: []any{"top", "a"}, NewKey: "aa", Replacement: "aa"},
			opItem{Op: "rename", Path: []any{"top"}, NewKey: "TOP", Replacement: "TOP"})
		if err != nil || !strings.HasPrefix(after, "TOP:\n  aa: 1\n") {
			t.Fatalf("%v %q", err, after)
		}
	})
}

// opsMutateKind writes into the source bytes it is given from PlanOperations.
type opsMutateKind struct{}

func init() { Register(opsMutateKind{}) }

func (opsMutateKind) ID() string                                        { return "test_ops_mutate" }
func (opsMutateKind) Validate(Params) (any, error)                      { return nil, nil }
func (opsMutateKind) Plan(intake.Document, []byte, any) ([]Edit, error) { return nil, nil }
func (opsMutateKind) PlanOperations(_ intake.Document, src []byte, _ any) ([]Planned, error) {
	src[0] ^= 0x20
	return nil, nil
}

func TestPlanOperationsGetsACopyOfTheSource(t *testing.T) {
	src := []byte("a: 1\nb: 2\n")
	_, err := Plan(display, src, []Request{{Kind: "test_ops_mutate"}}, Options{})
	wantReason(t, err, ReasonKindRefused)
	if string(src) != "a: 1\nb: 2\n" {
		t.Fatal("the caller's bytes were changed")
	}
}
