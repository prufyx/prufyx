// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"bytes"
	"sort"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

var knownReasons = map[Reason]bool{
	ReasonUnsupportedYAML: true, ReasonUnsupportedEncoding: true, ReasonTemplated: true, ReasonSecretDocument: true,
	ReasonPathNotFound: true, ReasonBlockScalar: true, ReasonMultiLineScalar: true, ReasonSpanNotIsolated: true,
	ReasonInvalidEdit: true, ReasonConflictingEdits: true, ReasonDecodeMismatch: true, ReasonNotIdempotent: true,
	ReasonUnknownKind: true, ReasonInvalidParams: true, ReasonKindRefused: true, ReasonLimit: true,
	ReasonFileChanged: true, ReasonUnsafeFile: true, ReasonOutsideRoots: true, ReasonWriteFailed: true, ReasonDescriptorLimit: true,
}

func addSeeds(f *testing.F, extra ...any) {
	seeds := []string{deployment, "a: 1\r\nb: \"x\"\r\n", "\uFEFFa: [x, 'y', \"z\"]\n", "- a: {b: c}\n- d\n", "a: |\n  x\nb: y\n",
		"a: one\n  two\n", "{\"k\":\"v\",\"n\":[1,2]}", "k: 'it''s'\n---\nj: \"q\\\"\"\n"}
	for _, text := range fixtures {
		seeds = append(seeds, text)
	}
	for _, seed := range seeds {
		f.Add(append([]any{[]byte(seed)}, extra...)...)
	}
}

func FuzzLocate(f *testing.F) {
	addSeeds(f, []byte("a"))
	f.Fuzz(func(t *testing.T, src []byte, probe []byte) {
		file, r := parseFile(src)
		if r != nil {
			if !knownReasons[r.Reason] || len(r.Detail) > maxDetail {
				t.Fatalf("refusal outside the vocabulary: %v", r)
			}
			return
		}
		// A path built from the probe bytes must never panic.
		var random Path
		for i, b := range probe {
			if i >= MaxPathSegments+2 {
				break
			}
			if b%2 == 0 {
				random = append(random, Index(int(b)/2%4))
			} else {
				random = append(random, Key(string(probe[i:min(i+3, len(probe))])))
			}
		}
		for doc := -1; doc <= len(file.docs); doc++ {
			if span, err := Locate(src, doc, random, Part(len(probe)%2)); err == nil && (span.Start < 0 || span.End > len(src) || span.Start >= span.End) {
				t.Fatalf("span out of bounds: %+v", span)
			}
		}
		for start, token := range file.tokenIndex() {
			span, err := Locate(src, token.document, token.path, token.part)
			if err != nil {
				if !knownReasons[ReasonOf(err)] {
					t.Fatalf("unexpected error: %v", err)
				}
				continue
			}
			if span.Start != start || span.Start < 0 || span.End > len(src) || span.Start >= span.End {
				t.Fatalf("span %+v for token at %d", span, start)
			}
			assertSentinel(t, src, token.document, token.path, token.part, span)
		}
	})
}

func FuzzApply(f *testing.F) {
	addSeeds(f, 3, 7, "batch/v1")
	f.Fuzz(func(t *testing.T, src []byte, start, end int, replacement string) {
		checkApply(t, src, start, end, replacement)
		// Also aim at a real token, chosen by start, so that most inputs
		// reach the verification instead of a span refusal.
		if file, r := parseFile(src); r == nil {
			var starts []int
			for offset, token := range file.tokenIndex() {
				if _, r := file.tokenSpan(token.node, token.part); r == nil {
					starts = append(starts, offset)
				}
			}
			if len(starts) > 0 {
				sort.Ints(starts)
				token := file.tokenIndex()[starts[uint(start)%uint(len(starts))]]
				span, _ := file.tokenSpan(token.node, token.part)
				checkApply(t, src, span.Start, span.End, replacement)
			}
		}
	})
}

func checkApply(t *testing.T, src []byte, start, end int, replacement string) {
	plan, err := Plan(display, src, []Request{rawRequest(rawEdit{start, end, replacement})}, Options{SkipIdempotenceCheck: true})
	if err != nil {
		if !knownReasons[ReasonOf(err)] {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	for _, edit := range plan.Edits {
		if edit.StartByte < 0 || edit.EndByte > len(src) || edit.StartByte >= edit.EndByte {
			t.Fatalf("edit out of bounds: %+v", edit)
		}
	}
	after, err := ApplyInMemory(src, plan, Options{SkipIdempotenceCheck: true})
	if err != nil {
		t.Fatalf("a verified plan does not apply: %v", err)
	}
	if len(plan.Edits) == 0 {
		if !bytes.Equal(after, src) {
			t.Fatal("no edits but bytes changed")
		}
		return
	}
	// The parameters travel as JSON, which may rewrite invalid UTF-8, so
	// the planned edit is the reference.
	edit := plan.Edits[0]
	if len(plan.Edits) != 1 || !bytes.Equal(after[:edit.StartByte], src[:edit.StartByte]) ||
		!bytes.Equal(after[edit.StartByte+len(edit.Replacement):], src[edit.EndByte:]) ||
		string(after[edit.StartByte:edit.StartByte+len(edit.Replacement)]) != edit.Replacement {
		t.Fatal("bytes outside the span changed")
	}
	if _, err := intake.Decode("x", after); err != nil {
		t.Fatalf("result does not decode: %v", err)
	}
	before, _ := parseFile(src)
	edited, r := parseFile(after)
	if r != nil || len(edited.docs) != len(before.docs) {
		t.Fatalf("result does not re-decode to the same documents: %v", r)
	}
	if plan.Diff == "" {
		t.Fatal("no diff for a change")
	}
}
