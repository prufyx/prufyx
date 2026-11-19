// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// movedBase is a 30-line file whose cited span is lines 10-12.
func movedBase() []string {
	lines := make([]string, 0, 30)
	for i := 1; i <= 30; i++ {
		lines = append(lines, fmt.Sprintf("context line %02d keeps its text", i))
	}
	lines[9], lines[10], lines[11] = "    if opts.Mode == \"strict\" {", "        return errStrictMode", "    }"
	return lines
}

func join(lines []string) []byte { return []byte(strings.Join(lines, "\n")) }

func prepend(n int, lines []string) []string {
	out := make([]string, 0, n+len(lines))
	for i := 0; i < n; i++ {
		out = append(out, fmt.Sprintf("added line %d", i))
	}
	return append(out, lines...)
}

func wantRefused(t *testing.T, name string, oldData []byte, start, end int, newData []byte, reason string) {
	t.Helper()
	if _, _, got := EvaluateMove(oldData, start, end, newData); got != reason {
		t.Errorf("%s: refusal %q, want %q", name, got, reason)
	}
}

func TestEvaluateMoveUniqueMoveIsRecorded(t *testing.T) {
	oldData := join(movedBase())
	newData := join(prepend(5, movedBase()))
	start, end, reason := EvaluateMove(oldData, 10, 12, newData)
	if reason != "" || start != 15 || end != 17 {
		t.Fatalf("got %d-%d %q", start, end, reason)
	}
}

func TestEvaluateMoveRefusesTwoLineAlignedOccurrences(t *testing.T) {
	newLines := prepend(5, movedBase())
	newLines = append(newLines, movedBase()[9:12]...)
	wantRefused(t, "second copy", join(movedBase()), 10, 12, join(newLines), MoveRefusedNotUnique)
}

func TestEvaluateMoveRefusesPeriodicOverlappingSpan(t *testing.T) {
	// Two identical lines cited; the new file holds three of them in a row,
	// so overlapping windows match twice.
	line := "    retries = retries + 1 // a repeated statement"
	oldLines := append(movedBase()[:9], line, line, "tail marker 1", "tail marker 2", "tail marker 3")
	newLines := append(prepend(3, movedBase()[:9]), line, line, line, "tail marker 1", "tail marker 2", "tail marker 3")
	wantRefused(t, "periodic", join(oldLines), 10, 11, join(newLines), MoveRefusedNotUnique)
}

func TestEvaluateMoveRefusesSecondByteOccurrenceInsideALongerLine(t *testing.T) {
	// The span also occurs once inside a longer line, so it is not at a line
	// boundary there: line-aligned count is 1, the byte count is 2.
	newLines := prepend(5, movedBase())
	newLines = append(newLines, "x    if opts.Mode == \"strict\" {\n        return errStrictMode\n    }")
	wantRefused(t, "inside longer line", join(movedBase()), 10, 12, join(newLines), MoveRefusedBytesNotUnique)
}

func TestEvaluateMoveRefusesPartialOrShiftedBytes(t *testing.T) {
	changed := prepend(5, movedBase())
	changed[15] = "        return errStrictModeChanged"
	wantRefused(t, "one line changed", join(movedBase()), 10, 12, join(changed), MoveRefusedNotFound)
	trailing := prepend(5, movedBase())
	trailing[14] += " "
	wantRefused(t, "trailing space", join(movedBase()), 10, 12, join(trailing), MoveRefusedNotFound)
}

func TestEvaluateMoveKeepsCRByteExact(t *testing.T) {
	oldData := []byte(strings.ReplaceAll(string(join(movedBase())), "\n", "\r\n"))
	lfNew := join(prepend(5, movedBase()))
	wantRefused(t, "CRLF old, LF new", oldData, 10, 12, lfNew, MoveRefusedNotFound)
	crlfNew := []byte(strings.ReplaceAll(string(lfNew), "\n", "\r\n"))
	if start, _, reason := EvaluateMove(oldData, 10, 12, crlfNew); reason != "" || start != 15 {
		t.Fatalf("CRLF in both files must still be a recorded move: %d %q", start, reason)
	}
}

func TestEvaluateMoveRefusesShortSpans(t *testing.T) {
	base := movedBase()
	base[9], base[10] = "x := 1", "y := 2"
	newLines := prepend(5, base)
	wantRefused(t, "under 40 bytes", join(base), 10, 11, join(newLines), MoveRefusedTooShort)
	wantRefused(t, "one non-blank line", join(movedBase()), 10, 10, join(prepend(5, movedBase())), MoveRefusedTooShort)
	blank := movedBase()
	blank[10] = ""
	blank[11] = "   "
	wantRefused(t, "blank lines do not count", join(blank), 10, 12, join(prepend(5, blank)), MoveRefusedTooShort)
}

func TestEvaluateMoveRefusesChangedContext(t *testing.T) {
	changedBefore := prepend(5, movedBase())
	changedBefore[13] = "context line 09 was rewritten"
	wantRefused(t, "line before", join(movedBase()), 10, 12, join(changedBefore), MoveRefusedContext)
	changedAfter := prepend(5, movedBase())
	changedAfter[19] = "context line 15 was rewritten"
	wantRefused(t, "line after", join(movedBase()), 10, 12, join(changedAfter), MoveRefusedContext)
	// The file start: the span was among the first lines, and is now below
	// other lines, so its context is not the file start any more.
	head := movedBase()[9:]
	wantRefused(t, "file start", join(head), 1, 3, join(prepend(5, head)), MoveRefusedContext)
}

func TestEvaluateMoveRefusesShiftOverTheCap(t *testing.T) {
	wantRefused(t, "201 lines", join(movedBase()), 10, 12, join(prepend(MovedMaxShift+1, movedBase())), MoveRefusedShift)
	if _, _, reason := EvaluateMove(join(movedBase()), 10, 12, join(prepend(MovedMaxShift, movedBase()))); reason != "" {
		t.Fatalf("a shift of exactly the cap is allowed: %q", reason)
	}
}

func TestEvaluateMoveRefusesAMoveIntoABlockComment(t *testing.T) {
	// The span and its context are byte-identical, but a block comment opened
	// far above now encloses them.
	newLines := prepend(5, movedBase())
	newLines[2] = "/* disabled for now"
	wantRefused(t, "block comment", join(movedBase()), 10, 12, join(newLines), MoveRefusedCommentOrString)
	fenced := prepend(5, movedBase())
	fenced[2] = "```"
	wantRefused(t, "fence", join(movedBase()), 10, 12, join(fenced), MoveRefusedCommentOrString)
}

func TestEvaluateMoveRefusesAnUnmovedSpan(t *testing.T) {
	wantRefused(t, "same place", join(movedBase()), 10, 12, join(movedBase()), MoveRefusedNotMoved)
}

func TestVerifyMovedToRecomputesPlaceAndDigest(t *testing.T) {
	oldData, newData := join(movedBase()), join(prepend(5, movedBase()))
	good := MovedTo{Commit: commitB, Path: "a.go", StartLine: 15, EndLine: 17, ContentDigest: sourcecorpus.SHA(newData)}
	if got := VerifyMovedTo(oldData, 10, 12, newData, commitB, "a.go", good); got != "" {
		t.Fatalf("a true move must verify: %q", got)
	}
	for name, mutate := range map[string]func(m *MovedTo){
		"digest":  func(m *MovedTo) { m.ContentDigest = sourcecorpus.SHA([]byte("other")) },
		"start":   func(m *MovedTo) { m.StartLine, m.EndLine = 16, 18 },
		"commit":  func(m *MovedTo) { m.Commit = commitA },
		"path":    func(m *MovedTo) { m.Path = "b.go" },
		"nocommt": func(m *MovedTo) { m.Commit = "" },
	} {
		moved := good
		mutate(&moved)
		if got := VerifyMovedTo(oldData, 10, 12, newData, commitB, "a.go", moved); got == "" {
			t.Errorf("%s: a changed record must not verify", name)
		}
	}
}

func movedResult(id string, oldStart, oldEnd int, class string, to *MovedTo) ClassResult {
	return ClassResult{
		RulePack: "rules.json", RuleID: "r", SourceID: id, Owner: "o", Repo: "r", Path: "a.go",
		OldCommit: commitA, NewCommit: commitB, OldStart: oldStart, OldEnd: oldEnd, Class: class, MovedTo: to,
	}
}

func TestMoveOrderPreservedRefusesASwap(t *testing.T) {
	a := movedResult("a", 10, 12, ClassSpanMoved, &MovedTo{Commit: commitB, Path: "a.go", StartLine: 40, EndLine: 42})
	b := movedResult("b", 20, 22, ClassSpanMoved, &MovedTo{Commit: commitB, Path: "a.go", StartLine: 25, EndLine: 27})
	if MoveOrderPreserved([]ClassResult{a, b}, a) {
		t.Fatal("a moved past b, which was after it: the order changed")
	}
	b.MovedTo.StartLine = 60
	if !MoveOrderPreserved([]ClassResult{a, b}, a) {
		t.Fatal("both moved down together: the order is kept")
	}
	still := movedResult("c", 30, 32, ClassSpanIdentical, nil)
	if MoveOrderPreserved([]ClassResult{a, still}, a) {
		t.Fatal("a moved past an unmoved span that was after it")
	}
	unknown := movedResult("d", 5, 6, ClassContentChanged, nil)
	if MoveOrderPreserved([]ClassResult{a, unknown}, a) {
		t.Fatal("a same-file citation whose new place is unknown cannot keep the order")
	}
	other := movedResult("e", 50, 52, ClassContentChanged, nil)
	other.Path = "other.go"
	if !MoveOrderPreserved([]ClassResult{a, other}, a) {
		t.Fatal("another file is not part of the order")
	}
}

func TestMoveBaselineOnlyOnALineHead(t *testing.T) {
	good := movedResult("a", 10, 12, ClassSpanMoved, nil)
	good.Baseline, good.LineStatus, good.PinnedTag, good.BaselineTag, good.BaselineLine = BaselineReleaseLine, LineStatusLaterReleases, "v1.0.0", "v1.0.4", "1.0"
	if !MoveBaselineOK(good) {
		t.Fatal("a release-line head baseline must allow a move")
	}
	for name, mutate := range map[string]func(*ClassResult){
		"latest":        func(c *ClassResult) { c.Baseline = BaselineLatest },
		"owner choice":  func(c *ClassResult) { c.Baseline = BaselineOwnerChoice },
		"pinned latest": func(c *ClassResult) { c.LineStatus = LineStatusPinnedIsLatest },
		"stale":         func(c *ClassResult) { c.Stale = true },
		"fallback":      func(c *ClassResult) { c.Resolution = resolutionTagFallback },
		"no pinned tag": func(c *ClassResult) { c.PinnedTag = "" },
	} {
		c := good
		mutate(&c)
		if MoveBaselineOK(c) {
			t.Errorf("%s must not allow a move", name)
		}
	}
	tagLine := good
	tagLine.Baseline = BaselineTagLine
	if !MoveBaselineOK(tagLine) {
		t.Fatal("a tag-line head baseline allows a move")
	}
}

func TestMovedURLKeepsTheShapeAndRefusesOthers(t *testing.T) {
	blob := "https://github.com/o/r/blob/" + commitA + "/dir/a.go"
	if got, ok := MovedURL(blob, "o", "r", commitB, "dir/a.go"); !ok || got != "https://github.com/o/r/blob/"+commitB+"/dir/a.go" {
		t.Fatalf("blob shape: %q %v", got, ok)
	}
	raw := "https://raw.githubusercontent.com/o/r/" + commitA + "/dir/a.go"
	if got, ok := MovedURL(raw, "o", "r", commitB, "dir/a.go"); !ok || got != "https://raw.githubusercontent.com/o/r/"+commitB+"/dir/a.go" {
		t.Fatalf("raw shape: %q %v", got, ok)
	}
	if _, ok := MovedURL("https://example.com/x", "o", "r", commitB, "a.go"); ok {
		t.Fatal("another shape must be refused")
	}
}

func movedFetcher(oldData, newData []byte) fakeBlobFetcher {
	return fakeBlobFetcher{
		"/o/r/" + commitB + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: newData},
		"/o/r/" + commitA + "/a.go": {Kind: "HTTP_200", StatusCode: 200, Body: oldData},
	}
}

func TestClassifyRecordsMovedToOnlyForAGuardedUniqueMove(t *testing.T) {
	oldData, newData := join(movedBase()), join(prepend(5, movedBase()))
	citation := Citation{Owner: "o", Repo: "r", Path: "a.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(oldData), StartLine: 10, EndLine: 12}
	result := Classify(context.Background(), citation, commitB, movedFetcher(oldData, newData))
	if result.Class != ClassSpanMoved || result.MovedTo == nil {
		t.Fatalf("a guarded unique move must carry movedTo: %+v", result)
	}
	want := MovedTo{Commit: commitB, Path: "a.go", StartLine: 15, EndLine: 17, ContentDigest: sourcecorpus.SHA(newData)}
	if *result.MovedTo != want {
		t.Fatalf("movedTo %+v, want %+v", *result.MovedTo, want)
	}

	two := append(prepend(5, movedBase()), movedBase()[9:12]...)
	result = Classify(context.Background(), citation, commitB, movedFetcher(oldData, join(two)))
	if result.Class != ClassSpanMoved || result.MovedTo != nil {
		t.Fatalf("two occurrences: SPAN_MOVED stays, with no movedTo: %+v", result)
	}
	far := join(prepend(MovedMaxShift+1, movedBase()))
	result = Classify(context.Background(), citation, commitB, movedFetcher(oldData, far))
	if result.Class != ClassSpanMoved || result.MovedTo != nil {
		t.Fatalf("a long shift: SPAN_MOVED stays, with no movedTo: %+v", result)
	}
}

func TestClassifyContentChangedNeverCarriesMovedTo(t *testing.T) {
	oldData := join(movedBase())
	changed := movedBase()
	changed[10] = "        return errSomethingElse"
	citation := Citation{Owner: "o", Repo: "r", Path: "a.go", OldCommit: commitA, OldDigest: sourcecorpus.SHA(oldData), StartLine: 10, EndLine: 12}
	result := Classify(context.Background(), citation, commitB, movedFetcher(oldData, join(prepend(5, changed))))
	if result.Class != ClassContentChanged || result.MovedTo != nil {
		t.Fatalf("%+v", result)
	}
}

func finalizeFixture() (ClassResult, map[string]string, fakeBlobFetcher, []byte, []byte) {
	oldData, newData := join(movedBase()), join(prepend(5, movedBase()))
	result := movedResult("a", 10, 12, ClassSpanMoved, &MovedTo{Commit: commitB, Path: "a.go", StartLine: 15, EndLine: 17, ContentDigest: sourcecorpus.SHA(newData)})
	result.Owner, result.Repo = "o", "r"
	result.Baseline, result.LineStatus, result.PinnedTag, result.BaselineTag, result.BaselineLine = BaselineReleaseLine, LineStatusLaterReleases, "v1.0.0", "v1.0.4", "1.0"
	return result, map[string]string{result.key(): sourcecorpus.SHA(oldData)}, movedFetcher(oldData, newData), oldData, newData
}

func TestFinalizeMovesKeepsAGuardedMoveAndReturnsBothFiles(t *testing.T) {
	result, digests, fetcher, oldData, newData := finalizeFixture()
	results := []ClassResult{result}
	blobs := finalizeMoves(context.Background(), results, fetcher, digests)
	if results[0].MovedTo == nil {
		t.Fatal("a move on a line head with the order kept must stay")
	}
	if string(blobs[sourcecorpus.SHA(oldData)]) != string(oldData) || string(blobs[sourcecorpus.SHA(newData)]) != string(newData) {
		t.Fatal("both files of the move must be returned by digest")
	}
}

func TestFinalizeMovesDropsMovesThatFailABaselineOrOrderGuard(t *testing.T) {
	for name, mutate := range map[string]func(r *ClassResult){
		"latest baseline": func(r *ClassResult) { r.Baseline = BaselineLatest },
		"other commit":    func(r *ClassResult) { r.MovedTo.Commit = commitA },
		"stale":           func(r *ClassResult) { r.Stale = true },
	} {
		result, digests, fetcher, _, _ := finalizeFixture()
		mutate(&result)
		results := []ClassResult{result}
		finalizeMoves(context.Background(), results, fetcher, digests)
		if results[0].MovedTo != nil {
			t.Errorf("%s: the move must be dropped", name)
		}
	}
	// A swap with a second cited span of the same file.
	result, digests, fetcher, _, _ := finalizeFixture()
	other := movedResult("b", 20, 22, ClassSpanMoved, &MovedTo{Commit: commitB, Path: "a.go", StartLine: 12, EndLine: 14})
	results := []ClassResult{result, other}
	finalizeMoves(context.Background(), results, fetcher, digests)
	if results[0].MovedTo != nil {
		t.Error("a swapped order must drop the move")
	}
	// Bytes that do not hash to the digest the move names.
	result, digests, fetcher, _, _ = finalizeFixture()
	result.MovedTo.ContentDigest = sourcecorpus.SHA([]byte("not the file"))
	results = []ClassResult{result}
	finalizeMoves(context.Background(), results, fetcher, digests)
	if results[0].MovedTo != nil {
		t.Error("a new file that does not hash to the recorded digest must drop the move")
	}
}

func TestWriteMovedBlobsIsContentAddressedAndExclusive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "blobs")
	data := []byte("file bytes")
	if err := WriteMovedBlobs(dir, map[string][]byte{sourcecorpus.SHA(data): data}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, strings.TrimPrefix(sourcecorpus.SHA(data), "sha256:")))
	if err != nil || string(raw) != string(data) {
		t.Fatalf("blob not written by its hex digest: %v", err)
	}
	if err := WriteMovedBlobs(dir, nil); err == nil {
		t.Fatal("an existing directory must be refused")
	}
	if err := WriteMovedBlobs(filepath.Join(t.TempDir(), "x"), map[string][]byte{sourcecorpus.SHA([]byte("a")): []byte("b")}); err == nil {
		t.Fatal("a blob that does not hash to its name must be refused")
	}
}

var _ sourcecapture.Fetcher = fakeBlobFetcher{}
