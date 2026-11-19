// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecapture"
	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

// The guards of a recorded move. A cited span whose bytes only moved may be
// renewed without a hand re-review only when the bytes are provably the same
// code in the same place of the file: the new place is the single occurrence of
// the span, the lines around it are unchanged, it did not travel far, and it
// is not inside a comment or string block that the old place was not. Each
// guard fails closed: any doubt means no MovedTo, and the rule stays for a
// human.
const (
	// MovedMinNonBlankLines and MovedMinBytes are the smallest span a move is
	// recorded for: short generic lines are unique by luck.
	MovedMinNonBlankLines = 2
	MovedMinBytes         = 40
	// MovedMaxShift is the largest change of the first line number.
	MovedMaxShift = 200
	// MovedContextLines is how many non-blank lines before and after the
	// span must be byte-identical in the old and the new file.
	MovedContextLines = 3
)

// MovedTo is where the cited bytes of a SPAN_MOVED citation are at the
// compared commit. ContentDigest is the WHOLE-file digest of the file at
// Commit (like a source's contentDigest), recomputed from the fetched bytes.
type MovedTo struct {
	Commit        string `json:"commit"`
	Path          string `json:"path"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
	ContentDigest string `json:"contentDigest"`
}

// Reasons EvaluateMove refuses a move with.
const (
	MoveRefusedOldSpan         = "OLD_SPAN_INVALID"
	MoveRefusedTooShort        = "SPAN_TOO_SHORT"
	MoveRefusedNotFound        = "SPAN_NOT_FOUND"
	MoveRefusedNotUnique       = "SPAN_NOT_UNIQUE"
	MoveRefusedBytesNotUnique  = "SPAN_BYTES_NOT_UNIQUE"
	MoveRefusedNotMoved        = "SPAN_NOT_MOVED"
	MoveRefusedShift           = "SHIFT_TOO_LARGE"
	MoveRefusedContext         = "CONTEXT_CHANGED"
	MoveRefusedCommentOrString = "MOVED_INTO_COMMENT_OR_STRING"
	MoveRefusedDigestMismatch  = "DIGEST_MISMATCH"
	MoveRefusedPlace           = "PLACE_MISMATCH"
	MoveRefusedOrder           = "ORDER_CHANGED"
	MoveRefusedBaseline        = "BASELINE_NOT_LINE_HEAD"
)

const moveCommentMarkerBlockCount = 5

var commentMarkers = [][]byte{
	[]byte("//"), []byte("#"), []byte("/*"), []byte("*"), []byte("--"), []byte(";"),
	[]byte("<!--"), []byte("%"), []byte(`"""`), []byte("'''"),
}

func blankLine(line []byte) bool { return len(bytes.TrimSpace(line)) == 0 }

func commentLine(line []byte) bool {
	trimmed := bytes.TrimLeft(line, " \t")
	for _, marker := range commentMarkers {
		if bytes.HasPrefix(trimmed, marker) {
			return true
		}
	}
	return false
}

func nonBlankCount(lines [][]byte) int {
	n := 0
	for _, line := range lines {
		if !blankLine(line) {
			n++
		}
	}
	return n
}

func equalLines(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// countOverlapping counts occurrences of needle in haystack at every byte
// offset (step 1), so a periodic span is counted as often as it can start.
func countOverlapping(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	count := 0
	for offset := 0; offset+len(needle) <= len(haystack); {
		i := bytes.Index(haystack[offset:], needle)
		if i < 0 {
			break
		}
		count++
		offset += i + 1
	}
	return count
}

// contextAround returns the nearest MovedContextLines non-blank lines before
// the 1-indexed span [start,end] (nearest first) and after it.
func contextAround(lines [][]byte, start, end int) (before, after [][]byte) {
	for i := start - 2; i >= 0 && len(before) < MovedContextLines; i-- {
		if !blankLine(lines[i]) {
			before = append(before, lines[i])
		}
	}
	for i := end; i < len(lines) && len(after) < MovedContextLines; i++ {
		if !blankLine(lines[i]) {
			after = append(after, lines[i])
		}
	}
	return before, after
}

// blockState is what the lines before a span leave open: unbalanced block
// comments and an odd count of string or fence delimiters.
type blockState [moveCommentMarkerBlockCount]int

func blockStateBefore(lines [][]byte, upto int) blockState {
	text := bytes.Join(lines[:upto], []byte{'\n'})
	return blockState{
		bytes.Count(text, []byte("/*")) - bytes.Count(text, []byte("*/")),
		bytes.Count(text, []byte("<!--")) - bytes.Count(text, []byte("-->")),
		bytes.Count(text, []byte(`"""`)) % 2,
		bytes.Count(text, []byte("'''")) % 2,
		bytes.Count(text, []byte("`")) % 2,
	}
}

func commentFlags(lines [][]byte) []bool {
	out := make([]bool, len(lines))
	for i, line := range lines {
		out[i] = commentLine(line)
	}
	return out
}

// EvaluateMove decides whether the cited span [start,end] of oldData is, byte
// for byte, at one new place of newData that passes every guard. It returns
// the new first and last line and an empty reason, or a refusal reason. It is
// pure and deterministic: the repin that records a move and the verifier that
// recomputes it call it with the same bytes.
func EvaluateMove(oldData []byte, start, end int, newData []byte) (newStart, newEnd int, reason string) {
	oldLines := bytes.Split(oldData, []byte{'\n'})
	oldSpan, ok := spanBytesAt(oldLines, start, end)
	if !ok {
		return 0, 0, MoveRefusedOldSpan
	}
	if nonBlankCount(oldLines[start-1:end]) < MovedMinNonBlankLines || len(oldSpan) < MovedMinBytes {
		return 0, 0, MoveRefusedTooShort
	}
	newLines := bytes.Split(newData, []byte{'\n'})
	n := end - start + 1
	var matches []int
	for candidate := 1; candidate+n-1 <= len(newLines); candidate++ {
		if equalLines(newLines[candidate-1:candidate-1+n], oldLines[start-1:end]) {
			matches = append(matches, candidate)
		}
	}
	switch {
	case len(matches) == 0:
		return 0, 0, MoveRefusedNotFound
	case len(matches) != 1:
		return 0, 0, MoveRefusedNotUnique
	}
	if countOverlapping(newData, oldSpan) != 1 {
		return 0, 0, MoveRefusedBytesNotUnique
	}
	ns := matches[0]
	ne := ns + n - 1
	if ns == start {
		return 0, 0, MoveRefusedNotMoved
	}
	shift := ns - start
	if shift < 0 {
		shift = -shift
	}
	if shift > MovedMaxShift {
		return 0, 0, MoveRefusedShift
	}
	oldBefore, oldAfter := contextAround(oldLines, start, end)
	newBefore, newAfter := contextAround(newLines, ns, ne)
	if !equalLines(oldBefore, newBefore) || !equalLines(oldAfter, newAfter) {
		return 0, 0, MoveRefusedContext
	}
	// The span and its context must carry the same comment markers as before,
	// and the new place must not sit inside a block that the old one did not.
	oldRegion := append(append(append([][]byte{}, oldBefore...), oldLines[start-1:end]...), oldAfter...)
	newRegion := append(append(append([][]byte{}, newBefore...), newLines[ns-1:ne]...), newAfter...)
	oldFlags, newFlags := commentFlags(oldRegion), commentFlags(newRegion)
	for i := range oldFlags {
		if oldFlags[i] != newFlags[i] {
			return 0, 0, MoveRefusedCommentOrString
		}
	}
	if blockStateBefore(oldLines, start-1) != blockStateBefore(newLines, ns-1) {
		return 0, 0, MoveRefusedCommentOrString
	}
	return ns, ne, ""
}

// VerifyMovedTo recomputes a recorded move from the two files' bytes: the
// guards of EvaluateMove, the place and whole-file digest it names, and that
// it was recorded for newCommit and the citation's own path. It returns an
// empty string when everything recomputes.
func VerifyMovedTo(oldData []byte, oldStart, oldEnd int, newData []byte, newCommit, path string, moved MovedTo) string {
	ns, ne, reason := EvaluateMove(oldData, oldStart, oldEnd, newData)
	if reason != "" {
		return reason
	}
	if moved.Commit == "" || moved.Commit != newCommit || moved.Path != path || moved.StartLine != ns || moved.EndLine != ne {
		return MoveRefusedPlace
	}
	if moved.ContentDigest != sourcecorpus.SHA(newData) {
		return MoveRefusedDigestMismatch
	}
	return ""
}

// MovedLocation is where a citation of a rule ends up at the compared commit:
// its old range when its file or span did not move, the recorded new range
// when it moved, and ok false when that is not known.
func MovedLocation(result ClassResult) (start int, ok bool) {
	switch result.Class {
	case ClassNoNewRelease, ClassFileIdentical, ClassSpanIdentical:
		return result.OldStart, true
	case ClassSpanMoved:
		if result.MovedTo != nil {
			return result.MovedTo.StartLine, true
		}
	}
	return 0, false
}

// MoveOrderPreserved reports whether the order of the cited spans of one file
// is the same at the compared commit as it was: for every other citation of
// the same rule in the same file as moved, whose place is known. A citation
// whose new place is not known fails the check.
func MoveOrderPreserved(ruleCitations []ClassResult, moved ClassResult) bool {
	type place struct{ oldStart, newStart int }
	var group []place
	for _, other := range ruleCitations {
		if other.Owner != moved.Owner || other.Repo != moved.Repo || other.Path != moved.Path {
			continue
		}
		start, ok := MovedLocation(other)
		if !ok {
			return false
		}
		group = append(group, place{other.OldStart, start})
	}
	sort.Slice(group, func(i, j int) bool {
		if group[i].oldStart != group[j].oldStart {
			return group[i].oldStart < group[j].oldStart
		}
		return group[i].newStart < group[j].newStart
	})
	for i := 1; i < len(group); i++ {
		a, b := group[i-1], group[i]
		switch {
		case a.oldStart == b.oldStart && a.newStart != b.newStart:
			return false
		case a.oldStart < b.oldStart && a.newStart >= b.newStart:
			return false
		}
	}
	return true
}

// MoveBaselineOK reports whether a citation's baseline is one a move may be
// recorded on: the line head of the pinned tag's own release line, resolved
// from Releases or from git tags, fresh, with later releases on the line.
// The latest-release and owner-chosen baselines never are.
func MoveBaselineOK(result ClassResult) bool {
	if result.Baseline != BaselineReleaseLine && result.Baseline != BaselineTagLine {
		return false
	}
	return result.LineStatus == LineStatusLaterReleases && result.Resolution == "" && !result.Stale &&
		result.PinnedTag != "" && result.BaselineTag != "" && result.BaselineLine != "" && result.NewCommit != ""
}

// ParseCitationURL is parseCitationURL for the verifier: the owner, repository,
// commit and path of a citation URL of an accepted immutable shape.
func ParseCitationURL(rawURL string) (owner, repo, commit, path string, ok bool) {
	return parseCitationURL(rawURL)
}

// MovedURL is the citation URL for a moved citation: the old URL's shape with
// the new commit (and the path, which never changes). ok is false for a URL of
// neither accepted shape.
func MovedURL(oldURL, owner, repo, commit, path string) (string, bool) {
	switch {
	case blobURLPattern.MatchString(oldURL):
		return "https://github.com/" + owner + "/" + repo + "/blob/" + commit + "/" + path, true
	case rawURLPattern.MatchString(oldURL):
		return "https://raw.githubusercontent.com/" + owner + "/" + repo + "/" + commit + "/" + path, true
	}
	return "", false
}

// finalizeMoves applies the guards that need more than one citation or the
// baseline to every SPAN_MOVED result of a run: a move is kept only on a line
// head baseline and with the order of the rule's other cited spans of the same
// file kept. It also returns the bytes of the old and new file of every kept
// move by digest, for the verifier (--moved-blobs-dir).
func finalizeMoves(ctx context.Context, results []ClassResult, blobFetcher sourcecapture.Fetcher, oldDigests map[string]string) map[string][]byte {
	byRule := map[string][]ClassResult{}
	for _, result := range results {
		byRule[result.RulePack+"\x00"+result.RuleID] = append(byRule[result.RulePack+"\x00"+result.RuleID], result)
	}
	blobs := map[string][]byte{}
	for i := range results {
		result := &results[i]
		if result.MovedTo == nil {
			continue
		}
		if result.Class != ClassSpanMoved || !MoveBaselineOK(*result) || result.MovedTo.Commit != result.NewCommit ||
			!MoveOrderPreserved(byRule[result.RulePack+"\x00"+result.RuleID], *result) {
			result.MovedTo = nil
			continue
		}
		for _, side := range []struct{ commit, digest string }{{result.OldCommit, oldDigests[result.key()]}, {result.NewCommit, result.MovedTo.ContentDigest}} {
			fetch := blobFetcher.Fetch(ctx, "/"+result.Owner+"/"+result.Repo+"/"+side.commit+"/"+result.Path)
			if fetch.Kind != "HTTP_200" || sourcecorpus.SHA(fetch.Body) != side.digest {
				result.MovedTo = nil
				break
			}
			blobs[side.digest] = fetch.Body
		}
	}
	return blobs
}

func (c ClassResult) key() string { return c.RulePack + "\x00" + c.RuleID + "\x00" + c.SourceID }

// WriteMovedBlobs writes each blob into dir, which must not exist yet, as a
// file named by its hex digest. The names carry no authority: the verifier
// hashes every file it reads.
func WriteMovedBlobs(dir string, blobs map[string][]byte) error {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	for digest, data := range blobs {
		if sourcecorpus.SHA(data) != digest {
			return fmt.Errorf("blob %s does not hash to its name", digest)
		}
		name := strings.TrimPrefix(digest, "sha256:")
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
