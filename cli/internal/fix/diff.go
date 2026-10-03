// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"sort"
	"strconv"
	"strings"
)

// diffContext is the number of unchanged lines shown around a change.
const diffContext = 3

// UnifiedDiff renders the change that edits make to src as a unified diff
// with three lines of context, fixed headers ("--- a/<display>",
// "+++ b/<display>") and no timestamps. Edits must be valid for src, sorted
// and non-overlapping, and must not add or remove line breaks, as edits from
// Plan are. It returns "" when nothing changes.
func UnifiedDiff(display string, src []byte, edits []Edit) (string, error) {
	if r := checkDisplay(display); r != nil {
		return "", r
	}
	for i, edit := range edits {
		if edit.StartByte < 0 || edit.StartByte >= edit.EndByte || edit.EndByte > len(src) ||
			i > 0 && edit.StartByte < edits[i-1].EndByte ||
			strings.ContainsAny(string(src[edit.StartByte:edit.EndByte])+edit.Replacement, "\n\r") {
			return "", refuse(ReasonInvalidEdit, "the edits are not sorted, single-line and within the file")
		}
	}
	lines := splitLines(string(src))
	changed := map[int]string{}
	for _, edit := range edits {
		line := lineOf(lines, edit.StartByte)
		if _, seen := changed[line]; !seen {
			changed[line] = lines[line].text
		}
	}
	// Apply edits per line, from the last edit backwards so offsets stay
	// valid.
	for i := len(edits) - 1; i >= 0; i-- {
		edit := edits[i]
		line := lineOf(lines, edit.StartByte)
		text := changed[line]
		start, end := edit.StartByte-lines[line].start, edit.EndByte-lines[line].start
		changed[line] = text[:start] + edit.Replacement + text[end:]
	}
	var numbers []int
	for line, text := range changed {
		if text != lines[line].text {
			numbers = append(numbers, line)
		}
	}
	if len(numbers) == 0 {
		return "", nil
	}
	sort.Ints(numbers)
	var out strings.Builder
	out.WriteString("--- a/" + display + "\n+++ b/" + display + "\n")
	for first := 0; first < len(numbers); {
		last := first
		for last+1 < len(numbers) && numbers[last+1]-numbers[last] <= 2*diffContext+1 {
			last++
		}
		from := max(numbers[first]-diffContext, 0)
		to := min(numbers[last]+diffContext, len(lines)-1)
		count := to - from + 1
		out.WriteString("@@ -" + hunkRange(from+1, count) + " +" + hunkRange(from+1, count) + " @@\n")
		for line := from; line <= to; {
			if _, isChanged := changed[line]; !isChanged || changed[line] == lines[line].text {
				writeLine(&out, ' ', lines[line])
				line++
				continue
			}
			run := line
			for run <= to && changed[run] != lines[run].text && hasKey(changed, run) {
				run++
			}
			for i := line; i < run; i++ {
				writeLine(&out, '-', lines[i])
			}
			for i := line; i < run; i++ {
				writeLine(&out, '+', diffLine{text: changed[i], newline: lines[i].newline})
			}
			line = run
		}
		first = last + 1
	}
	return out.String(), nil
}

type diffLine struct {
	start   int
	text    string // without the final LF
	newline bool
}

func splitLines(src string) []diffLine {
	var lines []diffLine
	for start := 0; start < len(src); {
		end := strings.IndexByte(src[start:], '\n')
		if end < 0 {
			lines = append(lines, diffLine{start: start, text: src[start:]})
			break
		}
		lines = append(lines, diffLine{start: start, text: src[start : start+end], newline: true})
		start += end + 1
	}
	return lines
}

func lineOf(lines []diffLine, offset int) int {
	return sort.Search(len(lines), func(i int) bool { return lines[i].start > offset }) - 1
}

func hasKey(m map[int]string, key int) bool {
	_, ok := m[key]
	return ok
}

func hunkRange(start, count int) string {
	if count == 1 {
		return strconv.Itoa(start)
	}
	return strconv.Itoa(start) + "," + strconv.Itoa(count)
}

func writeLine(out *strings.Builder, mark byte, line diffLine) {
	out.WriteByte(mark)
	out.WriteString(line.text)
	out.WriteByte('\n')
	if !line.newline {
		out.WriteString("\\ No newline at end of file\n")
	}
}
