// SPDX-License-Identifier: AGPL-3.0-only

package lineattest

import (
	"fmt"
	"strconv"
)

// calverComponents is the closed set of components whose release lines are
// calendar months, YY.M, instead of minor lines of one major. A component is
// added here by a reviewed change to the code, together with the target that
// names the release scheme for it (see crdversions.SchemeCalverEdge).
var calverComponents = map[string]bool{
	"pkg:github/clastix/kamaji": true,
}

// CalverComponent reports whether the component's lines are calendar months.
func CalverComponent(component string) bool { return calverComponents[component] }

// PreviousLine is the line a hop into line comes from. For an ordinary
// component it is M.(m-1) when m > 0. For a calendar component, line YY.M
// follows the previous calendar month, so YY.1 follows (YY-1).12; ok is false
// when line is not a calendar month or has no earlier year to roll back to.
// A month nobody released in is not a line, so the previous line of a
// project may not exist even when the previous month does.
func PreviousLine(component, line string) (string, bool) {
	if !ValidLine(line) {
		return "", false
	}
	major, minor := lineNumbers(line)
	if !CalverComponent(component) {
		if minor == 0 {
			return "", false
		}
		return fmt.Sprintf("%d.%d", major, minor-1), true
	}
	switch {
	case minor < 1 || minor > 12:
		return "", false
	case minor > 1:
		return strconv.FormatUint(major, 10) + "." + strconv.FormatUint(minor-1, 10), true
	case major == 0:
		return "", false
	}
	return strconv.FormatUint(major-1, 10) + ".12", true
}

// ValidCalverLine reports whether line is a calendar line YY.M: a valid line
// whose second number is a month.
func ValidCalverLine(line string) bool {
	if !ValidLine(line) {
		return false
	}
	_, month := lineNumbers(line)
	return month >= 1 && month <= 12
}

// SetCalverComponentsForTest replaces the calendar component set and returns
// a function that restores it. Tests of a calendar project that is not yet in
// the set use it; no production code calls it.
func SetCalverComponentsForTest(components ...string) (restore func()) {
	previous := calverComponents
	calverComponents = map[string]bool{}
	for _, c := range components {
		calverComponents[c] = true
	}
	return func() { calverComponents = previous }
}
