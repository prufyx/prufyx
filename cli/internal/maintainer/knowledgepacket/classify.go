// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"context"
	"regexp"
	"strings"
)

var exportRef = regexp.MustCompile(`^factory/export-[0-9a-f]+$`)

// Data trees. Unknown paths are never data.
var dataPrefixes = []string{
	"cli/knowledge/onboarding/",
	"cli/knowledge/approvals/",
	"cli/knowledge/reattestation/",
	"cli/internal/cncfcheck/data/",
	"cli/internal/projectcheck/data/",
	"changelog.d/",
}

// README.md is data only while its change stays inside the generated
// coverage block (see readmeOutside); any other edit is free text.
const readmePath = "README.md"

// Everything that produces the packet or the package, or defines what the
// online keys trust. Prefixes end in a slash so a sibling directory with a
// longer name is not matched by accident.
var trustPrefixes = []string{
	".github/workflows/",
	"cli/internal/knowledgepin/",
	"cli/internal/maintainer/",
	"cli/cmd/prufyx-maintainer/",
	"cli/internal/knowledge/",
	"cli/internal/knowledgereleaseplan/",
	"scripts/",
}

var dataAuthors = map[string]bool{"prufyx-bot": true, markerAuthor: true}

func isDataPath(p string) bool {
	if p == readmePath {
		return true // narrowed by the coverage-block check in classify
	}
	for _, pre := range dataPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

func isTrustPath(p string) bool {
	for _, pre := range trustPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// readmeOutside reports whether README.md changed between a and b anywhere
// except inside the coverage block. Anything it cannot read or parse counts
// as changed (fail closed).
func readmeOutside(ctx context.Context, r repo, a, b string, files []string) bool {
	touched := false
	for _, f := range files {
		if f == readmePath {
			touched = true
		}
	}
	if !touched {
		return false
	}
	before, err1 := r.show(ctx, a, readmePath)
	after, err2 := r.show(ctx, b, readmePath)
	if err1 != nil || err2 != nil {
		return true
	}
	x, ok1 := stripCoverage(before)
	y, ok2 := stripCoverage(after)
	return !ok1 || !ok2 || x != y
}

// stripCoverage removes the coverage block (markers included) and reports
// whether exactly one well-ordered block was present.
func stripCoverage(raw []byte) (string, bool) {
	s := string(raw)
	if strings.Count(s, readmeBegin) != 1 || strings.Count(s, readmeEnd) != 1 {
		return "", false
	}
	i, j := strings.Index(s, readmeBegin), strings.Index(s, readmeEnd)
	if j < i {
		return "", false
	}
	return s[:i] + s[j+len(readmeEnd):], true
}

// classify decides the class of one merged pull request. Anything not
// positively identified as data is NON-DATA; a trust-path file wins.
func classify(pr *PRInput, files []string, readmeOutside bool) (class, reason string) {
	for _, f := range files {
		if isTrustPath(f) {
			return ClassTrustPath, "touches " + f
		}
	}
	if pr == nil {
		return ClassNonData, "no pull request input"
	}
	if len(files) == 0 {
		return ClassNonData, "no changed files"
	}
	for _, f := range files {
		if !isDataPath(f) {
			return ClassNonData, "touches non-data path " + f
		}
	}
	if readmeOutside {
		for _, f := range files {
			if f == readmePath {
				return ClassNonData, "README.md changed outside the generated coverage block"
			}
		}
	}
	if !dataAuthors[pr.Author] {
		return ClassNonData, "author " + quote(pr.Author) + " is not an expected data author"
	}
	if pr.Author == "prufyx-bot" && exportRef.MatchString(pr.Ref) {
		return ClassData, "factory export by prufyx-bot, data paths only"
	}
	return ClassData, "data paths only, author " + pr.Author
}
