// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
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

var dataFiles = map[string]bool{"README.md": true}

// Paths whose change runs with the online keys or defines what they trust.
var trustPrefixes = []string{".github/workflows/", "cli/internal/knowledgepin/"}

var dataAuthors = map[string]bool{"prufyx-bot": true, markerAuthor: true}

func isDataPath(p string) bool {
	if dataFiles[p] {
		return true
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

// classify decides the class of one merged pull request. Anything not
// positively identified as data is NON-DATA; a trust-path file wins.
func classify(pr *PRInput, files []string) (class, reason string) {
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
	if !dataAuthors[pr.Author] {
		return ClassNonData, "author " + quote(pr.Author) + " is not an expected data author"
	}
	if pr.Author == "prufyx-bot" && exportRef.MatchString(pr.Ref) {
		return ClassData, "factory export by prufyx-bot, data paths only"
	}
	return ClassData, "data paths only, author " + pr.Author
}
