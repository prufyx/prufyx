// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The classification of a pull request from its changed paths. It lives in the
// tool, which the workflow builds from the base commit, so that a change cannot
// alter the rule that judges it. It reads one file, never the network and never
// the change's content: only path names.
//
// Classes, checked in this order:
//
//	ERROR             the list is unreadable, empty, malformed or over a bound
//	TRUST_PATH_CHANGE any path (old or new side of a rename included) is in a
//	                  trust path, or is a path the classifier refuses to judge
//	MIXED_CHANGE      a recipe or real-target path together with a path that is
//	                  neither (not a data-only change; never green)
//	APPLICABLE        every path is under the recipe root or is a real target
//	NOT_APPLICABLE    no path is in a trust path, a recipe or a real target
//
// None of these is eligibility. Only the verify step's ELIGIBLE result is.
const (
	// ClassifySchema names the machine-readable classification line.
	ClassifySchema = "prufyx.io/verify-pr-classify/v1"

	ClassTrustPathChange = "TRUST_PATH_CHANGE"
	ClassMixedChange     = "MIXED_CHANGE"
	ClassApplicable      = "APPLICABLE"
	ClassNotApplicable   = "NOT_APPLICABLE"
	ClassError           = "ERROR"

	// maxClassifyPaths bounds the records of one list; more is an ERROR (never
	// a guess), and the check stays red.
	maxClassifyPaths = 20000
)

// trustPathDirs are directories (or, for the CODEOWNERS file, one file) whose
// change is a change of the checks themselves. Matching is on whole path
// segments and ignores case (see classifyPath).
var trustPathDirs = []string{
	".github/workflows",
	".github/CODEOWNERS",
	"cli/internal/maintainer/targetdraft",
	"cli/internal/maintainer/knowledgegate",
	"cli/internal/maintainer/verifyprworkflow",
	"cli/internal/extract",
	"cli/knowledge",
	"cli/cmd/prufyx-maintainer",
}

// ClassifyResult is the outcome of ClassifyChanged.
type ClassifyResult struct {
	Class      string
	Paths      int // distinct paths judged
	Trust      int // trust-path paths, refused paths included
	Refused    int // paths refused as unjudgeable (counted in Trust)
	Data       int // recipe or real-target paths
	Other      int // everything else
	Reason     string
	ErrorCode  string
	ErrorExtra string
}

type pathKind int

const (
	kindOther pathKind = iota
	kindData
	kindTrust
	kindRefused
)

// refusePath reports whether p cannot be judged as a clean repository-relative
// path: empty, not UTF-8, a control character (NUL, newline), a backslash, an
// absolute path, a "." or ".." segment, a doubled or trailing slash.
func refusePath(p string) bool {
	if p == "" || !utf8.ValidString(p) || p[0] == '/' {
		return true
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return true
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return true
		}
	}
	return path.Clean(p) != p
}

// underFold reports whether p is dir or lies below it, comparing the leading
// runes of p with the ASCII dir by simple Unicode case folding. Folding is
// deliberate: git is case sensitive, but a checkout on a case-insensitive file
// system (or a path that folds to a trust name, such as one with the Kelvin
// sign) must never look like an unrelated path, so it is judged as the trust
// path. The boundary is a whole segment.
func underFold(p, dir string) bool {
	n := utf8.RuneCountInString(dir)
	if utf8.RuneCountInString(p) < n {
		return false
	}
	end := 0
	for i := 0; i < n; i++ {
		_, w := utf8.DecodeRuneInString(p[end:])
		end += w
	}
	if !strings.EqualFold(p[:end], dir) {
		return false
	}
	return end == len(p) || p[end] == '/'
}

func isRealTarget(p string) bool {
	rest, ok := strings.CutPrefix(p, CrdVersionsDir+"/")
	if !ok {
		return false
	}
	name, ok1 := strings.CutPrefix(rest, "target-")
	name, ok2 := strings.CutSuffix(name, ".json")
	return ok1 && ok2 && slugRE.MatchString(name) && p == realTargetPath(name)
}

// classifyPath judges one path. Data paths are matched exactly (case
// sensitive); trust paths are matched with folding, and trust is only left
// when the exact data rule matches first.
func classifyPath(p string) pathKind {
	if refusePath(p) {
		return kindRefused
	}
	if strings.HasPrefix(p, RecipesRoot) && len(p) > len(RecipesRoot) {
		return kindData
	}
	if isRealTarget(p) {
		return kindData
	}
	for _, d := range trustPathDirs {
		if underFold(p, d) {
			return kindTrust
		}
	}
	return kindOther
}

// changedPathsFromRaw reads `git diff --raw -z --no-abbrev` output. Every path
// of a record counts: for a rename or copy (status R or C, which the workflow's
// --no-renames never produces but a caller may) both the old and the new path.
// Any status, mode change or type change is accepted: only the names matter
// here. A record that is not well formed is an error, never skipped.
func changedPathsFromRaw(raw []byte) ([]string, string) {
	if len(raw) == 0 {
		return nil, "the changed-path list is empty"
	}
	if len(raw) > maxChangedList {
		return nil, fmt.Sprintf("the changed-path list is over %d bytes", maxChangedList)
	}
	var paths []string
	rest := raw
	records := 0
	for len(rest) > 0 {
		meta, r, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return nil, "record without terminator"
		}
		f := strings.Fields(string(meta))
		if len(f) != 5 || !strings.HasPrefix(f[0], ":") || !isObjectID(f[2]) || !isObjectID(f[3]) || f[4] == "" {
			return nil, "unexpected record " + strconv.Quote(clip(string(meta)))
		}
		records++
		if records > maxClassifyPaths {
			return nil, fmt.Sprintf("more than %d records", maxClassifyPaths)
		}
		n := 1
		if s := f[4][0]; s == 'R' || s == 'C' {
			n = 2
		}
		for i := 0; i < n; i++ {
			p, r2, ok := bytes.Cut(r, []byte{0})
			if !ok {
				return nil, "path without terminator"
			}
			r = r2
			// Kept as bytes-to-string so refusePath sees invalid UTF-8.
			paths = append(paths, string(p))
		}
		rest = r
	}
	return paths, ""
}

func isObjectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ClassifyChanged classifies the raw changed-path list. It never returns
// NOT_APPLICABLE or APPLICABLE for a list it could not read in full.
func ClassifyChanged(raw []byte) ClassifyResult {
	paths, msg := changedPathsFromRaw(raw)
	if msg != "" {
		return ClassifyResult{Class: ClassError, ErrorCode: "changed-list", ErrorExtra: msg}
	}
	res := ClassifyResult{}
	seen := map[string]bool{}
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		res.Paths++
		switch classifyPath(p) {
		case kindRefused:
			res.Trust++
			res.Refused++
		case kindTrust:
			res.Trust++
		case kindData:
			res.Data++
		default:
			res.Other++
		}
	}
	switch {
	case res.Trust > 0:
		res.Class, res.Reason = ClassTrustPathChange, "a changed path is in a trust path or cannot be judged"
	case res.Data > 0 && res.Other > 0:
		res.Class, res.Reason = ClassMixedChange, "recipe or target paths together with other paths"
	case res.Data > 0:
		res.Class, res.Reason = ClassApplicable, "every changed path is a recipe or real-target path"
	default:
		res.Class, res.Reason = ClassNotApplicable, "no changed path is a trust, recipe or target path"
	}
	return res
}

const classifyUsage = "usage: prufyx-maintainer target-draft classify-pr --changed-paths FILE [--json]\n" +
	"FILE is the output of: git diff --raw -z --no-abbrev --no-renames BASE HEAD. Prints exactly one line `class: X` with X one of TRUST_PATH_CHANGE, MIXED_CHANGE, APPLICABLE, NOT_APPLICABLE (exit 0) or ERROR (exit 2: unreadable, empty, malformed or over a bound). No class is eligibility, and a bare success is never eligibility. It reads only the file and never uses the network."

type classifyDoc struct {
	Schema  string `json:"schema"`
	Class   string `json:"class"`
	Paths   int    `json:"paths"`
	Trust   int    `json:"trustPaths"`
	Refused int    `json:"refusedPaths"`
	Data    int    `json:"dataPaths"`
	Other   int    `json:"otherPaths"`
	Reason  string `json:"reason"`
}

func runClassifyPR(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("target-draft classify-pr", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	var changed string
	var jsonOut bool
	fl.StringVar(&changed, "changed-paths", "", "")
	fl.BoolVar(&jsonOut, "json", false, "")
	if err := fl.Parse(args); err != nil || fl.NArg() != 0 || changed == "" {
		fmt.Fprintln(stderr, classifyUsage)
		return 2
	}
	raw, err := os.ReadFile(changed)
	if err != nil {
		fmt.Fprintf(stdout, "class: %s\n", ClassError)
		fmt.Fprintf(stderr, "classify-pr: %v\n", err)
		return 2
	}
	res := ClassifyChanged(raw)
	fmt.Fprintf(stdout, "class: %s\n", res.Class)
	if res.Class == ClassError {
		fmt.Fprintf(stdout, "detail: %s\n", strconv.Quote(res.ErrorCode+": "+res.ErrorExtra))
		return 2
	}
	fmt.Fprintf(stdout, "paths %d, trust %d (refused %d), data %d, other %d: %s\n", res.Paths, res.Trust, res.Refused, res.Data, res.Other, res.Reason)
	if jsonOut {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		doc := classifyDoc{Schema: ClassifySchema, Class: res.Class, Paths: res.Paths, Trust: res.Trust,
			Refused: res.Refused, Data: res.Data, Other: res.Other, Reason: res.Reason}
		if err := enc.Encode(doc); err != nil {
			fmt.Fprintf(stderr, "classify-pr: result: %v\n", err)
			return 2
		}
		fmt.Fprintf(stdout, "classify-json: %s", buf.String())
	}
	return 0
}
