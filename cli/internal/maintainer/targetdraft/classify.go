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
// The rule is default-deny. A path is only ever judged harmless when it is on
// the small explicit documentation allowlist below; a path is only data when it
// is a recipe or a real target; EVERY other path (all of .github/, scripts/,
// cli/ code and go.mod, Makefile, tools, root files, anything new) is a trust
// path. A new kind of file therefore fails closed instead of looking green.
//
// Classes, checked in this order:
//
//	ERROR             the list is unreadable, empty, malformed or over a bound
//	TRUST_PATH_CHANGE any path (old or new side of a rename included) is neither
//	                  data nor on the documentation allowlist, or cannot be
//	                  judged (refused path)
//	MIXED_CHANGE      only data and allowlisted paths, but both kinds (not a
//	                  data-only change; never green)
//	APPLICABLE        every path is under the recipe root or is a real target
//	NOT_APPLICABLE    every path is on the documentation allowlist
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

// isDocsPath is the whole non-trust allowlist; it matches case-sensitively and
// exactly (no folding, so a case variant is NOT allowlisted):
//   - README*.md at the repository root: prose, read by no tool;
//   - docs/**/*.md: maintainer documentation, markdown only;
//   - changelog.d/**/*.md: release-note fragments, markdown only.
//
// Deliberately not listed: cli/docs (it holds JSON that code reads), site and
// every other root file. A path with a CODEOWNERS segment is never allowlisted
// (GitHub reads docs/CODEOWNERS), and a path with any other extension is not.
func isDocsPath(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.EqualFold(seg, "CODEOWNERS") {
			return false
		}
	}
	if !strings.HasSuffix(p, ".md") {
		return false
	}
	if !strings.Contains(p, "/") {
		return strings.HasPrefix(p, "README")
	}
	return strings.HasPrefix(p, "docs/") || strings.HasPrefix(p, "changelog.d/")
}

// ClassifyResult is the outcome of ClassifyChanged.
type ClassifyResult struct {
	Class      string
	Paths      int // distinct paths judged
	Trust      int // trust-path paths, refused paths included
	Refused    int // paths refused as unjudgeable (counted in Trust)
	Data       int // recipe or real-target paths
	Other      int // allowlisted documentation paths
	Reason     string
	ErrorCode  string
	ErrorExtra string
}

type pathKind int

const (
	kindDocs pathKind = iota
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

func isRealTarget(p string) bool {
	rest, ok := strings.CutPrefix(p, CrdVersionsDir+"/")
	if !ok {
		return false
	}
	name, ok1 := strings.CutPrefix(rest, "target-")
	name, ok2 := strings.CutSuffix(name, ".json")
	return ok1 && ok2 && slugRE.MatchString(name) && p == realTargetPath(name)
}

// classifyPath judges one path, default-deny: anything that is not a recipe
// path, a real target or an allowlisted documentation path is a trust path.
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
	if isDocsPath(p) {
		return kindDocs
	}
	return kindTrust
}

// changedPathsFromRaw reads `git diff --raw -z --no-abbrev` output. Every path
// of a record counts: for a rename or copy (status R or C, which the workflow's
// --no-renames never produces but a caller may) both the old and the new path.
// Any status is accepted, but each path carries whether its record is a plain
// regular-file change (modes only 000000 or 100644, not both 000000): a
// documentation path that is a symlink, a gitlink, an executable or a type
// change is not documentation. A record that is not well formed is an error,
// never skipped.
type changedPath struct {
	path  string
	plain bool
}

func plainModes(oldMode, newMode string) bool {
	ok := func(m string) bool { return m == "000000" || m == "100644" }
	return ok(oldMode) && ok(newMode) && (oldMode != "000000" || newMode != "000000")
}

func changedPathsFromRaw(raw []byte) ([]changedPath, string) {
	if len(raw) == 0 {
		return nil, "the changed-path list is empty"
	}
	if len(raw) > maxChangedList {
		return nil, fmt.Sprintf("the changed-path list is over %d bytes", maxChangedList)
	}
	var paths []changedPath
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
		plain := plainModes(f[0][1:], f[1])
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
			paths = append(paths, changedPath{path: string(p), plain: plain})
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
	// One verdict per distinct path: if it appears twice, the stricter wins.
	kinds := map[string]pathKind{}
	for _, c := range paths {
		k := classifyPath(c.path)
		if k == kindDocs && !c.plain {
			k = kindTrust
		}
		if old, ok := kinds[c.path]; !ok || k > old {
			kinds[c.path] = k
		}
	}
	for _, k := range kinds {
		res.Paths++
		switch k {
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
		res.Class, res.Reason = ClassTrustPathChange, "a changed path is not data or allowlisted documentation (default deny), or cannot be judged"
	case res.Data > 0 && res.Other > 0:
		res.Class, res.Reason = ClassMixedChange, "recipe or target paths together with documentation paths"
	case res.Data > 0:
		res.Class, res.Reason = ClassApplicable, "every changed path is a recipe or real-target path"
	default:
		res.Class, res.Reason = ClassNotApplicable, "every changed path is allowlisted documentation"
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
	Other   int    `json:"docsPaths"`
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
	fmt.Fprintf(stdout, "paths %d, trust %d (refused %d), data %d, docs %d: %s\n", res.Paths, res.Trust, res.Refused, res.Data, res.Other, res.Reason)
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
