// SPDX-License-Identifier: AGPL-3.0-only

// Command goldensemantics compares two copies of a set of golden files (a
// snapshot taken before they were regenerated and the regenerated files) by
// what they say, not by their bytes: verdicts, statuses, assessments, levels,
// exit codes, hop states and the counts of findings, gaps and passes. It
// prints a before/after summary for every file and exits 3 when anything
// semantic differs, except in the files that -allow-semantic-change names
// (comma-separated paths or glob patterns; there is no accept-everything
// form). Rule ids, reason
// codes, citations, fix text, dates and digests are not compared: a change of
// the shipped rule pack is expected to move those. It is the guard of
// scripts/regenerate-pack-goldens.sh, which would otherwise absorb any change.
//
//	goldensemantics [-allow-semantic-change=PATH,PATH,...] BEFORE_DIR AFTER_DIR
//
// A path is relative to the two directories, slash-separated; it may be a
// glob (path.Match syntax) and it matches the whole path or any trailing part
// of it, so "knowledge-age-before.*" names the four files of that name.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const exitSemanticChange = 3

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("goldensemantics", flag.ContinueOnError)
	flags.SetOutput(stderr)
	allow := flags.String("allow-semantic-change", "", "accept a change of statuses, verdicts, exit codes or hop states in these files only (comma-separated paths or globs)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: goldensemantics [-allow-semantic-change=PATH,PATH,...] BEFORE_DIR AFTER_DIR")
		return 2
	}
	var allowed []string
	given := false
	flags.Visit(func(f *flag.Flag) { given = given || f.Name == "allow-semantic-change" })
	for _, pattern := range strings.Split(*allow, ",") {
		if pattern = strings.TrimSpace(pattern); pattern != "" {
			allowed = append(allowed, pattern)
		}
	}
	if given && len(allowed) == 0 {
		fmt.Fprintln(stderr, "-allow-semantic-change needs the names of the files it accepts")
		return 2
	}
	for _, pattern := range allowed {
		if _, err := path.Match(pattern, ""); err != nil {
			fmt.Fprintf(stderr, "-allow-semantic-change: bad pattern %q: %v\n", pattern, err)
			return 2
		}
	}
	before, err := readTree(flags.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	after, err := readTree(flags.Arg(1))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	result := report(stdout, before, after, allowed)
	for _, pattern := range result.unmatched {
		fmt.Fprintf(stdout, "  note: -allow-semantic-change names %q, which no semantically changed file matches\n", pattern)
	}
	switch {
	case result.refused > 0:
		fmt.Fprintf(stderr, "%d golden files changed semantically (statuses, verdicts, exit codes, hop states or counts) and are not named by --allow-semantic-change: refused. Read the lines above; if a change is intended, name that file in --allow-semantic-change=PATH,...\n", result.refused)
		return exitSemanticChange
	case result.accepted > 0:
		fmt.Fprintf(stdout, "%d golden files changed semantically: accepted by name (-allow-semantic-change)\n", result.accepted)
		return 0
	}
	fmt.Fprintf(stdout, "no semantic difference (%d of %d golden files differ in text only)\n", result.textChanged, len(union(before, after)))
	return 0
}

// readTree returns the files below dir by slash-separated relative path.
func readTree(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = raw
		return nil
	})
	return files, err
}

func union(a, b map[string][]byte) []string {
	seen := map[string]bool{}
	var names []string
	for _, m := range []map[string][]byte{a, b} {
		for name := range m {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// matching returns the patterns that name the file: a pattern matches the
// whole path or any trailing run of its segments.
func matching(patterns []string, name string) []string {
	var hit []string
	segments := strings.Split(name, "/")
	for _, pattern := range patterns {
		for start := range segments {
			if ok, _ := path.Match(pattern, strings.Join(segments[start:], "/")); ok {
				hit = append(hit, pattern)
				break
			}
		}
	}
	return hit
}

type result struct {
	refused, accepted, textChanged int
	unmatched                      []string
}

// report prints the comparison of the files whose bytes differ, and counts the
// files that differ in meaning and are not named in allowed (refused), those
// that are (accepted), and those that differ in text only. A file that exists
// on one side only differs in meaning.
func report(out io.Writer, before, after map[string][]byte, allowed []string) result {
	var res result
	used := map[string]bool{}
	semantic := func(name, label string) string {
		if hit := matching(allowed, name); len(hit) > 0 {
			res.accepted++
			for _, pattern := range hit {
				used[pattern] = true
			}
			return "ACCEPTED " + label
		}
		res.refused++
		return label
	}
	fmt.Fprintln(out, "golden semantics (statuses, verdicts, exit codes, hop states, counts), before -> after")
	for _, name := range union(before, after) {
		b, hadBefore := before[name]
		a, hasAfter := after[name]
		switch {
		case !hadBefore:
			fmt.Fprintf(out, "  %s %s: %s\n", semantic(name, "NEW     "), name, summarize(signature(name, a)))
		case !hasAfter:
			fmt.Fprintf(out, "  %s %s: %s\n", semantic(name, "REMOVED "), name, summarize(signature(name, b)))
		default:
			if bytes.Equal(a, b) {
				continue
			}
			sb, sa := signature(name, b), signature(name, a)
			if equal(sb, sa) {
				res.textChanged++
				fmt.Fprintf(out, "  same     %s: %s\n", name, summarize(sa))
				continue
			}
			fmt.Fprintf(out, "  %s %s\n           before: %s\n           after:  %s\n", semantic(name, "CHANGED "), name, summarize(sb), summarize(sa))
			for _, line := range diffLines(sb, sa) {
				fmt.Fprintf(out, "           %s\n", line)
			}
		}
	}
	for _, pattern := range allowed {
		if !used[pattern] {
			res.unmatched = append(res.unmatched, pattern)
		}
	}
	return res
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// summarize counts the signature lines: "verdict=BLOCKED status=BLOCKED x1 ...".
func summarize(sig []string) string {
	if len(sig) == 0 {
		return "(nothing semantic found)"
	}
	counts := map[string]int{}
	var order []string
	for _, line := range sig {
		if counts[line] == 0 {
			order = append(order, line)
		}
		counts[line]++
	}
	var parts []string
	for _, line := range order {
		if counts[line] > 1 {
			parts = append(parts, fmt.Sprintf("%s x%d", line, counts[line]))
		} else {
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, "; ")
}

// diffLines lists the signature entries that are not matched on the other side
// ("- " only before, "+ " only after), in order.
func diffLines(before, after []string) []string {
	remaining := map[string]int{}
	for _, line := range after {
		remaining[line]++
	}
	var out []string
	for _, line := range before {
		if remaining[line] > 0 {
			remaining[line]--
			continue
		}
		out = append(out, "- "+line)
	}
	left := map[string]int{}
	for _, line := range before {
		left[line]++
	}
	for _, line := range after {
		if left[line] > 0 {
			left[line]--
			continue
		}
		out = append(out, "+ "+line)
	}
	if len(out) == 0 {
		out = append(out, "(same entries in a different order)")
	}
	return out
}

// jsonKeys are the members whose string or number value is part of the
// meaning of a report; the elements of the arrays in jsonCounted are counted;
// jsonBools are the flags whose value is part of it; the strings in the arrays
// of jsonStringLists are part of it.
var (
	jsonKeys = map[string]bool{
		"verdict": true, "status": true, "assessment": true, "exit": true, "exitCode": true, "level": true,
		// batch check: the decision, its aggregate category and each item's outcome and category
		"decision": true, "aggregateCategory": true, "outcome": true, "category": true,
		// headline and exit code description, in the scan report and in SARIF
		"headline": true, "exitCodeDescription": true,
		// how fresh the evidence is
		"freshness": true, "evidenceFreshness": true,
		// why a hop or a claim is not covered
		"reason": true,
	}
	jsonBools       = map[string]bool{"covered": true, "established": true, "executionSuccessful": true}
	jsonStringLists = map[string]bool{"categories": true}
	jsonCounted     = map[string]bool{"findings": true, "gaps": true, "passes": true, "notices": true, "leads": true, "unsupported": true, "results": true, "hops": true, "paths": true}
)

// words are the status words of the human and Markdown renderings.
var words = regexp.MustCompile(`\b(PASS FOR THE DECLARED SCOPE|NOT CHECKED|STALE_EVIDENCE|PASS|BLOCKED|UNKNOWN|COVERED|PARTIAL|STALE)\b|\bexit (\d+)\b`)

// counts are the numbers the text renderings print next to what they count:
// "10 checks passed", "(1 covered)", "1 problem", "PROBLEMS TO FIX (1)",
// "NOT CHECKED (2)", "PASSED (6)".
var counts = regexp.MustCompile(`\b(\d+) (problems?|checks passed|covered)\b|\b([A-Z][A-Z ]*[A-Z]) \((\d+)\)`)

// signature is the ordered list of what a golden file says that matters.
func signature(name string, raw []byte) []string {
	var sig []string
	rest := raw
	if strings.HasSuffix(name, ".exit") {
		return []string{"exit=" + strings.TrimSpace(string(raw))}
	}
	if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".sarif") {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err == nil {
			walk(value, "", &sig)
			rest = raw[decoder.InputOffset():]
		}
	}
	if !isJSONOnly(name, rest) {
		text := string(rest)
		for _, match := range words.FindAllStringSubmatch(text, -1) {
			if match[1] != "" {
				sig = append(sig, "word="+match[1])
			} else {
				sig = append(sig, "exit="+match[2])
			}
		}
		for _, match := range counts.FindAllStringSubmatch(text, -1) {
			if match[1] != "" {
				sig = append(sig, "count="+match[1]+" "+strings.TrimSuffix(match[2], "s"))
			} else {
				sig = append(sig, "count="+match[3]+" ("+match[4]+")")
			}
		}
	}
	return sig
}

// isJSONOnly reports a JSON file that was parsed completely (nothing but
// white space follows the value).
func isJSONOnly(name string, rest []byte) bool {
	return (strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".sarif")) && len(bytes.TrimSpace(rest)) == 0
}

func walk(value any, path string, sig *[]string) {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := v[key]
			here := path + "/" + key
			switch c := child.(type) {
			case string:
				if jsonKeys[key] {
					*sig = append(*sig, fmt.Sprintf("%s=%s", key, c))
				}
			case json.Number:
				if jsonKeys[key] || strings.HasSuffix(path, "/summary") {
					*sig = append(*sig, fmt.Sprintf("%s=%s", key, c.String()))
				}
			case bool:
				if jsonBools[key] {
					*sig = append(*sig, fmt.Sprintf("%s=%t", key, c))
				}
			case []any:
				if jsonCounted[key] {
					*sig = append(*sig, fmt.Sprintf("%s[]=%d", key, len(c)))
				}
				if jsonStringLists[key] {
					for _, element := range c {
						if str, ok := element.(string); ok {
							*sig = append(*sig, fmt.Sprintf("%s[]=%s", key, str))
						}
					}
				}
				walk(c, here, sig)
			default:
				walk(child, here, sig)
			}
		}
	case []any:
		for _, element := range v {
			walk(element, path+"[]", sig)
		}
	}
}
