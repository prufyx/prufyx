// SPDX-License-Identifier: AGPL-3.0-only

// Command goldensemantics compares two copies of a set of golden files (a
// snapshot taken before they were regenerated and the regenerated files) by
// what they say, not by their bytes: verdicts, statuses, assessments, levels,
// exit codes, hop states and the counts of findings, gaps and passes. It
// prints a before/after summary for every file and exits 3 when anything
// semantic differs, unless -allow-semantic-change is given. Rule ids, reason
// codes, citations, fix text, dates and digests are not compared: a change of
// the shipped rule pack is expected to move those. It is the guard of
// scripts/regenerate-pack-goldens.sh, which would otherwise absorb any change.
//
//	goldensemantics [-allow-semantic-change] BEFORE_DIR AFTER_DIR
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
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
	allow := flags.Bool("allow-semantic-change", false, "accept a change of statuses, verdicts, exit codes or hop states")
	if err := flags.Parse(args); err != nil || flags.NArg() != 2 {
		fmt.Fprintln(stderr, "usage: goldensemantics [-allow-semantic-change] BEFORE_DIR AFTER_DIR")
		return 2
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
	changed, textChanged := report(stdout, before, after)
	switch {
	case changed == 0:
		fmt.Fprintf(stdout, "no semantic difference (%d of %d golden files differ in text only)\n", textChanged, len(union(before, after)))
		return 0
	case *allow:
		fmt.Fprintf(stdout, "%d golden files changed semantically: accepted by -allow-semantic-change\n", changed)
		return 0
	}
	fmt.Fprintf(stderr, "%d golden files changed semantically (statuses, verdicts, exit codes or hop states): refused. Read the lines above; if the change is intended, rerun with --allow-semantic-change.\n", changed)
	return exitSemanticChange
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

// report prints the comparison of the files whose bytes differ, and returns
// how many differ in meaning and how many differ in text only. A file that
// exists on one side only differs in meaning.
func report(out io.Writer, before, after map[string][]byte) (changed, textChanged int) {
	fmt.Fprintln(out, "golden semantics (statuses, verdicts, exit codes, hop states), before -> after")
	for _, name := range union(before, after) {
		b, hadBefore := before[name]
		a, hasAfter := after[name]
		switch {
		case !hadBefore:
			changed++
			fmt.Fprintf(out, "  NEW      %s: %s\n", name, summarize(signature(name, a)))
		case !hasAfter:
			changed++
			fmt.Fprintf(out, "  REMOVED  %s: %s\n", name, summarize(signature(name, b)))
		default:
			if bytes.Equal(a, b) {
				continue
			}
			sb, sa := signature(name, b), signature(name, a)
			switch {
			case equal(sb, sa):
				textChanged++
				fmt.Fprintf(out, "  same     %s: %s\n", name, summarize(sa))
			default:
				changed++
				fmt.Fprintf(out, "  CHANGED  %s\n           before: %s\n           after:  %s\n", name, summarize(sb), summarize(sa))
				for _, line := range diffLines(sb, sa) {
					fmt.Fprintf(out, "           %s\n", line)
				}
			}
		}
	}
	return changed, textChanged
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
// meaning of a report; the elements of the arrays in jsonCounted are counted.
var (
	jsonKeys    = map[string]bool{"verdict": true, "status": true, "assessment": true, "exit": true, "exitCode": true, "level": true}
	jsonCounted = map[string]bool{"findings": true, "gaps": true, "passes": true, "notices": true, "leads": true, "unsupported": true, "results": true, "hops": true, "paths": true}
	// A gap's reason says why a hop is UNKNOWN.
	jsonGapReason = "reason"
)

// words are the status words of the human and Markdown renderings.
var words = regexp.MustCompile(`\b(PASS FOR THE DECLARED SCOPE|NOT CHECKED|PASS|BLOCKED|UNKNOWN|COVERED|PARTIAL)\b|\bexit (\d+)\b`)

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
		for _, match := range words.FindAllStringSubmatch(string(rest), -1) {
			if match[1] != "" {
				sig = append(sig, "word="+match[1])
			} else {
				sig = append(sig, "exit="+match[2])
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
				if jsonKeys[key] || (key == jsonGapReason && strings.HasSuffix(path, "/gaps[]")) {
					*sig = append(*sig, fmt.Sprintf("%s=%s", key, c))
				}
			case json.Number:
				if jsonKeys[key] || strings.HasSuffix(path, "/summary") {
					*sig = append(*sig, fmt.Sprintf("%s=%s", key, c.String()))
				}
			case []any:
				if jsonCounted[key] {
					*sig = append(*sig, fmt.Sprintf("%s[]=%d", key, len(c)))
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
