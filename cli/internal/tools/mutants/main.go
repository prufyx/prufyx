// SPDX-License-Identifier: AGPL-3.0-only

// Command mutants applies the committed source mutations in
// testdata/mutants.json one at a time and checks that the targeted tests
// fail ("kill" the mutant). Each mutated file is written to a temporary
// directory and substituted with `go test -overlay`, so the working tree is
// never modified. Standard library only.
//
// Exit status: 0 when every mutant behaves as its "expect" says; 1 when a
// mutant expected to be killed survives, a `find` string does not occur
// exactly once, a mutant does not build, or the data file is invalid.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Schema is the value of the data file's "schema" field.
const Schema = "prufyx-mutants-v1"

// File is the committed data file.
type File struct {
	Schema  string   `json:"schema"`
	Mutants []Mutant `json:"mutants"`
}

// Mutant is one source change and the test that must notice it.
type Mutant struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	// File is relative to the module root (cli).
	File string `json:"file"`
	// Find must occur exactly once in File.
	Find    string `json:"find"`
	Replace string `json:"replace"`
	// Package is the go test package pattern, e.g. ./internal/scanreport.
	Package string `json:"package"`
	// Run is the go test -run pattern.
	Run string `json:"run"`
	// Tags is an optional go test -tags value, for tests behind a build tag.
	Tags string `json:"tags,omitempty"`
	// Expect is "killed" or "survived" (an equivalent mutant, with the reason in Description).
	Expect string `json:"expect"`
}

type outcome string

const (
	killed   outcome = "killed"
	survived outcome = "survived"
	stale    outcome = "stale"
	broken   outcome = "build-error"
)

func main() {
	data := flag.String("data", "testdata/mutants.json", "mutants data file")
	root := flag.String("module", ".", "module root (the directory with go.mod)")
	only := flag.String("only", "", "comma-separated mutant ids to run")
	timeout := flag.Duration("timeout", 10*time.Minute, "per-mutant test timeout")
	verbose := flag.Bool("v", false, "print the test output of survivors and errors")
	flag.Parse()
	os.Exit(run(*data, *root, *only, *timeout, *verbose))
}

func run(dataPath, root, only string, timeout time.Duration, verbose bool) int {
	raw, err := os.ReadFile(dataPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mutants:", err)
		return 1
	}
	var file File
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil || file.Schema != Schema {
		fmt.Fprintf(os.Stderr, "mutants: %s: invalid data (schema %q wanted): %v\n", dataPath, Schema, err)
		return 1
	}
	if err := validate(file.Mutants); err != nil {
		fmt.Fprintln(os.Stderr, "mutants:", err)
		return 1
	}
	selected := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		if id != "" {
			selected[id] = true
		}
	}
	tmp, err := os.MkdirTemp("", "prufyx-mutants-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mutants:", err)
		return 1
	}
	defer os.RemoveAll(tmp)
	absRoot, err := filepath.Abs(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mutants:", err)
		return 1
	}

	counts := map[outcome]int{}
	failed := 0
	for _, m := range file.Mutants {
		if len(selected) > 0 && !selected[m.ID] {
			continue
		}
		got, detail := runOne(m, absRoot, tmp, timeout)
		counts[got]++
		bad := got != outcome(m.Expect)
		mark := "ok  "
		if bad {
			mark, failed = "FAIL", failed+1
		}
		fmt.Printf("%s %-14s %-11s %s\n", mark, m.ID, got, m.Description)
		if bad && verbose || got == stale || got == broken {
			fmt.Println(indent(detail))
		}
	}
	fmt.Printf("mutants: %d killed, %d survived, %d stale, %d build errors; %d unexpected\n",
		counts[killed], counts[survived], counts[stale], counts[broken], failed)
	if failed > 0 {
		return 1
	}
	return 0
}

func validate(ms []Mutant) error {
	seen := map[string]bool{}
	for _, m := range ms {
		switch {
		case m.ID == "" || seen[m.ID]:
			return fmt.Errorf("mutant id %q is empty or repeated", m.ID)
		case m.File == "" || m.Find == "" || m.Package == "" || m.Run == "":
			return fmt.Errorf("%s: file, find, package and run are required", m.ID)
		case m.Find == m.Replace:
			return fmt.Errorf("%s: replace equals find", m.ID)
		case m.Expect != "killed" && m.Expect != "survived":
			return fmt.Errorf("%s: expect must be killed or survived", m.ID)
		case filepath.IsAbs(m.File) || strings.Contains(m.File, ".."):
			return fmt.Errorf("%s: file must be relative to the module root", m.ID)
		}
		seen[m.ID] = true
	}
	return nil
}

func runOne(m Mutant, root, tmp string, timeout time.Duration) (outcome, string) {
	src := filepath.Join(root, m.File)
	orig, err := os.ReadFile(src)
	if err != nil {
		return stale, err.Error()
	}
	if n := bytes.Count(orig, []byte(m.Find)); n != 1 {
		return stale, fmt.Sprintf("find string occurs %d times in %s, wanted exactly 1", n, m.File)
	}
	mutated := bytes.Replace(orig, []byte(m.Find), []byte(m.Replace), 1)
	dir := filepath.Join(tmp, m.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return broken, err.Error()
	}
	copyPath := filepath.Join(dir, filepath.Base(m.File))
	overlayPath := filepath.Join(dir, "overlay.json")
	overlay, _ := json.Marshal(map[string]map[string]string{"Replace": {src: copyPath}})
	if err := os.WriteFile(copyPath, mutated, 0o600); err != nil {
		return broken, err.Error()
	}
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		return broken, err.Error()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Minute)
	defer cancel()
	args := []string{"test", "-count=1", "-p", "2", "-overlay", overlayPath, "-timeout", timeout.String(), "-run", m.Run}
	if m.Tags != "" {
		args = append(args, "-tags", m.Tags)
	}
	cmd := exec.CommandContext(ctx, "go", append(args, m.Package)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOMAXPROCS=4", "GOFLAGS=-mod=vendor", "GOWORK=off")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err = cmd.Run()
	text := out.String()
	switch {
	case strings.Contains(text, "no tests to run"):
		return broken, "the -run pattern matches no test\n" + text
	case err == nil:
		return survived, text
	case strings.Contains(text, "[build failed]") || strings.Contains(text, "[setup failed]"):
		return broken, text
	case !strings.Contains(text, "FAIL"):
		return broken, text
	default:
		return killed, text
	}
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > 25 {
		lines = append(lines[:25], "...")
	}
	return "    " + strings.Join(lines, "\n    ")
}
