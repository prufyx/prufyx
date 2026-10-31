// SPDX-License-Identifier: AGPL-3.0-only

// Command workflowrun prints the `run:` body of one named step of a GitHub
// Actions workflow file as a shell script, so that scripts/release-dry-run.sh
// can execute the release workflow's own step bodies verbatim instead of
// keeping a copy that could drift.
//
//	workflowrun STEP-SCRIPT FILE JOB "STEP NAME"
//	workflowrun MATRIX      FILE JOB
//
// The step script starts with `cd "$GITHUB_WORKSPACE/<working-directory>"` and
// an `export` of every literal env entry of the step. An env entry that holds
// a `${{ }}` expression becomes `: "${NAME?}"`: the caller must provide it (empty is fine),
// and the script fails at once when it does not. The matrix mode prints one
// "goos goarch" line per include entry of the job.
package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type step struct {
	Name             string            `yaml:"name"`
	Env              map[string]string `yaml:"env"`
	Run              string            `yaml:"run"`
	WorkingDirectory string            `yaml:"working-directory"`
}

type job struct {
	Strategy struct {
		Matrix struct {
			Include []map[string]string `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []step `yaml:"steps"`
}

type workflow struct {
	Jobs map[string]job `yaml:"jobs"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "workflowrun:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: workflowrun STEP-SCRIPT|MATRIX FILE JOB [STEP NAME]")
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return err
	}
	j, ok := wf.Jobs[args[2]]
	if !ok {
		return fmt.Errorf("no job %q", args[2])
	}
	switch args[0] {
	case "MATRIX":
		return matrix(j, out)
	case "STEP-SCRIPT":
		if len(args) != 4 {
			return fmt.Errorf("STEP-SCRIPT needs a step name")
		}
		return stepScript(j, args[3], out)
	}
	return fmt.Errorf("unknown mode %q", args[0])
}

func matrix(j job, out io.Writer) error {
	if len(j.Strategy.Matrix.Include) == 0 {
		return fmt.Errorf("job has no matrix include list")
	}
	for _, entry := range j.Strategy.Matrix.Include {
		if entry["goos"] == "" || entry["goarch"] == "" || len(entry) != 2 {
			return fmt.Errorf("matrix entry %v is not exactly goos and goarch", entry)
		}
		fmt.Fprintf(out, "%s %s\n", entry["goos"], entry["goarch"])
	}
	return nil
}

func stepScript(j job, name string, out io.Writer) error {
	var found *step
	for i := range j.Steps {
		if j.Steps[i].Name != name {
			continue
		}
		if found != nil {
			return fmt.Errorf("step name %q is not unique", name)
		}
		found = &j.Steps[i]
	}
	if found == nil {
		return fmt.Errorf("no step %q", name)
	}
	if strings.TrimSpace(found.Run) == "" {
		return fmt.Errorf("step %q has no run block", name)
	}
	if strings.Contains(found.Run, "${{") {
		return fmt.Errorf("step %q has an expression in its run block", name)
	}
	if strings.Contains(found.WorkingDirectory, "${{") || strings.ContainsAny(found.WorkingDirectory, "\"$`\\\n") {
		return fmt.Errorf("step %q has an unsupported working-directory", name)
	}
	wd := "${GITHUB_WORKSPACE:?}"
	if found.WorkingDirectory != "" {
		wd += "/" + found.WorkingDirectory
	}
	fmt.Fprintf(out, "cd \"%s\"\n", wd)
	keys := make([]string, 0, len(found.Env))
	for k := range found.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !envName.MatchString(k) {
			return fmt.Errorf("step %q has an env key %q that is not a shell variable name", name, k)
		}
		v := found.Env[k]
		if strings.Contains(v, "${{") {
			fmt.Fprintf(out, ": \"${%s?the dry run must provide %s}\"\n", k, k)
			continue
		}
		fmt.Fprintf(out, "export %s='%s'\n", k, strings.ReplaceAll(v, "'", `'\''`))
	}
	_, err := io.WriteString(out, found.Run)
	return err
}
