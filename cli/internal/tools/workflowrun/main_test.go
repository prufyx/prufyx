// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `
jobs:
  build:
    strategy:
      matrix:
        include:
          - goos: linux
            goarch: amd64
          - goos: darwin
            goarch: arm64
    steps:
      - name: Build
        working-directory: cli
        env:
          GOOS: ${{ matrix.goos }}
          CGO_ENABLED: "0"
          QUOTE: "it's"
        run: |
          set -euo pipefail
          echo hi
      - name: Uses
        uses: actions/checkout@x
`

func runTool(t *testing.T, args ...string) (string, error) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "w.yml")
	if err := os.WriteFile(file, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run(append([]string{args[0], file}, args[1:]...), &out)
	return out.String(), err
}

func TestStepScript(t *testing.T) {
	got, err := runTool(t, "STEP-SCRIPT", "build", "Build")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`cd "${GITHUB_WORKSPACE:?}/cli"`,
		`: "${GOOS?the dry run must provide GOOS}"`,
		`export CGO_ENABLED='0'`,
		`export QUOTE='it'\''s'`,
		"set -euo pipefail\necho hi\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("script lacks %q:\n%s", want, got)
		}
	}
}

func TestStepScriptRefusals(t *testing.T) {
	for _, name := range []string{"Uses", "Missing"} {
		if _, err := runTool(t, "STEP-SCRIPT", "build", name); err == nil {
			t.Errorf("step %q must be refused", name)
		}
	}
}

func TestMatrix(t *testing.T) {
	got, err := runTool(t, "MATRIX", "build")
	if err != nil {
		t.Fatal(err)
	}
	if got != "linux amd64\ndarwin arm64\n" {
		t.Errorf("matrix = %q", got)
	}
}

// The real release workflow must yield a script for every step the dry run
// executes.
func TestReleaseWorkflowSteps(t *testing.T) {
	file := filepath.Join("..", "..", "..", "..", ".github", "workflows", "release.yml")
	if _, err := os.Stat(file); err != nil {
		t.Skip("no .github directory: staged release source tree")
	}
	for _, c := range [][2]string{
		{"build", "Check the tag"},
		{"build", "Check the knowledge root pin"},
		{"build", "Check the embedded knowledge is fresh"},
		{"build", "Build binaries"},
		{"packages", "Build packages"},
		{"provenance", "Generate SHA256SUMS"},
	} {
		var out bytes.Buffer
		if err := run([]string{"STEP-SCRIPT", file, c[0], c[1]}, &out); err != nil {
			t.Errorf("%s/%s: %v", c[0], c[1], err)
		}
	}
	var out bytes.Buffer
	if err := run([]string{"MATRIX", file, "build"}, &out); err != nil || strings.Count(out.String(), "\n") != 4 {
		t.Errorf("matrix: %q %v", out.String(), err)
	}
}

func TestStepScriptRefusesBadEnvKey(t *testing.T) {
	file := filepath.Join(t.TempDir(), "w.yml")
	bad := "jobs:\n  j:\n    steps:\n      - name: S\n        env:\n          \"A;rm\": x\n        run: echo\n"
	if err := os.WriteFile(file, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"STEP-SCRIPT", file, "j", "S"}, &bytes.Buffer{}); err == nil {
		t.Error("an env key that is not a variable name must be refused")
	}
}
