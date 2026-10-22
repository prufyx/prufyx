// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Run implements "onboard-bundle validate [--dir-is-slug] DIR...". With
// --dir-is-slug the directory name must equal the slug in project.json (the
// layout contrib/onboard-bundles/<slug>/). It returns 0 when every
// directory is well-formed, 1 when any has findings and 2 for usage or I/O
// errors. Output is deterministic and offline.
func Run(args []string, stdout, stderr io.Writer) int {
	dirIsSlug := false
	if len(args) > 1 && args[1] == "--dir-is-slug" {
		dirIsSlug = true
		args = append(args[:1:1], args[2:]...)
	}
	if len(args) < 2 || args[0] != "validate" {
		fmt.Fprintln(stderr, "usage: prufyx-maintainer onboard-bundle validate [--dir-is-slug] DIR [DIR...]")
		return 2
	}
	status := 0
	for _, dir := range args[1:] {
		findings, err := Validate(dir)
		if err != nil {
			fmt.Fprintf(stderr, "onboard-bundle: %s: %v\n", dir, err)
			return 2
		}
		if dirIsSlug {
			if f := dirSlugFinding(dir); f != "" {
				findings = append(findings, f)
			}
		}
		for _, f := range findings {
			fmt.Fprintf(stdout, "FAIL %s: %s\n", dir, f)
		}
		fmt.Fprintf(stdout, "onboard-bundle: %s: %d findings (structure only; no claim is verified)\n", dir, len(findings))
		if len(findings) > 0 {
			status = 1
		}
	}
	return status
}

// dirSlugFinding reports a directory whose name differs from the slug in a
// readable project.json. Other problems with project.json are Validate's.
func dirSlugFinding(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(abs, "project.json"))
	if err != nil || len(raw) > MaxFileBytes {
		return ""
	}
	var p struct {
		Slug string `json:"slug"`
	}
	if json.Unmarshal(raw, &p) != nil || p.Slug == "" {
		return ""
	}
	if filepath.Base(abs) != p.Slug {
		return "project.json: slug " + p.Slug + " differs from the directory name " + filepath.Base(abs)
	}
	return ""
}
