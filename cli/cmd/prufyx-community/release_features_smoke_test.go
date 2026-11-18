// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasenotes"
)

// TestReleaseFeatureDemosRun runs every binary entry of the release smoke list
// (cli/docs/release-features-smoke.json) through the command and checks the
// exit code and one line of the output. The release-docs gate requires the
// demo command of every "works" feature to be on that list.
func TestReleaseFeatureDemosRun(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(releasenotes.SmokePath)))
	if err != nil {
		t.Fatal(err)
	}
	list, err := releasenotes.LoadSmoke(raw)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	ran := 0
	for _, e := range list.Entries {
		if e.Kind != releasenotes.SmokeBinary {
			continue
		}
		ran++
		t.Run(e.Demo, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(context.Background(), e.Args, &out, &errb)
			if code != *e.WantExit {
				t.Fatalf("exit %d, want %d; stderr: %s", code, *e.WantExit, errb.String())
			}
			if !strings.Contains(out.String()+errb.String(), e.WantContains) {
				t.Fatalf("output lacks %q", e.WantContains)
			}
		})
	}
	if ran == 0 {
		t.Fatal("the smoke list has no binary entry")
	}
}
