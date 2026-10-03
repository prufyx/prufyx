// SPDX-License-Identifier: AGPL-3.0-only

package knowledgetargets

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func TestAlarmFiresAtEightyPercentOfTheCap(t *testing.T) {
	limit := DefaultLimit()
	if limit.Cap != 1<<20 || limit.Alarm != 838861 {
		t.Fatalf("limit=%+v", limit)
	}
	below := Target{Path: "knowledge/cncf/projects/a.v1.json", Bytes: limit.Alarm - 1}
	at := Target{Path: "knowledge/cncf/projects/b.v1.json", Bytes: limit.Alarm}
	over := Target{Path: "knowledge/cncf/projects/c.v1.json", Bytes: limit.Cap + 1}
	if got := Alarms([]Target{below}, limit); len(got) != 0 {
		t.Fatalf("alarm below 80%%: %+v", got)
	}
	if got := Alarms([]Target{below, at, over}, limit); len(got) != 2 || got[0] != over || got[1] != at {
		t.Fatalf("alarms=%+v", got)
	}
	var stdout, stderr bytes.Buffer
	if code := report([]Target{below, at}, limit, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "size alarm: target knowledge/cncf/projects/b.v1.json is 838861 bytes") {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := report([]Target{below}, limit, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
}

func TestBuildIsDeterministicAndCheckSizeReadsTheOutput(t *testing.T) {
	dir := t.TempDir()
	first, second := filepath.Join(dir, "one"), filepath.Join(dir, "two")
	for _, out := range []string{first, second} {
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"build", "--revision", "7", "--output-dir", out}, &stdout, &stderr); code != 0 {
			t.Fatalf("build code=%d stderr=%s", code, stderr.String())
		}
	}
	a, err := targetsInDir(first)
	if err != nil || len(a) < 2 {
		t.Fatalf("targets=%v err=%v", a, err)
	}
	for _, target := range a {
		x, _ := os.ReadFile(filepath.Join(first, filepath.FromSlash(target.Path)))
		y, _ := os.ReadFile(filepath.Join(second, filepath.FromSlash(target.Path)))
		if !bytes.Equal(x, y) {
			t.Fatalf("non-deterministic target %s", target.Path)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"build", "--revision", "7", "--output-dir", first}, &stdout, &stderr); code != 2 {
		t.Fatal("build overwrote an existing directory")
	}

	// Incremental build keeps unchanged projects at their old revision.
	third := filepath.Join(dir, "three")
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"build", "--revision", "8", "--previous-index", filepath.Join(first, "knowledge", "cncf", "index.v1.json"), "--output-dir", third}, &stdout, &stderr); code != 0 {
		t.Fatalf("incremental build code=%d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(third, "knowledge", "cncf", "index.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	index, err := cncfcheck.ParseExternalIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	if admission, _ := index.Admission(); admission.Revision != "8" {
		t.Fatalf("index revision %s", admission.Revision)
	}
	for _, entry := range index.Entries() {
		if entry.Revision != "7" {
			t.Fatalf("unchanged project %s moved to revision %s", entry.Project, entry.Revision)
		}
	}

	// An oversize file in the output directory fails the check with its name.
	big := filepath.Join(first, "knowledge", "cncf", "projects", "kubernetes.v1.json")
	if err := os.WriteFile(big, bytes.Repeat([]byte(" "), int(DefaultLimit().Alarm)), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"check-size", "--dir", first}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "knowledge/cncf/projects/kubernetes.v1.json is 838861 bytes") {
		t.Fatalf("check-size code=%d stderr=%s", code, stderr.String())
	}
}

// TestEmbeddedPackTargetsAreBelowTheAlarm is the CI gate on the embedded pack.
func TestEmbeddedPackTargetsAreBelowTheAlarm(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"check-size"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}
