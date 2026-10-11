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

func TestPackageTotalAlarmFiresAtEightyPercentOfTheMemberTotal(t *testing.T) {
	limit := DefaultLimit()
	if limit.TotalCap != 7<<20 || limit.TotalAlarm != 5872026 {
		t.Fatalf("limit=%+v", limit)
	}
	// Every target is far below the per-target alarm; only the sum is large.
	each := limit.Alarm - 1
	build := func(sum int64) []Target {
		var targets []Target
		for i := 0; sum > 0; i++ {
			size := each
			if sum < size {
				size = sum
			}
			targets = append(targets, Target{Path: "knowledge/cncf/projects/p" + string(rune('a'+i)) + ".v1.json", Bytes: size})
			sum -= size
		}
		return targets
	}
	var stdout, stderr bytes.Buffer
	if code := report(build(limit.TotalAlarm-1), limit, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("below: code=%d stderr=%s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := report(build(limit.TotalAlarm), limit, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "summed targets are 5872026 bytes") {
		t.Fatalf("at: code=%d stderr=%s", code, stderr.String())
	}
}

func TestSingleTargetLayoutIsGated(t *testing.T) {
	limit := DefaultLimit()
	if SingleTargetAlarmed(limit.Alarm-1, limit) || !SingleTargetAlarmed(limit.Alarm, limit) {
		t.Fatal("single-target boundary is not 80% of the cap")
	}
	original := exportSingleTarget
	defer func() { exportSingleTarget = original }()

	exportSingleTarget = func(string) ([]byte, error) { return make([]byte, limit.Alarm), nil }
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"check-size"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "single-target layout knowledge/constraints.v1.json is 838861 bytes") {
		t.Fatalf("at alarm: code=%d stderr=%s", code, stderr.String())
	}
	exportSingleTarget = func(string) ([]byte, error) { return make([]byte, limit.Alarm-1), nil }
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"check-size"}, &stdout, &stderr); code != 0 {
		t.Fatalf("below alarm: code=%d stderr=%s", code, stderr.String())
	}
	exportSingleTarget = func(string) ([]byte, error) { return nil, ErrRejected }
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"check-size"}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "no longer fits") {
		t.Fatalf("unbuildable: code=%d stderr=%s", code, stderr.String())
	}
}

// check-size --tree reads the pack files of a checkout, prints which tree it
// checked, and rejects what is not a tree; without --dir/--tree it says it
// checked the embedded pack.
func TestCheckSizeNamesWhatItChecked(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	if code := Run([]string{"check-size", "--tree", root}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "checked: CNCF pack files of tree ") {
		t.Fatalf("tree not named: %s", stdout.String())
	}
	stdout.Reset()
	if code := Run([]string{"check-size"}, &stdout, &stderr); code != 0 {
		t.Fatalf("embedded exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "embedded in this binary") {
		t.Fatalf("embedded default not named: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"check-size", "--tree", t.TempDir()}, &stdout, &stderr); code != 2 {
		t.Fatalf("a non-tree must be rejected, exit %d", code)
	}
	if code := Run([]string{"check-size", "--tree", root, "--dir", root}, &stdout, &stderr); code != 2 {
		t.Fatalf("--tree with --dir must be rejected, exit %d", code)
	}
}

// check-size --tree reads the pack with the gate's reader semantics: a link
// below the tree, a FIFO or an oversized pack input is refused (exit 2),
// never followed or waited on. The single-target line names its target.
func TestCheckSizeTreeRefusesLinksAndNamesTheSingleTarget(t *testing.T) {
	cli, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tree := t.TempDir()
	data := filepath.Join(tree, "cli", "internal", "cncfcheck", "data")
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"internal/projectcheck/data/projects.json", "internal/projectcheck/data/rules.json",
		"internal/cncfcheck/data/landscape-projects.json", "internal/cncfcheck/data/priority-portfolio.json", "internal/cncfcheck/data/rules.json",
	} {
		raw, err := os.ReadFile(filepath.Join(cli, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(tree, "cli", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr strings.Builder
	if code := Run([]string{"check-size", "--tree", tree}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "single-target layout: knowledge/constraints.v1.json ") {
		t.Fatalf("the single target is not named: %s", stdout.String())
	}
	// Move the data directory outside and link to it.
	outside := filepath.Join(t.TempDir(), "data")
	if err := os.Rename(data, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, data); err != nil {
		t.Skip("symlinks unavailable")
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"check-size", "--tree", tree}, &stdout, &stderr); code != 2 {
		t.Fatalf("a symlinked data directory was accepted: exit %d", code)
	}
}

// The targets of the community catalog are written under their own prefix,
// measured with the others, and nothing else is written outside the two
// prefixes.
func TestCommunityTargetsAreWrittenAndMeasured(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	targets := []cncfcheck.ExternalTarget{
		{Path: "knowledge/cncf/index.v1.json", Bytes: []byte("{}")},
		{Path: "knowledge/cncf/projects/kubernetes.v1.json", Bytes: []byte("{}")},
		{Path: cncfcheck.ProjectTargetPath("gateway-api"), Bytes: []byte("{ }")},
	}
	if err := writeTargets(dir, targets); err != nil {
		t.Fatal(err)
	}
	measured, err := targetsInDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]int64{}
	for _, target := range measured {
		paths[target.Path] = target.Bytes
	}
	if len(paths) != 3 || paths["knowledge/community/projects/gateway-api.v1.json"] != 3 || paths["knowledge/cncf/projects/kubernetes.v1.json"] != 2 {
		t.Fatalf("measured %v", paths)
	}
	// A package without a community directory is measured as before.
	plain := filepath.Join(t.TempDir(), "plain")
	if err := writeTargets(plain, targets[:2]); err != nil {
		t.Fatal(err)
	}
	if measured, err := targetsInDir(plain); err != nil || len(measured) != 2 {
		t.Fatalf("plain: %v %v", measured, err)
	}
	for _, bad := range []string{"knowledge/other/projects/x.v1.json", "knowledge/community/../x.v1.json", "knowledge/communities/projects/x.v1.json"} {
		if err := writeTargets(filepath.Join(t.TempDir(), "bad"), []cncfcheck.ExternalTarget{{Path: bad, Bytes: []byte("{}")}}); err == nil {
			t.Fatalf("%s written", bad)
		}
	}
}
