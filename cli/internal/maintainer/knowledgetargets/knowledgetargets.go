// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgetargets builds the per-project CNCF knowledge targets from
// the embedded rule pack and checks every target against the per-target size
// cap. It never signs, fetches, or reads a knowledge store.
package knowledgetargets

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/maintainer/corpusattest"
)

// ErrRejected is returned for invalid arguments or unusable inputs.
var ErrRejected = errors.New("knowledge targets rejected")

// Target is one built target: its TUF path and size in bytes.
type Target struct {
	Path  string
	Bytes int64
}

// Limit is the per-target cap and the size at which the check fails.
type Limit struct {
	Cap   int64
	Alarm int64
	// TotalCap is the bound on the summed size of all targets in one
	// package; TotalAlarm is the size at which the check fails.
	TotalCap   int64
	TotalAlarm int64
}

// DefaultLimit is the published per-target cap with the alarm at 80%.
func DefaultLimit() Limit {
	total := int64(knowledge.SplitMaxPackageMemberBytes)
	return Limit{
		Cap:        int64(cncfcheck.MaxExternalTargetBytes),
		Alarm:      cncfcheck.TargetSizeAlarmBytes(),
		TotalCap:   total,
		TotalAlarm: alarmBytes(total),
	}
}

// alarmBytes is the smallest size at or above 80% of limit, rounded up.
func alarmBytes(limit int64) int64 {
	value := limit * cncfcheck.TargetSizeAlarmPercent
	return (value + 99) / 100
}

// TotalAlarmed reports the summed target size and whether it is at or above
// the aggregate alarm.
func TotalAlarmed(targets []Target, limit Limit) (int64, bool) {
	var sum int64
	for _, target := range targets {
		sum += target.Bytes
	}
	return sum, sum >= limit.TotalAlarm
}

// SingleTargetAlarmed reports whether the single-target layout (the only one
// the publisher can produce today) is at or above the per-target alarm.
func SingleTargetAlarmed(bytes int64, limit Limit) bool {
	return bytes >= limit.Alarm
}

// Alarms returns the targets at or above the alarm size, largest first.
func Alarms(targets []Target, limit Limit) []Target {
	var failed []Target
	for _, target := range targets {
		if target.Bytes >= limit.Alarm {
			failed = append(failed, target)
		}
	}
	sort.SliceStable(failed, func(i, j int) bool {
		if failed[i].Bytes != failed[j].Bytes {
			return failed[i].Bytes > failed[j].Bytes
		}
		return failed[i].Path < failed[j].Path
	})
	return failed
}

// Build returns the index and project targets for revision, optionally
// keeping the revision of every project unchanged since previousIndex.
func Build(revision string, previousIndex []byte) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, error) {
	if previousIndex != nil {
		return cncfcheck.BuildEmbeddedExternalTargetsFrom(revision, previousIndex)
	}
	return cncfcheck.BuildEmbeddedExternalTargets(revision, nil)
}

// exportSingleTarget is a test seam for the single-target layout size.
var exportSingleTarget = cncfcheck.ExportEmbeddedExternalBundle

// Run implements "prufyx-maintainer knowledge-targets build|check-size".
// Exit codes: 0 success, 1 size alarm, 2 rejected command or input.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "build":
		return runBuild(args[1:], stdout, stderr)
	case "check-size":
		return runCheckSize(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
}

const usage = `usage:
  prufyx-maintainer knowledge-targets build --revision N [--previous-index FILE] --output-dir DIR
  prufyx-maintainer knowledge-targets check-size [--dir DIR | --tree TREE]

check-size without --dir or --tree checks the rule pack embedded in THIS binary,
not a candidate checkout; pass --tree TREE to check the pack files of a
checked-out tree (its root or its cli/ directory).`

func runBuild(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("knowledge-targets build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	revision := flags.String("revision", "", "positive index revision")
	previous := flags.String("previous-index", "", "previous index target; unchanged projects keep their revision")
	output := flags.String("output-dir", "", "new output directory")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *revision == "" || *output == "" {
		fmt.Fprintln(stderr, "knowledge-targets build: command rejected")
		return 2
	}
	var previousIndex []byte
	if *previous != "" {
		raw, err := readBounded(*previous)
		if err != nil {
			fmt.Fprintln(stderr, "knowledge-targets build: previous index unreadable")
			return 2
		}
		previousIndex = raw
	}
	index, projects, err := Build(*revision, previousIndex)
	if err != nil {
		fmt.Fprintln(stderr, "knowledge-targets build: targets rejected")
		return 2
	}
	if err := writeTargets(*output, append([]cncfcheck.ExternalTarget{index}, projects...)); err != nil {
		fmt.Fprintf(stderr, "knowledge-targets build: %v\n", err)
		return 2
	}
	targets := []Target{{Path: index.Path, Bytes: int64(len(index.Bytes))}}
	for _, project := range projects {
		targets = append(targets, Target{Path: project.Path, Bytes: int64(len(project.Bytes))})
	}
	fmt.Fprintf(stdout, "built %d project targets and the index at revision %s in %s\n", len(projects), *revision, *output)
	return report(targets, DefaultLimit(), stdout, stderr)
}

func runCheckSize(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("knowledge-targets check-size", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("dir", "", "directory written by build; default builds from the embedded pack")
	tree := flags.String("tree", "", "checked-out source tree (root or cli/ directory) whose CNCF pack files are checked instead of the embedded pack")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || (*dir != "" && *tree != "") {
		fmt.Fprintln(stderr, "knowledge-targets check-size: command rejected")
		return 2
	}
	var targets []Target
	if *tree != "" {
		return checkTree(*tree, stdout, stderr)
	}
	if *dir != "" {
		fmt.Fprintf(stdout, "checked: targets in directory %s\n", *dir)
		found, err := targetsInDir(*dir)
		if err != nil || len(found) == 0 {
			fmt.Fprintln(stderr, "knowledge-targets check-size: no targets found")
			return 2
		}
		targets = found
	} else {
		fmt.Fprintln(stdout, "checked: the rule pack embedded in this binary (not a checked-out tree; use --tree TREE to check a candidate checkout)")
		index, projects, err := Build("1", nil)
		if err != nil {
			fmt.Fprintln(stderr, "knowledge-targets check-size: embedded pack cannot be split into targets")
			return 2
		}
		targets = append(targets, Target{Path: index.Path, Bytes: int64(len(index.Bytes))})
		for _, project := range projects {
			targets = append(targets, Target{Path: project.Path, Bytes: int64(len(project.Bytes))})
		}
		// The publisher can only produce the single-target layout until it
		// emits per-project targets, so that layout is gated too. Remove
		// this gate when the single-target profile is retired.
		code := report(targets, DefaultLimit(), stdout, stderr)
		single, err := exportSingleTarget("1")
		switch {
		case err != nil:
			fmt.Fprintln(stderr, "size alarm: the embedded pack no longer fits the single target knowledge/constraints.v1.json")
			return 1
		case SingleTargetAlarmed(int64(len(single)), DefaultLimit()):
			fmt.Fprintf(stderr, "size alarm: single-target layout knowledge/constraints.v1.json is %d bytes, at or above %d%% of the %d-byte per-target cap (%d bytes); the publisher still produces only this layout\n", len(single), cncfcheck.TargetSizeAlarmPercent, DefaultLimit().Cap, DefaultLimit().Alarm)
			return 1
		}
		fmt.Fprintf(stdout, "single-target layout: knowledge/constraints.v1.json %d bytes (%.1f%% of cap)\n", len(single), percent(int64(len(single)), DefaultLimit().Cap))
		return code
	}
	return report(targets, DefaultLimit(), stdout, stderr)
}

// checkTree checks the CNCF pack files of a checked-out tree against the same
// per-target caps, admitting them with this binary's engine. It fails closed:
// an unreadable, unadmitted or unsplittable pack is a rejection, not a pass.
func checkTree(tree string, stdout, stderr io.Writer) int {
	cli, err := corpusattest.ResolveTreeCLI(tree)
	if err != nil {
		fmt.Fprintln(stderr, "knowledge-targets check-size: tree rejected")
		return 2
	}
	read := corpusattest.ReadRegularFile(cli)
	var files [3][]byte
	for i, rel := range []string{"internal/cncfcheck/data/landscape-projects.json", "internal/cncfcheck/data/priority-portfolio.json", "internal/cncfcheck/data/rules.json"} {
		if files[i], err = read(rel); err != nil || len(files[i]) > corpusattest.MaxInputBytes {
			fmt.Fprintln(stderr, "knowledge-targets check-size: tree pack files unreadable")
			return 2
		}
	}
	packReport, err := cncfcheck.CheckPackFiles(files[0], files[1], files[2])
	if err != nil {
		fmt.Fprintln(stderr, "knowledge-targets check-size: tree pack not admitted")
		return 2
	}
	if packReport.SplitErr != nil {
		fmt.Fprintln(stderr, "size alarm: the tree pack no longer splits into per-project targets")
		return 1
	}
	fmt.Fprintf(stdout, "checked: CNCF pack files of tree %s\n", filepath.ToSlash(cli))
	var targets []Target
	for _, target := range packReport.ProjectTargets {
		targets = append(targets, Target{Path: target.Path, Bytes: int64(len(target.Bytes))})
	}
	if len(targets) == 0 {
		fmt.Fprintln(stderr, "knowledge-targets check-size: no targets found")
		return 2
	}
	code := report(targets, DefaultLimit(), stdout, stderr)
	if SingleTargetAlarmed(int64(packReport.TargetBytes), DefaultLimit()) {
		fmt.Fprintf(stderr, "size alarm: single-target layout is %d bytes, at or above the per-target alarm (%d bytes)\n", packReport.TargetBytes, DefaultLimit().Alarm)
		return 1
	}
	fmt.Fprintf(stdout, "single-target layout: %d bytes (%.1f%% of cap)\n", packReport.TargetBytes, percent(int64(packReport.TargetBytes), DefaultLimit().Cap))
	return code
}

// report prints the largest targets and every alarm. The check fails when
// any target is at or above the alarm size.
func report(targets []Target, limit Limit, stdout, stderr io.Writer) int {
	sorted := append([]Target(nil), targets...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Bytes != sorted[j].Bytes {
			return sorted[i].Bytes > sorted[j].Bytes
		}
		return sorted[i].Path < sorted[j].Path
	})
	fmt.Fprintf(stdout, "per-target cap %d bytes; alarm at %d bytes (%d%%)\n", limit.Cap, limit.Alarm, cncfcheck.TargetSizeAlarmPercent)
	for i, target := range sorted {
		if i == 5 {
			break
		}
		fmt.Fprintf(stdout, "%s %d bytes (%.1f%% of cap)\n", target.Path, target.Bytes, percent(target.Bytes, limit.Cap))
	}
	failed := Alarms(targets, limit)
	for _, target := range failed {
		fmt.Fprintf(stderr, "size alarm: target %s is %d bytes, at or above %d%% of the %d-byte per-target cap (%d bytes)\n", target.Path, target.Bytes, cncfcheck.TargetSizeAlarmPercent, limit.Cap, limit.Alarm)
	}
	sum, totalAlarmed := TotalAlarmed(targets, limit)
	fmt.Fprintf(stdout, "package total %d bytes (%.1f%% of the %d-byte member total); alarm at %d bytes\n", sum, percent(sum, limit.TotalCap), limit.TotalCap, limit.TotalAlarm)
	if totalAlarmed {
		fmt.Fprintf(stderr, "size alarm: summed targets are %d bytes, at or above %d%% of the %d-byte package member total (%d bytes)\n", sum, cncfcheck.TargetSizeAlarmPercent, limit.TotalCap, limit.TotalAlarm)
	}
	if len(failed) > 0 || totalAlarmed {
		return 1
	}
	fmt.Fprintf(stdout, "all %d targets are below the size alarm\n", len(targets))
	return 0
}

func percent(value, total int64) float64 {
	return float64(value) * 100 / float64(total)
}

func writeTargets(dir string, targets []cncfcheck.ExternalTarget) error {
	if err := os.Mkdir(dir, 0o755); err != nil {
		return fmt.Errorf("output directory must not exist: %w", ErrRejected)
	}
	for _, target := range targets {
		if !strings.HasPrefix(target.Path, "knowledge/cncf/") || strings.Contains(target.Path, "..") {
			return ErrRejected
		}
		name := filepath.Join(dir, filepath.FromSlash(target.Path))
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := f.Write(target.Bytes); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// targetsInDir measures every .json file under DIR/knowledge/cncf. Sizes are
// measured without parsing, so an oversize target is still reported.
func targetsInDir(dir string) ([]Target, error) {
	base := filepath.Join(dir, "knowledge", "cncf")
	var targets []Target
	err := filepath.WalkDir(base, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return ErrRejected
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return ErrRejected
		}
		rel, err := filepath.Rel(dir, name)
		if err != nil {
			return err
		}
		targets = append(targets, Target{Path: filepath.ToSlash(rel), Bytes: info.Size()})
		return nil
	})
	return targets, err
}

func readBounded(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(cncfcheck.MaxExternalTargetBytes)+1))
	if err != nil || len(raw) > cncfcheck.MaxExternalTargetBytes {
		return nil, ErrRejected
	}
	return raw, nil
}
