// SPDX-License-Identifier: AGPL-3.0-only

// Package changelogcli wires the "changelog" maintainer subcommands. "entries"
// reads one release tag's changelog entry from the offline mirror (or a
// fixture tree) and prints the manifest on standard output. It reads only
// through the pinned reader, never the network, writes no file and decides
// nothing about any item.
package changelogcli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

const usage = `usage:
  prufyx-maintainer changelog entries --component NAME --repo github.com/OWNER/NAME --path FILE --form FORM --tag TAG (--mirror-state DIR | --fixture DIR)
  prufyx-maintainer changelog rows-check (--mirror-state DIR | --fixture DIR) [--component NAME] [--min-located-newest N]
  prufyx-maintainer changelog propose-rows (--mirror-state DIR | --fixture DIR) --component NAME --repo github.com/OWNER/NAME [--tags TAG,TAG]
exit: 0 manifest printed (entry or typed reason), every row PASS or a row proposed, 1 a row FAIL or NO-ROW, 2 input rejected or read failed`

// Main runs a "changelog" subcommand (args exclude the word "changelog") with
// the reviewed target table. It returns 0 when a manifest was printed and 2
// for every refusal; on a refusal nothing is written to stdout.
func Main(args []string, stdout, stderr io.Writer) int {
	return run(args, changelogentries.Reviewed, stdout, stderr)
}

func run(args []string, table []changelogentries.Target, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "propose-rows" {
		return proposeRows(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "rows-check" {
		return rowsCheck(args[1:], table, stdout, stderr)
	}
	if len(args) == 0 || args[0] != "entries" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	out, err := entries(args[1:], table)
	if err != nil {
		fmt.Fprintf(stderr, "changelog entries: %v\n", err)
		return 2
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "changelog entries: %v\n", err)
		return 2
	}
	return 0
}

// once is a string flag that refuses a second occurrence.
type once struct {
	v   *string
	set bool
}

func (o *once) String() string { return "" }
func (o *once) Set(s string) error {
	if o.set {
		return errors.New("flag given more than once")
	}
	o.set, *o.v = true, s
	return nil
}

type source interface {
	extract.PinnedReader
	extract.TagSource
}

func openSource(mirror, fixture string) (source, error) {
	if (mirror == "") == (fixture == "") {
		return nil, errors.New("give exactly one of --mirror-state and --fixture")
	}
	if mirror != "" {
		r, err := factorymirror.OpenReader(mirror)
		if err != nil {
			return nil, fmt.Errorf("open mirror: %w", err)
		}
		return extract.MirrorReader{R: r}, nil
	}
	return extract.FixtureReader{Root: fixture}, nil
}

// proposeRows prints the best closed candidate row for a component as
// targets.json JSON with its per-tag hit table, or NO-ROW with a typed reason.
// Read-only. 0 row printed, 1 NO-ROW, 2 input rejected.
func proposeRows(args []string, stdout, stderr io.Writer) int {
	var component, repo, tags, mirror, fixture string
	f := flag.NewFlagSet("changelog propose-rows", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	for name, v := range map[string]*string{"component": &component, "repo": &repo, "tags": &tags, "mirror-state": &mirror, "fixture": &fixture} {
		f.Var(&once{v: v}, name, "")
	}
	refuse := func(err error) int {
		fmt.Fprintf(stderr, "changelog propose-rows: %v\n", err)
		return 2
	}
	if err := f.Parse(args); err != nil {
		return refuse(fmt.Errorf("%v\n%s", err, usage))
	}
	if f.NArg() != 0 {
		return refuse(fmt.Errorf("unexpected argument %q\n%s", f.Arg(0), usage))
	}
	if component == "" || repo == "" {
		return refuse(fmt.Errorf("--component and --repo are required\n%s", usage))
	}
	var only []string
	if tags != "" {
		only = strings.Split(tags, ",")
	}
	src, err := openSource(mirror, fixture)
	if err != nil {
		return refuse(err)
	}
	p, err := changelogentries.ProposeRow(src, component, repo, only)
	var nr *changelogentries.NoRow
	if errors.As(err, &nr) {
		fmt.Fprintln(stdout, nr.Error())
		return 1
	}
	if err != nil {
		return refuse(err)
	}
	out, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return refuse(err)
	}
	fmt.Fprintf(stdout, "%s\n", out)
	return 0
}

// rowsCheck runs every reviewed row (or one) over all final tags of its
// repository and prints one line per row. Read-only; 0 only when no row failed.
func rowsCheck(args []string, table []changelogentries.Target, stdout, stderr io.Writer) int {
	var component, mirror, fixture, minArg string
	f := flag.NewFlagSet("changelog rows-check", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	for name, v := range map[string]*string{"component": &component, "mirror-state": &mirror, "fixture": &fixture, "min-located-newest": &minArg} {
		f.Var(&once{v: v}, name, "")
	}
	if err := f.Parse(args); err != nil {
		fmt.Fprintf(stderr, "changelog rows-check: %v\n%s\n", err, usage)
		return 2
	}
	if f.NArg() != 0 {
		fmt.Fprintf(stderr, "changelog rows-check: unexpected argument %q\n%s\n", f.Arg(0), usage)
		return 2
	}
	minLocated := changelogentries.DefaultMinLocatedNewest
	if minArg != "" {
		n, err := strconv.Atoi(minArg)
		if err != nil || n < 1 {
			fmt.Fprintf(stderr, "changelog rows-check: --min-located-newest %q must be an integer of at least 1\n", minArg)
			return 2
		}
		minLocated = n
	}
	src, err := openSource(mirror, fixture)
	if err != nil {
		fmt.Fprintf(stderr, "changelog rows-check: %v\n", err)
		return 2
	}
	digest, err := changelogentries.CodeDigest()
	if err != nil {
		fmt.Fprintf(stderr, "changelog rows-check: %v\n", err)
		return 2
	}
	results, err := changelogentries.CheckRowsMin(src, table, component, digest, minLocated)
	if err != nil {
		fmt.Fprintf(stderr, "changelog rows-check: %v\n", err)
		return 2
	}
	var out bytes.Buffer
	failed := 0
	for _, r := range results {
		fmt.Fprintf(&out, "%s %s form=%s tags=%d located=%d withheld=%d notFinal=%d newest=%d/%d", r.Status, r.Component, r.Form, r.Tags, r.Located, r.WithheldTotal(), r.NotFinal, r.WindowLocated, r.Window)
		for _, c := range r.SortedCodes() {
			fmt.Fprintf(&out, " %s=%d", c, r.Withheld[c])
		}
		out.WriteByte('\n')
		for _, why := range r.Reasons {
			fmt.Fprintf(&out, "  - %s\n", why)
		}
		if r.Status == changelogentries.RowFail {
			failed++
		}
	}
	fmt.Fprintf(&out, "rows=%d failed=%d minLocatedNewest=%d tagsDigest=%s", len(results), failed, minLocated, tagSetDigest(src, table, component))
	if md := mirrorDigest(src); md != "" {
		fmt.Fprintf(&out, " mirrorDigest=%s", md)
	}
	out.WriteByte('\n')
	if _, err := stdout.Write(out.Bytes()); err != nil {
		fmt.Fprintf(stderr, "changelog rows-check: %v\n", err)
		return 2
	}
	if failed > 0 {
		return 1
	}
	return 0
}

// tagSetDigest is the sha256 of the sorted, newline-joined tag names of the
// repositories the checked rows read (deduplicated), so the receipt is bound
// to the tag set it ran on. An unreadable tag list gives "unreadable".
func tagSetDigest(src source, table []changelogentries.Target, component string) string {
	var names []string
	for _, t := range table {
		if component != "" && t.Component != component {
			continue
		}
		switch t.Form {
		case changelogentries.FormFile, changelogentries.FormPerLineFile, changelogentries.FormPerVersionFile:
		default:
			continue
		}
		tags, err := src.Tags(t.Repo)
		if err != nil {
			return "unreadable"
		}
		for _, tg := range tags {
			names = append(names, t.Repo.Key+"@"+tg.Name)
		}
	}
	sort.Strings(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return hex.EncodeToString(sum[:])
}

// mirrorDigest is the mirror state index digest, "" for a fixture.
func mirrorDigest(src source) string {
	if m, ok := src.(extract.MirrorReader); ok {
		_, d := m.R.IndexInfo()
		return d
	}
	return ""
}

func entries(args []string, table []changelogentries.Target) ([]byte, error) {
	var component, repo, path, form, tag, mirror, fixture string
	f := flag.NewFlagSet("changelog entries", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	for name, v := range map[string]*string{
		"component": &component, "repo": &repo, "path": &path, "form": &form,
		"tag": &tag, "mirror-state": &mirror, "fixture": &fixture,
	} {
		f.Var(&once{v: v}, name, "")
	}
	if err := f.Parse(args); err != nil {
		return nil, fmt.Errorf("%v\n%s", err, usage)
	}
	if f.NArg() != 0 {
		return nil, fmt.Errorf("unexpected argument %q\n%s", f.Arg(0), usage)
	}
	if component == "" || repo == "" || path == "" || form == "" || tag == "" {
		return nil, fmt.Errorf("--component, --repo, --path, --form and --tag are all required\n%s", usage)
	}
	if (mirror == "") == (fixture == "") {
		return nil, errors.New("give exactly one of --mirror-state and --fixture")
	}
	// The reviewed row decides where the file is and how its headings read.
	// The flags only have to agree with it; a disagreement is refused, never
	// resolved in favour of the flag.
	t, err := changelogentries.Lookup(table, component)
	if err != nil {
		return nil, err
	}
	if repo != t.Repo.Key || path != t.Path || form != t.Form {
		return nil, fmt.Errorf("--repo, --path and --form do not match the reviewed target of %q", component)
	}
	src, err := openSource(mirror, fixture)
	if err != nil {
		return nil, err
	}
	tags, err := src.Tags(t.Repo)
	if err != nil {
		return nil, err
	}
	var pinned *extract.Tag
	for i := range tags {
		if tags[i].Name == tag {
			if pinned != nil {
				return nil, fmt.Errorf("tag %q is recorded twice", tag)
			}
			pinned = &tags[i]
		}
	}
	if pinned == nil {
		return nil, fmt.Errorf("tag %q is not recorded for %s", tag, t.Repo.Key)
	}
	digest, err := changelogentries.CodeDigest()
	if err != nil {
		return nil, err
	}
	m, err := changelogentries.BuildManifest(src, t, *pinned, digest)
	if err != nil {
		return nil, err
	}
	return m.Bytes()
}
