// SPDX-License-Identifier: AGPL-3.0-only

// Package changelogcli wires the "changelog" maintainer subcommands. "entries"
// reads one release tag's changelog entry from the offline mirror (or a
// fixture tree) and prints the manifest on standard output. It reads only
// through the pinned reader, never the network, writes no file and decides
// nothing about any item.
package changelogcli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/changelogentries"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

const usage = `usage:
  prufyx-maintainer changelog entries --component NAME --repo github.com/OWNER/NAME --path FILE --form FORM --tag TAG (--mirror-state DIR | --fixture DIR)
exit: 0 manifest printed (entry or typed reason), 2 input rejected or read failed`

// Main runs a "changelog" subcommand (args exclude the word "changelog") with
// the reviewed target table. It returns 0 when a manifest was printed and 2
// for every refusal; on a refusal nothing is written to stdout.
func Main(args []string, stdout, stderr io.Writer) int {
	return run(args, changelogentries.Reviewed, stdout, stderr)
}

func run(args []string, table []changelogentries.Target, stdout, stderr io.Writer) int {
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
	var src source
	if mirror != "" {
		r, err := factorymirror.OpenReader(mirror)
		if err != nil {
			return nil, fmt.Errorf("open mirror: %w", err)
		}
		src = extract.MirrorReader{R: r}
	} else {
		src = extract.FixtureReader{Root: fixture}
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
