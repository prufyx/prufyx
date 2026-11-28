// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/maintainer/changelogrenew"
)

const changelogRenewalUsage = "usage: prufyx-maintainer changelog-renewal --extractor changelog.listed.<project> --pack FILE --run DIR --second-run DIR --derived-at RFC3339 --lease-days N [--max N]"

// runChangelogRenewal renews the due changelog.listed_entries records of one
// extractor from two byte-identical runs. The pack file is rewritten only when
// every check passes.
func runChangelogRenewal(args []string, stdout io.Writer, now func() time.Time) error {
	reject := func(err error) error {
		return &commandError{code: 2, message: "changelog-renewal: " + err.Error(), err: err}
	}
	var opts changelogrenew.Options
	var pack string
	f := flag.NewFlagSet("changelog-renewal", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&opts.Extractor, "extractor", "", "")
	f.StringVar(&pack, "pack", "", "")
	f.StringVar(&opts.RunDir, "run", "", "")
	f.StringVar(&opts.SecondRunDir, "second-run", "", "")
	f.StringVar(&opts.DerivedAt, "derived-at", "", "")
	f.IntVar(&opts.LeaseDays, "lease-days", 0, "")
	f.IntVar(&opts.Max, "max", changelogrenew.MaxRecords, "")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || opts.Extractor == "" || pack == "" || opts.RunDir == "" || opts.SecondRunDir == "" || opts.DerivedAt == "" {
		return reject(errors.New("command rejected\n" + changelogRenewalUsage))
	}
	spec, ok := extractcli.Catalog()[opts.Extractor]
	if !ok {
		return reject(fmt.Errorf("unknown extractor %q", opts.Extractor))
	}
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		return reject(err)
	}
	if opts.Current, err = changelogrenew.Current(spec.New(1)); err != nil {
		return reject(err)
	}
	info, err := os.Lstat(pack)
	if err != nil || !info.Mode().IsRegular() {
		return reject(fmt.Errorf("%s is not a regular file", pack))
	}
	if opts.Pack, err = os.ReadFile(pack); err != nil {
		return reject(err)
	}
	opts.Repo, opts.Now = repo, now()
	res, err := changelogrenew.Assemble(opts)
	if err != nil {
		return reject(err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(pack), ".changelog-renewal-*")
	if err != nil {
		return reject(err)
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(res.Pack)
	if err = errors.Join(err, tmp.Chmod(info.Mode().Perm()), tmp.Close()); err != nil {
		return reject(err)
	}
	if err := os.Rename(tmp.Name(), pack); err != nil {
		return reject(err)
	}
	for _, group := range []struct {
		name string
		keys []string
	}{{"renewed", res.Renewed}, {"list changed, not renewed", res.ListChanged}, {"not derived, not renewed", res.NotDerived}, {"over the cap, not renewed", res.Deferred}} {
		for _, key := range group.keys {
			fmt.Fprintf(stdout, "%s: %s\n", group.name, key)
		}
	}
	fmt.Fprintf(stdout, "renewed %d, list changed %d, not derived %d, deferred %d, new records left out %d\n",
		len(res.Renewed), len(res.ListChanged), len(res.NotDerived), len(res.Deferred), res.LeftOut)
	// For the commit message and the change description: it records the origin
	// and authenticates nothing.
	fmt.Fprintf(stdout, "Origin-Derived-At: %s\nOrigin-Records: %d %s\nOrigin-Extractor: %s version=%s codeDigest=%s leaseDays=%d output=%s\n",
		opts.DerivedAt, len(res.Renewed), res.RecordsDigest, res.Build.ID, res.Build.Version, res.Build.CodeDigest, opts.LeaseDays, res.OutputDigest)
	for _, p := range res.Previous {
		fmt.Fprintf(stdout, "Origin-Previous-Extractor: %s version=%s codeDigest=%s records=%d\n",
			p.Build.ID, p.Build.Version, p.Build.CodeDigest, p.Records)
	}
	return nil
}
