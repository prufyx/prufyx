// SPDX-License-Identifier: AGPL-3.0-only

package chartversions

import (
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

//go:embed *.go
var sourceFiles embed.FS

// CodeDigest is the digest of this derivation's own code and the extraction
// framework it reads through.
func CodeDigest() (string, error) {
	files, err := extract.CodeFiles(extract.FrameworkSource(), extract.SourceSet{Dir: "maintainer/chartversions", Files: sourceFiles})
	if err != nil {
		return "", err
	}
	return extract.CodeDigest(files), nil
}

const usage = "usage: prufyx-maintainer chart-versions <derive|verify> --mirror DIR --mapping FILE --out FILE [--derived-at RFC3339] [--valid-days N] [--report FILE]"

// Main runs the chart-versions subcommands and returns the exit code.
// derive writes the table; verify re-derives it and compares byte for byte.
func Main(args []string, now func() time.Time, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "derive" && args[0] != "verify") {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	verify := args[0] == "verify"
	fs := flag.NewFlagSet("chart-versions "+args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	mirror := fs.String("mirror", "", "factory mirror state directory")
	mapping := fs.String("mapping", "", "chart mapping file")
	out := fs.String("out", "", "app-version table file")
	derivedAt := fs.String("derived-at", "", "derivation time (RFC 3339 UTC); default now")
	validDays := fs.Int("valid-days", 90, "days a derived record stays usable")
	reportPath := fs.String("report", "", "write the derive report (withheld tags) to this file")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || *mirror == "" || *mapping == "" || *out == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if *validDays < 1 || *validDays > 365 {
		fmt.Fprintln(stderr, "chart-versions: --valid-days must be between 1 and 365")
		return 2
	}
	m, err := LoadMapping(*mapping)
	if err != nil {
		fmt.Fprintf(stderr, "chart-versions: %v\n", err)
		return 2
	}
	digest, err := CodeDigest()
	if err != nil {
		fmt.Fprintf(stderr, "chart-versions: %v\n", err)
		return 2
	}
	opt := Options{Extractor: chartidentity.Extractor{ID: ExtractorID, Version: ExtractorVersion, CodeDigest: digest}}
	var existing []byte
	if verify {
		if existing, err = os.ReadFile(*out); err != nil {
			fmt.Fprintf(stderr, "chart-versions: %v\n", err)
			return 2
		}
		old, err := chartidentity.ParseAppVersions(existing)
		if err != nil {
			fmt.Fprintf(stderr, "chart-versions: verify: existing table is invalid: %v\n", err)
			return 1
		}
		opt.DerivedAt, opt.ValidUntil = time.Now(), time.Now()
		if len(old.Records) > 0 {
			ev := old.Records[0].Evidence
			opt.DerivedAt, _ = time.Parse("2006-01-02T15:04:05Z", ev.DerivedAt)
			opt.ValidUntil, _ = time.Parse("2006-01-02T15:04:05Z", ev.ValidUntil)
		}
	} else {
		opt.DerivedAt = now().UTC().Truncate(time.Second)
		if *derivedAt != "" {
			t, err := time.Parse("2006-01-02T15:04:05Z", *derivedAt)
			if err != nil {
				fmt.Fprintln(stderr, "chart-versions: --derived-at must be UTC like 2030-01-02T03:04:05Z")
				return 2
			}
			opt.DerivedAt = t
		}
		opt.ValidUntil = opt.DerivedAt.AddDate(0, 0, *validDays)
	}
	reader, err := factorymirror.OpenReader(*mirror)
	if err != nil {
		fmt.Fprintf(stderr, "chart-versions: open mirror: %v\n", err)
		return 2
	}
	table, report, err := Derive(extract.MirrorReader{R: reader}, m, opt)
	if err != nil {
		fmt.Fprintf(stderr, "chart-versions: %v\n", err)
		return 1
	}
	raw, err := table.Marshal()
	if err != nil {
		fmt.Fprintf(stderr, "chart-versions: %v\n", err)
		return 1
	}
	if *reportPath != "" {
		rb, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(*reportPath, append(rb, '\n'), 0o644)
		}
		if err != nil {
			fmt.Fprintf(stderr, "chart-versions: report: %v\n", err)
			return 2
		}
	}
	withheld := 0
	for _, e := range report.Entries {
		withheld += len(e.Withheld)
		for _, w := range e.Withheld {
			fmt.Fprintf(stdout, "withheld %s %s: %s\n", e.Chart, w.Tag, w.Reason)
		}
	}
	if verify {
		if !bytes.Equal(raw, existing) {
			fmt.Fprintf(stderr, "chart-versions: %s differs from the table re-derived from the mirror\n", *out)
			return 1
		}
		fmt.Fprintf(stdout, "verified %d records (%d withheld tags)\n", len(table.Records), withheld)
		return 0
	}
	if err := os.WriteFile(*out, raw, 0o644); err != nil {
		fmt.Fprintf(stderr, "chart-versions: %v\n", err)
		return 2
	}
	fmt.Fprintf(stdout, "derived %d records (%d withheld tags) -> %s\n", len(table.Records), withheld, *out)
	return 0
}
