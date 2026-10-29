// SPDX-License-Identifier: AGPL-3.0-only

// Package releasefreshness is the release gate that refuses a tag whose
// embedded knowledge would expire too soon after the release. It reads the
// end dates of the active evidence the binary carries (rules, project rules,
// line attestations, served-API lists, path policies, image and chart
// identity) through the same code the binary uses at run time, and compares the earliest one with the tagged
// commit's date plus a minimum number of days.
package releasefreshness

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/imageidentity"
	"github.com/prufyx/prufyx/cli/internal/knowledgeage"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

// DefaultMinDays is how long after the tagged commit the earliest embedded
// evidence must still be valid.
const DefaultMinDays = 30

// Earliest is the earliest end date over all sources. It fails when no source
// holds an active rule: a binary with no valid evidence is never fresh.
func Earliest(sources []knowledgeage.Source) (time.Time, error) {
	var earliest time.Time
	for _, source := range sources {
		for _, end := range source.Expiries {
			if earliest.IsZero() || end.Before(earliest) {
				earliest = end
			}
		}
	}
	if earliest.IsZero() {
		return time.Time{}, errors.New("no active embedded evidence found")
	}
	return earliest.UTC(), nil
}

// Check accepts earliest when it is at or after commit plus minDays.
func Check(earliest, commit time.Time, minDays int) error {
	need := commit.UTC().AddDate(0, 0, minDays)
	if earliest.UTC().Before(need) {
		return fmt.Errorf("earliest embedded evidence expiry %s is before the tagged commit date plus %d days (%s)",
			earliest.UTC().Format(time.RFC3339), minDays, need.Format(time.RFC3339))
	}
	return nil
}

func embedded() ([]knowledgeage.Source, error) {
	cncf, err := cncfcheck.EmbeddedEvidenceAge()
	if err != nil {
		return nil, err
	}
	projects, err := projectcheck.EmbeddedKnowledgeAge()
	if err != nil {
		return nil, err
	}
	images, err := imageSource()
	if err != nil {
		return nil, err
	}
	charts, err := chartSource()
	if err != nil {
		return nil, err
	}
	return knowledgeage.Merge(cncf, projects, images, charts), nil
}

func parseEnd(value string) (time.Time, error) {
	end, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("embedded evidence date %q is not RFC 3339", value)
	}
	return end.UTC(), nil
}

// imageSource is the end dates of the active embedded image identity records
// (an expired record answers UNKNOWN at run time).
func imageSource() ([]knowledgeage.Source, error) {
	table, err := imageidentity.Load()
	if err != nil {
		return nil, err
	}
	var ends []time.Time
	for _, r := range table.Records {
		if r.Evidence.State != imageidentity.StateActive {
			continue
		}
		end, err := parseEnd(r.Evidence.ValidUntil)
		if err != nil {
			return nil, err
		}
		ends = append(ends, end)
	}
	return []knowledgeage.Source{{ID: "embedded-image-identity", Expiries: ends}}, nil
}

// chartSource is the end dates of the active embedded chart source records
// and of the embedded chart app-version records.
func chartSource() ([]knowledgeage.Source, error) {
	sources, appVersions, err := chartidentity.LoadEmbedded()
	if err != nil {
		return nil, err
	}
	var ends []time.Time
	for _, r := range sources.Records {
		if r.Evidence.State != chartidentity.StateActive {
			continue
		}
		end, err := parseEnd(r.Evidence.ValidUntil)
		if err != nil {
			return nil, err
		}
		ends = append(ends, end)
	}
	for _, r := range appVersions.Records {
		end, err := parseEnd(r.Evidence.ValidUntil)
		if err != nil {
			return nil, err
		}
		ends = append(ends, end)
	}
	return []knowledgeage.Source{{ID: "embedded-chart-identity", Expiries: ends}}, nil
}

// Run prints the earliest embedded evidence expiry (RFC 3339, UTC) on stdout.
// With --commit-date it also fails when that expiry is earlier than the
// commit date plus --min-days.
func Run(args []string, stdout, _ io.Writer) error {
	flags := flag.NewFlagSet("release-freshness", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	commitDate := flags.String("commit-date", "", "tagged commit date, RFC 3339")
	minDays := flags.Int("min-days", DefaultMinDays, "minimum days of validity after the commit date (at least 1)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *minDays < 1 {
		return errors.New("usage: release-freshness [--commit-date RFC3339] [--min-days N]")
	}
	sources, err := embedded()
	if err != nil {
		return fmt.Errorf("read embedded knowledge: %w", err)
	}
	earliest, err := Earliest(sources)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, earliest.Format(time.RFC3339))
	if *commitDate == "" {
		return nil
	}
	commit, err := time.Parse(time.RFC3339, *commitDate)
	if err != nil {
		return errors.New("--commit-date is not RFC 3339")
	}
	return Check(earliest, commit, *minDays)
}
