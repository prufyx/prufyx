// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import "github.com/prufyx/prufyx/cli/internal/extract"

// reviewedBatch2 holds the rows of the second reviewed batch. They are
// appended to Reviewed when the package initialises, after Reviewed's own
// declaration, so the order is fixed: Reviewed, then this batch. A component
// that appears in both places has two rows and Lookup refuses it.
//
// Every row below was read over every final tag of the last six minor lines
// of its repository (the tag's own file, at the tag's own commit) and located
// with no residue and no withheld code.
var reviewedBatch2 = []Target{
	{
		Component: "blackbox_exporter", Repo: extract.RepoRef{Key: "github.com/prometheus/blackbox_exporter"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   `^(?P<version>[0-9]+\.[0-9]+\.[0-9]+) / [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
		BoundaryPatterns: []string{`^master / unreleased$`},
	},
	{
		Component: "openfga", Repo: extract.RepoRef{Key: "github.com/openfga/openfga"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   `^\[(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$`,
		BoundaryPatterns: []string{`^\[Unreleased\]$`},
	},
	{
		Component: "in-toto", Repo: extract.RepoRef{Key: "github.com/in-toto/in-toto"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern: `^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)$`,
	},
	{
		Component: "fluentd", Repo: extract.RepoRef{Key: "github.com/fluent/fluentd"},
		Form: FormFile, Path: "CHANGELOG.md",
		HeadingPattern:   `^Release v(?P<version>[0-9]+\.[0-9]+\.[0-9]+) - [0-9]{4}/[0-9]{2}/[0-9]{2}$`,
		BoundaryPatterns: []string{`^v[0-9]+\.[0-9]+$`},
	},
}

func init() { Reviewed = append(Reviewed, reviewedBatch2...) }
