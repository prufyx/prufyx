// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"context"
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/chartrun"
)

// Derivation is one run of a registered extractor, under the framework it
// belongs to: chartrun for a chart extractor (chartrun.Register), extract
// for any other.
type Derivation struct {
	Manifest extract.Manifest
	// Entries are the derived pack entries by rule id, as JSON.
	Entries map[string][]byte
	// Output is the extract framework's output; nil for a chart extractor.
	Output *extract.Output
	files  func() (map[string][]byte, error)
}

// Files renders the run's output files, as extract.Output.Files does.
func (d *Derivation) Files() (map[string][]byte, error) { return d.files() }

// Derive runs ex: chartrun.Run for a chart extractor, extract.Run for any
// other.
func Derive(ctx context.Context, ex extract.Extractor, tags extract.TagSource, reader extract.PinnedReader, opts extract.Options) (*Derivation, error) {
	entries := map[string][]byte{}
	if cx, ok := chartrun.Unwrap(ex); ok {
		out, err := chartrun.Run(ctx, cx, tags, reader, opts)
		if err != nil {
			return nil, err
		}
		for _, e := range out.Entries {
			raw, err := json.Marshal(e)
			if err != nil {
				return nil, err
			}
			entries[e.Rule.ID] = raw
		}
		return &Derivation{Manifest: out.Manifest, Entries: entries, files: out.Files}, nil
	}
	out, err := extract.Run(ctx, ex, tags, reader, opts)
	if err != nil {
		return nil, err
	}
	for _, e := range out.Entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		entries[e.Rule.ID] = raw
	}
	return &Derivation{Manifest: out.Manifest, Entries: entries, Output: out, files: out.Files}, nil
}

// VerifyRun re-derives the run recorded in dir: chartrun.Verify for a chart
// extractor, extract.Verify for any other.
func VerifyRun(ctx context.Context, ex extract.Extractor, tags extract.TagSource, reader extract.PinnedReader, dir string, existing []string) ([]string, error) {
	if cx, ok := chartrun.Unwrap(ex); ok {
		return chartrun.Verify(ctx, cx, tags, reader, dir, existing)
	}
	return extract.Verify(ctx, ex, tags, reader, dir, existing)
}
