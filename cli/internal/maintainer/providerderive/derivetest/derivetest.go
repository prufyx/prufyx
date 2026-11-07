// SPDX-License-Identifier: AGPL-3.0-only

// Package derivetest holds helpers shared by the extractor tests.
package derivetest

import (
	"encoding/json"
	"os"
	"testing"

	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
)

// Excerpts composes one valid excerpt per body.
func Excerpts(t testing.TB, provider, id, url, anchor string, page []byte, bodies []string) []pd.Excerpt {
	t.Helper()
	var out []pd.Excerpt
	for i, b := range bodies {
		e, data, err := pd.Compose(pd.Spec{
			ID: id + "-" + string(rune('a'+i)), Provider: provider, SourceURL: url, FetchedAt: "2026-11-07T09:47:40Z",
			Anchor: anchor, Sentence: "s-" + string(rune('a'+i)), PageSHA256: pd.PageDigest(page),
		}, b)
		if err != nil {
			t.Fatalf("compose: %v", err)
		}
		out = append(out, pd.Excerpt{Entry: e, Data: data})
	}
	return out
}

// Golden compares v (as indented JSON) with the testdata file; with
// UPDATE_GOLDEN=1 it rewrites the file instead.
func Golden(t testing.TB, path string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Fatalf("golden mismatch for %s:\n%s", path, got)
	}
}
