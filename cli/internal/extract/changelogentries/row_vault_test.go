// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestReviewedRow_vault(t *testing.T) {
	row, err := Lookup(Reviewed, "vault")
	if err != nil {
		t.Fatal(err)
	}
	if row.Repo.Key != "github.com/hashicorp/vault" || row.Form != FormPostTag || row.Path != "" || row.HeadingPattern != "" {
		t.Fatalf("unexpected row: %+v", row)
	}
	r := &memReader{err: errReadBoom}
	m, err := BuildManifest(r, row, extract.Tag{Name: "v1.18.0", Commit: testCommit}, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil || m.Withheld == nil || m.Entry != nil || m.Withheld.Code != EntryNotAtTag {
		t.Fatalf("want withheld EntryNotAtTag: %v %+v", err, m)
	}
	if r.reads != 0 {
		t.Fatalf("a non-file row read %d times", r.reads)
	}
}
