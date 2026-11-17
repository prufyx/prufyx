// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestReviewedRow_csidriversmb(t *testing.T) {
	row, err := Lookup(Reviewed, "csi-driver-smb")
	if err != nil {
		t.Fatal(err)
	}
	if row.Repo.Key != "github.com/kubernetes-csi/csi-driver-smb" || row.Form != FormGithubRelease || row.Path != "" || row.HeadingPattern != "" {
		t.Fatalf("unexpected row: %+v", row)
	}
	r := &memReader{err: errReadBoom}
	m, err := BuildManifest(r, row, extract.Tag{Name: "v1.17.0", Commit: testCommit}, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil || m.Withheld == nil || m.Entry != nil || m.Withheld.Code != SourceNotPinnedGit {
		t.Fatalf("want withheld SourceNotPinnedGit: %v %+v", err, m)
	}
	if r.reads != 0 {
		t.Fatalf("a non-file row read %d times", r.reads)
	}
}
