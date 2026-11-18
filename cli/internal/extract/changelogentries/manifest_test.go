// SPDX-License-Identifier: AGPL-3.0-only

package changelogentries

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func TestManifestMustHoldExactlyOne(t *testing.T) {
	if _, err := (Manifest{}).Bytes(); err == nil {
		t.Fatal("an empty manifest was rendered")
	}
	both := Manifest{Entry: &Entry{}, Withheld: &Withheld{}}
	if _, err := both.Bytes(); err == nil {
		t.Fatal("a manifest with an entry and a reason was rendered")
	}
}

func TestBuildManifestEntryWithheldAndReadFailure(t *testing.T) {
	d := "sha256:" + strings.Repeat("0", 64)
	tag := extract.Tag{Name: "v3.5.0", Commit: testCommit}
	file := "## 3.5.0 / 2025-07-14\n\n* [FEATURE] x. #1\n"
	r := &memReader{files: map[string][]byte{promTarget.Repo.Key + "@" + testCommit + ":" + promTarget.Path: []byte(file)}}
	m, err := BuildManifest(r, promTarget, tag, d)
	if err != nil || m.Entry == nil || m.Withheld != nil || m.Extractor.CodeDigest != d || m.Extractor.Version != "changelog.entries/4" {
		t.Fatalf("entry: %v %+v", err, m)
	}
	a, _ := m.Bytes()
	m2, _ := BuildManifest(r, promTarget, tag, d)
	b, _ := m2.Bytes()
	if !bytes.Equal(a, b) {
		t.Fatal("not deterministic")
	}
	m, err = BuildManifest(r, promTarget, extract.Tag{Name: "v3.4.0", Commit: testCommit}, d)
	if err != nil || m.Withheld == nil || m.Withheld.Code != EntryMissing {
		t.Fatalf("withheld: %v %+v", err, m)
	}
	// A read failure is an error and never a reason.
	if _, err := BuildManifest(&memReader{err: errReadBoom}, promTarget, tag, d); err == nil {
		t.Fatal("a read failure became a manifest")
	}
}

func TestLookupNeedsExactlyOneRow(t *testing.T) {
	if _, err := Lookup(nil, "prometheus"); err == nil {
		t.Fatal("empty table")
	}
	if _, err := Lookup([]Target{promTarget, promTarget}, "prometheus"); err == nil {
		t.Fatal("two rows")
	}
	if got, err := Lookup([]Target{cortexTarget, promTarget}, "prometheus"); err != nil || got.Component != "prometheus" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestCodeDigestCoversThisPackageAndTheFramework(t *testing.T) {
	d, err := CodeDigest()
	if err != nil || !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		t.Fatalf("%q %v", d, err)
	}
	dir, files := SourceFiles()
	cf, err := extract.CodeFiles(extract.SourceSet{Dir: dir, Files: files}, extract.FrameworkSource())
	if err != nil {
		t.Fatal(err)
	}
	var own, fw bool
	for _, f := range cf {
		own = own || f.Path == SourceDir+"/manifest.go"
		fw = fw || strings.HasPrefix(f.Path, extract.FrameworkDir+"/")
	}
	if !own || !fw {
		t.Fatalf("digest misses its own source (%v) or the framework (%v)", own, fw)
	}
}

var errReadBoom = errors.New("boom")
