// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// A refused command prints nothing and leaves the pack as it was.
func TestChangelogRenewalCommandRefuses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pack := filepath.Join(dir, "rules.json")
	content := []byte("{\n  \"entries\": []\n}\n")
	if err := os.WriteFile(pack, content, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(pack, link); err != nil {
		t.Fatal(err)
	}
	a, b := t.TempDir(), t.TempDir()
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Second).Format(time.RFC3339)
	full := []string{"changelog-renewal", "--extractor", "changelog.listed.prometheus", "--pack", pack, "--run", a, "--second-run", b, "--derived-at", at, "--lease-days", "80"}
	with := func(flag, value string) []string {
		out := slices.Clone(full)
		out[slices.Index(out, flag)+1] = value
		return out
	}
	rejected := "changelog-renewal: command rejected\n" + changelogRenewalUsage
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no flags":          {full[:1], rejected},
		"no second run":     {with("--second-run", ""), rejected},
		"unknown flag":      {append(slices.Clone(full), "--force"), rejected},
		"argument":          {append(slices.Clone(full), "extra"), rejected},
		"duplicate flag":    {append(slices.Clone(full), "--lease-days", "1"), "prufyx-maintainer: duplicate option rejected"},
		"unknown extractor": {with("--extractor", "changelog.listed.none"), `changelog-renewal: unknown extractor "changelog.listed.none"`},
		"other family": {with("--extractor", "k8s.served-api-removal"),
			"changelog-renewal: changelog-renewal/other-extractor: only a changelog.listed.<project> extractor is renewed here"},
		"pack not a file": {with("--pack", dir), "changelog-renewal: " + dir + " is not a regular file"},
		"pack a symlink":  {with("--pack", link), "changelog-renewal: " + link + " is not a regular file"},
		"long lease":      {with("--lease-days", "91"), "changelog-renewal: changelog-renewal/lease: the lease must be 1-90 days"},
		"future derivation": {with("--derived-at", "2999-01-01T00:00:00Z"),
			"changelog-renewal: changelog-renewal/derivation-time: the derivation time 2999-01-01T00:00:00Z is in the future"},
		"empty runs": {full, "changelog-renewal: changelog-renewal/run: the run has no manifest"},
	} {
		var out bytes.Buffer
		err := run(tc.args, &out, io.Discard)
		if err == nil || err.Error() != tc.want || out.Len() != 0 {
			t.Errorf("%s: error %v, output %q, want %q", name, err, out.String(), tc.want)
		}
		if got, err := os.ReadFile(pack); err != nil || !bytes.Equal(got, content) {
			t.Fatalf("%s: the pack changed", name)
		}
	}
}

// renewalUpstream is a synthetic Prometheus repository with the lines 3.4 and
// 3.5.
type renewalUpstream struct{}

var renewalVersions = []string{"3.3.0", "3.4.0", "3.4.1", "3.5.0", "3.5.1"}

func renewalCommit(version string) string {
	return strings.Repeat("0", 34) + fmt.Sprintf("%06s", strings.ReplaceAll(version, ".", "0"))
}

func (renewalUpstream) Tags(extract.RepoRef) ([]extract.Tag, error) {
	var out []extract.Tag
	for _, v := range renewalVersions {
		out = append(out, extract.Tag{Name: "v" + v, Commit: renewalCommit(v)})
	}
	return out, nil
}

func (renewalUpstream) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, nil
}

func (renewalUpstream) Read(_ extract.RepoRef, commit, path string) ([]byte, error) {
	var b strings.Builder
	b.WriteString("# Changelog\n\n## main / unreleased\n\n")
	on := false
	for i := len(renewalVersions) - 1; i >= 0; i-- {
		v := renewalVersions[i]
		on = on || renewalCommit(v) == commit
		if on {
			fmt.Fprintf(&b, "## %s / 2025-01-01\n\n* [BUGFIX] Fix %s. #1\n\n", v, v)
		}
	}
	if !on || path != "CHANGELOG.md" {
		return nil, extract.ErrNotFound
	}
	return []byte(b.String()), nil
}

// A successful command rewrites the pack in place, keeps its mode, leaves no
// other file behind and prints the records and the origin lines.
func TestChangelogRenewalCommandRenews(t *testing.T) {
	t.Parallel()
	const id = "changelog.listed.prometheus"
	oldAt := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	newAt := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	spec := extractcli.Catalog()[id]
	repo, err := extract.ParseRepo(spec.Repo)
	if err != nil {
		t.Fatal(err)
	}
	derive := func(at time.Time, days int) *extract.Output {
		t.Helper()
		out, err := extract.Run(context.Background(), spec.New(1), renewalUpstream{}, renewalUpstream{},
			extract.Options{Repo: repo, DerivedAt: at, Lease: time.Duration(days) * 24 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	render := func(atts []lineattest.LineAttestation) []byte {
		t.Helper()
		raw, err := lineattest.Marshal(atts)
		if err != nil {
			t.Fatal(err)
		}
		out, err := (&extractpack.Pack{Members: map[string]json.RawMessage{"schema": json.RawMessage(`"synthetic"`), lineattest.PackMember: raw}}).Render()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	digest := func(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }

	// The line 3.5 record is of an older build.
	base := derive(oldAt, 40).Attestations
	if len(base) != 2 {
		t.Fatalf("%d records", len(base))
	}
	older := *base[1].Evidence.Extractor
	older.CodeDigest = digest([]byte("older build"))
	base[1].Evidence.Extractor = &older
	next := derive(newAt, 80)
	files, err := next.Files()
	if err != nil {
		t.Fatal(err)
	}
	dirs := []string{t.TempDir(), t.TempDir()}
	for _, dir := range dirs {
		for name, data := range files {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	var listing strings.Builder
	for _, name := range names {
		fmt.Fprintf(&listing, "%s\x00%s\n", name, digest(files[name]))
	}
	want := slices.Clone(base)
	for i := range want {
		want[i].Evidence = next.Attestations[i].Evidence
	}

	packDir := t.TempDir()
	pack := filepath.Join(packDir, "rules.json")
	if err := os.WriteFile(pack, render(base), 0o600); err != nil {
		t.Fatal(err)
	}
	// A mode no file is created with, whatever the umask.
	if err := os.Chmod(pack, 0o640); err != nil {
		t.Fatal(err)
	}
	args := []string{"--extractor", id, "--pack", pack, "--run", dirs[0], "--second-run", dirs[1], "--derived-at", "2026-12-01T00:00:00Z", "--lease-days", "80"}
	var out bytes.Buffer
	if err := runChangelogRenewal(args, &out, func() time.Time { return newAt.Add(time.Hour) }); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(pack)
	if err != nil || !bytes.Equal(got, render(want)) {
		t.Fatalf("the pack is not the renewed one (%v):\n%s", err, got)
	}
	info, err := os.Lstat(pack)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o640 {
		t.Fatalf("pack mode %v", info.Mode())
	}
	if left, err := os.ReadDir(packDir); err != nil || len(left) != 1 {
		t.Fatalf("files beside the pack: %v %v", left, err)
	}
	keys := []string{base[0].Key().String(), base[1].Key().String()}
	build := next.Manifest.Extractor
	expected := "renewed: " + keys[0] + "\nrenewed: " + keys[1] + "\n" +
		"renewed 2, list changed 0, not derived 0, deferred 0, new records left out 0\n" +
		"Origin-Derived-At: 2026-12-01T00:00:00Z\n" +
		"Origin-Records: 2 " + digest([]byte(keys[0]+"\n"+keys[1]+"\n")) + "\n" +
		"Origin-Extractor: " + id + " version=" + build.Version + " codeDigest=" + build.CodeDigest + " leaseDays=80 output=" + digest([]byte(listing.String())) + "\n" +
		"Origin-Previous-Extractor: " + id + " version=" + older.Version + " codeDigest=" + older.CodeDigest + " records=1\n"
	if out.String() != expected {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), expected)
	}
}
