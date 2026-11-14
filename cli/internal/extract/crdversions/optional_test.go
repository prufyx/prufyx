// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"errors"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
)

type optionalFaultReader struct {
	extract.PinnedReader
	readPath, listDir string
	readErr, listErr  error
	edit              func(string, []extract.TreeEntry) []extract.TreeEntry
}

func (r optionalFaultReader) Read(repo extract.RepoRef, commit, file string) ([]byte, error) {
	if r.readErr != nil && file == r.readPath {
		return nil, r.readErr
	}
	return r.PinnedReader.Read(repo, commit, file)
}

func (r optionalFaultReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	if r.listErr != nil && dir == r.listDir {
		return nil, r.listErr
	}
	entries, err := r.PinnedReader.List(repo, commit, dir)
	if err == nil && r.edit != nil {
		entries = r.edit(dir, slices.Clone(entries))
	}
	return entries, err
}

func TestOptionalPathTreeProof(t *testing.T) {
	repo, _ := extract.ParseRepo("github.com/argoproj/argo-cd")
	commit := commitOf("optional-tree")
	file := "extra/operator.yml"
	base := memReader{commit + ":" + file: []byte(crd("Beta", "v1"))}
	for _, tc := range []struct {
		name            string
		spec            PathSpec
		reader          optionalFaultReader
		missing, refuse bool
	}{
		{name: "present file", spec: PathSpec{Path: file}},
		{name: "present directory", spec: PathSpec{Path: "extra", Dir: true}},
		{name: "absent ancestor", spec: PathSpec{Path: "missing/operator.yml"}, missing: true},
		{name: "absent leaf", spec: PathSpec{Path: "extra/missing.yml"}, missing: true},
		{name: "absent directory", spec: PathSpec{Path: "extra/missing", Dir: true}, missing: true},
		{name: "unsafe path", spec: PathSpec{Path: "../operator.yml"}, refuse: true},
		{name: "unreadable root", spec: PathSpec{Path: file}, reader: optionalFaultReader{listErr: errors.New("list failed")}, refuse: true},
		{name: "unavailable parent", spec: PathSpec{Path: file}, reader: optionalFaultReader{listDir: "extra", listErr: extract.ErrNotFound}, refuse: true},
		{name: "file as directory", spec: PathSpec{Path: file, Dir: true}, refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.reader
			r.PinnedReader = base
			missing, err := optionalPathMissing(r, repo, commit, tc.spec)
			if (err != nil) != tc.refuse || missing != tc.missing {
				t.Fatalf("missing=%v error=%v", missing, err)
			}
		})
	}
	for _, tc := range []struct {
		name, entry, mode, typ string
	}{
		{"symlink ancestor", "extra", "120000", "blob"},
		{"gitlink ancestor", "extra", "160000", "commit"},
		{"blob ancestor", "extra", "100644", "blob"},
		{"unknown tree mode", "extra", "100644", "tree"},
		{"unknown type", "extra", "040000", "unknown"},
		{"symlink leaf", file, "120000", "blob"},
		{"gitlink leaf", file, "160000", "commit"},
		{"tree leaf", file, "040000", "tree"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := optionalFaultReader{PinnedReader: base, edit: func(_ string, entries []extract.TreeEntry) []extract.TreeEntry {
				for i := range entries {
					if entries[i].Path == tc.entry {
						entries[i].Mode, entries[i].Type = tc.mode, tc.typ
					}
				}
				return entries
			}}
			if missing, err := optionalPathMissing(r, repo, commit, PathSpec{Path: file}); err == nil || missing {
				t.Fatalf("opaque entry accepted: missing=%v error=%v", missing, err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func([]extract.TreeEntry) []extract.TreeEntry
	}{
		{"duplicate", func(e []extract.TreeEntry) []extract.TreeEntry { return append(e, e[0]) }},
		{"malformed path", func(e []extract.TreeEntry) []extract.TreeEntry { e[0].Path = "extra/../extra"; return e }},
		{"non-direct entry", func(e []extract.TreeEntry) []extract.TreeEntry { e[0].Path = file; return e }},
		{"invalid object id", func(e []extract.TreeEntry) []extract.TreeEntry { e[0].SHA = strings.Repeat("g", 40); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := optionalFaultReader{PinnedReader: base, edit: func(_ string, e []extract.TreeEntry) []extract.TreeEntry { return tc.edit(e) }}
			if missing, err := optionalPathMissing(r, repo, commit, PathSpec{Path: "missing.yml"}); err == nil || missing {
				t.Fatalf("malformed listing proved absence: missing=%v error=%v", missing, err)
			}
		})
	}
}

func TestOptionalListedButUnreadableWithholds(t *testing.T) {
	const file = "extra/operator.yml"
	source := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), file: crd("Beta", "v1")}},
	)
	repo, _ := extract.ParseRepo("github.com/argoproj/argo-cd")
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			tg := attestingTarget()
			optional := PathSpec{Path: file, Optional: true}
			if directory {
				optional = PathSpec{Path: "extra", Dir: true, Optional: true, Match: regexp.MustCompile(`\.yml$`)}
			}
			tg.Paths = append(tg.Paths, optional)
			run := func(reader extract.PinnedReader) (*extract.Output, error) {
				x := New(tg).WithIndex(syntheticOwnership(tg, synthGroup))
				return extract.Run(context.Background(), x, ReleaseTags(x, source), reader, extract.Options{Repo: repo, DerivedAt: derivedAt})
			}
			baseline, err := run(source)
			if err != nil || len(baseline.Attestations) != 1 {
				t.Fatalf("valid absent/present baseline: %+v %v", baseline, err)
			}
			reader := optionalFaultReader{PinnedReader: source, readPath: file, readErr: extract.ErrNotFound}
			if directory {
				reader.readErr, reader.listDir, reader.listErr = nil, "extra", extract.ErrNotFound
			}
			out, err := run(reader)
			if err != nil {
				t.Fatal(err)
			}
			pair, _ := pairOf(t, out, "1.0.0", "1.1.0")
			if pair.Status != extract.PairWithheld || len(out.Attestations) != 0 || pair.Attestation == nil || pair.Attestation.Status != extract.PairNotAttested {
				t.Fatalf("listed but unreadable path was attested: %+v", pair)
			}
			if !directory {
				readFailure := errors.New("read failed")
				reader.readErr = readFailure
				if _, err := run(reader); !errors.Is(err, readFailure) {
					t.Fatalf("generic I/O error did not propagate: %v", err)
				}
			}
		})
	}
}

func TestDeclaredFilesRequireReceipts(t *testing.T) {
	tg := synthTarget()
	tg.Paths = append(tg.Paths, PathSpec{Path: "extra/operator.yml", Optional: true})
	x := New(tg)
	inv := &Inventory{Files: []FileRecord{{Path: "deploy/crds/a.yaml"}}, Channels: []ChannelInventory{{Files: []FileRecord{{Path: "channel/real.yml"}}}}}
	got := x.declaredFiles(inv)
	if got["extra/operator.yml"] || !got["deploy/crds/a.yaml"] || !got["channel/real.yml"] {
		t.Fatalf("declared without a successful source receipt: %+v", got)
	}
}

// The reviewed Antrea optional directory is present at all pinned releases.
// Check its new parent-tree proof without repeating the full derivations.
func TestOptionalAntreaPinnedTrees(t *testing.T) {
	root := os.Getenv("ANTREA_MODE_SOURCE_MIRROR")
	if root == "" {
		t.Skip("no offline source mirror supplied")
	}
	mirror, err := factorymirror.OpenReader(root)
	if err != nil {
		t.Fatal(err)
	}
	reader := extract.MirrorReader{R: mirror}
	tg := target(t, "antrea")
	repo, _ := extract.ParseRepo(tg.Repo)
	var commits []string
	for commit := range antreaModePins {
		commits = append(commits, commit)
	}
	sort.Strings(commits)
	if len(commits) != 21 {
		t.Fatalf("reviewed release count: %d", len(commits))
	}
	optional := 0
	for _, spec := range tg.Paths {
		if !spec.Optional {
			continue
		}
		optional++
		for _, commit := range commits {
			if missing, err := optionalPathMissing(reader, repo, commit, spec); err != nil || missing {
				t.Fatalf("pinned optional path %s at %s: missing=%v error=%v", spec.Path, commit, missing, err)
			}
		}
	}
	if optional != 1 {
		t.Fatalf("reviewed optional path count: %d", optional)
	}
}
