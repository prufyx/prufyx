// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

func projectsFixture(t *testing.T) Options {
	t.Helper()
	o := fixture(t)
	o.Profile = ProfileCNCFProjects
	o.FirstRelease = true
	o.PackageURL = ""
	return o
}

func TestProjectsReleaseSignsEveryTargetAndProducesTheNextIndex(t *testing.T) {
	o := projectsFixture(t)
	result, err := Run(o)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.Profile != ProfileCNCFProjects || result.Receipt.Status != "VERIFIED_FOR_PACKAGING" || result.Receipt.KnowledgeRevision != o.Revision || len(result.Receipt.Verification.ProjectTargets) < 2 {
		t.Fatalf("unexpected result %+v", result)
	}
	for _, name := range result.Files {
		if strings.Contains(name, "release-plan") {
			t.Fatalf("a per-project release wrote a release plan: %s", name)
		}
	}
	indexRaw, err := os.ReadFile(filepath.Join(o.OutputDir, "knowledge", "cncf", "index.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalIndex(indexRaw); err != nil {
		t.Fatalf("written index does not parse: %v", err)
	}
	if _, err := knowledge.VerifyConstraintsProjects(knowledge.VerifyRequest{
		PackagePath: filepath.Join(o.OutputDir, "cncf-projects-"+o.Revision+".tar"), BootstrapRootPath: o.Root, BootstrapRootDigest: o.RootDigest,
		ExpectedRevision: o.Revision, ExpectedBundleDigest: result.Receipt.TargetDigest,
	}); err != nil {
		t.Fatalf("the signed package does not verify: %v", err)
	}
	// The same keys and inputs reproduce every file.
	again := o
	again.OutputDir = filepath.Join(filepath.Dir(o.OutputDir), "out2")
	if _, err := Run(again); err != nil {
		t.Fatal(err)
	}
	for _, name := range result.Files {
		x, _ := os.ReadFile(filepath.Join(o.OutputDir, filepath.FromSlash(name)))
		y, _ := os.ReadFile(filepath.Join(again.OutputDir, filepath.FromSlash(name)))
		if len(x) == 0 || !bytes.Equal(x, y) {
			t.Fatalf("%s not reproducible", name)
		}
	}

	// The next release is built from the index the first one produced: the
	// unchanged projects keep their revision and the revision must advance.
	next := o
	next.FirstRelease = false
	next.PreviousIndex = filepath.Join(o.OutputDir, "knowledge", "cncf", "index.v1.json")
	next.Revision, next.Version = "92", 2
	next.OutputDir = filepath.Join(filepath.Dir(o.OutputDir), "out3")
	if _, err := Run(next); err != nil {
		t.Fatal(err)
	}
	nextIndex, err := os.ReadFile(filepath.Join(next.OutputDir, "knowledge", "cncf", "index.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := cncfcheck.ParseExternalIndex(nextIndex)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range parsed.Entries() {
		if entry.Revision != o.Revision {
			t.Fatalf("unchanged project %s moved to revision %s", entry.Project, entry.Revision)
		}
	}
	for name, revision := range map[string]string{"equal": o.Revision, "lower": "90"} {
		t.Run("revision "+name, func(t *testing.T) {
			stale := next
			stale.Revision = revision
			stale.OutputDir = filepath.Join(filepath.Dir(o.OutputDir), "stale-"+name)
			if _, err := Run(stale); err == nil {
				t.Fatal("a revision that does not advance the previous index was released")
			}
			if _, err := os.Stat(stale.OutputDir); err == nil {
				t.Fatal("output written for a refused release")
			}
		})
	}
}

func TestProjectsReleaseRejections(t *testing.T) {
	cases := map[string]func(*Options){
		"neither previous index nor first release": func(o *Options) { o.FirstRelease = false },
		"both previous index and first release":    func(o *Options) { o.PreviousIndex = filepath.Join(filepath.Dir(o.Root), "index.json") },
		"relative previous index":                  func(o *Options) { o.FirstRelease, o.PreviousIndex = false, "index.json" },
		"missing previous index": func(o *Options) {
			o.FirstRelease, o.PreviousIndex = false, filepath.Join(filepath.Dir(o.Root), "absent.json")
		},
		"unknown profile": func(o *Options) { o.Profile = "cncf-all" },
		"previous index on the single profile": func(o *Options) {
			o.Profile, o.FirstRelease, o.PackageURL = ProfileCNCF, true, "https://metadata.example.test/x.tar"
		},
		"expiry beyond rules": func(o *Options) { o.Expires = "2999-01-01T00:00:00Z" },
		"swapped role keys":   func(o *Options) { o.TargetsKey, o.SnapshotKey = o.SnapshotKey, o.TargetsKey },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := projectsFixture(t)
			mutate(&o)
			if _, err := Run(o); err == nil {
				t.Fatal("expected rejection")
			}
			if _, err := os.Stat(o.OutputDir); err == nil && name != "swapped role keys" {
				t.Fatal("output written for a refused release")
			}
		})
	}
}

// A pack holding distribution records cannot be published per project: the
// release is refused, the sentinel survives for the caller's message, and
// nothing is written.
func TestProjectsReleaseRefusesDistributionRecords(t *testing.T) {
	original := buildFirst
	defer func() { buildFirst = original }()
	buildFirst = func(string, map[string]string) (cncfcheck.ExternalTarget, []cncfcheck.ExternalTarget, error) {
		return cncfcheck.ExternalTarget{}, nil, errors.Join(cncfcheck.ErrIntegrity, cncfcheck.ErrDistributionsNotPublishable)
	}
	o := projectsFixture(t)
	_, err := Run(o)
	if !errors.Is(err, cncfcheck.ErrDistributionsNotPublishable) || !errors.Is(err, ErrRejected) {
		t.Fatalf("err=%v", err)
	}
	if _, statErr := os.Stat(o.OutputDir); statErr == nil {
		t.Fatal("output written for a refused release")
	}
}
