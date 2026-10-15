// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/maintainer/corpusattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/docstables"
)

// The onboarding fixture: a synthetic project, served by a local upstream
// fixture, onboarded under the slug of a CNCF landscape project that the
// repository's reviewed table and targets do not hold (picked at test time,
// so onboarding that project later does not move this test). Nothing here is
// a real upstream.
const (
	obGroup  = "storage.synthetic.example"
	obFrom   = "00000000000000000000000000000000000a1000"
	obTo     = "00000000000000000000000000000000000a1100"
	obOwner  = "airstand"
	obLedger = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	obCRD    = "deploy/crds/widgets.yaml"
)

var (
	obSlug, obRepo, obComp, obFact, obTargetJSON = obPick()
	// obOwnerRepo is obRepo without its host.
	obOwnerRepo = strings.TrimPrefix(obRepo, "github.com/")
)

// obPick picks the first CNCF landscape project, by slug, with a GitHub
// repository that the reviewed table and the targets do not hold.
func obPick() (slug, repo, component, fact, target string) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "cli/internal/cncfcheck/data/landscape-projects.json"))
	if err != nil {
		panic(err)
	}
	var landscape struct {
		Projects []struct {
			Slug          string `json:"slug"`
			RepositoryURL string `json:"repositoryURL"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &landscape); err != nil {
		panic(err)
	}
	urlRE := regexp.MustCompile(`^https://github\.com/([a-z0-9-]+/[a-z0-9-]+)$`)
	for _, p := range landscape.Projects {
		m := urlRE.FindStringSubmatch(p.RepositoryURL)
		if m == nil || !onboardingSlugRE.MatchString(p.Slug) {
			continue
		}
		if _, held := customresources.ProjectFor(p.Slug); held {
			continue
		}
		if _, held := crdversions.TargetFor(p.Slug); held {
			continue
		}
		repo, component, fact = "github.com/"+m[1], "pkg:github/"+m[1], strings.ReplaceAll(p.Slug, "-", "_")
		target = fmt.Sprintf(`{
  "schema": "prufyx.io/crd-version-target/v1",
  "target": {
    "project": %q,
    "name": "Synthetic",
    "repo": %q,
    "component": %q,
    "factProject": %q,
    "tagPrefixes": ["v"],
    "minFrom": "1.0",
    "paths": [
      {"path": "deploy/crds", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}
    ],
    "exclude": []
  }
}
`, p.Slug, repo, component, fact)
		return p.Slug, repo, component, fact, target
	}
	panic("no landscape project left to onboard in the fixture")
}

// obCRDDoc renders the fixture's one CRD serving versions.
func obCRDDoc(group string, versions ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.%s\nspec:\n  group: %s\n  names:\n    kind: Widget\n    plural: widgets\n  scope: Namespaced\n  versions:\n", group, group)
	for i, v := range versions {
		fmt.Fprintf(&b, "  - name: %s\n    served: true\n    storage: %v\n    schema:\n      openAPIV3Schema:\n        type: object\n", v, i == len(versions)-1)
	}
	return b.String()
}

// obSource is a fixture upstream that counts a REST request per
// listing, as the GitHub source counts tree calls.
type obSource struct {
	extract.FixtureReader
	mu      sync.Mutex
	api     int64
	perList int64
}

func (c *obSource) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	c.mu.Lock()
	c.api += c.perList
	c.mu.Unlock()
	return c.FixtureReader.List(repo, commit, dir)
}

func (c *obSource) Stats() GitHubStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return GitHubStats{APIRequests: c.api, RateLimitRemaining: -1}
}

type onboardingFixture struct {
	base, head Tree
	key        testApprovalKey
	upstream   string
	src        *obSource
	draft      onboardingDraft
	signedAt   time.Time
}

func onboardingRepoFiles(t *testing.T, tr Tree) {
	t.Helper()
	ol := DefaultLayout().Onboarding
	dir := filepath.Join(repoRoot, filepath.FromSlash(ol.TargetsDir))
	names, err := filepath.Glob(filepath.Join(dir, "target-*.json"))
	if err != nil || len(names) == 0 {
		t.Fatalf("targets: %v", err)
	}
	rels := []string{ol.TablePath, ol.DocsDir + "/" + docstables.CRDTargetsPath, ol.DocsDir + "/" + docstables.CustomResourcesPath}
	for _, n := range names {
		rels = append(rels, ol.TargetsDir+"/"+filepath.Base(n))
	}
	for _, rel := range rels {
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(rel)), raw)
	}
}

func writeUpstream(t *testing.T, root, commit, rel, content string) {
	t.Helper()
	writeFile(t, filepath.Join(root, filepath.FromSlash(obRepo), "commits", commit, filepath.FromSlash(rel)), []byte(content))
}

func newOnboardingFixture(t *testing.T) *onboardingFixture {
	t.Helper()
	base, head := trees(t)
	onboardingRepoFiles(t, base)
	onboardingRepoFiles(t, head)
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, obOwner)
	up := t.TempDir()
	writeFile(t, filepath.Join(up, filepath.FromSlash(obRepo), "tags.json"), []byte(`{"v1.0.0": "`+obFrom+`", "v1.1.0": "`+obTo+`"}`))
	writeUpstream(t, up, obFrom, obCRD, obCRDDoc(obGroup, "v1alpha1", "v1"))
	writeUpstream(t, up, obTo, obCRD, obCRDDoc(obGroup, "v1"))
	f := &onboardingFixture{base: base, head: head, key: key, upstream: up, src: &obSource{FixtureReader: extract.FixtureReader{Root: up}, perList: 1}, signedAt: gateNow.Add(-time.Hour)}
	f.onboard(t, obSlug, obTargetJSON, obGroup, obCRD)
	f.draft = onboardingDraft{BatchID: "ob-20261003-1", CandidateID: "pr-1", Projects: []OnboardingProject{f.project(obSlug, OnboardingKindNew, obGroup)}}
	return f
}

// onboard adds a project's target and table row to the head and moves
// every file that follows them.
func (f *onboardingFixture) onboard(t *testing.T, slug, targetJSON, group, crdPath string) {
	f.onboardRow(t, slug, targetJSON, obComp, group, crdPath)
}

func (f *onboardingFixture) onboardRow(t *testing.T, slug, targetJSON, component, group, crdPath string) {
	t.Helper()
	ol := DefaultLayout().Onboarding
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(targetPath(ol, slug))), []byte(targetJSON))
	f.editTable(t, func(projects []customresources.Project) []customresources.Project {
		return append(projects, customresources.Project{Slug: slug, Catalog: customresources.CatalogCNCF, FactProject: strings.ReplaceAll(slug, "-", "_"),
			Component: component, Groups: []customresources.Group{{Name: group, Source: "https://github.com/" + obOwnerRepo + "/blob/" + obTo + "/" + crdPath}}})
	})
}

// editTable rewrites the head table (canonical spelling) and every file
// that follows it: the pack's revision and registryDigest, the corpus
// attestation, the generated inventory and the docs tables.
func (f *onboardingFixture) editTable(t *testing.T, edit func([]customresources.Project) []customresources.Project) {
	t.Helper()
	ol := DefaultLayout().Onboarding
	raw, err := f.head.Read(ol.TablePath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	projects, reserved, err := customresources.LoadTable(raw)
	if err != nil {
		t.Fatal(err)
	}
	projects = edit(projects)
	sort.Slice(projects, func(i, j int) bool { return projects[i].Slug < projects[j].Slug })
	table, err := customresources.CanonicalTable(projects, reserved)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(ol.TablePath)), table)
	f.follow(t)
}

// follow bumps the head pack revision once (from the base's) and sets its
// registryDigest from the head table, then regenerates what follows.
func (f *onboardingFixture) follow(t *testing.T) {
	t.Helper()
	ol := DefaultLayout().Onboarding
	table, err := f.head.Read(ol.TablePath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := cncfcheck.TableRegistryDigest(table)
	if err != nil {
		// A test of a table the loader refuses: the pack keeps its
		// registry, the revision still moves.
		digest = ""
	}
	baseRaw, err := f.base.Read(cncfRulesPath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	var members struct {
		Revision       string `json:"revision"`
		RegistryDigest string `json:"registryDigest"`
	}
	if err := json.Unmarshal(baseRaw, &members); err != nil {
		t.Fatal(err)
	}
	next, ok := nextRevision(members.Revision)
	if !ok {
		t.Fatalf("revision %s", members.Revision)
	}
	headRaw := bytes.Replace(baseRaw, []byte(`"revision": "`+members.Revision+`"`), []byte(`"revision": "`+next+`"`), 1)
	if digest != "" {
		headRaw = bytes.Replace(headRaw, []byte(members.RegistryDigest), []byte(digest), 1)
	}
	f.writePack(t, headRaw)
}

func (f *onboardingFixture) writePack(t *testing.T, packRaw []byte) {
	t.Helper()
	ol := DefaultLayout().Onboarding
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(cncfRulesPath)), packRaw)
	table, err := f.head.Read(ol.TablePath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	if att, err := corpusattest.DocumentFromFilesWithTable(corpusattest.PackCNCF, f.head.readUnder(cliDir), table); err == nil {
		writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(cncfAttestPath)), att)
	}
	for _, g := range DefaultLayout().Generated {
		j, md, err := g.Generate(f.head)
		if err != nil {
			t.Fatalf("regenerate %s: %v", g.JSONPath, err)
		}
		writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(g.JSONPath)), j)
		writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(g.MarkdownPath)), []byte(md))
	}
	f.writeDocs(t)
}

func (f *onboardingFixture) writeDocs(t *testing.T) {
	t.Helper()
	ol := DefaultLayout().Onboarding
	targets, err := treeTargets(f.head, ol.TargetsDir)
	if err != nil {
		t.Fatal(err)
	}
	var loaded []crdversions.Target
	for name, raw := range targets {
		tg, err := crdversions.LoadTarget(name, raw)
		if err != nil {
			return // a test of a target the loader refuses
		}
		loaded = append(loaded, tg)
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].Project < loaded[j].Project })
	table, _ := f.head.Read(ol.TablePath, MaxFileBytes)
	projects, reserved, err := customresources.LoadTable(table)
	if err != nil {
		return
	}
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(ol.DocsDir+"/"+docstables.CRDTargetsPath)), []byte(docstables.CRDTargets(loaded)))
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(ol.DocsDir+"/"+docstables.CustomResourcesPath)), []byte(docstables.CustomResources(projects, reserved)))
}

// project is the draft entry of a project, its target file as it is in the
// head now.
func (f *onboardingFixture) project(slug, kind string, groups ...string) OnboardingProject {
	ol := DefaultLayout().Onboarding
	raw, _ := f.head.Read(targetPath(ol, slug), MaxFileBytes)
	sort.Strings(groups)
	return OnboardingProject{
		Artifacts: []OnboardingArtifact{{Path: targetPath(ol, slug), Digest: CandidateDigest(raw)}},
		Catalog:   "cncf", Facts: []string{"component." + strings.ReplaceAll(slug, "-", "_") + ".custom_resource_versions_set"},
		Groups: groups, Kind: kind, Slug: slug,
		Proof: OnboardingProof{Claims: OnboardingClaims{Confirmed: 3, Ledger: obLedger}, Pair: OnboardingPair{FromCommit: obFrom, FromTag: "v1.0.0", ToCommit: obTo, ToTag: "v1.1.0"}, Scan: []OnboardingFinding{}},
	}
}

// refresh recomputes every artifact digest of the draft from the head.
func (f *onboardingFixture) refresh() {
	ol := DefaultLayout().Onboarding
	for i, p := range f.draft.Projects {
		raw, _ := f.head.Read(targetPath(ol, p.Slug), MaxFileBytes)
		f.draft.Projects[i].Artifacts = []OnboardingArtifact{{Path: targetPath(ol, p.Slug), Digest: CandidateDigest(raw)}}
	}
}

const obNonce = "0123456789abcdef0123456789abcdef"

// record prepares and completes the record as the signing tool does; it
// fails the test when the offline checks refuse it.
func (f *onboardingFixture) record(t *testing.T) OnboardingRecord {
	t.Helper()
	rec, ok := f.tryRecord(t)
	if !ok {
		t.Fatal("the offline checks refuse the fixture")
	}
	return rec
}

// tryRecord completes the record without the offline checks' verdict, so a
// test can sign what the signer would refuse and show the gate refuses it.
func (f *onboardingFixture) tryRecord(t *testing.T) (OnboardingRecord, bool) {
	t.Helper()
	layout := DefaultLayout()
	cls, err := Classify(layout, f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ChangedPaths(f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	st, err := newOnboardingState(layout, f.base, f.head, cls, paths)
	if err != nil {
		t.Logf("state: %v", err)
		return OnboardingRecord{}, false
	}
	rec := OnboardingRecord{Base: st.base.state, Head: st.head.state, BatchID: f.draft.BatchID, CandidateID: f.draft.CandidateID, ChangeSetDigest: st.changeSetDigest, Nonce: obNonce, Projects: f.draft.Projects}
	if rec.Sample, err = onboardingSample(rec.core()); err != nil {
		t.Fatal(err)
	}
	problems := st.check(rec, layout.Onboarding.Dir+"/"+rec.BatchID+".json")
	rec.SummaryDigest = CandidateDigest([]byte(st.summary(rec)))
	rec.Identity, rec.Decision = obOwner, ApprovalDecisionApprove
	rec.DecidedAt = f.signedAt.UTC().Format("2006-01-02T15:04:05Z")
	rec.NotAfter = f.signedAt.Add(MaxOnboardingValidity).UTC().Format("2006-01-02T15:04:05Z")
	if len(problems) > 0 {
		t.Logf("offline problems: %v", problems)
	}
	return rec, len(problems) == 0
}

func (k testApprovalKey) signOnboarding(t *testing.T, r OnboardingRecord) []byte {
	t.Helper()
	msg, err := SignedOnboardingBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(OnboardingEnvelope{Schema: OnboardingSchema, Record: r, KeyID: ApprovalKeyID(k.public), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(k.private, msg))}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func (f *onboardingFixture) writeBatch(t *testing.T, tr Tree, name string, raw []byte) {
	t.Helper()
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().Onboarding.Dir), name), raw)
}

// sign signs rec and adds it to the head.
func (f *onboardingFixture) sign(t *testing.T, rec OnboardingRecord) {
	t.Helper()
	f.writeBatch(t, f.head, rec.BatchID+".json", f.key.signOnboarding(t, rec))
}

func (f *onboardingFixture) gate(t *testing.T) *Report {
	t.Helper()
	return runGate(t, Options{Base: f.base, Head: f.head, Source: f.src, Author: obOwner, Sender: obOwner})
}

func (f *onboardingFixture) gateWith(t *testing.T, edit func(*Options)) *Report {
	t.Helper()
	opts := Options{Base: f.base, Head: f.head, Source: f.src, Author: obOwner, Sender: obOwner}
	edit(&opts)
	return runGate(t, opts)
}

var _ = context.Background
