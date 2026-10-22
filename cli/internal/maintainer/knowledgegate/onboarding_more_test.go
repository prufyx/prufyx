// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

const (
	atFrom = "00000000000000000000000000000000000b1300"
	atTo   = "00000000000000000000000000000000000b1400"
)

// atPick is a target of the repository that does not attest yet and that a
// small fixture can stand in for: a registered CNCF project with one plain
// directory path, no exclusions, remote source or channels.
func atPick(t *testing.T) (crdversions.Target, customresources.Project) {
	t.Helper()
	return atPickIn(t, crdversions.CatalogCNCF)
}

// atPickIn is atPick for a target of the given catalog.
func atPickIn(t *testing.T, catalog string) (crdversions.Target, customresources.Project) {
	t.Helper()
	for _, tg := range crdversions.Targets {
		row, registered := customresources.ProjectFor(tg.Project)
		if tg.Attest || !registered || tg.Catalog != catalog || tg.Remote != nil || len(tg.Channels) > 0 || len(tg.Exclude) > 0 || len(tg.Paths) != 1 || !tg.Paths[0].Dir || tg.Paths[0].Recursive || len(tg.TagPrefixes) == 0 {
			continue
		}
		return tg, row
	}
	t.Skip("no target of the repository is left to turn attestation on for")
	return crdversions.Target{}, customresources.Project{}
}

// attestFixture turns on attestation for atPick's target, against a
// synthetic upstream fixture; edit changes the head target document too.
func attestFixture(t *testing.T, edit func(target map[string]any)) *onboardingFixture {
	t.Helper()
	return attestFixtureIn(t, crdversions.CatalogCNCF, edit)
}

// attestFixtureIn is attestFixture for a project of the given catalog.
func attestFixtureIn(t *testing.T, catalog string, edit func(target map[string]any)) *onboardingFixture {
	t.Helper()
	tg, row := atPickIn(t, catalog)
	base, head := trees(t)
	onboardingRepoFiles(t, base)
	onboardingRepoFiles(t, head)
	key := newApprovalKey(t)
	key.pinBoth(t, base, head, obOwner)
	up := t.TempDir()
	prefix := tg.TagPrefixes[0]
	fromTag := fmt.Sprintf("%s%d.%d.0", prefix, tg.MinFrom[0], tg.MinFrom[1])
	toTag := fmt.Sprintf("%s%d.%d.0", prefix, tg.MinFrom[0], tg.MinFrom[1]+1)
	writeFile(t, filepath.Join(up, filepath.FromSlash(tg.Repo), "tags.json"), []byte(`{"`+fromTag+`": "`+atFrom+`", "`+toTag+`": "`+atTo+`"}`))
	group := row.Groups[0].Name
	for _, c := range []string{atFrom, atTo} {
		writeFile(t, filepath.Join(up, filepath.FromSlash(tg.Repo), "commits", c, filepath.FromSlash(tg.Paths[0].Path), group+"_widgets-crd.yaml"), []byte(obCRDDoc(group, "v1beta1")))
	}
	f := &onboardingFixture{base: base, head: head, key: key, upstream: up, src: &obSource{FixtureReader: extract.FixtureReader{Root: up}, perList: 1}, signedAt: gateNow.Add(-time.Hour)}
	ol := DefaultLayout().Onboarding
	path := filepath.Join(head.Root, filepath.FromSlash(targetPath(ol, tg.Project)))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["target"].(map[string]any)["attest"] = true
	if edit != nil {
		edit(doc["target"].(map[string]any))
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	writeFile(t, path, append(out, '\n'))
	f.follow(t)
	var groups []string
	for _, g := range row.Groups {
		groups = append(groups, g.Name)
	}
	p := f.project(tg.Project, OnboardingKindAttest, groups...)
	p.Facts = []string{row.FactID()}
	p.Catalog = string(row.Catalog)
	p.Proof.Pair = OnboardingPair{FromCommit: atFrom, FromTag: fromTag, ToCommit: atTo, ToTag: toTag}
	f.draft = onboardingDraft{BatchID: "ob-20261003-1", CandidateID: "pr-2", Projects: []OnboardingProject{p}}
	return f
}

func TestOnboardingAttestFlip(t *testing.T) {
	t.Parallel()
	f := attestFixture(t, nil)
	f.sign(t, f.record(t))
	r := f.gate(t)
	requirePass(t, r)
	if len(r.Changes) != 0 {
		t.Fatalf("an attest flip changes no pack member, got %+v", r.Changes)
	}
	if !strings.Contains(r.onboarding.summary, "**Attestation turned on: "+f.draft.Projects[0].Slug+".**") {
		t.Fatalf("summary does not lead with the attest flip:\n%s", r.onboarding.summary)
	}
}

func TestOnboardingAttestRefusals(t *testing.T) {
	t.Parallel()
	t.Run("refuted claims", func(t *testing.T) {
		f := attestFixture(t, nil)
		f.draft.Projects[0].Proof.Claims.Refuted = 1
		rec, _ := f.tryRecord(t)
		f.sign(t, rec)
		requireFail(t, f.gate(t), "no refuted claim")
	})
	t.Run("another member changes with attest", func(t *testing.T) {
		f := attestFixture(t, func(target map[string]any) { target["name"] = "Renamed" })
		f.refresh()
		rec, _ := f.tryRecord(t)
		f.sign(t, rec)
		requireFail(t, f.gate(t), "may change only the target's attest member")
	})
	t.Run("a target with an exclusion", func(t *testing.T) {
		f := attestFixture(t, func(target map[string]any) {
			target["exclude"] = []any{map[string]any{"path": "test/crds/", "repo": target["repo"], "reason": "end-to-end test manifests", "evidence": "the directory holds only the manifests of the end-to-end tests"}}
		})
		f.refresh()
		rec, _ := f.tryRecord(t)
		f.sign(t, rec)
		requireFail(t, f.gate(t), "never turned on for attestation by a batch")
	})
	t.Run("the pair does not attest", func(t *testing.T) {
		f := attestFixture(t, nil)
		// A stray definition outside the listed path keeps the scan from
		// being clean, so the line cannot be attested; the proposal lists
		// it, so only the attestation refuses.
		tg, _ := atPick(t)
		for _, c := range []string{atTo, atFrom} {
			writeFile(t, filepath.Join(f.upstream, filepath.FromSlash(tg.Repo), "commits", c, "hack/stray-crd.yaml"), []byte(obCRDDoc("stray.synthetic.example", "v1")))
		}
		src := &obSource{FixtureReader: extract.FixtureReader{Root: f.upstream}, perList: 1}
		f.draft.Projects[0].Proof.Scan = scanOf(t, f, src)
		f.sign(t, f.record(t))
		requireFail(t, f.gate(t), "does not attest its newest pair")
	})
	t.Run("kind attest for a target the base does not hold", func(t *testing.T) {
		f := newOnboardingFixture(t)
		f.draft.Projects[0].Kind = OnboardingKindAttest
		rec, _ := f.tryRecord(t)
		f.sign(t, rec)
		requireFail(t, f.gate(t), "kind attest, but the base holds no target file")
	})
}

// scanOf runs the fixture's first project's newest pair once, as the
// proposal's dry run does, and returns its scan findings as a proof lists
// them.
func scanOf(t *testing.T, f *onboardingFixture, src *obSource) []OnboardingFinding {
	t.Helper()
	slug := f.draft.Projects[0].Slug
	raw, err := f.head.Read(targetPath(DefaultLayout().Onboarding, slug), MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	tg, err := crdversions.LoadTarget(crdversions.TargetFileName(slug), raw)
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := extract.ParseRepo(tg.Repo)
	ex := &newestPairOnly{Extractor: crdversions.New(tg)}
	out, err := extract.Run(t.Context(), ex, src, src, extract.Options{Repo: repo, DerivedAt: gateNow})
	if err != nil || len(out.Manifest.Pairs) != 1 {
		t.Fatalf("dry run: %v", err)
	}
	var proof crdversions.PairProof
	b, _ := json.Marshal(out.Manifest.Pairs[0].Proof)
	if err := json.Unmarshal(b, &proof); err != nil || proof.Lines == nil {
		t.Fatalf("proof: %v", err)
	}
	seen := map[string]bool{}
	var list []OnboardingFinding
	for _, line := range []crdversions.LineRecord{proof.Lines.From, proof.Lines.To} {
		for _, tag := range line.Tags {
			for _, fd := range tag.ScanFindings {
				o := OnboardingFinding{Class: fd.Class, Path: fd.Path, SHA256: fd.SHA256}
				if !seen[onboardingFindingKey(o)] {
					seen[onboardingFindingKey(o)] = true
					list = append(list, o)
				}
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return onboardingFindingKey(list[i]) < onboardingFindingKey(list[j]) })
	if len(list) == 0 {
		t.Fatal("no scan finding")
	}
	t.Logf("findings %+v", list)
	return list
}

func TestOnboardingRecordsRule(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	rec := f.record(t)
	raw := f.key.signOnboarding(t, rec)
	// The batch is merged: both trees hold it, and a later change edits it.
	f.writeBatch(t, f.base, rec.BatchID+".json", raw)
	f.writeBatch(t, f.head, rec.BatchID+".json", bytes.Replace(raw, []byte(`"pr-1"`), []byte(`"pr-9"`), 1))
	r := runGate(t, Options{Base: f.base, Head: f.base, Source: f.src})
	if _, ok := check(r, "onboarding-records"); ok {
		t.Fatal("an unchanged directory is checked")
	}
	head := copyTree(t, f.base)
	f.writeBatch(t, head, rec.BatchID+".json", bytes.Replace(raw, []byte(`"pr-1"`), []byte(`"pr-9"`), 1))
	requireFail(t, runGate(t, Options{Base: f.base, Head: head, Source: f.src}), "an onboarding batch file is never changed")
	head = copyTree(t, f.base)
	os.Remove(filepath.Join(head.Root, filepath.FromSlash(DefaultLayout().Onboarding.Dir), rec.BatchID+".json"))
	requireFail(t, runGate(t, Options{Base: f.base, Head: head, Source: f.src}), "may not be removed until 14 days after it expired")
	// After the retention it may go.
	r = runGate(t, Options{Base: f.base, Head: head, Source: f.src, Now: f.signedAt.Add(MaxOnboardingValidity + OnboardingRetention + time.Hour)})
	if c, ok := check(r, "onboarding-records"); !ok || !c.OK {
		t.Fatalf("removal after the retention: %+v", c)
	}
}

// A knowledge batch refuses an onboarding path, and an onboarding batch an
// approval path: neither path admits the other's files.
func TestOnboardingAndKnowledgeBatchesRefuseEachOther(t *testing.T) {
	t.Parallel()
	bf := newBatchFixture(t, 3)
	rec := bf.record(t)
	bf.signAndWrite(t, rec)
	writeFile(t, filepath.Join(bf.head.Root, filepath.FromSlash(DefaultLayout().Onboarding.Dir), "ob-20261003-1.json"), []byte("{}\n"))
	r := runGate(t, Options{Base: bf.base, Head: bf.head, Author: "airstand", Sender: "airstand"})
	requireFail(t, r, "a change carrying a batch approval may change only")
	requireFail(t, r, "O1: onboarding batch")

	f := newOnboardingFixture(t)
	f.sign(t, f.record(t))
	writeFile(t, filepath.Join(f.head.Root, filepath.FromSlash(DefaultLayout().BatchDir), "b-20261003-1.json"), []byte("{}\n"))
	requireFail(t, f.gate(t), "cli/knowledge/approvals/batches/b-20261003-1.json")
}

func TestOnboardingSignAndVerifyCommands(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	ol := DefaultLayout().Onboarding
	dir := t.TempDir()
	draft, _ := json.Marshal(f.draft)
	draftPath := filepath.Join(dir, "draft.json")
	writeFile(t, draftPath, draft)
	keysPath := filepath.Join(f.base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
	keysRaw, _ := os.ReadFile(keysPath)
	digest := pinnedDigest(keysRaw)
	var confirmed string
	env := approvalEnv{stdin: bytes.NewReader(f.key.pemKey(t)), now: func() time.Time { return f.signedAt }, checkStdin: func(io.Reader) error { return nil },
		confirm: func(prompt string) (string, error) { confirmed = prompt; return f.draft.BatchID, nil }, random: rand.Reader}
	var out, errOut bytes.Buffer
	code := approvalMain([]string{"sign", "--onboarding", draftPath, "--base", f.base.Root, "--head", f.head.Root, "--keys", keysPath, "--keys-digest", digest, "--identity", obOwner, "--key-stdin"}, env, DefaultLayout(), &out, &errOut)
	if code != 0 {
		t.Fatalf("sign: %d %s %s", code, out.String(), errOut.String())
	}
	if !strings.Contains(confirmed, "Type the batch id ob-20261003-1") || !strings.Contains(out.String(), "# Onboarding batch ob-20261003-1") {
		t.Fatalf("prompt %q output %s", confirmed, out.String())
	}
	batch := filepath.Join(f.head.Root, filepath.FromSlash(ol.Dir), f.draft.BatchID+".json")
	out.Reset()
	code = approvalMain([]string{"verify", "--onboarding", batch, "--base", f.base.Root, "--head", f.head.Root, "--keys", keysPath, "--keys-digest", digest, "--now", gateNow.Format(time.RFC3339)}, env, DefaultLayout(), &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "onboarding batch OK") || !strings.Contains(out.String(), "not checked here (no network): the dry run") {
		t.Fatalf("verify: %d %s %s", code, out.String(), errOut.String())
	}
	requirePass(t, f.gate(t))

	// A tampered file is refused by verify.
	raw, _ := os.ReadFile(batch)
	writeFile(t, batch, bytes.Replace(raw, []byte(`"pr-1"`), []byte(`"pr-2"`), 1))
	out.Reset()
	code = approvalMain([]string{"verify", "--onboarding", batch, "--base", f.base.Root, "--head", f.head.Root, "--keys", keysPath, "--keys-digest", digest, "--now", gateNow.Format(time.RFC3339)}, env, DefaultLayout(), &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "REFUSED") {
		t.Fatalf("tampered: %d %s", code, out.String())
	}
}

// The signed bytes, the sample and the change-set digest are pinned: the
// signing tool and the gate of a later revision must compute them alike.
func TestOnboardingVectors(t *testing.T) {
	t.Parallel()
	p := OnboardingProject{
		Artifacts: []OnboardingArtifact{{Digest: obLedger, Path: "cli/internal/extract/crdversions/target-sample.json"}},
		Catalog:   "cncf", Facts: []string{"component.sample.custom_resource_versions_set"}, Groups: []string{"sample.synthetic.example"}, Kind: OnboardingKindNew, Slug: "sample",
		Proof: OnboardingProof{Claims: OnboardingClaims{Confirmed: 1, Ledger: obLedger}, Pair: OnboardingPair{FromCommit: obFrom, FromTag: "v1.0.0", ToCommit: obTo, ToTag: "v1.1.0"}, Scan: []OnboardingFinding{}},
	}
	var projects []OnboardingProject
	for _, s := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "za", "zb", "zc", "zd", "ze", "zf", "zg"} {
		q := p
		q.Slug = s
		projects = append(projects, q)
	}
	state := OnboardingState{PackRevision: "cncf-2026-09-13.8", RegistryDigest: obLedger, TableDigest: obLedger, TargetsDigest: obLedger}
	core := onboardingCore{Base: state, BatchID: "ob-20261003-1", CandidateID: "pr-1", ChangeSetDigest: obLedger, Head: state, Nonce: obNonce, Projects: projects}
	sample, err := onboardingSample(core)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sample, []int{0, 16, 22, 25}; !equalInts(got, want) {
		t.Fatalf("sample %v, pinned %v", got, want)
	}
	rec := OnboardingRecord{Base: state, BatchID: core.BatchID, CandidateID: core.CandidateID, ChangeSetDigest: obLedger, DecidedAt: "2026-10-03T11:00:00Z", Decision: "approve", Head: state, Identity: obOwner, Nonce: obNonce, NotAfter: "2026-10-06T11:00:00Z", Projects: projects[:1], Sample: []int{0}, SummaryDigest: obLedger}
	signed, err := SignedOnboardingBytes(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(signed, []byte("prufyx.io/knowledge-onboarding-batch/v1\x00{\"base\":{\"packRevision\"")) || bytes.HasPrefix(signed, []byte(BatchDomain)) || bytes.HasPrefix(signed, []byte(ApprovalDomain)) {
		t.Fatalf("signed bytes %q", signed[:80])
	}
	if got, want := CandidateDigest(signed), "sha256:bf565592c4028282f5184c60f6461b9cd3311484fe5b082beae5e8b54d793316"; got != want {
		t.Fatalf("signed bytes digest %s, pinned %s", got, want)
	}
	set, err := domainDigest(onboardingChangeDomain, onboardingChangeSet{Changes: []changeSetItem{}, ChainsChanged: []string{}, Paths: []string{"cli/internal/customresources/table.json"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:65fdaa4b33a463947e3e8994b2037b379e20d044b5da4bd7e1973071edf81f7d"; set != want {
		t.Fatalf("change set digest %s, pinned %s", set, want)
	}
}

// The registry the gate compiles from the embedded table is the compiled
// registry the embedded pack names.
func TestTableRegistryDigestOfTheEmbeddedTable(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(repoRoot, "cli/internal/customresources/table.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := cncfcheck.TableRegistryDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	pack, _ := os.ReadFile(filepath.Join(repoRoot, cncfRulesPath))
	var m struct {
		RegistryDigest string `json:"registryDigest"`
	}
	if err := json.Unmarshal(pack, &m); err != nil || got != m.RegistryDigest {
		t.Fatalf("table registry %s, pack %s", got, m.RegistryDigest)
	}
	if len(cncfcheck.TableDefinitions(customresources.Projects())) == 0 {
		t.Fatal("no definitions")
	}
}
