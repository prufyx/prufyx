// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/consensus"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	consensusFrom = "0000000000000000000000000000000000014000"
	consensusTo   = "0000000000000000000000000000000000014100"
	consensusPath = "CHANGELOG/CHANGELOG-1.41.md"
)

// consensusSource is the consensus verifier's synthetic two-release
// fixture with notes as the later release's release notes.
func consensusSource(t *testing.T, notes string) extract.FixtureReader {
	t.Helper()
	from := filepath.Join("..", "..", "consensus", "testdata", "injection", "base")
	root := t.TempDir()
	err := filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(root, rel), 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(root, rel), raw, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "github.com", "kubernetes", "kubernetes", "commits", consensusTo, filepath.FromSlash(consensusPath)), []byte(notes))
	return extract.FixtureReader{Root: root}
}

func consensusBundle(t *testing.T, notes string, names ...string) []byte {
	t.Helper()
	n, err := consensus.Normalise([]byte(notes), consensus.SectionSpec{Repo: consensus.KubernetesRepo, Path: consensusPath, Version: "v1.41.0"})
	if err != nil {
		t.Fatal(err)
	}
	b := consensus.Bundle{
		Schema: consensus.BundleSchema,
		Source: consensus.Source{Repo: consensus.KubernetesRepo, Commit: consensusTo, Path: consensusPath, FileSHA256: consensus.FileDigest([]byte(notes)),
			Section: "v1.41.0", NormaliserVersion: consensus.NormaliserVersion, NormalisedSHA256: n.Digest()},
		FromRelease: consensus.FromRelease{Repo: consensus.KubernetesRepo, Commit: consensusFrom, Tag: "v1.40.0"},
		ToRelease:   consensus.ToRelease{Tag: "v1.41.0"},
	}
	for i, name := range names {
		b.Claims = append(b.Claims, consensus.Claim{ID: "c" + string(rune('1'+i)), Kind: "removed_feature_gate", Names: []string{name}})
	}
	raw, err := extract.Canonical(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const consensusNotes = "# v1.41.0\n\n## Changes by Kind\n\n- Removed the SilentDial feature gate. ([#140005](https://github.com/kubernetes/kubernetes/pull/140005)) [SIG Node]\n- Removed the PhantomAccelerator feature gate. ([#140005](https://github.com/kubernetes/kubernetes/pull/140005))\n\n# v1.41.0-rc.1\n"

// consensusChange adds a well-formed consensus rule to the head pack, with
// a claims bundle when bundle is not nil, and runs the gate.
func consensusChange(t *testing.T, bundle []byte, src Source) (*Report, *Change) {
	t.Helper()
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	p := readPack(t, head, cncfRulesPath)
	added := deepCopy(p.find(t, ids[0])).(map[string]any)
	id := ids[0] + "-consensus"
	ruleOf(added)["id"] = id
	evidence := evidenceOf(added)
	evidence["basis"], evidence["derivedAt"] = "consensus", evidence["reviewedAt"]
	p.entries = append(p.entries, added)
	p.sortByID()
	p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha7"`)
	p.write(t, head, cncfRulesPath)
	if bundle != nil {
		writeFile(t, filepath.Join(head.Root, filepath.FromSlash(DefaultLayout().ConsensusClaimsDir), "cncf", id+".json"), bundle)
	}
	r := runGate(t, Options{Base: base, Head: head, Source: src})
	for _, c := range r.Changes {
		if c.RuleID == id {
			return r, c
		}
	}
	t.Fatal("the consensus change is not reported")
	return nil, nil
}

// A consensus rule whose every claim verifies is still refused, with the
// same refusal as before; nothing about admission depends on the verdict.
func TestGateConsensusStillRefused(t *testing.T) {
	notes := "# v1.41.0\n\n## Changes by Kind\n\n- Removed the SilentDial feature gate. ([#140005](https://github.com/kubernetes/kubernetes/pull/140005))\n\n# v1.41.0-rc.1\n"
	r, c := consensusChange(t, consensusBundle(t, notes, "SilentDial"), consensusSource(t, notes))
	if c.Consensus == nil || c.Consensus.Verified != 1 || c.Consensus.Error != "" {
		t.Fatalf("verdict %+v", c.Consensus)
	}
	if c.OK || c.Proof != "" || !strings.HasPrefix(c.Detail, "consensus evidence has no verifier in this gate; not admitted") {
		t.Fatalf("change %+v", c)
	}
	requireFail(t, r, "consensus evidence has no verifier in this gate")
	if r.Passed() || r.AutoMerge.Eligible {
		t.Fatal("the gate passed a consensus rule")
	}
	// Without a bundle the change reads exactly as before.
	_, c = consensusChange(t, nil, consensusSource(t, notes))
	if c.Consensus != nil || c.Detail != "consensus evidence has no verifier in this gate; not admitted" {
		t.Fatalf("change without a bundle %+v", c)
	}
}

// The gate re-runs the verifier on the bundle and reports each verdict.
func TestGateReportsVerifierVerdict(t *testing.T) {
	_, c := consensusChange(t, consensusBundle(t, consensusNotes, "SilentDial", "PhantomAccelerator"), consensusSource(t, consensusNotes))
	v := c.Consensus
	if v == nil || v.Verified != 1 || v.Dropped != 1 || len(v.Results) != 2 || v.Results[1].Reason != consensus.ReasonNotInInventory {
		t.Fatalf("verdict %+v", v)
	}
	if !strings.HasSuffix(c.Detail, "; consensus verifier (report only): 1 verified, 0 lead, 1 dropped") || c.OK {
		t.Fatalf("detail %q", c.Detail)
	}
	if !strings.HasSuffix(v.Claims, "/cncf/"+c.RuleID+".json") {
		t.Fatalf("claims path %q", v.Claims)
	}
	// The verdict is computed by the gate, not read from the head: changed
	// release notes no longer match the pinned bundle.
	_, c = consensusChange(t, consensusBundle(t, consensusNotes, "SilentDial"), consensusSource(t, consensusNotes+"\n"))
	if c.Consensus == nil || c.Consensus.Verified != 0 || c.Consensus.Results[0].Reason != consensus.ReasonSourceMismatch {
		t.Fatalf("changed notes %+v", c.Consensus)
	}
	// A bundle the decoder refuses, and a gate without a source.
	_, c = consensusChange(t, []byte(`{"schema":"x"}`), consensusSource(t, consensusNotes))
	if c.Consensus == nil || c.Consensus.Error == "" || c.OK {
		t.Fatalf("bad bundle %+v", c.Consensus)
	}
	_, c = consensusChange(t, consensusBundle(t, consensusNotes, "SilentDial"), nil)
	if c.Consensus == nil || c.Consensus.Error != "no upstream source" {
		t.Fatalf("no source %+v", c.Consensus)
	}
}

// One gate run verifies at most MaxConsensusBundles bundles and shares one
// inventory cache between them.
func TestGateConsensusBounds(t *testing.T) {
	src := consensusSource(t, consensusNotes)
	head := Tree{Root: t.TempDir()}
	layout := DefaultLayout()
	bundle := consensusBundle(t, consensusNotes, "SilentDial")
	run := &consensusRun{}
	var first *consensus.ExtractorInventories
	for i := 0; i <= MaxConsensusBundles; i++ {
		id := fmt.Sprintf("rule-%d", i)
		writeFile(t, filepath.Join(head.Root, filepath.FromSlash(layout.ConsensusClaimsDir), "cncf", id+".json"), bundle)
		c := &Change{Pack: "cncf", RuleID: id}
		run.report(context.Background(), c, Options{Layout: layout, Head: head, Source: src})
		if i == 0 {
			first = run.inventories
		}
		if run.inventories != first {
			t.Fatal("the inventory cache is not shared")
		}
		switch {
		case i < MaxConsensusBundles && (c.Consensus.Error != "" || c.Consensus.Verified != 1):
			t.Fatalf("bundle %d: %+v", i, c.Consensus)
		case i == MaxConsensusBundles && !strings.Contains(c.Consensus.Error, "claims bundles in one run"):
			t.Fatalf("bundle over the cap: %+v", c.Consensus)
		}
	}
	run.close()
	// A cancelled run reports an error rather than a verdict, and its
	// reads stop: the budget is shared by every bundle of the run.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Change{Pack: "cncf", RuleID: "rule-0"}
	cancelled := &consensusRun{}
	defer cancelled.close()
	cancelled.report(ctx, c, Options{Layout: layout, Head: head, Source: src})
	if c.Consensus.Error == "" || c.OK {
		t.Fatalf("cancelled: %+v", c.Consensus)
	}
	if _, err := cancelled.reader.Read(extract.RepoRef{Key: consensus.KubernetesRepo}, consensusTo, consensusPath); !errors.Is(err, context.Canceled) {
		t.Fatalf("read after the budget: %v", err)
	}
	if _, err := cancelled.reader.List(extract.RepoRef{Key: consensus.KubernetesRepo}, consensusTo, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("listing after the budget: %v", err)
	}
	if ConsensusBudget > 10*time.Minute {
		t.Fatalf("budget %v", ConsensusBudget)
	}
}
