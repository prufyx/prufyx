// SPDX-License-Identifier: AGPL-3.0-only

package corpusattest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

func cliRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("locate cli root: %v", err)
	}
	return root
}

// TestCommittedAttestationIsCurrent is the CI gate: the asset the runtime
// consumes must be exactly what this command emits for today's pack.
func TestCommittedAttestationIsCurrent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"check"}, &stdout, &stderr, cliRoot(t)); code != 0 {
		t.Fatalf("check exit=%d stderr=%s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("corpus-attestation current:")) {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

// TestGenerateIsDeterministicAndCoversTheWholePack: the command computes over
// the unfiltered pack, and two runs produce byte-identical output.
func TestGenerateIsDeterministicAndCoversTheWholePack(t *testing.T) {
	root := cliRoot(t)
	first := filepath.Join(t.TempDir(), "attestation.json")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"generate", "--output", first}, &stdout, &stderr, root); code != 0 {
		t.Fatalf("generate exit=%d stderr=%s", code, stderr.String())
	}
	second := filepath.Join(t.TempDir(), "attestation.json")
	stdout.Reset()
	if code := Run([]string{"generate", "--output", second}, &stdout, &stderr, root); code != 0 {
		t.Fatalf("second generate exit=%d stderr=%s", code, stderr.String())
	}
	firstRaw, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	secondRaw, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("generate is not deterministic")
	}
	committed, err := os.ReadFile(filepath.Join(root, "internal/projectcheck", projectcheck.AttestationPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRaw, committed) {
		t.Fatal("generated attestation differs from the committed asset")
	}

	attestation, err := projectcheck.ParseAttestation(firstRaw)
	if err != nil {
		t.Fatalf("parse generated attestation: %v", err)
	}
	if attestation.Attestation != constraintengine.CorpusAttestation {
		t.Fatalf("attestation token=%q", attestation.Attestation)
	}
	inventory, err := projectcheck.UnfilteredCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if attestation.RuleCount != inventory.RuleCount || attestation.RuleSetDigest != inventory.RuleSetDigest || attestation.PackDigest != inventory.PackDigest {
		t.Fatalf("attestation does not describe the unfiltered pack: %+v vs %+v", attestation, inventory)
	}
	if len(attestation.Components) != len(inventory.Components) {
		t.Fatalf("attested %d components, pack holds rules for %d", len(attestation.Components), len(inventory.Components))
	}
}

// TestCheckRejectsATamperedAsset: the check mode is byte-exact, so a
// hand-edited attestation — for example one that added a component the pack
// holds no rule for — is caught in CI rather than at evaluation time.
func TestCheckRejectsATamperedAsset(t *testing.T) {
	root := cliRoot(t)
	document, err := Document()
	if err != nil {
		t.Fatal(err)
	}
	var attestation projectcheck.Attestation
	if err := json.Unmarshal(document, &attestation); err != nil {
		t.Fatal(err)
	}
	attestation.Components = append(attestation.Components, "pkg:github/example/not-in-this-pack")
	tampered, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "attestation.json")
	if err := os.WriteFile(path, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"check", "--output", path}, &stdout, &stderr, root); code == 0 {
		t.Fatal("check accepted a tampered attestation asset")
	}
}

// TestPackBindingIsVerifiedAgainstTheWorkingTree: the command refuses to emit
// an attestation whose packDigest does not match the pack file it was pointed
// at, so an attestation can never describe a pack nobody can produce.
func TestPackBindingIsVerifiedAgainstTheWorkingTree(t *testing.T) {
	root := cliRoot(t)
	decoy := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(decoy, []byte(`{"schema":"decoy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"generate", "--output", filepath.Join(t.TempDir(), "out.json"), "--rules", decoy}, &stdout, &stderr, root); code == 0 {
		t.Fatal("generate accepted a rule pack that is not the embedded one")
	}
}

func TestUnknownModeIsRejected(t *testing.T) {
	root := cliRoot(t)
	for _, args := range [][]string{{}, {"publish"}, {"generate", "--unknown"}, {"check", "extra"}, {"check", "--pack", "everything"}, {"generate", "--pack", ""}} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr, root); code == 0 {
			t.Fatalf("accepted %v", args)
		}
	}
}

// TestCNCFAttestationIsCurrent is the CI gate for the second corpus. The CNCF
// pack is attested separately from the community pack and over its own
// unfiltered entries: 167 reviewed rules across 54 subject components,
// including the 31 that have no native CLI descriptor.
func TestCNCFAttestationIsCurrent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"check", "--pack", PackCNCF}, &stdout, &stderr, cliRoot(t)); code != 0 {
		t.Fatalf("check exit=%d stderr=%s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("corpus-attestation current: pack=cncf")) {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

// TestCNCFGenerateCoversTheWholePack: the command computes over the unfiltered
// CNCF pack, deterministically, and the asset the runtime embeds is exactly
// what it emits.
func TestCNCFGenerateCoversTheWholePack(t *testing.T) {
	root := cliRoot(t)
	first := filepath.Join(t.TempDir(), "attestation.json")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"generate", "--pack", PackCNCF, "--output", first}, &stdout, &stderr, root); code != 0 {
		t.Fatalf("generate exit=%d stderr=%s", code, stderr.String())
	}
	firstRaw, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(t.TempDir(), "attestation.json")
	stdout.Reset()
	if code := Run([]string{"generate", "--pack", PackCNCF, "--output", second}, &stdout, &stderr, root); code != 0 {
		t.Fatalf("second generate exit=%d stderr=%s", code, stderr.String())
	}
	secondRaw, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatal("generate is not deterministic")
	}
	committed, err := os.ReadFile(filepath.Join(root, "internal/cncfcheck", cncfcheck.AttestationPath))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstRaw, committed) {
		t.Fatal("generated CNCF attestation differs from the committed asset")
	}

	attestation, err := cncfcheck.ParseAttestation(firstRaw)
	if err != nil {
		t.Fatalf("parse generated attestation: %v", err)
	}
	if attestation.Attestation != constraintengine.CorpusAttestation {
		t.Fatalf("attestation token=%q", attestation.Attestation)
	}
	inventory, err := cncfcheck.UnfilteredCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if attestation.RuleCount != inventory.RuleCount || attestation.RuleSetDigest != inventory.RuleSetDigest || attestation.PackDigest != inventory.PackDigest {
		t.Fatalf("attestation does not describe the unfiltered pack: %+v vs %+v", attestation, inventory)
	}
	if len(attestation.Components) != len(inventory.Components) {
		t.Fatalf("attested %d components, pack holds rules for %d", len(attestation.Components), len(inventory.Components))
	}
}

// TestCNCFCheckRejectsATamperedAsset: the check mode is byte-exact for the
// CNCF asset too, so a hand-edited attestation — for example one that added a
// component the pack holds no rule for — is caught in CI rather than at
// evaluation time.
func TestCNCFCheckRejectsATamperedAsset(t *testing.T) {
	root := cliRoot(t)
	document, err := DocumentFor(PackCNCF)
	if err != nil {
		t.Fatal(err)
	}
	var attestation cncfcheck.Attestation
	if err := json.Unmarshal(document, &attestation); err != nil {
		t.Fatal(err)
	}
	attestation.Components = append(attestation.Components, "pkg:github/example/not-in-this-pack")
	tampered, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "attestation.json")
	if err := os.WriteFile(path, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"check", "--pack", PackCNCF, "--output", path}, &stdout, &stderr, root); code == 0 {
		t.Fatal("check accepted a tampered CNCF attestation asset")
	}
}

// TestCNCFAttestationIsNotTheCommunityOne: the two corpora are attested
// separately. Neither attestation may be pointed at the other's pack, because
// each is bound to its own pack bytes by digest.
func TestCNCFAttestationIsNotTheCommunityOne(t *testing.T) {
	root := cliRoot(t)
	crossed := [][]string{
		{"generate", "--pack", PackCNCF, "--output", filepath.Join(t.TempDir(), "out.json"), "--rules", filepath.Join(root, "internal/projectcheck/data/rules.json")},
		{"generate", "--pack", PackCommunity, "--output", filepath.Join(t.TempDir(), "out.json"), "--rules", filepath.Join(root, "internal/cncfcheck/data/rules.json")},
	}
	for _, args := range crossed {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr, root); code == 0 {
			t.Fatalf("accepted an attestation bound to the other pack: %v", args)
		}
	}
}

// DocumentFromTree over this source tree must reproduce the embedded
// attestation byte for byte: both paths admit the same pack bytes.
func TestDocumentFromTreeMatchesEmbedded(t *testing.T) {
	for _, pack := range []string{PackCommunity, PackCNCF} {
		embedded, err := DocumentFor(pack)
		if err != nil {
			t.Fatal(err)
		}
		fromTree, err := DocumentFromTree(pack, filepath.Join("..", "..", ".."))
		if err != nil {
			t.Fatalf("%s: %v", pack, err)
		}
		if string(embedded) != string(fromTree) {
			t.Fatalf("%s: attestation from the tree differs from the embedded one", pack)
		}
	}
	if _, err := DocumentFromTree("other", filepath.Join("..", "..", "..")); err == nil {
		t.Fatal("unknown pack accepted")
	}
}

// treeCopy copies the pack inputs of this repository into a new tree root
// (which holds cli/), the layout --tree accepts.
func treeCopy(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{
		"internal/cncfcheck/data/landscape-projects.json", "internal/cncfcheck/data/priority-portfolio.json", "internal/cncfcheck/data/rules.json", "internal/cncfcheck/data/corpus-attestation.json",
		"internal/projectcheck/data/projects.json", "internal/projectcheck/data/rules.json", "internal/projectcheck/data/corpus-attestation.json",
	} {
		raw, err := os.ReadFile(filepath.Join(cliRoot(t), filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(root, "cli", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// A pack changed in a tree is attested from the tree's bytes: generate
// --tree rewrites the tree's asset, check --tree then agrees, and the
// binding names the tree and the pack digest. The embedded default still
// rejects the changed pack.
func TestGenerateFromTreeBindsToTheTreesPack(t *testing.T) {
	for _, pack := range []string{PackCommunity, PackCNCF} {
		tree := treeCopy(t)
		rules := filepath.Join(tree, "cli", "internal", "projectcheck", "data", "rules.json")
		if pack == PackCNCF {
			rules = filepath.Join(tree, "cli", "internal", "cncfcheck", "data", "rules.json")
		}
		raw, err := os.ReadFile(rules)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		doc["revision"] = "tree-test-revision"
		changed, _ := json.MarshalIndent(doc, "", "  ")
		if err := os.WriteFile(rules, append(changed, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"check", "--pack", pack, "--tree", tree}, &stdout, &stderr, cliRoot(t)); code == 0 {
			t.Fatalf("%s: check accepted a stale asset", pack)
		}
		stdout.Reset()
		stderr.Reset()
		if code := Run([]string{"generate", "--pack", pack, "--tree", tree}, &stdout, &stderr, cliRoot(t)); code != 0 {
			t.Fatalf("%s: generate exit=%d stderr=%s", pack, code, stderr.String())
		}
		if !bytes.Contains(stdout.Bytes(), []byte("binding=tree:")) || !bytes.Contains(stdout.Bytes(), []byte("packDigest=sha256:")) {
			t.Fatalf("%s: binding not explicit: %s", pack, stdout.String())
		}
		stdout.Reset()
		if code := Run([]string{"check", "--pack", pack, "--tree", filepath.Join(tree, "cli")}, &stdout, &stderr, cliRoot(t)); code != 0 {
			t.Fatalf("%s: check --tree exit=%d stderr=%s", pack, code, stderr.String())
		}
		// The tree's pack is what was attested, not the embedded one.
		want, err := DocumentFromTree(pack, filepath.Join(tree, "cli"))
		if err != nil {
			t.Fatal(err)
		}
		asset := filepath.Join(tree, "cli", "internal", "projectcheck", projectcheck.AttestationPath)
		if pack == PackCNCF {
			asset = filepath.Join(tree, "cli", "internal", "cncfcheck", cncfcheck.AttestationPath)
		}
		got, _ := os.ReadFile(asset)
		embedded, _ := DocumentFor(pack)
		if !bytes.Equal(got, want) || bytes.Equal(got, embedded) {
			t.Fatalf("%s: asset is not bound to the tree's pack", pack)
		}
		// Default (embedded) binding is unchanged: the tree's changed pack
		// does not satisfy it.
		if code := Run([]string{"generate", "--pack", pack, "--output", filepath.Join(t.TempDir(), "o.json"), "--rules", rules}, &stdout, &stderr, cliRoot(t)); code == 0 {
			t.Fatalf("%s: embedded binding accepted the changed pack", pack)
		}
	}
}

// --tree fails closed: not a tree, a mismatched --rules file, a symlinked
// input, and a missing input are all rejected, and nothing is written.
func TestGenerateFromTreeFailsClosed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"generate", "--tree", t.TempDir()}, &stdout, &stderr, cliRoot(t)); code == 0 {
		t.Fatal("an empty directory was accepted as a tree")
	}
	tree := treeCopy(t)
	decoy := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(decoy, []byte(`{"schema":"decoy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.json")
	if code := Run([]string{"generate", "--tree", tree, "--rules", decoy, "--output", out}, &stdout, &stderr, cliRoot(t)); code == 0 {
		t.Fatal("a rules file that is not the tree's pack was accepted")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("an attestation was written despite the binding mismatch")
	}
	rules := filepath.Join(tree, "cli", "internal", "projectcheck", "data", "rules.json")
	real := rules + ".real"
	if err := os.Rename(rules, real); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"generate", "--tree", tree, "--output", out}, &stdout, &stderr, cliRoot(t)); code == 0 {
		t.Fatal("a tree missing its pack was accepted")
	}
	if err := os.Symlink(real, rules); err != nil {
		t.Skip("symlinks unavailable")
	}
	if code := Run([]string{"generate", "--tree", tree, "--output", out}, &stdout, &stderr, cliRoot(t)); code == 0 {
		t.Fatal("a symlinked pack was accepted")
	}
}
