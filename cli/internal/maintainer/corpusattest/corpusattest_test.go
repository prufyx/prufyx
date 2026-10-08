// SPDX-License-Identifier: AGPL-3.0-only

package corpusattest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// --tree names the tree it works on: neither generate nor check needs a CLI
// root from the working directory, and a missing root is refused only when a
// default path would need it.
func TestTreeModeNeedsNoCLIRoot(t *testing.T) {
	tree := treeCopy(t)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"generate", "--pack", PackCNCF, "--tree", tree}, &stdout, &stderr, ""); code != 0 {
		t.Fatalf("generate exit=%d stderr=%s", code, stderr.String())
	}
	if code := Run([]string{"check", "--pack", PackCNCF, "--tree", tree}, &stdout, &stderr, ""); code != 0 {
		t.Fatalf("check exit=%d stderr=%s", code, stderr.String())
	}
	stderr.Reset()
	if code := Run([]string{"check"}, &stdout, &stderr, ""); code != 2 || !strings.Contains(stderr.String(), "CLI root is unavailable") {
		t.Fatalf("embedded mode without a root: exit=%d stderr=%s", code, stderr.String())
	}
}

// ReadRegularFile applies the gate reader's semantics: a link on any
// component, a directory, a missing file and an oversized file are refused.
func TestReadRegularFileRefusesLinksAndOversizeInputs(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "f.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real", "ok.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, MaxInputBytes+1)
	if err := os.WriteFile(filepath.Join(root, "real", "big.json"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	read := ReadRegularFile(root)
	if raw, err := read("real/ok.json"); err != nil || string(raw) != "{}" {
		t.Fatalf("regular file: %q %v", raw, err)
	}
	if _, err := read("real/big.json"); err == nil {
		t.Fatal("an oversized file was read")
	}
	if _, err := read("real"); err == nil {
		t.Fatal("a directory was read")
	}
	if _, err := read("real/absent.json"); err == nil {
		t.Fatal("a missing file was read")
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := read("linkdir/f.json"); err == nil {
		t.Fatal("a file below a symlinked directory was read")
	}
	if err := os.Symlink(filepath.Join(outside, "f.json"), filepath.Join(root, "real", "link.json")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := read("real/link.json"); err == nil {
		t.Fatal("a symlinked file was read")
	}
}

// ResolveTreeCLI is deterministic and checks the whole layout: the root and
// the cli/ directory both resolve, an ambiguous or partial tree and a
// symlinked cli/ do not.
func TestResolveTreeCLI(t *testing.T) {
	tree := treeCopy(t)
	want := filepath.Join(tree, "cli")
	for _, arg := range []string{tree, want} {
		got, err := ResolveTreeCLI(arg)
		if err != nil || got != want {
			t.Fatalf("%s: %q %v", arg, got, err)
		}
	}
	if _, err := ResolveTreeCLI(filepath.Join(tree, "absent")); err == nil {
		t.Fatal("a missing directory resolved")
	}

	// Ambiguous: cli/ holds the layout and also a nested cli/ with the layout.
	nested := treeCopy(t)
	inner := filepath.Join(nested, "cli", "cli")
	if err := filepath.Walk(filepath.Join(nested, "cli", "internal"), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join(nested, "cli"), p)
		dst := filepath.Join(inner, rel)
		if info.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, raw, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveTreeCLI(filepath.Join(nested, "cli")); err == nil {
		t.Fatalf("a cli/ holding the layout and a nested cli/ resolved to %s", got)
	}
	if got, err := ResolveTreeCLI(nested); err != nil || got != filepath.Join(nested, "cli") {
		t.Fatalf("the root of an ambiguous tree: %q %v", got, err)
	}
	if got, err := ResolveTreeCLI(inner); err != nil || got != inner {
		t.Fatalf("the inner directory: %q %v", got, err)
	}

	// Partial layout: a tree without one pack file is not a tree.
	partial := treeCopy(t)
	if err := os.Remove(filepath.Join(partial, "cli", "internal", "cncfcheck", "data", "priority-portfolio.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveTreeCLI(partial); err == nil {
		t.Fatal("a tree without a pack input resolved")
	}

	// A symlinked cli/ is refused, even when its target holds the layout.
	linked := treeCopy(t)
	real := filepath.Join(t.TempDir(), "real-cli")
	if err := os.Rename(filepath.Join(linked, "cli"), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(linked, "cli")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if got, err := ResolveTreeCLI(linked); err == nil {
		t.Fatalf("a symlinked cli/ resolved to %s", got)
	}
}
