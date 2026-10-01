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
