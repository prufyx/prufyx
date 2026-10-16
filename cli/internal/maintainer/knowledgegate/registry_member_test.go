// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencereattest"
)

// The synthetic fact definition the registry tests add. No rule reads it.
var addedFact = constraintengine.FactDefinition{ID: "component.argo_cd.synthetic_registry_addition", Component: "pkg:github/argoproj/argo-cd", Type: constraintengine.FactBool}

const (
	addedFactLine = `		{ID: "component.argo_cd.synthetic_registry_addition", Component: "pkg:github/argoproj/argo-cd", Type: constraintengine.FactBool, EnumTokens: nil},`
	listOpen      = "return append([]constraintengine.FactDefinition{\n"
	enumLine      = `		{ID: "component.argo_cd.latest_distribution", Component: "pkg:github/argoproj/argo-cd", Type: constraintengine.FactEnum, EnumTokens: []string{"custom_build", "official_upstream"}},`
	existingLine  = `		{ID: "component.argo_cd.disable_fine_grained_inheritance", Component: "pkg:github/argoproj/argo-cd", Type: constraintengine.FactBool, EnumTokens: nil},`
)

func cncfSpec(t *testing.T) PackSpec {
	t.Helper()
	for _, s := range DefaultLayout().Packs {
		if s.Name == evidencereattest.PackCNCF {
			return s
		}
	}
	t.Fatal("no cncf pack")
	return PackSpec{}
}

func registrySource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(cncfRegistrySource)))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if strings.Count(src, listOpen) != 1 || strings.Count(src, existingLine+"\n") != 1 || strings.Count(src, enumLine+"\n") != 1 {
		t.Fatal("the registry source is not in the form these tests edit")
	}
	return src
}

// withAdded adds the synthetic definition's line to the literal list.
func withAdded(src string) string {
	return strings.Replace(src, listOpen, listOpen+addedFactLine+"\n", 1)
}

func registryDigestOf(t *testing.T, definitions []constraintengine.FactDefinition) string {
	t.Helper()
	r, err := constraintengine.NewCompiledRegistry(definitions)
	if err != nil {
		t.Fatal(err)
	}
	return r.Digest()
}

// editRegistryPack edits the cncf pack of a tree and regenerates its corpus
// attestation under definitions, and the outputs generated from it (all left
// as they are when the pack cannot be attested under them).
func editRegistryPack(t *testing.T, tr Tree, definitions []constraintengine.FactDefinition, edit func(p *packDoc)) {
	t.Helper()
	p := readPack(t, tr, cncfRulesPath)
	edit(p)
	p.write(t, tr, cncfRulesPath)
	spec := cncfSpec(t)
	attestation, err := spec.AttestWith(tr, AdmitOpts{Definitions: definitions})
	if err != nil {
		return
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(spec.AttestationPath)), attestation)
	for _, g := range DefaultLayout().Generated {
		j, md, err := g.Generate(tr)
		if err != nil {
			t.Fatalf("regenerate %s: %v", g.JSONPath, err)
		}
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(g.JSONPath)), j)
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(g.MarkdownPath)), []byte(md))
	}
}

func setRegistryDigest(t *testing.T, tr Tree, digest string, definitions []constraintengine.FactDefinition) {
	t.Helper()
	editRegistryPack(t, tr, definitions, func(p *packDoc) {
		raw, err := json.Marshal(digest)
		if err != nil {
			t.Fatal(err)
		}
		p.fields["registryDigest"] = raw
	})
}

// registryTrees returns a base and a head whose registry source the head
// edits with editHead; the head's registryDigest member names headDefs and
// its corpus attestation is regenerated under them.
func registryTrees(t *testing.T, editHead func(string) string, headDefs []constraintengine.FactDefinition) (Tree, Tree) {
	t.Helper()
	base, head := trees(t)
	src := registrySource(t)
	writeFile(t, filepath.Join(base.Root, filepath.FromSlash(cncfRegistrySource)), []byte(src))
	writeFile(t, filepath.Join(head.Root, filepath.FromSlash(cncfRegistrySource)), []byte(editHead(src)))
	setRegistryDigest(t, head, registryDigestOf(t, headDefs), headDefs)
	return base, head
}

func addedDefinitions() []constraintengine.FactDefinition {
	return append(cncfcheck.CompiledFactDefinitions(), addedFact)
}

// signRegistry signs the approval of the registry change between base and
// head, as the owner's sign command does, and returns the file.
func signRegistry(t *testing.T, key testApprovalKey, base, head Tree) []byte {
	t.Helper()
	subject, addition, err := RegistryApprovalSubject(cncfSpec(t), base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(addition.Added) != 1 || addition.Added[0].ID != addedFact.ID {
		t.Fatalf("added %v", addition.Added)
	}
	keysRaw, err := base.Read(DefaultLayout().ApprovalKeysPath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := LoadApprovalKeys(keysRaw, pinnedDigest(keysRaw))
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := SignApproval(SignApprovalOptions{Subject: subject, CandidateID: "cand-1", Identity: "airstand", Keys: keys, Key: key.private, Now: gateNow.Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func registryApprovalFile(tr Tree) string {
	return filepath.Join(tr.Root, filepath.FromSlash(registryApprovalPath(DefaultLayout(), evidencereattest.PackCNCF)))
}

func registryChangeOf(t *testing.T, r *Report) *Change {
	t.Helper()
	for _, c := range r.Changes {
		if c.Pack == evidencereattest.PackCNCF && c.Member == registryMember {
			return c
		}
	}
	t.Fatal("no registryDigest change")
	return nil
}

func TestRegistryDocumentIsWhatTheDigestCovers(t *testing.T) {
	r, err := constraintengine.NewCompiledRegistry(addedDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	if CandidateDigest(r.Document()) != r.Digest() {
		t.Fatal("the approval base digest of the registry document is not the registry digest")
	}
}

func TestParsePackagedDefinitionsReadsTheShippedSource(t *testing.T) {
	literal, err := parsePackagedDefinitions([]byte(registrySource(t)))
	if err != nil {
		t.Fatal(err)
	}
	compiled := map[string]constraintengine.FactDefinition{}
	for _, d := range cncfcheck.CompiledFactDefinitions() {
		n, err := normalDefinition(d)
		if err != nil {
			t.Fatal(err)
		}
		compiled[d.ID] = n
	}
	if len(literal) == 0 {
		t.Fatal("no literal definition read")
	}
	for _, d := range literal {
		n, err := normalDefinition(d)
		if err != nil || !sameDefinition(compiled[d.ID], n) {
			t.Fatalf("%s does not read as compiled", d.ID)
		}
	}
}

func TestGateRegistryAddition(t *testing.T) {
	key := newApprovalKey(t)

	t.Run("admitted", func(t *testing.T) {
		base, head := registryTrees(t, withAdded, addedDefinitions())
		key.pinBoth(t, base, head, "airstand")
		writeFile(t, registryApprovalFile(head), signRegistry(t, key, base, head))
		r := runGate(t, Options{Base: base, Head: head})
		requirePass(t, r)
		c := registryChangeOf(t, r)
		if !c.OK || c.Proof != ProofApproval {
			t.Fatalf("ok %v proof %q", c.OK, c.Proof)
		}
		if !strings.Contains(strings.Join(r.AutoMerge.Reasons, "\n"), "adds fact definitions") {
			t.Fatalf("auto-merge reasons %v", r.AutoMerge.Reasons)
		}
	})

	removedLine := func(src string) string { return strings.Replace(withAdded(src), existingLine+"\n", "", 1) }
	without := func(id string) []constraintengine.FactDefinition {
		var out []constraintengine.FactDefinition
		for _, d := range addedDefinitions() {
			if d.ID != id {
				out = append(out, d)
			}
		}
		return out
	}
	changed := func(id string, edit func(*constraintengine.FactDefinition)) []constraintengine.FactDefinition {
		out := addedDefinitions()
		for i := range out {
			if out[i].ID == id {
				edit(&out[i])
			}
		}
		return out
	}
	existingID := "component.argo_cd.disable_fine_grained_inheritance"
	enumID := "component.argo_cd.latest_distribution"
	cases := map[string]struct {
		editHead func(string) string
		headDefs []constraintengine.FactDefinition
		setup    func(t *testing.T, base, head Tree, opts *Options)
		want     string
	}{
		"definition removed": {removedLine, without(existingID), nil, "fact definitions removed or renamed: " + existingID},
		"definition retyped": {func(src string) string {
			return strings.Replace(withAdded(src), existingLine, strings.Replace(existingLine, "constraintengine.FactBool", "constraintengine.FactSet", 1), 1)
		}, changed(existingID, func(d *constraintengine.FactDefinition) { d.Type = constraintengine.FactSet }), nil, "fact definitions retyped: " + existingID},
		"component changed": {func(src string) string {
			return strings.Replace(withAdded(src), existingLine, strings.Replace(existingLine, "pkg:github/argoproj/argo-cd", "pkg:github/argoproj/argo-cd-fork", 1), 1)
		}, changed(existingID, func(d *constraintengine.FactDefinition) { d.Component = "pkg:github/argoproj/argo-cd-fork" }), nil, "fact definitions moved to another component: " + existingID},
		"head digest names another list": {withAdded, append(addedDefinitions(), constraintengine.FactDefinition{ID: "component.argo_cd.another_addition", Component: "pkg:github/argoproj/argo-cd", Type: constraintengine.FactBool}), nil, "the head registryDigest is not the digest of the head's fact definitions"},
		"base digest is not the gate's registry": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			setRegistryDigest(t, base, registryDigestOf(t, without(existingID)), without(existingID))
		}, "the base registryDigest is not the digest of the gate's own fact registry"},
		"head source not in the literal form": {func(src string) string {
			return strings.Replace(withAdded(src), "customResourceVersionDefinitions()...)", "customResourceVersionDefinitions()[0:]...)", 1)
		}, addedDefinitions(), nil, "packagedDefinitions is not in the literal form this gate reads"},
		"enum tokens changed": {func(src string) string {
			return strings.Replace(withAdded(src), enumLine, strings.Replace(enumLine, `"official_upstream"}`, `"official_upstream", "vendor_build"}`, 1), 1)
		}, changed(enumID, func(d *constraintengine.FactDefinition) { d.EnumTokens = append(d.EnumTokens, "vendor_build") }), nil, "fact definitions with other enum tokens: " + enumID},
		"trust material changed too": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			key.pin(t, head, "airstand", "other-owner")
		}, "trust material changed in the same change"},
		"addition outside the literal list": {func(src string) string { return src }, addedDefinitions(), nil, "the head adds no fact definition"},
		"no approval": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			if err := os.Remove(registryApprovalFile(head)); err != nil {
				t.Fatal(err)
			}
		}, "no owner approval"},
		"no keys configured": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			opts.ApprovalKeysDigest = "none"
		}, "no owner approval key digest is configured"},
		"invalid signature": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			env := decodeTestApproval(t, head)
			writeFile(t, registryApprovalFile(head), newApprovalKey(t).sign(t, env.Record))
		}, "signed by a key that is not pinned"},
		"wrong subject": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			env := decodeTestApproval(t, head)
			env.Record.Subject, env.Record.Scope = "", ""
			writeFile(t, registryApprovalFile(head), key.sign(t, env.Record))
		}, "approves a different kind of subject"},
		"approval over another id list": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			env := decodeTestApproval(t, head)
			other := []constraintengine.FactDefinition{addedFact, {ID: "component.argo_cd.another_addition", Component: "pkg:github/argoproj/argo-cd", Type: constraintengine.FactBool}}
			canonical, err := extract.Canonical(RegistryAddition{Schema: RegistryAdditionSchema, BaseRegistryDigest: registryDigestOf(t, cncfcheck.CompiledFactDefinitions()), HeadRegistryDigest: registryDigestOf(t, addedDefinitions()), Added: other})
			if err != nil {
				t.Fatal(err)
			}
			env.Record.CandidateDigest = CandidateDigest(canonical)
			writeFile(t, registryApprovalFile(head), key.sign(t, env.Record))
		}, "candidate digest does not match"},
		"approval already in the base": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			raw, err := os.ReadFile(registryApprovalFile(head))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, registryApprovalFile(base), raw)
		}, "the owner approval is already in the base"},
		"revision changed too": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			editRegistryPack(t, head, addedDefinitions(), func(p *packDoc) { p.fields["revision"] = json.RawMessage(`"registry-test-revision"`) })
		}, "another top-level member changed in the same change: cncf revision"},
		"schema changed too": {withAdded, addedDefinitions(), func(t *testing.T, base, head Tree, opts *Options) {
			editRegistryPack(t, head, addedDefinitions(), func(p *packDoc) { p.fields["schema"] = json.RawMessage(`"prufyx.io/registry-test-schema/v1"`) })
		}, "a schema-level change of the cncf pack is in the same change"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			base, head := registryTrees(t, tc.editHead, tc.headDefs)
			key.pinBoth(t, base, head, "airstand")
			if strings.HasPrefix(name, "definition") || name == "component changed" || name == "enum tokens changed" || name == "addition outside the literal list" || name == "head digest names another list" || name == "head source not in the literal form" {
				// The change cannot be read as an addition, so there is
				// nothing to sign: any approval file is refused before it
				// is read.
				writeFile(t, registryApprovalFile(head), []byte("{}\n"))
			} else {
				writeFile(t, registryApprovalFile(head), signRegistry(t, key, base, head))
			}
			opts := Options{Base: base, Head: head}
			if tc.setup != nil {
				tc.setup(t, base, head, &opts)
			}
			r := runGate(t, opts)
			requireFail(t, r, tc.want)
			if c := registryChangeOf(t, r); c.OK {
				t.Fatal("the registry change was admitted")
			}
		})
	}
}

func decodeTestApproval(t *testing.T, head Tree) ApprovalEnvelope {
	t.Helper()
	raw, err := os.ReadFile(registryApprovalFile(head))
	if err != nil {
		t.Fatal(err)
	}
	env, err := decodeApproval(raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestApprovalCLIRegistryAddition(t *testing.T) {
	key := newApprovalKey(t)
	base, head := registryTrees(t, withAdded, addedDefinitions())
	key.pinBoth(t, base, head, "airstand")
	keys := filepath.Join(base.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath))
	keysRaw, err := os.ReadFile(keys)
	if err != nil {
		t.Fatal(err)
	}
	subject := []string{"--subject", "registryDigest", "--pack", "cncf", "--base-root", base.Root, "--head-root", head.Root, "--keys", keys, "--keys-digest", pinnedDigest(keysRaw)}
	out := registryApprovalFile(head)
	r := runApproval(t, nil, signNow, append(append([]string{"sign"}, subject...), "--identity", "airstand", "--candidate-id", "cand-1", "--key", key.keyFile(t, 0o600), "--output", out)...)
	if r.code != 0 || !strings.Contains(r.stdout, "fact registry addition cncf/"+RegistryApprovalID) {
		t.Fatalf("sign: %d %s %s", r.code, r.stdout, r.stderr)
	}
	r = runApproval(t, nil, signNow, append(append([]string{"verify"}, subject...), "--approval", out)...)
	if r.code != 0 || !strings.HasPrefix(r.stdout, "approval OK") {
		t.Fatalf("verify: %d %s %s", r.code, r.stdout, r.stderr)
	}
	requirePass(t, runGate(t, Options{Base: base, Head: head}))

	// The same approval for another head is refused.
	writeFile(t, filepath.Join(head.Root, filepath.FromSlash(cncfRegistrySource)), []byte(strings.Replace(withAdded(registrySource(t)), "synthetic_registry_addition", "synthetic_registry_addition_other", 1)))
	other := append(cncfcheck.CompiledFactDefinitions(), constraintengine.FactDefinition{ID: addedFact.ID + "_other", Component: addedFact.Component, Type: addedFact.Type})
	setRegistryDigest(t, head, registryDigestOf(t, other), other)
	r = runApproval(t, nil, signNow, append(append([]string{"verify"}, subject...), "--approval", out)...)
	if r.code != 1 || !strings.Contains(r.stdout, "candidate digest does not match") {
		t.Fatalf("verify of another head: %d %s %s", r.code, r.stdout, r.stderr)
	}
	r = runApproval(t, nil, signNow, "verify", "--subject", "registryDigest", "--pack", "cncf", "--head-root", head.Root, "--keys", keys, "--keys-digest", pinnedDigest(keysRaw), "--approval", out)
	if r.code != 2 || !strings.Contains(r.stderr, "--base-root is required") {
		t.Fatalf("verify without --base-root: %d %s %s", r.code, r.stdout, r.stderr)
	}
}

func TestRegistryStatementIsCanonicalJSON(t *testing.T) {
	base, err := constraintengine.NewCompiledRegistry(cncfcheck.CompiledFactDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	head, err := constraintengine.NewCompiledRegistry(addedDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := registryStatement(base, head, []constraintengine.FactDefinition{addedFact})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"added\": [\n    {\n      \"component\": \"pkg:github/argoproj/argo-cd\",\n      \"enumTokens\": null,\n      \"id\": \"component.argo_cd.synthetic_registry_addition\",\n      \"type\": \"bool\"\n    }\n  ],\n  \"baseRegistryDigest\": \"" + base.Digest() + "\",\n  \"headRegistryDigest\": \"" + head.Digest() + "\",\n  \"schema\": \"prufyx.io/fact-registry-addition/v1\"\n}\n"
	if string(raw) != want {
		t.Fatalf("statement:\n%s", raw)
	}
}
