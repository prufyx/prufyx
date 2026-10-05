// SPDX-License-Identifier: AGPL-3.0-only

package consensus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const silentDial = "- Removed the SilentDial feature gate. ([#140005](https://github.com/kubernetes/kubernetes/pull/140005), [@dev-h](https://github.com/dev-h)) [SIG Node]"

// notes is a minimal v1.41 release notes file with body as the v1.41.0
// section.
func notes(body string) []byte {
	return []byte("# v1.41.1\n\n- Fixed a crash. (#140101)\n\n# v1.41.0\n\n## Changes by Kind\n\n### Deprecation\n\n" + body + "\n\n# v1.41.0-rc.1\n\n- Bumped the toolchain. (#140009)\n")
}

func gateClaim(names ...string) []Claim {
	return []Claim{{ID: "c1", Kind: "removed_feature_gate", Names: names}}
}

type stubInventories struct{ err error }

func (s stubInventories) Inventory(context.Context, string, extract.RepoRef, string) (*Inventory, error) {
	return nil, s.err
}

type stubHistory struct{ err error }

func (s stubHistory) RangeSubjects(extract.RepoRef, string, string, int) ([]CommitSubject, error) {
	return nil, s.err
}

func (s stubHistory) OnBranch(extract.RepoRef, string, string, string) (bool, error) {
	return false, s.err
}

// prLink is a pull request reference as the line grammar accepts it.
func prLink(n string) string {
	return "([#" + n + "](https://github.com/kubernetes/kubernetes/pull/" + n + "))"
}

func onlyClaim(t *testing.T, rep *Report) ClaimResult {
	t.Helper()
	if len(rep.Claims) != 1 {
		t.Fatalf("%d claims", len(rep.Claims))
	}
	return rep.Claims[0]
}

// Every reason, each produced by the step that owns it.
func TestVerifyReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   string
		claims []Claim
		bundle func(*Bundle)
		inputs func(*Inputs, string)
		want   string
	}{
		{name: "verified", body: silentDial, want: "verified:"},
		{name: "file digest", body: silentDial, bundle: func(b *Bundle) { b.Source.FileSHA256 = FileDigest(nil) }, want: "dropped:source-mismatch"},
		{name: "normalised digest", body: silentDial, bundle: func(b *Bundle) { b.Source.NormalisedSHA256 = FileDigest(nil) }, want: "dropped:source-mismatch"},
		{name: "normaliser version", body: silentDial, bundle: func(b *Bundle) { b.Source.NormaliserVersion = "0" }, want: "dropped:source-mismatch"},
		{name: "source path missing", body: silentDial, bundle: func(b *Bundle) { b.Source.Path = "CHANGELOG/CHANGELOG-1.41.md.orig" }, want: "dropped:source-refused"},
		{name: "source refused", body: silentDial + "\n# v1.41.0\n", want: "dropped:source-refused"},
		{name: "section is not the later release", body: silentDial, bundle: func(b *Bundle) { b.Source.Section = "v1.40.0" }, want: "dropped:release-mismatch"},
		{name: "earlier release not the previous minor", body: silentDial, bundle: func(b *Bundle) { b.FromRelease.Tag = "v1.39.0" }, want: "dropped:release-mismatch"},
		{name: "earlier release commit", body: silentDial, bundle: func(b *Bundle) { b.FromRelease.Commit = toCommit }, want: "dropped:release-mismatch"},
		{name: "other repository", body: silentDial, bundle: func(b *Bundle) { b.FromRelease.Repo = "github.com/example/other" }, want: "dropped:release-mismatch"},
		{name: "kind", body: silentDial, claims: []Claim{{ID: "c1", Kind: "removed_flag", Names: []string{"--silent-dial"}}}, want: "lead:kind-not-allowed"},
		{name: "component", body: silentDial, claims: []Claim{{ID: "c1", Kind: "removed_feature_gate", Component: "kubelet", Names: []string{"SilentDial"}}}, want: "lead:kind-not-allowed"},
		{name: "name form", body: silentDial, claims: gateClaim("silentDial"), want: "dropped:name-invalid"},
		{name: "name twice", body: silentDial, claims: gateClaim("SilentDial", "SilentDial"), want: "dropped:name-invalid"},
		{name: "api version form", body: silentDial, claims: []Claim{{ID: "c1", Kind: "removed_api_version", Names: []string{"Gizmo"}}}, want: "dropped:name-invalid"},
		{name: "no cue", body: "- The SilentDial feature gate is GA. (#140005)", want: "dropped:no-cited-cue"},
		{name: "not an item", body: "Removed the SilentDial feature gate. (#140005)", want: "dropped:no-cited-cue"},
		{name: "ambiguous", body: silentDial + "\n- Removed SilentDial and EchoSwitch. (#140010)", want: "lead:ambiguous-citation"},
		{name: "hidden", body: "- Removed the Silent\u200bDial feature gate. " + prLink("140005"), want: "lead:hidden-content"},
		{name: "unparsed", body: silentDial + "\n- Updated <b>docs</b>.", want: "lead:unparsed-section"},
		{name: "unparsed outside the cited item", body: silentDial + "\n\n```\nx\n```", want: "lead:unparsed-section"},
		{name: "name in another, unparsed section", body: silentDial + "\n\n### Other\n\n- Restored the SilentDial gate <b>here</b>.", want: "lead:unparsed-section"},
		{name: "unparsed section without the name", body: silentDial + "\n\n### Other\n\n- Updated <b>docs</b>.", want: "verified:"},
		{name: "name spelled with references in an unparsed section", body: silentDial + "\n\n### Other\n\n- Restored Silent&#68;ial <b>here</b>.", want: "lead:unparsed-section"},
		{name: "name named again without a cue", body: silentDial + "\n- The SilentDial feature gate is back. " + prLink("140006"), want: "lead:ambiguous-citation"},
		{name: "unparsed child section", body: silentDial + "\n\n#### Child\n\n- Updated <b>docs</b>.", want: "lead:unparsed-section"},
		{name: "negated cue", body: "- The SilentDial feature gate is not removed in this release. " + prLink("140005"), want: "lead:hedged-cue"},
		{name: "future removal", body: "- The SilentDial feature gate will be removed in v1.43. " + prLink("140005"), want: "lead:hedged-cue"},
		{name: "reverted removal", body: "- Reverted the removal of the SilentDial feature gate. " + prLink("140005"), want: "lead:hedged-cue"},
		{name: "source unbound", body: silentDial, bundle: func(b *Bundle) { b.Source.Commit = strings.Repeat("f", 40) }, want: "dropped:source-unbound"},
		{name: "inventory incomplete", body: silentDial, inputs: func(in *Inputs, _ string) { in.Inventory = stubInventories{&Incomplete{Reason: "test"}} }, want: "lead:inventory-incomplete"},
		{name: "not in inventory", body: "- Removed the GhostGate feature gate. (#140005)", claims: gateClaim("GhostGate"), want: "dropped:not-in-inventory"},
		{name: "still present", body: "- Removed the StableThing feature gate. (#140005)", claims: gateClaim("StableThing"), want: "dropped:still-present"},
		{name: "no pull request", body: "- Removed the SilentDial feature gate. [SIG Node]", want: "lead:no-provenance"},
		{name: "pull request not in range", body: "- Removed the SilentDial feature gate. " + prLink("149999"), want: "lead:no-provenance"},
		{name: "bare pull request number", body: "- Removed the SilentDial feature gate. (#140005)", want: "lead:no-provenance"},
		{name: "range too long", body: silentDial, inputs: func(in *Inputs, _ string) { in.HistoryLimit = 3 }, want: "lead:provenance-unbounded"},
		{name: "no history", body: silentDial, inputs: func(in *Inputs, _ string) { in.History = nil }, want: "lead:provenance-unavailable"},
		{name: "fixture without history", body: silentDial, inputs: func(in *Inputs, root string) {
			os.Remove(filepath.Join(root, "github.com", "kubernetes", "kubernetes", "history.json"))
		}, want: "lead:provenance-unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureWith(t, notes(tc.body))
			claims := tc.claims
			if claims == nil {
				claims = gateClaim("SilentDial")
			}
			b := honestBundle(t, root, claims)
			if tc.bundle != nil {
				tc.bundle(b)
			}
			in := fixtureInputs(root)
			if tc.inputs != nil {
				tc.inputs(&in, root)
			}
			rep, err := Verify(context.Background(), b, in)
			if err != nil {
				t.Fatal(err)
			}
			c := onlyClaim(t, rep)
			if got := c.Verdict + ":" + c.Reason; got != tc.want {
				t.Fatalf("%s (%s), want %s", got, c.Detail, tc.want)
			}
		})
	}
}

// The first failing step decides.
func TestVerifyStepOrder(t *testing.T) {
	root := fixtureWith(t, notes("- The GhostGate is GA. (#149999)"))
	b := honestBundle(t, root, []Claim{
		{ID: "a", Kind: "removed_flags", Names: []string{"ghost gate"}},
		{ID: "b", Kind: "removed_feature_gate", Names: []string{"ghost gate"}},
		{ID: "c", Kind: "removed_feature_gate", Names: []string{"GhostGate"}},
		{ID: "d", Kind: "removed_feature_gate", Names: []string{"SilentDial", "GhostGate"}},
	})
	b.Source.FileSHA256 = FileDigest([]byte("x"))
	rep := verifyFixture(t, root, b)
	for _, c := range rep.Claims {
		if c.Reason != ReasonSourceMismatch {
			t.Fatalf("%s: %s, want source-mismatch first", c.ID, c.Reason)
		}
	}
	b = honestBundle(t, root, b.Claims)
	rep = verifyFixture(t, root, b)
	want := []string{"kind-not-allowed", "name-invalid", "no-cited-cue", "no-cited-cue"}
	for i, c := range rep.Claims {
		if c.Reason != want[i] {
			t.Fatalf("%s: %s, want %s", c.ID, c.Reason, want[i])
		}
	}
	if rep.Summary != (Summary{Lead: 1, Dropped: 3}) {
		t.Fatalf("summary %+v", rep.Summary)
	}
}

// A phantom name is dropped even when every other check passes; a name in
// the earlier release's inventory goes on to the next check.
func TestExistenceCheck(t *testing.T) {
	root := fixtureWith(t, notes("- Removed the GhostGate and SilentDial feature gates, and stopped serving ghosts.example.io/v1beta1 and gizmos.example.io/v1beta1. "+prLink("140005")))
	rep := verifyFixture(t, root, honestBundle(t, root, []Claim{
		{ID: "ghost", Kind: "removed_feature_gate", Names: []string{"GhostGate"}},
		{ID: "pair", Kind: "removed_feature_gate", Names: []string{"SilentDial", "GhostGate"}},
		{ID: "real", Kind: "removed_feature_gate", Names: []string{"SilentDial"}},
		{ID: "ghost-api", Kind: "removed_api_version", Names: []string{"ghosts.example.io/v1beta1"}},
		{ID: "real-api", Kind: "removed_api_version", Names: []string{"gizmos.example.io/v1beta1"}},
	}))
	got := map[string]string{}
	for _, c := range rep.Claims {
		got[c.ID] = c.Verdict + ":" + c.Reason
	}
	want := map[string]string{
		"ghost": "dropped:not-in-inventory", "pair": "dropped:not-in-inventory", "real": "verified:",
		"ghost-api": "dropped:not-in-inventory", "real-api": "verified:",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("verdicts %v, want %v", got, want)
	}
}

// An inventory that cannot be established completely never answers
// "absent": the claim stays a lead. A file the mirror does not hold makes
// the inputs incomplete instead (see TestConsensusCommands).
func TestInventoryIncomplete(t *testing.T) {
	base := filepath.Join("github.com", "kubernetes", "kubernetes", "commits")
	for _, tc := range []struct {
		name   string
		claim  Claim
		damage func(root string)
	}{
		{"feature gate registry of the earlier release", gateClaim("SilentDial")[0], func(root string) {
			p := filepath.Join(root, base, fromCommit, "staging/src/k8s.io/component-base/featuregate/feature_gate.go")
			raw, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.ReplaceAll(raw, []byte("unrecognized feature gate"), []byte("unknown gate")), 0o644)
		}},
		{"feature gate registry of the later release", gateClaim("SilentDial")[0], func(root string) {
			os.WriteFile(filepath.Join(root, base, toCommit, "pkg/features/kube_features.go"), []byte("package features\n\nvar x = map[featuregate.Feature]featuregate.FeatureSpec{y: {}}\n"), 0o644)
		}},
		{"missing specification", Claim{ID: "c1", Kind: "removed_api_version", Names: []string{"gizmos.example.io/v1beta1"}}, func(root string) {
			os.Remove(filepath.Join(root, base, fromCommit, "api/openapi-spec/swagger.json"))
		}},
		{"specification without kinds", Claim{ID: "c1", Kind: "removed_api_version", Names: []string{"gizmos.example.io/v1beta1"}}, func(root string) {
			os.WriteFile(filepath.Join(root, base, toCommit, "api/openapi-spec/swagger.json"), []byte(`{"swagger":"2.0","definitions":{}}`), 0o644)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureWith(t, notes("- Removed the SilentDial feature gate and gizmos.example.io/v1beta1. (#140005)"))
			tc.damage(root)
			c := onlyClaim(t, verifyFixture(t, root, honestBundle(t, root, []Claim{tc.claim})))
			if c.Verdict != VerdictLead || c.Reason != ReasonInventoryIncomplete {
				t.Fatalf("%s:%s (%s)", c.Verdict, c.Reason, c.Detail)
			}
		})
	}
}

func TestProvenance(t *testing.T) {
	k := "https://github.com/kubernetes/kubernetes/pull/"
	for _, tc := range []struct {
		name, ref, want string
	}{
		{"squash subject", prLink("140005"), "verified:"},
		{"merge subject", prLink("140006"), "verified:"},
		{"merge commit with a parent before the range", prLink("140010"), "verified:"},
		{"two links in range", "([#140005](" + k + "140005), [#140006](" + k + "140006), [@dev-h](https://github.com/dev-h))", "verified:"},
		{"not in range", prLink("149999"), "lead:no-provenance"},
		{"merged before the range", prLink("139990"), "lead:no-provenance"},
		{"one of two not in range", "([#140005](" + k + "140005), [#149999](" + k + "149999))", "lead:no-provenance"},
		{"link text and target differ", "([#140005](" + k + "140006))", "lead:no-provenance"},
		{"link text not a number", "([details](" + k + "140005))", "lead:no-provenance"},
		{"issue link", "([#140005](https://github.com/kubernetes/kubernetes/issues/140005))", "lead:no-provenance"},
		{"link in a code span", "(`[#140005](" + k + "140005)`)", "lead:no-provenance"},
		{"bare number", "(#140005)", "lead:no-provenance"},
		{"bare URL", k + "140005", "lead:no-provenance"},
		{"URL inside another host's URL", "(https://evil.example/" + k + "140005)", "lead:no-provenance"},
		{"another repository's URL", "https://github.com/example/kubernetes/pull/140005", "lead:no-provenance"},
		{"another repository's shorthand", "(example/kubernetes#140005)", "lead:no-provenance"},
		{"HTML entity", "(&#140005;)", "lead:no-provenance"},
		{"no reference", "[SIG Node]", "lead:no-provenance"},
		{"another repository's link", "([#140005](https://github.com/example/kubernetes/pull/140005))", "lead:unparsed-section"},
		{"upper-case repository in the link", "([#140005](https://github.com/Kubernetes/Kubernetes/pull/140005))", "lead:unparsed-section"},
		{"link title", "([details](https://kubernetes.io/notes \"#140005\"))", "lead:unparsed-section"},
		{"another host's link", "([#140005](https://evil.example/kubernetes/kubernetes/pull/140005))", "lead:unparsed-section"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixtureWith(t, notes("- Removed the SilentDial feature gate. "+tc.ref))
			c := onlyClaim(t, verifyFixture(t, root, honestBundle(t, root, gateClaim("SilentDial"))))
			if got := c.Verdict + ":" + c.Reason; got != tc.want {
				t.Fatalf("%s (%s), want %s", got, c.Detail, tc.want)
			}
			if c.Verdict == VerdictVerified && (len(c.Provenance) == 0 || !extract.IsCommitSHA(c.Provenance[0].Commit)) {
				t.Fatalf("provenance %+v", c.Provenance)
			}
		})
	}
	// A range end missing from the history is an incomplete input.
	root := fixtureWith(t, notes(silentDial))
	in := fixtureInputs(root)
	in.History = stubHistory{ErrHistoryIncomplete}
	if _, err := Verify(context.Background(), honestBundle(t, root, gateClaim("SilentDial")), in); !errors.Is(err, ErrInputsIncomplete) {
		t.Fatalf("err %v", err)
	}
}

func TestPRReferences(t *testing.T) {
	repo := extract.RepoRef{Key: KubernetesRepo}
	k := "https://github.com/kubernetes/kubernetes/pull/"
	for _, tc := range []struct {
		text       string
		refs       []int
		consistent bool
	}{
		{"x ([#1](" + k + "1), [#22](" + k + "22))", []int{1, 22}, true},
		{"[#5](" + k + "5) and [@u](https://github.com/u)", []int{5}, true},
		{"[#5](https://github.com/other/kubernetes/pull/5)", nil, true},
		{"[#5](" + k + "6)", []int{6}, false},
		{"[see #5](" + k + "5)", []int{5}, false},
		{"x (#1, #22) " + k + "3 other/repo#7", nil, true},
		{"`[#5](" + k + "5)`", nil, true},
		{"[#5](" + k + "5/files)", nil, true},
		{"[#5](https://github.com/kubernetes/kubernetes/issues/5)", nil, true},
	} {
		refs, consistent := prReferences(tc.text, repo)
		if !reflect.DeepEqual(refs, tc.refs) || consistent != tc.consistent {
			t.Errorf("%q: %v %v, want %v %v", tc.text, refs, consistent, tc.refs, tc.consistent)
		}
	}
}

// The release notes must be the release's own: read at a release tag
// commit of its minor line, or at a commit of its release branch after
// the tag. Anything else is dropped before the notes are read.
func TestSourceBinding(t *testing.T) {
	for _, tc := range []struct {
		name, commit string
		inputs       func(*Inputs)
		tags         string
		want         string
	}{
		{name: "tag commit", commit: toCommit, want: "verified:"},
		{name: "release branch after the tag", commit: branchCommit, want: "verified:"},
		{name: "descends from the tag, not on the branch", commit: offBranchCommit, want: "dropped:source-unbound"},
		{name: "not in the history", commit: strings.Repeat("f", 40), want: "dropped:source-unbound"},
		{name: "earlier release's commit", commit: fromCommit, want: "dropped:source-unbound"},
		{name: "branch commit without a history", commit: branchCommit, inputs: func(in *Inputs) { in.History = nil }, want: "dropped:source-unbound"},
		{name: "branch commit, history unavailable", commit: branchCommit, inputs: func(in *Inputs) { in.History = stubHistory{ErrHistoryUnavailable} }, want: "dropped:source-unbound"},
		{name: "patch tag commit without a history", commit: branchCommit, tags: `{"v1.40.0": "` + fromCommit + `", "v1.41.0": "` + toCommit + `", "v1.41.1": "` + branchCommit + `"}`,
			inputs: func(in *Inputs) { in.History = nil }, want: "lead:provenance-unavailable"},
		{name: "pre-release tag commit is not bound", commit: strings.Repeat("c", 40), tags: `{"v1.40.0": "` + fromCommit + `", "v1.41.0": "` + toCommit + `", "v1.41.0-rc.1": "` + strings.Repeat("c", 40) + `"}`,
			inputs: func(in *Inputs) { in.History = nil }, want: "dropped:source-unbound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := notes(silentDial)
			root := fixtureWith(t, text)
			if tc.commit != toCommit {
				placeNotes(t, root, tc.commit, text)
			}
			if tc.tags != "" {
				os.WriteFile(filepath.Join(root, "github.com", "kubernetes", "kubernetes", "tags.json"), []byte(tc.tags), 0o644)
			}
			b := honestBundle(t, root, gateClaim("SilentDial"))
			b.Source.Commit = tc.commit
			in := fixtureInputs(root)
			if tc.inputs != nil {
				tc.inputs(&in)
			}
			rep, err := Verify(context.Background(), b, in)
			if err != nil {
				t.Fatal(err)
			}
			c := onlyClaim(t, rep)
			if got := c.Verdict + ":" + c.Reason; got != tc.want {
				t.Fatalf("%s (%s), want %s", got, c.Detail, tc.want)
			}
		})
	}
}

// Every identical copy of a cited item is checked for hidden content, not
// only the first.
func TestHiddenContentOnEveryCopy(t *testing.T) {
	hidden := strings.Replace(silentDial, "feature gate", "feature\u200b gate", 1)
	root := fixtureWith(t, notes(silentDial+"\n"+hidden))
	c := onlyClaim(t, verifyFixture(t, root, honestBundle(t, root, gateClaim("SilentDial"))))
	if c.Verdict != VerdictLead || c.Reason != ReasonHiddenContent {
		t.Fatalf("%s:%s (%s)", c.Verdict, c.Reason, c.Detail)
	}
}

// Verify stops between claims when its context ends.
func TestVerifyContext(t *testing.T) {
	root := fixtureWith(t, notes(silentDial))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Verify(ctx, honestBundle(t, root, gateClaim("SilentDial")), fixtureInputs(root)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

func TestContainsToken(t *testing.T) {
	for _, tc := range []struct {
		text, name string
		want       bool
	}{
		{"Removed `SilentDial`.", "SilentDial", true},
		{"Removed SilentDial, EchoSwitch", "SilentDial", true},
		{"Removed SilentDialV2", "SilentDial", false},
		{"Removed XSilentDial", "SilentDial", false},
		{"Removed SilentDial-related", "SilentDial", false},
		{"Removed SilentDial\u0301", "SilentDial", false},
		{"Removed Silent_Dial SilentDial_x", "SilentDial", false},
		{"apps.example.io/v1beta1.", "apps.example.io/v1beta1", true},
		{"x.apps.example.io/v1beta1", "apps.example.io/v1beta1", false},
		{"apps.example.io/v1beta10", "apps.example.io/v1beta1", false},
		{"apps.example.io/v1beta1.x", "apps.example.io/v1beta1", false},
		{"/apis/apps.example.io/v1beta1", "apps.example.io/v1beta1", false},
		{"SilentDialSilentDial SilentDial", "SilentDial", true},
	} {
		if got := containsToken(tc.text, tc.name); got != tc.want {
			t.Errorf("containsToken(%q, %q) = %v", tc.text, tc.name, got)
		}
	}
}

func TestListItems(t *testing.T) {
	n := mustNormalise(t, doc("intro\n- a\n  cont\n  - nested\n* b\n\n- d\n### h\nloose"))
	var got []string
	for _, it := range listItems(n) {
		got = append(got, it.text)
	}
	want := []string{"- a\n  cont", "  - nested", "* b", "- d"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("items %q, want %q", got, want)
	}
}

func TestDecodeBundleStrict(t *testing.T) {
	root := fixtureWith(t, notes(silentDial))
	good, err := extract.Canonical(honestBundle(t, root, gateClaim("SilentDial")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBundle(good); err != nil {
		t.Fatalf("good bundle: %v", err)
	}
	s := string(good)
	for name, bad := range map[string]string{
		"unknown top-level field": strings.Replace(s, `"schema":`, `"quote": "x", "schema":`, 1),
		"unknown source field":    strings.Replace(s, `"commit": "`+toCommit+`"`, `"commit": "`+toCommit+`", "line": 3`, 1),
		"unknown claim field":     strings.Replace(s, `"id": "c1"`, `"id": "c1", "quote": "Removed"`, 1),
		"repeated member":         strings.Replace(s, `"id": "c1"`, `"id": "c1", "id": "c2"`, 1),
		"case-variant member":     strings.Replace(s, `"id": "c1"`, `"id": "c1", "ID": "c2"`, 1),
		"trailing data":           s + "{}",
		"other schema":            strings.Replace(s, BundleSchema, "prufyx.io/consensus-claims/v2", 1),
		"short commit":            strings.Replace(s, `"commit": "`+toCommit+`"`, `"commit": "abc"`, 1),
		"no claims":               s[:strings.Index(s, `"claims": [`)] + `"claims": [], "fromRelease"` + s[strings.Index(s, `"fromRelease"`)+len(`"fromRelease"`):],
		"bad claim id":            strings.Replace(s, `"id": "c1"`, `"id": "C 1"`, 1),
		"no names":                strings.Replace(s, `"names": [`, `"other": [`, 1),
		"upper-case repository":   strings.Replace(s, `"repo": "github.com/kubernetes/kubernetes"`, `"repo": "github.com/Kubernetes/kubernetes"`, 1),
	} {
		if _, err := DecodeBundle([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dup := strings.Replace(s, `"claims": [`, `"claims": [{"id": "c1", "kind": "removed_feature_gate", "names": ["X"]},`, 1)
	if _, err := DecodeBundle([]byte(dup)); err == nil {
		t.Error("duplicate claim id accepted")
	}
	if _, err := DecodeBundle(append([]byte(" "), bytes.Repeat([]byte(" "), MaxBundleBytes)...)); err == nil {
		t.Error("over-long bundle accepted")
	}
	// At most MaxClaims claims.
	many := honestBundle(t, root, nil)
	for i := 0; i <= MaxClaims; i++ {
		many.Claims = append(many.Claims, Claim{ID: fmt.Sprintf("c%d", i), Kind: "removed_feature_gate", Names: []string{"X"}})
	}
	raw, _ := extract.Canonical(many)
	if _, err := DecodeBundle(raw); err == nil || !strings.Contains(err.Error(), "claims, want 1-500") {
		t.Errorf("%d claims: %v", len(many.Claims), err)
	}
	many.Claims = many.Claims[:MaxClaims]
	raw, _ = extract.Canonical(many)
	if _, err := DecodeBundle(raw); err != nil {
		t.Errorf("%d claims: %v", len(many.Claims), err)
	}
}

func FuzzDecodeBundle(f *testing.F) {
	f.Add([]byte(`{"schema":"prufyx.io/consensus-claims/v1","claims":[]}`))
	f.Add([]byte(`{"schema":"prufyx.io/consensus-claims/v1","source":{},"fromRelease":{},"toRelease":{},"claims":[{"id":"a","kind":"k","names":["N"]}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := DecodeBundle(raw)
		if err != nil {
			return
		}
		if b.Schema != BundleSchema || len(b.Claims) == 0 || !extract.IsCommitSHA(b.Source.Commit) {
			t.Fatalf("accepted %q", raw)
		}
	})
}

func TestReportDeterministic(t *testing.T) {
	root := fixtureWith(t, notes(silentDial+"\n- Removed the OldPortal feature gate. "+prLink("140002")))
	b := honestBundle(t, root, []Claim{
		{ID: "b", Kind: "removed_feature_gate", Names: []string{"OldPortal"}},
		{ID: "a", Kind: "removed_feature_gate", Names: []string{"SilentDial"}},
		{ID: "z", Kind: "removed_flag", Names: []string{"--x"}},
	})
	first, err := verifyFixture(t, root, b).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		again, _ := verifyFixture(t, root, b).Canonical()
		if !bytes.Equal(first, again) {
			t.Fatal("reports differ")
		}
	}
	for _, want := range []string{`"schema": "` + ReportSchema + `"`, `"cueVersion": "` + CueVersion + `"`, `"normaliserVersion": "` + NormaliserVersion + `"`, `"originalLines": [`, `"fromDigest": "sha256:`} {
		if !strings.Contains(string(first), want) {
			t.Fatalf("report lacks %s:\n%s", want, first)
		}
	}
}

// mirrorRepo builds a bare mirror repository under state from commits
// made in a work tree, and returns a git runner for the work tree, the
// bare repository's directory and the commit ids by subject.
func mirrorRepo(t *testing.T, state string, subjects ...string) (func(dir string, args ...string) string, string, []string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	work := filepath.Join(state, "work")
	dir := filepath.Join(state, "mirror", "github.com", "kubernetes", "kubernetes.git")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(in string, args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = in
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + state, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
			"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z"}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(work, "init", "-q", "-b", "main")
	var ids []string
	for _, s := range subjects {
		git(work, "commit", "-q", "--allow-empty", "-m", s)
		ids = append(ids, git(work, "rev-parse", "HEAD"))
	}
	return git, dir, ids
}

// The mirror's commit walk reads commit objects with git, offline.
func TestMirrorHistory(t *testing.T) {
	state := t.TempDir()
	git, dir, ids := mirrorRepo(t, state, "Merge pull request #1 from a/b", "Release commit (#2)", "Remove the X feature gate (#3)", "Merge pull request #4 from c/d", "Later (#5)")
	from, c3, to, later := ids[1], ids[2], ids[3], ids[4]
	work := filepath.Join(state, "work")
	git(work, "branch", "release-1.41", to)
	git(work, "checkout", "-q", "-b", "side", to)
	git(work, "commit", "-q", "--allow-empty", "-m", "Side (#6)")
	side := git(work, "rev-parse", "HEAD")
	git(state, "clone", "-q", "--bare", work, dir)

	repo := extract.RepoRef{Key: KubernetesRepo}
	h := MirrorHistory{State: state}
	got, err := h.RangeSubjects(repo, from, to, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []CommitSubject{{to, "Merge pull request #4 from c/d"}, {c3, "Remove the X feature gate (#3)"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("range %v, want %v", got, want)
	}
	if _, err := h.RangeSubjects(repo, from, to, 1); !errors.Is(err, ErrHistoryUnbounded) {
		t.Fatalf("limit: %v", err)
	}
	if _, err := h.RangeSubjects(repo, from, strings.Repeat("e", 40), 10); !errors.Is(err, ErrHistoryIncomplete) {
		t.Fatalf("unknown commit: %v", err)
	}
	if _, err := (MirrorHistory{State: t.TempDir()}).RangeSubjects(repo, from, to, 10); !errors.Is(err, ErrHistoryIncomplete) {
		t.Fatalf("not mirrored: %v", err)
	}
	for _, tc := range []struct {
		base, commit, branch string
		want                 bool
	}{
		{to, to, "release-1.41", true},
		{c3, to, "release-1.41", true},
		{to, later, "release-1.41", false},
		{to, side, "release-1.41", false},
		{to, from, "release-1.41", false},
		{to, to, "release-1.42", false},
	} {
		ok, err := h.OnBranch(repo, tc.base, tc.commit, tc.branch)
		if err != nil || ok != tc.want {
			t.Errorf("OnBranch(%s, %s, %s) = %v, %v; want %v", tc.base[:7], tc.commit[:7], tc.branch, ok, err, tc.want)
		}
	}
	if _, err := h.OnBranch(repo, to, strings.Repeat("e", 40), "release-1.41"); !errors.Is(err, ErrHistoryIncomplete) {
		t.Fatalf("unknown commit: %v", err)
	}
}

// A mirror's own configuration and refs cannot make the walk run a
// program, fetch, or read replaced commits.
func TestMirrorHistoryIsolated(t *testing.T) {
	state := t.TempDir()
	mark := t.TempDir()
	git, dir, ids := mirrorRepo(t, state, "Release (#2)", "Remove X (#3)")
	work := filepath.Join(state, "work")
	from, c3 := ids[0], ids[1]
	// A signed-looking commit, so a signature check would run gpg.program.
	tree := git(work, "rev-parse", "HEAD^{tree}")
	obj := "tree " + tree + "\nparent " + c3 + "\nauthor t <t@example.invalid> 1767225600 +0000\ncommitter t <t@example.invalid> 1767225600 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQ==\n -----END PGP SIGNATURE-----\n\nSigned (#4)\n"
	objFile := filepath.Join(mark, "obj")
	os.WriteFile(objFile, []byte(obj), 0o644)
	to := git(work, "hash-object", "-t", "commit", "-w", objFile)
	git(work, "update-ref", "refs/heads/main", to)
	git(state, "clone", "-q", "--bare", work, dir)
	// A replacement object that would rename the commit carrying #3.
	fake := strings.Replace(git(dir, "cat-file", "commit", c3), "Remove X (#3)", "Remove Y (#999)", 1)
	os.WriteFile(objFile, []byte(fake+"\n"), 0o644)
	git(dir, "replace", c3, git(dir, "hash-object", "-t", "commit", "-w", objFile))

	script := func(name string) string {
		p := filepath.Join(mark, "bin-"+name)
		os.WriteFile(p, []byte("#!/bin/sh\ntouch "+filepath.Join(mark, "RAN-"+name)+"\nexit 0\n"), 0o755)
		return p
	}
	inc := filepath.Join(mark, "inc.cfg")
	os.WriteFile(inc, []byte("[core]\n\tfsmonitor = "+script("fsmonitor-include")+"\n"), 0o644)
	for k, v := range map[string]string{
		"log.showSignature": "true", "gpg.program": script("gpg"), "core.fsmonitor": script("fsmonitor"),
		"core.pager": script("pager"), "include.path": inc, "core.hooksPath": mark,
		"remote.origin.url": "ext::" + script("ext") + " %S", "remote.origin.promisor": "true",
		"extensions.partialClone": "origin", "protocol.allow": "always",
	} {
		git(dir, "config", k, v)
	}

	h := MirrorHistory{State: state}
	got, err := h.RangeSubjects(extract.RepoRef{Key: KubernetesRepo}, from, to, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Subject != "Remove X (#3)" || got[0].Subject != "Signed (#4)" {
		t.Fatalf("subjects %v", got)
	}
	h.RangeSubjects(extract.RepoRef{Key: KubernetesRepo}, from, strings.Repeat("e", 40), 10)
	entries, _ := os.ReadDir(mark)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "RAN-") {
			t.Errorf("the walk ran %s", e.Name())
		}
	}
}
