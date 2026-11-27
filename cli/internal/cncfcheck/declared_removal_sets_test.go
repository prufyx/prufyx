// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// The rules below are synthetic: they forbid a flag that does not exist, are
// added to syntheticBase only, and are never published.

type declaredRemovalFact struct {
	project, component, id string
}

// declaredRemovalFacts is the closed list of declared-removal set facts.
func declaredRemovalFacts() []declaredRemovalFact {
	return []declaredRemovalFact{
		{"cri-o", "pkg:github/cri-o/cri-o", "component.crio.crio_cli_flags_set"},
		{"etcd", "pkg:github/etcd-io/etcd", "component.etcd.server_cli_flags_set"},
		{"vitess", "pkg:github/vitessio/vitess", "component.vitess.vtgate_cli_flags_set"},
		{"vitess", "pkg:github/vitessio/vitess", "component.vitess.vttablet_cli_flags_set"},
	}
}

const (
	removalMember   = "synthetic-removed-flag"
	removalRevision = "7"
)

var removalNow = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func (f declaredRemovalFact) ruleID(side string) string {
	slug := strings.NewReplacer(".", "-", "_", "-").Replace(strings.TrimPrefix(f.id, "component."))
	return f.project + ".synthetic-" + side + "-" + slug + ".1-8-0-to-1-9-0"
}

// entry is a ranged forbid_set_member rule over the fact on side.
func (f declaredRemovalFact) entry(side string) Entry {
	const rev = "0000000000000000000000000000000000000003"
	repo := strings.TrimPrefix(f.component, "pkg:github/")
	var bounds []string
	for _, b := range [][2]string{{"from.gte", "UPGRADE_FROM_SERIES"}, {"from.lt", "UPGRADE_FROM_SERIES"}, {"to.gte", "TARGET_SERIES"}, {"to.lt", "TARGET_SERIES"}} {
		bounds = append(bounds, fmt.Sprintf(`{"basis":%q,"bound":%q,"sourceId":"source"}`, b[1], b[0]))
	}
	rule := fmt.Sprintf(`{"id":%q,"operator":"forbid_set_member","subject":{"component":%q,"from":"1.8.0","to":"1.9.0"},`+
		`"range":{"from":{"gte":"1.8.0","lt":"1.9.0"},"to":{"gte":"1.9.0","lt":"1.10.0"},"bounds":[%s]},`+
		`"setCondition":{"side":%q,"component":%q,"factId":%q,"members":[%q]},`+
		`"evidence":{"state":"active","reviewedAt":"2026-09-20T00:00:00Z","validUntil":"2026-12-19T00:00:00Z","sources":[{"id":"source","url":"https://github.com/%s/blob/%s/main.go","revision":%q,"contentDigest":"sha256:%s","startLine":1,"endLine":2}]},`+
		`"reasonCode":"SYNTHETIC_FLAG_REMOVED","nextAction":"remove %s before upgrading"}`,
		f.ruleID(side), f.component, strings.Join(bounds, ","), side, f.component, f.id, removalMember, repo, rev, rev, strings.Repeat("0", 64), removalMember)
	return Entry{
		Project:       f.project,
		Description:   "Synthetic test-only removed flag.",
		RequiredFacts: []Fact{{Side: side, ID: f.id, Component: f.component, Type: constraintengine.FactSet, Description: "Flags the binary is started with."}},
		Rule:          json.RawMessage(rule),
	}
}

// input declares one set per side; an empty side string declares nothing.
func (f declaredRemovalFact) input(to, currentSet, proposedSet string) []byte {
	facts := func(set string) string {
		if set == "" {
			return ""
		}
		return fmt.Sprintf(`{"id":%q,"state":"declared","setValue":%s}`, f.id, set)
	}
	return []byte(fmt.Sprintf(`{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":%q,"version":"1.8.0","facts":[%s]}]},"proposed":{"components":[{"component":%q,"version":%q,"facts":[%s]}]}}`,
		f.component, facts(currentSet), f.component, to, facts(proposedSet)))
}

func removalSet(complete bool, members ...string) string {
	if members == nil {
		members = []string{}
	}
	raw, _ := json.Marshal(members)
	return fmt.Sprintf(`{"members":%s,"complete":%t}`, raw, complete)
}

// sideInput declares set on side only.
func (f declaredRemovalFact) sideInput(side, set string) []byte {
	if side == "current" {
		return f.input("1.9.0", set, "")
	}
	return f.input("1.9.0", "", set)
}

func removalBundle(t *testing.T, side string) bundle {
	t.Helper()
	pack := syntheticBase(t)
	for _, f := range declaredRemovalFacts() {
		pack.Entries = append(pack.Entries, f.entry(side))
	}
	sort.SliceStable(pack.Entries, func(i, j int) bool { return ruleID(t, pack.Entries[i]) < ruleID(t, pack.Entries[j]) })
	pack.Schema, pack.Revision = packSchemaSet, "synthetic-test-only"
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	b, err := assembleSynthetic(raw, nil)
	if err != nil {
		t.Fatalf("synthetic declared-removal pack refused: %v", err)
	}
	return b
}

func removalExternal(t *testing.T, b bundle) ExternalBundle {
	t.Helper()
	capability, err := ExternalCapabilityDigest()
	if err != nil {
		t.Fatal(err)
	}
	pack := b.pack
	pack.Revision = removalRevision
	raw, err := json.Marshal(externalFixtureDocument{Schema: externalBundleSchema, Revision: removalRevision, Purpose: "operator_provided", EngineCapabilityDigest: capability, Pack: pack})
	if err != nil {
		t.Fatal(err)
	}
	external, err := ParseExternalBundle(raw)
	if err != nil {
		t.Fatalf("external envelope refused: %v", err)
	}
	return external
}

// removalPaths evaluates raw on every route that reads caller input and
// returns the status of the fact's rule on each.
func removalPaths(t *testing.T, b bundle, external ExternalBundle, f declaredRemovalFact, side string, raw []byte) map[string]Report {
	t.Helper()
	out := map[string]Report{}
	keep := func(name string, report Report, err error) {
		if err != nil {
			t.Fatalf("%s %s: %v", f.id, name, err)
		}
		out[name] = report
	}
	r, err := b.check(f.project, "", raw, removalNow)
	keep("check", r, err)
	r, err = b.check(f.project, f.ruleID(side), raw, removalNow)
	keep("check-rule", r, err)
	r, err = b.checkFacts(f.project, []string{f.id}, raw, removalNow)
	keep("check-facts", r, err)
	r, err = external.Evaluate(f.project, raw, removalNow)
	keep("external", r, err)
	// An external rule that the compiled pack does not hold cannot be
	// selected by id.
	if _, err := external.EvaluateRule(f.project, f.ruleID(side), raw, removalNow); !errors.Is(err, ErrInvalid) {
		t.Fatalf("%s external rule selection: %v", f.id, err)
	}
	return out
}

func removalClaim(t *testing.T, claims []constraintengine.Claim, id string) constraintengine.Claim {
	t.Helper()
	for _, claim := range claims {
		if claim.RuleID == id {
			return claim
		}
	}
	t.Fatalf("no claim of %s in %+v", id, claims)
	return constraintengine.Claim{}
}

// removalScope evaluates raw, with a scope declaration for the fact's
// component added, on the corpus replay route (assessScopeWith).
func removalScope(t *testing.T, b bundle, f declaredRemovalFact, raw []byte) (ScopeReport, error) {
	t.Helper()
	ruleSet, err := b.unfilteredRuleSetDigest()
	if err != nil {
		t.Fatal(err)
	}
	attestation := reattest(t, func(a *Attestation) {
		a.Revision, a.PackDigest, a.RuleCount, a.RuleSetDigest = b.pack.Revision, b.packDigest, len(b.pack.Entries), ruleSet
		a.Components = []string{f.component}
	})
	scoped := strings.Replace(string(raw), `"current":{`,
		fmt.Sprintf(`"scope":{"declaration":%q,"components":[%q]},"current":{`, constraintengine.ScopeDeclaration, f.component), 1)
	if scoped == string(raw) {
		t.Fatalf("%s: no scope declaration added", f.id)
	}
	return assessScopeWith(b, attestation, []byte(scoped), removalNow)
}

func TestDeclaredRemovalFactsRegisteredAndGuarded(t *testing.T) {
	t.Parallel()
	registry, err := compiledRegistry()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]constraintengine.FactDefinition{}
	for _, d := range registry.Definitions() {
		have[d.ID] = d
	}
	var listed, guarded []string
	for _, f := range declaredRemovalFacts() {
		listed = append(listed, f.id)
		d, ok := have[f.id]
		if !ok || d.Type != constraintengine.FactSet || d.Component != f.component {
			t.Errorf("%s is not registered as a set fact of %s", f.id, f.component)
		}
		if relnotesGuardedFacts[f.id] {
			t.Errorf("%s is also a release-note fact", f.id)
		}
	}
	for id := range declaredRemovalGuardedFacts {
		guarded = append(guarded, id)
	}
	sort.Strings(guarded)
	if !slices.Equal(listed, guarded) {
		t.Fatalf("guarded %v, want %v", guarded, listed)
	}
	// No published rule reads these facts.
	for _, entry := range shippedPack(t).Entries {
		for id := range declaredRemovalGuardedFacts {
			if strings.Contains(string(entry.Rule), id) {
				t.Fatalf("published rule %s reads %s", ruleID(t, entry), id)
			}
		}
	}
}

func TestDeclaredRemovalSetsOnlyBlockOrUnknown(t *testing.T) {
	t.Parallel()
	for _, side := range []string{"current", "proposed"} {
		b := removalBundle(t, side)
		external := removalExternal(t, b)
		for _, f := range declaredRemovalFacts() {
			for _, tc := range []struct {
				name, set, status string
				exit              int
			}{
				{"complete without member", removalSet(true, "kept-flag"), "UNKNOWN", 11},
				{"complete and empty", removalSet(true), "UNKNOWN", 11},
				{"incomplete without member", removalSet(false, "kept-flag"), "UNKNOWN", 11},
				{"complete with a longer name", removalSet(true, removalMember+"-kept"), "UNKNOWN", 11},
				{"complete with member", removalSet(true, removalMember), "BLOCKED", 10},
				{"incomplete with member", removalSet(false, removalMember), "BLOCKED", 10},
			} {
				raw := f.sideInput(side, tc.set)
				for path, report := range removalPaths(t, b, external, f, side, raw) {
					claim := removalClaim(t, report.Check.Claims, f.ruleID(side))
					if claim.Status != tc.status {
						t.Fatalf("%s %s %s %s: status %s, want %s", f.id, side, path, tc.name, claim.Status, tc.status)
					}
					if exit := ClaimExit(report); exit == 0 || (strings.HasSuffix(path, "rule") && exit != tc.exit) {
						t.Fatalf("%s %s %s %s: exit %d", f.id, side, path, tc.name, exit)
					}
					if tc.status == "UNKNOWN" && strings.Contains(tc.set, `"complete":true`) && report.NextAction != declaredRemovalNextAction {
						t.Fatalf("%s %s %s %s: next action %q", f.id, side, path, tc.name, report.NextAction)
					}
					if report.InputFileDigest != digest(raw) {
						t.Fatalf("%s %s: input file digest is not that of the original bytes", f.id, path)
					}
				}
				scope, err := removalScope(t, b, f, raw)
				if err != nil {
					t.Fatalf("%s %s corpus %s: %v", f.id, side, tc.name, err)
				}
				if got := removalClaim(t, scope.Check.Claims, f.ruleID(side)).Status; got != tc.status || scope.Check.Assessment == "SCOPE_COMPLETE_PASS" {
					t.Fatalf("%s %s corpus %s: %s (%s), want %s", f.id, side, tc.name, got, scope.Check.Assessment, tc.status)
				}
			}
			// The engine alone would pass the complete set: the guard is
			// what keeps it UNKNOWN.
			raw := f.sideInput(side, removalSet(true, "kept-flag"))
			input, err := constraintengine.ParseInput(raw, b.registry)
			if err != nil {
				t.Fatal(err)
			}
			selected, err := b.selectRule(f.project, f.ruleID(side))
			if err != nil {
				t.Fatal(err)
			}
			result, err := constraintengine.Evaluate(input, selected.rules, removalNow)
			if err != nil || removalClaim(t, result.Claims, f.ruleID(side)).Status != "PASS" {
				t.Fatalf("%s: unguarded engine result %+v %v, want PASS", f.id, result.Claims, err)
			}
			// A missing set, a member on the other side only and a hop
			// outside the range decide nothing.
			other := map[string]string{"current": "proposed", "proposed": "current"}[side]
			for name, raw := range map[string][]byte{
				"missing set":     f.input("1.9.0", "", ""),
				"other side only": f.sideInput(other, removalSet(true, removalMember)),
				"above range":     f.input("1.10.0", removalSet(true, removalMember), removalSet(true, removalMember)),
			} {
				for path, report := range removalPaths(t, b, external, f, side, raw) {
					for _, claim := range report.Check.Claims {
						if claim.RuleID == f.ruleID(side) && (claim.Status == "BLOCKED" || claim.Status == "PASS") {
							t.Fatalf("%s %s %s %s: %s", f.id, side, path, name, claim.Status)
						}
					}
					if ClaimExit(report) == 0 {
						t.Fatalf("%s %s %s %s: exit 0", f.id, side, path, name)
					}
				}
				scope, err := removalScope(t, b, f, raw)
				if err != nil {
					t.Fatalf("%s %s corpus %s: %v", f.id, side, name, err)
				}
				for _, claim := range scope.Check.Claims {
					if claim.RuleID == f.ruleID(side) && (claim.Status == "BLOCKED" || claim.Status == "PASS") {
						t.Fatalf("%s %s corpus %s: %s", f.id, side, name, claim.Status)
					}
				}
				if scope.Check.Assessment == "SCOPE_COMPLETE_PASS" {
					t.Fatalf("%s %s corpus %s: scope passed", f.id, side, name)
				}
			}
		}
	}
}

// olderBuild is this build with the declared-removal facts not registered.
func olderBuild(t *testing.T) bundle {
	t.Helper()
	older, err := load()
	if err != nil {
		t.Fatal(err)
	}
	var kept []constraintengine.FactDefinition
	for _, d := range compiledDefinitions() {
		if !declaredRemovalGuardedFacts[d.ID] {
			kept = append(kept, d)
		}
	}
	if len(kept) != len(compiledDefinitions())-len(declaredRemovalFacts()) {
		t.Fatalf("%d definitions kept", len(kept))
	}
	older.registry, err = constraintengine.NewCompiledRegistry(kept)
	if err != nil {
		t.Fatal(err)
	}
	older.pack.RegistryDigest = older.registry.Digest()
	return older
}

// A build that does not register the facts reads a newer compatible feed in
// compat mode: every rule over them is deferred, produces no claim, and no
// input yields PASS or BLOCKED for it. An input naming such a fact is refused.
func TestDeclaredRemovalRulesDeferredByBuildWithoutTheFacts(t *testing.T) {
	t.Parallel()
	older := olderBuild(t)
	for _, side := range []string{"current", "proposed"} {
		newer := removalBundle(t, side)
		index, targets, _, err := buildExternalTargetsPinned(newer, removalRevision, "operator_provided", func(string, func(string) ([]byte, error)) (string, error) { return removalRevision, nil }, nil)
		if err != nil {
			t.Fatal(err)
		}
		var document externalIndexDocument
		if err := json.Unmarshal(index.Bytes, &document); err != nil {
			t.Fatal(err)
		}
		document.BaseCapabilityDigest = baseCapabilityDigest(newer)
		indexRaw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		oldIndex, err := parseExternalIndex(indexRaw, &older)
		if err != nil || !oldIndex.Compat() {
			t.Fatalf("older build: compat %t, %v", oldIndex.Compat(), err)
		}
		newIndex, err := parseExternalIndex(indexRaw, &newer)
		if err != nil || newIndex.Compat() {
			t.Fatalf("control: compat %t, %v", newIndex.Compat(), err)
		}
		byProject := map[string][]byte{}
		for _, target := range targets {
			if slug, ok := ProjectFromTargetPath(target.Path); ok {
				byProject[slug] = target.Bytes
			}
		}
		for _, f := range declaredRemovalFacts() {
			deferred, err := AdmitExternalProjectTarget(oldIndex, f.project, byProject[f.project])
			if err != nil {
				t.Fatalf("%s %s: older build: %v", f.id, side, err)
			}
			found := false
			for _, rule := range deferred.DeferredRules() {
				if rule.RuleID == f.ruleID(side) {
					found = slices.Equal(rule.MissingFacts, []string{f.id})
				}
			}
			if !found {
				t.Fatalf("%s %s: not deferred: %+v", f.id, side, deferred.DeferredRules())
			}
			current, err := AdmitExternalProjectTarget(newIndex, f.project, byProject[f.project])
			if err != nil {
				t.Fatalf("%s %s: control: %v", f.id, side, err)
			}
			for _, member := range []string{"kept-flag", removalMember} {
				raw := f.sideInput(side, removalSet(true, member))
				if _, err := deferred.Evaluate(f.project, raw, removalNow); !errors.Is(err, ErrInvalid) {
					t.Fatalf("%s %s %s: unregistered fact accepted: %v", f.id, side, member, err)
				}
				if _, err := deferred.EvaluateRule(f.project, f.ruleID(side), raw, removalNow); !errors.Is(err, ErrInvalid) {
					t.Fatalf("%s %s %s: rule selection accepted: %v", f.id, side, member, err)
				}
				report, err := deferred.Evaluate(f.project, f.input("1.9.0", "", ""), removalNow)
				if err != nil {
					t.Fatalf("%s %s: %v", f.id, side, err)
				}
				for _, claim := range report.Check.Claims {
					if claim.RuleID == f.ruleID(side) {
						t.Fatalf("%s %s: deferred rule produced %s", f.id, side, claim.Status)
					}
				}
				if len(report.DeferredRules) == 0 || report.Assessment != "UNKNOWN" || ClaimExit(report) != 11 || !strings.HasPrefix(report.NextAction, deferredNextAction) {
					t.Fatalf("%s %s: deferred report %+v exit %d", f.id, side, report.DeferredRules, ClaimExit(report))
				}
				want := "UNKNOWN"
				if member == removalMember {
					want = "BLOCKED"
				}
				report, err = current.Evaluate(f.project, raw, removalNow)
				if err != nil || removalClaim(t, report.Check.Claims, f.ruleID(side)).Status != want {
					t.Fatalf("%s %s %s: control %+v %v", f.id, side, member, report.Check.Claims, err)
				}
			}
		}
	}
}

func TestDeclaredRemovalSetsRefuseHostileSpellings(t *testing.T) {
	t.Parallel()
	for _, side := range []string{"current", "proposed"} {
		b := removalBundle(t, side)
		external := removalExternal(t, b)
		for _, f := range declaredRemovalFacts() {
			good := string(f.sideInput(side, removalSet(true, "kept-flag")))
			// bs starts a JSON escape in the document bytes.
			bs := string(rune(92))
			escapedID := strings.Replace(f.id, "_cli_", bs+"u005fcli_", 1)
			escapedUpper := strings.Replace(good, "kept-flag", bs+"u004bept-flag", 1)
			if escapedID == f.id || !strings.Contains(escapedUpper, bs+"u004b") {
				t.Fatalf("%s: escapes not applied", f.id)
			}
			// Accepted spellings of the same document stay guarded.
			for name, raw := range map[string]string{
				"escaped fact id": strings.Replace(good, f.id, escapedID, 1),
				"reordered set":   strings.Replace(good, removalSet(true, "kept-flag"), `{"complete":true,"members":["kept-flag"]}`, 1),
				"white space":     strings.Replace(good, `"complete":true`, "\"complete\" :\n true", 1),
			} {
				if raw == good {
					t.Fatalf("%s %s: variant not applied", f.id, name)
				}
				for path, report := range removalPaths(t, b, external, f, side, []byte(raw)) {
					if got := removalClaim(t, report.Check.Claims, f.ruleID(side)).Status; got != "UNKNOWN" {
						t.Fatalf("%s %s %s: %s", f.id, name, path, got)
					}
				}
			}
			refused := map[string]string{
				"upper case":          string(f.sideInput(side, removalSet(true, "Kept-Flag"))),
				"upper-case removed":  string(f.sideInput(side, removalSet(false, strings.ToUpper(removalMember)))),
				"escaped upper case":  escapedUpper,
				"escaped id upper":    strings.Replace(strings.Replace(good, "kept-flag", "Kept-flag", 1), f.id, escapedID, 1),
				"duplicate complete":  strings.Replace(good, `"complete":true`, `"complete":false,"complete":true`, 1),
				"case-variant key":    strings.Replace(good, `"complete":true`, `"complete":false,"Complete":true`, 1),
				"trailing data":       good + `{}`,
				"duplicate member":    string(f.sideInput(side, removalSet(true, "a", "a"))),
				"unsorted members":    string(f.sideInput(side, removalSet(true, "b", "a"))),
				"illegal member":      string(f.sideInput(side, removalSet(true, "--"+removalMember))),
				"member with a value": string(f.sideInput(side, removalSet(true, removalMember+"=1"))),
				"wrong value type":    strings.Replace(good, `"setValue":`+removalSet(true, "kept-flag"), `"boolValue":true`, 1),
				"wrong component":     strings.ReplaceAll(good, f.component, "pkg:github/thanos-io/thanos"),
			}
			for name, raw := range refused {
				if raw == good {
					t.Fatalf("%s %s: variant not applied", f.id, name)
				}
				if _, err := b.check(f.project, "", []byte(raw), removalNow); !errors.Is(err, ErrInvalid) {
					t.Fatalf("%s %s check: %v", f.id, name, err)
				}
				if _, err := b.checkFacts(f.project, []string{f.id}, []byte(raw), removalNow); !errors.Is(err, ErrInvalid) {
					t.Fatalf("%s %s check facts: %v", f.id, name, err)
				}
				if _, err := external.Evaluate(f.project, []byte(raw), removalNow); !errors.Is(err, ErrInvalid) {
					t.Fatalf("%s %s external: %v", f.id, name, err)
				}
				if _, err := removalScope(t, b, f, []byte(raw)); !errors.Is(err, ErrInvalid) {
					t.Fatalf("%s %s corpus: %v", f.id, name, err)
				}
				if err := ValidateCanonicalInput(f.project, []byte(raw)); !errors.Is(err, ErrInvalid) {
					t.Fatalf("%s %s validate: %v", f.id, name, err)
				}
			}
			for _, name := range []string{"upper case", "escaped upper case"} {
				if err := ValidateCanonicalInput(f.project, []byte(refused[name])); !errors.Is(err, ErrMemberSpelling) {
					t.Fatalf("%s %s: %v, want the spelling reason", f.id, name, err)
				}
			}
			// The embedded knowledge (no rule yet) accepts a canonical set.
			if err := ValidateCanonicalInput(f.project, []byte(good)); err != nil {
				t.Fatalf("%s: canonical input refused: %v", f.id, err)
			}
			report, err := Check(f.project, []byte(good), packClock(t))
			if err != nil || ClaimExit(report) == 0 {
				t.Fatalf("%s: embedded check: %v", f.id, err)
			}
		}
	}
}

// An input without a declared-removal set, or with one already declared
// incomplete, comes back byte for byte, so earlier reports replay unchanged.
func TestDeclaredRemovalGuardLeavesOtherInputsUnchanged(t *testing.T) {
	t.Parallel()
	f := declaredRemovalFacts()[0]
	relnotes := cortexStoreRule.input(true, cortexStoreRule.to, "cluster.peer")
	for name, raw := range map[string][]byte{
		"release-note set": relnotes,
		"containerd":       containerdInput(t),
		"incomplete":       f.sideInput("current", removalSet(false, "kept-flag")),
		"not declared":     f.input("1.9.0", "", ""),
	} {
		out, downgraded, err := guardDeclaredRemovalSets(raw)
		if err != nil || downgraded || !bytes.Equal(out, raw) {
			t.Fatalf("%s: rewritten (%t, %v)", name, downgraded, err)
		}
	}
	if _, _, err := guardDeclaredRemovalSets([]byte("{")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unreadable document: %v", err)
	}
}
