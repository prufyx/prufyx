// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package scanrun

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

type scanForwardIndex struct {
	Schema     string                         `json:"schema"`
	Revision   string                         `json:"revision"`
	Purpose    string                         `json:"purpose"`
	Capability string                         `json:"engineCapabilityDigest"`
	Base       string                         `json:"baseCapabilityDigest,omitempty"`
	Projects   []cncfcheck.ExternalIndexEntry `json:"projects"`
	MinClient  string                         `json:"minClientVersion,omitempty"`
}

func scanForwardHash(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }

// The test producer computes the whole semantic identity through the public
// strict non-evaluating rule parser, using only the target's declared types.
func scanForwardWholeDigest(t *testing.T, pack map[string]json.RawMessage) string {
	t.Helper()
	var entries []cncfcheck.Entry
	if err := json.Unmarshal(pack["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	var definitions []constraintengine.FactDefinition
	seen := map[string]bool{}
	rules := []json.RawMessage{}
	for _, e := range entries {
		rules = append(rules, e.Rule)
		for _, f := range e.RequiredFacts {
			if !seen[f.ID] {
				definitions = append(definitions, constraintengine.FactDefinition{ID: f.ID, Component: f.Component, Type: f.Type, EnumTokens: f.EnumTokens})
				seen[f.ID] = true
			}
		}
	}
	registry, err := constraintengine.NewCompiledRegistry(definitions)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := constraintengine.RulesSchemaFor(rules)
	if err != nil {
		t.Fatal(err)
	}
	var revision, policy, policyDigest string
	_ = json.Unmarshal(pack["revision"], &revision)
	_ = json.Unmarshal(pack["policyId"], &policy)
	_ = json.Unmarshal(pack["policyDigest"], &policyDigest)
	doc := struct {
		Schema       string            `json:"schema"`
		Revision     string            `json:"revision"`
		Policy       string            `json:"policyId"`
		PolicyDigest string            `json:"policyDigest"`
		Rules        []json.RawMessage `json:"rules"`
	}{schema, revision, policy, policyDigest, rules}
	raw, _ := json.Marshal(doc)
	parsed, err := constraintengine.ParseRuleSet(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := parsed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	records := struct {
		Line   json.RawMessage `json:"lineAttestations,omitempty"`
		Path   json.RawMessage `json:"pathPolicies,omitempty"`
		Served json.RawMessage `json:"servedAPIs,omitempty"`
	}{pack["lineAttestations"], pack["pathPolicies"], pack["servedAPIs"]}
	raw, _ = json.Marshal(records)
	content := struct {
		Schema string `json:"schema"`
		Rule   string `json:"ruleDigest"`
		Record string `json:"recordDigest"`
	}{"prufyx.io/cncf-knowledge-content/v1", digest, scanForwardHash(raw)}
	raw, _ = json.Marshal(content)
	return scanForwardHash(raw)
}

func signedForwardScanStore(t *testing.T, mode string) (*storeFixture, knowledge.ImportReceipt, cncfcheck.ExternalIndexEntry) {
	t.Helper()
	f := newStoreFixture(t, cncfknowledge.LayoutPerProject)
	index, targets, err := cncfcheck.BuildEmbeddedCompatibleExternalTargets("9", nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc scanForwardIndex
	if err := json.Unmarshal(index.Bytes, &doc); err != nil {
		t.Fatal(err)
	}
	oldCapability := doc.Capability
	doc.Capability = scanForwardHash([]byte("synthetic later legacy capability"))
	var selected cncfcheck.ExternalIndexEntry
	var raw []byte
	for _, entry := range doc.Projects {
		if (mode != "absent" && entry.Project == kubernetesSlug) || (mode == "absent" && entry.Project != kubernetesSlug && entry.Catalog == "") {
			selected = entry
			break
		}
	}
	for _, target := range targets {
		if target.Path == selected.TargetPath {
			raw = bytes.ReplaceAll(target.Bytes, []byte(oldCapability), []byte(doc.Capability))
			break
		}
	}
	if len(raw) == 0 {
		t.Fatal("missing selected producer target")
	}
	if mode != "absent" {
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		var pack map[string]json.RawMessage
		if err := json.Unmarshal(envelope["pack"], &pack); err != nil {
			t.Fatal(err)
		}
		delete(pack, "lineAttestations")
		if mode == "opaque" {
			// Retain a real served-API section in the opaque signed bytes;
			// none of its records may enter the evaluated empty target.
			rawRecords, err := os.ReadFile("../cncfcheck/data/rules.json")
			if err != nil {
				t.Fatal(err)
			}
			var source map[string]json.RawMessage
			if json.Unmarshal(rawRecords, &source) != nil || len(source["servedAPIs"]) == 0 {
				t.Fatal("served fixture absent")
			}
			pack["servedAPIs"] = source["servedAPIs"]
		} else {
			delete(pack, "servedAPIs")
		}
		if len(pack["pathPolicies"]) == 0 {
			t.Fatal("test needs the reviewed path policy")
		}
		pack["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha5"`)
		pack["entries"] = bytes.ReplaceAll(pack["entries"], []byte("component.kubernetes.hpa_v2beta1_removed_gvk_present"), []byte("component.kubernetes.hpa_v2beta1_removed_gvk_present_future"))
		if !bytes.Contains(pack["entries"], []byte("_future")) {
			t.Fatal("deferred control missing")
		}
		selected.RuleDigest = scanForwardWholeDigest(t, pack)
		var entries []cncfcheck.Entry
		_ = json.Unmarshal(pack["entries"], &entries)
		materials := []json.RawMessage{}
		for _, entry := range entries {
			materials = append(materials, entry.Rule)
		}
		var policies []json.RawMessage
		_ = json.Unmarshal(pack["pathPolicies"], &policies)
		materials = append(materials, policies...)
		selected.EvidenceExpiresAt = ""
		for _, material := range materials {
			var item struct {
				Evidence struct {
					Until string `json:"validUntil"`
				} `json:"evidence"`
			}
			if json.Unmarshal(material, &item) != nil || item.Evidence.Until == "" {
				t.Fatal("fixture evidence missing")
			}
			if selected.EvidenceExpiresAt == "" || item.Evidence.Until < selected.EvidenceExpiresAt {
				selected.EvidenceExpiresAt = item.Evidence.Until
			}
		}
		envelope["pack"], _ = json.Marshal(pack)
		if mode == "opaque" {
			envelope["schema"] = json.RawMessage(`"prufyx.io/operator-cncf-knowledge/v99"`)
		}
		raw, _ = json.Marshal(envelope)
		selected.Records = true
	}
	selected.Length = int64(len(raw))
	selected.Digest = scanForwardHash(raw)
	doc.Projects = []cncfcheck.ExternalIndexEntry{selected}
	doc.Schema = cncfcheck.ExternalIndexSchema
	if selected.Records {
		doc.Schema = cncfcheck.ExternalIndexSchemaRecords
	}
	indexRaw, _ := json.Marshal(doc)
	packageRaw, err := f.repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: map[string][]byte{index.Path: indexRaw, selected.TargetPath: raw}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{PackagePath: f.write("forward.tar", packageRaw), StoreRoot: f.store, BootstrapRootPath: f.root, BootstrapRootDigest: f.repo.RootDigest})
	if err != nil {
		t.Fatal(err)
	}
	return f, receipt, selected
}

func TestSignedForwardScanKeepsGapAndIndependentCrossing(t *testing.T) {
	entry := cncfcheck.Entry{Project: kubernetesSlug, Description: "Synthetic independently embedded removal crossing.", RequiredFacts: []cncfcheck.Fact{{Side: "proposed", ID: cronjobFact, Component: "pkg:github/kubernetes/kubernetes", Type: constraintengine.FactBool, Description: "Declared CronJob API presence."}}, Rule: json.RawMessage(crossingRule(crossingRuleID, false))}
	registry, err := constraintengine.NewRegistry([]constraintengine.FactDefinition{{ID: cronjobFact, Component: "pkg:github/kubernetes/kubernetes", Type: constraintengine.FactBool}})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := constraintengine.RulesSchemaFor([]json.RawMessage{entry.Rule})
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(map[string]any{"schema": schema, "revision": "fixture", "policyId": "fixture", "policyDigest": scanForwardHash([]byte("fixture")), "rules": []json.RawMessage{entry.Rule}})
	if _, err := constraintengine.ParseRuleSet(doc, registry); err != nil {
		t.Fatalf("crossing fixture schema: %v", err)
	}
	var original struct {
		Revision     string            `json:"revision"`
		Policy       string            `json:"policyId"`
		Digest       string            `json:"policyDigest"`
		Entries      []cncfcheck.Entry `json:"entries"`
		PathPolicies json.RawMessage   `json:"pathPolicies"`
	}
	if json.Unmarshal(embeddedPack(t), &original) != nil {
		t.Fatal("fixture source")
	}
	all := []json.RawMessage{entry.Rule}
	for _, e := range original.Entries {
		all = append(all, e.Rule)
	}
	sort.Slice(all, func(i, j int) bool {
		var a, b struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(all[i], &a)
		_ = json.Unmarshal(all[j], &b)
		return a.ID < b.ID
	})
	schema, err = constraintengine.RulesSchemaFor(all)
	if err != nil {
		t.Fatal(err)
	}
	registry, err = constraintengine.NewCompiledRegistry(cncfcheck.CompiledFactDefinitions())
	if err != nil {
		t.Fatal(err)
	}
	doc, _ = json.Marshal(map[string]any{"schema": schema, "revision": "fixture", "policyId": original.Policy, "policyDigest": original.Digest, "rules": all})
	if _, err := constraintengine.ParseRuleSet(doc, registry); !errors.Is(err, constraintengine.ErrInvalid) || !strings.Contains(err.Error(), "overlapping rules constrain the same fact") {
		t.Fatalf("sibling-overlap negative lost: %v", err)
	}
	var before cncfcheck.Entry
	expectedID := ""
	for _, candidate := range original.Entries {
		var rule struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(candidate.Rule, &rule)
		if rule.ID == cronjobRuleID {
			before = candidate
			expectedID = rule.ID
			break
		}
	}
	if expectedID == "" {
		t.Fatal("reviewed source entry missing")
	}
	after := before
	var rule map[string]json.RawMessage
	if json.Unmarshal(before.Rule, &rule) != nil {
		t.Fatal("source rule")
	}
	var evidence struct {
		Sources []constraintengine.SourceEvidence `json:"sources"`
	}
	if json.Unmarshal(rule["evidence"], &evidence) != nil || len(evidence.Sources) == 0 {
		t.Fatal("source evidence")
	}
	crossing := constraintengine.CrossingSpec{Change: constraintengine.CrossingChange{Version: "1.25.0", Basis: constraintengine.BasisRemovedInRelease, SourceID: evidence.Sources[0].ID}, Horizon: constraintengine.CrossingHorizon{Lt: "1.36.0", Basis: constraintengine.BasisReviewedThroughMinorLine, SourceID: evidence.Sources[0].ID}}
	rule["crossing"], _ = json.Marshal(crossing)
	after.Rule, _ = json.Marshal(rule)
	records := cncfcheck.SyntheticRecords{PathPolicies: original.PathPolicies}
	for _, kind := range []string{"description", "predicate", "missing-source-entry"} {
		changedBefore, changedAfter := before, after
		switch kind {
		case "description":
			changedAfter.Description += " changed"
		case "predicate":
			changedAfter.Rule = bytes.Replace(changedAfter.Rule, []byte(`"boolValue":true`), []byte(`"boolValue":false`), 1)
		case "missing-source-entry":
			changedBefore.Rule = bytes.ReplaceAll(changedBefore.Rule, []byte(expectedID), []byte("kubernetes.unknown-source-entry"))
			changedAfter.Rule = bytes.ReplaceAll(changedAfter.Rule, []byte(expectedID), []byte("kubernetes.unknown-source-entry"))
		}
		if restore, err := cncfcheck.UseSyntheticCrossingReplacement(changedBefore, changedAfter, records); err == nil {
			restore()
			t.Fatalf("fixture changed more than crossing: %s", kind)
		}
	}
	restore, err := cncfcheck.UseSyntheticCrossingReplacement(before, after, records)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	for _, mode := range []string{"deferred", "opaque", "absent"} {
		t.Run(mode, func(t *testing.T) {
			f, receipt, target := signedForwardScanStore(t, mode)
			for _, removed := range []bool{true, false} {
				t.Run(fmt.Sprint(removed), func(t *testing.T) {
					manifest := cronjobV1
					if removed {
						manifest = cronjobV1beta1
					}
					path := f.write(fmt.Sprintf("apply-%t.yaml", removed), []byte(manifest))
					request, err := ParseArgs(storeArgs([]string{path}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--knowledge-db", f.store))
					if err != nil {
						t.Fatal(err)
					}
					result, err := Run(request, Options{Build: &testBuild})
					if err != nil {
						t.Fatal(err)
					}
					if result.Exit == scanreport.ExitPass || result.Report.Verdict == scanreport.VerdictPass {
						t.Fatal("incomplete signed target passed")
					}
					p := result.Report.Provenance
					if p.KnowledgeOrigin != "external_signed_local" || p.KnowledgeRevision != receipt.TrustReceipt.KnowledgeRevision || p.KnowledgeDigest != receipt.TrustReceipt.TargetDigest || p.KnowledgeStore == nil || p.KnowledgeStore.TrustReceiptDigest != receipt.TrustReceiptDigest {
						t.Fatalf("receipt/context mismatch %+v", p)
					}
					if p.EvaluatedAt < receipt.TrustReceipt.VerifiedAt {
						t.Fatal("backdated external evaluation")
					}
					wantDetail := map[string]string{"deferred": "rules of kubernetes", "opaque": "semantic identity is unverified", "absent": "no knowledge for kubernetes"}[mode]
					foundGap := false
					for _, gap := range result.Report.Gaps {
						if gap.Component == kubernetesSlug && gap.Reason == scanreport.ReasonProjectNotInKnowledge && strings.Contains(gap.Detail, wantDetail) && gap.Action != "" {
							foundGap = true
						}
					}
					if !foundGap || !p.KnowledgeStore.Compat {
						t.Fatalf("missing specific signed coverage gap: %+v", result.Report.Gaps)
					}
					if removed && mode != "absent" {
						if result.Exit != scanreport.ExitBlocked {
							t.Fatalf("lost independent block exit%d gaps%v", result.Exit, gapReasons(result.Report))
						}
						found := false
						for _, finding := range result.Report.Findings {
							if finding.RuleID == expectedID {
								found = true
								if len(finding.Citations) == 0 || (finding.Crossing == nil && finding.Match != "range") {
									t.Fatal("crossing provenance missing")
								}
							}
						}
						if !found {
							t.Fatalf("wrong blocker %+v", result.Report.Findings)
						}
					} else if result.Exit != scanreport.ExitUnknown {
						t.Fatalf("expected UNKNOWN exit%d", result.Exit)
					}
					if mode == "absent" {
						if len(result.Report.Findings) != 0 || p.KnowledgeStore.Projects[0].Status != "absent_from_index" {
							t.Fatal("absent target fell back to embedded")
						}
					} else {
						if p.KnowledgeStore.Projects[0].Digest != target.Digest {
							t.Fatal("wrong target digest")
						}
						if mode == "opaque" {
							if p.KnowledgeStore.Projects[0].Status != "unreadable_target" || !strings.Contains(strings.Join(receipt.UnreadableProjects, ","), kubernetesSlug) {
								t.Fatal("opaque semantic identity hidden")
							}
						}
					}
					conformReport(t, "signed forward state", result.Report)
					if mode != "absent" {
						// Keep the same explicitly declared parsed API-presence
						// facts on a wider requested transition, as chain checking
						// does. This signed check exercises crossing matching; the
						// stepped scan above exercises its retained reviewed range.
						prepared, err := cncfprepare.PrepareKubernetesRemovedAPIs([]byte(manifest), "1.24.17", "1.25.3", "official_upstream", true, true)
						if err != nil {
							t.Fatal(err)
						}
						var input map[string]any
						if json.Unmarshal(prepared.CanonicalInputJSON, &input) != nil {
							t.Fatal("parsed declaration")
						}
						input["proposed"].(map[string]any)["components"].([]any)[0].(map[string]any)["version"] = "1.30.4"
						canonical, _ := json.Marshal(input)
						checked, err := cncfknowledge.EvaluateCurrent(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: f.store}, Project: kubernetesSlug, SelectedRuleID: expectedID, Input: canonical, InputDigest: scanForwardHash(canonical)})
						if err != nil {
							t.Fatal(err)
						}
						want := 11
						if removed {
							want = 10
						}
						if cncfknowledge.ClaimExit(checked) != want || checked.Knowledge.TrustReceiptDigest != receipt.TrustReceiptDigest || checked.Check.InputFileDigest != scanForwardHash(canonical) {
							t.Fatalf("signed crossing context mismatch %+v", checked)
						}
						if removed {
							if len(checked.Check.Check.Claims) != 1 || checked.Check.Check.Claims[0].RuleID != expectedID || checked.Check.Check.Claims[0].CrossingMatch == nil || checked.Check.Check.Claims[0].Status != "BLOCKED" {
								t.Fatalf("signed crossing missing %+v", checked.Check.Check.Claims)
							}
						}
						if mode == "opaque" && !checked.Check.UnverifiedSemanticIdentity {
							t.Fatal("opaque semantic identity presented as verified")
						}
					}
				})
			}
			// A tampered selected target fails on actual reopen; it never falls
			// back to the embedded rule which the same manifest would block.
			if mode == "deferred" {
				changed := false
				err := filepath.WalkDir(f.store, func(path string, d os.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if d.Type().IsRegular() {
						raw, e := os.ReadFile(path)
						if e != nil {
							return e
						}
						if scanForwardHash(raw) == target.Digest {
							changed = true
							return os.WriteFile(path, append(raw, ' '), 0o600)
						}
					}
					return nil
				})
				if err != nil || !changed {
					t.Fatalf("tamper fixture %v changed%t", err, changed)
				}
				request, err := ParseArgs(storeArgs([]string{f.write("bad-input.yaml", []byte(cronjobV1beta1))}, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.25.3", "--knowledge-db", f.store))
				if err != nil {
					t.Fatal(err)
				}
				if result, err := Run(request, Options{Build: &testBuild}); !errors.Is(err, ErrIntegrity) || result.Report.Schema != "" {
					t.Fatal("tampered store silently selected other knowledge")
				}
			}
		})
	}
}
