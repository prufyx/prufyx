// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/buildidentity"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func withBuildVersion(t *testing.T, version string) {
	t.Helper()
	old := buildidentity.Version
	buildidentity.Version = version
	t.Cleanup(func() { buildidentity.Version = old })
}

func indexWithExtra(t *testing.T, index []byte, extra string) []byte {
	t.Helper()
	if !bytes.HasSuffix(index, []byte("}")) {
		t.Fatal("index is not a JSON object")
	}
	return append(append(append([]byte(nil), index[:len(index)-1]...), ','), append([]byte(extra), '}')...)
}

// An index the pinned root signed but this build cannot read is rejected
// without advancing trust, so the store stays usable and a later readable
// package still imports.
func TestUnsupportedIndexDoesNotAdvanceTrust(t *testing.T) {
	base := projectsTargets(t, "5", nil)
	index := base[ConstraintsProjectsIndexTargetPath]
	withIndex := func(raw []byte) map[string][]byte {
		c := map[string][]byte{}
		for k, v := range base {
			c[k] = v
		}
		c[ConstraintsProjectsIndexTargetPath] = raw
		return c
	}
	cases := []struct {
		name    string
		version string
		index   []byte
		min     string
	}{
		{"unknown index field", "dev", indexWithExtra(t, index, `"futureField":true`), ""},
		{"schema bump", "dev", bytes.Replace(index, []byte(`"schema":"`), []byte(`"schema":"v9-`), 1), ""},
		{"minClientVersion above this build", "v0.1.0-beta.0", indexWithExtra(t, index, `"minClientVersion":"v0.1.0-beta.1"`), "v0.1.0-beta.1"},
		{"minClientVersion with a future schema", "v0.1.0-beta.0", indexWithExtra(t, bytes.Replace(index, []byte(`"schema":"`), []byte(`"schema":"v9-`), 1), `"minClientVersion":"v0.2.0"`), "v0.2.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withBuildVersion(t, tc.version)
			f := newProjectsFixture(t)
			good, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
			if err != nil {
				t.Fatal(err)
			}
			kept, err := loadSelectionAt(f.store)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: withIndex(tc.index)}))
			if !errors.Is(err, ErrUnsupportedKnowledge) || errors.Is(err, ErrIntegrity) {
				t.Fatalf("err=%v receipt=%+v", err, receipt)
			}
			if got := UnsupportedMinVersion(err); got != tc.min {
				t.Fatalf("min version %q, want %q", got, tc.min)
			}
			if receipt.Status != "REJECTED" || receipt.TrustStateAdvanced || receipt.SelectionChanged || receipt.TrustStateDigest != good.TrustStateDigest {
				t.Fatalf("receipt=%+v", receipt)
			}
			assertSelectionKept(t, f.store, kept, receipt)
			status, err := InspectConstraintsProjects(f.store)
			if err != nil || status.State != "READY" || status.SelectedRevision != "5" {
				t.Fatalf("status=%+v err=%v", status, err)
			}
			first, _ := firstProjects(base)
			if _, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{projectOf(t, first)}); err != nil {
				t.Fatalf("open after unsupported import: %v", err)
			}
			recovered, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: projectsTargets(t, "6", nil)}))
			if err != nil || recovered.TrustReceipt.KnowledgeRevision != "6" {
				t.Fatalf("recovery receipt=%+v err=%v", recovered, err)
			}
		})
	}
}

func TestUnsupportedFirstImportLeavesNoTrust(t *testing.T) {
	withBuildVersion(t, "v0.1.0-beta.0")
	base := projectsTargets(t, "5", nil)
	base[ConstraintsProjectsIndexTargetPath] = indexWithExtra(t, base[ConstraintsProjectsIndexTargetPath], `"minClientVersion":"v0.2.0"`)
	f := newProjectsFixture(t)
	receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
	if !errors.Is(err, ErrUnsupportedKnowledge) || receipt.TrustStateAdvanced {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	ok, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: projectsTargets(t, "6", nil)}))
	if err != nil || ok.Status != "IMPORTED" {
		t.Fatalf("later readable package: %+v err=%v", ok, err)
	}
}

func TestMinClientVersionSatisfiedImports(t *testing.T) {
	withBuildVersion(t, "v0.1.0-beta.1")
	base := projectsTargets(t, "5", nil)
	base[ConstraintsProjectsIndexTargetPath] = indexWithExtra(t, base[ConstraintsProjectsIndexTargetPath], `"minClientVersion":"v0.1.0-beta.0"`)
	f := newProjectsFixture(t)
	receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
	if err != nil || receipt.Status != "IMPORTED" {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
}

// A tampered project target is still an integrity failure that advances
// trust, exactly as before.
func TestTamperedProjectTargetStaysIntegrityAndAdvancesTrust(t *testing.T) {
	base := projectsTargets(t, "5", nil)
	first, _ := firstProjects(base)
	f := newProjectsFixture(t)
	good, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base, Replace: map[string][]byte{first: flipByte(base[first])}}))
	if !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrUnsupportedKnowledge) || receipt.Status != "REJECTED" || !receipt.TrustStateAdvanced || receipt.TrustStateDigest == good.TrustStateDigest {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	var mismatch *metadata.ErrLengthOrHashMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("the length or hash mismatch cause was flattened: %v", err)
	}
	if !strings.Contains(err.Error(), "signed length and hash") {
		t.Fatalf("err=%v", err)
	}
}

func TestExternalIndexMinClientIsLenient(t *testing.T) {
	if v, ok := cncfcheck.ExternalIndexMinClient([]byte(`{"schema":"v99","weird":[1,2],"minClientVersion":"v1.2.3"}`)); !ok || v != "v1.2.3" {
		t.Fatalf("got %q %t", v, ok)
	}
	for _, raw := range []string{``, `[]`, `{"schema":"v1"}`, `{"minClientVersion":5}`, `nope`} {
		if v, ok := cncfcheck.ExternalIndexMinClient([]byte(raw)); ok || v != "" {
			t.Fatalf("%q: got %q %t", raw, v, ok)
		}
	}
}

// A signed, hash-verified project target this build cannot parse (an unknown
// field), listed by an index without minClientVersion, is unsupported: no
// trust advance, the store stays READY.
func TestUnsupportedProjectTargetDoesNotAdvanceTrust(t *testing.T) {
	base := projectsTargets(t, "5", nil)
	first, _ := firstProjects(base)
	oldRaw := base[first]
	newRaw := append(append([]byte(nil), oldRaw[:len(oldRaw)-1]...), []byte(`,"futureField":true}`)...)
	oldFrag := fmt.Sprintf(`"length":%d,"digest":"%s"`, len(oldRaw), digestBytes(oldRaw))
	newFrag := fmt.Sprintf(`"length":%d,"digest":"%s"`, len(newRaw), digestBytes(newRaw))
	index := base[ConstraintsProjectsIndexTargetPath]
	if !bytes.Contains(index, []byte(oldFrag)) {
		t.Fatal("index entry fragment not found")
	}
	changed := map[string][]byte{}
	for k, v := range base {
		changed[k] = v
	}
	changed[first] = newRaw
	changed[ConstraintsProjectsIndexTargetPath] = bytes.Replace(index, []byte(oldFrag), []byte(newFrag), 1)

	f := newProjectsFixture(t)
	good, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: changed}))
	if !errors.Is(err, ErrUnsupportedKnowledge) || errors.Is(err, ErrIntegrity) {
		t.Fatalf("err=%v receipt=%+v", err, receipt)
	}
	if receipt.Status != "REJECTED" || receipt.TrustStateAdvanced || receipt.TrustStateDigest != good.TrustStateDigest {
		t.Fatalf("receipt=%+v", receipt)
	}
	status, err := InspectConstraintsProjects(f.store)
	if err != nil || status.State != "READY" || status.SelectedRevision != "5" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

// The "upgrade to >= X" hint is given only when this build is below X: a
// parse failure with an already satisfied minimum names no version.
func TestCNCFMinOrEmptyHintsOnlyWhenNotMet(t *testing.T) {
	withBuildVersion(t, "v0.2.0")
	for _, c := range []struct{ raw, want string }{
		{`{"schema":"v9","minClientVersion":"v0.3.0"}`, "v0.3.0"},
		{`{"schema":"v9","minClientVersion":"v0.2.0"}`, ""},
		{`{"schema":"v9","minClientVersion":"v0.1.0"}`, ""},
		{`{"schema":"v9"}`, ""},
	} {
		if got := cncfMinOrEmpty([]byte(c.raw)); got != c.want {
			t.Fatalf("%s: got %q, want %q", c.raw, got, c.want)
		}
	}
	// Through the real path: an unreadable index whose minimum is met.
	err := unsupportedFailure(cncfMinOrEmpty([]byte(`{"schema":"v9","minClientVersion":"v0.1.0"}`)), "index target parse")
	if got := UnsupportedMinVersion(err); got != "" {
		t.Fatalf("hint for a met minimum: %q", got)
	}
}

// Unknown outer extensions of an exact profile are unreadable, but cannot
// hide malformed known content or advance trust merely by being rejected.
type exactOuterIndex struct {
	Schema     string                         `json:"schema"`
	Revision   string                         `json:"revision"`
	Purpose    string                         `json:"purpose"`
	Capability string                         `json:"engineCapabilityDigest"`
	Base       string                         `json:"baseCapabilityDigest,omitempty"`
	Projects   []cncfcheck.ExternalIndexEntry `json:"projects"`
	Min        string                         `json:"minClientVersion,omitempty"`
}

func TestExactOuterExtensionClassification(t *testing.T) {
	for _, canary := range []bool{false, true} {
		t.Run(fmt.Sprintf("canary-%t", canary), func(t *testing.T) {
			all := projectsTargets(t, "5", nil)
			first, _ := firstProjects(all)
			var target map[string]json.RawMessage
			if json.Unmarshal(all[first], &target) != nil {
				t.Fatal("fixture")
			}
			var pack map[string]json.RawMessage
			if json.Unmarshal(target["pack"], &pack) != nil {
				t.Fatal("pack fixture")
			}
			if canary {
				req, err := cncfcheck.MariaDBCanaryProfileRequirements()
				if err != nil {
					t.Fatal(err)
				}
				target["engineCapabilityDigest"], _ = json.Marshal(req.EngineCapabilityDigest)
				pack["registryDigest"], _ = json.Marshal(req.RegistryDigest)
				target["pack"], _ = json.Marshal(pack)
			}
			raw, _ := json.Marshal(target)
			b, err := cncfcheck.ParseExternalBundle(raw)
			if err != nil {
				t.Fatal(err)
			}
			a, err := b.Admission()
			if err != nil {
				t.Fatal(err)
			}
			var index exactOuterIndex
			_ = json.Unmarshal(all[ConstraintsProjectsIndexTargetPath], &index)
			entries := index.Projects
			var selected cncfcheck.ExternalIndexEntry
			for _, e := range entries {
				if e.TargetPath == first {
					selected = e
				}
			}
			selected.Length, selected.Digest = int64(len(raw)), digestBytes(raw)
			index.Projects = []cncfcheck.ExternalIndexEntry{selected}
			index.Capability = a.EngineCapabilityDigest
			if selected.Records {
				index.Schema = cncfcheck.ExternalIndexSchemaRecords
			} else {
				index.Schema = cncfcheck.ExternalIndexSchema
			}
			indexRaw, _ := json.Marshal(index)
			base := map[string][]byte{first: raw, ConstraintsProjectsIndexTargetPath: indexRaw}
			for _, mode := range []string{"extension", "unknown-null", "direct-null", "known-null", "missing-known", "wrong-type", "collision", "alias", "digest-mismatch", "expiry-mismatch", "reserved-id"} {
				t.Run(mode, func(t *testing.T) {
					var envelope map[string]json.RawMessage
					_ = json.Unmarshal(raw, &envelope)
					envelope["futureField"] = json.RawMessage(`{"nested":true}`)
					var content map[string]json.RawMessage
					_ = json.Unmarshal(envelope["pack"], &content)
					switch mode {
					case "unknown-null":
						envelope["futureField"] = json.RawMessage(`{"nested":[null]}`)
					case "direct-null":
						envelope["futureField"] = json.RawMessage(`null`)
					case "known-null":
						content["entries"] = json.RawMessage(`null`)
					case "missing-known":
						delete(content, "policyId")
					case "wrong-type":
						content["entries"] = json.RawMessage(`{}`)
					case "collision":
						var es []map[string]json.RawMessage
						_ = json.Unmarshal(content["entries"], &es)
						var facts []map[string]json.RawMessage
						_ = json.Unmarshal(es[0]["requiredFacts"], &facts)
						facts[0]["component"] = json.RawMessage(`"pkg:github/other/other"`)
						es[0]["requiredFacts"], _ = json.Marshal(facts)
						content["entries"], _ = json.Marshal(es)
					case "reserved-id":
						var es []map[string]json.RawMessage
						_ = json.Unmarshal(content["entries"], &es)
						var rule map[string]json.RawMessage
						_ = json.Unmarshal(es[0]["rule"], &rule)
						rule["id"], _ = json.Marshal(cncfcheck.MariaDBCanaryRuleID)
						es[0]["rule"], _ = json.Marshal(rule)
						content["entries"], _ = json.Marshal(es)
					case "alias":
						envelope["Schema"] = envelope["schema"]
					}
					envelope["pack"], _ = json.Marshal(content)
					changedRaw, _ := json.Marshal(envelope)
					entry := selected
					entry.Length, entry.Digest = int64(len(changedRaw)), digestBytes(changedRaw)
					if mode == "digest-mismatch" {
						entry.RuleDigest = "sha256:" + strings.Repeat("ab", 32)
					}
					if mode == "expiry-mismatch" {
						entry.EvidenceExpiresAt = "2099-01-01T00:00:00Z"
					}
					changedIndex := index
					changedIndex.Projects = []cncfcheck.ExternalIndexEntry{entry}
					changedIndexRaw, _ := json.Marshal(changedIndex)
					changed := map[string][]byte{first: changedRaw, ConstraintsProjectsIndexTargetPath: changedIndexRaw}
					f := newProjectsFixture(t)
					good, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base}))
					if err != nil {
						t.Fatal(err)
					}
					receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: changed}))
					if mode == "extension" || mode == "unknown-null" || mode == "direct-null" {
						if !errors.Is(err, ErrUnsupportedKnowledge) || errors.Is(err, ErrIntegrity) || receipt.TrustStateAdvanced || receipt.TrustStateDigest != good.TrustStateDigest || receipt.SelectionChanged {
							t.Fatalf("unsupported extension: %v %+v", err, receipt)
						}
					} else if !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrUnsupportedKnowledge) || receipt.SelectionChanged {
						t.Fatalf("malformed extension: %v %+v", err, receipt)
					}
				})
			}
		})
	}
}

func TestCompatOuterExtensionsRemainIntegrity(t *testing.T) {
	base := futureProjectsTargets(t, "5")
	first, _ := firstProjects(base)
	old := base[first]
	for _, extension := range []string{`"futureField":true`, `"futureField":null`} {
		t.Run(extension, func(t *testing.T) {
			raw := append(append([]byte(nil), old[:len(old)-1]...), []byte(","+extension+"}")...)
			index := bytes.Replace(base[ConstraintsProjectsIndexTargetPath], []byte(fmt.Sprintf(`"length":%d,"digest":"%s"`, len(old), digestBytes(old))), []byte(fmt.Sprintf(`"length":%d,"digest":"%s"`, len(raw), digestBytes(raw))), 1)
			if bytes.Equal(index, base[ConstraintsProjectsIndexTargetPath]) {
				t.Fatal("target binding absent")
			}
			changed := make(map[string][]byte)
			for k, v := range base {
				changed[k] = v
			}
			changed[first] = raw
			changed[ConstraintsProjectsIndexTargetPath] = index
			f := newProjectsFixture(t)
			if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: base})); err != nil {
				t.Fatal(err)
			}
			receipt, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: changed}))
			if !errors.Is(err, ErrIntegrity) || errors.Is(err, ErrUnsupportedKnowledge) || receipt.SelectionChanged {
				t.Fatalf("compat extension: %v %+v", err, receipt)
			}
		})
	}
}
