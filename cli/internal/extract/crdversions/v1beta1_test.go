// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// betaCRD is a complete v1beta1 definition: spec.version names the first
// entry, every entry states served and storage.
func betaCRD(kind string, versions ...string) string { return legacyCRD(kind, versions...) }

func lineNumberOf(t *testing.T, text, needle string, nth int) int {
	t.Helper()
	for i, l := range strings.Split(text, "\n") {
		if strings.Contains(l, needle) {
			if nth == 0 {
				return i + 1
			}
			nth--
		}
	}
	t.Fatalf("no line %q in\n%s", needle, text)
	return 0
}

// A complete v1beta1 definition is a source: its record names the source
// apiVersion, and every version cites the lines of its entry, served and
// storage keys, exactly as the v1 reader does.
func TestV1beta1ReadAsSource(t *testing.T) {
	text := betaCRD("Alpha", "v1beta1", "v1")
	_, crds, err := parseInventoryFile("deploy/crds/a.yaml", []byte(text))
	if err != nil || len(crds) != 1 {
		t.Fatalf("crds %v err %v", crds, err)
	}
	c := crds[0]
	if c.SourceAPIVersion != crdAPIVersionV1beta1 || c.StorageVersion != "v1" || len(c.Versions) != 2 {
		t.Fatalf("crd %+v", c)
	}
	for i, v := range c.Versions {
		if v.ServedLine != lineNumberOf(t, text, "served:", i) || v.StorageLine != lineNumberOf(t, text, "storage:", i) ||
			v.StartLine != lineNumberOf(t, text, "- name:", i) || v.EndLine < v.StorageLine {
			t.Fatalf("version %d lines %+v", i, v)
		}
	}
	if c.VersionsLine != lineNumberOf(t, text, "  versions:", 0) || c.StartLine != 1 {
		t.Fatalf("lines %+v", c)
	}
	if err := checkCitedLines(c); err != nil {
		t.Fatal(err)
	}
	// The v1 reader (every other caller) still refuses it.
	if _, _, err := parseFile("deploy/crds/a.yaml", []byte(text)); err == nil || !strings.Contains(err.Error(), "only apiextensions.k8s.io/v1 is read") {
		t.Fatalf("parseFile: %v", err)
	}
}

// v1 records carry no sourceApiVersion member: their bytes are unchanged.
func TestV1RecordHasNoSourceMember(t *testing.T) {
	_, crds, err := parseInventoryFile("deploy/crds/a.yaml", []byte(crd("Alpha", "v1beta1", "v1")))
	must(t, err)
	raw, err := json.Marshal(crds[0])
	must(t, err)
	if crds[0].SourceAPIVersion != "" || strings.Contains(string(raw), "sourceApiVersion") {
		t.Fatalf("v1 record %s", raw)
	}
}

// Every shape the narrow reader does not admit stays refused, with the
// reason of the v1-only reader.
func TestV1beta1Withheld(t *testing.T) {
	good := betaCRD("Alpha", "v1beta1", "v1")
	versionOnly := legacyCRD("Alpha") + "  version: v1\n"
	cases := []struct{ name, text, want string }{
		{"spec.version only", versionOnly, ""},
		{"neither version nor versions", legacyCRD("Alpha"), ""},
		{"spec.version differs from the first entry", strings.Replace(good, "  version: v1beta1\n", "  version: v1\n", 1), ""},
		{"spec.version not a string", strings.Replace(good, "  version: v1beta1\n", "  version: 1\n", 1), ""},
		{"served missing", strings.Replace(good, "    served: true\n", "", 1), ""},
		{"storage missing", strings.Replace(good, "    storage: false\n", "", 1), ""},
		{"served string", strings.Replace(good, "    served: true\n", "    served: \"true\"\n", 1), ""},
		{"storage string", strings.Replace(good, "    storage: true\n", "    storage: \"true\"\n", 1), ""},
		{"two storage versions", strings.Replace(good, "storage: false", "storage: true", 1), ""},
		{"no storage version", strings.Replace(good, "storage: true", "storage: false", 1), ""},
		{"duplicate version name", strings.Replace(good, "  - name: v1\n", "  - name: v1beta1\n", 1), ""},
		{"empty versions list", strings.Replace(good, "  versions:\n  - name: v1beta1\n    served: true\n    storage: false\n  - name: v1\n    served: true\n    storage: true\n", "  versions: []\n", 1), ""},
		{"versions entry not a mapping", strings.Replace(good, "  - name: v1beta1\n    served: true\n    storage: false\n", "  - v1beta1\n", 1), ""},
		{"bad version name", strings.Replace(good, "- name: v1\n", "- name: V1\n", 1), ""},
		{"name not plural.group", strings.Replace(good, "name: alphas.synth.example.io", "name: other.synth.example.io", 1), ""},
		{"v1beta2", strings.Replace(good, "apiextensions.k8s.io/v1beta1", "apiextensions.k8s.io/v1beta2", 1), "only apiextensions.k8s.io/v1 is read"},
		{"templated", "{{- if .Values.crds }}\n" + good, "template syntax"},
		{"List", "apiVersion: v1\nkind: List\nitems: []\n", "list items are not read"},
		{"CRD List", "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinitionList\nitems: []\n", "list items are not read"},
		{"anchor", strings.Replace(good, "  scope: Namespaced", "  scope: &s Namespaced", 1), "strict YAML subset"},
		{"duplicate key", strings.Replace(good, "    served: true\n", "    served: true\n    served: false\n", 1), "strict YAML subset"},
		{"oversized", good + "#" + strings.Repeat("x", MaxFileBytes) + "\n", "-byte bound"},
		{"other kind in the group", "apiVersion: apiextensions.k8s.io/v1beta1\nkind: Other\n", "has apiVersion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, crds, err := parseInventoryFile("deploy/crds/a.yaml", []byte(tc.text))
			if err == nil || len(crds) != 0 {
				t.Fatalf("read %v, err %v", crds, err)
			}
			want := tc.want
			if want == "" {
				want = "only apiextensions.k8s.io/v1 is read"
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("reason %q lacks %q", err.Error(), want)
			}
		})
	}
	// The good text is read, so every case above fails for its mutation.
	if _, crds, err := parseInventoryFile("deploy/crds/a.yaml", []byte(good)); err != nil || len(crds) != 1 {
		t.Fatalf("good: %v %v", crds, err)
	}
}

// A wrong PASS attempt: flags the file does not write must not be implied
// (a version without storage, a spec.version-only definition), and a
// citation line of 0 must be refused wherever a definition could carry one.
func TestV1beta1WrongPassAttempts(t *testing.T) {
	// Implied flags: no served/storage keys at all.
	implied := strings.NewReplacer("    served: true\n", "", "    storage: false\n", "", "    storage: true\n", "").Replace(betaCRD("Alpha", "v1beta1", "v1"))
	if _, crds, err := parseInventoryFile("deploy/crds/a.yaml", []byte(implied)); err == nil || len(crds) != 0 {
		t.Fatalf("implied flags read: %v %v", crds, err)
	}
	// End to end: the pair stays withheld, with no rule.
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": legacyCRD("Alpha") + "  version: v1\n"}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
	)
	out := runSynth(t, synthTarget(), s)
	p, _ := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "only apiextensions.k8s.io/v1 is read") || len(out.Entries) != 0 {
		t.Fatalf("spec.version-only pair %+v entries %d", p, len(out.Entries))
	}
	// Citation line 0 fails the guard for each line, and the oracle reports it.
	_, crds, err := parseInventoryFile("deploy/crds/a.yaml", []byte(betaCRD("Alpha", "v1beta1", "v1")))
	must(t, err)
	for name, mutate := range map[string]func(c *CRD){
		"start":    func(c *CRD) { c.StartLine = 0 },
		"versions": func(c *CRD) { c.VersionsLine = 0 },
		"entry":    func(c *CRD) { c.Versions[1].StartLine = 0 },
		"end":      func(c *CRD) { c.Versions[1].EndLine = 0 },
		"served":   func(c *CRD) { c.Versions[1].ServedLine = 0 },
		"storage":  func(c *CRD) { c.Versions[0].StorageLine = 0 },
	} {
		c := crds[0]
		c.Versions = append([]CRDVersion(nil), c.Versions...)
		mutate(&c)
		if checkCitedLines(c) == nil {
			t.Fatalf("%s: line 0 accepted", name)
		}
		if d := sourceDiffs([]*Inventory{{Tag: "1.0.0", CRDs: []CRD{c}}}); len(d) != 1 || !strings.HasPrefix(d[0], "LINES ") {
			t.Fatalf("%s: oracle diffs %v", name, d)
		}
	}
	if d := sourceDiffs([]*Inventory{{Tag: "1.0.0", CRDs: []CRD{{Name: "x", SourceAPIVersion: "apiextensions.k8s.io/v1beta2"}}}}); len(d) < 1 || !strings.HasPrefix(d[0], "LINES ") && !strings.HasPrefix(d[0], "SOURCE ") {
		t.Fatalf("unexpected apiVersion accepted: %v", d)
	}
}

// v1beta1 to v1 and v1beta1 to v1beta1 pairs derive the removals, cite
// the served line of the earlier file and carry sourceApiVersion; the oracle
// agrees.
func TestV1beta1PairsAndOracle(t *testing.T) {
	text := betaCRD("Alpha", "v1beta1", "v1")
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": text}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.2.0", map[string]string{"deploy/crds/a.yaml": betaCRD("Alpha", "v1", "v2")}},
	)
	out := runSynth(t, synthTarget(), s)
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || len(proof.Removals) != 1 || proof.Removals[0].Member != synthGroup+"/v1beta1/Alpha" || proof.Removals[0].Reason != ReasonAbsent {
		t.Fatalf("pair %+v removals %+v", p, proof.Removals)
	}
	if c := proof.From.CRDs[0]; c.SourceAPIVersion != crdAPIVersionV1beta1 || proof.To.CRDs[0].SourceAPIVersion != "" {
		t.Fatalf("source versions: from %q to %q", c.SourceAPIVersion, proof.To.CRDs[0].SourceAPIVersion)
	}
	if rm := proof.Removals[0]; rm.FromStartLine != lineNumberOf(t, text, "- name: v1beta1", 0) || rm.FromStartLine < 1 || rm.FromEndLine < rm.FromStartLine {
		t.Fatalf("cited lines %+v", rm)
	}
	// v1beta1 to v1beta1 (storage v1 -> v2, v1 stays served).
	p2, proof2 := pairOf(t, out, "1.1.0", "1.2.0")
	if p2.Status != extract.PairDerived || len(proof2.Removals) != 0 {
		t.Fatalf("pair 2 %+v %+v", p2, proof2.Removals)
	}
	dir := filepath.Join(t.TempDir(), "out")
	must(t, out.Write(dir))
	one := 1
	exp, _ := json.Marshal(Expected{
		Removals: []ExpectedRemoval{{From: "1.0.0", To: "1.1.0", Member: synthGroup + "/v1beta1/Alpha", Reason: "absent"}},
		Pairs:    []ExpectedPair{{From: "1.0.0", To: "1.1.0", Status: "derived", Removals: &one}},
	})
	diffs, err := Oracle(dir, exp)
	must(t, err)
	if len(diffs) != 0 {
		t.Fatalf("oracle: %v", diffs)
	}
	// The oracle still fails when the expectation is wrong.
	bad, _ := json.Marshal(Expected{Removals: []ExpectedRemoval{{From: "1.0.0", To: "1.1.0", Member: synthGroup + "/v1/Alpha", Reason: "absent"}}})
	if diffs, err = Oracle(dir, bad); err != nil || len(diffs) == 0 {
		t.Fatalf("oracle accepted a wrong expectation: %v %v", diffs, err)
	}
	// sourceApiVersion is in the proof written to the manifest.
	raw, err := os.ReadFile(filepath.Join(dir, extract.FileManifest))
	must(t, err)
	if strings.Count(string(raw), `"sourceApiVersion": "apiextensions.k8s.io/v1beta1"`) == 0 {
		t.Fatal("manifest proof lacks sourceApiVersion")
	}
}

// The existing conflict checks run across both apiVersions: the same CRD
// name or kind in a v1 file and a v1beta1 file of the listed paths
// withholds the pair, whatever the versions.
func TestV1beta1ConflictAcrossAPIVersions(t *testing.T) {
	for name, extra := range map[string]map[string]string{
		"same name, same versions":      {"deploy/crds/b.yaml": crd("Alpha", "v1")},
		"same name, differing versions": {"deploy/crds/b.yaml": crd("Alpha", "v1beta1", "v1")},
		"same name, differing flags":    {"deploy/crds/b.yaml": strings.Replace(crd("Alpha", "v1"), "served: true", "served: false", 1)},
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"deploy/crds/a.yaml": betaCRD("Alpha", "v1beta1", "v1")}
			for k, v := range extra {
				files[k] = v
			}
			s := newSynth(
				release{"v1.0.0", files},
				release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
			)
			out := runSynth(t, synthTarget(), s)
			p, _ := pairOf(t, out, "1.0.0", "1.1.0")
			if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "is defined in both") || len(out.Entries) != 0 {
				t.Fatalf("pair %+v", p)
			}
		})
	}
	// The group or kind of one name changing across releases (v1beta1 to v1)
	// is still the identity conflict.
	changed := strings.Replace(crd("Alpha", "v1"), "kind: Alpha", "kind: Alphax", 1)
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": betaCRD("Alpha", "v1beta1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": changed}},
	)
	out := runSynth(t, synthTarget(), s)
	if p, _ := pairOf(t, out, "1.0.0", "1.1.0"); p.Status != extract.PairWithheld || len(out.Entries) != 0 {
		t.Fatalf("kind change %+v", p)
	}
}

// parseLegacy (the reader of v1beta1 copies) never panics and never reads a
// definition the narrow source reader refuses without refusing it itself
// or keeping the copy-only class: a source read implies a legacy read of
// the same versions.
func FuzzV1beta1Source(f *testing.F) {
	f.Add([]byte(betaCRD("Alpha", "v1beta1", "v1")))
	f.Add([]byte(betaCRD("Alpha", "v1")))
	f.Add([]byte(crd("Alpha", "v1")))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, src, err := parseInventoryFile("f.yaml", data)
		legacy, lerr := parseLegacy(data)
		if err != nil {
			return
		}
		for _, c := range src {
			if err := checkCitedLines(c); c.SourceAPIVersion != "" && err != nil {
				t.Fatalf("source read without citable lines: %v", err)
			}
			if c.SourceAPIVersion == "" {
				continue
			}
			if lerr != nil || len(legacy) == 0 {
				t.Fatalf("source read but legacy refused: %v", lerr)
			}
			found := false
			for _, l := range legacy {
				if l.Name == c.Name && len(l.Versions) == len(c.Versions) {
					found = true
					for i := range l.Versions {
						if l.Versions[i].Name != c.Versions[i].Name || l.Versions[i].Served != c.Versions[i].Served || l.Versions[i].Storage != c.Versions[i].Storage {
							t.Fatalf("versions differ: %+v vs %+v", l.Versions, c.Versions)
						}
					}
				}
			}
			if !found {
				t.Fatalf("no legacy twin for %s", c.Name)
			}
		}
	})
}
