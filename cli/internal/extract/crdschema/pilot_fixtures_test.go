// SPDX-License-Identifier: AGPL-3.0-only

package crdschema

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Pilot fixtures: unmodified upstream CRD manifests at pinned release tags
// (testdata/pilot/manifest.json records repo, tag, commit, path and sha256).
// Each pair is derived with the real extractor and compared with a golden
// stored in testdata/pilot/golden. Regenerate the goldens by running this
// package's tests with -update-pilot, then review the diff by eye.
var updatePilot = flag.Bool("update-pilot", false, "rewrite the pilot goldens")

type pilotManifest struct {
	Files []struct {
		Project      string `json:"project"`
		Tag          string `json:"tag"`
		Commit       string `json:"commit"`
		UpstreamPath string `json:"upstream_path"`
		SHA256       string `json:"sha256"`
	} `json:"files"`
	Pairs []struct {
		Name    string `json:"name"`
		Project string `json:"project"`
		From    string `json:"from"`
		To      string `json:"to"`
	} `json:"pairs"`
}

func loadPilotManifest(t *testing.T) pilotManifest {
	t.Helper()
	raw, err := os.ReadFile("testdata/pilot/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m pilotManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func pilotSide(t *testing.T, m *memReader, commit, project, tag string) {
	t.Helper()
	dir := filepath.Join("testdata", "pilot", project, tag, "crd")
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) == 0 {
		t.Fatalf("pilot side %s/%s: %v", project, tag, err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		m.put(commit, "crd/"+e.Name(), b)
	}
}

func TestPilotFixturesProvenance(t *testing.T) {
	m := loadPilotManifest(t)
	if len(m.Files) == 0 || len(m.Pairs) == 0 {
		t.Fatal("empty pilot manifest")
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		if len(f.Commit) != 40 || strings.Trim(f.Commit, "0123456789abcdef") != "" {
			t.Errorf("%s %s: commit %q is not a full sha", f.Project, f.Tag, f.Commit)
		}
		rel := filepath.Join(f.Project, f.Tag, "crd", filepath.Base(f.UpstreamPath))
		b, err := os.ReadFile(filepath.Join("testdata", "pilot", rel))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("%s: sha256 differs from the manifest", rel)
		}
		listed[rel] = true
	}
	// No fixture file may exist without provenance.
	root := filepath.Join("testdata", "pilot")
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if strings.HasSuffix(rel, ".json") && (rel == "manifest.json" || filepath.Dir(rel) == "golden") {
			return nil
		}
		if !listed[rel] {
			t.Errorf("%s has no provenance entry", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPilotFixtures(t *testing.T) {
	m := loadPilotManifest(t)
	results := map[string]*Result{}
	for _, p := range m.Pairs {
		mem := newMem()
		pilotSide(t, mem, commitA, p.Project, p.From)
		pilotSide(t, mem, commitB, p.Project, p.To)
		res, err := Derive(context.Background(), mem, testTarget, commitA, commitB)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		results[p.Name] = res
		got, err := res.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, got, "", "  "); err != nil {
			t.Fatal(err)
		}
		pretty.WriteByte('\n')
		golden := filepath.Join("testdata", "pilot", "golden", p.Name+".json")
		if *updatePilot {
			if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(golden, pretty.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if !bytes.Equal(want, pretty.Bytes()) {
			t.Errorf("%s: result differs from golden\n got: %s\nwant: %s", p.Name, pretty.String(), want)
		}
	}

	// Hand-checked against the upstream diffs. Upstream only adds from
	// cert-manager 1.15 to 1.18 and from Argo CD 2.14 to 3.2, so the forward
	// pairs report no removal; read backwards, the same files report those
	// additions as removals.
	for _, n := range []string{"certmanager_certificates_1.15_to_1.18", "argocd_appproject_2.14_to_3.2"} {
		r := results[n]
		if !r.Fields.Complete || !r.Enums.Complete || len(r.Fields.Members) != 0 || len(r.Enums.Members) != 0 || len(r.Ledger) != 0 {
			t.Errorf("%s: want a complete result with no removal", n)
		}
	}
	if r := results["certmanager_certificates_1.18_to_1.15"]; !containsSuffix(r.Fields.Members, "/renewBeforePercentage") {
		t.Errorf("reverse cert-manager pair must report renewBeforePercentage removed: %v", r.Fields.Members)
	}
	if r := results["argocd_appproject_3.2_to_2.14"]; !containsSuffix(r.Fields.Members, "/andOperator") {
		t.Errorf("reverse Argo CD pair must report andOperator removed: %v", r.Fields.Members)
	}
	// cert-manager 1.5 to 1.6 carries a conversion webhook: withheld, never
	// a claim.
	w := results["certmanager_certificaterequests_1.5_to_1.6"]
	if w.Fields.Complete || len(w.Ledger) == 0 || w.Ledger[0].Code != "CRD_CONVERSION_WEBHOOK" {
		t.Errorf("1.5 to 1.6 must be withheld for the conversion webhook: %+v", w.Ledger)
	}
}

func containsSuffix(ms []string, suf string) bool {
	for _, m := range ms {
		if strings.HasSuffix(m, suf) {
			return true
		}
	}
	return false
}
