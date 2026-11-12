// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

func antreaProjectionFixture() map[string][]byte {
	data := map[string][]byte{}
	var resources strings.Builder
	resources.WriteString("resources:\n")
	var definitions []string
	for _, kind := range []string{"Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Zeta", "Eta", "Theta", "Iota"} {
		p := "bases/" + strings.ToLower(kind) + ".yaml"
		fmt.Fprintf(&resources, "- %s\n", p)
		body := crd(kind, "v1")
		data["multicluster/config/crd/"+p] = []byte(body)
		definitions = append(definitions, body)
	}
	data["multicluster/config/crd/kustomization.yaml"] = []byte(resources.String())
	for _, mode := range antreaModes {
		output := mode
		if mode == "leader-ns" {
			output = "leader-namespaced"
			data["multicluster/build/yamls/antrea-multicluster-"+output+".yml"] = []byte("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: example\n")
			continue
		}
		var shipped, patches []string
		for i, body := range definitions {
			deleted := mode == "member" && i >= 6 || mode != "member" && i < 5
			if !deleted {
				shipped = append(shipped, body)
				continue
			}
			_, crds, _ := parseFile("fixture.yaml", []byte(body))
			patches = append(patches, "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: "+crds[0].Name+"\n$patch: delete\n")
		}
		data["multicluster/config/overlays/"+mode+"/crd_patch.yaml"] = []byte(strings.Join(patches, "---\n"))
		data["multicluster/build/yamls/antrea-multicluster-"+output+".yml"] = []byte(strings.Join(shipped, "---\n"))
	}
	return data
}

func TestAntreaModeProjection(t *testing.T) {
	data := antreaProjectionFixture()
	modes, err := projectAntreaModes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(modes) != 4 || len(modes["leader-ns"]) != 0 || len(modes["leader"]) != 4 || len(modes["member"]) != 6 {
		t.Fatalf("mode inventories: %+v", modes)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string][]byte)
	}{
		{"namespace gains a CRD", func(d map[string][]byte) {
			d["multicluster/build/yamls/antrea-multicluster-leader-namespaced.yml"] = []byte(crd("Alpha", "v1"))
		}},
		{"missing namespace output", func(d map[string][]byte) {
			delete(d, "multicluster/build/yamls/antrea-multicluster-leader-namespaced.yml")
		}},
		{"served flag differs", func(d map[string][]byte) {
			p := "multicluster/build/yamls/antrea-multicluster-member.yml"
			d[p] = []byte(strings.Replace(string(d[p]), "served: true", "served: false", 1))
		}},
		{"unexpected deletion directive", func(d map[string][]byte) {
			p := "multicluster/config/overlays/leader/crd_patch.yaml"
			d[p] = []byte(strings.ReplaceAll(string(d[p]), "$patch: delete", "$patch: replace"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := antreaProjectionFixture()
			tc.edit(d)
			if _, err := projectAntreaModes(d); err == nil {
				t.Fatal("accepted a different or missing mode output")
			}
		})
	}
}

func TestAntreaWholeDeleteStrict(t *testing.T) {
	name := "alphas." + synthGroup
	known := map[string]CRD{name: {Name: name}}
	good := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: " + name + "\n$patch: delete\n"
	if _, err := antreaDeletes([]byte(good), known); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		good + "spec: {}\n", good + "metadata: {}\n", good + "---\n" + good,
		strings.Replace(good, name, "missing."+synthGroup, 1),
		strings.Replace(good, "$patch: delete", "$patch: replace", 1),
		strings.Replace(good, "  name: "+name, "  name: "+name+"\n  labels: {}", 1),
		strings.Replace(good, "apiextensions.k8s.io/v1", "apiextensions.k8s.io/v1beta1", 1),
	} {
		if _, err := antreaDeletes([]byte(bad), known); err == nil {
			t.Fatalf("accepted non-exact deletion: %s", bad)
		}
	}
}

func antreaModeState(tag string, modes map[string][]string) *tagState {
	return &tagState{tag: extract.Tag{Name: tag}, inv: &Inventory{Complete: true},
		scan: &ScanRecord{Complete: true, AntreaModes: &AntreaModeRecord{Modes: modes, verified: true}}}
}

func TestAntreaModeLossCannotHideInUnion(t *testing.T) {
	base := func() map[string][]string {
		return map[string][]string{"leader": {"example.io/v1/Shared"}, "leader-global": {}, "leader-ns": {}, "member": {"example.io/v1/Shared"}}
	}
	from, to := antreaModeState("v2.2.0", base()), antreaModeState("v2.3.0", base())
	fromLine, toLine := &releaseLine{Major: 2, Minor: 2}, &releaseLine{Major: 2, Minor: 3}
	check := func() *Completeness {
		return completeness(antreaComponent, fromLine, toLine, []*tagState{from}, []*tagState{to}, &LinesRecord{LineWide: true}, nil, nil)
	}
	if !check().Attestable {
		t.Fatal("unchanged verified mode views should permit the completeness check")
	}
	to.scan.AntreaModes.Modes["leader"] = nil
	if !slices.Contains(to.scan.AntreaModes.Modes["member"], "example.io/v1/Shared") {
		t.Fatal("fixture must retain the member in the global union")
	}
	if got := check(); got.Attestable || !strings.Contains(strings.Join(got.Reasons, " "), "mode leader no longer serves") {
		t.Fatalf("union concealed a mode removal: %+v", got)
	}
	for _, tc := range []struct {
		name string
		edit func(*AntreaModeRecord)
	}{
		{"hidden mode", func(p *AntreaModeRecord) { p.Modes["hidden"] = nil }},
		{"aliased mode", func(p *AntreaModeRecord) { p.Modes["namespace"] = p.Modes["leader-ns"]; delete(p.Modes, "leader-ns") }},
		{"namespace gains a CRD", func(p *AntreaModeRecord) { p.Modes["leader-ns"] = []string{"example.io/v1/Shared"} }},
		{"serialized observation", func(p *AntreaModeRecord) {
			raw, _ := json.Marshal(p)
			*p = AntreaModeRecord{}
			_ = json.Unmarshal(raw, p)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			to = antreaModeState("v2.3.0", base())
			tc.edit(to.scan.AntreaModes)
			if check().Attestable {
				t.Fatal("attested an incomplete or unverified mode inventory")
			}
		})
	}
}

func TestAntreaModeSourceReadsBodies(t *testing.T) {
	repo, _ := extract.ParseRepo("github.com/antrea-io/antrea")
	commit := commitOf("antrea-mode-fixture")
	p := "multicluster/config/overlays/leader-ns/kustomization.yaml"
	reader := memReader{commit + ":" + p: []byte("bases: [../../default]\n")}
	entries := []extract.TreeEntry{{Path: p, Mode: "100644", Type: "blob", SHA: strings.Repeat("1", 40)}}
	_, baseline, err := readAntreaModeSource(reader, repo, commit, entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, added := range []string{"multicluster/config/overlays/hidden/kustomization.yaml", "multicluster/config/overlays/namespace/kustomization.yaml"} {
		reader[commit+":"+added] = []byte("bases: [../../default]\n")
		extra := append(slices.Clone(entries), extract.TreeEntry{Path: added, Mode: "100644", Type: "blob", SHA: strings.Repeat("2", 40)})
		_, changed, err := readAntreaModeSource(reader, repo, commit, extra)
		if err != nil || changed == baseline {
			t.Fatalf("hidden or aliased mode did not change the authoritative source pin: %s", added)
		}
	}
	reader[commit+":"+p] = []byte("bases: [../../crd]\n")
	_, changed, err := readAntreaModeSource(reader, repo, commit, entries)
	if err != nil || changed == baseline {
		t.Fatal("unchanged metadata concealed changed no-CRD-word source bytes")
	}
	for _, mode := range []string{"120000", "160000"} {
		bad := slices.Clone(entries)
		bad[0].Mode = mode
		if _, _, err := readAntreaModeSource(reader, repo, commit, bad); err == nil {
			t.Fatal("accepted a source indirection")
		}
	}
	if _, err := readAntreaModes(reader, repo, commit, entries); err == nil {
		t.Fatal("unreviewed source commit admitted")
	}
}

// An optional offline source fixture exercises all reviewed upstream pins.
// Ordinary synthetic refusal controls above do not require this fixture.
func TestAntreaCapturedModes(t *testing.T) {
	root := os.Getenv("ANTREA_MODE_SOURCE_FIXTURE")
	if root == "" {
		t.Skip("no offline source fixture supplied")
	}
	var records []struct {
		Tag, Commit string
		Entries     []extract.TreeEntry
	}
	raw, err := os.ReadFile(filepath.Join(root, "profile-source-index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 21 {
		t.Fatalf("release census: %d", len(records))
	}
	repo, _ := extract.ParseRepo("github.com/antrea-io/antrea")
	for _, record := range records {
		t.Run(record.Tag, func(t *testing.T) {
			r := antreaCapturedReader{root: filepath.Join(root, "captured", record.Tag)}
			proof, err := readAntreaModes(r, repo, record.Commit, record.Entries)
			if err != nil || proof == nil || !proof.verified || len(proof.Modes) != 4 || len(proof.Modes["leader-ns"]) != 0 {
				t.Fatalf("actual four-mode profile: %+v, %v", proof, err)
			}
		})
	}
	first := records[0]
	t.Run("only verified delete findings become nonblocking", func(t *testing.T) {
		r := antreaCapturedReader{root: filepath.Join(root, "captured", first.Tag)}
		scan := &ScanRecord{Complete: true, Findings: []Finding{
			{Path: "multicluster/config/overlays/leader/crd_patch.yaml", Class: ClassUnread, Reason: ReasonPatchNotStrict},
			{Path: "multicluster/config/crd/k8smcs/multicluster.x-k8s.io_serviceexports.yaml", Class: ClassExtra},
			{Path: "multicluster/config/overlays/hidden/crd_patch.yaml", Class: ClassUnread, Reason: ReasonPatchNotStrict},
		}}
		x := New(Target{Component: antreaComponent})
		if err := x.checkAntreaModes(r, repo, first.Commit, first.Entries, scan); err != nil {
			t.Fatal(err)
		}
		if scan.AntreaModes == nil || scan.Findings[0].blocks() || !scan.Findings[1].blocks() || !scan.Findings[2].blocks() {
			t.Fatal("the mode proof bypassed a source or ownership hold")
		}
	})
	for _, p := range []string{
		"multicluster/config/overlays/leader-ns/kustomization.yaml",
		"multicluster/config/overlays/leader/prefix_transformer.yaml",
		"multicluster/hack/generate-manifest.sh", "hack/verify-kustomize.sh",
		"multicluster/build/yamls/antrea-multicluster-leader-namespaced.yml",
	} {
		t.Run("changed/"+p, func(t *testing.T) {
			r := antreaCapturedReader{root: filepath.Join(root, "captured", first.Tag), override: map[string][]byte{p: []byte("unreviewed tool override or transform\n")}}
			if proof, err := readAntreaModes(r, repo, first.Commit, first.Entries); err == nil || proof != nil {
				t.Fatal("accepted changed bytes with a claimed known source inventory")
			}
		})
	}
}

type antreaCapturedReader struct {
	root     string
	override map[string][]byte
}

func (r antreaCapturedReader) Read(_ extract.RepoRef, _, p string) ([]byte, error) {
	if body, ok := r.override[p]; ok {
		return body, nil
	}
	return os.ReadFile(filepath.Join(r.root, filepath.FromSlash(p)))
}

func (r antreaCapturedReader) List(extract.RepoRef, string, string) ([]extract.TreeEntry, error) {
	return nil, fmt.Errorf("source pin verification uses the supplied complete tree inventory")
}
