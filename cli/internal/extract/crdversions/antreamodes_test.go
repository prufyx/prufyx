// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/factorymirror"
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
	_, proof := antreaDependencyFixture()
	proof.Modes = modes
	return &tagState{tag: extract.Tag{Name: tag}, inv: &Inventory{Complete: true},
		scan: &ScanRecord{Complete: true, AntreaModes: proof}}
}

func antreaDependencyFixture() (*Inventory, *AntreaModeRecord) {
	commit := "a13d931239e8ac2c94e002dc82ce923d0a28b71d"
	inv := &Inventory{Commit: commit, Complete: true, CRDs: []CRD{{Name: "alphas.crd.antrea.io", Group: "crd.antrea.io", Kind: "Alpha"}}}
	proof := &AntreaModeRecord{SourceSHA256: antreaModePins[commit], verified: true, dependencies: map[string]CRD{},
		Modes: map[string][]string{"leader": {}, "leader-global": {}, "leader-ns": {}, "member": {}}}
	for _, spec := range append(slices.Clone(antreaMCSDependencies), antreaNADDependency) {
		c := CRD{Name: spec.name, Group: spec.group, Kind: spec.kind,
			Plural: strings.Split(spec.name, ".")[0], Scope: "Namespaced", Path: spec.file,
			StorageVersion: spec.version, Versions: []CRDVersion{{Name: spec.version, Served: true, Storage: true}}}
		inv.CRDs = append(inv.CRDs, c)
		inv.Files = append(inv.Files, FileRecord{Path: spec.file, SHA256: spec.sha256, CRDs: 1})
		proof.dependencies[spec.name] = c
		if spec.group == "multicluster.x-k8s.io" {
			proof.Modes["member"] = append(proof.Modes["member"], member(c.Group, spec.version, c.Kind))
		}
	}
	return inv, proof
}

func TestAntreaInstalledDependencies(t *testing.T) {
	repo, _ := extract.ParseRepo("github.com/antrea-io/antrea")
	target := Target{Project: "antrea", Repo: repo.Key, Component: antreaComponent}
	x := New(target)
	raw, proof := antreaDependencyFixture()
	before, _ := json.Marshal(raw)
	got, err := x.attributedAntreaInventory(repo, raw, proof)
	if err != nil || len(got.CRDs) != 1 || len(got.Foreign) != 3 || len(got.Files) != 3 {
		t.Fatalf("installed dependency classification: %+v, %v", got, err)
	}
	after, _ := json.Marshal(raw)
	if string(before) != string(after) {
		t.Fatal("cached raw inventory changed")
	}
	got.Files[0].SHA256 = "changed receipt"
	if raw.Files[0].SHA256 != antreaMCSDependencies[0].sha256 {
		t.Fatal("attributed inventory shares mutable file receipts with the raw cache")
	}
	for _, spec := range antreaMCSDependencies {
		if _, attribution := customresources.DefaultIndex().OwnerOf("multicluster.x-k8s.io", spec.kind); attribution != customresources.Unknown {
			t.Fatal("unmapped customer MCS resources must remain unknown")
		}
	}
	if _, attribution := customresources.DefaultIndex().OwnerOf(antreaNADDependency.group, antreaNADDependency.kind); attribution != customresources.Unknown {
		t.Fatal("unmapped customer NAD resources must remain unknown")
	}
	otherOwner := New(target).WithIndex(customresources.NewIndex([]customresources.Project{
		{Slug: "antrea", Groups: []customresources.Group{{Name: "crd.antrea.io"}}},
		{Slug: "other", Groups: []customresources.Group{{Name: "multicluster.x-k8s.io"}}},
		{Slug: "nad-owner", Groups: []customresources.Group{{Name: "k8s.cni.cncf.io"}}},
	}))
	if inv, err := otherOwner.attributedAntreaInventory(repo, raw, proof); err != nil || len(inv.Foreign) != 3 {
		t.Fatalf("a unique other owner was not preserved: %+v, %v", inv, err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Inventory, *AntreaModeRecord, *Extractor)
	}{
		{"own object as foreign", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) { i.CRDs[1].Group = "crd.antrea.io" }},
		{"missing object", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) { i.CRDs = i.CRDs[:2] }},
		{"missing listed receipt", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) { i.Files = i.Files[:1] }},
		{"changed body receipt", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) {
			i.Files[0].SHA256 = "sha256:" + strings.Repeat("0", 64)
		}},
		{"changed dependency API", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) { i.CRDs[1].Versions[0].Name = "v1alpha2" }},
		{"missing mode", func(_ *Inventory, p *AntreaModeRecord, _ *Extractor) { delete(p.Modes, "leader-ns") }},
		{"forged source pin", func(_ *Inventory, p *AntreaModeRecord, _ *Extractor) { p.SourceSHA256 = strings.Repeat("0", 64) }},
		{"serialized proof", func(_ *Inventory, p *AntreaModeRecord, _ *Extractor) {
			b, _ := json.Marshal(p)
			*p = AntreaModeRecord{}
			_ = json.Unmarshal(b, p)
		}},
		{"Antrea ownership", func(_ *Inventory, _ *AntreaModeRecord, x *Extractor) {
			x.WithIndex(syntheticOwnership(target, "multicluster.x-k8s.io"))
		}},
		{"ambiguous ownership", func(_ *Inventory, _ *AntreaModeRecord, x *Extractor) {
			x.WithIndex(customresources.NewIndex([]customresources.Project{
				{Slug: "other", Groups: []customresources.Group{{Name: "multicluster.x-k8s.io"}}},
				{Slug: "second", Groups: []customresources.Group{{Name: "multicluster.x-k8s.io"}}},
			}))
		}},
		{"foreign repository", func(_ *Inventory, _ *AntreaModeRecord, x *Extractor) { x.target.Repo = "github.com/example/other" }},
		{"missing NAD source proof", func(_ *Inventory, p *AntreaModeRecord, _ *Extractor) {
			delete(p.dependencies, antreaNADDependency.name)
		}},
		{"missing NAD object", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) { i.CRDs = i.CRDs[:3] }},
		{"missing NAD receipt", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) { i.Files = i.Files[:2] }},
		{"changed NAD receipt", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) {
			i.Files[2].SHA256 = "sha256:" + strings.Repeat("0", 64)
		}},
		{"changed NAD API", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) { i.CRDs[3].Versions[0].Name = "v2" }},
		{"repeated NAD object", func(i *Inventory, _ *AntreaModeRecord, _ *Extractor) { i.CRDs = append(i.CRDs, i.CRDs[3]) }},
		{"Antrea NAD ownership", func(_ *Inventory, _ *AntreaModeRecord, x *Extractor) {
			x.WithIndex(syntheticOwnership(target, "k8s.cni.cncf.io"))
		}},
		{"ambiguous NAD ownership", func(_ *Inventory, _ *AntreaModeRecord, x *Extractor) {
			x.WithIndex(customresources.NewIndex([]customresources.Project{
				{Slug: "other", Groups: []customresources.Group{{Name: "k8s.cni.cncf.io"}}},
				{Slug: "second", Groups: []customresources.Group{{Name: "k8s.cni.cncf.io"}}},
			}))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, p := antreaDependencyFixture()
			x := New(target)
			tc.edit(i, p, x)
			if got, err := x.attributedAntreaInventory(repo, i, p); err == nil || got != nil {
				t.Fatal("unproved dependency was classified foreign")
			}
		})
	}
}

func TestAntreaMCSModeLossCannotHideInUnion(t *testing.T) {
	m := "multicluster.x-k8s.io/v1alpha1/ServiceExport"
	base := func() map[string][]string {
		return map[string][]string{"leader": {m}, "leader-global": {}, "leader-ns": {}, "member": {m}}
	}
	from, to := antreaModeState("v2.2.0", base()), antreaModeState("v2.3.0", base())
	to.scan.AntreaModes.Modes["leader"] = nil
	got := completeness(antreaComponent, &releaseLine{Major: 2, Minor: 2}, &releaseLine{Major: 2, Minor: 3},
		[]*tagState{from}, []*tagState{to}, &LinesRecord{LineWide: true}, nil, nil)
	if !slices.Contains(to.scan.AntreaModes.Modes["member"], m) || got.Attestable {
		t.Fatalf("MCS removal concealed by the retained union: %+v", got)
	}
	to = antreaModeState("v2.3.0", base())
	to.scan.AntreaModes.Modes["leader"] = append(to.scan.AntreaModes.Modes["leader"], "multicluster.x-k8s.io/v1alpha2/ServiceExport")
	if len(antreaModeProblems(antreaComponent, []*tagState{from, to})) == 0 {
		t.Fatal("a changed MCS dependency serving set was accepted")
	}
}

func TestAntreaDependencyAttributionBound(t *testing.T) {
	view := func(ix customresources.Index) string {
		body, err := fs.ReadFile(CodeViewWithIndex(source, "antrea", ix), AttributionFileName)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	baseline := view(customresources.DefaultIndex())
	for _, group := range []string{"multicluster.x-k8s.io", "k8s.cni.cncf.io"} {
		projects := customresources.Projects()
		projects = append(projects, customresources.Project{Slug: "other", Groups: []customresources.Group{{Name: group}}})
		owned := view(customresources.NewIndex(projects))
		projects = append(projects, customresources.Project{Slug: "second", Groups: []customresources.Group{{Name: group}}})
		ambiguous := view(customresources.NewIndex(projects))
		if baseline == owned || owned == ambiguous || baseline == ambiguous {
			t.Fatalf("consulted attribution of %s changed without changing the code identity input", group)
		}
	}
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
		"multicluster/config/crd/k8smcs/multicluster.x-k8s.io_serviceexports.yaml",
		"multicluster/config/crd/k8smcs/multicluster.x-k8s.io_serviceimports.yaml",
		antreaNADDependency.file,
	} {
		t.Run("changed/"+p, func(t *testing.T) {
			r := antreaCapturedReader{root: filepath.Join(root, "captured", first.Tag), override: map[string][]byte{p: []byte("unreviewed tool override or transform\n")}}
			if proof, err := readAntreaModes(r, repo, first.Commit, first.Entries); err == nil || proof != nil {
				t.Fatal("accepted changed bytes with a claimed known source inventory")
			}
		})
	}
}

// A missing mandatory dependency at one release must not borrow another
// release's complete inventory or preserve that line's attestation.
func TestAntreaMissingDependencyWithholdsPair(t *testing.T) {
	root := os.Getenv("ANTREA_MODE_SOURCE_MIRROR")
	if root == "" {
		t.Skip("no offline source mirror supplied")
	}
	mirror, err := factorymirror.OpenReader(root)
	if err != nil {
		t.Fatal(err)
	}
	base := extract.MirrorReader{R: mirror}
	tg := target(t, "antrea")
	if !tg.Attest {
		t.Fatal("the positive baseline requires the reviewed attesting target")
	}
	repo, err := extract.ParseRepo(tg.Repo)
	if err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, r extract.PinnedReader) *extract.Output {
		t.Helper()
		x := New(tg)
		out, err := extract.Run(context.Background(), x, ReleaseTags(x, base), r, extract.Options{Repo: repo, DerivedAt: derivedAt})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	positive := run(t, base)
	if positive.Manifest.Totals.Derived != 5 || positive.Manifest.Totals.Withheld != 0 || positive.Manifest.Totals.Attestations != 5 {
		t.Fatalf("positive baseline is not fully attested: %+v", positive.Manifest.Totals)
	}
	var last extract.PairRecord
	for _, pair := range positive.Manifest.Pairs {
		if pair.From == "2.6.0" && pair.To == "2.7.0" {
			last = pair
		}
	}
	if last.ToCommit == "" || last.Attestation == nil || last.Attestation.Status != extract.PairAttested {
		t.Fatalf("missing attested last-line baseline: %+v", last)
	}
	for _, file := range []string{antreaMCSDependencies[0].file, antreaNADDependency.file} {
		t.Run(file, func(t *testing.T) {
			out := run(t, antreaMissingDependencyReader{PinnedReader: base, commit: last.ToCommit, file: file})
			for _, pair := range out.Manifest.Pairs {
				if pair.From != last.From || pair.To != last.To {
					continue
				}
				if pair.Status != extract.PairWithheld || pair.Attestation == nil || pair.Attestation.Status != extract.PairNotAttested {
					t.Fatalf("missing mandatory dependency retained the pair: %+v", pair)
				}
				return
			}
			t.Fatal("the required last-line pair disappeared")
		})
	}
}

type antreaMissingDependencyReader struct {
	extract.PinnedReader
	commit, file string
}

func (r antreaMissingDependencyReader) Read(repo extract.RepoRef, commit, file string) ([]byte, error) {
	if commit == r.commit && file == r.file {
		return nil, extract.ErrNotFound
	}
	return r.PinnedReader.Read(repo, commit, file)
}

func (r antreaMissingDependencyReader) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	entries, err := r.PinnedReader.List(repo, commit, dir)
	if commit == r.commit {
		entries = slices.DeleteFunc(slices.Clone(entries), func(e extract.TreeEntry) bool { return e.Path == r.file })
		// Removing a blob changes every enclosing tree. Do not let the
		// recorder reuse an earlier release's unchanged directory listing.
		for i := range entries {
			if entries[i].Type == "tree" && strings.HasPrefix(r.file, entries[i].Path+"/") {
				entries[i].SHA = commitOf("missing:" + entries[i].Path + ":" + r.file)
			}
		}
	}
	return entries, err
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
