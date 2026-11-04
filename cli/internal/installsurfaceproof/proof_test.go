// SPDX-License-Identifier: AGPL-3.0-only

package installsurfaceproof

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixtureReader struct {
	materials          Materials
	output             Output
	reads, inspections int
}

func (f *fixtureReader) Materialize(context.Context, Proof) (Materials, error) {
	f.reads++
	return f.materials, nil
}
func (f *fixtureReader) Inspect(_ context.Context, b []byte) (Output, error) {
	f.inspections++
	if Digest(b) != f.output.Digest {
		return Output{}, errors.New("fixture inspector input changed")
	}
	return f.output, nil
}

type fixtureRenderer struct {
	recipe Render
	output []byte
	calls  int
	err    error
}

func (r *fixtureRenderer) Identity() (string, string, string) {
	return r.recipe.BinaryDigest, r.recipe.ImageDigest, r.recipe.Version
}
func (r *fixtureRenderer) Render(_ context.Context, recipe Render, _ Materials) ([]byte, error) {
	r.calls++
	if !reflect.DeepEqual(recipe, r.recipe) {
		return nil, errors.New("fixture recipe changed")
	}
	return r.output, r.err
}

func proofFixture() (Proof, BasePolicy, *fixtureReader, *fixtureRenderer, time.Time) {
	file := []byte("apiVersion: v2\nname: fixture\nversion: 1.0.0\n")
	values := []byte("replicas: 1\n")
	rendered := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fixture\n")
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	f := File{Path: "Chart.yaml", Mode: "100644", Size: int64(len(file)), GitBlob: strings.Repeat("1", 40), Digest: Digest(file)}
	resource := File{Path: "000-configmap.json", Mode: "100644", Size: int64(len(rendered)), Digest: Digest(rendered)}
	p := Proof{Schema: Schema, Tuple: Tuple{Project: "fixture", Component: "pkg:github/example/fixture", Surface: "helm", AppRepository: "github.com/example/fixture", AppTag: "1.0.0", AppCommit: strings.Repeat("2", 40), From: "0.9.0", To: "1.0.0", ConfigID: "synthetic-defaults", Families: []string{"helm.values"}},
		Origin:           Origin{IndexURL: "https://example.invalid/index.yaml", IndexDigest: Digest([]byte("index fixture")), ChartName: "fixture", ChartVersion: "1.0.0", AppVersion: "1.0.0", ArchiveURL: "https://example.invalid/fixture-1.0.0.tgz", ArchiveDigest: Digest([]byte("archive fixture")), Source: Source{Repository: "github.com/example/fixture", Commit: strings.Repeat("2", 40), Directory: "charts/fixture", Tree: strings.Repeat("3", 40)}, ObservedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		ArchiveInventory: []File{f}, SourceInventory: []File{f}, ChartLockDigest: Digest(nil), Dependencies: []Dependency{},
		Render: Render{Version: "fixture-only", BinaryDigest: Digest([]byte("fixture binary")), ImageDigest: Digest([]byte("fixture image")), KubernetesVersion: "1.31.0", Capabilities: []string{"v1/ConfigMap"}, Values: []Artifact{{Path: "values.yaml", Digest: Digest(values)}}, Flags: []string{}, CPUMillis: 1000, MemoryMiB: 128, PIDs: 32, TimeoutSeconds: 1},
		Output: Output{Digest: Digest(rendered), Resources: []File{resource}, CRDs: []CRD{}}}
	id, _ := p.Tuple.CaseID()
	policy := BasePolicy{Commit: strings.Repeat("4", 40), Tree: strings.Repeat("5", 40), Associations: []Association{{CaseID: id, InputDigest: InputDigest(p)}}, MaxObservationAge: 24 * time.Hour}
	reader := &fixtureReader{materials: Materials{Index: []byte("index fixture"), Archive: []byte("archive fixture"), ProducedOutput: rendered, ArchiveFiles: map[string]MaterializedFile{"Chart.yaml": {Mode: f.Mode, GitBlob: f.GitBlob, Bytes: file}}, SourceFiles: map[string]MaterializedFile{"Chart.yaml": {Mode: f.Mode, GitBlob: f.GitBlob, Bytes: file}}, Values: map[string][]byte{"values.yaml": values}, Dependencies: map[string][]byte{}}, output: p.Output}
	reader.materials.ObservedAt = now.Add(-time.Minute)
	reader.materials.ExpiresAt = now.Add(time.Hour)
	return p, policy, reader, &fixtureRenderer{recipe: p.Render, output: rendered}, now
}

func encodeFixture(t *testing.T, p Proof) []byte {
	t.Helper()
	b, e := Encode(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestCanonicalProof(t *testing.T) {
	p, _, _, _, _ := proofFixture()
	raw := encodeFixture(t, p)
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, got) {
		t.Fatal("round trip changed proof")
	}
	for name, b := range map[string][]byte{
		"whitespace": append([]byte(" "), raw...), "newline": append(append([]byte{}, raw...), '\n'),
		"unknown":          bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":0,"schema":`), 1),
		"duplicate":        bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"other","schema":`), 1),
		"nested duplicate": bytes.Replace(raw, []byte(`"surface":"helm"`), []byte(`"surface":"raw","surface":"helm"`), 1),
		"two documents":    append(append([]byte{}, raw...), raw...), "oversized": bytes.Repeat([]byte{' '}, MaxProofBytes+1),
		"wrong scalar type": bytes.Replace(raw, []byte(`"enabled":false`), []byte(`"enabled":"false"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "wrong scalar type" {
				b = bytes.Replace(raw, []byte(`"cpuMillis":1000`), []byte(`"cpuMillis":"1000"`), 1)
			}
			if _, e := Decode(b); e == nil {
				t.Fatal("accepted malformed proof")
			}
		})
	}
	mutations := map[string]func(*Proof){
		"traversal":            func(p *Proof) { p.SourceInventory[0].Path = "../outside" },
		"absolute":             func(p *Proof) { p.SourceInventory[0].Path = "/outside" },
		"mode":                 func(p *Proof) { p.SourceInventory[0].Mode = "120000" },
		"empty source blob":    func(p *Proof) { p.SourceInventory[0].GitBlob = "" },
		"file size":            func(p *Proof) { p.SourceInventory[0].Size = MaxFileBytes + 1 },
		"duplicate path":       func(p *Proof) { p.SourceInventory = append(p.SourceInventory, p.SourceInventory[0]) },
		"duplicate capability": func(p *Proof) { p.Render.Capabilities = []string{"v1/ConfigMap", "v1/ConfigMap"} },
		"missing capabilities": func(p *Proof) { p.Render.Capabilities = nil },
		"unbound values":       func(p *Proof) { p.Render.Values = nil },
		"dependency depth": func(p *Proof) {
			p.Dependencies = []Dependency{{CaseID: strings.Repeat("a", 64), ProofDigest: Digest(nil), PredicateDigest: Digest(nil), Depth: MaxDependencyDepth + 1}}
		},
		"URL credentials":       func(p *Proof) { p.Origin.ArchiveURL = "https://user@example.invalid/archive" },
		"bad expiry":            func(p *Proof) { p.Origin.ExpiresAt = p.Origin.ObservedAt },
		"missing CRD inventory": func(p *Proof) { p.Output.CRDs = nil },
		"JSON depth":            func(p *Proof) { p.SourceInventory[0].Path = strings.Repeat("a/", MaxDepth) + "file" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			p, _, _, _, _ := proofFixture()
			mutate(&p)
			if _, e := Encode(p); e == nil {
				t.Fatal("invalid proof encoded")
			}
		})
	}
}

func TestReplayRequiresIndependentInputs(t *testing.T) {
	p, policy, reader, renderer, now := proofFixture()
	raw := encodeFixture(t, p)
	result, e := CheckReplay(context.Background(), raw, p.Tuple, policy, reader, renderer, now)
	if e != nil {
		t.Fatal(e)
	}
	if reader.reads != 1 || reader.inspections != 1 || renderer.calls != 1 || result.RenderedDigest != p.Output.Digest {
		t.Fatal("replay skipped a required boundary")
	}
	path, e := p.Tuple.PublicPath()
	if e != nil || result.PublicPath != path || !strings.HasPrefix(path, "cli/knowledge/install-surfaces/fixture/") {
		t.Fatalf("derived path: %q %v", path, e)
	}
	// Output is not part of the independently reviewed input association. A
	// malicious producer can recompute all output hashes, but cannot change
	// the actual independent renderer's bytes or obtain a positive replay.
	p, policy, reader, renderer, now = proofFixture()
	forged := []byte("forged manifest fixture")
	p.Output.Digest = Digest(forged)
	p.Output.Resources[0].Size = int64(len(forged))
	p.Output.Resources[0].Digest = Digest(forged)
	reader.materials.ProducedOutput = forged
	reader.output = p.Output
	_, e = CheckReplay(context.Background(), encodeFixture(t, p), p.Tuple, policy, reader, renderer, now)
	if e == nil || renderer.calls != 1 || reader.inspections != 0 {
		t.Fatalf("forged output accepted/skipped rerender: %v", e)
	}
}

func TestReplayRefusals(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*Proof, *BasePolicy, *fixtureReader, *fixtureRenderer, *time.Time)
		unavailable bool
	}{
		{"no authority", func(_ *Proof, p *BasePolicy, _ *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			p.Associations = nil
		}, true},
		{"self hash not authority", func(p *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			p.Origin.IndexDigest = Digest([]byte("replacement index"))
			r.materials.Index = []byte("replacement index")
		}, false},
		{"expired", func(_ *Proof, _ *BasePolicy, _ *fixtureReader, _ *fixtureRenderer, n *time.Time) {
			*n = n.Add(2 * time.Hour)
		}, false},
		{"producer timestamp forgery", func(p *Proof, _ *BasePolicy, _ *fixtureReader, _ *fixtureRenderer, n *time.Time) {
			p.Origin.ObservedAt = n.Add(-time.Second).Format(time.RFC3339)
		}, false},
		{"capture timestamp absent", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			r.materials.ObservedAt = time.Time{}
		}, false},
		{"archive replacement", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			r.materials.Archive = []byte("other archive")
		}, false},
		{"omitted file", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			delete(r.materials.ArchiveFiles, "Chart.yaml")
		}, false},
		{"extra file", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			r.materials.SourceFiles["outside"] = MaterializedFile{}
		}, false},
		{"mode drift", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			f := r.materials.SourceFiles["Chart.yaml"]
			f.Mode = "100755"
			r.materials.SourceFiles["Chart.yaml"] = f
		}, false},
		{"values omission", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			r.materials.Values = map[string][]byte{}
		}, false},
		{"values replacement", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			r.materials.Values["values.yaml"] = []byte("replicas: 9")
		}, false},
		{"unlisted dependency", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			r.materials.Dependencies["other"] = []byte("other")
		}, false},
		{"renderer drift", func(_ *Proof, _ *BasePolicy, _ *fixtureReader, r *fixtureRenderer, _ *time.Time) {
			r.recipe.BinaryDigest = Digest([]byte("other binary"))
		}, false},
		{"render error", func(_ *Proof, _ *BasePolicy, _ *fixtureReader, r *fixtureRenderer, _ *time.Time) {
			r.err = &Unavailable{"fixture renderer refused unsupported input"}
		}, true},
		{"forged CRD inventory", func(_ *Proof, _ *BasePolicy, r *fixtureReader, _ *fixtureRenderer, _ *time.Time) {
			r.output.CRDs = []CRD{{Name: "unexpected"}}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, policy, reader, renderer, now := proofFixture()
			tc.mutate(&p, &policy, reader, renderer, &now)
			_, err := CheckReplay(context.Background(), encodeFixture(t, p), p.Tuple, policy, reader, renderer, now)
			if err == nil {
				t.Fatal("invalid replay accepted")
			}
			var unavailable *Unavailable
			if errors.As(err, &unavailable) != tc.unavailable {
				t.Fatalf("wrong refusal: %v", err)
			}
		})
	}
	for _, missing := range []string{"reader", "renderer"} {
		t.Run("missing "+missing, func(t *testing.T) {
			p, policy, r, ren, now := proofFixture()
			var reader Materializer = r
			var renderer Renderer = ren
			if missing == "reader" {
				reader = nil
			} else {
				renderer = nil
			}
			_, e := CheckReplay(context.Background(), encodeFixture(t, p), p.Tuple, policy, reader, renderer, now)
			var unavailable *Unavailable
			if !errors.As(e, &unavailable) {
				t.Fatalf("missing backend did not refuse: %v", e)
			}
		})
	}
}

func TestProofMutationDoesNotChangeRequestedScope(t *testing.T) {
	p, policy, reader, renderer, now := proofFixture()
	want := p.Tuple
	p.Tuple.ConfigID = "other"
	_, e := CheckReplay(context.Background(), encodeFixture(t, p), want, policy, reader, renderer, now)
	if e == nil || reader.reads != 0 || renderer.calls != 0 {
		t.Fatal("producer selected its own scope")
	}
	raw, _ := json.Marshal(p)
	if bytes.Contains(raw, []byte("associations")) {
		t.Fatal("proof embeds authority")
	}
}
