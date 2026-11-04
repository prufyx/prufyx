// SPDX-License-Identifier: AGPL-3.0-only

package installsurfaceproof

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
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

type graphFixtureReader struct {
	materials map[string]Materials
	reads     map[string]int
	inspector *fixtureReader
}

func (g *graphFixtureReader) Materialize(_ context.Context, p Proof) (Materials, error) {
	id, err := p.Tuple.CaseID()
	if err != nil {
		return Materials{}, err
	}
	g.reads[id]++
	m, ok := g.materials[id]
	if !ok {
		return Materials{}, errors.New("graph fixture missing case")
	}
	return m, nil
}

func (g *graphFixtureReader) Inspect(ctx context.Context, b []byte) (Output, error) {
	return g.inspector.Inspect(ctx, b)
}

// Children follow their parents in edges; depths are absolute from the root,
// matching the dependency format. Shared nodes retain identical proof bytes.
func replayGraphFixture(t *testing.T, edges [][]int, depths []int) (Proof, BasePolicy, *graphFixtureReader, *fixtureRenderer, time.Time) {
	t.Helper()
	_, policy, inspector, renderer, now := proofFixture()
	policy.Associations = nil
	reader := &graphFixtureReader{materials: map[string]Materials{}, reads: map[string]int{}, inspector: inspector}
	proofs, raws := make([]Proof, len(edges)), make([][]byte, len(edges))
	for i := len(edges) - 1; i >= 0; i-- {
		p, _, fixture, _, _ := proofFixture()
		p.Tuple.ConfigID = fmt.Sprintf("graph-case-%02d", i)
		for _, child := range edges[i] {
			if child <= i || child >= len(edges) {
				t.Fatal("invalid fixture edge")
			}
			id, _ := proofs[child].Tuple.CaseID()
			p.Dependencies = append(p.Dependencies, Dependency{CaseID: id, ProofDigest: Digest(raws[child]), Depth: depths[child], Enabled: true, PredicateDigest: Digest([]byte("enabled synthetic condition"))})
			fixture.materials.Dependencies[id] = raws[child]
		}
		sort.Slice(p.Dependencies, func(i, j int) bool { return p.Dependencies[i].CaseID < p.Dependencies[j].CaseID })
		id, _ := p.Tuple.CaseID()
		policy.Associations = append(policy.Associations, Association{CaseID: id, InputDigest: InputDigest(p)})
		proofs[i], raws[i], reader.materials[id] = p, encodeFixture(t, p), fixture.materials
	}
	return proofs[0], policy, reader, renderer, now
}

func TestReplayClosure(t *testing.T) {
	t.Run("recursive positive", func(t *testing.T) {
		p, policy, reader, renderer, now := replayGraphFixture(t, [][]int{{1}, {2}, {}}, []int{0, 1, 2})
		if _, err := CheckReplay(context.Background(), encodeFixture(t, p), p.Tuple, policy, reader, renderer, now); err != nil {
			t.Fatal(err)
		}
		if len(reader.reads) != 3 || renderer.calls != 3 || reader.inspector.inspections != 3 {
			t.Fatal("recursive replay skipped a boundary")
		}
	})
	t.Run("whole root transitive bound", func(t *testing.T) {
		// Each node is individually below sixteen, but the root has eighteen
		// unique transitive dependencies: two parents and sixteen leaves.
		edges, depths := make([][]int, 19), make([]int, 19)
		edges[0], depths[1], depths[2] = []int{1, 2}, 1, 1
		for i := 3; i < 19; i++ {
			parent := 1
			if i >= 11 {
				parent = 2
			}
			edges[parent], depths[i] = append(edges[parent], i), 2
		}
		p, policy, reader, renderer, now := replayGraphFixture(t, edges, depths)
		_, err := CheckReplay(context.Background(), encodeFixture(t, p), p.Tuple, policy, reader, renderer, now)
		if err == nil {
			t.Fatal("accepted more than sixteen transitive dependencies")
		}
		if len(reader.reads) > MaxDependencies+1 || renderer.calls > MaxDependencies+1 {
			t.Fatal("performed unbounded work before refusing the closure")
		}
	})
	t.Run("repeated DAG work bounded", func(t *testing.T) {
		// Seventeen unique nodes expand to 341 recursive replays without a
		// root-wide exact-proof cache: four fully connected levels of four.
		edges, depths := make([][]int, 17), make([]int, 17)
		edges[0] = []int{1, 2, 3, 4}
		for i := 1; i < 17; i++ {
			depths[i] = (i-1)/4 + 1
			if depths[i] < MaxDependencyDepth {
				first := 1 + depths[i]*4
				edges[i] = []int{first, first + 1, first + 2, first + 3}
			}
		}
		p, policy, reader, renderer, now := replayGraphFixture(t, edges, depths)
		if _, err := CheckReplay(context.Background(), encodeFixture(t, p), p.Tuple, policy, reader, renderer, now); err != nil {
			t.Fatal(err)
		}
		if len(reader.reads) != MaxDependencies+1 || renderer.calls != MaxDependencies+1 || reader.inspector.inspections != MaxDependencies+1 {
			t.Fatalf("amplified DAG work: unique=%d renders=%d inspections=%d", len(reader.reads), renderer.calls, reader.inspector.inspections)
		}
		for id, count := range reader.reads {
			if count != 1 {
				t.Fatalf("case %s materialized %d times", id, count)
			}
		}
	})
	t.Run("shared case cannot substitute proof bytes", func(t *testing.T) {
		p, policy, reader, renderer, now := replayGraphFixture(t, [][]int{{1, 2}, {3}, {3}, {}}, []int{0, 1, 1, 2})
		rootID, _ := p.Tuple.CaseID()
		// Mutate the parent replayed second so the shared leaf is already
		// verified. Both parents remain independently anchored fixtures.
		laterParent := p.Dependencies[1].CaseID
		parent, err := Decode(reader.materials[rootID].Dependencies[laterParent])
		if err != nil {
			t.Fatal(err)
		}
		leafID := parent.Dependencies[0].CaseID
		leaf, err := Decode(reader.materials[laterParent].Dependencies[leafID])
		if err != nil {
			t.Fatal(err)
		}
		leaf.Output.Digest = Digest([]byte("substituted rendered output"))
		substituted := encodeFixture(t, leaf)
		parent.Dependencies[0].ProofDigest = Digest(substituted)
		reader.materials[laterParent].Dependencies[leafID] = substituted
		parentBytes := encodeFixture(t, parent)
		p.Dependencies[1].ProofDigest = Digest(parentBytes)
		reader.materials[rootID].Dependencies[laterParent] = parentBytes
		for i, a := range policy.Associations {
			switch a.CaseID {
			case laterParent:
				policy.Associations[i].InputDigest = InputDigest(parent)
			case rootID:
				policy.Associations[i].InputDigest = InputDigest(p)
			}
		}
		_, err = CheckReplay(context.Background(), encodeFixture(t, p), p.Tuple, policy, reader, renderer, now)
		if err == nil || !strings.Contains(err.Error(), "different proof bytes") || reader.reads[leafID] != 1 {
			t.Fatalf("substitution reused the shared result: error=%v shared reads=%d", err, reader.reads[leafID])
		}
	})
}

type cancelingFixtureReader struct {
	*fixtureReader
	cancel context.CancelFunc
}

func (r *cancelingFixtureReader) Inspect(ctx context.Context, b []byte) (Output, error) {
	r.cancel()
	return r.fixtureReader.Inspect(ctx, b)
}

func TestReplayInspectionCancellation(t *testing.T) {
	p, policy, fixture, renderer, now := proofFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &cancelingFixtureReader{fixtureReader: fixture, cancel: cancel}
	result, err := CheckReplay(ctx, encodeFixture(t, p), p.Tuple, policy, reader, renderer, now)
	if !errors.Is(err, context.Canceled) || result.CaseID != "" {
		t.Fatalf("canceled inspection yielded a replay: result=%+v error=%v", result, err)
	}
	if renderer.calls != 1 || fixture.inspections != 1 {
		t.Fatal("fixture did not reach the matching-output inspection")
	}
}
