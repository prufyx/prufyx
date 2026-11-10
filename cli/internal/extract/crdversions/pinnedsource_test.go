// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"context"
	"crypto/sha1" //nolint:gosec // git blob ids only
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The pinned read-only source (Exclusion.Pinned): the real cue template of
// the adopt command of kubevela (testdata/kubevela, byte for byte from the
// public tags v1.7.0, v1.8.0 and v1.9.0) and the Go file that embeds it.

const (
	kvCue   = "references/cli/adopt-templates/default.cue"
	kvAdopt = "references/cli/adopt.go"
	kvHS    = "charts/vela-core/crds/core.oam.dev_healthscopes.yaml"
)

func kvCueBytes(t *testing.T, tag string) string {
	return kvFile(t, "references/cli/adopt-templates/default.cue."+tag)
}

func gitBlobID(data []byte) string {
	sum := sha1.Sum([]byte(fmt.Sprintf("blob %d\x00", len(data)) + string(data))) //nolint:gosec // git blob ids only
	return hex.EncodeToString(sum[:])
}

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return sha256Prefix + hex.EncodeToString(sum[:])
}

// pinTree is kvTree plus the embedding Go file, the pinned template of tag
// and a definition (HealthScope) that exists only in the earlier release.
func pinTree(t *testing.T, tag string, early bool, edit func(map[string]string)) map[string]string {
	versions := []string{"v1beta1"}
	if early {
		versions = []string{"v1alpha2", "v1beta1"}
	}
	return kvTree(versions, func(m map[string]string) {
		m[kvAdopt] = kvFile(t, kvAdopt)
		m[kvCue] = kvCueBytes(t, tag)
		if early {
			m[kvHS] = kvCRD("HealthScope", "v1alpha2")
		}
		if edit != nil {
			edit(m)
		}
	})
}

// pinRun derives 1.8.0 -> 1.9.0 over a reader (nil: the in-memory one).
func pinRun(t *testing.T, tg Target, from, to func(map[string]string), wrap func(synthRepo) pinReader) (extract.PairRecord, PairProof) {
	t.Helper()
	s := newSynth(
		release{"v1.8.0", pinTree(t, "v1.8.0", true, from)},
		release{"v1.9.0", pinTree(t, "v1.9.0", false, to)},
	)
	var src pinReader = s
	if wrap != nil {
		src = wrap(s)
	}
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	out, err := extract.Run(context.Background(), New(tg), ReleaseTags(New(tg), src), src, extract.Options{Repo: repo, DerivedAt: derivedAt})
	must(t, err)
	return pairOf(t, out, "1.8.0", "1.9.0")
}

type pinReader interface {
	extract.PinnedReader
	Tags(extract.RepoRef) ([]extract.Tag, error)
}

// pinLinkRepo lists one path as a symbolic link.
type pinLinkRepo struct {
	synthRepo
	link string
}

func (l pinLinkRepo) List(r extract.RepoRef, c, d string) ([]extract.TreeEntry, error) {
	es, err := l.synthRepo.List(r, c, d)
	for i := range es {
		if es[i].Path == l.link {
			es[i].Mode = "120000"
		}
	}
	return es, err
}

// pinTarget is the reviewed kubevela target, with its one exclusion
// changed by edit.
func pinTarget(t *testing.T, edit func(*Exclusion)) Target {
	t.Helper()
	return kvTarget(t, func(tg *Target) {
		tg.Exclude = append([]Exclusion(nil), tg.Exclude...)
		if len(tg.Exclude) != 1 || tg.Exclude[0].Path != kvCue || tg.Exclude[0].Pinned == nil {
			t.Fatalf("the reviewed target has no pinned %s: %+v", kvCue, tg.Exclude)
		}
		if edit != nil {
			edit(&tg.Exclude[0])
		}
	})
}

func TestPinnedCueFilesAreTheRealBytes(t *testing.T) {
	tg := pinTarget(t, nil)
	for tag, blob := range map[string]string{"v1.7.0": "3dc4bdfb", "v1.8.0": "a02dfa02", "v1.9.0": "cae5e499"} {
		data := []byte(kvCueBytes(t, tag))
		if why := pinnedSourceProblem(tg.Exclude[0].Pinned, data); why != "" {
			t.Errorf("%s (blob %s): %s", tag, blob, why)
		}
		if gitBlobID(data)[:8] != blob {
			t.Errorf("%s is not the upstream blob %s", tag, blob)
		}
	}
}

// With the pin held, the template is an excluded finding of Reason
// pinned-source: not opaque, not blocking. The whole-CRD removal
// (HealthScope) is then a definition that is gone, the pair is derived with
// the one version-level rule, and it is not attestable.
func TestPinnedSourceHolds(t *testing.T) {
	p, proof := pinRun(t, pinTarget(t, nil), nil, nil, nil)
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || proof.Completeness.Attestable {
		t.Fatalf("pair %s %q rules %v attestable %v", p.Status, p.Reason, p.Rules, proof.Completeness.Attestable)
	}
	for _, inv := range []*Inventory{proof.From, proof.To} {
		f := kvFinding(inv, kvCue)
		if f == nil || f.Class != ClassExcluded || f.Reason != ReasonPinnedSource || f.Location != kvCue || f.blocks() || f.opaque() || f.SHA256 == "" {
			t.Fatalf("%s: finding %+v", inv.Tag, f)
		}
		if inv.Scan.holds("healthscopes.core.oam.dev") {
			t.Errorf("%s: the scan still holds a definition", inv.Tag)
		}
		if g := kvFinding(inv, kvAdopt); g != nil {
			t.Errorf("%s: the embedding file has a finding %+v", inv.Tag, g)
		}
	}
}

// Anything that breaks the pin voids the entry: the template is opaque
// again, every definition is held and the later tag withholds the pair; at
// the earlier tag the pair is derived and not attestable.
func TestPinnedSourceFailsClosed(t *testing.T) {
	changed := func(m map[string]string) { m[kvCue] += "\n// changed\n" }
	plain := func() Target { return pinTarget(t, nil) }
	cases := []struct {
		name     string
		tg       func() Target
		from, to func(map[string]string)
		wrap     func(synthRepo) pinReader
		side     string // the tag whose scan voids ("to" withholds the pair)
	}{
		{name: "digest mismatch at the later tag", tg: plain, to: changed, side: "to"},
		{name: "digest mismatch at the earlier tag", tg: plain, from: changed, side: "from"},
		{name: "matching digest, bytes holding the apiextensions group", side: "to",
			tg: func() Target {
				return pinTarget(t, func(e *Exclusion) {
					e.Pinned = &PinnedSource{SHA256: []string{sha256Of(kvCueBytes(t, "v1.9.0") + "\n// apiextensions.K8S.io\n")}}
				})
			},
			to: func(m map[string]string) { m[kvCue] += "\n// apiextensions.K8S.io\n" }},
		{name: "matching digest, template syntax", side: "to",
			tg: func() Target {
				return pinTarget(t, func(e *Exclusion) {
					e.Pinned = &PinnedSource{SHA256: []string{sha256Of(kvCueBytes(t, "v1.9.0") + "{{ x }}")}}
				})
			},
			to: func(m map[string]string) { m[kvCue] += "{{ x }}" }},
		{name: "a kustomization lists the template", side: "to", tg: plain, to: func(m map[string]string) {
			m["kustomization.yaml"] = "resources:\n- " + kvCue + "\n"
		}},
		{name: "a Makefile names the template", side: "to", tg: plain, to: func(m map[string]string) {
			m["Makefile"] = "all:\n\tkustomize build " + kvCue + "\n"
		}},
		{name: "a document names the template", side: "to", tg: plain, to: func(m map[string]string) {
			m["README.md"] = "Build it\n\n    kustomize build " + kvCue + "\n"
		}},
		{name: "the same file under a plain exclusion", side: "to", tg: func() Target { return pinTarget(t, func(e *Exclusion) { e.Pinned = nil }) }},
		{name: "template absent", side: "to-absent", tg: plain, to: func(m map[string]string) { delete(m, kvCue) }},
		{name: "template a symbolic link", side: "to-absent", tg: plain, wrap: func(s synthRepo) pinReader { return pinLinkRepo{s, kvCue} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, proof := pinRun(t, tc.tg(), tc.from, tc.to, tc.wrap)
			inv := proof.To
			switch tc.side {
			case "to":
				if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "scan not clean") {
					t.Fatalf("pair %s %q, want withheld (scan not clean)", p.Status, p.Reason)
				}
			case "to-absent":
				// No file, no opaque finding: the void blocks attestation only.
				if p.Status != extract.PairDerived || proof.Completeness.Attestable {
					t.Fatalf("pair %s %q attestable %v", p.Status, p.Reason, proof.Completeness.Attestable)
				}
			default:
				if p.Status != extract.PairDerived || proof.Completeness.Attestable {
					t.Fatalf("pair %s %q attestable %v", p.Status, p.Reason, proof.Completeness.Attestable)
				}
				inv = proof.From
			}
			if inv == nil {
				if tc.side == "to" {
					return
				}
				t.Fatal("no inventory")
			}
			voided := false
			for _, f := range inv.Scan.Findings {
				voided = voided || f.Class == ClassVoided
				if f.Path == kvCue && f.Reason == ReasonPinnedSource {
					t.Fatalf("the template is still pinned-source: %+v", f)
				}
			}
			if !voided {
				t.Fatalf("no void finding: %+v", inv.Scan.Findings)
			}
		})
	}
}

// An embed pattern that reaches the pinned file is relaxed for that file
// only: a sibling template that names the kind stays unsupported and holds
// every definition.
func TestPinnedSourceEmbedGlobRelaxesOnlyThePinnedFile(t *testing.T) {
	sibling := "references/cli/adopt-templates/other.cue"
	to := func(m map[string]string) {
		m[kvAdopt] = strings.Replace(m[kvAdopt], "//go:embed adopt-templates/default.cue", "//go:embed adopt-templates/*", 1)
		m[sibling] = "// installs CustomResourceDefinition\nkind: \"CustomResourceDefinition\"\n"
	}
	p, proof := pinRun(t, pinTarget(t, nil), nil, to, nil)
	if p.Status != extract.PairWithheld || proof.To == nil {
		t.Fatalf("pair %s %q", p.Status, p.Reason)
	}
	if f := kvFinding(proof.To, kvCue); f == nil || f.Reason != ReasonPinnedSource {
		t.Errorf("the pinned file: %+v", f)
	}
	if f := kvFinding(proof.To, sibling); f == nil || f.Class != ClassUnsupported || !f.opaque() {
		t.Errorf("the sibling: %+v", f)
	}
	if !proof.To.Scan.holds("healthscopes.core.oam.dev") {
		t.Error("the scan does not hold a definition")
	}
}

// The loader refuses every malformed pinned entry.
func TestPinnedSourceLoader(t *testing.T) {
	raw, err := fs.ReadFile(source, TargetFileName("kubevela"))
	must(t, err)
	good := func() map[string]any {
		var doc map[string]any
		must(t, json.Unmarshal(raw, &doc))
		return doc
	}
	ent := func(d map[string]any) map[string]any {
		return d["target"].(map[string]any)["exclude"].([]any)[0].(map[string]any)
	}
	load := func(d map[string]any) error {
		b, err := json.Marshal(d)
		must(t, err)
		_, err = LoadTarget(TargetFileName("kubevela"), b)
		return err
	}
	if err := load(good()); err != nil {
		t.Fatalf("the reviewed file is refused: %v", err)
	}
	dig := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	pin := func(d map[string]any, ds ...string) {
		l := make([]any, len(ds))
		for i, x := range ds {
			l[i] = x
		}
		ent(d)["pinned"] = map[string]any{"sha256": l}
	}
	for name, edit := range map[string]func(map[string]any){
		"a directory":             func(d map[string]any) { ent(d)["path"] = "references/cli/adopt-templates/" },
		"a glob":                  func(d map[string]any) { ent(d)["path"] = "references/cli/adopt-templates/*.cue" },
		"a yaml file":             func(d map[string]any) { ent(d)["path"] = "references/cli/adopt-templates/default.yaml" },
		"a json file":             func(d map[string]any) { ent(d)["path"] = "references/cli/adopt-templates/default.json" },
		"an upper-case extension": func(d map[string]any) { ent(d)["path"] = "references/cli/adopt-templates/default.CUE" },
		"a go file":               func(d map[string]any) { ent(d)["path"] = "references/cli/adopt.go" },
		"with defines":            func(d map[string]any) { ent(d)["defines"] = "none" },
		"with copies":             func(d map[string]any) { ent(d)["copies"] = true },
		"with prePatch":           func(d map[string]any) { ent(d)["prePatch"] = "x/kustomization.yaml" },
		"with foreign": func(d map[string]any) {
			ent(d)["foreign"] = map[string]any{"groups": []any{"a.example.net"}, "sha256": []any{dig("1")}}
		},
		"no digest":          func(d map[string]any) { pin(d) },
		"unsorted digests":   func(d map[string]any) { pin(d, dig("2"), dig("1")) },
		"duplicate digests":  func(d map[string]any) { pin(d, dig("1"), dig("1")) },
		"a malformed digest": func(d map[string]any) { pin(d, "sha256:ABC") },
		"a bare hex digest":  func(d map[string]any) { pin(d, strings.Repeat("1", 64)) },
		"too many digests": func(d map[string]any) {
			pin(d, dig("1"), dig("2"), dig("3"), dig("4"), dig("5"), dig("6"), dig("7"), dig("8"), dig("9"), dig("a"), dig("b"), dig("c"), dig("d"), dig("e"), dig("f"), "sha256:"+strings.Repeat("f", 63)+"g")
		},
		"an unknown member":    func(d map[string]any) { ent(d)["pinned"].(map[string]any)["groups"] = []any{"a.example.net"} },
		"under an install dir": func(d map[string]any) { ent(d)["path"] = "config/crd/adopt.cue" },
	} {
		doc := good()
		edit(doc)
		if err := load(doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
