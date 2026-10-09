// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// The per-line source switch (Remote): from one release line on, a release
// installs its definitions from a kustomize directory of another repository,
// at the tag its own kustomization names, resolved through reviewed pins.

const (
	remoteRepo      = "github.com/example/crds"
	remoteDirectory = "config/crd/dir"
	remoteKustPath  = "deploy/kustomization.yaml"
)

var (
	pinA = strings.Repeat("a", 40)
	pinB = strings.Repeat("b", 40)
	pinC = strings.Repeat("c", 40)
)

func remoteSwitch(pins ...Pin) *Remote {
	if len(pins) == 0 {
		pins = []Pin{{Tag: "v0.1.0", Commit: pinA}, {Tag: "v0.1.1", Commit: pinB}, {Tag: "v0.2.0", Commit: pinC}}
	}
	return &Remote{FromLine: [2]int{1, 1}, Kustomization: remoteKustPath, Repo: remoteRepo, Directory: remoteDirectory, Pins: pins}
}

func kustomizationFor(ref string) string {
	return "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - https://github.com/example/crds/" + remoteDirectory + "?ref=" + ref + " # auto-updated\n"
}

func dirKustomization(files ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n\nresources:\n")
	for _, f := range files {
		fmt.Fprintf(&b, "  - %s\n", f)
	}
	return b.String()
}

// remoteWorld is a repository whose lines 1.1 and later install from the
// remote directory, and the remote repository at three pinned commits.
func remoteWorld(extra func(s synthRepo)) synthRepo {
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.1.0", map[string]string{remoteKustPath: kustomizationFor("v0.1.0")}},
		release{"v1.1.1", map[string]string{remoteKustPath: kustomizationFor("v0.1.1")}},
		release{"v1.2.0", map[string]string{remoteKustPath: kustomizationFor("v0.2.0")}},
	)
	for commit, versions := range map[string][]string{pinA: {"v1"}, pinB: {"v1"}, pinC: {"v1"}} {
		s.files[commit+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("a.yaml"))
		s.files[commit+":"+remoteDirectory+"/a.yaml"] = []byte(crd("Alpha", versions...))
	}
	if extra != nil {
		extra(s)
	}
	return s
}

func remoteTargetOf(r *Remote) Target {
	tg := synthTarget()
	tg.Remote = r
	return tg
}

func TestRemoteSourceSwitchReadsTheOtherRepositoryAtThePinnedCommit(t *testing.T) {
	out := runSynth(t, remoteTargetOf(remoteSwitch()), remoteWorld(nil))
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || !proof.Lines.LineWide || len(proof.Removals) != 1 || proof.Removals[0].Member != "synth.example.io/v1beta1/Alpha" {
		t.Fatalf("pair %+v removals %+v lines %+v", p, proof.Removals, proof.Lines)
	}
	// The earlier side is read from the release's own repository, the later
	// side from the remote at the pinned commit, and the proof says so.
	if proof.From.Remote != nil || proof.To.Remote == nil {
		t.Fatalf("remote records: from %+v to %+v", proof.From.Remote, proof.To.Remote)
	}
	rec := proof.To.Remote
	if rec.Ref != "v0.1.0" || rec.Repo != remoteRepo || rec.Commit != pinA || rec.Directory != remoteDirectory || len(rec.Resources) != 1 || rec.Resources[0] != "a.yaml" ||
		rec.Kustomization.Path != remoteKustPath || !strings.HasPrefix(rec.Kustomization.SHA256, "sha256:") || rec.DirectoryManifest.Path != remoteDirectory+"/kustomization.yaml" {
		t.Fatalf("remote record %+v", rec)
	}
	if len(proof.To.CRDs) != 1 || proof.To.CRDs[0].Repo != remoteRepo || proof.To.CRDs[0].Commit != pinA || proof.To.CRDs[0].Path != remoteDirectory+"/a.yaml" {
		t.Fatalf("crds %+v", proof.To.CRDs)
	}
	if len(proof.To.Files) != 1 || proof.To.Files[0].Repo != remoteRepo || proof.To.Files[0].Commit != pinA {
		t.Fatalf("files %+v", proof.To.Files)
	}
	// Every citation names the repository and the full commit it was read
	// at: the own repository for the earlier side, the remote for the later.
	e := ruleOf(t, out, "argo-cd.crd-version-removal.alphas-synth-example-io.1-0-0-to-1-1-0")
	var own, other int
	for _, src := range e.Rule.Evidence.Sources {
		if len(src.Revision) != 40 {
			t.Fatalf("citation %+v is not at a full commit", src)
		}
		switch {
		case strings.HasPrefix(src.URL, "https://github.com/argoproj/argo-cd/blob/"+src.Revision+"/"):
			own++
			if src.Revision != commitOf("v1.0.0") {
				t.Fatalf("own citation %+v", src)
			}
		case strings.HasPrefix(src.URL, "https://github.com/example/crds/blob/"+pinA+"/"+remoteDirectory+"/a.yaml"):
			other++
			if src.Revision != pinA {
				t.Fatalf("remote citation %+v", src)
			}
		default:
			t.Fatalf("citation %+v", src)
		}
	}
	if own == 0 || other == 0 {
		t.Fatalf("sources %+v: own %d remote %d", e.Rule.Evidence.Sources, own, other)
	}
	// Later lines of the remote lines read the other pins.
	_, quiet := pairOf(t, out, "1.1.0", "1.2.0")
	if quiet.To.Remote == nil || quiet.To.Remote.Commit != pinC || len(quiet.Removals) != 0 {
		t.Fatalf("quiet pair %+v", quiet.To.Remote)
	}
	// A line that installs from the remote is never attested.
	for _, pr := range out.Manifest.Pairs {
		if pr.Attestation != nil && pr.Attestation.Status == extract.PairAttested {
			t.Fatalf("pair %s -> %s attested", pr.From, pr.To)
		}
	}
	if len(out.Attestations) != 0 {
		t.Fatalf("%d attestations", len(out.Attestations))
	}
}

// Every way the reading can be wrong withholds the pairs that read the
// release, with a reason that names it.
func TestRemoteSourceSwitchWithholdsWhatItCannotEstablish(t *testing.T) {
	good := kustomizationFor("v0.1.0")
	cases := map[string]struct {
		mutate func(s synthRepo)
		pins   []Pin
		want   string
	}{
		"a tag the table does not pin": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(kustomizationFor("v0.9.9"))
		}, nil, "does not pin to a commit"},
		"a pre-release tag that is not pinned": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(kustomizationFor("v0.1.0-rc.1"))
		}, nil, "does not pin to a commit"},
		"a branch instead of a tag": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "ref=v0.1.0", "ref=main", 1))
		}, nil, "without exactly one ref=<release tag>"},
		"a commit instead of a tag": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "ref=v0.1.0", "ref="+pinA, 1))
		}, nil, "without exactly one ref=<release tag>"},
		"no ref": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "?ref=v0.1.0", "", 1))
		}, nil, "without exactly one ref=<release tag>"},
		"a second query parameter": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "ref=v0.1.0", "ref=v0.1.0&timeout=5", 1))
		}, nil, "without exactly one ref=<release tag>"},
		"another repository": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "example/crds", "other/crds", 1))
		}, nil, "not https://github.com/example/crds/"},
		"another directory": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "config/crd/dir", "config/crd/other", 1))
		}, nil, "not https://github.com/example/crds/"},
		"not https": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "https://", "http://", 1))
		}, nil, "not https://github.com/example/crds/"},
		"another host": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "github.com", "gitlab.com", 1))
		}, nil, "not https://github.com/example/crds/"},
		"credentials in the url": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "https://", "https://user@", 1))
		}, nil, "not https://github.com/example/crds/"},
		"a local resource as well": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "resources:\n", "resources:\n  - bases\n", 1))
		}, nil, "exactly one remote resource"},
		"a patch": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(good + "patches:\n- path: p.yaml\n")
		}, nil, "only apiVersion, kind and resources are modelled"},
		"a name prefix": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(good + "namePrefix: x-\n")
		}, nil, "only apiVersion, kind and resources are modelled"},
		"another kind": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(strings.Replace(good, "kind: Kustomization", "kind: Component", 1))
		}, nil, "is not a kustomize.config.k8s.io/v1beta1 Kustomization"},
		"a template in the kustomization": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(good + "# {{ .x }}\n")
		}, nil, "not one strictly decodable document"},
		"two documents": {func(s synthRepo) {
			s.files[commitOf("v1.1.0")+":"+remoteKustPath] = []byte(good + "---\n" + good)
		}, nil, "not one strictly decodable document"},
		"no kustomization": {func(s synthRepo) {
			delete(s.files, commitOf("v1.1.0")+":"+remoteKustPath)
		}, nil, "does not exist"},
		"no remote directory kustomization": {func(s synthRepo) {
			delete(s.files, pinA+":"+remoteDirectory+"/kustomization.yaml")
		}, nil, "does not exist in github.com/example/crds"},
		"a listed file that does not exist": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("a.yaml", "b.yaml"))
		}, nil, "listed file"},
		"a listed path outside the directory": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("../other/a.yaml"))
		}, nil, "only distinct plain file names"},
		"a remote resource of the directory": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("https://github.com/x/y/z?ref=v1.0.0"))
		}, nil, "only distinct plain file names"},
		"a listed file twice": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("a.yaml", "a.yaml"))
		}, nil, "only distinct plain file names"},
		"the kustomization listed as a resource": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("kustomization.yaml"))
		}, nil, "only distinct plain file names"},
		"a patch in the directory kustomization": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("a.yaml") + "patches:\n- path: p.yaml\n")
		}, nil, "only apiVersion, kind and resources are modelled"},
		"no CRD in the listed files": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/a.yaml"] = []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")
		}, nil, "no CustomResourceDefinition"},
		"template syntax in a listed file": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/a.yaml"] = []byte("{{- if .Values.x }}\n" + crd("Alpha", "v1") + "{{- end }}\n")
		}, nil, "template syntax"},
		"a definition twice": {func(s synthRepo) {
			s.files[pinA+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("a.yaml", "b.yaml"))
			s.files[pinA+":"+remoteDirectory+"/b.yaml"] = []byte(crd("Alpha", "v1"))
		}, nil, "is defined in both"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := runSynth(t, remoteTargetOf(remoteSwitch(tc.pins...)), remoteWorld(tc.mutate))
			p, _ := pairOf(t, out, "1.0.0", "1.1.0")
			if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, tc.want) {
				t.Fatalf("pair 1.0.0 -> 1.1.0: %s %q, want a withheld pair mentioning %q", p.Status, p.Reason, tc.want)
			}
		})
	}
}

// A release that reads its own repository is unaffected by a Remote that
// starts at a later line, and the switch starts exactly at its line.
func TestRemoteSourceSwitchStartsAtItsLine(t *testing.T) {
	tg := remoteTargetOf(remoteSwitch())
	tg.Remote.FromLine = [2]int{1, 2}
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1")}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1")}},
		release{"v1.2.0", map[string]string{remoteKustPath: kustomizationFor("v0.2.0")}},
	)
	s.files[pinC+":"+remoteDirectory+"/kustomization.yaml"] = []byte(dirKustomization("a.yaml"))
	s.files[pinC+":"+remoteDirectory+"/a.yaml"] = []byte(crd("Alpha", "v1"))
	out := runSynth(t, tg, s)
	_, first := pairOf(t, out, "1.0.0", "1.1.0")
	_, second := pairOf(t, out, "1.1.0", "1.2.0")
	if first.To.Remote != nil || first.From.Remote != nil || second.From.Remote != nil || second.To.Remote == nil {
		t.Fatalf("remote records: %+v %+v %+v %+v", first.From.Remote, first.To.Remote, second.From.Remote, second.To.Remote)
	}
	p, _ := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived {
		t.Fatalf("own-repository pair %s %q", p.Status, p.Reason)
	}
	// A target without a Remote reads a release whose kustomization names a
	// remote resource as it always did: its listed path is required.
	plain := runSynth(t, synthTarget(), remoteWorld(nil))
	p, _ = pairOf(t, plain, "1.0.0", "1.1.0")
	if p.Status != extract.PairWithheld {
		t.Fatalf("a target without Remote derived a pair from a release without its listed path: %s", p.Status)
	}
}

func TestRemoteAppliesToLines(t *testing.T) {
	var none *Remote
	if none.appliesTo(9, 9) {
		t.Fatal("a missing Remote applies")
	}
	r := &Remote{FromLine: [2]int{3, 4}}
	for line, want := range map[[2]int]bool{{3, 3}: false, {3, 4}: true, {3, 5}: true, {4, 0}: true, {2, 9}: false} {
		if got := r.appliesTo(line[0], line[1]); got != want {
			t.Fatalf("%v: %v", line, got)
		}
	}
}

// targets.json: the loader holds a Remote to its rules.
func TestLoadTargetsRemote(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"project": "argo-cd", "name": "Synth", "repo": "github.com/argoproj/argo-cd", "component": "pkg:github/argoproj/argo-cd", "factProject": "argo_cd",
			"tagPrefixes": []string{"v"}, "minFrom": "1.0", "attest": false,
			"paths":   []any{map[string]any{"path": "deploy/crds", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}},
			"exclude": []any{},
			"remote": map[string]any{
				"fromLine": "1.1", "kustomization": "deploy/kustomization.yaml", "repo": "github.com/example/crds", "directory": "config/crd/dir",
				"pins": []any{map[string]any{"tag": "v0.1.0", "commit": pinA}, map[string]any{"tag": "v0.2.0-rc.1", "commit": pinB}, map[string]any{"tag": "v0.2.0", "commit": pinC}, map[string]any{"tag": "v0.10.0", "commit": strings.Repeat("d", 40)}},
			},
		}
	}
	load := func(mutate func(t map[string]any)) error {
		tg := base()
		if mutate != nil {
			mutate(tg)
		}
		doc, _ := json.Marshal(map[string]any{"schema": TargetsSchema, "targets": []any{tg}})
		_, err := LoadTargets(doc)
		return err
	}
	if err := load(nil); err != nil {
		t.Fatalf("a valid remote refused: %v", err)
	}
	remote := func(t map[string]any) map[string]any { return t["remote"].(map[string]any) }
	pins := func(t map[string]any) []any { return remote(t)["pins"].([]any) }
	for name, mutate := range map[string]func(t map[string]any){
		"from line":                 func(t map[string]any) { remote(t)["fromLine"] = "1" },
		"repo is the target's own":  func(t map[string]any) { remote(t)["repo"] = "github.com/argoproj/argo-cd" },
		"repo not canonical":        func(t map[string]any) { remote(t)["repo"] = "https://github.com/example/crds" },
		"repo with a capital":       func(t map[string]any) { remote(t)["repo"] = "github.com/Example/crds" },
		"kustomization path":        func(t map[string]any) { remote(t)["kustomization"] = "../deploy/kustomization.yaml" },
		"directory path":            func(t map[string]any) { remote(t)["directory"] = "/config" },
		"no pins":                   func(t map[string]any) { remote(t)["pins"] = []any{} },
		"unsorted pins":             func(t map[string]any) { remote(t)["pins"] = []any{pins(t)[1], pins(t)[0]} },
		"repeated pin":              func(t map[string]any) { remote(t)["pins"] = []any{pins(t)[0], pins(t)[0]} },
		"pin tag without v":         func(t map[string]any) { pins(t)[0].(map[string]any)["tag"] = "0.1.0" },
		"pin tag is a branch":       func(t map[string]any) { pins(t)[0].(map[string]any)["tag"] = "main" },
		"pin commit short":          func(t map[string]any) { pins(t)[0].(map[string]any)["commit"] = "abc123" },
		"pin commit upper case":     func(t map[string]any) { pins(t)[0].(map[string]any)["commit"] = strings.Repeat("A", 40) },
		"attest":                    func(t map[string]any) { t["attest"] = true },
		"unknown member":            func(t map[string]any) { remote(t)["branch"] = "main" },
		"pin tags in text order":    func(t map[string]any) { remote(t)["pins"] = []any{pins(t)[3], pins(t)[0]} },
		"pin release before its rc": func(t map[string]any) { remote(t)["pins"] = []any{pins(t)[2], pins(t)[1]} },
	} {
		if err := load(mutate); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The kong target reads the Kong Ingress Controller's own CRDs before 3.4
// and Kong/kubernetes-configuration after.
func TestKongTargetSwitchesSources(t *testing.T) {
	tg, ok := TargetFor("kong-ingress-controller")
	if !ok || tg.Remote == nil {
		t.Fatalf("kong target %+v", tg)
	}
	r := tg.Remote
	if r.FromLine != [2]int{3, 4} || r.Repo != "github.com/kong/kubernetes-configuration" || r.Directory != "config/crd/ingress-controller" || r.Kustomization != "config/crd/kustomization.yaml" || len(r.Pins) < 2 {
		t.Fatalf("remote %+v", r)
	}
	if tg.Attest || tg.Catalog != CatalogCommunity || tg.Paths[0].Path != "config/crd/bases" {
		t.Fatalf("target %+v", tg)
	}
	if r.appliesTo(3, 3) || !r.appliesTo(3, 4) || !r.appliesTo(3, 5) {
		t.Fatal("the switch does not start at 3.4")
	}
	if _, ok := r.pinFor("v1.5.2"); !ok {
		t.Fatal("v1.5.2 is not pinned")
	}
}
