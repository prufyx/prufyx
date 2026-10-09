// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Install channels (Target.Channels): the rules are about the declared
// channel, and a version another channel still serves is never forbidden.

func channelTarget() Target {
	tg := synthTarget()
	tg.DeclaredChannel = "standard"
	tg.Channels = []Channel{{Name: "experimental", Paths: []PathSpec{{Path: "deploy/experimental", Dir: true, Match: regexp.MustCompile(`^[^.][^/]*\.ya?ml$`), Guard: regexp.MustCompile(`(?i)crd`)}}}}
	return tg
}

// crdOf renders a CRD of the given kind in the synthetic group.
func crdOf(kind string, versions ...string) string { return crd(kind, versions...) }

func channelWorld(std, exp map[string]string) release {
	files := map[string]string{}
	for name, content := range std {
		files["deploy/crds/"+name] = content
	}
	for name, content := range exp {
		files["deploy/experimental/"+name] = content
	}
	return release{files: files}
}

func channelReleases(mutate func(rs []release)) synthRepo {
	rs := []release{
		channelWorld(
			map[string]string{"a.yaml": crdOf("Alpha", "v1beta1", "v1"), "b.yaml": crdOf("Beta", "v1beta1", "v1")},
			map[string]string{"a.yaml": crdOf("Alpha", "v1alpha1", "v1beta1", "v1"), "b.yaml": crdOf("Beta", "v1beta1", "v1"), "g.yaml": crdOf("Gamma", "v1alpha2")},
		),
		channelWorld(
			map[string]string{"a.yaml": crdOf("Alpha", "v1"), "b.yaml": crdOf("Beta", "v1")},
			map[string]string{"a.yaml": crdOf("Alpha", "v1beta1", "v1"), "b.yaml": crdOf("Beta", "v1"), "g.yaml": crdOf("Gamma", "v1alpha2")},
		),
	}
	rs[0].tag, rs[1].tag = "v1.0.0", "v1.1.0"
	if mutate != nil {
		mutate(rs)
	}
	return newSynth(rs...)
}

func TestChannelRetainedVersionsAreNotForbidden(t *testing.T) {
	out := runSynth(t, channelTarget(), channelReleases(nil))
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || !proof.Lines.LineWide {
		t.Fatalf("pair %s %q", p.Status, p.Reason)
	}
	// Beta v1beta1 is gone from both channels: one rule. Alpha v1beta1 is
	// gone from the standard channel and still served by the experimental
	// one: no rule, recorded.
	if len(out.Entries) != 1 || out.Entries[0].Rule.ID != "argo-cd.crd-version-removal.betas-synth-example-io.1-0-0-to-1-1-0" {
		t.Fatalf("rules %v", ruleIDs(out))
	}
	if len(proof.Removals) != 1 || proof.Removals[0].Member != "synth.example.io/v1beta1/Beta" {
		t.Fatalf("removals %+v", proof.Removals)
	}
	if len(proof.ChannelRetained) != 1 || proof.ChannelRetained[0] != (ChannelRetained{CRD: "alphas.synth.example.io", Member: "synth.example.io/v1beta1/Alpha", Channel: "experimental", ToTag: "v1.1.0"}) {
		t.Fatalf("retained %+v", proof.ChannelRetained)
	}
	// The description says which channel the rule is about.
	if d := out.Entries[0].Description; !strings.Contains(d, "standard install channel") || !strings.Contains(d, "another install channel (experimental)") {
		t.Fatalf("description %q", d)
	}
	// The channel is in the proof, read in full, and its files are not
	// scan findings.
	if len(proof.To.Channels) != 1 || proof.To.Channels[0].Name != "experimental" || len(proof.To.Channels[0].CRDs) != 3 || len(proof.To.Channels[0].Files) != 3 {
		t.Fatalf("channels %+v", proof.To.Channels)
	}
	for _, lt := range proof.Lines.To.Tags {
		if !lt.ScanClean {
			t.Fatalf("channel files are scan findings: %+v", lt.ScanFindings)
		}
	}
	// A pair with channels is never attested.
	if pr := p; pr.Attestation != nil && pr.Attestation.Status == extract.PairAttested {
		t.Fatal("attested")
	}
}

func ruleIDs(out *extract.Output) []string {
	var ids []string
	for _, e := range out.Entries {
		ids = append(ids, e.Rule.ID)
	}
	return ids
}

// Without the channel declared, the experimental directory is a conflicting
// copy and the pair is withheld: the declaration is what makes it derivable.
func TestChannelFilesConflictWithoutTheDeclaration(t *testing.T) {
	out := runSynth(t, synthTarget(), channelReleases(nil))
	if p, _ := pairOf(t, out, "1.0.0", "1.1.0"); p.Status != extract.PairWithheld {
		t.Fatalf("pair %s without channels", p.Status)
	}
}

func TestChannelEveryWayItCanBeWrongWithholds(t *testing.T) {
	cases := map[string]struct {
		mutate func(rs []release)
		want   string
	}{
		"a channel directory that does not exist": {func(rs []release) {
			for _, r := range rs {
				for p := range r.files {
					if strings.HasPrefix(p, "deploy/experimental/") {
						delete(r.files, p)
					}
				}
			}
		}, "channel experimental: listed directory deploy/experimental does not exist"},
		"a definition twice in a channel": {func(rs []release) {
			rs[1].files["deploy/experimental/a2.yaml"] = crdOf("Alpha", "v1")
		}, "channel experimental"},
		"template syntax in a channel file": {func(rs []release) {
			rs[1].files["deploy/experimental/a.yaml"] = "{{- if .Values.x }}\n" + crdOf("Alpha", "v1") + "{{- end }}\n"
		}, "channel experimental"},
		"a channel file that looks like a CRD but is not read": {func(rs []release) {
			rs[1].files["deploy/experimental/crd-extra.txt"] = "x"
		}, "channel experimental"},
		"a channel that defines a declared kind under another name": {func(rs []release) {
			rs[1].files["deploy/experimental/z.yaml"] = strings.Replace(crdOf("Alpha", "v1"), "name: alphas.", "name: zetas.", 1)
		}, "channel experimental"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			out := runSynth(t, channelTarget(), channelReleases(tc.mutate))
			p, _ := pairOf(t, out, "1.0.0", "1.1.0")
			if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, tc.want) {
				t.Fatalf("%s %q, want a withheld pair mentioning %q", p.Status, p.Reason, tc.want)
			}
		})
	}
}

// A definition the declared channel drops and another channel still holds is
// not told from a removed one: the pair is withheld, as for a moved file.
func TestChannelDefinitionMovedToAnotherChannelIsNotRemoved(t *testing.T) {
	out := runSynth(t, channelTarget(), channelReleases(func(rs []release) {
		delete(rs[1].files, "deploy/crds/b.yaml") // Beta only in the experimental channel at 1.1
	}))
	p, _ := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "betas.synth.example.io") {
		t.Fatalf("%s %q", p.Status, p.Reason)
	}
}

// A version only the other channel served is not part of the declared
// channel's claim: no rule, nothing recorded as retained.
func TestChannelOnlyVersionsAreOutsideTheClaim(t *testing.T) {
	out := runSynth(t, channelTarget(), channelReleases(func(rs []release) {
		// Gamma v1alpha2 is served only by the experimental channel and
		// disappears from it at 1.1.
		rs[1].files["deploy/experimental/g.yaml"] = crdOf("Gamma", "v1")
	}))
	p, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived {
		t.Fatalf("%s %q", p.Status, p.Reason)
	}
	for _, id := range ruleIDs(out) {
		if strings.Contains(id, "gammas") {
			t.Fatalf("rule %s for a version only the experimental channel served", id)
		}
	}
	for _, rt := range proof.ChannelRetained {
		if strings.Contains(rt.Member, "Gamma") {
			t.Fatalf("retained %+v", rt)
		}
	}
}

// A version retained by a release of the later line other than its anchor
// is retained too (the rule ranges over the whole line).
func TestChannelRetentionCoversEveryReleaseOfTheLaterLine(t *testing.T) {
	rs := []release{
		channelWorld(map[string]string{"a.yaml": crdOf("Alpha", "v1beta1", "v1")}, map[string]string{"a.yaml": crdOf("Alpha", "v1beta1", "v1")}),
		channelWorld(map[string]string{"a.yaml": crdOf("Alpha", "v1")}, map[string]string{"a.yaml": crdOf("Alpha", "v1")}),
		channelWorld(map[string]string{"a.yaml": crdOf("Alpha", "v1")}, map[string]string{"a.yaml": crdOf("Alpha", "v1beta1", "v1")}),
	}
	rs[0].tag, rs[1].tag, rs[2].tag = "v1.0.0", "v1.1.0", "v1.1.1"
	out := runSynth(t, channelTarget(), newSynth(rs...))
	_, proof := pairOf(t, out, "1.0.0", "1.1.0")
	if len(out.Entries) != 0 || len(proof.ChannelRetained) != 1 || proof.ChannelRetained[0].ToTag != "v1.1.1" {
		t.Fatalf("rules %v retained %+v", ruleIDs(out), proof.ChannelRetained)
	}
}

func TestLoadTargetsChannels(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"project": "argo-cd", "name": "Synth", "repo": "github.com/argoproj/argo-cd", "component": "pkg:github/argoproj/argo-cd", "factProject": "argo_cd",
			"tagPrefixes": []string{"v"}, "minFrom": "1.0",
			"paths":           []any{map[string]any{"path": "deploy/crds", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}},
			"exclude":         []any{},
			"declaredChannel": "standard",
			"channels":        []any{map[string]any{"name": "experimental", "paths": []any{map[string]any{"path": "deploy/experimental", "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}}}},
		}
	}
	load := func(mutate func(t map[string]any)) (Target, error) {
		tg := base()
		if mutate != nil {
			mutate(tg)
		}
		doc, _ := json.Marshal(map[string]any{"schema": TargetsSchema, "targets": []any{tg}})
		ts, err := LoadTargets(doc)
		if err != nil {
			return Target{}, err
		}
		return ts[0], nil
	}
	tg, err := load(nil)
	if err != nil || tg.DeclaredChannel != "standard" || len(tg.Channels) != 1 || tg.Channels[0].Name != "experimental" {
		t.Fatalf("valid channels refused: %v %+v", err, tg)
	}
	channel := func(t map[string]any) map[string]any { return t["channels"].([]any)[0].(map[string]any) }
	for name, mutate := range map[string]func(t map[string]any){
		"no declared channel":             func(t map[string]any) { delete(t, "declaredChannel") },
		"declared channel without others": func(t map[string]any) { delete(t, "channels") },
		"channel named like the declared": func(t map[string]any) { channel(t)["name"] = "standard" },
		"channel name":                    func(t map[string]any) { channel(t)["name"] = "Experimental" },
		"two channels of one name": func(t map[string]any) {
			t["channels"] = []any{channel(t), channel(t)}
		},
		"no paths":                 func(t map[string]any) { channel(t)["paths"] = []any{} },
		"channel path unclean":     func(t map[string]any) { channel(t)["paths"].([]any)[0].(map[string]any)["path"] = "../x" },
		"channel path in declared": func(t map[string]any) { channel(t)["paths"].([]any)[0].(map[string]any)["path"] = "deploy/crds/sub" },
		"declared path in channel": func(t map[string]any) { channel(t)["paths"].([]any)[0].(map[string]any)["path"] = "deploy" },
		"every channel path optional": func(t map[string]any) {
			channel(t)["paths"].([]any)[0].(map[string]any)["optional"] = true
		},
		"attest": func(t map[string]any) { t["attest"] = true },
		"with a remote": func(t map[string]any) {
			t["remote"] = map[string]any{"fromLine": "1.1", "kustomization": "k.yaml", "repo": "github.com/example/crds", "directory": "d", "pins": []any{map[string]any{"tag": "v1.0.0", "commit": strings.Repeat("a", 40)}}}
		},
		"an exclusion covering a channel path": func(t map[string]any) {
			t["exclude"] = []any{map[string]any{"path": "deploy/experimental/", "repo": "github.com/argoproj/argo-cd", "reason": "a long enough reason", "evidence": strings.Repeat("e", 48)}}
		},
		"more than four channels": func(t map[string]any) {
			var chs []any
			for _, n := range []string{"a", "b", "c", "d", "e"} {
				chs = append(chs, map[string]any{"name": n, "paths": []any{map[string]any{"path": "deploy/" + n, "directory": true, "match": "^[^.][^/]*\\.ya?ml$", "guard": "(?i)crd"}}})
			}
			t["channels"] = chs
		},
	} {
		if _, err := load(mutate); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestGatewayAPITargetDeclaresItsChannels(t *testing.T) {
	tg, ok := TargetFor("gateway-api")
	if !ok || tg.DeclaredChannel != "standard" || len(tg.Channels) != 1 || tg.Channels[0].Name != "experimental" || tg.Paths[0].Path != "config/crd/standard" || tg.Channels[0].Paths[0].Path != "config/crd/experimental" {
		t.Fatalf("gateway-api target %+v", tg)
	}
	if tg.Attest || tg.Catalog != CatalogCommunity {
		t.Fatalf("target %+v", tg)
	}
}
