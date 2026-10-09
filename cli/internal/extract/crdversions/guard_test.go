// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const fixtureDir = "test/fixtures/"

// fixtureExclusion is a reviewed exclusion of test fixtures.
func fixtureExclusion() Exclusion {
	return Exclusion{Path: fixtureDir, Repo: "github.com/argoproj/argo-cd", Reason: "fixtures of the unit tests of the project", Evidence: "only read by the Go tests of the package through os.ReadFile; no install path names them"}
}

// guardPair runs a pair of releases whose trees hold the listed paths
// (both) next to the CRD of a quiet pair and an extra definition under
// test/fixtures/, with the given reviewed exclusions.
func guardPair(t *testing.T, extra map[string]string, exclude ...Exclusion) (extract.PairRecord, PairProof) {
	t.Helper()
	alpha := crd("Alpha", "v1beta1", "v1")
	later := crd("Alpha", "v1")
	from := map[string]string{"deploy/crds/a.yaml": alpha, fixtureDir + "crd.yaml": crd("Gamma", "v1")}
	to := map[string]string{"deploy/crds/a.yaml": later, fixtureDir + "crd.yaml": crd("Gamma", "v1")}
	for p, c := range extra {
		from[p], to[p] = c, c
	}
	s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
	p, proof := pairOf(t, runSynth(t, synthTarget(exclude...), s), "1.0.0", "1.1.0")
	return p, proof
}

// voidFindings are the findings of class exclusion-void at the later anchor.
func voidFindings(proof PairProof) []Finding {
	var out []Finding
	for _, f := range proof.To.Scan.Findings {
		if f.Class == ClassVoided {
			out = append(out, f)
		}
	}
	return out
}

// An unreferenced fixture directory is excluded and the pair attests; a
// reference from any install surface voids the entry for the tag, the
// fixture then blocks attestation as any file would, and the finding names
// the referrer.
func TestGuardInstallSurfaces(t *testing.T) {
	cases := []struct {
		name  string
		extra map[string]string
		// by is the referrer path of the finding ("" when none is wanted).
		by     string
		detail string
	}{
		{name: "nothing refers to it"},
		{name: "a kustomization resource", extra: map[string]string{"deploy/kustomization.yaml": "resources:\n- crds/a.yaml\n- ../test/fixtures/crd.yaml\n"}, by: "deploy/kustomization.yaml", detail: "kustomization refers to test/fixtures/crd.yaml"},
		{name: "a kustomization directory", extra: map[string]string{"deploy/kustomization.yml": "bases:\n  - ../test/fixtures\n"}, by: "deploy/kustomization.yml", detail: "refers to test/fixtures"},
		{name: "a kustomization patch path", extra: map[string]string{"deploy/Kustomization": "patches:\n- path: ../test/fixtures/patch.yaml\n  target:\n    kind: Deployment\n"}, by: "deploy/Kustomization"},
		{name: "a flow style kustomization", extra: map[string]string{"deploy/kustomization.yaml": "resources: [\"../test/fixtures/crd.yaml\"]\n"}, by: "deploy/kustomization.yaml"},
		{name: "a config map file", extra: map[string]string{"deploy/kustomization.yaml": "configMapGenerator:\n- name: x\n  files:\n  - crd.yaml=../test/fixtures/crd.yaml\n"}, by: "deploy/kustomization.yaml"},
		{name: "an unreadable kustomization is read as text", extra: map[string]string{"test/other/kustomization.yaml": "{{ if .x }}\nresources:\n- ../fixtures\n\t- bad: [\n"}, by: "test/other/kustomization.yaml"},
		{name: "a kustomization chain", extra: map[string]string{
			"deploy/kustomization.yaml":               "resources:\n- overlays/prod\n",
			"deploy/overlays/prod/kustomization.yaml": "resources:\n- ../../../test/fixtures/crd.yaml\n",
		}, by: "deploy/overlays/prod/kustomization.yaml"},
		{name: "a chain through a kustomization inside the excluded path", extra: map[string]string{
			"deploy/kustomization.yaml":             "resources:\n- ../test/fixtures/base\n",
			"test/fixtures/base/kustomization.yaml": "resources:\n- ../../../other\n",
			"other/kustomization.yaml":              "resources:\n- ../test/fixtures/crd.yaml\n",
		}, by: "deploy/kustomization.yaml"},
		{name: "a kustomization inside the excluded path that nothing reaches", extra: map[string]string{
			"test/fixtures/base/kustomization.yaml": "resources:\n- ../../../test/fixtures/crd.yaml\n",
		}},
		{name: "a reached kustomization inside the excluded path refers outside", extra: map[string]string{
			"test/fixtures/base/kustomization.yaml": "resources:\n- ../crd.yaml\n- ../../../deploy/crds\n",
		}},
		{name: "a kustomization naming a similar path", extra: map[string]string{"deploy/kustomization.yaml": "resources:\n- ../test/fixtures-old/crd.yaml\n- ../test/fixture\n"}},
		{name: "a chart dependency", extra: map[string]string{
			"charts/app/Chart.yaml": "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n- name: crds\n  version: 1.0.0\n  repository: file://../../test/fixtures/crds-chart\n",
		}, by: "charts/app/Chart.yaml", detail: "Helm chart refers to test/fixtures/crds-chart"},
		{name: "a chart requirements file", extra: map[string]string{
			"charts/app/requirements.yaml": "dependencies:\n- name: crds\n  repository: \"file://../../test/fixtures/crds-chart\"\n",
		}, by: "charts/app/requirements.yaml"},
		{name: "a chart dependency chain", extra: map[string]string{
			"charts/app/Chart.yaml":            "dependencies:\n- name: sub\n  repository: file://../sub\n",
			"charts/sub/Chart.yaml":            "dependencies:\n- name: crds\n  repository: file://../../test/fixtures/c\n",
			"charts/other/Chart.yaml":          "name: other\n",
			"test/fixtures/c/Chart.yaml":       "name: c\n",
			"test/fixtures/c/templates/x.yaml": "x: 1\n",
		}, by: "charts/sub/Chart.yaml"},
		{name: "a chart fixture inside the excluded path", extra: map[string]string{"test/fixtures/chart/Chart.yaml": "apiVersion: v2\nname: fixture\nversion: 1.0.0\n"}},
		{name: "the excluded path lies under a chart", extra: map[string]string{"Chart.yaml": "apiVersion: v2\nname: root\nversion: 1.0.0\n"}, by: "Chart.yaml", detail: "lies under a Helm chart"},
		{name: "a Makefile install target", extra: map[string]string{"Makefile": "install:\n\tkubectl apply -f test/fixtures/crd.yaml\n"}, by: "Makefile", detail: "Makefile refers to test/fixtures/crd.yaml"},
		{name: "a Makefile with a variable", extra: map[string]string{"hack/targets.mk": "FIXTURES ?= $(ROOT)/test/fixtures\n\ndeploy-dev:\n\t$(KUSTOMIZE) build $(FIXTURES) | $(KUBECTL) apply -f -\n"}, by: "hack/targets.mk", detail: "$(FIXTURES)"},
		{name: "a Makefile with a braced variable", extra: map[string]string{"Makefile": "FIX = test/fixtures\n\nrun:\n\tkubectl apply -f ${FIX}/crd.yaml\n"}, by: "Makefile", detail: "${FIX}"},
		{name: "a Makefile line outside a recipe", extra: map[string]string{"Makefile": "$(shell kubectl apply -f test/fixtures/crd.yaml)\n"}, by: "Makefile"},
		{name: "a Makefile assignment that runs a tool", extra: map[string]string{"Makefile": "OUT := $(shell kubectl apply -f test/fixtures/crd.yaml)\n"}, by: "Makefile"},
		{name: "a Makefile continuation", extra: map[string]string{"Makefile": "setup:\n\thelm template x ./chart \\\n\t  --values test/fixtures/values.yaml\n"}, by: "Makefile"},
		{name: "a Makefile one-line rule", extra: map[string]string{"Makefile": "setup: ; kubectl create -f test/fixtures\n"}, by: "Makefile"},
		{name: "a Makefile test target", extra: map[string]string{"Makefile": "test-e2e:\n\tkubectl apply -f test/fixtures/crd.yaml\n\nlint check:\n\tkubectl apply --dry-run=client -f test/fixtures\n"}},
		{name: "a Makefile target that is not a test target", extra: map[string]string{"Makefile": "e2e-setup: prepare\n\t@echo\n\nlatest-run:\n\tkubectl apply -f test/fixtures/crd.yaml\n"}, by: "Makefile"},
		{name: "a Makefile line without an install tool", extra: map[string]string{"Makefile": "gen:\n\tgo run ./hack/gen --out test/fixtures\n\tcp test/fixtures/crd.yaml /tmp\n"}},
		{name: "a Makefile inside the excluded path", extra: map[string]string{"test/fixtures/Makefile": "install:\n\tkubectl apply -f test/fixtures/crd.yaml\n"}},
		{name: "a document with an install command", extra: map[string]string{"docs/quickstart.md": "Install:\n\n```\nkubectl apply -f https://raw.githubusercontent.com/o/r/main/test/fixtures/crd.yaml\n```\n"}, by: "docs/quickstart.md", detail: "document refers to //raw.githubusercontent.com/o/r/main/test/fixtures/crd.yaml"},
		{name: "a document with a helm command", extra: map[string]string{"README.rst": "    $ helm install demo ./test/fixtures/chart\n"}, by: "README.rst"},
		{name: "a document that names the path in prose", extra: map[string]string{"CONTRIBUTING.md": "Create a new CRD fixture under test/fixtures/ and run the tests.\n"}},
		{name: "the same bytes as a kustomization and a document", extra: map[string]string{"deploy/kustomization.yaml": "kubectl apply -f test/fixtures/crd.yaml\n", "docs/x.md": "kubectl apply -f test/fixtures/crd.yaml\n"}, by: "docs/x.md"},
		{name: "a document in a vendored directory", extra: map[string]string{"vendor/x/README.md": "kubectl apply -f test/fixtures/crd.yaml\n"}},
		{name: "a document inside the excluded path", extra: map[string]string{"test/fixtures/README.md": "kubectl apply -f test/fixtures/crd.yaml\n"}},
		{name: "a document naming a similar path", extra: map[string]string{"docs/a.adoc": "kubectl apply -f test/fixtures-v2/crd.yaml and test/fixture.yaml\n"}},
		{name: "a Go package that embeds the directory", extra: map[string]string{"test/embed.go": "package test\n\nimport \"embed\"\n\n//go:embed fixtures\nvar fs embed.FS\n"}, by: "test/embed.go", detail: "//go:embed fixtures"},
		{name: "a Go package that embeds a pattern", extra: map[string]string{"test/more.go": "package test\n\n//go:embed all:fixtures/*.yaml other.txt\nvar x string\n"}, by: "test/more.go"},
		{name: "a Go package that embeds with quotes", extra: map[string]string{"test/e.go": "package test\n\n//go:embed \"other.txt\" `fixtures/crd.yaml`\nvar x string\n"}, by: "test/e.go"},
		{name: "a Go package at the root that embeds a subdirectory", extra: map[string]string{"main.go": "package main\n\n//go:embed test/fixtures\nvar fs embed.FS\n"}, by: "main.go"},
		{name: "a Go test file that embeds", extra: map[string]string{"test/embed_test.go": "package test\n\n//go:embed fixtures\nvar fs embed.FS\n"}},
		{name: "a Go package that embeds another directory", extra: map[string]string{"test/embed.go": "package test\n\n//go:embed templates fixtures-old\nvar fs embed.FS\n"}},
		{name: "a Go package elsewhere", extra: map[string]string{"pkg/embed.go": "package pkg\n\n//go:embed fixtures\nvar fs embed.FS\n"}},
		// Review of 2026-10-09 (MED-1): Go packages inside the excluded
		// path, container builds, nix, shell scripts, install-like targets.
		{name: "a Go package inside the excluded path", extra: map[string]string{fixtureDir + "install.go": "package fixtures\n\n//go:embed crd.yaml\nvar crd []byte\n"}, by: fixtureDir + "install.go", detail: "//go:embed crd.yaml"},
		{name: "a Go package below the excluded path", extra: map[string]string{fixtureDir + "pkg/install.go": "package pkg\n\n//go:embed *.yaml\nvar more embed.FS\n", fixtureDir + "pkg/x.yaml": "a: 1\n"}, by: fixtureDir + "pkg/install.go"},
		{name: "a Go test file inside the excluded path", extra: map[string]string{fixtureDir + "install_test.go": "package fixtures\n\n//go:embed crd.yaml\nvar crd []byte\n"}},
		{name: "a Dockerfile COPY", extra: map[string]string{"Dockerfile": "FROM scratch\nCOPY test/fixtures/ /crds\n"}, by: "Dockerfile", detail: "container build refers to test/fixtures/"},
		{name: "a Dockerfile ADD with options", extra: map[string]string{"build/Dockerfile.operator": "FROM scratch\nADD --chown=1000:1000 \\\n  ./test/fixtures/crd.yaml /crds/\n"}, by: "build/Dockerfile.operator"},
		{name: "a Dockerfile COPY in JSON form", extra: map[string]string{"x.dockerfile": "COPY [\"test/fixtures\", \"/crds\"]\n"}, by: "x.dockerfile"},
		{name: "a Containerfile COPY relative to its directory", extra: map[string]string{"test/Containerfile": "FROM scratch\nCOPY fixtures /crds\n"}, by: "test/Containerfile"},
		{name: "a Dockerfile COPY of a directory above", extra: map[string]string{"Dockerfile": "FROM scratch\nCOPY test /src/test\n"}, by: "Dockerfile"},
		{name: "a Dockerfile COPY of the whole context", extra: map[string]string{"Dockerfile": "FROM golang AS build\nCOPY . /src\nRUN make\nFROM scratch\nCOPY --from=build /src/bin/manager /manager\n"}},
		{name: "a Dockerfile that only writes to the path", extra: map[string]string{"Dockerfile": "FROM scratch\nCOPY bin/manager /test/fixtures/\n"}},
		{name: "a Dockerfile naming the path outside COPY", extra: map[string]string{"Dockerfile": "FROM scratch\nRUN echo test/fixtures\nLABEL x=test/fixtures\n"}},
		{name: "an Earthfile COPY", extra: map[string]string{"Earthfile": "image:\n    FROM scratch\n    COPY --dir test/fixtures/ /crds\n"}, by: "Earthfile"},
		{name: "an Earthfile SAVE ARTIFACT", extra: map[string]string{"Earthfile": "gen:\n    SAVE ARTIFACT test/fixtures AS LOCAL out/fixtures\n"}, by: "Earthfile"},
		{name: "an Earthfile SAVE ARTIFACT to the path", extra: map[string]string{"Earthfile": "gen:\n    SAVE ARTIFACT out AS LOCAL test/fixtures\n"}},
		{name: "a nix copy", extra: map[string]string{"nix/build.nix": "{ self, ... }:\n{\n  installPhase = ''\n    cp -r ${self}/test/fixtures/* $out/crds\n  '';\n}\n"}, by: "nix/build.nix"},
		{name: "a nix relative path", extra: map[string]string{"nix/build.nix": "{\n  crds = ../test/fixtures;\n}\n"}, by: "nix/build.nix"},
		{name: "a nix file without the path", extra: map[string]string{"nix/build.nix": "{ self, ... }:\n{\n  src = ./.;\n  meta = { description = \"test fixtures\"; };\n  # cp test/fixtures/crd.yaml $out\n  installPhase = \"cp -r ${self}/cluster/crds $out\";\n}\n"}},
		{name: "a shell script with an install command", extra: map[string]string{"hack/install.sh": "#!/bin/sh\nset -e\nkubectl apply -f \"${ROOT}/test/fixtures/crd.yaml\"\n"}, by: "hack/install.sh", detail: "shell script refers to"},
		{name: "a shell script without an install tool", extra: map[string]string{"hack/gen.bash": "#!/bin/bash\ncp test/fixtures/crd.yaml /tmp\n"}},
		{name: "a Makefile install target named like a test", extra: map[string]string{"Makefile": "verify-install:\n\tkubectl apply -f test/fixtures/crd.yaml\n"}, by: "Makefile"},
		{name: "a Makefile e2e deploy target", extra: map[string]string{"Makefile": "e2e-deploy:\n\tkubectl apply -f test/fixtures/crd.yaml\n"}, by: "Makefile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, proof := guardPair(t, tc.extra, fixtureExclusion())
			if p.Status != extract.PairDerived {
				t.Fatalf("pair %s %q", p.Status, p.Reason)
			}
			voids := voidFindings(proof)
			if tc.by == "" {
				if len(voids) != 0 || !proof.Completeness.Attestable {
					t.Fatalf("voided %+v, completeness %+v", voids, proof.Completeness)
				}
				var excluded bool
				for _, f := range proof.To.Scan.Findings {
					excluded = excluded || (f.Class == ClassExcluded && f.Location == fixtureDir)
				}
				if !excluded {
					t.Fatalf("the fixture is not recorded as excluded: %+v", proof.To.Scan.Findings)
				}
				return
			}
			if len(voids) != 1 || voids[0].Path != tc.by || voids[0].Location != fixtureDir || !strings.Contains(voids[0].Detail, tc.detail) {
				t.Fatalf("void findings %+v, want %s %q", voids, tc.by, tc.detail)
			}
			if proof.Completeness.Attestable || proof.Completeness.Scan || !strings.Contains(strings.Join(proof.Completeness.Reasons, "\n"), "exclusion-void ("+fixtureDir+")") {
				t.Fatalf("completeness %+v", proof.Completeness)
			}
			// The fixture is read like any file of a default-excluded
			// directory: it is an extra definition there, at a void location.
			var extra bool
			for _, f := range proof.To.Scan.Findings {
				extra = extra || (f.Class == ClassExtra && f.Path == fixtureDir+"crd.yaml" && f.Location == "void: "+fixtureDir)
			}
			if !extra {
				t.Fatalf("findings %+v", proof.To.Scan.Findings)
			}
		})
	}
}

// The guard decides per tag: a reference at one release of a line voids
// the entry there only, and every pair that reads that release is not
// attestable.
func TestGuardIsPerTag(t *testing.T) {
	alpha, later := crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1")
	fixture := map[string]string{fixtureDir + "crd.yaml": crd("Gamma", "v1")}
	with := func(base map[string]string, extra ...string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for i := 0; i+1 < len(extra); i += 2 {
			out[extra[i]] = extra[i+1]
		}
		return out
	}
	fromFiles := with(fixture, "deploy/crds/a.yaml", alpha)
	toFiles := with(fixture, "deploy/crds/a.yaml", later)
	referenced := with(toFiles, "Makefile", "install:\n\tkubectl apply -f test/fixtures/crd.yaml\n")
	s := newSynth(
		release{"v1.0.0", fromFiles},
		release{"v1.1.0", toFiles},
		release{"v1.1.1", referenced},
		release{"v1.2.0", toFiles},
	)
	out := runSynth(t, synthTarget(fixtureExclusion()), s)
	_, quiet := pairOf(t, out, "1.0.0", "1.1.0")
	byTag := map[string][]Finding{}
	for _, lt := range quiet.Lines.To.Tags {
		for _, f := range lt.ScanFindings {
			if f.Class == ClassVoided {
				byTag[lt.Tag] = append(byTag[lt.Tag], f)
			}
		}
	}
	if len(voidFindings(quiet)) != 0 || len(byTag) != 1 || len(byTag["v1.1.1"]) != 1 {
		t.Fatalf("void findings by tag %v", byTag)
	}
	if quiet.Completeness.Attestable {
		t.Fatalf("a pair that reads the release is attestable: %+v", quiet.Completeness)
	}
	if !strings.Contains(strings.Join(quiet.Completeness.Reasons, "\n"), "v1.1.1: the full-tree scan found exclusion-void") {
		t.Fatalf("reasons %v", quiet.Completeness.Reasons)
	}
	// The pair that does not read the release is attestable.
	s2 := newSynth(release{"v1.0.0", fromFiles}, release{"v1.1.0", toFiles})
	_, ok := pairOf(t, runSynth(t, synthTarget(fixtureExclusion()), s2), "1.0.0", "1.1.0")
	if !ok.Completeness.Attestable {
		t.Fatalf("completeness %+v", ok.Completeness)
	}
}

// An entry with no file at the tag is not void, and a declared copy is
// never guarded (a chart's templates are install surfaces by nature).
func TestGuardScope(t *testing.T) {
	refs := map[string]string{"Makefile": "install:\n\tkubectl apply -f test/fixtures/crd.yaml\n\tkubectl apply -f charts/templates/crds.yaml\n"}
	// The entry has no file at the tag.
	alpha, later := crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1")
	s := newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha, "Makefile": refs["Makefile"]}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": later, "Makefile": refs["Makefile"]}},
	)
	_, proof := pairOf(t, runSynth(t, synthTarget(fixtureExclusion()), s), "1.0.0", "1.1.0")
	if !proof.Completeness.Attestable || len(voidFindings(proof)) != 0 {
		t.Fatalf("an entry without files is void: %+v", proof.To.Scan.Findings)
	}
	// A file that is not a candidate (a picture) does not make it present.
	s = newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha, "Makefile": refs["Makefile"], fixtureDir + "logo.png": "x"}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": later, "Makefile": refs["Makefile"], fixtureDir + "logo.png": "x"}},
	)
	_, proof = pairOf(t, runSynth(t, synthTarget(fixtureExclusion()), s), "1.0.0", "1.1.0")
	if !proof.Completeness.Attestable {
		t.Fatalf("completeness %+v", proof.Completeness)
	}
	// A declared copy that a Makefile applies stays a checked copy.
	copyEntry := Exclusion{Path: "charts/templates/", Repo: "github.com/argoproj/argo-cd", Reason: "Helm templates of the same definitions", Evidence: "checked as copies of the listed definitions at every tag", Copies: true}
	crds := "{{- if .Values.crds }}\n" + later
	s = newSynth(
		release{"v1.0.0", map[string]string{"deploy/crds/a.yaml": alpha, "charts/templates/crds.yaml": "{{- if .Values.crds }}\n" + alpha, "Makefile": refs["Makefile"]}},
		release{"v1.1.0", map[string]string{"deploy/crds/a.yaml": later, "charts/templates/crds.yaml": crds, "Makefile": refs["Makefile"]}},
	)
	p, proof := pairOf(t, runSynth(t, synthTarget(copyEntry), s), "1.0.0", "1.1.0")
	if p.Status != extract.PairDerived || !proof.Completeness.Attestable || len(voidFindings(proof)) != 0 {
		t.Fatalf("pair %s completeness %+v findings %+v", p.Status, proof.Completeness, proof.To.Scan.Findings)
	}
}

// A void entry is a default-like location: its files are classified and
// block attestation, but they do not withhold the pair or narrow its rules
// (a rule stays derived), Go sources under it are read, and a definition is
// not taken to be gone while an opaque file lies there.
func TestGuardVoidKeepsTheRule(t *testing.T) {
	entry := Exclusion{Path: "tools/gen/", Repo: "github.com/argoproj/argo-cd", Reason: "generators that print definitions for the docs", Evidence: "run by go generate only; nothing installs the output directory"}
	templated := "{{- if .Values.crds }}\n" + crd("Beta", "v1")
	alpha, later := crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1")
	run := func(extra map[string]string) (extract.PairRecord, PairProof) {
		from := map[string]string{"deploy/crds/a.yaml": alpha, "tools/gen/crds.yaml": templated}
		to := map[string]string{"deploy/crds/a.yaml": later, "tools/gen/crds.yaml": templated}
		for k, v := range extra {
			from[k], to[k] = v, v
		}
		return pairOf(t, runSynth(t, synthTarget(entry), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})), "1.0.0", "1.1.0")
	}
	p, proof := run(nil)
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || !proof.Completeness.Attestable {
		t.Fatalf("pair %s %q %+v", p.Status, p.Reason, proof.Completeness)
	}
	p, proof = run(map[string]string{"Makefile": "install:\n\tkustomize build tools/gen | kubectl apply -f -\n"})
	var unread bool
	for _, f := range proof.To.Scan.Findings {
		unread = unread || (f.Class == ClassUnread && f.Path == "tools/gen/crds.yaml" && f.Location == "void: tools/gen/")
	}
	if p.Status != extract.PairDerived || len(p.Rules) != 1 || proof.Completeness.Attestable || !unread || !slices.Contains(proof.To.Scan.Exclusions, "void: tools/gen/") {
		t.Fatalf("pair %s %q rules %v completeness %+v findings %+v", p.Status, p.Reason, p.Rules, proof.Completeness, proof.To.Scan.Findings)
	}
	// Go code that builds a definition is read under a void entry only.
	goBuild := map[string]string{"tools/gen/crd/build.go": "package crd\n\nvar x = &apiextv1.CustomResourceDefinition{\n\tObjectMeta: metav1.ObjectMeta{},\n}\n"}
	_, proof = run(goBuild)
	for _, f := range proof.To.Scan.Findings {
		if f.Path == "tools/gen/crd/build.go" {
			t.Fatalf("Go source read under a valid entry: %+v", f)
		}
	}
	goBuild["Makefile"] = "install:\n\tkustomize build tools/gen | kubectl apply -f -\n"
	p, proof = run(goBuild)
	var unsupported bool
	for _, f := range proof.To.Scan.Findings {
		unsupported = unsupported || (f.Class == ClassUnsupported && f.Path == "tools/gen/crd/build.go" && f.Location == "void: tools/gen/")
	}
	if p.Status != extract.PairDerived || !unsupported {
		t.Fatalf("pair %s %q findings %+v", p.Status, p.Reason, proof.To.Scan.Findings)
	}
}

// A definition that left the listed paths is not gone while an opaque file
// lies under a void entry (the file may be installed), and is gone, a
// removed definition, while the entry holds.
func TestGuardVoidHoldsDefinitions(t *testing.T) {
	entry := Exclusion{Path: "tools/gen/", Repo: "github.com/argoproj/argo-cd", Reason: "generators that print definitions for the docs", Evidence: "run by go generate only; nothing installs the output directory"}
	run := func(extra map[string]string) extract.PairRecord {
		from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1"), "tools/gen/x.yaml": "{{ if x }}\nkind: CustomResourceDefinition\n"}
		to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "tools/gen/x.yaml": "{{ if x }}\nkind: CustomResourceDefinition\n"}
		delete(to, "deploy/crds/b.yaml")
		for k, v := range extra {
			from[k], to[k] = v, v
		}
		p, _ := pairOf(t, runSynth(t, synthTarget(entry), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})), "1.0.0", "1.1.0")
		return p
	}
	// An opaque file under a reviewed exclusion holds, void or not.
	for name, extra := range map[string]map[string]string{"valid": nil, "void": {"Makefile": "install:\n\tkubectl apply -f tools/gen\n"}} {
		if p := run(extra); p.Status != extract.PairWithheld || !strings.Contains(p.Reason, "a removed definition cannot be told from a moved one") {
			t.Fatalf("%s entry: %s %q", name, p.Status, p.Reason)
		}
	}
	// In a default-excluded directory (no entry) it does not.
	from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1"), "test/gen/x.yaml": "{{ if x }}\nkind: CustomResourceDefinition\n"}
	to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "test/gen/x.yaml": "{{ if x }}\nkind: CustomResourceDefinition\n"}
	if p, proof := pairOf(t, runSynth(t, synthTarget(), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})), "1.0.0", "1.1.0"); p.Status != extract.PairDerived || len(proof.DefinitionsRemoved) != 1 {
		t.Fatalf("default directory: %s %q %+v", p.Status, p.Reason, proof.DefinitionsRemoved)
	}
}

// The scan with the guard is the same at any concurrency.
func TestGuardDeterministicUnderConcurrency(t *testing.T) {
	files := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), fixtureDir + "crd.yaml": crd("Gamma", "v1"), "Makefile": "install:\n\tkubectl apply -f test/fixtures\n"}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("docs/d%02d.md", i)] = fmt.Sprintf("kubectl apply -f test/fixtures/x%02d.yaml\n", i)
		files[fmt.Sprintf("k%02d/kustomization.yaml", i)] = fmt.Sprintf("resources:\n- ../test/fixtures/x%02d.yaml\n", i)
		files[fmt.Sprintf("pkg%02d/e.go", i)] = "package p\n\n//go:embed x\n"
	}
	s := newSynth(release{"v1.0.0", files}, release{"v1.1.0", files})
	want := outputBytes(t, runSynthConcurrent(t, synthTarget(fixtureExclusion()), s, 1))
	for run := 0; run < 20; run++ {
		got := outputBytes(t, runSynthConcurrent(t, synthTarget(fixtureExclusion()), s, 8))
		var names []string
		for k := range want {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			if !bytes.Equal(want[k], got[k]) {
				t.Fatalf("run %d: %s differs with concurrency 8", run, k)
			}
		}
	}
	_, proof := pairOf(t, runSynthConcurrent(t, synthTarget(fixtureExclusion()), s, 1), "1.0.0", "1.1.0")
	if v := voidFindings(proof); len(v) != 1 || v[0].Path != "k00/kustomization.yaml" {
		t.Fatalf("the first referrer in path order is named: %+v", v)
	}
}

func TestMention(t *testing.T) {
	dir := Exclusion{Path: "test/e2e/testdata/"}
	file := Exclusion{Path: "pkg/engine/resources/default-config.yaml"}
	glob := Exclusion{Path: "cmd/cli/data/crds/cli.kyverno.io_*"}
	for _, tc := range []struct {
		e    Exclusion
		text string
		want string
	}{
		{dir, "kubectl apply -f test/e2e/testdata/crd.yaml", "test/e2e/testdata/crd.yaml"},
		{dir, "kubectl apply -f ./test/e2e/testdata/", "./test/e2e/testdata/"},
		{dir, "kubectl apply -f test/e2e/testdata", "test/e2e/testdata"},
		{dir, "kubectl apply -f test/e2e/testdata.", "test/e2e/testdata."},
		{dir, "kubectl apply -f=test/e2e/testdata/*.yaml", "test/e2e/testdata/*.yaml"},
		{dir, "kubectl apply -f $(ROOT)/test/e2e/testdata/a.yaml", "/test/e2e/testdata/a.yaml"},
		{dir, "kubectl apply -f ../../test/e2e/testdata/a.yaml", "../../test/e2e/testdata/a.yaml"},
		{dir, "kubectl apply -f 'https://raw.githubusercontent.com/o/r/main/test/e2e/testdata/a.yaml?raw=1'", "//raw.githubusercontent.com/o/r/main/test/e2e/testdata/a.yaml?raw"},
		{dir, "kubectl apply -f test/e2e/testdata-old/a.yaml", ""},
		{dir, "kubectl apply -f test/e2e/testdatax", ""},
		{dir, "kubectl apply -f test/e2e", ""},
		{Exclusion{Path: "design/"}, "kubectl apply -f design", ""},
		{Exclusion{Path: "design/"}, "kubectl apply -f design/", "design/"},
		{Exclusion{Path: "design/"}, "kubectl apply -f ./design", "./design"},
		{Exclusion{Path: "design/"}, "kubectl apply -f ../design/x.yaml", "../design/x.yaml"},
		{dir, "kubectl apply -f e2e/testdata", ""},
		{dir, "", ""},
		{file, "kubectl apply -f pkg/engine/resources/default-config.yaml", "pkg/engine/resources/default-config.yaml"},
		{file, "kubectl apply -f pkg/engine/resources/default-config.yaml.bak", ""},
		{file, "curl https://x/raw/pkg/engine/resources/default-config.yaml?ref=main", "//x/raw/pkg/engine/resources/default-config.yaml?ref"},
		{file, "kubectl apply -f pkg/engine/resources/default-config.yaml#L12", "pkg/engine/resources/default-config.yaml#L12"},
		{file, "kubectl apply -f pkg/engine/resources", ""},
		{glob, "kubectl apply -f cmd/cli/data/crds/cli.kyverno.io_tests.yaml", "cmd/cli/data/crds/cli.kyverno.io_tests.yaml"},
		{glob, "kubectl apply -f cmd/cli/data/crds/other.yaml", ""},
	} {
		got, ok := mention(tc.e, tc.text)
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("%q in %q: %q %v, want %q", tc.e.Path, tc.text, got, ok, tc.want)
		}
	}
}

func TestSurfaceParsing(t *testing.T) {
	mk, why := makeLines([]byte("ROOT := .\nMANIFESTS ?= $(ROOT)/test/fixtures\nPLAIN = value\nexport KUBE = kubectl --context x\n.PHONY: install e2e\n\ninstall: build\n\t@$(KUBECTL) apply \\\n\t  -f $(MANIFESTS)\n\techo done\n\ne2e test-all:\n\tkubectl apply -f x\nplain:\n\t# kubectl comment is a recipe line\n\ngen:\n\tgo generate ./...\nincl := $(shell kustomize build a/b)\n"))
	if why != "" {
		t.Fatal(why)
	}
	var got []string
	for _, l := range mk {
		got = append(got, fmt.Sprintf("%v|%s|%s", l.Targets, l.Assign, strings.Join(strings.Fields(l.Text), " ")))
	}
	want := []string{
		"[]|MANIFESTS|$(ROOT)/test/fixtures",
		"[install]||@$(KUBECTL) apply -f $(MANIFESTS)",
		"[e2e test-all]||kubectl apply -f x",
		"[]|incl|$(shell kustomize build a/b)",
		"[]||$(shell kustomize build a/b)",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("lines\n%q\nwant\n%q", got, want)
	}
	if testOnlyTargets(nil) || !testOnlyTargets([]string{"e2e", "test-all"}) || testOnlyTargets([]string{"e2e", "install"}) || testOnlyTargets([]string{"latest", "contest"}) || !testOnlyTargets([]string{"run-e2e-suite", "unit_tests", "pkg/lint"}) {
		t.Fatal("test targets")
	}
	toks, why := refTokens([]byte("resources: # ../x\n- ../a/b  # trailing\n- \"file://../c\"\n- -\n- ../a/b\nkey: v\n"))
	if why != "" || !slices.Equal(toks, []string{"resources", "../a/b", "../c", "key", "v"}) {
		t.Fatalf("tokens %q %q", toks, why)
	}
	emb, _ := goEmbeds([]byte("package p\n\n//go:embed a b/*.yaml \"c d\" `e` all:f\n// go:embed no\n//go:embed ../up\n\t//go:embed g\n"))
	if !slices.Equal(emb, []string{"a", "b/*.yaml", "c d", "e", "f", "g"}) {
		t.Fatalf("embeds %q", emb)
	}
	var many strings.Builder
	for i := 0; i <= maxSurfaceLines; i++ {
		many.WriteString("kubectl apply -f x\n")
	}
	if _, why := docLines([]byte(many.String())); !strings.Contains(why, "command lines") {
		t.Fatalf("bound %q", why)
	}
	if _, why := makeLines([]byte("a:\n" + strings.Repeat("\tkubectl apply -f x\n", maxSurfaceLines+1))); !strings.Contains(why, "command lines") {
		t.Fatalf("make bound %q", why)
	}
	var words strings.Builder
	for i := 0; i <= maxSurfaceTokens; i++ {
		fmt.Fprintf(&words, "w%d ", i)
	}
	if _, why := refTokens([]byte(words.String())); !strings.Contains(why, "words") {
		t.Fatalf("token bound %q", why)
	}
	for in, want := range map[string]bool{
		"kubectl apply -f x": true, "  $ kubectl get": true, "sudo helm install x": true, "$(KUBECTL) apply": true, "${KUSTOMIZE} build": true,
		"oc apply -f x": true, "OC apply": false, "kubectl-kyverno test": false, "./bin/kubectl apply": false, "echo kind: CustomResourceDefinition": false, "see the kubectl docs": true,
		"kustomize/config": false, "helm-chart": false,
		"velero install --provider aws": true, "see [Velero](https://github.com/o/velero/tree/main/design)": false, "cilium install": true, "the cilium agent": false, "argocd app create x": true, "crossplane xpkg build": true,
	} {
		if toolRE.MatchString(in) != want {
			t.Errorf("toolRE %q: %v", in, !want)
		}
	}
}

func TestHitsPath(t *testing.T) {
	for _, tc := range []struct {
		entry, p string
		want     bool
	}{
		{"a/b/", "a/b", true}, {"a/b/", "a/b/c/d.yaml", true}, {"a/b/", "a/bc", false}, {"a/b/", "a", false}, {"a/b/", "", false}, {"a/b/", ".", false},
		{"a/b.yaml", "a/b.yaml", true}, {"a/b.yaml", "a/b.yaml/x", false}, {"a/b.yaml", "a", false},
		{"a/*.yaml", "a/x.yaml", true}, {"a/*.yaml", "a/x/y.yaml", false},
		{"*", "", false}, {"*", ".", false}, {"a/*", "", false},
	} {
		if got := hitsPath(Exclusion{Path: tc.entry}, tc.p); got != tc.want {
			t.Errorf("%s vs %s: %v", tc.entry, tc.p, got)
		}
	}
	if !embedMatches("pkg/testdata", "pkg", "pkg/testdata/x/y.yaml") || !embedMatches("pkg/testdata/*", "pkg", "pkg/testdata/x/y.yaml") ||
		!embedMatches("pkg/*.yaml", "pkg", "pkg/a.yaml") || embedMatches("pkg/other", "pkg", "pkg/testdata/a.yaml") || embedMatches("pkg", "pkg", "pkg/a.yaml") {
		t.Fatal("embedMatches")
	}
}

// Install locations are refused for entries that are not declared copies.
func TestExclusionsRefuseInstallLocations(t *testing.T) {
	for entry, want := range map[string]string{
		"a/install":                              "",
		"deploy":                                 "",
		"deploy/examples/":                       "deploy",
		"install/":                               "install",
		"config/crd/":                            "config/crd",
		"config/crds/bases/x.yaml":               "config/crds",
		"cmd/cli/config/crds/":                   "config/crds",
		"api/src/test/resources/crds/":           "",
		"crd/":                                   "",
		"config/other/crd/":                      "",
		"manifests/":                             "manifests",
		"manifests/crds/x.yaml":                  "manifests",
		"test/e2e/manifests/":                    "",
		"charts/foo/tests/":                      "charts",
		"deploy/charts/x/templates":              "deploy",
		"a/Chart/b/":                             "chart",
		"x/helm/*.yaml":                          "",
		"vendor/sigs.k8s.io/mcs-api/config/crd/": "config/crd",
		"test/e2e/":                              "",
		"internal/xcrd/":                         "",
		"pkg/crds.go":                            "",
		"design/":                                "",
		"crds.yaml":                              "",
	} {
		if got := installSegment(entry); got != want {
			t.Errorf("%s: %q, want %q", entry, got, want)
		}
	}
	// Review of 2026-10-09 (MED-3): a pattern in the directory part
	// would match install locations the literal check does not see.
	for _, entry := range []string{"de*/examples/csi-operator.yaml", "*/examples/csi-operator.yaml", "deplo?/examples/x.yaml", "[d]eploy/x.yaml", "a/*/b/c.yaml"} {
		ej := fmt.Sprintf(`{"path":%q,"repo":"github.com/o/p","reason":"examples of the project","evidence":"read only by the go test files of test/e2e; nothing installs from it"}`, entry)
		if _, err := LoadTargets(testTargetsJSON(ej)); err == nil || !strings.Contains(err.Error(), "last path element") {
			t.Errorf("%s: %v", entry, err)
		}
	}
	for _, entry := range []string{"x/helm/*.yaml", "cmd/cli/data/crds/cli.kyverno.io_*", "test/fixture?.yaml"} {
		ej := fmt.Sprintf(`{"path":%q,"repo":"github.com/o/p","reason":"examples of the project","evidence":"read only by the go test files of test/e2e; nothing installs from it"}`, entry)
		if _, err := LoadTargets(testTargetsJSON(ej)); err != nil {
			t.Errorf("%s: %v", entry, err)
		}
	}
	mutate := testTargetsJSON
	good := `{"path":"test/e2e/","repo":"github.com/o/p","reason":"end to end test fixtures","evidence":"read only by the go test files of test/e2e; nothing installs from it"}`
	if _, err := LoadTargets(mutate(good)); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ ej, want string }{
		"install location": {`{"path":"deploy/examples/","repo":"github.com/o/p","reason":"examples of the project","evidence":"read only by the go test files of test/e2e; nothing installs from it"}`, "never excluded"},
		"chart location":   {`{"path":"charts/x/tests/","repo":"github.com/o/p","reason":"tests of the chart here","evidence":"read only by the go test files of test/e2e; nothing installs from it"}`, "never excluded"},
		"no evidence":      {`{"path":"test/e2e/","repo":"github.com/o/p","reason":"end to end test fixtures"}`, "evidence"},
		"short evidence":   {`{"path":"test/e2e/","repo":"github.com/o/p","reason":"end to end test fixtures","evidence":"tests"}`, "evidence"},
		"no repo":          {`{"path":"test/e2e/","reason":"end to end test fixtures","evidence":"read only by the go test files of test/e2e; nothing installs from it"}`, "names repository"},
		"other repo":       {`{"path":"test/e2e/","repo":"github.com/o/q","reason":"end to end test fixtures","evidence":"read only by the go test files of test/e2e; nothing installs from it"}`, "names repository"},
	} {
		if _, err := LoadTargets(mutate(tc.ej)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// A declared copy may lie under a chart: it is checked, not trusted.
	copies := `{"path":"charts/x/templates/","repo":"github.com/o/p","reason":"templates of the same definitions","evidence":"checked as copies of the listed definitions at every tag","copies":true}`
	if _, err := LoadTargets(mutate(copies)); err != nil {
		t.Fatal(err)
	}
}

// testTargetsJSON is a targets file of one target with one exclusion.
func testTargetsJSON(ej string) []byte {
	return []byte(fmt.Sprintf(`{"schema":%q,"targets":[{"project":"p","name":"P","repo":"github.com/o/p","component":"pkg:github/o/p","factProject":"p","tagPrefixes":["v"],"minFrom":"1.0","paths":[{"path":"crds/a.yaml"}],"exclude":[%s]}]}`, TargetsSchema, ej))
}

// An excluded path under a ko kodata directory is packed into the image:
// void. A symbolic link inside a kodata directory voids every entry.
func TestGuardKodata(t *testing.T) {
	entry := Exclusion{Path: "cmd/app/kodata/fixtures/", Repo: "github.com/argoproj/argo-cd", Reason: "fixtures of the unit tests of the app", Evidence: "only read by the Go tests of the package through os.ReadFile; no install path names them"}
	alpha, later := crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1")
	from := map[string]string{"deploy/crds/a.yaml": alpha, entry.Path + "crd.yaml": crd("Gamma", "v1")}
	to := map[string]string{"deploy/crds/a.yaml": later, entry.Path + "crd.yaml": crd("Gamma", "v1")}
	_, proof := pairOf(t, runSynth(t, synthTarget(entry), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})), "1.0.0", "1.1.0")
	if v := voidFindings(proof); len(v) != 1 || v[0].Path != "cmd/app/kodata" || !strings.Contains(v[0].Detail, "kodata") || proof.Completeness.Attestable {
		t.Fatalf("voids %+v completeness %+v", v, proof.Completeness)
	}
	from = map[string]string{"deploy/crds/a.yaml": alpha, fixtureDir + "crd.yaml": crd("Gamma", "v1"), "cmd/app/kodata/crds": "x"}
	to = map[string]string{"deploy/crds/a.yaml": later, fixtureDir + "crd.yaml": crd("Gamma", "v1"), "cmd/app/kodata/crds": "x"}
	s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
	ls := linkRepo{synthRepo: s, links: map[string]bool{"cmd/app/kodata/crds": true}}
	repo, err := extract.ParseRepo("github.com/argoproj/argo-cd")
	must(t, err)
	out, err := extract.Run(context.Background(), New(synthTarget(fixtureExclusion())), ls, ls, extract.Options{Repo: repo, DerivedAt: derivedAt})
	must(t, err)
	_, proof = pairOf(t, out, "1.0.0", "1.1.0")
	if v := voidFindings(proof); len(v) != 1 || v[0].Path != "cmd/app/kodata/crds" || !strings.Contains(v[0].Detail, "kodata") {
		t.Fatalf("voids %+v", v)
	}
}

func TestCopyMention(t *testing.T) {
	dir := Exclusion{Path: "cluster/meta/"}
	for _, tc := range []struct {
		at, text string
		bare     bool
		want     bool
	}{
		{"", "cluster/meta /crds", true, true},
		{"", "cluster /src", true, true},
		{"", "cluster/crds", true, false},
		{"", "clusters/meta", true, false},
		{"cluster", "meta", true, true},
		{"cluster", "meta", false, false},
		{"nix", "../cluster/meta", false, true},
		{"nix", "./cluster/meta", false, true},
		{"nix", "${self}/cluster", false, true},
		{"nix", "https://example.org/cluster/meta", false, true},
		{"nix", "https://example.org/cluster", false, true},
		{"nix", "https://example.org/clusters", false, false},
		{"", "/", true, false},
		{"", "./", true, false},
		{"build", "..", true, false},
	} {
		if _, got := copyMention(dir, tc.at, tc.bare, tc.text); got != tc.want {
			t.Errorf("%q in %q (bare %v): %v", tc.text, tc.at, tc.bare, got)
		}
	}
	lines, why := buildLines([]byte("FROM x\ncopy --from=build --chown=1:1 a b /dst/\nADD [\"c\", \"/d\"]\nCOPY . /src\nCOPY ./ /src\nSAVE ARTIFACT e AS LOCAL f\nSAVE ARTIFACT g\nCOPY /only\nRUN cp h i\n"))
	var got []string
	for _, l := range lines {
		got = append(got, l.Text)
	}
	if why != "" || !slices.Equal(got, []string{"a b", "c", "e", "g", "/only"}) {
		t.Fatalf("build lines %q %q", got, why)
	}
	if testOnlyTargets([]string{"verify-install"}) || testOnlyTargets([]string{"e2e-setup"}) || !testOnlyTargets([]string{"verify"}) || !testOnlyTargets([]string{"test-upgrade"}) {
		t.Fatal("install-like targets")
	}
}

// Every reviewed exclusion of the table names its repository and evidence,
// is none of the paths the project installs from, and the table as loaded
// has no entry under an install location unless it is a checked copy.
func TestReviewedTableRules(t *testing.T) {
	for _, tg := range Targets {
		for _, e := range tg.Exclude {
			if e.Repo != tg.Repo || len(e.Evidence) < 40 || len(e.Reason) < 12 {
				t.Errorf("%s %s: %+v", tg.Project, e.Path, e)
			}
			if seg := installSegment(e.Path); seg != "" && !e.Copies {
				t.Errorf("%s %s lies under %s", tg.Project, e.Path, seg)
			}
			for _, bad := range []string{"deploy/examples/", "vendor/sigs.k8s.io/mcs-api/"} {
				if exclusionMatches(e.Path, bad+"x.yaml") || strings.HasPrefix(bad, e.Path) {
					t.Errorf("%s %s covers %s", tg.Project, e.Path, bad)
				}
			}
		}
	}
}

// linkRepo marks some paths of a synthetic repository as symbolic links.
type linkRepo struct {
	synthRepo
	links map[string]bool
}

func (l linkRepo) List(r extract.RepoRef, c, d string) ([]extract.TreeEntry, error) {
	out, err := l.synthRepo.List(r, c, d)
	for i := range out {
		if l.links[out[i].Path] {
			out[i].Mode = "120000"
		}
	}
	return out, err
}

// A symbolic link in a chart or kustomization directory may lead into the
// excluded path and is not followed: the entry is void. Links elsewhere, and
// links inside the excluded path, do not matter.
func TestGuardSymbolicLinks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra map[string]string
		link  string
		by    string
	}{
		{name: "in a chart", extra: map[string]string{"charts/app/Chart.yaml": "name: app\n", "charts/app/crds/a.yaml": "x"}, link: "charts/app/crds/a.yaml", by: "charts/app/crds/a.yaml"},
		{name: "below a kustomization", extra: map[string]string{"deploy/kustomization.yaml": "resources:\n- a.yaml\n", "deploy/sub/b.yaml": "x"}, link: "deploy/sub/b.yaml", by: "deploy/sub/b.yaml"},
		{name: "elsewhere", extra: map[string]string{"docs/shared.adoc": "x"}, link: "docs/shared.adoc"},
		{name: "inside the excluded path", extra: map[string]string{"charts/app/Chart.yaml": "name: app\n", "test/fixtures/link.yaml": "x"}, link: "test/fixtures/link.yaml"},
		{name: "vendored", extra: map[string]string{"charts/app/Chart.yaml": "name: app\n", "vendor/x/link": "x"}, link: "vendor/x/link"},
		{name: "inside the excluded path below a kustomization", extra: map[string]string{"test/kustomization.yaml": "resources:\n- a.yaml\n", "test/fixtures/link.yaml": "x"}, link: "test/fixtures/link.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alpha, later := crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1")
			from := map[string]string{"deploy/crds/a.yaml": alpha, fixtureDir + "crd.yaml": crd("Gamma", "v1")}
			to := map[string]string{"deploy/crds/a.yaml": later, fixtureDir + "crd.yaml": crd("Gamma", "v1")}
			for p, c := range tc.extra {
				from[p], to[p] = c, c
			}
			s := newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})
			ls := linkRepo{synthRepo: s, links: map[string]bool{tc.link: true}}
			repo, err := extract.ParseRepo("github.com/argoproj/argo-cd")
			must(t, err)
			out, err := extract.Run(context.Background(), New(synthTarget(fixtureExclusion())), ls, ls, extract.Options{Repo: repo, DerivedAt: derivedAt})
			must(t, err)
			_, proof := pairOf(t, out, "1.0.0", "1.1.0")
			voids := voidFindings(proof)
			if tc.by == "" {
				if len(voids) != 0 || !proof.Completeness.Attestable {
					t.Fatalf("voids %+v completeness %+v", voids, proof.Completeness)
				}
				return
			}
			if len(voids) != 1 || voids[0].Path != tc.by || !strings.Contains(voids[0].Detail, "symbolic link") {
				t.Fatalf("voids %+v", voids)
			}
		})
	}
}

// A kustomization or chart inside one excluded path that is reached from the
// install surfaces is followed: it can lead into another excluded path.
func TestGuardFollowsThroughExcludedPaths(t *testing.T) {
	other := Exclusion{Path: "test/other/", Repo: "github.com/argoproj/argo-cd", Reason: "more fixtures of the unit tests", Evidence: "only read by the Go tests of the package through os.ReadFile; no install path names them"}
	run := func(extra map[string]string) []Finding {
		alpha, later := crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1")
		from := map[string]string{"deploy/crds/a.yaml": alpha, fixtureDir + "crd.yaml": crd("Gamma", "v1"), "test/other/crd.yaml": crd("Delta", "v1")}
		to := map[string]string{"deploy/crds/a.yaml": later, fixtureDir + "crd.yaml": crd("Gamma", "v1"), "test/other/crd.yaml": crd("Delta", "v1")}
		for p, c := range extra {
			from[p], to[p] = c, c
		}
		_, proof := pairOf(t, runSynth(t, synthTarget(fixtureExclusion(), other), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})), "1.0.0", "1.1.0")
		return voidFindings(proof)
	}
	// Reached through a directory name, then through a file name.
	for name, extra := range map[string]map[string]string{
		"directory": {"deploy/kustomization.yaml": "resources:\n- ../test/other\n", "test/other/kustomization.yaml": "resources:\n- ../fixtures/crd.yaml\n"},
		"file":      {"deploy/kustomization.yaml": "resources:\n- ../test/other/kustomization.yaml\n", "test/other/kustomization.yaml": "resources:\n- ../fixtures/crd.yaml\n"},
		"chart":     {"charts/app/Chart.yaml": "dependencies:\n- repository: file://../../test/other/chart\n", "test/other/chart/Chart.yaml": "dependencies:\n- repository: file://../../fixtures\n"},
	} {
		by := map[string]string{}
		for _, f := range run(extra) {
			by[f.Location] = f.Path
		}
		if len(by) != 2 || by["test/fixtures/"] != "test/other/kustomization.yaml" && by["test/fixtures/"] != "test/other/chart/Chart.yaml" || !strings.HasPrefix(by["test/other/"], "deploy/") && !strings.HasPrefix(by["test/other/"], "charts/") {
			t.Errorf("%s: %v", name, by)
		}
	}
	// Nothing reaches the kustomization inside the excluded path: no void.
	if v := run(map[string]string{"test/other/kustomization.yaml": "resources:\n- ../fixtures/crd.yaml\n"}); len(v) != 0 {
		t.Errorf("unreached: %+v", v)
	}
}

// An exclusion that is itself a chart directory lies under that chart; a
// submodule under an excluded path makes the entry present.
func TestGuardChartAndSubmodule(t *testing.T) {
	entry := Exclusion{Path: "charts/app/", Repo: "github.com/argoproj/argo-cd", Reason: "the application chart of the tests", Evidence: "only read by the Go tests of the package through os.ReadFile; no install path names it"}
	alpha, later := crd("Alpha", "v1beta1", "v1"), crd("Alpha", "v1")
	files := func(a string) map[string]string {
		return map[string]string{"deploy/crds/a.yaml": a, "charts/app/Chart.yaml": "name: app\n", "charts/app/crds/x.yaml": crd("Gamma", "v1")}
	}
	_, proof := pairOf(t, runSynth(t, synthTarget(entry), newSynth(release{"v1.0.0", files(alpha)}, release{"v1.1.0", files(later)})), "1.0.0", "1.1.0")
	if v := voidFindings(proof); len(v) != 1 || v[0].Path != "charts/app/Chart.yaml" || proof.Completeness.Attestable {
		t.Fatalf("voids %+v", v)
	}
	// A submodule under the entry, a Makefile that installs from it.
	sub := func(a string) map[string]string {
		return map[string]string{"deploy/crds/a.yaml": a, "test/fixtures/sub": "x", "Makefile": "install:\n\tkubectl apply -f test/fixtures/sub\n"}
	}
	s := newSynth(release{"v1.0.0", sub(alpha)}, release{"v1.1.0", sub(later)})
	ls := submodules{synthRepo: s, paths: map[string]bool{"test/fixtures/sub": true}}
	repo, err := extract.ParseRepo("github.com/argoproj/argo-cd")
	must(t, err)
	out, err := extract.Run(context.Background(), New(synthTarget(fixtureExclusion())), ls, ls, extract.Options{Repo: repo, DerivedAt: derivedAt})
	must(t, err)
	_, proof = pairOf(t, out, "1.0.0", "1.1.0")
	if v := voidFindings(proof); len(v) != 1 || v[0].Path != "Makefile" {
		t.Fatalf("voids %+v", v)
	}
}

// submodules marks paths of a synthetic repository as submodule entries.
type submodules struct {
	synthRepo
	paths map[string]bool
}

func (l submodules) List(r extract.RepoRef, c, d string) ([]extract.TreeEntry, error) {
	out, err := l.synthRepo.List(r, c, d)
	for i := range out {
		if l.paths[out[i].Path] {
			out[i].Type, out[i].Mode = "commit", "160000"
		}
	}
	return out, err
}

// A line must apply, render or build manifests to count: prose that names a
// tool and a path does not.
func TestCommandLines(t *testing.T) {
	for in, want := range map[string]bool{
		"kubectl apply -f x":                                    true,
		"kubectl get -f x":                                      true,
		"kubectl -k dir":                                        true,
		"helm template ./chart":                                 true,
		"helm show values ./chart --values v.yaml":              true,
		"$(KUSTOMIZE) build $(DIR) | $(KUBECTL) apply -f -":     true,
		"argocd app create guestbook --path test/fixtures":      true,
		"cilium install --chart-directory ./x":                  true,
		"The design is inspired from the kubectl patch command": false,
		"Install helm and read the docs in test/fixtures":       false,
		"kubectl get pods":                                      false,
		"velero is a tool":                                      false,
		"velero install --provider aws":                         true,
		"apply the fixtures in test/fixtures":                   false,
		"veleroinstall --x":                                     false, "velero\tinstall --x": true,
		"kubectl-style flags": false,
	} {
		if isCommand(in) != want {
			t.Errorf("%q: %v", in, !want)
		}
	}
	text := "The design is inspired from [kubectl patch command](https://github.com/o/r/tree/main/test/fixtures) and the docs say how to helm"
	_, proof := guardPair(t, map[string]string{"docs/prose.md": text + "\n"}, fixtureExclusion())
	if len(voidFindings(proof)) != 0 || !proof.Completeness.Attestable {
		t.Fatalf("prose voids the entry: %+v", voidFindings(proof))
	}
}

// An unread file under a reviewed exclusion that lies in a default-excluded
// directory (test fixtures) does not keep a removed definition from being
// established, as in a default-excluded directory without an entry; the same
// file under a void entry, or under an entry elsewhere, does.
func TestReviewedFixturesAreDefaultLikeForRemovedDefinitions(t *testing.T) {
	templated := "{{ if x }}\nkind: CustomResourceDefinition\n"
	run := func(entryPath string, extra map[string]string) (extract.PairRecord, PairProof) {
		entry := Exclusion{Path: entryPath, Repo: "github.com/argoproj/argo-cd", Reason: "fixtures of the unit tests of the project", Evidence: "only read by the Go tests of the package through os.ReadFile; no install path names them"}
		from := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), "deploy/crds/b.yaml": crd("Beta", "v1"), entryPath + "x.yaml": templated}
		to := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), entryPath + "x.yaml": templated}
		for k, v := range extra {
			from[k], to[k] = v, v
		}
		return pairOf(t, runSynth(t, synthTarget(entry), newSynth(release{"v1.0.0", from}, release{"v1.1.0", to})), "1.0.0", "1.1.0")
	}
	// In a default-excluded directory: established, a removed definition.
	p, proof := run("test/gen/", nil)
	if p.Status != extract.PairDerived || len(proof.DefinitionsRemoved) != 1 {
		t.Fatalf("test fixtures: %s %q %+v", p.Status, p.Reason, proof.DefinitionsRemoved)
	}
	var recorded bool
	for _, f := range proof.To.Scan.Findings {
		recorded = recorded || (f.Class == ClassExcludedUnread && f.Location == "test/gen/")
	}
	if !recorded {
		t.Fatalf("findings %+v", proof.To.Scan.Findings)
	}
	// Void: the files may be installed.
	if p, _ := run("test/gen/", map[string]string{"Makefile": "install:\n\tkubectl apply -f test/gen\n"}); p.Status != extract.PairWithheld {
		t.Fatalf("void fixtures: %s %q", p.Status, p.Reason)
	}
	// Elsewhere: still opaque.
	if p, _ := run("tools/gen/", nil); p.Status != extract.PairWithheld {
		t.Fatalf("other directory: %s %q", p.Status, p.Reason)
	}
}
