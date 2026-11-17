// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The pinned files, copied from upstream per tag (see each PROVENANCE.txt).
var metadataFixturesByTag = map[string]map[string]string{
	"v1.16.0": {
		"crd-certificaterequests.yaml": "bae51a8380d6944a665f0394f953bf94290d093edd9d21cc86f2f488524545e6",
		"crd-certificates.yaml":        "b419c7a07f7ea95044beede49fcc0c33dc8c1f81b97f888c890d34c293012112",
		"crd-orders.yaml":              "b48f8389d98acca81f28a0b46d89ade07e9742b4e967f45057dc6b2aa2a64c32",
	},
	"v1.17.0": {
		"crd-certificaterequests.yaml": "bae51a8380d6944a665f0394f953bf94290d093edd9d21cc86f2f488524545e6",
		"crd-certificates.yaml":        "d4791e087fa951de9bf0a0eb573dba32314a3a6c4021d74388024332abf7e73e",
		"crd-orders.yaml":              "b48f8389d98acca81f28a0b46d89ade07e9742b4e967f45057dc6b2aa2a64c32",
	},
	"v1.18.0": {
		"crd-certificaterequests.yaml": "bae51a8380d6944a665f0394f953bf94290d093edd9d21cc86f2f488524545e6",
		"crd-certificates.yaml":        "25f58d784b3e7f9520dcb101db8d86f93294d2c91fc37616b378516f9a94cf28",
		"crd-orders.yaml":              "f10e292dd9efe0ffa2549edf4e368857308ffeda1a8c2e196c405b11ba405bcc",
	},
}

var metadataFixtures = metadataFixturesByTag["v1.18.0"]

func readTagFixture(t *testing.T, tag, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "certmanager-"+tag, name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != metadataFixturesByTag[tag][name] {
		t.Fatalf("%s %s digest %s differs from the pinned %s", tag, name, got, metadataFixturesByTag[tag][name])
	}
	return string(b)
}

func readMetadataFixture(t *testing.T, name string) string {
	t.Helper()
	return readTagFixture(t, "v1.18.0", name)
}

// Every pinned tag: the rule reads each file, records it, and the served
// and storage flags it derives are the ones the file declares (decoded here
// by a plain YAML parse, which ignores comments).
func TestMetadataTemplateFilesAreReadAndRecorded(t *testing.T) {
	for tag, files := range metadataFixturesByTag {
		for name := range files {
			text := readTagFixture(t, tag, name)
			if !strings.Contains(text, "{{") {
				t.Fatalf("%s %s: fixture has no marker", tag, name)
			}
			rec, crds, err := parseFile("deploy/crds/"+name, []byte(text))
			if err != nil {
				t.Fatalf("%s %s: refused: %v", tag, name, err)
			}
			if rec.TemplateRead != templateReadMetadata {
				t.Fatalf("%s %s: read under the rule but not recorded: %q", tag, name, rec.TemplateRead)
			}
			var decl struct {
				Spec struct {
					Versions []struct {
						Name    string `yaml:"name"`
						Served  bool   `yaml:"served"`
						Storage bool   `yaml:"storage"`
					} `yaml:"versions"`
				} `yaml:"spec"`
			}
			if err := yaml.Unmarshal([]byte(text), &decl); err != nil {
				t.Fatalf("%s %s: %v", tag, name, err)
			}
			if len(decl.Spec.Versions) == 0 || len(crds) != 1 || len(crds[0].Versions) != len(decl.Spec.Versions) {
				t.Fatalf("%s %s: read %+v, declared %+v", tag, name, crds, decl.Spec.Versions)
			}
			for i, d := range decl.Spec.Versions {
				got := crds[0].Versions[i]
				if got.Name != d.Name || got.Served != d.Served || got.Storage != d.Storage {
					t.Fatalf("%s %s: version %d derived %+v, declared %+v", tag, name, i, got, d)
				}
			}
		}
	}
	// A file without markers is never recorded.
	rec, _, err := parseFile("deploy/crds/a.yaml", []byte(crdText("", "", "type: object")))
	if err != nil || rec.TemplateRead != "" {
		t.Fatalf("plain file: %v %q", err, rec.TemplateRead)
	}
}

func TestMetadataTemplateRefusals(t *testing.T) {
	base := readMetadataFixture(t, "crd-orders.yaml")
	mutate := func(old, repl string) string {
		if strings.Count(base, old) < 1 {
			t.Fatalf("base lacks %q", old)
		}
		return strings.Replace(base, old, repl, 1)
	}
	cases := map[string]string{
		"marker in version name":         mutate("    - name: v1\n", "    - name: '{{ .v }}'\n"),
		"marker in schema":               mutate("                  format: date-time\n", "                  format: date-time\n                  default: '{{ .d }}'\n"),
		"marker in a key":                mutate("    app.kubernetes.io/component: \"crds\"\n", "    app.kubernetes.io/component: \"crds\"\n    '{{ .k }}': x\n"),
		"unquoted label value":           mutate("    app: '{{ template \"cert-manager.name\" . }}'\n", "    app: {{ .x }}\n"),
		"unquoted plain label value":     mutate("    app: '{{ template \"cert-manager.name\" . }}'\n", "    app: a{{ .x }}\n"),
		"marker in metadata.name":        mutate("  name: orders.acme.cert-manager.io\n", "  name: '{{ .n }}.acme.cert-manager.io'\n"),
		"marker in group":                mutate("  group: acme.cert-manager.io\n", "  group: \"{{ .g }}\"\n"),
		"block scalar under spec":        mutate("  scope: Namespaced\n", "  scope: Namespaced\n  x-note: |\n    a {{ .x }}\n"),
		"comment-looking block scalar":   mutate("  scope: Namespaced\n", "  scope: Namespaced\n  x-note: |\n    # {{ .x }}\n"),
		"closing marker in block scalar": mutate("  scope: Namespaced\n", "  scope: Namespaced\n  x-note: |\n    # }}\n"),
		"closing marker in spec":         mutate("  scope: Namespaced\n", "  scope: Namespaced\n  x-note: \"a }}\"\n"),
		"two documents":                  base + "---\n" + base,
		"comment then templated spec":    mutate("  scope: Namespaced\n", "  # {{- if .x }}\n  scope: {{ .scope }}\n"),
		"comment marker within spec":     mutate("  scope: Namespaced\n", "  # {{ .x }}\n  scope: Namespaced\n"),
		"trailing comment marker":        mutate("  scope: Namespaced\n", "  scope: Namespaced # {{ .x }}\n"),
		"escaped marker in label":        mutate("    app.kubernetes.io/component: \"crds\"\n", "    app.kubernetes.io/component: \"\\x7b{ x \\x7d}\"\n"),
		"escape and trailing comment":    mutate("    app.kubernetes.io/component: \"crds\"\n", "    app.kubernetes.io/component: \"\\x7b{\" # {{\n"),
		"marker in a description":        mutate("                  format: date-time\n", "                  format: date-time\n                  description: \"{{ .d }}\"\n"),
		"not a CRD":                      strings.Replace(base, "kind: CustomResourceDefinition", "kind: ConfigMap", 1),
		"marker in apiVersion":           mutate("apiVersion: apiextensions.k8s.io/v1\n", "apiVersion: apiextensions.k8s.io/v1 # x\n#{{\napiVersion2: '{{'\n"),
		"label value is a block scalar":  mutate("    app: '{{ template \"cert-manager.name\" . }}'\n", "    app: |\n      {{ .x }}\n"),
	}
	// Trim and tilde markers in a comment, at top level and in metadata.
	for _, m := range []string{"# x {{ .a -}}", "# x {{ .a ~}}", "# x {{~ .a }}"} {
		cases["top-level comment "+m] = mutate("apiVersion: apiextensions.k8s.io/v1\n", m+"\napiVersion: apiextensions.k8s.io/v1\n")
		cases["metadata comment "+m] = mutate("  # START annotations", "  "+m+"\n  # START annotations")
	}
	for name, text := range cases {
		_, crds, err := parseFile("deploy/crds/a.yaml", []byte(text))
		pr, isProblem := asProblem(err)
		if err == nil || !isProblem || !strings.Contains(pr.msg, "contains template syntax") || len(crds) != 0 {
			t.Errorf("%s: not refused with the template reason (err %v)", name, err)
		}
	}
}

// A marker under spec stays refused even when every label marker is fine.
func TestMetadataTemplateRuleIsNotWiderThanDescriptions(t *testing.T) {
	text := crdText("  labels:\n    app: '{{ .x }}'\n", "", "type: object\ndescription: \"{{ .a }}\"")
	// Label markers plus a description marker: neither rule admits both.
	if _, _, err := parseFile("a.yaml", []byte(text)); err == nil {
		t.Fatal("label marker with a description marker was read")
	}
	// Label markers alone, with the synthetic spec, are read.
	ok := crdText("  labels:\n    app: '{{ .x }}'\n", "", "type: object")
	rec, _, err := parseFile("a.yaml", []byte(ok))
	if err != nil || rec.TemplateRead == "" {
		t.Fatalf("labels only: %v %q", err, rec.TemplateRead)
	}
}
