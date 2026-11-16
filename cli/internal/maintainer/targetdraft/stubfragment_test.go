// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"strings"
	"testing"
)

const (
	stubPath = "config/crd/patches/cainjection_in_imagelists.yaml"
	stubID   = "imagelists.eraser.example.test"
)

// stubFull is a full definition of identity stubID.
func stubFull(strategy string) string {
	conv := ""
	if strategy != "" {
		conv = "  conversion:\n    strategy: " + strategy + "\n"
	}
	return "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: " + stubID +
		"\nspec:\n  group: eraser.example.test\n  names:\n    kind: ImageList\n    plural: imagelists\n  scope: Cluster\n" + conv +
		"  versions:\n  - name: v1\n    served: true\n    storage: true\n    schema:\n      openAPIV3Schema:\n        type: object\n"
}

func stubTree(files map[string]string) *memTree {
	m := newMemTree()
	m.files["config/crd/kustomization.yaml"] = []byte(fragKustomizationText)
	m.files["config/crd/bases/a.yaml"] = []byte(stubFull("Webhook"))
	for p, c := range files {
		m.files[p] = []byte(c)
	}
	return m
}

// stubClass reads one path with the option off, with only the fragment
// option, and with both options.
func stubClass(m *memTree, p string, skip, tol bool) string {
	fs, _, frags := scanTreeStubs(m, skip, tol)
	for _, f := range frags {
		if f == p {
			return "fragment"
		}
	}
	for _, f := range fs {
		if f.Path == p {
			if f.Unreadable != "" {
				return "unreadable"
			}
			return "definition"
		}
	}
	return "none"
}

const stubHead = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  creationTimestamp: null\n  name: " + stubID + "\n"

// wantStub: the option off and fragments-only keep the stub unreadable; both
// options give want.
func wantStub(t *testing.T, m *memTree, p, want string) {
	t.Helper()
	for _, c := range []struct {
		skip, tol bool
		want      string
	}{{false, false, "unreadable"}, {true, false, "unreadable"}, {true, true, want}} {
		if want == "none" {
			break
		}
		if got := stubClass(m, p, c.skip, c.tol); got != c.want {
			t.Fatalf("%s skip=%v tolerate=%v: got %s want %s", p, c.skip, c.tol, got, c.want)
		}
	}
	if got := stubClass(m, p, true, true); got != want {
		t.Fatalf("%s: got %s want %s", p, got, want)
	}
}

func TestStubPositives(t *testing.T) {
	for name, content := range map[string]string{
		"creationTimestamp and status null": stubHead + "status: null\n",
		"status with null fields":           stubHead + "status:\n  acceptedNames:\n    kind: null\n  conditions: null\n",
		"var annotation with timestamp":     stubHead + "  annotations:\n    cert-manager.io/inject-ca-from: $(CERTIFICATE_NAMESPACE)/$(CERTIFICATE_NAME)\n",
		"v1alpha1 stub":                     strings.Replace(stubHead, "apiextensions.k8s.io/v1", "apiextensions.k8s.io/v1alpha1", 1),
		"v1beta1 stub":                      strings.Replace(stubHead, "apiextensions.k8s.io/v1", "apiextensions.k8s.io/v1beta1", 1),
		"conversion service with vars":      stubHead + "spec:\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        service:\n          namespace: $(SERVICE_NAMESPACE)\n          name: $(SERVICE_NAME)\n          path: /convert\n          port: 443\nstatus: null\n",
		"labels only":                       stubHead + "  labels:\n    a: b\nstatus:\n",
	} {
		t.Run(name, func(t *testing.T) {
			m := stubTree(map[string]string{stubPath: content})
			wantStub(t, m, stubPath, "fragment")
		})
	}
	// A stub document next to a #574 fragment document in one file.
	m := stubTree(map[string]string{stubPath: stubHead + "status: null\n---\n" + fragCA})
	wantStub(t, m, stubPath, "fragment")
}

func TestStubNegatives(t *testing.T) {
	cases := map[string]string{
		"adds a version":       stubHead + "spec:\n  versions:\n  - name: v2\n",
		"adds a schema":        stubHead + "spec:\n  versions:\n  - name: v1\n    schema:\n      openAPIV3Schema:\n        type: object\n",
		"adds validation":      stubHead + "spec:\n  validation:\n    openAPIV3Schema:\n      type: object\n",
		"changes names":        stubHead + "spec:\n  names:\n    kind: Other\n",
		"changes scope":        stubHead + "spec:\n  scope: Namespaced\n",
		"changes group":        stubHead + "spec:\n  group: other.example.test\n",
		"unknown spec field":   stubHead + "spec:\n  preserveUnknownFieldz: true\n",
		"unknown top key":      stubHead + "extra: 1\n",
		"unknown metadata key": stubHead + "  generateName: x\n",
		"other strategy":       stubHead + "spec:\n  conversion:\n    strategy: None\n",
		"bad strategy":         stubHead + "spec:\n  conversion:\n    strategy: Other\n",
		"unknown conversion":   stubHead + "spec:\n  conversion:\n    webhook:\n      conversionReviewVersions: [v1]\n",
		"url in clientConfig":  stubHead + "spec:\n  conversion:\n    webhook:\n      clientConfig:\n        url: https://x\n",
		"unknown service key":  stubHead + "spec:\n  conversion:\n    webhook:\n      clientConfig:\n        service:\n          x: y\n",
		"null service value":   stubHead + "spec:\n  conversion:\n    webhook:\n      clientConfig:\n        service:\n          name: null\n",
		"timestamp not null":   strings.Replace(stubHead, "creationTimestamp: null", "creationTimestamp: \"2020-01-01T00:00:00Z\"", 1),
		"status with a value":  stubHead + "status:\n  x: 1\n",
		"status list":          stubHead + "status:\n  conditions: []\n",
		"spec scalar":          stubHead + "spec: 3\n",
		"not a CRD kind":       strings.Replace(stubHead, "CustomResourceDefinition", "ConfigMap", 1) + "status: null\n# CustomResourceDefinition\n",
		"name without a dot":   strings.Replace(stubHead, stubID, "imagelists", 1),
		"name is a variable":   strings.Replace(stubHead, stubID, "$(NAME)", 1),
		"unknown identity":     strings.Replace(stubHead, stubID, "other.eraser.example.test", 1),
		"other apiVersion":     strings.Replace(stubHead, "apiextensions.k8s.io/v1", "apiextensions.k8s.io/v2", 1),
		"template syntax":      stubHead + "status: null\n# {{ x }}\n",
		"json patch list":      "- op: add\n  path: /metadata/annotations\n  value: {a: b}\n# CustomResourceDefinition\n",
		"alias":                stubHead + "status: &a null\n",
		"garbled":              "apiVersion: [\nkind: CustomResourceDefinition\n",
		"empty":                "",
		"only comment":         "# CustomResourceDefinition\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			m := stubTree(map[string]string{stubPath: content})
			if got := stubClass(m, stubPath, true, true); got == "fragment" {
				t.Fatalf("set aside:\n%s", content)
			}
			if got := stubClass(m, stubPath, true, true); got != stubClass(m, stubPath, true, false) {
				t.Fatalf("the option changed the verdict: %s", got)
			}
		})
	}
	// "not a CRD kind" and kind-less files may read as none or unreadable; the
	// stub-shaped ConfigMap must never be a fragment, proven above.
}

func TestStubKindNotCRDWithStubShape(t *testing.T) {
	m := stubTree(map[string]string{stubPath: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  creationTimestamp: null\n  name: " + stubID + "\n"})
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("a ConfigMap is not a stub")
	}
}

func TestStubIdentityNeedsExactlyOneFullDefinition(t *testing.T) {
	stub := stubHead + "status: null\n"
	// No full definition at all.
	m := stubTree(map[string]string{stubPath: stub})
	delete(m.files, "config/crd/bases/a.yaml")
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("no definition: set aside")
	}
	// Two full definitions (an equal copy elsewhere counts too).
	m = stubTree(map[string]string{stubPath: stub, "charts/x/crds/a.yaml": stubFull("Webhook")})
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("two definitions: set aside")
	}
	// A copy under a refused path counts as well (fail closed).
	m = stubTree(map[string]string{stubPath: stub, "docs/crds/a.yaml": stubFull("Webhook")})
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("docs copy: set aside")
	}
	// The only definition is partial: no schema, no scope.
	m = stubTree(map[string]string{stubPath: stub})
	m.files["config/crd/bases/a.yaml"] = []byte(strings.Replace(stubFull("Webhook"), "    schema:\n      openAPIV3Schema:\n        type: object\n", "", 1))
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("schema-less definition: set aside")
	}
	m.files["config/crd/bases/a.yaml"] = []byte(strings.Replace(stubFull("Webhook"), "  scope: Cluster\n", "", 1))
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("scope-less definition: set aside")
	}
	// A definition whose metadata.name disagrees with its spec identity.
	m.files["config/crd/bases/a.yaml"] = []byte(strings.Replace(stubFull("Webhook"), "name: "+stubID, "name: other.example.test", 1))
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("inconsistent definition: set aside")
	}
	// A hidden definition in an undecodable file blocks every stub.
	m = stubTree(map[string]string{stubPath: stub, "deploy/x.yaml": "kind: CustomResourceDefinition\nspec: [\n"})
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("undecodable definition file: set aside")
	}
	m = stubTree(map[string]string{stubPath: stub, "deploy/x.yaml": "kind: CustomResourceDefinition\n{{ .Values.x }}\n"})
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("template definition file: set aside")
	}
	// A second definition inside a List document counts.
	m = stubTree(map[string]string{stubPath: stub, "deploy/l.yaml": "apiVersion: v1\nkind: List\nitems:\n- " + strings.ReplaceAll(strings.TrimSuffix(stubFull("Webhook"), "\n"), "\n", "\n  ") + "\n"})
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("definition in a list: set aside")
	}
}

func TestStubStrategyMustEqualAnExplicitOne(t *testing.T) {
	stub := stubHead + "spec:\n  conversion:\n    strategy: Webhook\n"
	m := stubTree(map[string]string{stubPath: stub})
	wantStub(t, m, stubPath, "fragment")
	m.files["config/crd/bases/a.yaml"] = []byte(stubFull("None"))
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("strategy differs: set aside")
	}
	m.files["config/crd/bases/a.yaml"] = []byte(stubFull(""))
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("full definition without a strategy: set aside")
	}
}

func TestStubPathsTheGeneratorRefuses(t *testing.T) {
	stub := stubHead + "status: null\n"
	for _, p := range []string{
		".github/kustomize/patches/a.yaml",
		"config/crd/testdata/a.yaml",
		"config/crd/docs/a.yaml",
		"config/crd/fixtures/a.yaml",
		"config/crd/vendor/a.yaml",
	} {
		m := stubTree(map[string]string{p: stub})
		if got := stubClass(m, p, true, true); got == "fragment" {
			t.Fatalf("%s: set aside", p)
		}
	}
	// Outside any kustomization directory and at the repository root.
	m := stubTree(map[string]string{"other/a.yaml": stub, "root.yaml": stub})
	for _, p := range []string{"other/a.yaml", "root.yaml"} {
		if got := stubClass(m, p, true, true); got == "fragment" {
			t.Fatalf("%s: set aside", p)
		}
	}
	// A stub reached through a symbolic link stays what the link rules say.
	m = stubTree(map[string]string{stubPath: stub})
	m.links["config/crd/patches/link.yaml"] = "cainjection_in_imagelists.yaml"
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("linked stub: set aside")
	}
}

func TestStubMixedFileKeepsFullDefinitionCounting(t *testing.T) {
	stub := stubHead + "status: null\n"
	// The only full definition lives in a file that also holds a stub. The
	// mixed file is not set aside (it holds a definition) and the other stub
	// file is, because the identity has exactly one full definition.
	mixed := stubFull("Webhook") + "---\n" + stub
	m := stubTree(map[string]string{stubPath: stub, "config/crd/patches/mixed.yaml": mixed})
	delete(m.files, "config/crd/bases/a.yaml")
	if got := stubClass(m, "config/crd/patches/mixed.yaml", true, true); got == "fragment" {
		t.Fatal("a file with a full definition must not be set aside")
	}
	if got := stubClass(m, stubPath, true, true); got != "fragment" {
		t.Fatalf("the full definition in the mixed file must count once: %s", got)
	}
	// With a second copy the count is two and the stub stays.
	m.files["config/crd/bases/a.yaml"] = []byte(stubFull("Webhook"))
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("two definitions: set aside")
	}
}

func TestStubOptionNeedsFragmentOption(t *testing.T) {
	in := inferSkip(infSource(infControl(), nil))
	in.SkipPatchFragments = false
	in.TolerateStubs = true
	infStops(t, in, StopBadInput)
}

func stubSource(withStub bool) memSource {
	src := memSource{trees: map[string]*memTree{}}
	for _, tag := range ipTags {
		m := newMemTree()
		m.files["config/crd/bases/a.yaml"] = []byte(stubFull("Webhook"))
		m.files["README.md"] = []byte("x")
		if withStub {
			m.files[fragKustomization] = []byte(fragKustomizationText)
			m.files[stubPath] = []byte(stubHead + "status: null\n")
		}
		src.trees[tag] = m
	}
	return src
}

func TestStubEndToEnd(t *testing.T) {
	// Off, and with only the fragment option: the stop of today.
	infStops(t, infInput(stubSource(true)), StopInstallPathAmbiguous)
	infStops(t, inferSkip(stubSource(true)), StopInstallPathAmbiguous)
	// With both: the draft equals the one without the stub; the stub is listed.
	in := inferSkip(stubSource(true))
	in.TolerateStubs = true
	with := mustGenerate(t, in)
	plain := mustGenerate(t, infInput(stubSource(false)))
	if !bytes.Equal(with.A, plain.A) || !bytes.Equal(with.B, plain.B) || !bytes.Equal(with.TableRow, plain.TableRow) {
		t.Fatal("a stub must not change the target")
	}
	if len(with.Report.PatchFragments) != len(ipTags) || with.Report.FactsDigest == plain.Report.FactsDigest {
		t.Fatalf("the set-aside stub must be listed and covered by the digest: %+v", with.Report.PatchFragments)
	}
	for _, pf := range with.Report.PatchFragments {
		if strings.Join(pf.Paths, ",") != stubPath {
			t.Fatalf("paths: %+v", pf)
		}
	}
	// A second full definition keeps the typed stop even with both options.
	src := stubSource(true)
	for _, m := range src.trees {
		m.files["charts/x/crds/a.yaml"] = []byte(stubFull("Webhook"))
	}
	in = inferSkip(src)
	in.TolerateStubs = true
	if _, err := Generate(in); err == nil {
		t.Fatal("two definitions must stop")
	}
	// A bad stub at one tag only stops the run.
	src = stubSource(true)
	src.trees[ipTags[1]].files[stubPath] = []byte(stubHead + "spec:\n  scope: Namespaced\n")
	in = inferSkip(src)
	in.TolerateStubs = true
	infStops(t, in, StopInstallPathAmbiguous)
}

func TestStubNullsThatDeleteAreRefused(t *testing.T) {
	for name, content := range map[string]string{
		"spec null":                  stubHead + "spec: null\n",
		"spec empty value":           stubHead + "spec:\n",
		"spec versions null":         stubHead + "spec:\n  versions: null\n",
		"spec conversion null":       stubHead + "spec:\n  conversion: null\n",
		"conversion webhook null":    stubHead + "spec:\n  conversion:\n    webhook: null\n",
		"conversion strategy null":   stubHead + "spec:\n  conversion:\n    strategy: null\n",
		"label patch directive":      stubHead + "  labels:\n    $patch: delete\n",
		"annotation patch directive": stubHead + "  annotations:\n    $patch: replace\n",
		"metadata labels null":       stubHead + "  labels: null\n",
	} {
		m := stubTree(map[string]string{stubPath: content})
		if got := stubClass(m, stubPath, true, true); got == "fragment" {
			t.Fatalf("%s: set aside", name)
		}
	}
	// status: null stays tolerated, also next to a spec conversion.
	m := stubTree(map[string]string{stubPath: stubHead + "status: null\n"})
	wantStub(t, m, stubPath, "fragment")
	// conversion: null against a full definition without any conversion.
	m = stubTree(map[string]string{stubPath: stubHead + "spec:\n  conversion: null\n"})
	m.files["config/crd/bases/a.yaml"] = []byte(stubFull(""))
	if got := stubClass(m, stubPath, true, true); got == "fragment" {
		t.Fatal("null conversion: set aside")
	}
}

func TestStubSecondDefinitionCannotHideBehindSyntax(t *testing.T) {
	stub := stubHead + "status: null\n"
	full := stubFull("Webhook")
	for name, dup := range map[string]string{
		"escaped kind":  strings.Replace(full, "kind: CustomResourceDefinition", `kind: "CustomResource\u0044efinition"`, 1),
		"double quoted": strings.Replace(full, "kind: CustomResourceDefinition", `kind: "CustomResourceDefinition"`, 1),
		"single quoted": strings.Replace(full, "kind: CustomResourceDefinition", `kind: 'CustomResourceDefinition'`, 1),
		"escaped key":   strings.Replace(full, "kind: CustomResourceDefinition", `"kind": CustomResourceDefinition`, 1),
		"tagged":        strings.Replace(full, "kind: CustomResourceDefinition", `kind: !!str CustomResourceDefinition`, 1),
		"flow style":    "{apiVersion: apiextensions.k8s.io/v1, \"kind\": \"CustomResource\\u0044efinition\", metadata: {name: " + stubID + "}, spec: {group: eraser.example.test, names: {kind: ImageList, plural: imagelists}, scope: Cluster, versions: [{name: v1, served: true, storage: true, schema: {openAPIV3Schema: {type: object}}}]}}\n",
		"json":          `{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"` + stubID + `"},"spec":{"group":"eraser.example.test","names":{"kind":"ImageList","plural":"imagelists"},"scope":"Cluster","versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object"}}}]}}`,
	} {
		for _, p := range []string{"deploy/dup.yaml", "deploy/dup.json"} {
			m := stubTree(map[string]string{stubPath: stub, p: dup})
			if got := stubClass(m, stubPath, true, true); got == "fragment" {
				t.Fatalf("%s in %s: second definition evaded the count", name, p)
			}
		}
	}
	// Control: an unrelated decodable file does not block.
	m := stubTree(map[string]string{stubPath: stub, "deploy/cm.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n"})
	wantStub(t, m, stubPath, "fragment")
}

func TestStubListNestingLimitBlocks(t *testing.T) {
	stub := stubHead + "status: null\n"
	base := `{"kind":"CustomResourceDefinition","metadata":{"name":"` + stubID + `"},"spec":{"group":"eraser.example.test","names":{"kind":"ImageList","plural":"imagelists"},"scope":"Cluster","versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object"}}}]}}`
	nest := func(levels int) string {
		doc := base
		for i := 0; i < levels; i++ {
			doc = `{"kind":"List","items":[` + doc + `]}`
		}
		return doc
	}
	// The only definition sits inside lists. Down to depth 3 it is counted
	// (exactly one: the stub is set aside); deeper the bound is exhausted and
	// every stub stays a stop (fail closed).
	for lv, want := range map[int]string{1: "fragment", 2: "fragment", 3: "fragment", 4: "unreadable", 5: "unreadable"} {
		m := stubTree(map[string]string{stubPath: stub, "deploy/l.json": nest(lv)})
		delete(m.files, "config/crd/bases/a.yaml")
		if got := stubClass(m, stubPath, true, true); got != want {
			t.Fatalf("nesting %d: got %s want %s", lv, got, want)
		}
		// With a second definition at the bottom the stub never passes.
		m.files["config/crd/bases/a.yaml"] = []byte(stubFull("Webhook"))
		if got := stubClass(m, stubPath, true, true); got == "fragment" {
			t.Fatalf("nesting %d plus a duplicate: set aside", lv)
		}
	}
}

func TestStubOtherRefusedCIDirs(t *testing.T) {
	stub := stubHead + "status: null\n"
	for _, p := range []string{".gitlab/k/patches/a.yaml", ".circleci/k/patches/a.yaml"} {
		m := stubTree(map[string]string{p: stub})
		m.files[path0(p)+"/kustomization.yaml"] = []byte(fragKustomizationText)
		if got := stubClass(m, p, true, true); got == "fragment" {
			t.Fatalf("%s: set aside", p)
		}
	}
	// The sole full definition under a refused path still counts as the one
	// definition (documented): the stub beside it is set aside.
	m := stubTree(map[string]string{stubPath: stub})
	delete(m.files, "config/crd/bases/a.yaml")
	m.files["config/crd/testdata/a.yaml"] = []byte(stubFull("Webhook"))
	if got := stubClass(m, stubPath, true, true); got != "fragment" {
		t.Fatalf("sole definition under testdata counts: %s", got)
	}
}

func path0(p string) string { return p[:strings.LastIndex(p, "/")] }

func TestStubConversionNeedsExplicitWebhookOnBothSides(t *testing.T) {
	svc := "    webhook:\n      clientConfig:\n        service:\n          name: svc\n"
	withStrategy := func(s string) string { return stubHead + "spec:\n  conversion:\n    strategy: " + s + "\n" + svc }
	noStrategy := stubHead + "spec:\n  conversion:\n" + svc
	for name, c := range map[string]struct{ stub, full string }{
		"omitted stub strategy, full absent":   {noStrategy, stubFull("")},
		"omitted stub strategy, full None":     {noStrategy, stubFull("None")},
		"omitted stub strategy, full Webhook":  {noStrategy, stubFull("Webhook")},
		"Webhook stub, full absent":            {withStrategy("Webhook"), stubFull("")},
		"Webhook stub, full None":              {withStrategy("Webhook"), stubFull("None")},
		"None stub with webhook, full None":    {withStrategy("None"), stubFull("None")},
		"None stub with webhook, full Webhook": {withStrategy("None"), stubFull("Webhook")},
		"empty conversion, full Webhook":       {stubHead + "spec:\n  conversion: {}\n", stubFull("Webhook")},
	} {
		m := stubTree(map[string]string{stubPath: c.stub})
		m.files["config/crd/bases/a.yaml"] = []byte(c.full)
		if got := stubClass(m, stubPath, true, true); got == "fragment" {
			t.Fatalf("%s: set aside", name)
		}
	}
	// Positive: explicit Webhook on both sides, service-only fields; and a stub
	// with no conversion at all is unaffected by the full definition's strategy.
	m := stubTree(map[string]string{stubPath: withStrategy("Webhook")})
	wantStub(t, m, stubPath, "fragment")
	for _, full := range []string{stubFull(""), stubFull("None")} {
		m = stubTree(map[string]string{stubPath: stubHead + "status: null\n"})
		m.files["config/crd/bases/a.yaml"] = []byte(full)
		wantStub(t, m, stubPath, "fragment")
	}
}
