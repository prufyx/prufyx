// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	patchHook = "config/crd/patches/webhook_in_alphas.yaml"
	patchCA   = "config/crd/patches/cainjection_in_alphas.yaml"
)

// A kubebuilder conversion-webhook patch and a certificate-injection patch.
const fragWebhook = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.widgets.example.test\nspec:\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        service:\n          namespace: system\n          name: webhook-service\n          path: /convert\n      conversionReviewVersions:\n      - v1\n"
const fragCA = "# The following patch adds a directive for certmanager to inject CA into the CRD\napiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  annotations:\n    cert-manager.io/inject-ca-from: $(CERTIFICATE_NAMESPACE)/$(CERTIFICATE_NAME)\n  name: alphas.widgets.example.test\n"

// fragFiles puts the given text files into every tag of an infControl source.
func fragFiles(files map[string]string) func(tag string, m *memTree) {
	return func(_ string, m *memTree) {
		m.files[fragKustomization] = []byte(fragKustomizationText)
		for p, c := range files {
			m.files[p] = []byte(c)
		}
	}
}

// The kustomization every kubebuilder project keeps beside its patches.
const (
	fragKustomization     = "config/crd/kustomization.yaml"
	fragKustomizationText = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- bases/a.yaml\n"
)

// fragTree is the control tree plus the kustomization.
func fragTree() *memTree {
	m := infTree(infControl())
	m.files[fragKustomization] = []byte(fragKustomizationText)
	return m
}

func bothFragments() map[string]string {
	return map[string]string{patchHook: fragWebhook, patchCA: fragCA}
}

// scanClass reports, for one path of a fixture tree, how the scanner reads it
// with the option off and on: "unreadable", "fragment", "definition" or "none".
func scanClass(t *testing.T, m *memTree, p string, skip bool) string {
	t.Helper()
	fs, _, frags := scanTreeFragments(m, skip)
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

// wantClass asserts the fixture is what a test claims: its class without and
// with the option.
func wantClass(t *testing.T, p, content string, off, on string) {
	t.Helper()
	m := fragTree()
	m.files[p] = []byte(content)
	if got := scanClass(t, m, p, false); got != off {
		t.Fatalf("%s: option off reads %s, want %s", p, got, off)
	}
	if got := scanClass(t, m, p, true); got != on {
		t.Fatalf("%s: option on reads %s, want %s", p, got, on)
	}
}

func inferSkip(src Source) Input {
	in := infInput(src)
	in.SkipPatchFragments = true
	return in
}

func TestSkipFragmentsFixturesAreWhatTheyClaim(t *testing.T) {
	wantClass(t, patchHook, fragWebhook, "unreadable", "fragment")
	wantClass(t, patchCA, fragCA, "unreadable", "fragment")
}

func TestSkipFragmentsInferenceStopsWithoutAndPassesWith(t *testing.T) {
	mut := fragFiles(bothFragments())
	// Without the option: the rank-1 unreadable fragment directory stops the
	// inference (the measured case).
	se := infStops(t, infInput(infSource(infControl(), mut)), StopInstallPathAmbiguous)
	if !strings.Contains(se.Error(), "config/crd/patches/") {
		t.Fatalf("the stop must name the patches directory: %v", se)
	}
	// With the option: the same draft as without any fragment.
	with := mustGenerate(t, inferSkip(infSource(infControl(), mut)))
	plain := mustGenerate(t, infInput(infSource(infControl(), nil)))
	if !bytes.Equal(with.A, plain.A) || !bytes.Equal(with.B, plain.B) || !bytes.Equal(with.TableRow, plain.TableRow) {
		t.Fatal("a fragment must not change the target")
	}
	// The ranking evidence is the one without fragments: fragments never rank.
	wj, _ := json.Marshal(with.Report.InferredInstallPaths)
	pj, _ := json.Marshal(plain.Report.InferredInstallPaths)
	if !bytes.Equal(wj, pj) {
		t.Fatalf("ranking changed:\n%s\n%s", wj, pj)
	}
	if len(with.Report.PatchFragments) != len(ipTags) {
		t.Fatalf("fragments listed per window tag: %+v", with.Report.PatchFragments)
	}
	for _, pf := range with.Report.PatchFragments {
		if strings.Join(pf.Paths, ",") != patchCA+","+patchHook {
			t.Fatalf("paths: %+v", pf)
		}
	}
	// Never an install file, never a non-install copy.
	for _, c := range with.Report.NonInstallCopies {
		if strings.Contains(c.Path, "patches/") {
			t.Fatalf("a fragment is not a copy: %+v", c)
		}
	}
	if strings.Contains(string(with.A), "patches/") {
		t.Fatal("a fragment must never be an install file")
	}
	// The digest covers the fragments only when there are some.
	if with.Report.FactsDigest == plain.Report.FactsDigest {
		t.Fatal("the facts digest must cover the set-aside fragments")
	}
}

func TestSkipFragmentsDigestMovesWithTheFragmentList(t *testing.T) {
	one := mustGenerate(t, inferSkip(infSource(infControl(), fragFiles(map[string]string{patchHook: fragWebhook}))))
	two := mustGenerate(t, inferSkip(infSource(infControl(), fragFiles(bothFragments()))))
	if one.Report.FactsDigest == two.Report.FactsDigest {
		t.Fatal("a different fragment list must change the digest")
	}
}

func TestSkipFragmentsOffIsByteIdentical(t *testing.T) {
	// The option on with no fragment in the tree: nothing differs, byte for byte.
	off := mustGenerate(t, infInput(infSource(infControl(), nil)))
	on := mustGenerate(t, inferSkip(infSource(infControl(), nil)))
	oj, _ := json.Marshal(off.Report)
	nj, _ := json.Marshal(on.Report)
	if !bytes.Equal(off.A, on.A) || !bytes.Equal(off.B, on.B) || !bytes.Equal(oj, nj) || !bytes.Equal(off.Changelog, on.Changelog) {
		t.Fatal("no fragment: the option must change nothing")
	}
	if strings.Contains(string(oj), "patchFragments") {
		t.Fatal("no field without the option")
	}
	// The option off with fragments present: the existing stop, no field.
	infStops(t, infInput(infSource(infControl(), fragFiles(bothFragments()))), StopInstallPathAmbiguous)
}

func TestSkipFragmentsHandPathAndCopyCheck(t *testing.T) {
	mut := fragFiles(bothFragments())
	// Check on, option off: the unreadable fragments outside stop.
	infStops(t, handInput(t, infControl(), mut, true), StopInstallPathHidesCRD)
	// Check on, option on: passes, fragments listed, no copy entry.
	in := handInput(t, infControl(), mut, true)
	in.SkipPatchFragments = true
	res := mustGenerate(t, in)
	if len(res.Report.PatchFragments) != len(ipTags) {
		t.Fatalf("%+v", res.Report.PatchFragments)
	}
	for _, c := range res.Report.NonInstallCopies {
		if strings.Contains(c.Path, "patches/") {
			t.Fatalf("a fragment is not a copy: %+v", c)
		}
	}
	// Check off: before the option the unreadable fragment outside was a
	// reported unreadable copy; with it, a fragment.
	in = handInput(t, infControl(), mut, false)
	res = mustGenerate(t, in)
	seen := false
	for _, c := range res.Report.NonInstallCopies {
		if c.Path == patchHook && c.Unreadable != "" {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("option off keeps the unreadable copy: %+v", res.Report.NonInstallCopies)
	}
	in.SkipPatchFragments = true
	res = mustGenerate(t, in)
	for _, c := range res.Report.NonInstallCopies {
		if c.Path == patchHook {
			t.Fatalf("a fragment is not a copy: %+v", c)
		}
	}
}

func TestSkipFragmentsStillStopOnEverythingElse(t *testing.T) {
	// Each fixture is unreadable with the option off AND on.
	cases := map[string]string{
		"templated":      "{{- if .Values.crds }}\n" + fragWebhook + "{{- end }}\n",
		"versions-only":  "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.widgets.example.test\nspec:\n  versions:\n  - name: v1\n    served: true\n    storage: true\n",
		"names-only":     "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.widgets.example.test\nspec:\n  names:\n    kind: Alpha\n",
		"group-only":     "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.widgets.example.test\nspec:\n  group: widgets.example.test\n",
		"unparsable":     "kind: CustomResourceDefinition\nmetadata: [\n",
		"fragment+full":  fragWebhook + "---\n" + infCRD("Gamma", "d"),
		"two-tmpl-lines": fragWebhook + "# {{ .Values.x }}\n",
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			wantClass(t, patchHook, c, "unreadable", "unreadable")
			mut := fragFiles(map[string]string{patchHook: c})
			infStops(t, inferSkip(infSource(infControl(), mut)), StopInstallPathAmbiguous)
			in := handInput(t, infControl(), mut, true)
			in.SkipPatchFragments = true
			infStops(t, in, StopInstallPathHidesCRD)
		})
	}
}

func TestSkipFragmentsOneBadFileAmongGoodStillStops(t *testing.T) {
	files := bothFragments()
	files["config/crd/patches/versions_in_alphas.yaml"] = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: alphas.widgets.example.test\nspec:\n  versions:\n  - name: v2\n"
	wantClass(t, "config/crd/patches/versions_in_alphas.yaml", files["config/crd/patches/versions_in_alphas.yaml"], "unreadable", "unreadable")
	infStops(t, inferSkip(infSource(infControl(), fragFiles(files))), StopInstallPathAmbiguous)
}

func TestSkipFragmentsFullDefinitionIsADefinition(t *testing.T) {
	full := infCRD("Gamma", "d")
	// Not a fragment: the scanner reads a definition with the option on or off.
	wantClass(t, "config/crd/patches/full.yaml", full, "definition", "definition")
	// A definition no install path defines is the typed stop, option on.
	in := handInput(t, infControl(), fragFiles(map[string]string{"config/crd/patches/full.yaml": full}), true)
	in.SkipPatchFragments = true
	infStops(t, in, StopInstallPathHidesCRD)
	// A full definition (Alpha, equal to the installed one) next to a
	// fragment is a copy, and the fragment is still set aside.
	mut := fragFiles(map[string]string{"config/crd/patches/full.yaml": infCRD("Alpha", "d"), patchHook: fragWebhook})
	in = handInput(t, infControl(), mut, true)
	in.SkipPatchFragments = true
	res := mustGenerate(t, in)
	var copyPath, fragPath bool
	for _, c := range res.Report.NonInstallCopies {
		copyPath = copyPath || c.Path == "config/crd/patches/full.yaml"
	}
	for _, pf := range res.Report.PatchFragments {
		fragPath = fragPath || strings.Join(pf.Paths, ",") == patchHook
	}
	if !copyPath || !fragPath {
		t.Fatalf("copy %v fragment %v: %+v", copyPath, fragPath, res.Report)
	}
	// A different decoded spec is still caught.
	mut = fragFiles(map[string]string{"config/crd/patches/full.yaml": infCRD("Alpha", "other"), patchHook: fragWebhook})
	in = handInput(t, infControl(), mut, true)
	in.SkipPatchFragments = true
	infStops(t, in, StopInstallPathCopyDiffers)
}

func TestSkipFragmentsJSONPatchListStaysUnreadable(t *testing.T) {
	// The extractor reads no JSON-patch list, so neither does the generator:
	// each stays unreadable-shape with the option on.
	for name, c := range map[string]string{
		"metadata":   "- op: add\n  path: /metadata/annotations/cert-manager.io~1inject-ca-from\n  value: ns/cert # CustomResourceDefinition\n",
		"conversion": "- op: replace\n  path: /spec/conversion\n  value: {strategy: None} # CustomResourceDefinition\n",
		"versions":   "- op: add\n  path: /spec/versions/-\n  value: {name: v2} # CustomResourceDefinition\n",
		"empty":      "[] # CustomResourceDefinition\n",
	} {
		wantClass(t, "config/crd/patches/json_patch.yaml", c, "unreadable", "unreadable")
		mut := fragFiles(map[string]string{"config/crd/patches/json_patch.yaml": c})
		infStops(t, inferSkip(infSource(infControl(), mut)), StopInstallPathAmbiguous)
		_ = name
	}
	js := `[{"op":"add","path":"/metadata/labels/x","value":"CustomResourceDefinition"}]`
	wantClass(t, "config/crd/patches/p.json", js, "unreadable", "unreadable")
}

func TestSkipFragmentsNeedsAKustomizationDirectory(t *testing.T) {
	// Content alone is not enough: the fragment must lie below a directory
	// (not the repository root) that holds a kustomization file.
	cases := map[string]struct {
		kust, frag string
		want       string
	}{
		"beside":         {"config/crd/kustomization.yaml", patchHook, "fragment"},
		"yml":            {"config/crd/kustomization.yml", patchHook, "fragment"},
		"no-extension":   {"config/crd/Kustomization", patchHook, "fragment"},
		"ancestor":       {"config/kustomization.yaml", patchHook, "fragment"},
		"none":           {"", patchHook, "unreadable"},
		"root-only":      {"kustomization.yaml", patchHook, "unreadable"},
		"sibling-dir":    {"config/rbac/kustomization.yaml", patchHook, "unreadable"},
		"below-fragment": {"config/crd/patches/sub/kustomization.yaml", patchHook, "unreadable"},
		"other-name":     {"config/crd/kustomize.yaml", patchHook, "unreadable"},
	}
	for name, c := range cases {
		m := infTree(infControl())
		m.files[c.frag] = []byte(fragWebhook)
		if c.kust != "" {
			m.files[c.kust] = []byte(fragKustomizationText)
		}
		if got := scanClass(t, m, c.frag, true); got != c.want {
			t.Errorf("%s: got %s, want %s", name, got, c.want)
		}
		if got := scanClass(t, m, c.frag, false); got != "unreadable" {
			t.Errorf("%s: option off reads %s", name, got)
		}
	}
	// A kustomization that is a link does not declare a directory.
	m := infTree(infControl())
	m.files[patchHook] = []byte(fragWebhook)
	m.files["elsewhere.yaml"] = []byte(fragKustomizationText)
	m.links[fragKustomization] = "../../elsewhere.yaml"
	if got := scanClass(t, m, patchHook, true); got != "unreadable" {
		t.Fatalf("a linked kustomization: %s", got)
	}
	// The stop is the existing one when no kustomization exists.
	infStops(t, inferSkip(infSource(infControl(), func(_ string, m *memTree) { m.files[patchHook] = []byte(fragWebhook) })), StopInstallPathAmbiguous)
}

func TestSkipFragmentsRefusesNonUTF8AndDeepNesting(t *testing.T) {
	// Bounded, typed result, no panic: the file stays unreadable-shape.
	bad := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: \xff\xfe.x\n"
	wantClass(t, patchHook, bad, "unreadable", "unreadable")
	if isPatchFragment([]byte(bad)) {
		t.Fatal("invalid UTF-8 must not be a fragment")
	}
	if isPatchFragment([]byte("\xff\xfe\x00 CustomResourceDefinition")) {
		t.Fatal("binary must not be a fragment")
	}
	deep := func(n int) string {
		return "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: a.x\nspec:\n  conversion:\n    webhook:\n      clientConfig:\n        k: " + strings.Repeat("[", n) + strings.Repeat("]", n) + "\n"
	}
	// Past the bound, and a pathological depth: never a fragment, no panic.
	for _, n := range []int{10, 200, 5000, 200000} {
		if isPatchFragment([]byte(deep(n))) {
			t.Errorf("nesting %d must not be a fragment", n)
		}
	}
	m := fragTree()
	m.files[patchHook] = []byte(deep(200000))
	if got := scanClass(t, m, patchHook, true); got != "unreadable" {
		t.Fatalf("deep nesting reads %s", got)
	}
	// A very wide mapping and many documents are refused too.
	wide := "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: a.x\n  labels:\n"
	for i := 0; i < fragMaxMembers+1; i++ {
		wide += "    k" + strconv.Itoa(i) + ": v\n"
	}
	if isPatchFragment([]byte(wide)) {
		t.Fatal("too many members must not be a fragment")
	}
	many := strings.Repeat(fragCA+"---\n", fragMaxDocuments+1)
	if isPatchFragment([]byte(many)) {
		t.Fatal("too many documents must not be a fragment")
	}
	if isPatchFragment(append([]byte(fragCA+"# "), bytes.Repeat([]byte("x"), 8<<20)...)) {
		t.Fatal("an oversized file must not be a fragment")
	}
}

func TestSkipFragmentsEmptyFile(t *testing.T) {
	// An empty file is not a definition and never unreadable: the option does
	// not change what it is, and it is not listed.
	for _, c := range []string{"", "---\n", "# CustomResourceDefinition only a comment\n"} {
		wantClass(t, "config/crd/patches/empty.yaml", c, "none", "none")
	}
	mut := fragFiles(map[string]string{"config/crd/patches/empty.yaml": ""})
	res := mustGenerate(t, inferSkip(infSource(infControl(), mut)))
	if len(res.Report.PatchFragments) != 0 {
		t.Fatalf("%+v", res.Report.PatchFragments)
	}
}

func TestSkipFragmentsThroughSymlinkFollowsTheLinkRules(t *testing.T) {
	// Reached through a link from an install-like (non-skipped) path.
	const link = "deploy/link.yaml"
	mut := func(_ string, m *memTree) {
		m.files[patchHook] = []byte(fragWebhook)
		m.links[link] = relTo(link, patchHook)
	}
	m := fragTree()
	mut("", m)
	if got := scanClass(t, m, patchHook, true); got != "unreadable" {
		t.Fatalf("a linked fragment must stay unreadable, got %s", got)
	}
	fs, _, _ := scanTreeFragments(m, true)
	reached := false
	for _, f := range fs {
		reached = reached || (f.Path == patchHook && len(f.Reached) == 1 && f.Reached[0] == link)
	}
	if !reached {
		t.Fatal("the fixture must be reached through the link")
	}
	infStops(t, inferSkip(infSource(infControl(), mut)), StopInstallPathAmbiguous)
	in := handInput(t, infControl(), mut, true)
	in.SkipPatchFragments = true
	infStops(t, in, StopInstallPathHidesCRD)
	// The unlinked sibling is still set aside in the same tree.
	m.files[patchCA] = []byte(fragCA)
	if got := scanClass(t, m, patchCA, true); got != "fragment" {
		t.Fatalf("%s", got)
	}
	// Reached only from a skipped directory: also kept unreadable (any link
	// leaves it to the existing link rules, which judge a non-skipped file
	// path strictly).
	const docLink = "docs/link.yaml"
	mut2 := func(_ string, m *memTree) {
		m.files[patchHook] = []byte(fragWebhook)
		m.links[docLink] = relTo(docLink, patchHook)
	}
	m2 := fragTree()
	mut2("", m2)
	if got := scanClass(t, m2, patchHook, true); got != "unreadable" {
		t.Fatalf("got %s", got)
	}
	infStops(t, inferSkip(infSource(infControl(), mut2)), StopInstallPathAmbiguous)
}

func TestSkipFragmentsDeterministic(t *testing.T) {
	var prev []byte
	for i := 0; i < 5; i++ {
		res := mustGenerate(t, inferSkip(infSource(infControl(), fragFiles(bothFragments()))))
		j, _ := json.Marshal(res.Report)
		b := append(append(append([]byte{}, res.A...), res.B...), j...)
		if prev != nil && !bytes.Equal(prev, b) {
			t.Fatal("not deterministic")
		}
		prev = b
	}
}

func TestSkipFragmentsRankOneUnreadablePatchDirOutsideBases(t *testing.T) {
	// The measured case: a rank-1 patches directory beside config/crd/bases.
	// Option off: stop. Option on: the chosen directory is config/crd/bases/.
	mut := fragFiles(bothFragments())
	infStops(t, infInput(infSource(infControl(), mut)), StopInstallPathAmbiguous)
	res := mustGenerate(t, inferSkip(infSource(infControl(), mut)))
	if res.Report.InferredInstallPaths.Paths[0] != "config/crd/bases/" {
		t.Fatalf("%+v", res.Report.InferredInstallPaths)
	}
	// Another unreadable rank-1 file in the same directory is still a stop:
	// the option is per file, never per directory.
	files := bothFragments()
	files["config/crd/patches/tmpl_in_alphas.yaml"] = "kind: CustomResourceDefinition\n{{ .x }}\n"
	infStops(t, inferSkip(infSource(infControl(), fragFiles(files))), StopInstallPathAmbiguous)
}

func TestSkipFragmentsWithDeriveDuplicates(t *testing.T) {
	// #566: duplicates inside the inferred directory are still derived and a
	// fragment elsewhere no longer blocks the derivation.
	mut := fragFiles(bothFragments())
	in := infInput(infSource(inferDupFiles(), mut))
	in.DeriveDuplicates = true
	infStops(t, in, StopInstallPathAmbiguous)
	in = inferSkip(infSource(inferDupFiles(), mut))
	in.DeriveDuplicates = true
	res := mustGenerate(t, in)
	base := infInput(infSource(inferDupFiles(), nil))
	base.DeriveDuplicates = true
	want := mustGenerate(t, base)
	if !bytes.Equal(res.A, want.A) || len(res.Report.DerivedSources) != len(want.Report.DerivedSources) || len(res.Report.DerivedSources) == 0 {
		t.Fatalf("derived: %+v vs %+v", res.Report.DerivedSources, want.Report.DerivedSources)
	}
	if len(res.Report.PatchFragments) != len(ipTags) {
		t.Fatalf("%+v", res.Report.PatchFragments)
	}
}

func TestSkipFragmentsWithCollapse(t *testing.T) {
	// #565: a fragment in another directory leaves the collapse of the install
	// directory alone.
	in := inferSkip(infSource(infControl(), fragFiles(bothFragments())))
	in.CollapseDirectories = true
	res := mustGenerate(t, in)
	if res.Report.Representation != "directory" || len(res.Report.Directories) != 1 || res.Report.Directories[0].Dir != "config/crd/bases" {
		t.Fatalf("%+v", res.Report.Directories)
	}
	// A fragment INSIDE the collapsed directory is matched by the directory
	// entry but is no definition: the collapse stops dir-mixed (never silently
	// reads it); without the collapse the exact files are written.
	inside := fragFiles(map[string]string{"config/crd/bases/crd-patch.yaml": fragWebhook})
	wantClass(t, "config/crd/bases/crd-patch.yaml", fragWebhook, "unreadable", "fragment")
	in = inferSkip(infSource(infControl(), inside))
	in.CollapseDirectories = true
	infStops(t, in, StopDirMixed)
	in = inferSkip(infSource(infControl(), inside))
	res = mustGenerate(t, in)
	if strings.Contains(string(res.A), "crd-patch.yaml") {
		t.Fatal("a fragment is never an install file")
	}
}

func TestSkipFragmentsInsideInferredDirectoryIsNotInstalled(t *testing.T) {
	// A fragment below the chosen directory: set aside, not an install file,
	// and not a ranking candidate (the evidence equals the run without it).
	inside := fragFiles(map[string]string{"config/crd/bases/crd-patch.yaml": fragWebhook})
	infStops(t, infInput(infSource(infControl(), inside)), StopInstallPathAmbiguous)
	got := mustGenerate(t, inferSkip(infSource(infControl(), inside)))
	plain := mustGenerate(t, infInput(infSource(infControl(), nil)))
	if !bytes.Equal(got.A, plain.A) {
		t.Fatal("the target must not change")
	}
}

func TestCLISkipPatchFragmentsFlag(t *testing.T) {
	src := infSource(infControl(), fragFiles(bothFragments()))
	open := func(string) Source { return src }
	args := func(out string, extra ...string) []string {
		return append([]string{"generate", "--dir", "x", "--slug", "widgets", "--name", "Widgets", "--repo", "github.com/example/widgets", "--tags", strings.Join(ipTags, ","), "--out", out, "--infer-install-paths"}, extra...)
	}
	var so, se bytes.Buffer
	if code := run(args(filepath.Join(t.TempDir(), "o")), &so, &se, open); code != 1 || !strings.Contains(so.String(), StopInstallPathAmbiguous) {
		t.Fatalf("default off must stop: exit %d %s", code, so.String())
	}
	out := filepath.Join(t.TempDir(), "o")
	so.Reset()
	if code := run(args(out, "--skip-patch-fragments"), &so, &se, open); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	rep, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil || !strings.Contains(string(rep), `"patchFragments"`) || !strings.Contains(string(rep), patchHook) {
		t.Fatalf("report: %v %s", err, rep)
	}
}

func TestBacktestSkipPatchFragmentsOptionMapsAndDefaultsOff(t *testing.T) {
	var got Input
	old := generate
	defer func() { generate = old }()
	generate = func(in Input) (*Result, error) {
		got = in
		return old(in)
	}
	dirBT(t, func(e *btEntry) { e.SkipPatchFragments = true }, genCollapsed(t, false), "")
	if !got.SkipPatchFragments {
		t.Fatalf("%+v", got)
	}
	got = Input{}
	dirBT(t, func(e *btEntry) {}, genCollapsed(t, false), "")
	if got.SkipPatchFragments {
		t.Fatalf("default must stay off: %+v", got)
	}
	raw := `{"schema":"` + BacktestSchema + `","count":1,"entries":[{"slug":"a","name":"a","repo":"r","tags":["v1"],"mirror":"m","expected":"e.json","half":"A","skipPatchFragments":true}],"seeds":[{"entry":"a","kind":"path"}]}`
	m, err := parseBacktestManifest([]byte(raw))
	if err != nil || !m.Entries[0].SkipPatchFragments {
		t.Fatalf("%v %+v", err, m)
	}
}

// TestPatchFragmentPredicateTable pins the content proof, one case per rule;
// each "no" case is made to differ from the nearest "yes" case by one thing.
func TestPatchFragmentPredicateTable(t *testing.T) {
	const head = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
	const meta = "metadata:\n  name: a.x\n"
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"webhook", fragWebhook, true},
		{"cainjection", fragCA, true},
		{"minimal", head + meta, true},
		{"v1beta1", "apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\n" + meta, true},
		{"no apiVersion", "kind: CustomResourceDefinition\n" + meta, false},
		{"namespace", head + "metadata:\n  name: a.x\n  namespace: n\n", false},
		{"preserve not bool", head + meta + "spec:\n  preserveUnknownFields: \"no\"\n", false},
		{"labels non-string", head + "metadata:\n  name: a.x\n  labels:\n    k: 1\n", false},
		{"apiVersion v2", "apiVersion: apiextensions.k8s.io/v2\nkind: CustomResourceDefinition\n" + meta, false},
		{"conversion not strict", head + meta + "spec:\n  conversion:\n    strategy: Other\n", false},
		{"name too long", head + "metadata:\n  name: " + strings.Repeat("a", 254) + "\n", false},
		{"preserve", head + meta + "spec:\n  preserveUnknownFields: false\n", true},
		{"labels", head + "metadata:\n  name: a.x\n  labels:\n    k: v\n", true},
		{"two fragments", head + meta + "---\n" + head + "metadata:\n  name: b.x\n", true},
		{"leading empty doc", "---\n---\n" + head + meta, true},
		{"empty", "", false},
		{"only a comment", "# CustomResourceDefinition\n", false},
		{"template", head + meta + "# {{ x }}\n", false},
		{"no kind mention", "a: b\n", false},
		{"other kind", "apiVersion: v1\nkind: ConfigMap\n" + meta + "data:\n  k: CustomResourceDefinition\n", false},
		{"kind not string", "kind: [CustomResourceDefinition]\n" + meta, false},
		{"no metadata", head, false},
		{"metadata not map", head + "metadata: x\n", false},
		{"no name", head + "metadata:\n  labels:\n    a: b\n", false},
		{"empty name", head + "metadata:\n  name: \"\"\n", false},
		{"unknown metadata key", head + meta + "  finalizers: [a]\n", false},
		{"labels not map", head + "metadata:\n  name: a.x\n  labels: x\n", false},
		{"foreign apiVersion", "apiVersion: v1\nkind: CustomResourceDefinition\n" + meta, false},
		{"apiVersion not string", "apiVersion: 1\nkind: CustomResourceDefinition\n" + meta, false},
		{"unknown top key", head + meta + "status: {}\n", false},
		{"patch directive", head + meta + "$patch: delete\n", false},
		{"spec not map", head + meta + "spec: x\n", false},
		{"group", head + meta + "spec:\n  group: g.x\n", false},
		{"names", head + meta + "spec:\n  names:\n    kind: A\n", false},
		{"versions", head + meta + "spec:\n  versions:\n  - name: v1\n", false},
		{"scope", head + meta + "spec:\n  scope: Namespaced\n", false},
		{"validation", head + meta + "spec:\n  validation: {}\n", false},
		{"version", head + meta + "spec:\n  version: v1\n", false},
		{"conversion and versions", head + meta + "spec:\n  conversion:\n    strategy: None\n  versions: []\n", false},
		{"fragment and full", head + meta + "---\n" + head + meta + "spec:\n  group: g.x\n  names:\n    kind: A\n  versions:\n  - name: v1\n", false},
		{"fragment and other kind", head + meta + "---\nkind: ConfigMap\n", false},
		{"anchor", head + "metadata: &m\n  name: a.x\n", false},
		{"alias", head + "metadata:\n  name: &n a.x\n  labels:\n    k: *n\n", false},
		{"merge key", head + "metadata:\n  <<: {name: a.x}\n", false},
		{"custom tag", head + "metadata:\n  name: !custom a.x\n", false},
		{"duplicate key", head + meta + "metadata:\n  name: b.x\n", false},
		{"not yaml", "kind: CustomResourceDefinition\nmetadata: [\n", false},
		{"scalar", "CustomResourceDefinition\n", false},
		{"list of scalars", "- CustomResourceDefinition\n", false},
		{"json patch", "- {op: add, path: /metadata/labels/x, value: CustomResourceDefinition}\n", false},
		{"json patch conversion", "- {op: replace, path: /spec/conversion, value: {strategy: None}} # CustomResourceDefinition\n", false},
		{"json patch preserve", "- {op: replace, path: /spec/preserveUnknownFields, value: false} # CustomResourceDefinition\n", false},
		{"json patch copy", "- {op: copy, from: /metadata/labels, path: /metadata/annotations} # CustomResourceDefinition\n", false},
		{"json patch empty list", "[] # CustomResourceDefinition\n", false},
		{"json patch bare metadata", "- {op: remove, path: /metadata/} # CustomResourceDefinition\n", false},
		{"json patch metadata prefix only", "- {op: remove, path: /metadataX/a} # CustomResourceDefinition\n", false},
		{"json patch conversion prefix only", "- {op: remove, path: /spec/conversionX} # CustomResourceDefinition\n", false},
		{"json patch spec", "- {op: add, path: /spec/versions/-, value: {}} # CustomResourceDefinition\n", false},
		{"json patch names", "- {op: replace, path: /spec/names, value: {}} # CustomResourceDefinition\n", false},
		{"json patch from versions", "- {op: move, from: /spec/versions, path: /metadata/labels/x} # CustomResourceDefinition\n", false},
		{"json patch from not string", "- {op: move, from: 1, path: /metadata/labels/x} # CustomResourceDefinition\n", false},
		{"json patch unknown key", "- {op: add, path: /metadata/labels/x, value: a, extra: b} # CustomResourceDefinition\n", false},
		{"json patch bad op", "- {op: nope, path: /metadata/labels/x} # CustomResourceDefinition\n", false},
		{"json patch op not string", "- {op: 1, path: /metadata/labels/x} # CustomResourceDefinition\n", false},
		{"json patch path not string", "- {op: add, path: 1} # CustomResourceDefinition\n", false},
		{"json patch element not map", "- x # CustomResourceDefinition\n", false},
		{"json patch one bad op", "- {op: add, path: /metadata/labels/x, value: a}\n- {op: add, path: /spec/scope, value: Cluster} # CustomResourceDefinition\n", false},
		{"json file", `[{"op":"add","path":"/metadata/labels/x","value":"CustomResourceDefinition"}]`, false},
	}
	for _, c := range cases {
		if got := isPatchFragment([]byte(c.in)); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Every case the predicate calls a fragment fails the shape check of the
// scanner (so the option only ever changes an unreadable file), and every
// whole definition is a definition (so it is never set aside).
func TestPatchFragmentIsAlwaysUnreadableToTheScanner(t *testing.T) {
	for _, c := range []string{fragWebhook, fragCA} {
		if _, err := parseCRDs([]byte(c)); err == nil {
			t.Fatalf("fixture must be unreadable to the scanner:\n%s", c)
		}
		if !isPatchFragment([]byte(c)) {
			t.Fatalf("fixture must be a fragment:\n%s", c)
		}
	}
	whole := []byte(infCRD("Alpha", "d"))
	if crds, err := parseCRDs(whole); err != nil || len(crds) != 1 {
		t.Fatalf("%v %v", crds, err)
	}
	if isPatchFragment(whole) {
		t.Fatal("a whole definition is never a fragment")
	}
}
