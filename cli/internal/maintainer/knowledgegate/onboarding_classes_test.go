// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// The scan classes a proof may list that the scanner emits beyond the first
// eight, each with an upstream layout the fixture project's scan reads as
// that class. Every file is written at both releases of the pair, beside the
// fixture's listed definition (deploy/crds/widgets.yaml, group obGroup).
const (
	obKustomization = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- crds/widgets.yaml\nconfigurations:\n- kustomizeconfig.yaml\n"
	obWebhookPatch  = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets." + obGroup + "\nspec:\n  preserveUnknownFields: false\n  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        caBundle: Cg==\n        service:\n          namespace: system\n          name: webhook-service\n          path: /convert\n          port: 443\n      conversionReviewVersions:\n      - v1\n"
	obKustConfig    = "nameReference:\n- kind: Service\n  version: v1\n  fieldSpecs:\n  - kind: CustomResourceDefinition\n    version: v1\n    group: apiextensions.k8s.io\n    path: spec/conversion/webhook/clientConfig/service/name\n\nvarReference:\n- path: metadata/annotations\n"
	obSchemaPatch   = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- generated/a.yaml\npatches:\n- target:\n    group: apiextensions.k8s.io\n    version: v1\n    kind: CustomResourceDefinition\n    name: widgets." + obGroup + "\n  patch: |-\n    - op: add\n      path: \"/metadata/labels\"\n      value:\n        app.kubernetes.io/name: widgets\n"
	obGoDefined     = "package crd\n\nfunc New() *apiextv1.CustomResourceDefinition {\n\treturn &apiextv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: \"widgets." + obGroup + "\"}}\n}\n"
)

// obLegacyDoc is the fixture's CRD as an apiextensions.k8s.io/v1beta1
// definition serving the same versions.
func obLegacyDoc(versions ...string) string {
	var b strings.Builder
	b.WriteString("apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets." + obGroup + "\nspec:\n  group: " + obGroup + "\n  names:\n    kind: Widget\n    plural: widgets\n  scope: Namespaced\n  validation:\n    openAPIV3Schema:\n      type: object\n  version: " + versions[0] + "\n  versions:\n")
	for i, v := range versions {
		b.WriteString("  - name: " + v + "\n    served: true\n    storage: " + strconv.FormatBool(i == len(versions)-1) + "\n")
	}
	return b.String()
}

// obTemplatedDoc is the fixture's CRD as a Helm chart template: an
// annotation under a condition and a conversion service in the release
// namespace.
func obTemplatedDoc(versions ...string) string {
	body := obCRDDoc(obGroup, versions...)
	body = strings.Replace(body, "metadata:\n", "metadata:\n  annotations:\n    controller-gen.kubebuilder.io/version: v0.16.3\n", 1)
	return body + "  conversion:\n    strategy: Webhook\n    webhook:\n      clientConfig:\n        caBundle: Cg==\n        service:\n          name: widgets-webhook\n          namespace: {{ .Release.Namespace }}\n          path: /convert\n      conversionReviewVersions:\n      - v1\n"
}

type obClassLayout struct {
	// files maps a path to its content at the earlier and the later release
	// (the versions the listed definition serves there).
	files func(from, to bool) map[string]string
}

var obAddedClasses = map[string]obClassLayout{
	crdversions.ClassTemplatedCopy: {func(from, to bool) map[string]string {
		if from {
			return map[string]string{"charts/widgets/templates/widgets.yaml": obTemplatedDoc("v1alpha1", "v1")}
		}
		return map[string]string{"charts/widgets/templates/widgets.yaml": obTemplatedDoc("v1")}
	}},
	crdversions.ClassLegacyCopy: {func(from, to bool) map[string]string {
		if from {
			return map[string]string{"deploy/v1beta1/widgets.yaml": obLegacyDoc("v1alpha1", "v1")}
		}
		return map[string]string{"deploy/v1beta1/widgets.yaml": obLegacyDoc("v1")}
	}},
	crdversions.ClassSchemaPatch: {func(from, to bool) map[string]string {
		return map[string]string{"build/crd/widgets/kustomization.yaml": obSchemaPatch}
	}},
	crdversions.ClassCRDPatch: {func(from, to bool) map[string]string {
		return map[string]string{"deploy/kustomization.yaml": obKustomization, "deploy/patches/webhook_in_widgets.yaml": obWebhookPatch, "deploy/kustomizeconfig.yaml": obKustConfig}
	}},
	crdversions.ClassKustomizeConfig: {func(from, to bool) map[string]string {
		return map[string]string{"deploy/kustomization.yaml": obKustomization, "deploy/kustomizeconfig.yaml": obKustConfig}
	}},
	// Go code that builds a definition withholds the pair's rules at the
	// later release when they exist, so it lies at the earlier one only.
	crdversions.ClassGoDefined: {func(from, to bool) map[string]string {
		if from {
			return map[string]string{"pkg/crd/build.go": obGoDefined}
		}
		return nil
	}},
}

// obClassFixture is a fixture whose upstream holds the layout of class at
// both releases, and its dry run's findings, as a proof lists them.
func obClassFixture(t *testing.T, class string) (*onboardingFixture, []OnboardingFinding) {
	t.Helper()
	f := newOnboardingFixture(t)
	layout := obAddedClasses[class]
	for rel, content := range layout.files(true, false) {
		writeUpstream(t, f.upstream, obFrom, rel, content)
	}
	for rel, content := range layout.files(false, true) {
		writeUpstream(t, f.upstream, obTo, rel, content)
	}
	src := &obSource{FixtureReader: extract.FixtureReader{Root: f.upstream}, perList: 1}
	f.src = src
	return f, scanOf(t, f, src)
}

func hasClass(list []OnboardingFinding, class string) bool {
	for _, f := range list {
		if f.Class == class {
			return true
		}
	}
	return false
}

// A project whose newest pair scans to one of the added classes is signed
// and admitted when its proof lists the findings; the gate's own scan must
// find the class (the fixture does), and O6 still refuses when the proof
// leaves a finding of that class out.
func TestOnboardingAddedFindingClasses(t *testing.T) {
	t.Parallel()
	for class := range obAddedClasses {
		t.Run(class, func(t *testing.T) {
			if !onboardingFindingClasses[class] {
				t.Fatalf("%s is not in the allow-list", class)
			}
			f, list := obClassFixture(t, class)
			if !hasClass(list, class) {
				t.Fatalf("the fixture's scan finds no %s: %+v", class, list)
			}
			f.draft.Projects[0].Proof.Scan = list
			f.refresh()
			f.sign(t, f.record(t))
			requirePass(t, f.gate(t))

			// The same proof without the findings of that class.
			var rest []OnboardingFinding
			for _, fd := range list {
				if fd.Class != class {
					rest = append(rest, fd)
				}
			}
			f.draft.Projects[0].Proof.Scan = rest
			rec, _ := f.tryRecord(t)
			f.sign(t, rec)
			r := f.gate(t)
			requireFail(t, r, "the scan finds")
			requireFail(t, r, class+" ")
		})
	}
}

// The classes the allow-list keeps out, and a class no scanner emits, are
// refused in a proof: the record does not validate, so it can be neither
// signed nor verified.
var obRefusedClasses = map[string]string{
	crdversions.ClassVoided:         "a reviewed exclusion that does not hold: a batch's target has no exclusion",
	crdversions.ClassExcludedUnread: "an unread file under a reviewed exclusion: a batch's target has no exclusion",
	crdversions.ClassPrePatchCopy:   "a copy under a reviewed pre-patch exclusion: a batch's target has no exclusion",
	crdversions.ClassPrePatch:       "a kustomization of a reviewed pre-patch exclusion: a batch's target has no exclusion",
	crdversions.ClassNoDefinition:   "a file under a reviewed exclusion that defines nothing: a batch's target has no exclusion",
}

func TestOnboardingRefusedFindingClasses(t *testing.T) {
	t.Parallel()
	classes := []string{"no-such-class", ""}
	for c := range obRefusedClasses {
		classes = append(classes, c)
	}
	for _, class := range classes {
		t.Run("class "+class, func(t *testing.T) {
			if class != "" && class != "no-such-class" && onboardingFindingClasses[class] {
				t.Fatalf("%s is in the allow-list", class)
			}
			f := newOnboardingFixture(t)
			f.draft.Projects[0].Proof.Scan = []OnboardingFinding{{Class: class, Path: "deploy/other/widgets.yaml"}}
			rec, _ := f.tryRecord(t)
			if err := rec.validate(); err == nil || !strings.Contains(err.Error(), "out of range") {
				t.Fatalf("record validates: %v", err)
			}
			if _, err := SignedOnboardingBytes(rec); err == nil {
				t.Fatal("a refused class has signed bytes")
			}
		})
	}
}

// Every class constant of the scanner is either accepted in a proof or named
// in obRefusedClasses: adding a class to the scanner fails this test until
// someone decides which.
func TestOnboardingFindingClasses(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(repoRoot, "cli/internal/extract/crdversions")
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	scanner := map[string]string{} // value -> constant name
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		{
			file, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if !strings.HasPrefix(n.Name, "Class") || i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						v, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatal(err)
						}
						scanner[v] = n.Name
					}
				}
			}
		}
	}
	if len(scanner) < 10 {
		t.Fatalf("read only %d class constants of the scanner", len(scanner))
	}
	var undecided []string
	for v, name := range scanner {
		_, refused := obRefusedClasses[v]
		switch {
		case onboardingFindingClasses[v] && refused:
			t.Errorf("%s (%q) is both accepted and refused", name, v)
		case !onboardingFindingClasses[v] && !refused:
			undecided = append(undecided, name+" ("+v+")")
		}
	}
	sort.Strings(undecided)
	if len(undecided) > 0 {
		t.Errorf("scanner classes neither in onboardingFindingClasses nor in obRefusedClasses: %s", strings.Join(undecided, ", "))
	}
	for v := range onboardingFindingClasses {
		if _, ok := scanner[v]; !ok {
			t.Errorf("the allow-list names %q, which the scanner does not emit", v)
		}
	}
	for v := range obRefusedClasses {
		if _, ok := scanner[v]; !ok {
			t.Errorf("the refused list names %q, which the scanner does not emit", v)
		}
	}
	// Every added class has a fixture.
	for v := range onboardingFindingClasses {
		switch v {
		case crdversions.ClassConflict, crdversions.ClassCopy, crdversions.ClassExcluded, crdversions.ClassExternal, crdversions.ClassExtra,
			crdversions.ClassReference, crdversions.ClassUnread, crdversions.ClassUnsupported:
		default:
			if _, ok := obAddedClasses[v]; !ok {
				t.Errorf("accepted class %q has no fixture in obAddedClasses", v)
			}
		}
	}
}
