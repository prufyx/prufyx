// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"strings"
	"testing"
)

// feOpts describes one definition of kind Alpha; the zero value is the
// installed definition.
type feOpts struct {
	apiVersion string
	scope      string
	plural     string
	short      string // yaml flow list, e.g. "[a]"
	versions   string // yaml block of versions; empty = one served storage v1
	conversion string // yaml block under spec; empty = absent
	schema     string // description text of the schema
	extraKind  string // second definition in the same file
}

func feDef(o feOpts) string {
	def := func(kind string) string {
		if o.apiVersion == "" {
			o.apiVersion = "apiextensions.k8s.io/v1"
		}
		if o.scope == "" {
			o.scope = "Namespaced"
		}
		if o.plural == "" {
			o.plural = "alphas"
		}
		if o.short == "" {
			o.short = "[al]"
		}
		if o.versions == "" {
			o.versions = "  - name: v1\n    served: true\n    storage: true\n"
		}
		if o.schema == "" {
			o.schema = "d"
		}
		s := "apiVersion: " + o.apiVersion + "\nkind: CustomResourceDefinition\nspec:\n  group: " + infGroup +
			"\n  scope: " + o.scope + "\n  names:\n    kind: " + kind + "\n    plural: " + o.plural + "\n    shortNames: " + o.short + "\n  versions:\n" + o.versions +
			"    schema:\n      openAPIV3Schema:\n        description: " + o.schema + "\n"
		if o.conversion != "" {
			s += o.conversion
		}
		return s
	}
	d := def("Alpha")
	if o.extraKind != "" {
		d += "---\n" + def(o.extraKind)
	}
	return d
}

const feCopy = "charts/x/crds/all.yaml"

// feSource serves every tag with the installed definition and the copy; the
// copy of the newest tag, or of the tags selected by only, is replaced.
func feSource(copy func(tag string) []byte) memSource {
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range ipTags {
		m := newMemTree()
		m.files["config/crd/bases/a.yaml"] = []byte(feDef(feOpts{}))
		m.files[feCopy] = copy(tag)
		m.files["README.md"] = []byte("not a definition")
		s.trees[tag] = m
	}
	return s
}

func feSame(o feOpts) func(string) []byte {
	return func(string) []byte { return []byte(feDef(o)) }
}

func feInput(src Source, accept bool) Input {
	in := infInput(src)
	in.AcceptFactEqualCopies = accept
	return in
}

// Positives: copies differing only by schema text or apiVersion form.
func TestFactEqualAcceptsSchemaAndAPIVersionOnlyDifferences(t *testing.T) {
	for name, o := range map[string]feOpts{
		"schema text only":                 {schema: "other text"},
		"legacy apiVersion":                {apiVersion: "apiextensions.k8s.io/v1beta1"},
		"legacy apiVersion and schema":     {apiVersion: "apiextensions.k8s.io/v1beta1", schema: "old"},
		"version order is not a fact":      {versions: "  - name: v1\n    served: true\n    storage: true\n  - name: v2\n    served: true\n    storage: false\n"},
		"chart copy with long schema text": {schema: strings.Repeat("x", 300)},
	} {
		t.Run(name, func(t *testing.T) {
			src := feSource(feSame(o))
			if name == "version order is not a fact" {
				// the installed definition carries the same two versions in the other order
				for _, tag := range ipTags {
					src.trees[tag].files["config/crd/bases/a.yaml"] = []byte(feDef(feOpts{versions: "  - name: v2\n    served: true\n    storage: false\n  - name: v1\n    served: true\n    storage: true\n", schema: "q"}))
				}
			}
			if _, err := Generate(feInput(src, false)); !hasStopCode(err, StopInstallPathCopyDiffers) {
				t.Fatalf("flag off must keep the stop: %v", err)
			}
			res := mustGenerate(t, feInput(src, true))
			if !strings.Contains(string(res.Changelog), "same published facts") {
				t.Fatalf("changelog must name the set-aside copies: %s", res.Changelog)
			}
			// the accepted copy changes no path and no CRD count
			if res.Report.CRDCount != 1 {
				t.Fatalf("crd count: %d", res.Report.CRDCount)
			}
		})
	}
}

// Seeded negatives: a difference in any fact keeps the typed stop. Every case
// is also a case the flag-off run stops on, so the flag never turns a stop
// into a different stop.
func TestFactEqualNegativesKeepTheStop(t *testing.T) {
	two := "  - name: v1\n    served: true\n    storage: true\n  - name: v2\n    served: true\n    storage: false\n"
	for name, o := range map[string]feOpts{
		"served flipped":        {versions: "  - name: v1\n    served: false\n    storage: true\n"},
		"storage flipped":       {versions: "  - name: v1\n    served: true\n    storage: false\n"},
		"version added":         {versions: two},
		"version renamed":       {versions: "  - name: v1beta1\n    served: true\n    storage: true\n"},
		"scope differs":         {scope: "Cluster"},
		"plural differs":        {plural: "betas"},
		"shortNames differ":     {short: "[zz]"},
		"conversion webhook":    {conversion: "  conversion:\n    strategy: Webhook\n    webhook:\n      conversionReviewVersions: [v1]\n"},
		"conversion None":       {conversion: "  conversion:\n    strategy: None\n"},
		"schema and scope both": {scope: "Cluster", schema: "other"},
	} {
		t.Run(name, func(t *testing.T) {
			src := feSource(feSame(o))
			for _, accept := range []bool{false, true} {
				se := infStops(t, feInput(src, accept), StopInstallPathCopyDiffers)
				if !strings.Contains(se.Error(), feCopy) {
					t.Fatalf("accept=%v: stop must name the copy: %v", accept, se)
				}
			}
		})
	}
	t.Run("version removed", func(t *testing.T) {
		src := feSource(feSame(feOpts{}))
		for _, tag := range ipTags {
			src.trees[tag].files["config/crd/bases/a.yaml"] = []byte(feDef(feOpts{versions: two}))
		}
		infStops(t, feInput(src, true), StopInstallPathCopyDiffers)
	})
	t.Run("installed has conversion, copy has none", func(t *testing.T) {
		src := feSource(feSame(feOpts{}))
		for _, tag := range ipTags {
			src.trees[tag].files["config/crd/bases/a.yaml"] = []byte(feDef(feOpts{conversion: "  conversion:\n    strategy: None\n"}))
		}
		infStops(t, feInput(src, true), StopInstallPathCopyDiffers)
	})
}

// Per-tag: the projection is computed at every tag. A differing newest tag
// stops; a differing OLDER tag behaves exactly as with the flag off (the
// window shrinks, strict-window stops), never accepted silently.
func TestFactEqualChecksEveryTag(t *testing.T) {
	diff := feOpts{versions: "  - name: v1\n    served: true\n    storage: true\n  - name: v0\n    served: true\n    storage: false\n"}
	for i, tag := range ipTags {
		t.Run(tag, func(t *testing.T) {
			src := feSource(func(tg string) []byte {
				if tg == tag {
					return []byte(feDef(diff))
				}
				return []byte(feDef(feOpts{schema: "other"}))
			})
			if i == len(ipTags)-1 {
				infStops(t, feInput(src, true), StopInstallPathCopyDiffers)
				return
			}
			if i == 1 {
				// a middle tag leaves a window of one tag: never accepted
				if res, err := Generate(feInput(src, true)); err == nil {
					t.Fatalf("a differing middle tag must stop, got a draft %+v", res.Report.CRDCount)
				}
				return
			}
			on := mustGenerate(t, feInput(src, true))
			if len(on.Report.Dropped) != 1 || on.Report.Dropped[0].Tag != tag {
				t.Fatalf("a differing tag must be withheld from the window, not accepted: %+v", on.Report.Dropped)
			}
			in := feInput(src, true)
			in.StrictWindow = true
			infStops(t, in, StopWindowShortened)
		})
	}
}

// The option needs copy checks or inference and never applies otherwise.
func TestFactEqualNeedsChecks(t *testing.T) {
	src := feSource(feSame(feOpts{schema: "other"}))
	in := ipInput(src, nil)
	in.AcceptFactEqualCopies = true
	infStops(t, in, StopBadInput)
}

// A copy that defines an extra identity, or cannot be parsed, or has no
// versions at all, is never accepted (hides-crd or unreadable stop).
func TestFactEqualUnreadableOrExtraStays(t *testing.T) {
	for name, copy := range map[string][]byte{
		"extra identity":                     []byte(feDef(feOpts{schema: "other", extraKind: "Gamma"})),
		"no versions":                        []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: " + infGroup + "\n  scope: Namespaced\n  names:\n    kind: Alpha\n    plural: alphas\n"),
		"broken yaml":                        []byte("kind: CustomResourceDefinition\nspec: [\n"),
		"v1beta1 spec.version only":          []byte("apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nspec:\n  group: " + infGroup + "\n  version: v1\n  scope: Namespaced\n  names:\n    kind: Alpha\n    plural: alphas\n"),
		"fact-equal doc plus extra identity": []byte(feDef(feOpts{schema: "other"}) + "---\n" + feDef(feOpts{schema: "other", extraKind: "Gamma"})[strings.Index(feDef(feOpts{extraKind: "Gamma"}), "---\n")+4:]),
		"template syntax":                    []byte("kind: CustomResourceDefinition\nspec:\n  group: {{ .Values.g }}\n"),
	} {
		t.Run(name, func(t *testing.T) {
			src := feSource(func(string) []byte { return copy })
			if res, err := Generate(feInput(src, true)); err == nil {
				t.Fatalf("must stop, got a draft: %+v", res.Report.CRDCount)
			}
		})
	}
	t.Run("hides-crd stays with the option on", func(t *testing.T) {
		src := feSource(feSame(feOpts{extraKind: "Gamma"}))
		infStops(t, feInput(src, true), StopInstallPathHidesCRD)
	})
}

// Copies under .github or testdata are handled exactly as with the flag off:
// the same outcome (stop text or draft bytes), the option changes nothing.
func TestFactEqualDoesNotChangeCIAndTestdataHandling(t *testing.T) {
	for name, p := range map[string]string{
		".github unreadable": ".github/workflows/ci.yml",
		"testdata readable":  "internal/testdata/crd/a.yaml",
		"docs readable":      "docs/crds/a.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			content := feDef(feOpts{scope: "Cluster"})
			if strings.HasPrefix(name, ".github") {
				content = "name: ci\non: push\nenv:\n  x: ${{ secrets.X }}\nkind: CustomResourceDefinition\nspec: [\n"
			}
			src := feSource(feSame(feOpts{}))
			for _, tag := range ipTags {
				src.trees[tag].files[p] = []byte(content)
			}
			offRes, offErr := Generate(feInput(src, false))
			onRes, onErr := Generate(feInput(src, true))
			if (offErr == nil) != (onErr == nil) {
				t.Fatalf("outcome differs: off=%v on=%v", offErr, onErr)
			}
			if offErr != nil {
				if offErr.Error() != onErr.Error() {
					t.Fatalf("stop text differs:\n%v\n%v", offErr, onErr)
				}
				return
			}
			if string(offRes.A) != string(onRes.A) || string(offRes.B) != string(onRes.B) || string(offRes.Changelog) != string(onRes.Changelog) || offRes.Report.FactsDigest != onRes.Report.FactsDigest {
				t.Fatal("option on changed the output")
			}
		})
	}
}

// With the option off, or on without any set-aside copy, every output and the
// facts digest are byte-identical to the plain run.
func TestFactEqualOffIsByteIdentical(t *testing.T) {
	src := feSource(feSame(feOpts{}))
	off := mustGenerate(t, feInput(src, false))
	on := mustGenerate(t, feInput(src, true))
	if string(off.A) != string(on.A) || string(off.B) != string(on.B) || string(off.TableRow) != string(on.TableRow) ||
		string(off.Changelog) != string(on.Changelog) || off.Report.FactsDigest != on.Report.FactsDigest {
		t.Fatal("no set-aside copy: the option must change nothing")
	}
	// With a set-aside copy the target bytes stay equal, only the digest and the
	// changelog show it.
	acc := mustGenerate(t, feInput(feSource(feSame(feOpts{schema: "other"})), true))
	if string(acc.A) != string(off.A) || string(acc.B) != string(off.B) || string(acc.TableRow) != string(off.TableRow) {
		t.Fatal("a set-aside copy must not change the target")
	}
	if acc.Report.FactsDigest == off.Report.FactsDigest {
		t.Fatal("the set-aside copies must be part of the facts digest")
	}
}

// factEqual unit table: each facet alone is load-bearing.
func TestFactEqualFunctionFacets(t *testing.T) {
	base := crd{Group: "g", Kind: "K", Versions: []string{"v1:true:true", "v2:true:false"}, SpecDigest: "d1",
		SpecParts: map[string]string{"spec.scope": "s", "spec.names": "n", "spec.conversion": "c", "spec.versions": "x", "apiVersion": "a"}}
	mod := func(f func(*crd)) crd {
		c := base
		c.Versions = append([]string(nil), base.Versions...)
		c.SpecParts = map[string]string{}
		for k, v := range base.SpecParts {
			c.SpecParts[k] = v
		}
		f(&c)
		return c
	}
	if !factEqual(base, mod(func(c *crd) {
		c.SpecDigest = "d2"
		c.SpecParts["apiVersion"] = "b"
		c.SpecParts["spec.versions"] = "y"
		c.Versions[0], c.Versions[1] = c.Versions[1], c.Versions[0]
	})) {
		t.Fatal("schema, apiVersion and order must not matter")
	}
	for name, f := range map[string]func(*crd){
		"group":           func(c *crd) { c.Group = "h" },
		"kind":            func(c *crd) { c.Kind = "L" },
		"digest empty":    func(c *crd) { c.SpecDigest = "" },
		"parts nil":       func(c *crd) { c.SpecParts = nil },
		"versions empty":  func(c *crd) { c.Versions = nil },
		"flag":            func(c *crd) { c.Versions[0] = "v1:false:true" },
		"version added":   func(c *crd) { c.Versions = append(c.Versions, "v3:true:false") },
		"scope":           func(c *crd) { c.SpecParts["spec.scope"] = "t" },
		"scope missing":   func(c *crd) { delete(c.SpecParts, "spec.scope") },
		"names":           func(c *crd) { c.SpecParts["spec.names"] = "m" },
		"names missing":   func(c *crd) { delete(c.SpecParts, "spec.names") },
		"conversion":      func(c *crd) { c.SpecParts["spec.conversion"] = "z" },
		"conversion gone": func(c *crd) { delete(c.SpecParts, "spec.conversion") },
	} {
		if factEqual(base, mod(f)) || factEqual(mod(f), base) {
			t.Errorf("%s: must be unequal", name)
		}
	}
	empty := mod(func(c *crd) { c.Versions = nil })
	if factEqual(empty, empty) {
		t.Fatal("an empty projection is never equal")
	}
	noConv := mod(func(c *crd) { delete(c.SpecParts, "spec.conversion") })
	if !factEqual(noConv, noConv) {
		t.Fatal("conversion absent on both sides is equal")
	}
}

func feInclusion(cs ...crd) []*inclusion { return []*inclusion{{Path: "i.yaml", CRDs: cs}} }

func feCRD(scope string) crd {
	return crd{Group: "g", Kind: "K", Versions: []string{"v1:true:true"}, SpecDigest: "d-" + scope,
		SpecParts: map[string]string{"spec.scope": scope, "spec.names": "n"}}
}

// Several installed definitions of one key: any differing holder stops, in
// either order; the accepted list stays empty (no stale acceptance).
func TestFactEqualMultipleHoldersAnyDifferentStops(t *testing.T) {
	eq := feCRD("s")
	eq.SpecDigest = "d-other" // digest differs, facts equal
	diff := feCRD("t")
	copyDef := feCRD("s")
	for name, held := range map[string][]crd{"equal then different": {eq, diff}, "different then equal": {diff, eq}} {
		t.Run(name, func(t *testing.T) {
			var in []*inclusion
			for _, h := range held {
				in = append(in, &inclusion{Path: "i.yaml", CRDs: []crd{h}})
			}
			stops, acc := outsideChecksFE(in, []*finding{{Path: "o.yaml", CRDs: []crd{copyDef}}}, true)
			if len(stops) != 1 || stops[0].Code != StopInstallPathCopyDiffers || len(acc) != 0 {
				t.Fatalf("stops=%+v accepted=%v", stops, acc)
			}
		})
	}
	// all holders fact-equal: accepted, no stop
	stops, acc := outsideChecksFE([]*inclusion{{Path: "i.yaml", CRDs: []crd{eq}}, {Path: "j.yaml", CRDs: []crd{eq}}}, []*finding{{Path: "o.yaml", CRDs: []crd{copyDef}}}, true)
	if len(stops) != 0 || len(acc) != 1 {
		t.Fatalf("stops=%+v accepted=%v", stops, acc)
	}
}

// A duplicate identity inside one copy file: one differing document stops.
func TestFactEqualDuplicateIdentityInCopyFile(t *testing.T) {
	inst := feCRD("s")
	inst.SpecDigest = "d-inst"
	same := feCRD("s")
	diff := feCRD("t")
	for name, docs := range map[string][]crd{"equal first": {same, diff}, "different first": {diff, same}} {
		stops, acc := outsideChecksFE(feInclusion(inst), []*finding{{Path: "o.yaml", CRDs: docs}}, true)
		if len(stops) != 1 || stops[0].Code != StopInstallPathCopyDiffers || len(acc) != 0 {
			t.Fatalf("%s: stops=%+v accepted=%v", name, stops, acc)
		}
	}
}

// An empty scope or names digest is never a fact, even when equal on both
// sides.
func TestFactEqualEmptyPartIsUnequal(t *testing.T) {
	for _, p := range []string{"spec.scope", "spec.names"} {
		a, b := feCRD("s"), feCRD("s")
		a.SpecParts[p], b.SpecParts[p] = "", ""
		if factEqual(a, b) {
			t.Fatalf("empty %s must be unequal", p)
		}
	}
}
