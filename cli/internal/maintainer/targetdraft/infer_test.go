// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const infGroup = "widgets.example.test"

// infCRD is a definition with a description so a twin can differ in the spec.
func infCRD(kind, desc string) string {
	return "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec:\n  group: " + infGroup +
		"\n  names:\n    kind: " + kind + "\n  versions:\n  - name: v1\n    served: true\n    storage: true\n    schema:\n      openAPIV3Schema:\n        description: " + desc + "\n"
}

// infTree builds a tree: path -> kinds defined in the file (description "d").
func infTree(files map[string][]string) *memTree {
	m := newMemTree()
	for p, kinds := range files {
		var docs []string
		for _, k := range kinds {
			docs = append(docs, infCRD(k, "d"))
		}
		m.files[p] = ipDocs(docs...)
	}
	m.files["README.md"] = []byte("not a definition")
	return m
}

// infSource serves every ipTags tag with the same files; mutate may change one.
func infSource(files map[string][]string, mutate func(tag string, m *memTree)) memSource {
	s := memSource{trees: map[string]*memTree{}}
	for _, tag := range ipTags {
		m := infTree(files)
		if mutate != nil {
			mutate(tag, m)
		}
		s.trees[tag] = m
	}
	return s
}

func infInput(src Source) Input {
	in := ipInput(src, nil)
	in.InferInstallPaths = true
	return in
}

// A control layout: config/crd/bases is the install directory, every other
// place holds an equal copy.
func infControl() map[string][]string {
	return map[string][]string{
		"config/crd/bases/a.yaml":      {"Alpha"},
		"config/crd/bases/b.yaml":      {"Beta"},
		"charts/x/crds/all.yaml":       {"Alpha", "Beta"},
		"bundle/manifests/all.yaml":    {"Alpha", "Beta"},
		"docs/crds/a.yaml":             {"Alpha"},
		"internal/testdata/crd/a.yaml": {"Alpha"},
	}
}

func infStops(t *testing.T, in Input, code string) *StopError {
	t.Helper()
	res, err := Generate(in)
	if err == nil {
		t.Fatalf("want stop %s, got a draft (%d CRDs)", code, res.Report.CRDCount)
	}
	if res != nil {
		t.Fatal("a stop must return no result")
	}
	return wantStop(t, err, code)
}

func TestInferControlPicksRankOneAndReportsCopies(t *testing.T) {
	res := mustGenerate(t, infInput(infSource(infControl(), nil)))
	inf := res.Report.InferredInstallPaths
	if inf == nil || inf.Rule != "R2" || inf.Rank != 1 || strings.Join(inf.Paths, ",") != "config/crd/bases/" {
		t.Fatalf("inferred: %+v", inf)
	}
	if len(inf.Tags) != len(ipTags) {
		t.Fatalf("rank evidence per tag: %+v", inf.Tags)
	}
	if res.Report.CRDCount != 2 {
		t.Fatalf("crd count %d", res.Report.CRDCount)
	}
	got := map[string]bool{}
	for _, c := range res.Report.NonInstallCopies {
		got[c.Path] = true
	}
	for _, p := range []string{"charts/x/crds/all.yaml", "bundle/manifests/all.yaml", "docs/crds/a.yaml", "internal/testdata/crd/a.yaml"} {
		if !got[p] {
			t.Fatalf("identical copy %s must be reported as a non-install copy: %+v", p, res.Report.NonInstallCopies)
		}
	}
	a := string(res.A)
	if !strings.Contains(a, "config/crd/bases/a.yaml") || strings.Contains(a, "charts/") || strings.Contains(a, "bundle/") || strings.Contains(a, "docs/") {
		t.Fatalf("target must list only the inferred directory's files:\n%s", a)
	}
	if !strings.Contains(string(res.Changelog), "inferred") {
		t.Fatal("changelog must say the paths were inferred")
	}
}

func TestInferDeterministic(t *testing.T) {
	a := mustGenerate(t, infInput(infSource(infControl(), nil)))
	b := mustGenerate(t, infInput(infSource(infControl(), nil)))
	ra, _ := json.Marshal(a.Report)
	rb, _ := json.Marshal(b.Report)
	if !bytes.Equal(a.A, b.A) || !bytes.Equal(a.B, b.B) || !bytes.Equal(ra, rb) || !bytes.Equal(a.Changelog, b.Changelog) {
		t.Fatal("two runs differ")
	}
}

func TestInferChartOnlyUsesRankThree(t *testing.T) {
	files := map[string][]string{
		"charts/x/crds/a.yaml":      {"Alpha"},
		"charts/x/crds/b.yaml":      {"Beta"},
		"bundle/manifests/all.yaml": {"Alpha", "Beta"},
	}
	res := mustGenerate(t, infInput(infSource(files, nil)))
	if inf := res.Report.InferredInstallPaths; inf.Rank != 3 || inf.Paths[0] != "charts/x/crds/" {
		t.Fatalf("inferred: %+v", inf)
	}
}

func TestInferRankOneBeatsRankTwo(t *testing.T) {
	files := map[string][]string{
		"config/crd/a.yaml": {"Alpha", "Beta"},
		"pkg/crds/all.yaml": {"Alpha", "Beta"},
	}
	res := mustGenerate(t, infInput(infSource(files, nil)))
	if inf := res.Report.InferredInstallPaths; inf.Rank != 1 || inf.Paths[0] != "config/crd/" {
		t.Fatalf("inferred: %+v", inf)
	}
	// A definition only the rank-2 directory holds joins the tier: two
	// directories, no single choice.
	files["pkg/crds/all.yaml"] = []string{"Alpha", "Beta", "Gamma"}
	infStops(t, infInput(infSource(files, nil)), StopInstallPathAmbiguous)
	// A rank-2 twin with another spec is compared, not ignored.
	files["pkg/crds/all.yaml"] = nil
	src := infSource(files, func(tag string, m *memTree) {
		m.files["pkg/crds/all.yaml"] = ipDocs(infCRD("Alpha", "changed"), infCRD("Beta", "d"))
	})
	infStops(t, infInput(src), StopInstallPathCopyDiffers)
}

// Seed (a): the only ranked source is a docs / test / bundle copy.
func TestInferDecoyOnlyIsAmbiguous(t *testing.T) {
	for name, files := range map[string]map[string][]string{
		"docs":       {"docs/crds/a.yaml": {"Alpha"}},
		"test":       {"test/e2e/crds/a.yaml": {"Alpha"}},
		"testdata":   {"config/crd/testdata/a.yaml": {"Alpha"}},
		"bundle":     {"bundle/manifests/crds/a.yaml": {"Alpha"}},
		"olm":        {"olm/crds/a.yaml": {"Alpha"}},
		"templates":  {"charts/x/templates/crds/a.yaml": {"Alpha"}},
		"vendor":     {"vendor/x/config/crd/a.yaml": {"Alpha"}},
		"unranked":   {"deploy/a.yaml": {"Alpha"}},
		"nothing":    {},
		"bundle-dir": {"bundles/config/crd/a.yaml": {"Alpha"}},
	} {
		t.Run(name, func(t *testing.T) {
			infStops(t, infInput(infSource(files, nil)), StopInstallPathAmbiguous)
		})
	}
}

// Seed (b)/(f): a definition that exists only outside the chosen directory.
func TestInferHiddenDefinitionOutsideStops(t *testing.T) {
	files := infControl()
	files["deploy/extra.yaml"] = []string{"Gamma"}
	se := infStops(t, infInput(infSource(files, nil)), StopInstallPathHidesCRD)
	if !strings.Contains(se.Error(), "Gamma") {
		t.Fatalf("stop must name the hidden key: %v", se)
	}
	// Same through a bundle copy that holds a kind no install file holds.
	files = infControl()
	files["bundle/manifests/all.yaml"] = []string{"Alpha", "Beta", "Gamma"}
	infStops(t, infInput(infSource(files, nil)), StopInstallPathHidesCRD)
}

// A narrower directory than the real surface: a second kind lives elsewhere.
func TestInferDropOneDirectoryStopsAmbiguous(t *testing.T) {
	files := map[string][]string{
		"config/crd/bases/a.yaml": {"Alpha"},
		"pkg/crds/b.yaml":         {"Beta"},
	}
	infStops(t, infInput(infSource(files, nil)), StopInstallPathAmbiguous)
}

// Seed (c): a lower-rank directory with a non-duplicate definition.
func TestInferLowerRankNonDuplicateStops(t *testing.T) {
	files := infControl()
	files["charts/y/crds/z.yaml"] = []string{"Gamma"}
	// Rank 3 never joins a rank 1 choice; the definition it alone holds is
	// the hidden one.
	infStops(t, infInput(infSource(files, nil)), StopInstallPathHidesCRD)
}

// Seed (e): two equal-rank candidates for the same definition.
func TestInferTwoEqualRankDirectoriesAmbiguous(t *testing.T) {
	files := map[string][]string{
		"a/config/crd/x.yaml": {"Alpha"},
		"b/config/crd/x.yaml": {"Alpha"},
	}
	se := infStops(t, infInput(infSource(files, nil)), StopInstallPathAmbiguous)
	if !strings.Contains(se.Error(), "a/config/crd/") || !strings.Contains(se.Error(), "b/config/crd/") {
		t.Fatalf("both candidates must be named: %v", se)
	}
	files = map[string][]string{
		"pkg/a/crds/x.yaml": {"Alpha"},
		"pkg/b/crds/x.yaml": {"Alpha"},
	}
	infStops(t, infInput(infSource(files, nil)), StopInstallPathAmbiguous)
}

// Seed (h): the candidate exists only at some tags. Every tag is checked.
func TestInferCandidateMissingAtOlderTagStops(t *testing.T) {
	for _, tag := range ipTags {
		tag := tag
		t.Run("missing "+tag, func(t *testing.T) {
			src := infSource(infControl(), func(tg string, m *memTree) {
				if tg == tag {
					delete(m.files, "config/crd/bases/a.yaml")
					delete(m.files, "config/crd/bases/b.yaml")
				}
			})
			se := infStops(t, infInput(src), StopInstallPathAmbiguous)
			if !strings.Contains(se.Error(), tag) && tag != ipTags[0] {
				// the stop names the first tag whose choice differs
				t.Logf("stop: %v", se)
			}
		})
	}
	// Candidate of the same rank but another directory at the oldest tag.
	src := infSource(infControl(), func(tg string, m *memTree) {
		if tg == ipTags[0] {
			for _, k := range []string{"a", "b"} {
				m.files["config/crd/old/"+k+".yaml"] = m.files["config/crd/bases/"+k+".yaml"]
				delete(m.files, "config/crd/bases/"+k+".yaml")
			}
		}
	})
	infStops(t, infInput(src), StopInstallPathAmbiguous)
}

// Seed (d): the chart twin carries another spec.
func TestInferChartTwinDiffersStops(t *testing.T) {
	for name, mutate := range map[string]func(tag string, m *memTree){
		"newest description": func(tag string, m *memTree) {
			if tag == ipTags[len(ipTags)-1] {
				m.files["charts/x/crds/all.yaml"] = ipDocs(infCRD("Alpha", "changed"), infCRD("Beta", "d"))
			}
		},
		"extra version": func(tag string, m *memTree) {
			if tag == ipTags[len(ipTags)-1] {
				m.files["charts/x/crds/all.yaml"] = ipDocs(infCRD("Alpha", "d")+"  - name: v2\n    served: true\n    storage: false\n", infCRD("Beta", "d"))
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			se := infStops(t, infInput(infSource(infControl(), mutate)), StopInstallPathCopyDiffers)
			if !strings.Contains(se.Error(), "charts/x/crds/all.yaml") {
				t.Fatalf("stop must name the copy: %v", se)
			}
		})
	}
	// The same twin at an OLDER tag shrinks the window instead of ending the
	// run; the newest tag is the one that decides.
	src := infSource(infControl(), func(tag string, m *memTree) {
		if tag == ipTags[0] {
			m.files["charts/x/crds/all.yaml"] = ipDocs(infCRD("Alpha", "changed"), infCRD("Beta", "d"))
		}
	})
	res := mustGenerate(t, infInput(src))
	if len(res.Report.Dropped) != 1 || res.Report.Dropped[0].Tag != ipTags[0] {
		t.Fatalf("older tag with a differing twin must be withheld: %+v", res.Report.Dropped)
	}
	in := infInput(src)
	in.StrictWindow = true
	infStops(t, in, StopWindowShortened)
}

// The comparator is the one shared function: weakening it removes the stop, so
// the seeds above depend on it.
func TestInferCopyDiffersDependsOnComparator(t *testing.T) {
	src := infSource(infControl(), func(tag string, m *memTree) {
		m.files["charts/x/crds/all.yaml"] = ipDocs(infCRD("Alpha", "changed"), infCRD("Beta", "d"))
	})
	infStops(t, infInput(src), StopInstallPathCopyDiffers)
	saved := crdsEqual
	crdsEqual = func(a, b crd) bool { return true }
	defer func() { crdsEqual = saved }()
	if _, err := Generate(infInput(src)); hasStopCode(err, StopInstallPathCopyDiffers) {
		t.Fatal("with a weakened comparator the stop must be gone (proves the seed exercises it)")
	}
}

// A twin whose spec cannot be digested is never treated as equal.
func TestInferEmptyDigestNeverEqual(t *testing.T) {
	saved := crdsEqual
	defer func() { crdsEqual = saved }()
	stops := outsideChecks(
		[]*inclusion{{Path: "i.yaml", CRDs: []crd{{Group: "g", Kind: "K", SpecDigest: ""}}}},
		[]*finding{{Path: "o.yaml", CRDs: []crd{{Group: "g", Kind: "K", SpecDigest: ""}}}})
	if len(stops) != 1 || stops[0].Code != StopInstallPathCopyDiffers {
		t.Fatalf("stops: %+v", stops)
	}
}

// The directory entry would read a file the ranking does not accept.
func TestInferDirectoryReadingUnrankedFileStops(t *testing.T) {
	for name, extra := range map[string]string{
		"skipped subdir": "config/crd/bases/test/c.yaml",
		"deeper subdir":  "config/crd/bases/legacy/c.yaml",
		"docs subdir":    "config/crd/bases/docs/c.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			files := infControl()
			files[extra] = []string{"Alpha"}
			infStops(t, infInput(infSource(files, nil)), StopInstallPathAmbiguous)
		})
	}
}

// An unreadable definition file that ranks as well as the choice is never
// guessed around.
func TestInferUnreadableCandidateStops(t *testing.T) {
	bad := func(tag string, m *memTree) {
		m.files["other/config/crd/x.yaml"] = []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec: {{ .Values.x }}\n")
	}
	src := infSource(infControl(), bad)
	// Make sure the fixture really is an unreadable definition file.
	fs, _ := scanTree(src.trees[ipTags[0]])
	found := false
	for _, f := range fs {
		if f.Path == "other/config/crd/x.yaml" && f.Unreadable != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("fixture is not an unreadable definition file")
	}
	infStops(t, infInput(src), StopInstallPathAmbiguous)
}

func TestInferInputRefusals(t *testing.T) {
	hand := ipRules(t, "["+ipEntry+"]")
	in := infInput(ipSource(nil))
	in.Rules = hand
	infStops(t, in, StopBadInput)

	surf, err := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[{"path":"manifests/all.yaml","reason":"r"}],"exclusions":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	in = infInput(ipSource(nil))
	in.Rules = surf
	infStops(t, in, StopBadInput)

	in = infInput(ipSource(nil))
	in.RangeCheckTags = ipTags
	infStops(t, in, StopBadInput)

	ex, err := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[{"class":"exact-file","path":"hack/x.yaml","reason":"r","evidence":"e"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	in = infInput(ipSource(nil))
	in.Rules = ex
	infStops(t, in, StopBadInput)

	// The check on its own needs a hand list.
	in = ipInput(ipSource(nil), nil)
	in.CheckInstallPathCopies = true
	infStops(t, in, StopBadInput)

	// A refused run never mutates the caller's rules.
	if len(hand.InstallPaths) != 1 || hand.checkCopies {
		t.Fatal("caller rules changed")
	}
}

func TestInferDoesNotMutateRulesAndKeepsExclusions(t *testing.T) {
	rules, err := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	in := infInput(infSource(infControl(), nil))
	in.Rules = rules
	mustGenerate(t, in)
	if len(rules.InstallPaths) != 0 || rules.checkCopies {
		t.Fatal("inference must work on a copy of the rules")
	}
}

// --- hand installPaths with --check-install-path-copies ------------------

func handInput(t *testing.T, files map[string][]string, mutate func(tag string, m *memTree), check bool) Input {
	t.Helper()
	in := ipInput(infSource(files, mutate), ipRules(t, `[{"path":"config/crd/bases/","reason":"r","evidence":"e"}]`))
	in.CheckInstallPathCopies = check
	return in
}

func TestHandPathHidingACRDIsRefusedOnlyWithTheFlag(t *testing.T) {
	files := infControl()
	files["deploy/extra.yaml"] = []string{"Gamma"}
	// Flag off: the existing behaviour, the gap stays documented here.
	res := mustGenerate(t, handInput(t, files, nil, false))
	if res.Report.InferredInstallPaths != nil {
		t.Fatal("no inference block without the flag")
	}
	infStops(t, handInput(t, files, nil, true), StopInstallPathHidesCRD)
}

func TestHandPathCopyDiffersRefusedOnlyWithTheFlag(t *testing.T) {
	mut := func(tag string, m *memTree) {
		m.files["charts/x/crds/all.yaml"] = ipDocs(infCRD("Alpha", "changed"), infCRD("Beta", "d"))
	}
	mustGenerate(t, handInput(t, infControl(), mut, false))
	infStops(t, handInput(t, infControl(), mut, true), StopInstallPathCopyDiffers)
}

// Flag off and flag on with only identical copies produce the same bytes: the
// flag adds stops, never a field or a digest change for a hand path.
func TestHandFlagAddsNoFieldWhenCopiesAreEqual(t *testing.T) {
	off := mustGenerate(t, handInput(t, infControl(), nil, false))
	on := mustGenerate(t, handInput(t, infControl(), nil, true))
	ro, _ := json.Marshal(off.Report)
	rn, _ := json.Marshal(on.Report)
	if !bytes.Equal(off.A, on.A) || !bytes.Equal(off.B, on.B) || !bytes.Equal(ro, rn) || !bytes.Equal(off.Changelog, on.Changelog) || !bytes.Equal(off.TableRow, on.TableRow) {
		t.Fatal("the check flag must not change the output of a passing hand path")
	}
	if strings.Contains(string(ro), "inferredInstallPaths") {
		t.Fatal("inference field in a hand run")
	}
}

// Inference off: the default output has no inference field and equals the
// previous behaviour (the pinned goldens of the other tests cover the bytes).
func TestInferOffByDefaultLeavesNoTrace(t *testing.T) {
	res := mustGenerate(t, ipInput(ipSource(nil), rulesFrom(t, "testdata/installpaths/rules.json")))
	rep, _ := json.Marshal(res.Report)
	if strings.Contains(string(rep), "inferred") {
		t.Fatal("default run mentions inference")
	}
	// No installPaths and no flag: the plain run still stops on the copies.
	_, err := Generate(ipInput(ipSource(nil), nil))
	if err == nil {
		t.Fatal("the plain run of this fixture stops on its duplicates")
	}
}

// Excluded files are reviewed judgments and keep their own stops; the new
// checks do not re-judge them.
func TestHandCheckSkipsReviewedExclusions(t *testing.T) {
	files := infControl()
	files["hack/foreign.yaml"] = []string{"Gamma"}
	rules, err := ParseRules([]byte(`{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[{"class":"exact-file","path":"hack/foreign.yaml","reason":"r","evidence":"e"}],"installPaths":[{"path":"config/crd/bases/","reason":"r","evidence":"e"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	in := ipInput(infSource(files, nil), rules)
	in.CheckInstallPathCopies = true
	// The exact-file exclusion defines an owned group here (same group as the
	// install files), which its own rule refuses; the new check must not
	// have replaced that stop.
	_, gerr := Generate(in)
	if !hasStopCode(gerr, StopExclusionOwnedGroup) {
		t.Fatalf("want the exclusion's own stop, got %v", gerr)
	}
	if hasStopCode(gerr, StopInstallPathHidesCRD) {
		t.Fatal("an excluded file must not be judged by the hides check")
	}
}

// --- digest --------------------------------------------------------------

func TestInferFactsDigestCoversTheInference(t *testing.T) {
	inferred := mustGenerate(t, infInput(infSource(infControl(), nil)))
	in := ipInput(infSource(infControl(), nil), ipRules(t, `[{"path":"config/crd/bases/","reason":"r","evidence":"e"}]`))
	hand := mustGenerate(t, in)
	if inferred.Report.FactsDigest == hand.Report.FactsDigest {
		t.Fatal("an inferred run must not share the digest of a hand run")
	}
	// Different ranking evidence (an extra decoy candidate) changes the digest.
	files := infControl()
	files["tools/crds/a.yaml"] = []string{"Alpha"}
	other := mustGenerate(t, infInput(infSource(files, nil)))
	if other.Report.FactsDigest == inferred.Report.FactsDigest {
		t.Fatal("the rank evidence must be part of the digest")
	}
}

// --- interactions: inference first, then collapse, derive, multi-prefix ---

func TestInferThenCollapse(t *testing.T) {
	in := infInput(infSource(infControl(), nil))
	in.CollapseDirectories = true
	res := mustGenerate(t, in)
	if res.Report.Representation != "directory" || len(res.Report.Directories) != 1 || res.Report.Directories[0].Dir != "config/crd/bases" {
		t.Fatalf("collapse of the inferred directory: %+v", res.Report.Directories)
	}
	if res.Report.InferredInstallPaths == nil {
		t.Fatal("inference block lost")
	}
	// A directory that holds a non-install file the entry would read still
	// stops in the collapse proof.
	src := infSource(infControl(), func(tag string, m *memTree) {
		if tag == ipTags[len(ipTags)-1] {
			m.files["config/crd/bases/crd-notes.yaml"] = []byte("a: b\n")
		}
	})
	in = infInput(src)
	in.CollapseDirectories = true
	if _, err := Generate(in); err == nil {
		t.Fatal("collapse must still prove the directory")
	}
}

func inferDupFiles() map[string][]string {
	return map[string][]string{
		"config/crd/bases/a.yaml":      {"Alpha"},
		"config/crd/bases/a-copy.yaml": {"Alpha"},
		"config/crd/bases/b.yaml":      {"Beta"},
	}
}

func TestInferThenDeriveDuplicates(t *testing.T) {
	// Without the derivation the duplicate stays a stop.
	infStops(t, infInput(infSource(inferDupFiles(), nil)), StopDuplicateCRD)
	in := infInput(infSource(inferDupFiles(), nil))
	in.DeriveDuplicates = true
	res := mustGenerate(t, in)
	if res.Report.InferredInstallPaths == nil || len(res.Report.DerivedSources) != 1 {
		t.Fatalf("both blocks expected: %+v", res.Report)
	}
	if strings.Count(string(res.A), "config/crd/bases/") != 2 {
		t.Fatalf("one copy kept, so two files in the target:\n%s", res.A)
	}
	// Copies that differ stay a stop (the derivation's own proof).
	src := infSource(inferDupFiles(), func(tag string, m *memTree) {
		m.files["config/crd/bases/a-copy.yaml"] = ipDocs(infCRD("Alpha", "other"))
	})
	in = infInput(src)
	in.DeriveDuplicates = true
	if _, err := Generate(in); err == nil {
		t.Fatal("differing copies must stop")
	}
	// A hidden definition outside the directory is not rescued by the
	// derivation: its stop is not duplicate-crd, so the derivation is not even
	// eligible.
	files := inferDupFiles()
	files["deploy/extra.yaml"] = []string{"Gamma"}
	in = infInput(infSource(files, nil))
	in.DeriveDuplicates = true
	infStops(t, in, StopInstallPathHidesCRD)
}

func TestInferThenMultiPrefix(t *testing.T) {
	in := mpInput(mpTags, mpSource(mpTags, nil), true, false)
	in.InferInstallPaths = true
	res := mustGenerate(t, in)
	if res.Report.InferredInstallPaths == nil || res.Report.InferredInstallPaths.Paths[0] != "config/crd/" || len(res.Report.PrefixWindows) != 2 {
		t.Fatalf("report: %+v", res.Report)
	}
	// The newer prefix family keeps its definitions elsewhere: no common set.
	src := mpSource(mpTags, func(tag string, m *memTree) {
		if strings.HasPrefix(tag, "v") {
			m.files["pkg/crds/a.yaml"] = m.files["config/crd/a.yaml"]
			m.files["pkg/crds/b.yaml"] = m.files["config/crd/b.yaml"]
			delete(m.files, "config/crd/a.yaml")
			delete(m.files, "config/crd/b.yaml")
		}
	})
	in = mpInput(mpTags, src, true, false)
	in.InferInstallPaths = true
	infStops(t, in, StopInstallPathAmbiguous)
}

// --- CLI -------------------------------------------------------------------

func TestCLIInferFlags(t *testing.T) {
	src := infSource(infControl(), nil)
	open := func(string) Source { return src }
	args := func(out string, extra ...string) []string {
		return append([]string{"generate", "--dir", "x", "--slug", "widgets", "--name", "Widgets", "--repo", "github.com/example/widgets", "--tags", strings.Join(ipTags, ","), "--out", out}, extra...)
	}
	out := filepath.Join(t.TempDir(), "o")
	var so, se bytes.Buffer
	if code := run(args(out, "--infer-install-paths"), &so, &se, open); code != 0 {
		t.Fatalf("exit %d: %s %s", code, so.String(), se.String())
	}
	rep, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil || !strings.Contains(string(rep), `"inferredInstallPaths"`) || !strings.Contains(string(rep), "config/crd/bases/") {
		t.Fatalf("report: %v %s", err, rep)
	}
	// Default off: the same input without the flag writes no inference block
	// (and stops on the duplicates of this fixture: nothing written).
	out2 := filepath.Join(t.TempDir(), "o")
	so.Reset()
	if code := run(args(out2), &so, &se, open); code != 1 {
		t.Fatalf("flag off must keep its own result, exit %d: %s", code, so.String())
	}
	if _, err := os.Stat(out2); err == nil {
		if ents, _ := os.ReadDir(out2); len(ents) > 0 {
			t.Fatal("a stop must write nothing")
		}
	}
	// A typed stop exits 1 and writes nothing.
	bad := infSource(map[string][]string{"docs/crds/a.yaml": {"Alpha"}}, nil)
	out3 := filepath.Join(t.TempDir(), "o")
	so.Reset()
	if code := run(args(out3, "--infer-install-paths"), &so, &se, func(string) Source { return bad }); code != 1 || !strings.Contains(so.String(), StopInstallPathAmbiguous) {
		t.Fatalf("exit %d: %s", code, so.String())
	}
	if ents, _ := os.ReadDir(out3); len(ents) > 0 {
		t.Fatal("a stop must write nothing")
	}
	// The check flag alone needs a rules file with installPaths.
	so.Reset()
	if code := run(args(filepath.Join(t.TempDir(), "o"), "--check-install-path-copies"), &so, &se, open); code != 1 || !strings.Contains(so.String(), StopBadInput) {
		t.Fatalf("exit %d: %s", code, so.String())
	}
}

func TestInferRankTable(t *testing.T) {
	for p, want := range map[string]int{
		"config/crd/bases/a.yaml":           1,
		"config/crds/a.yaml":                1,
		"operator/config/crd/a.yaml":        1,
		"pkg/crds/a.yaml":                   2,
		"crd/a.yaml":                        2,
		"charts/x/crds/a.yaml":              3,
		"helm/x/crd/a.yaml":                 3,
		"charts/x/config/crd/a.yaml":        3,
		"charts/x/templates/crds/a.yaml":    0,
		"bundle/manifests/a.yaml":           0,
		"bundles/crds/a.yaml":               0,
		"docs/crds/a.yaml":                  0,
		"test/crds/a.yaml":                  0,
		"config/crd/testdata/a.yaml":        0,
		"vendor/x/crds/a.yaml":              0,
		"examples/crds/a.yaml":              0,
		"deploy/a.yaml":                     0,
		"a.yaml":                            0,
		"CONFIG/CRD/a.yaml":                 1,
		"config/crd-extra/a.yaml":           0,
		"third_party/config/crd/a.yaml":     0,
		"hack/config/crd/a.yaml":            0,
		"config/crds/samples/a.yaml":        0,
		"node_modules/x/config/crd/a.yaml":  0,
		"config/crd/bases/output/a.yaml":    0,
		"config/crd/bases/dist/a.yaml":      0,
		"config/crd/bases/e2e/a.yaml":       0,
		"config/crd/bases/olm-catalog/a.ym": 0,
	} {
		if got := inferRank(p); got != want {
			t.Errorf("inferRank(%q) = %d, want %d", p, got, want)
		}
	}
}

func unreadableAt(path string) func(tag string, m *memTree) {
	return func(tag string, m *memTree) {
		m.files[path] = []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec: {{ .Values.x }}\n")
	}
}

// An unreadable file outside the chosen directory may define anything: a stop
// everywhere except below a skipped directory.
func TestUnreadableOutsideFileStopsUnlessSkippedDir(t *testing.T) {
	for _, p := range []string{"deploy/x.yaml", "install/x.yaml", "charts/x/crds/y.yaml", "manifests/x.yaml", "pkg/foo/x.yaml"} {
		p := p
		t.Run("stop "+p, func(t *testing.T) {
			mut := unreadableAt(p)
			// the fixture must be an unreadable definition file
			m := infTree(infControl())
			mut("", m)
			fs, _ := scanTree(m)
			ok := false
			for _, f := range fs {
				if f.Path == p && f.Unreadable != "" {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("%s is not an unreadable definition file", p)
			}
			infStops(t, infInput(infSource(infControl(), mut)), StopInstallPathHidesCRD)
			// the hand path with the flag is held to the same rule
			infStops(t, handInput(t, infControl(), mut, true), StopInstallPathHidesCRD)
			// flag off: the existing behaviour
			mustGenerate(t, handInput(t, infControl(), mut, false))
		})
	}
	for _, p := range []string{"docs/x.yaml", "test/x.yaml", "vendor/x.yaml", "charts/x/templates/x.yaml", "bundle/x.yaml", "olm/x.yaml"} {
		p := p
		t.Run("pass "+p, func(t *testing.T) {
			res := mustGenerate(t, infInput(infSource(infControl(), unreadableAt(p))))
			found := false
			for _, c := range res.Report.NonInstallCopies {
				if c.Path == p && c.Unreadable != "" {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s must stay a reported unreadable non-install copy", p)
			}
		})
	}
}

func TestInferCandidateOrderPinned(t *testing.T) {
	files := infControl()
	files["tools/crds/a.yaml"] = []string{"Alpha"}
	files["aaa/crds/a.yaml"] = []string{"Alpha"}
	files["charts/w/crds/a.yaml"] = []string{"Alpha"}
	res := mustGenerate(t, infInput(infSource(files, nil)))
	var got []string
	for _, c := range res.Report.InferredInstallPaths.Tags[0].Candidates {
		got = append(got, c.Dir+"@"+string(rune('0'+c.Rank)))
	}
	want := "config/crd/bases/@1,aaa/crds/@2,tools/crds/@2,charts/w/crds/@3,charts/x/crds/@3"
	if strings.Join(got, ",") != want {
		t.Fatalf("candidates %v", got)
	}
}

func TestInferChangelogStatesDerivePaths(t *testing.T) {
	in := infInput(infSource(inferDupFiles(), nil))
	in.DeriveDuplicates = true
	res := mustGenerate(t, in)
	if !strings.Contains(string(res.Changelog), "derived exact files") {
		t.Fatal("changelog must say the derived files are read")
	}
	plain := mustGenerate(t, infInput(infSource(infControl(), nil)))
	if strings.Contains(string(plain.Changelog), "derived exact files") {
		t.Fatal("no derive sentence without derivation")
	}
}

func unreadableDef() []byte {
	return []byte("apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nspec: {{ .Values.x }}\n")
}

// linkedUnreadable puts an unreadable definition at target and a link to it at
// link, and asserts the scanner sees it as unreadable and reached by the link.
func linkedUnreadable(t *testing.T, link, target string) func(tag string, m *memTree) {
	t.Helper()
	mut := func(tag string, m *memTree) {
		m.files[target] = unreadableDef()
		m.links[link] = relTo(link, target)
	}
	m := infTree(infControl())
	mut("", m)
	fs, _ := scanTree(m)
	ok := false
	for _, f := range fs {
		if f.Path == target && f.Unreadable != "" && len(f.Reached) == 1 && f.Reached[0] == link {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("fixture %s -> %s is not an unreadable definition reached through the link", link, target)
	}
	return mut
}

// relTo is the relative link text from link to target (both repository paths).
func relTo(link, target string) string {
	up := strings.Count(link, "/")
	return strings.Repeat("../", up) + target
}

func TestUnreadableSkippedFileReachedByInstallLinkStops(t *testing.T) {
	mut := linkedUnreadable(t, "deploy/link.yaml", "docs/bad.yaml")
	infStops(t, infInput(infSource(infControl(), mut)), StopInstallPathHidesCRD)
	infStops(t, handInput(t, infControl(), mut, true), StopInstallPathHidesCRD)
	// Flag off keeps the existing output.
	mustGenerate(t, handInput(t, infControl(), mut, false))
}

func TestUnreadableSkippedFileReachedOnlyBySkippedLinkPasses(t *testing.T) {
	mut := linkedUnreadable(t, "test/link.yaml", "docs/bad.yaml")
	res := mustGenerate(t, infInput(infSource(infControl(), mut)))
	found := false
	for _, c := range res.Report.NonInstallCopies {
		if c.Path == "docs/bad.yaml" && c.Unreadable != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("must stay a reported unreadable copy: %+v", res.Report.NonInstallCopies)
	}
	mustGenerate(t, handInput(t, infControl(), mut, true))
}

// Hand path with the flag: an unreadable file under docs/ without any
// non-skipped link passes and is reported.
func TestHandCheckUnreadableUnderDocsPasses(t *testing.T) {
	res := mustGenerate(t, handInput(t, infControl(), unreadableAt("docs/bad.yaml"), true))
	found := false
	for _, c := range res.Report.NonInstallCopies {
		if c.Path == "docs/bad.yaml" && c.Unreadable != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("not reported: %+v", res.Report.NonInstallCopies)
	}
}
