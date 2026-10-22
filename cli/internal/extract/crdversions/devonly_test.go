// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

const (
	kwokDir    = "scripts/config/kwok/"
	devTarget  = "dev-lab-kwok"
	devBase    = "dev-lab-base"
	devApplied = "\t@kubectl apply -k ./scripts/config/kwok\n"
	// devMakefile is the shape of the kyverno case: a default goal, the
	// target declared phony, one rule that applies the excluded directory.
	devMakefile = "all:\n\t@echo all\n\n.PHONY: dev-lab-kwok\ndev-lab-kwok:\n" + devApplied
)

func kwokExclusion() Exclusion {
	return Exclusion{Path: kwokDir, Repo: "github.com/argoproj/argo-cd", Reason: "a kustomization for a local test cluster", Evidence: "only applied by the dev-lab-kwok target of the Makefile, which starts a local lab; no install path names it"}
}

func devEntry(makefile, target string) DevOnlyMake {
	return DevOnlyMake{Makefile: makefile, Target: target, Reason: "starts a local lab cluster", Evidence: "the target only applies the lab kustomization to a local kwok cluster; nothing else runs it"}
}

// devPair runs a pair whose trees hold the kwok-shaped Makefile and the
// given files (they replace it by path), with the given entries, and
// returns the later release's record of each.
func devPair(t *testing.T, extra map[string]string, entries ...DevOnlyMake) (extract.PairRecord, PairProof) {
	t.Helper()
	files := map[string]string{
		"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1"),
		kwokDir + "crd.yaml": crd("Gamma", "v1"),
		"Makefile":           devMakefile,
	}
	later := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), kwokDir + "crd.yaml": crd("Gamma", "v1"), "Makefile": devMakefile}
	for p, c := range extra {
		files[p], later[p] = c, c
	}
	tg := synthTarget(kwokExclusion())
	tg.DevOnlyMake = entries
	return pairOf(t, runSynth(t, tg, newSynth(release{"v1.0.0", files}, release{"v1.1.0", later})), "1.0.0", "1.1.0")
}

func TestDevOnlyMake(t *testing.T) {
	one := []DevOnlyMake{devEntry("Makefile", devTarget)}
	both := []DevOnlyMake{devEntry("Makefile", devBase), devEntry("Makefile", devTarget)}
	chain := "all:\n\t@echo all\n\n.PHONY: dev-lab-kwok dev-lab-base\ndev-lab-kwok: dev-lab-base\n" + devApplied + "dev-lab-base:\n\t@kubectl apply -k ./scripts/config/kwok/base\n"
	// big holds more distinct words than a file may keep for the check.
	var big strings.Builder
	big.WriteString("X :=")
	for i := 0; i <= maxDevUses; i++ {
		fmt.Fprintf(&big, " w%d", i)
	}
	big.WriteString("\n")
	waived := []DevOnlyWaiver{{Exclusion: kwokDir, Token: "./scripts/config/kwok"}}
	cases := []struct {
		name    string
		extra   map[string]string
		entries []DevOnlyMake
		// why is empty for an applied entry, else a part of the reason.
		why string
		// void: the exclusion is void at the tag.
		void bool
		// waived and docs are wanted in the record of the first entry
		// (waived nil: none).
		waived []DevOnlyWaiver
		docs   []string
		// baseWaived is wanted in the record of the first of two entries.
		baseWaived []DevOnlyWaiver
		// baseWhy is wanted in the reason of the first of two entries.
		baseWhy string
	}{
		{name: "the kwok-shaped Makefile", entries: one, waived: waived},
		{name: "no entry: the exclusion is void", void: true},
		{name: "a comment line names it", extra: map[string]string{"Makefile": "# run dev-lab-kwok for a lab\n" + devMakefile}, entries: one, waived: waived},
		{name: "a document names it", extra: map[string]string{"docs/dev.md": "Run `make dev-lab-kwok` for a lab.\n"}, entries: one, waived: waived, docs: []string{"docs/dev.md"}},
		{name: "default goal set, target first", extra: map[string]string{"Makefile": ".DEFAULT_GOAL := all\n.PHONY: dev-lab-kwok\ndev-lab-kwok:\n" + devApplied + "all:\n\t@echo all\n"}, entries: one, waived: waived},
		{name: "an include of a Makefile that was read", extra: map[string]string{"Makefile": "all:\n\t@echo all\ninclude hack/common.mk\n.PHONY: dev-lab-kwok\ndev-lab-kwok:\n" + devApplied, "hack/common.mk": "X := 1\n"}, entries: one, waived: waived},
		{name: "a script that runs make on another target", extra: map[string]string{"hack/run.sh": "#!/bin/sh\nmake all\n"}, entries: one, waived: waived},
		{name: "make with a literal target", extra: map[string]string{"Makefile": devMakefile + "lab:\n\t@$(MAKE) kind-install-kyverno\n"}, entries: one, waived: waived},
		{name: "the rule of an applied entry has a variable prerequisite", extra: map[string]string{"Makefile": "all:\n\t@echo all\n.PHONY: dev-lab-kwok\ndev-lab-kwok: $(DEPS)\n" + devApplied}, entries: one, waived: waived},

		// (a)
		{name: "(a) the Makefile is missing", entries: []DevOnlyMake{devEntry("other/Makefile", devTarget)}, why: "missing", void: true},
		{name: "(a) no rule header names it", extra: map[string]string{"Makefile": "all:\n\t@echo all\n.PHONY: dev-lab-kwok\nlab:\n" + devApplied}, entries: one, why: "no rule header", void: true},
		// (b)
		{name: "(b) a prerequisite in the Makefile", extra: map[string]string{"Makefile": devMakefile + "up: dev-lab-kwok\n"}, entries: one, why: "prerequisite or target of up", void: true},
		{name: "(b) a prerequisite in another Makefile", extra: map[string]string{"hack/ci.mk": "ci: dev-lab-kwok\n"}, entries: one, why: "prerequisite or target of ci in hack/ci.mk", void: true},
		{name: "(b) a recipe line runs make on it", extra: map[string]string{"Makefile": devMakefile + "lab:\n\t@$(MAKE) dev-lab-kwok\n"}, entries: one, why: "invoked by lab", void: true},
		{name: "(b) the recipe of a special rule", extra: map[string]string{"Makefile": devMakefile + ".DEFAULT:\n\t@$(MAKE) dev-lab-kwok\n"}, entries: one, why: "invoked by .DEFAULT", void: true},
		{name: "(b) an assignment", extra: map[string]string{"Makefile": "T := dev-lab-kwok\n" + devMakefile}, entries: one, why: "the name occurs in Makefile", void: true},
		{name: "(b) .DEFAULT_GOAL names it", extra: map[string]string{"Makefile": ".DEFAULT_GOAL := dev-lab-kwok\n" + devMakefile}, entries: one, why: "the name occurs in Makefile", void: true},
		{name: "(b) a shell script", extra: map[string]string{"hack/run.sh": "#!/bin/sh\nmake dev-lab-kwok\n"}, entries: one, why: "the name occurs in hack/run.sh", void: true},
		{name: "(b) a container build", extra: map[string]string{"Dockerfile": "FROM scratch\nRUN make dev-lab-kwok\n"}, entries: one, why: "the name occurs in Dockerfile", void: true},
		{name: "(b) the same name in another Makefile", extra: map[string]string{"hack/Makefile": "dev-lab-kwok:\n\t@kubectl apply -k ../scripts/config/kwok\n"}, entries: one, why: "prerequisite or target of dev-lab-kwok in hack/Makefile", void: true},
		// (c)
		{name: "(c) make with a variable", extra: map[string]string{"Makefile": devMakefile + "lab:\n\t$(MAKE) $(GOAL)\n"}, entries: one, why: "make is run with a variable", void: true},
		{name: "(c) make with a path variable and a name", extra: map[string]string{"Makefile": devMakefile + "lab:\n\t$(MAKE) -C $(DIR) build\n"}, entries: one, why: "make is run with a variable", void: true},
		{name: "(c) make with an automatic variable", extra: map[string]string{"Makefile": devMakefile + "lab:\n\t${MAKE} $@\n"}, entries: one, why: "make is run with a variable", void: true},
		{name: "(c) make with a pattern", extra: map[string]string{"hack/run.sh": "make %\n"}, entries: one, why: "make is run with a variable or % in hack/run.sh", void: true},
		{name: "(c) gmake in a script", extra: map[string]string{"hack/run.sh": "gmake \"$1\"\n"}, entries: one, why: "hack/run.sh", void: true},
		{name: "(c) make in a container build", extra: map[string]string{"Dockerfile": "FROM scratch\nRUN make ${TARGET}\n"}, entries: one, why: "Dockerfile", void: true},
		// (d)
		{name: "(d) a variable prerequisite", extra: map[string]string{"Makefile": devMakefile + "build: $(BINS)\n"}, entries: one, why: "a rule of build in Makefile has a prerequisite with a variable", void: true},
		{name: "(d) a pattern prerequisite", extra: map[string]string{"Makefile": devMakefile + "%.o: %.c\n"}, entries: one, why: "prerequisite with a variable", void: true},
		// (e)
		{name: "(e) a computed include", extra: map[string]string{"Makefile": "all:\n\t@echo all\ninclude $(wildcard hack/*.mk)\n.PHONY: dev-lab-kwok\ndev-lab-kwok:\n" + devApplied}, entries: one, why: "include of", void: true},
		{name: "(e) an include of a file that was not read", extra: map[string]string{"Makefile": "all:\n\t@echo all\n-include missing.mk\n.PHONY: dev-lab-kwok\ndev-lab-kwok:\n" + devApplied}, entries: one, why: "include of", void: true},
		{name: "(e) an include above the repository", extra: map[string]string{"Makefile": "all:\n\t@echo all\nsinclude ../common.mk\n.PHONY: dev-lab-kwok\ndev-lab-kwok:\n" + devApplied}, entries: one, why: "include of", void: true},
		// (f)
		{name: "(f) the target is the default goal", extra: map[string]string{"Makefile": ".PHONY: dev-lab-kwok\ndev-lab-kwok:\n" + devApplied + "all:\n\t@echo all\n"}, entries: one, why: "default goal", void: true},
		{name: "(f) an include precedes the first rule", extra: map[string]string{"Makefile": "include hack/common.mk\n" + devMakefile, "hack/common.mk": "X := 1\n"}, entries: one, why: "an include precedes the first rule", void: true},
		{name: "(f) a computed default goal", extra: map[string]string{"Makefile": ".DEFAULT_GOAL := $(X)\n" + devMakefile}, entries: one, why: ".DEFAULT_GOAL holds a variable", void: true},
		{name: "(f) a computed first target", extra: map[string]string{"Makefile": "$(BIN):\n\t@echo\n" + devMakefile}, entries: one, why: "variable or % in its target", void: true},
		// (g)
		{name: "(g) a recipe prefix", extra: map[string]string{"Makefile": ".RECIPEPREFIX = >\n" + devMakefile}, entries: one, why: ".RECIPEPREFIX", void: true},
		{name: "(g) a GNUmakefile beside it", extra: map[string]string{"GNUmakefile": "all:\n\t@echo gnu\n"}, entries: one, why: "instead of Makefile", void: true},
		// Bounds and an unreadable surface.
		{name: "a file over the bound of the check", extra: map[string]string{"hack/big.mk": big.String()}, entries: one, why: "too large", void: true},
		{name: "an install surface that cannot be checked", extra: map[string]string{"hack/many.mk": "a:\n" + strings.Repeat("\tkubectl apply -f x\n", maxSurfaceLines+1)}, entries: one, why: "unverified install surface", void: true},
		// A recipe the entry does not cover.
		{name: "a rule with a target that is not listed", extra: map[string]string{"Makefile": "all:\n\t@echo all\ndev-lab-kwok lab:\n" + devApplied}, entries: one, void: true},
		{name: "a recipe line after a define", extra: map[string]string{"Makefile": "all:\n\t@echo all\ndev-lab-kwok:\n\t@echo lab\ndefine X\nendef\n" + devApplied}, entries: one, void: true},
		{name: "a recipe line after an include", extra: map[string]string{"Makefile": "all:\n\t@echo all\ndev-lab-kwok:\n\t@echo lab\ninclude hack/common.mk\n" + devApplied, "hack/common.mk": "X := 1\n"}, entries: one, void: true},
		// Entries decided together.
		{name: "two entries, one a prerequisite of the other", extra: map[string]string{"Makefile": chain}, entries: both, waived: waived, baseWaived: []DevOnlyWaiver{{Exclusion: kwokDir, Token: "./scripts/config/kwok/base"}}},
		{name: "only the prerequisite is listed", extra: map[string]string{"Makefile": chain}, entries: []DevOnlyMake{devEntry("Makefile", devBase)}, why: "prerequisite or target of dev-lab-kwok", void: true},
		{name: "a third rule drops both", extra: map[string]string{"Makefile": chain + "ci: dev-lab-kwok\n"}, entries: both, why: "prerequisite or target of ci", baseWhy: "prerequisite or target of dev-lab-kwok in Makefile", void: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, proof := devPair(t, tc.extra, tc.entries...)
			if p.Status != extract.PairDerived {
				t.Fatalf("pair %s %q", p.Status, p.Reason)
			}
			voids := voidFindings(proof)
			if tc.void != (len(voids) == 1) || len(voids) > 1 || (len(voids) == 1 && voids[0].Location != kwokDir) {
				t.Fatalf("void findings %+v, want void=%v", voids, tc.void)
			}
			if tc.void == proof.Completeness.Attestable {
				t.Fatalf("completeness %+v", proof.Completeness)
			}
			recs := proof.To.Scan.DevOnlyMake
			if len(recs) != len(tc.entries) {
				t.Fatalf("%d records for %d entries: %+v", len(recs), len(tc.entries), recs)
			}
			if len(recs) == 0 {
				return
			}
			for i, en := range tc.entries {
				if recs[i].Makefile != en.Makefile || recs[i].Target != en.Target {
					t.Fatalf("record %d is %+v, want %s %s", i, recs[i], en.Makefile, en.Target)
				}
			}
			// The last entry's record decides the case.
			rec := recs[len(recs)-1]
			if tc.why == "" {
				if !rec.Applied || rec.WhyNot != "" {
					t.Fatalf("record %+v, want applied", rec)
				}
			} else {
				if rec.Applied || !strings.Contains(rec.WhyNot, tc.why) {
					t.Fatalf("record %+v, want not applied (%q)", rec, tc.why)
				}
				if len(rec.Waived) != 0 {
					t.Fatalf("a record that is not applied waived %+v", rec.Waived)
				}
			}
			if len(rec.Waived) != len(tc.waived) || (len(tc.waived) > 0 && !reflect.DeepEqual(rec.Waived, tc.waived)) {
				t.Fatalf("waived %+v, want %+v", rec.Waived, tc.waived)
			}
			if tc.baseWhy != "" && (recs[0].Applied || !strings.Contains(recs[0].WhyNot, tc.baseWhy)) {
				t.Fatalf("record of the first entry %+v, want not applied (%q)", recs[0], tc.baseWhy)
			}
			if tc.baseWaived != nil && !reflect.DeepEqual(recs[0].Waived, tc.baseWaived) {
				t.Fatalf("waived of the first entry %+v, want %+v", recs[0].Waived, tc.baseWaived)
			}
			if !slices.Equal(rec.Docs, tc.docs) {
				t.Fatalf("docs %v, want %v", rec.Docs, tc.docs)
			}
		})
	}
}

// Without an entry the record is absent: a target that lists none
// encodes as before.
func TestDevOnlyMakeAbsentWithoutEntries(t *testing.T) {
	_, proof := devPair(t, nil)
	if proof.To.Scan.DevOnlyMake != nil {
		t.Fatalf("records %+v", proof.To.Scan.DevOnlyMake)
	}
}

// An entry is decided at every tag: a release that adds a referrer is void
// there only.
func TestDevOnlyMakeIsPerTag(t *testing.T) {
	files := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1beta1", "v1"), kwokDir + "crd.yaml": crd("Gamma", "v1"), "Makefile": devMakefile}
	later := map[string]string{"deploy/crds/a.yaml": crd("Alpha", "v1"), kwokDir + "crd.yaml": crd("Gamma", "v1"), "Makefile": devMakefile + "up: dev-lab-kwok\n"}
	tg := synthTarget(kwokExclusion())
	tg.DevOnlyMake = []DevOnlyMake{devEntry("Makefile", devTarget)}
	_, proof := pairOf(t, runSynth(t, tg, newSynth(release{"v1.0.0", files}, release{"v1.1.0", later})), "1.0.0", "1.1.0")
	from, to := proof.From.Scan.DevOnlyMake, proof.To.Scan.DevOnlyMake
	if len(from) != 1 || !from[0].Applied || len(to) != 1 || to[0].Applied || !strings.Contains(to[0].WhyNot, "up") {
		t.Fatalf("from %+v to %+v", from, to)
	}
}

// The parse of a Makefile is a function of its bytes: the lines the guard
// reads do not depend on the dev-only words, and the words do not change
// between reads.
func TestDevOnlyParseIsPure(t *testing.T) {
	data := []byte(devMakefile + "include a.mk\nup: dev-lab-kwok $(X)\n\t$(MAKE) $(T)\n.DEFAULT_GOAL := all\n")
	plain, _, why := parseMake(data, false)
	if why != "" {
		t.Fatal(why)
	}
	l1, d1, _ := parseMake(data, true)
	l2, d2, _ := parseMake(data, true)
	if !reflect.DeepEqual(plain, l1) || !reflect.DeepEqual(l1, l2) || !reflect.DeepEqual(d1, d2) || d1 == nil {
		t.Fatalf("lines %+v %+v, info %+v %+v", plain, l1, d1, d2)
	}
	if !d1.dynMake || !d1.hasGoal || d1.dynGoal || d1.recipePrefix || !slices.Equal(d1.includes, []string{"a.mk"}) || d1.includeBeforeGoal {
		t.Fatalf("info %+v", d1)
	}
	if s := summarizeSurface(surfMake, data, false); s.dev != nil {
		t.Fatalf("dev info without the flag: %+v", s.dev)
	}
	for _, kind := range []int{surfDoc, surfShell, surfBuild} {
		a, b := summarizeSurface(kind, data, true), summarizeSurface(kind, data, true)
		if a.dev == nil || !reflect.DeepEqual(a, b) || len(a.dev.find(devTarget)) == 0 {
			t.Fatalf("kind %d: %+v", kind, a.dev)
		}
		if summarizeSurface(kind, data, false).dev != nil {
			t.Fatalf("kind %d: dev info without the flag", kind)
		}
	}
}

func TestDynamicMake(t *testing.T) {
	for in, want := range map[string]bool{
		"$(MAKE) $(GOAL)":                    true,
		"${MAKE} -C ${DIR} x":                true,
		"make %":                             true,
		"gmake $1":                           true,
		"make $@":                            true,
		"@$(MAKE) kind-install-kyverno":      false,
		"\t/usr/bin/make build":              false,
		"make-sure $X":                       false,
		"cmake $X":                           false,
		"echo $X":                            false,
		"make build && echo $HOME":           true,
		"run make; echo done":                false,
		"lab: ; $(MAKE) -f $(FILE)":          true,
		"RUN make build TARGET=dev-lab-kwok": false,
	} {
		if got := dynamicMake(in); got != want {
			t.Errorf("dynamicMake(%q) = %v", in, got)
		}
	}
}

// A define, endef, include or .RECIPEPREFIX line ends the rule the recipe
// lines before it belonged to, so a tab line after it is not a recipe of
// that rule (and not skipped as the recipe of a test target).
func TestMakeLinesRuleEnds(t *testing.T) {
	for _, sep := range []string{"define X", "endef", "include a.mk", "-include a.mk", "sinclude a.mk", ".RECIPEPREFIX = >", ".RECIPEPREFIX := >"} {
		lines, why := makeLines([]byte("test-e2e:\n\tkubectl apply -f a\n" + sep + "\n\tkubectl apply -f b\n"))
		if why != "" || len(lines) != 2 {
			t.Fatalf("%s: %+v %q", sep, lines, why)
		}
		if !slices.Equal(lines[0].Targets, []string{"test-e2e"}) || len(lines[1].Targets) != 0 {
			t.Errorf("%s: targets %v then %v", sep, lines[0].Targets, lines[1].Targets)
		}
	}
	// An assignment named like one does not.
	lines, _ := makeLines([]byte("test-e2e:\n\tkubectl apply -f a\ndefined = 1\n\tkubectl apply -f b\n"))
	if len(lines) != 2 || !slices.Equal(lines[1].Targets, []string{"test-e2e"}) {
		t.Errorf("assignment: %+v", lines)
	}
}

// A define or include line also ends a test target's recipe in the scan:
// an apply of the excluded path after it voids the exclusion.
func TestGuardRuleEndsVoid(t *testing.T) {
	for name, mk := range map[string]string{
		"the recipe of a test target":   "test-e2e:\n\tkubectl apply -f x\n",
		"after a define":                "test-e2e:\n\tkubectl apply -f x\ndefine X\nendef\n\tkubectl apply -k ./scripts/config/kwok\n",
		"after an include":              "test-e2e:\n\tkubectl apply -f x\ninclude hack/common.mk\n\tkubectl apply -k ./scripts/config/kwok\n",
		"inside a test target (no end)": "test-e2e:\n\tkubectl apply -f x\n\tkubectl apply -k ./scripts/config/kwok\n",
	} {
		_, proof := devPair(t, map[string]string{"Makefile": mk, "hack/common.mk": "X := 1\n"})
		wantVoid := strings.Contains(name, "after")
		if got := len(voidFindings(proof)) == 1; got != wantVoid {
			t.Errorf("%s: void=%v", name, got)
		}
	}
}

// The loader keeps the entries to plain names of Makefile targets.
func TestDevOnlyMakeLoader(t *testing.T) {
	const ex = `{"path":"scripts/config/kwok/","repo":"github.com/o/p","reason":"a kustomization for a local lab","evidence":"only applied by the dev-lab-kwok target of the Makefile; no install path names it"}`
	dj := func(makefile, target string) string {
		return fmt.Sprintf(`{"makefile":%q,"target":%q,"reason":"starts a local lab cluster","evidence":"the target only applies the lab kustomization to a local kwok cluster"}`, makefile, target)
	}
	load := func(dev string) (Target, error) {
		raw := strings.Replace(string(testTargetsJSON(ex)), `"exclude":[`+ex+`]`, `"exclude":[`+ex+`],"devOnlyMakeTargets":[`+dev+`]`, 1)
		return LoadTarget("target-p.json", []byte(raw))
	}
	for _, tc := range [][2]string{{"Makefile", "dev-lab-kwok"}, {"hack/dev.mk", "lab"}, {"build/GNUmakefile", "A_b.c-1"}, {"x/Makefile.make", "0lab"}} {
		tg, err := load(dj(tc[0], tc[1]))
		if err != nil || len(tg.DevOnlyMake) != 1 || tg.DevOnlyMake[0].Makefile != tc[0] || tg.DevOnlyMake[0].Target != tc[1] {
			t.Errorf("%v: %v %+v", tc, err, tg.DevOnlyMake)
		}
	}
	// Without the member, nothing changes.
	if tg, err := LoadTarget("target-p.json", testTargetsJSON(ex)); err != nil || tg.DevOnlyMake != nil {
		t.Fatalf("%v %+v", err, tg.DevOnlyMake)
	}
	long := strings.Repeat("x", 129)
	for name, tc := range map[string]struct{ dev, want string }{
		"a parent directory":      {dj("../Makefile", "lab"), "clean repository path"},
		"an absolute path":        {dj("/Makefile", "lab"), "clean repository path"},
		"an unclean path":         {dj("hack//Makefile", "lab"), "clean repository path"},
		"a dot segment":           {dj("./Makefile", "lab"), "clean repository path"},
		"no path":                 {dj("", "lab"), "clean repository path"},
		"not a Makefile":          {dj("hack/run.sh", "lab"), "clean repository path of a Makefile"},
		"a directory":             {dj("hack/", "lab"), "clean repository path"},
		"an empty target":         {dj("Makefile", ""), "plain target name"},
		"a pattern":               {dj("Makefile", "%.o"), "plain target name"},
		"a variable":              {dj("Makefile", "$(T)"), "plain target name"},
		"a colon":                 {dj("Makefile", "a:b"), "plain target name"},
		"white space":             {dj("Makefile", "a b"), "plain target name"},
		"a leading dot":           {dj("Makefile", ".PHONY"), "plain target name"},
		"a leading dash":          {dj("Makefile", "-lab"), "plain target name"},
		"a slash":                 {dj("Makefile", "a/b"), "plain target name"},
		"a long name":             {dj("Makefile", long), "plain target name"},
		"install":                 {dj("Makefile", "install"), "never dev-only"},
		"deploy in a name":        {dj("Makefile", "lab-deploy"), "never dev-only"},
		"up in a name":            {dj("Makefile", "kind_up"), "never dev-only"},
		"release":                 {dj("Makefile", "release"), "never dev-only"},
		"a duplicate":             {dj("Makefile", "lab") + "," + dj("Makefile", "lab"), "listed twice"},
		"short evidence":          {`{"makefile":"Makefile","target":"lab","reason":"starts a local lab cluster","evidence":"short"}`, "evidence"},
		"long evidence":           {`{"makefile":"Makefile","target":"lab","reason":"starts a local lab cluster","evidence":"` + strings.Repeat("e", 801) + `"}`, "evidence"},
		"no reason":               {`{"makefile":"Makefile","target":"lab","evidence":"the target only applies the lab kustomization to a local cluster"}`, "reason"},
		"a padded reason":         {`{"makefile":"Makefile","target":"lab","reason":" starts a local lab cluster","evidence":"the target only applies the lab kustomization to a local cluster"}`, "reason"},
		"an unknown member":       {`{"makefile":"Makefile","target":"lab","reason":"starts a local lab cluster","evidence":"the target only applies the lab kustomization to a local cluster","x":1}`, "unknown field"},
		"a name that is an array": {`{"makefile":"Makefile","target":["lab"],"reason":"starts a local lab cluster","evidence":"the target only applies the lab kustomization to a local cluster"}`, "cannot unmarshal"},
	} {
		if _, err := load(tc.dev); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}
