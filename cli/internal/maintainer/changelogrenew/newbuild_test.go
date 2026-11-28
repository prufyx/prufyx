// SPDX-License-Identifier: AGPL-3.0-only

package changelogrenew

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract/extractcli"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

var olderDigest = sum([]byte("older build"))

// older gives the base record i an older build with the given version.
func (f *fixture) older(t *testing.T, i int, version string) constraintengine.Extractor {
	t.Helper()
	build := constraintengine.Extractor{ID: testID, Version: version, CodeDigest: olderDigest}
	f.base[i].Evidence.Extractor = &build
	f.repack(t)
	return build
}

func TestCurrentIsTheRunBuild(t *testing.T) {
	t.Parallel()
	current, err := Current(extractcli.Catalog()[testID].New(1))
	if err != nil {
		t.Fatal(err)
	}
	if got := derive(t, upstream{baseVersions}, testAt, testLease).Manifest.Extractor; got != current {
		t.Fatalf("a run records %+v, Current is %+v", got, current)
	}
}

func TestAssembleRenewsAnOlderBuild(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	was := f.older(t, 0, "0.9.0")
	f.older(t, 1, "0.9.0")
	res, err := Assemble(f.opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Renewed) != 2 || !slices.Equal(res.Previous, []PreviousBuild{{Build: was, Records: 2}}) || res.Build != f.opts.Current {
		t.Fatalf("result %+v", res)
	}
	got := changedMembers(t, f.opts.Pack, res.Pack)
	if len(got) != 5 || got["derivedAt"] != 2 || got["reviewedAt"] != 2 || got["validUntil"] != 2 || got["version"] != 2 || got["codeDigest"] != 2 {
		t.Fatalf("changed members %v", got)
	}
	// One record of an older build and one of the current build.
	f = newFixture(t)
	was = f.older(t, 1, f.opts.Current.Version)
	res, err = Assemble(f.opts)
	if err != nil || len(res.Renewed) != 2 || !slices.Equal(res.Previous, []PreviousBuild{{Build: was, Records: 1}}) {
		t.Fatalf("result %+v %v", res, err)
	}
	if got := changedMembers(t, f.opts.Pack, res.Pack); got["codeDigest"] != 1 || got["version"] != 0 {
		t.Fatalf("changed members %v", got)
	}
}

// Runs of a build that the binary does not hold still renew the records of that
// same build; only a change of build needs the held one.
func TestAssembleSameBuildDoesNotNeedTheHeldBuild(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.opts.Current = constraintengine.Extractor{}
	res, err := Assemble(f.opts)
	if err != nil || len(res.Renewed) != 2 || len(res.Previous) != 0 {
		t.Fatalf("result %+v %v", res, err)
	}
}

func TestAssembleNewBuildRefuses(t *testing.T) {
	t.Parallel()
	notHeld := ": the base record is of another build, and the runs are not of the build this binary holds"
	changed := refusal(CodeChanged, "the record differs in more than evidence.extractor.version and codeDigest, derivedAt, reviewedAt and validUntil")
	for name, edit := range map[string]func(t *testing.T, f *fixture) string{
		"no held build": func(t *testing.T, f *fixture) string {
			f.older(t, 0, "0.9.0")
			f.opts.Current = constraintengine.Extractor{}
			return refusal(CodeBuild, f.key(0)+notHeld)
		},
		"runs of a build the binary does not hold": func(t *testing.T, f *fixture) string {
			f.older(t, 0, "0.9.0")
			f.opts.Current.CodeDigest = sum([]byte("another build"))
			return refusal(CodeBuild, f.key(0)+notHeld)
		},
		"lower version": func(t *testing.T, f *fixture) string {
			f.older(t, 0, "2.0.0")
			return f.key(0) + ": " + refusal(CodeBuild, "the extractor version "+f.opts.Current.Version+" is lower than the base 2.0.0")
		},
		"same digest, another version": func(t *testing.T, f *fixture) string {
			f.base[0].Evidence.Extractor.Version = "0.9.0"
			f.repack(t)
			return f.key(0) + ": " + refusal(CodeBuild, "the code digest is the base one: this is not a new build")
		},
		"lower version on a line that grew": func(t *testing.T, f *fixture) string {
			f.older(t, 1, "2.0.0")
			f.both(t, runFiles(t, derive(t, upstream{append(slices.Clone(baseVersions), "3.5.2")}, testAt, testLease)))
			return f.key(1) + ": " + refusal(CodeBuild, "the extractor version "+f.opts.Current.Version+" is lower than the base 2.0.0")
		},
		"base record lapsed": func(t *testing.T, f *fixture) string {
			f.base = derive(t, upstream{baseVersions}, testOldAt, 20).Attestations
			f.older(t, 0, "0.9.0")
			return f.key(0) + ": " + refusal(CodeNotInForce, "both records must be in force")
		},
		"changed range": func(t *testing.T, f *fixture) string {
			f.base[0].Evidence.Sources[0].EndLine++
			f.older(t, 0, "0.9.0")
			return f.key(0) + ": " + changed
		},
		"changed source URL": func(t *testing.T, f *fixture) string {
			f.base[0].Evidence.Sources[0].URL += ".old"
			f.older(t, 0, "0.9.0")
			return f.key(0) + ": " + changed
		},
		"changed source digest": func(t *testing.T, f *fixture) string {
			f.base[0].Evidence.Sources[0].ContentDigest = sum([]byte("before"))
			f.older(t, 0, "0.9.0")
			return f.key(0) + ": " + changed
		},
		"changed release commit": func(t *testing.T, f *fixture) string {
			f.base[0].Releases.From[0].Commit = commitOf("8.8.8")
			f.older(t, 0, "0.9.0")
			return f.key(0) + ": " + changed
		},
		// One difference refuses the whole run, the good record included.
		"one differing record beside a good one": func(t *testing.T, f *fixture) string {
			f.base[1].Evidence.Sources[0].EndLine++
			f.older(t, 0, "0.9.0")
			f.older(t, 1, "0.9.0")
			return f.key(1) + ": " + changed
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			want := edit(t, f)
			requireRefusal(t, f.opts, want)
		})
	}
}

// A line of an older build that grew or is not derived is left as it is, the
// older build included.
func TestAssembleNewBuildLeavesOtherRecords(t *testing.T) {
	t.Parallel()
	for name, versions := range map[string][]string{
		"grew":        append(slices.Clone(baseVersions), "3.5.2"),
		"not derived": {"3.3.0", "3.4.0", "3.4.1"},
	} {
		f := newFixture(t)
		was := f.older(t, 1, "0.9.0")
		f.both(t, runFiles(t, derive(t, upstream{versions}, testAt, testLease)))
		res, err := Assemble(f.opts)
		if err != nil || !slices.Equal(res.Renewed, []string{f.key(0)}) || len(res.Previous) != 0 ||
			!slices.Equal(append(res.ListChanged, res.NotDerived...), []string{f.key(1)}) {
			t.Fatalf("%s: %+v %v", name, res, err)
		}
		head := parsedSection(t, res.Pack)[1].Evidence
		if *head.Extractor != was || head.DerivedAt != testOldAt {
			t.Fatalf("%s: the record moved: %+v", name, head)
		}
	}
}

// move must not write through the extractor pointer a shallow clone shares
// with the base records.
func TestMoveLeavesTheBaseRecords(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	was := f.older(t, 0, "0.9.0")
	next := derive(t, upstream{baseVersions}, testAt, testLease).Attestations[0]
	head := slices.Clone(f.base)
	move(head, 0, next, true)
	if *f.base[0].Evidence.Extractor != was || f.base[0].Evidence.DerivedAt != testOldAt {
		t.Fatalf("the base record changed: %+v", f.base[0].Evidence)
	}
	if head[0].Evidence.Extractor == f.base[0].Evidence.Extractor || head[0].Evidence.Extractor == next.Evidence.Extractor {
		t.Fatal("the head record shares an extractor pointer")
	}
	if *head[0].Evidence.Extractor != *next.Evidence.Extractor || head[0].Evidence.DerivedAt != testAt {
		t.Fatalf("the head record did not move: %+v", head[0].Evidence)
	}
}

// The final check judges the result on its own.
func TestAuditRefuses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.older(t, 0, "0.9.0")
	next := derive(t, upstream{baseVersions}, testAt, testLease).Attestations
	head := slices.Clone(f.base)
	move(head, 0, next[0], true)
	moved := packOf(t, head)
	one := map[lineattest.Key]bool{f.base[0].Key(): true}
	two := map[lineattest.Key]bool{f.base[0].Key(): true, f.base[1].Key(): true}
	if err := audit(f.opts.Pack, moved, one, f.opts.Current, testNow); err != nil {
		t.Fatal(err)
	}
	other := f.opts.Current
	other.CodeDigest = sum([]byte("another build"))
	head[0].Evidence.Sources = slices.Clone(head[0].Evidence.Sources)
	head[0].Evidence.Sources[0].EndLine++
	edited := packOf(t, head)
	for name, tc := range map[string]struct {
		head    []byte
		renewed map[lineattest.Key]bool
		current constraintengine.Extractor
		now     time.Time
		want    string
	}{
		"another build": {moved, one, other, testNow, refusal(CodeBuild, "the result moves a record to a build this binary does not hold")},
		"not renewed":   {moved, nil, f.opts.Current, testNow, refusal(CodeChanged, "the result changes a record it does not renew")},
		"fewer changes": {moved, two, f.opts.Current, testNow, refusal(CodeChanged, "the result changes 1 records, not the 2 renewed")},
		"no clock":      {moved, one, f.opts.Current, time.Time{}, refusal(CodeDerivationTime, "there is no clock to judge a new build by")},
		"content": {edited, one, f.opts.Current, testNow,
			refusal(CodeChanged, "the record differs in more than evidence.extractor.version and codeDigest, derivedAt, reviewedAt and validUntil")},
	} {
		if err := audit(f.opts.Pack, tc.head, tc.renewed, tc.current, tc.now); err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
}

func TestNewBuild(t *testing.T) {
	t.Parallel()
	u := upstream{baseVersions}
	old := derive(t, u, testOldAt, testOld).Attestations[0]
	good := derive(t, u, testAt, testLease).Attestations[0]
	extractor := func(e map[string]any) map[string]any { return e["extractor"].(map[string]any) }
	source := func(e map[string]any) map[string]any { return e["sources"].([]any)[0].(map[string]any) }
	releases := func(r map[string]any, side string) []any { return r["releases"].(map[string]any)[side].([]any) }
	// was is the base record: an older build of the given version.
	was := func(version string, edit func(r, e map[string]any)) []byte {
		return rawRecord(t, old, func(r, e map[string]any) {
			extractor(e)["codeDigest"], extractor(e)["version"] = olderDigest, version
			if edit != nil {
				edit(r, e)
			}
		})
	}
	next := func(edit func(r, e map[string]any)) []byte { return rawRecord(t, good, edit) }
	version := func(v string) func(r, e map[string]any) {
		return func(_, e map[string]any) { extractor(e)["version"] = v }
	}

	// The same version, a lower base version, and a numeric (not textual)
	// comparison are accepted, as are exactly 90 days and a derivation five
	// minutes ahead of the clock.
	for name, tc := range map[string]struct {
		base, head []byte
		now        time.Time
	}{
		"same version":      {was(good.Evidence.Extractor.Version, nil), next(nil), testNow},
		"lower base":        {was("0.9.0", nil), next(nil), testNow},
		"two digit version": {was("9.0.0", nil), next(version("10.0.0")), testNow},
		"90 days":           {was("0.9.0", nil), next(func(_, e map[string]any) { e["validUntil"] = "2027-03-01T00:00:00Z" }), testNow},
		"clock skew":        {was("0.9.0", nil), next(nil), testNow.Add(-time.Hour - ClockSkew)},
	} {
		if err := NewBuild(tc.base, tc.head, tc.now); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	changed := refusal(CodeChanged, "the record differs in more than evidence.extractor.version and codeDigest, derivedAt, reviewedAt and validUntil")
	oneExtractor := refusal(CodeOtherExtractor, "both records must name one changelog.listed.<project> extractor")
	notNumeric := refusal(CodeBuild, "an extractor version is not numeric x.y.z")
	unreadableDigest := refusal(CodeBuild, "a code digest cannot be read")
	sameDigest := refusal(CodeBuild, "the code digest is the base one: this is not a new build")
	notLater := refusal(CodeDerivationTime, "derivedAt must be a new derivation later than the base one and equal reviewedAt")
	badLife := refusal(CodeLease, "validUntil must be more than 0 and at most 90 days after derivedAt")
	notInForce := refusal(CodeNotInForce, "both records must be in force")
	kubernetes := refusal(CodeComponent, "a Kubernetes record is not renewed across extractor builds")
	family := func(side string) string {
		return refusal(CodeInput, "the "+side+" record is not a changelog.listed_entries record with evidence")
	}
	type refused struct {
		base, head []byte
		now        time.Time
		want       string
	}
	cases := map[string]refused{
		"no clock": {was("0.9.0", nil), next(nil), time.Time{}, refusal(CodeDerivationTime, "there is no clock to judge a new build by")},
		"ahead of the clock": {was("0.9.0", nil), next(nil), testNow.Add(-time.Hour - ClockSkew - time.Second),
			refusal(CodeDerivationTime, "derivedAt is ahead of the clock")},
		"base lapsed": {was("0.9.0", func(_, e map[string]any) { e["validUntil"] = "2026-12-01T01:00:00Z" }), next(nil), testNow, notInForce},
		"head lapsed": {was("0.9.0", nil), next(func(_, e map[string]any) { e["validUntil"] = testAt }), testNow, notInForce},

		"same digest, same version": {rawRecord(t, old, nil), next(nil), testNow, sameDigest},
		"same digest, new version":  {rawRecord(t, old, nil), next(version("9.0.0")), testNow, sameDigest},
		"lower version":             {was("1.0.1", nil), next(version("1.0.0")), testNow, refusal(CodeBuild, "the extractor version 1.0.0 is lower than the base 1.0.1")},
		"lower major":               {was("10.0.0", nil), next(version("9.9.9")), testNow, refusal(CodeBuild, "the extractor version 9.9.9 is lower than the base 10.0.0")},
		"base digest unreadable": {was("0.9.0", func(_, e map[string]any) { extractor(e)["codeDigest"] = "sha256:00" }), next(nil), testNow,
			unreadableDigest},
		"new digest unreadable": {was("0.9.0", nil), next(func(_, e map[string]any) { extractor(e)["codeDigest"] = "new" }), testNow, unreadableDigest},

		"other extractor": {was("0.9.0", nil), next(func(_, e map[string]any) { extractor(e)["id"] = "changelog.listed.tuf" }), testNow, oneExtractor},
		"another family of extractor": {
			was("0.9.0", func(_, e map[string]any) { extractor(e)["id"] = "crd.version-removal.prometheus" }),
			next(func(_, e map[string]any) { extractor(e)["id"] = "crd.version-removal.prometheus" }), testNow, oneExtractor},
		"prefix only": {
			was("0.9.0", func(_, e map[string]any) { extractor(e)["id"] = ListedIDPrefix }),
			next(func(_, e map[string]any) { extractor(e)["id"] = ListedIDPrefix }), testNow, oneExtractor},
		"extra extractor member": {was("0.9.0", nil), next(func(_, e map[string]any) { extractor(e)["flags"] = "x" }), testNow, changed},

		"Kubernetes on both sides": {
			was("0.9.0", func(r, _ map[string]any) { r["component"] = kubernetesComponent }),
			next(func(r, _ map[string]any) { r["component"] = kubernetesComponent }), testNow, kubernetes},
		"Kubernetes in the base": {was("0.9.0", func(r, _ map[string]any) { r["component"] = kubernetesComponent }), next(nil), testNow, kubernetes},
		"a rule-listing family": {was("0.9.0", nil),
			next(func(r, _ map[string]any) { r["factFamily"] = lineattest.FamilyCustomResourceVersions }), testNow, family("new")},
		"a served list": {[]byte(`{"line":"1.30","apis":[]}`), next(nil), testNow, family("base")},
		"reviewed basis": {was("0.9.0", nil), next(func(_, e map[string]any) { e["basis"] = "reviewed" }), testNow,
			refusal(CodeInput, "the new record is not mechanical")},

		"derivedAt not later": {was("0.9.0", nil), next(func(_, e map[string]any) { e["derivedAt"], e["reviewedAt"] = testOldAt, testOldAt }), testNow, notLater},
		"reviewedAt differs":  {was("0.9.0", nil), next(func(_, e map[string]any) { e["reviewedAt"] = testOldAt }), testNow, notLater},
		"end not later": {was("0.9.0", nil), next(func(_, e map[string]any) { e["validUntil"] = old.Evidence.ValidUntil }), testNow,
			refusal(CodeLease, "validUntil is not later than the base one")},
		"over 90 days": {was("0.9.0", nil), next(func(_, e map[string]any) { e["validUntil"] = "2027-03-01T00:00:01Z" }), testNow, badLife},
	}
	for _, v := range []string{"1.0", "v1.0.0", "01.0.0", "1.0.0-rc1", "1.0.0.0", " 1.0.0", "1000000000.0.0"} {
		cases["base version "+v] = refused{was(v, nil), next(nil), testNow, notNumeric}
		cases["new version "+v] = refused{was("0.9.0", nil), next(version(v)), testNow, notNumeric}
	}
	// Every other member, one at a time.
	for name, edit := range map[string]func(r, e map[string]any){
		"component":    func(r, _ map[string]any) { r["component"] = "pkg:github/prometheus/alertmanager" },
		"line":         func(r, _ map[string]any) { r["line"] = "9.9" },
		"completeness": func(r, _ map[string]any) { r["completeness"] = "partial" },
		"rule ids":     func(r, _ map[string]any) { r["ruleIds"] = []any{"x"} },
		"install profiles": func(r, _ map[string]any) {
			r["installProfiles"] = []any{}
		},
		"release added": func(r, _ map[string]any) {
			r["releases"].(map[string]any)["to"] = append(releases(r, "to"), map[string]any{"version": "3.4.9", "commit": commitOf("3.4.9")})
		},
		"release dropped": func(r, _ map[string]any) { r["releases"].(map[string]any)["to"] = releases(r, "to")[:1] },
		"releases reordered": func(r, _ map[string]any) {
			list := releases(r, "to")
			list[0], list[1] = list[1], list[0]
		},
		"release commit": func(r, _ map[string]any) { releases(r, "from")[0].(map[string]any)["commit"] = commitOf("9.9.9") },
		"lease member":   func(_, e map[string]any) { e["lease"] = "pinned" },
		"source id":      func(_, e map[string]any) { source(e)["id"] = "other" },
		"source URL":     func(_, e map[string]any) { source(e)["url"] = source(e)["url"].(string) + ".old" },
		"revision":       func(_, e map[string]any) { source(e)["revision"] = commitOf("9.9.9") },
		"content digest": func(_, e map[string]any) { source(e)["contentDigest"] = olderDigest },
		"start line":     func(_, e map[string]any) { source(e)["startLine"] = 99 },
		"end line":       func(_, e map[string]any) { source(e)["endLine"] = 99 },
		"source added":   func(_, e map[string]any) { e["sources"] = append(e["sources"].([]any), source(e)) },
		"source dropped": func(_, e map[string]any) { e["sources"] = e["sources"].([]any)[1:] },
		"unknown member": func(r, _ map[string]any) { r["note"] = "x" },
	} {
		cases["changed "+name] = refused{was("0.9.0", nil), next(edit), testNow, changed}
	}
	for name, tc := range cases {
		if err := NewBuild(tc.base, tc.head, tc.now); err == nil || err.Error() != tc.want {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
}

// Every extractor version stored in the shipped data, of both families that may
// be renewed across builds, can be read.
func TestStoredExtractorVersionsParse(t *testing.T) {
	t.Parallel()
	families := []string{"crd.version-removal.", ListedIDPrefix}
	seen := map[string]int{}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				walk(path, item)
			}
		case map[string]any:
			if ex, ok := x["extractor"].(map[string]any); ok {
				id, _ := ex["id"].(string)
				for _, family := range families {
					if !strings.HasPrefix(id, family) {
						continue
					}
					seen[family]++
					version, _ := ex["version"].(string)
					if _, ok := parseVersion(version); !ok {
						t.Errorf("%s: %s has version %q", path, id, version)
					}
				}
			}
			for _, item := range x {
				walk(path, item)
			}
		}
	}
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".json" || filepath.Base(filepath.Dir(path)) != "data" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		walk(path, doc)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if seen[family] == 0 {
			t.Errorf("no stored record of %s", family)
		}
	}
}
