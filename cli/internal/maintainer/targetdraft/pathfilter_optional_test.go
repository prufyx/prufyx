// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"strings"
	"testing"
)

// The two rule classes together: pathFilter (filtered copies) and optional
// installPaths entries (verified absence). Fixture: the optional-entry window
// plus a reserved-group copy inside the mandatory directory at every tag.

const (
	pfoCopyA = "api/config/crd/policy.networking.k8s.io_a.yaml"
	pfoCopyB = "api/config/crd/policy.networking.k8s.io_b.yaml"
	pfoGlob  = "api/config/crd/policy.networking.k8s.io_*.yaml"
)

func pfoMutate(tag string, s *optSpec) {
	s.files[pfoCopyB] = ipCRD("policy.networking.k8s.io", "BetaPolicy")
	s.files[pfoCopyA] = ipCRD("policy.networking.k8s.io", "AlphaPolicy")
}

func pfoRulesJSON(filters string, optional bool, absent ...string) string {
	base := `{"schema":"prufyx.io/target-draft-rules/v1","installSurface":[],"exclusions":[],"installPaths":[` +
		`{"path":"api/config/crd/","reason":"the declared API definitions","evidence":"synthetic fixture"}`
	if optional {
		var q []string
		for _, a := range absent {
			q = append(q, `"`+a+`"`)
		}
		base += `,{"path":"` + optPath + `","reason":"operator definition added by a later line","evidence":"synthetic fixture","optional":true,"absentTags":[` + strings.Join(q, ",") + `]}`
	}
	base += `]`
	if filters != "" {
		base += `,"pathFilter":[` + filters + `]`
	}
	return base + `}`
}

func pfoRules(t *testing.T, filters string, optional bool, absent ...string) *Rules {
	t.Helper()
	r, err := ParseRules([]byte(pfoRulesJSON(filters, optional, absent...)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPathFilterWithOptionalBothReportedSortedAndDeterministic(t *testing.T) {
	repo := optRepo(t, pfoMutate)
	run := func() *Result {
		return mustGenerate(t, optInput(GitSource{Dir: repo}, pfoRules(t, pfFilter(pfoGlob), true, firstFive...)))
	}
	a, b := run(), run()
	rep := a.Report
	if len(rep.OptionalPaths) != 6 {
		t.Fatalf("optional facts %+v", rep.OptionalPaths)
	}
	for i, f := range rep.OptionalPaths {
		want := "verified-absent"
		if i == 5 {
			want = "read"
		}
		if f.Tag != optTags[i] || f.Path != optPath || f.Status != want {
			t.Fatalf("optional fact %d: %+v", i, f)
		}
	}
	if rep.FilteredCopyCount != 2 || len(rep.FilteredCopies) != 2 ||
		rep.FilteredCopies[0].Path != pfoCopyA || rep.FilteredCopies[1].Path != pfoCopyB {
		t.Fatalf("filtered copies not sorted or incomplete: %+v", rep.FilteredCopies)
	}
	for _, fc := range rep.FilteredCopies {
		if strings.Join(fc.Tags, ",") != strings.Join(optTags, ",") {
			t.Fatalf("filtered copy tags %+v", fc)
		}
	}
	if rep.CRDCount != 3 {
		t.Fatalf("want 3 read definitions (Alpha, Beta, Operator), got %d", rep.CRDCount)
	}
	ra, _ := marshal(a.Report)
	rb, _ := marshal(b.Report)
	if !bytes.Equal(a.A, b.A) || !bytes.Equal(a.B, b.B) || !bytes.Equal(a.Changelog, b.Changelog) || !bytes.Equal(ra, rb) {
		t.Fatal("two runs differ")
	}
}

func TestPathFilterAndOptionalDigestLinesOnlyWhenUsed(t *testing.T) {
	repo := optRepo(t, pfoMutate)
	both := mustGenerate(t, optInput(GitSource{Dir: repo}, pfoRules(t, pfFilter(pfoGlob), true, firstFive...)))
	filterOnly := mustGenerate(t, optInput(GitSource{Dir: repo}, pfoRules(t, pfFilter(pfoGlob), false)))
	optOnlyRepo := optRepo(t, nil)
	optOnly := mustGenerate(t, optInput(GitSource{Dir: optOnlyRepo}, optRules(t, firstFive...)))
	if filterOnly.Report.OptionalPaths != nil || filterOnly.Report.FilteredCopyCount != 2 {
		t.Fatalf("filter-only run: optional %+v filtered %d", filterOnly.Report.OptionalPaths, filterOnly.Report.FilteredCopyCount)
	}
	if optOnly.Report.FilteredCopies != nil || optOnly.Report.FilteredCopyCount != 0 {
		t.Fatalf("optional-only run reports filtered copies: %+v", optOnly.Report.FilteredCopies)
	}
	if both.Report.FactsDigest == filterOnly.Report.FactsDigest || both.Report.FactsDigest == optOnly.Report.FactsDigest {
		t.Fatal("combined digest equals a single-feature digest")
	}
	// A changed filtered list moves the combined digest.
	changed := optRepo(t, func(tag string, s *optSpec) {
		pfoMutate(tag, s)
		if tag == optTags[3] {
			s.files["api/config/crd/policy.networking.k8s.io_c.yaml"] = ipCRD("policy.networking.k8s.io", "GammaPolicy")
		}
	})
	moved := mustGenerate(t, optInput(GitSource{Dir: changed}, pfoRules(t, pfFilter(pfoGlob), true, firstFive...)))
	if moved.Report.FactsDigest == both.Report.FactsDigest {
		t.Fatal("filtered list change did not move the combined digest")
	}
}

// A filter that matches an optional exact entry is refused when the rules are
// parsed: the entry must be read at the newest tag, a filter would remove it.
func TestPathFilterMatchingOptionalEntryRefused(t *testing.T) {
	for _, glob := range []string{optPath, "integration/fixtures/operator/*.yml"} {
		_, err := ParseRules([]byte(pfoRulesJSON(pfFilter(glob), true, firstFive...)))
		if err == nil || !strings.Contains(err.Error(), "optional install path") {
			t.Fatalf("glob %q: want a refusal naming the optional install path, got %v", glob, err)
		}
	}
}

// Optional absence at a tag and a filter at that same tag. A filter with no
// match at an older tag follows the existing window rule (that tag is dropped,
// the optional entry is then settled only on the remaining tags); the same at
// the newest tag is the typed stop. Neither feature hides a failure of the other.
func TestPathFilterNoMatchAtOptionalAbsentTagDropsOnlyThatTag(t *testing.T) {
	repo := optRepo(t, func(tag string, s *optSpec) {
		pfoMutate(tag, s)
		if tag == optTags[0] {
			delete(s.files, pfoCopyA)
			delete(s.files, pfoCopyB) // the filter matches nothing at the oldest tag
		}
	})
	res := mustGenerate(t, optInput(GitSource{Dir: repo}, pfoRules(t, pfFilter(pfoGlob), true, firstFive...)))
	if len(res.Report.Dropped) != 1 || res.Report.Dropped[0].Tag != optTags[0] {
		t.Fatalf("dropped %+v", res.Report.Dropped)
	}
	for _, f := range res.Report.OptionalPaths {
		if f.Tag == optTags[0] {
			t.Fatalf("optional fact for the dropped tag: %+v", f)
		}
	}
	for _, fc := range res.Report.FilteredCopies {
		if strings.Contains(strings.Join(fc.Tags, ","), optTags[0]) {
			t.Fatalf("filtered copy names the dropped tag: %+v", fc)
		}
	}
}

func TestPathFilterNoMatchAtNewestWithOptionalStops(t *testing.T) {
	repo := optRepo(t, func(tag string, s *optSpec) {
		pfoMutate(tag, s)
		if tag == optTags[len(optTags)-1] {
			delete(s.files, pfoCopyA)
			delete(s.files, pfoCopyB)
		}
	})
	_, err := Generate(optInput(GitSource{Dir: repo}, pfoRules(t, pfFilter(pfoGlob), true, firstFive...)))
	wantStop(t, err, StopPathFilterNothing)
}

// A filter never hides a file of a group the target reads, also when an
// optional entry supplies that group at the newest tag.
func TestPathFilterCannotHideTheGroupOfAnOptionalEntry(t *testing.T) {
	repo := optRepo(t, func(tag string, s *optSpec) {
		s.files["api/config/crd/widgets.example.test_copy.yaml"] = ipCRD("widgets.example.test", "Copy")
	})
	_, err := Generate(optInput(GitSource{Dir: repo}, pfoRules(t, pfFilter("api/config/crd/widgets.example.test_copy.yaml"), true, firstFive...)))
	wantStop(t, err, StopFilterHidesOwned)
}
