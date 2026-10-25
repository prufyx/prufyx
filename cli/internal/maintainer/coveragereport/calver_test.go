// SPDX-License-Identifier: AGPL-3.0-only

package coveragereport

import (
	"slices"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

func calverScenario(lines ...string) scenario {
	s := gatewayScenario(lines...)
	s.scheme = crdversions.SchemeCalverEdge
	s.releases = map[string][]string{"25.11": {"25.11.1"}, "25.12": {"25.12.1", "25.12.2"}, "26.1": {"26.1.1"}, "26.2": {"26.2.1"}}
	return s
}

// A calendar project's January line follows the December of the year
// before: the pair across the new year is attested and the project is
// complete. Without the calendar rule the same snapshot would compare 26.1
// with 26.0.
func TestCalverRolloverPairIsAttested(t *testing.T) {
	restore := lineattest.SetCalverComponentsForTest("pkg:github/kubernetes-sigs/gateway-api")
	r := combined(t, calverScenario("25.11", "25.12", "26.1", "26.2"))
	p := rowOf(t, r, "gateway-api")
	if statuses(p) != "AAA" || p.A != 3 {
		t.Fatalf("calendar project: %s (%+v)", statuses(p), p)
	}
	// A calendar project is never complete: a skipped month is no hole.
	assertComplete(t, p, false, whyCalendarLines)
	if p.Counts.Decided != 3 {
		t.Fatalf("counts %+v", p.Counts)
	}
	restore()
	// The control: the same component as an ordinary one reads 26.1 after 26.0.
	s := calverScenario("25.11", "25.12", "26.1", "26.2")
	s.scheme = ""
	p = rowOf(t, combined(t, s), "gateway-api")
	if statuses(p) != "AGA" {
		t.Fatalf("ordinary component: %s", statuses(p))
	}
}

// A month nobody released in is not a line: the pair over the gap is not
// attested.
func TestCalverSkippedMonthIsNotAttested(t *testing.T) {
	defer lineattest.SetCalverComponentsForTest("pkg:github/kubernetes-sigs/gateway-api")()
	s := calverScenario("25.10", "25.11", "26.1")
	s.releases = map[string][]string{"25.10": {"25.10.1"}, "25.11": {"25.11.1"}, "26.1": {"26.1.1"}}
	if got := statuses(rowOf(t, combined(t, s), "gateway-api")); got != "AG" {
		t.Fatalf("pair over a skipped month: %s", got)
	}
}

func TestLinesSchemeField(t *testing.T) {
	doc := func(scheme string, lines ...string) []byte {
		quoted := `"` + strings.Join(lines, `","`) + `"`
		return []byte(`{"schema":"` + LinesSchema + `","projects":{"p":{` + scheme + `"lines":[` + quoted + `]}}}`)
	}
	for _, c := range []struct {
		name   string
		scheme string
		lines  []string
		ok     bool
	}{
		{"absent", ``, []string{"1.28", "1.29"}, true},
		{"calver", `"scheme":"calver-edge",`, []string{"25.12", "26.1", "26.10"}, true},
		{"unknown scheme", `"scheme":"calver",`, []string{"26.1"}, false},
		{"empty scheme is absent", `"scheme":"",`, []string{"26.1"}, true},
		{"month 13", `"scheme":"calver-edge",`, []string{"26.13"}, false},
		{"month 0", `"scheme":"calver-edge",`, []string{"26.0"}, false},
		{"semver snapshot may hold minor 13", ``, []string{"1.13"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseLines(doc(c.scheme, c.lines...))
			if (err == nil) != c.ok {
				t.Fatalf("ParseLines: %v, want ok=%v", err, c.ok)
			}
			if err == nil && strings.Contains(c.scheme, "calver-edge") && f.Projects["p"].Scheme != crdversions.SchemeCalverEdge {
				t.Fatalf("scheme %q", f.Projects["p"].Scheme)
			}
		})
	}
	// The member survives the canonical marshal.
	f, err := ParseLines(doc(`"scheme":"calver-edge",`, "26.1"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := MarshalLines(f)
	if err != nil || !strings.Contains(string(out), `"scheme": "calver-edge"`) {
		t.Fatalf("marshal: %v\n%s", err, out)
	}
	// A snapshot without a scheme marshals without the member.
	f, _ = ParseLines(doc(``, "1.28"))
	if out, _ := MarshalLines(f); strings.Contains(string(out), "scheme") {
		t.Fatalf("scheme written for a semver project:\n%s", out)
	}
}

func TestLinesFromCalverTags(t *testing.T) {
	scheme := func(project string) string {
		if project == "edge" {
			return crdversions.SchemeCalverEdge
		}
		return ""
	}
	tags := "refs/tags/edge-24.7.1\nrefs/tags/edge-25.03.1\nrefs/tags/edge-25.12.5\nrefs/tags/26.1.1-edge\nrefs/tags/26.1.2-edge\n" +
		"refs/tags/26.10.4-edge\nrefs/tags/26.10.4-edge^{}\nrefs/tags/edge-26.3.2-rc1\nrefs/tags/v26.3.2-edge\nrefs/tags/26.3.2\n"
	f, err := linesFromTags(map[string][]byte{"edge": []byte(tags), "plain": []byte("v1.2.0\nv1.2.1\n")}, nil, scheme, "2026-10-22")
	if err != nil {
		t.Fatal(err)
	}
	e := f.Projects["edge"]
	if e.Scheme != crdversions.SchemeCalverEdge || !slices.Equal(e.Lines, []string{"24.7", "25.3", "25.12", "26.1", "26.10"}) {
		t.Fatalf("edge %+v", e)
	}
	if !slices.Equal(e.Releases["26.1"], []string{"26.1.1", "26.1.2"}) || !slices.Equal(e.Releases["26.10"], []string{"26.10.4"}) || !slices.Equal(e.Releases["25.3"], []string{"25.3.1"}) {
		t.Fatalf("releases %+v", e.Releases)
	}
	if p := f.Projects["plain"]; p.Scheme != "" || !slices.Equal(p.Lines, []string{"1.2"}) {
		t.Fatalf("plain %+v", p)
	}
	// A project without a calendar target keeps reading semver tags, so the
	// public entry points are unchanged for every project of today.
	if line, ok := LineOfTag("demo", "26.1.1-edge"); ok {
		t.Fatalf("semver project read an edge tag as line %s", line)
	}
	if line, ok := lineOfTag("edge", crdversions.SchemeCalverEdge, "26.1.1-edge"); !ok || line != "26.1" {
		t.Fatalf("calendar tag: %q %v", line, ok)
	}
	if v, ok := releaseOfTag("edge", crdversions.SchemeCalverEdge, "edge-24.7.1"); !ok || v != "24.7.1" {
		t.Fatalf("calendar release: %q %v", v, ok)
	}
	if _, ok := releaseOfTag("edge", crdversions.SchemeCalverEdge, "edge-24.7.01"); ok {
		t.Fatal("a non-canonical counter is not a release")
	}
	if v, ok := releaseOfTag("edge", crdversions.SchemeCalverEdge, "edge-24.07.1"); !ok || v != "24.7.1" {
		t.Fatalf("zero-padded month: %q %v", v, ok)
	}
}
