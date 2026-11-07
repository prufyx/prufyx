// SPDX-License-Identifier: AGPL-3.0-only

package aks

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/derivetest"
)

// Synthetic data only: pages and release lists in testdata repeat the
// structure of the anchored sources; every value is invented.

const supURL = "https://" + SupportHost + SupportPath
const relURL = "https://github.com" + ReleasesPath

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func kind(t *testing.T, err error) string {
	t.Helper()
	var d *pd.DriftError
	if !errors.As(err, &d) || !errors.Is(err, pd.ErrDrift) {
		t.Fatalf("want a typed drift error, got %v", err)
	}
	return d.Kind
}

func rep(old, new string) func(string) string {
	return func(s string) string {
		if !strings.Contains(s, old) {
			panic("fixture does not contain " + old)
		}
		return strings.Replace(s, old, new, 1)
	}
}

func TestSupportGolden(t *testing.T) {
	h := read(t, "support.html")
	s, err := ParseSupport([]byte(h))
	if err != nil {
		t.Fatal(err)
	}
	bodies, err := s.Bodies()
	if err != nil {
		t.Fatal(err)
	}
	derivetest.Golden(t, "testdata/support-bodies.golden.json", bodies)
	xs := derivetest.Excerpts(t, "aks", "aks-support", supURL, "supported-versions", []byte(h), bodies)
	f, err := DeriveSupport(xs)
	if err != nil {
		t.Fatal(err)
	}
	derivetest.Golden(t, "testdata/support-facts.golden.json", f)
	f2, _ := DeriveSupport(xs)
	if !reflect.DeepEqual(f, f2) {
		t.Fatal("not deterministic")
	}
	rev := strings.Repeat("a", 40)
	rec := distribution.Record{Distribution: "aks", ControlPlane: distribution.ControlPlaneManaged, Lifecycle: f.Lifecycle,
		Evidence: distribution.Evidence{State: distribution.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
			Sources: []constraintengine.SourceEvidence{{ID: "x", URL: "https://github.com/prufyx/prufyx/blob/" + rev + "/cli/knowledge/provider-excerpts/aks/aks-support-a.txt", Revision: rev, ContentDigest: xs[0].Entry.SHA256, StartLine: 9, EndLine: 10}}}}
	if err := rec.Validate(); err != nil {
		t.Fatalf("record: %v", err)
	}
}

func TestSupportSemantics(t *testing.T) {
	h := read(t, "support.html")
	s, _ := ParseSupport([]byte(h))
	bodies, _ := s.Bodies()
	f, err := DeriveSupport(derivetest.Excerpts(t, "aks", "aks-support", supURL, "supported-versions", []byte(h), bodies))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]distribution.Lifecycle{}
	for _, l := range f.Lifecycle {
		by[l.Line] = l
	}
	// The LTS-only line (dropped from the standard table) is kept; the day in
	// its End of life cell coarsens to the row's month precision.
	if l := by["1.70"]; l.GA != "2030-07" || l.StandardEnd != "2031-08" || l.ExtendedEnd != "2032-07" || l.Precision != "month" || l.ExtendedRequiresOptIn == nil || !*l.ExtendedRequiresOptIn {
		t.Fatalf("1.70: %+v", l)
	}
	// A standard-only line has no extended end and no opt-in flag.
	if l := by["1.75"]; l.ExtendedEnd != "" || l.ExtendedRequiresOptIn != nil || l.StandardEnd != "2033-03" {
		t.Fatalf("1.75: %+v", l)
	}
	// "Until 1.N GA" in Platform support is not a date and not a lifecycle field.
	if _, ok := by["1.72"]; !ok {
		t.Fatal("1.72 missing")
	}
	// Preview-only line (GA is TBD): no lifecycle row, listed as prerelease.
	if _, ok := by["1.78"]; ok || !reflect.DeepEqual(f.Prerelease, []string{"1.78"}) {
		t.Fatalf("1.78 must be prerelease only: %v", f.Prerelease)
	}
	// A TBD GA date makes a line a prerelease as well.
	h2 := rep("<td>Apr 2032</td><td>Jun 2032</td><td>Aug 2032</td>", "<td>Apr 2032</td><td>Jun 2032</td><td>TBD</td>")(h)
	s2, err := ParseSupport([]byte(h2))
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := s2.Bodies()
	f2, err := DeriveSupport(derivetest.Excerpts(t, "aks", "aks-support", supURL, "supported-versions", []byte(h2), b2))
	if err != nil || !reflect.DeepEqual(f2.Prerelease, []string{"1.76", "1.78"}) {
		t.Fatalf("%v %v", err, f2.Prerelease)
	}
	if len(f.PlatformUpgrade) != 7 {
		t.Fatalf("platform upgrade dates: %v", f.PlatformUpgrade)
	}
	// Tables are found by header text, not position: the fixture puts the LTS
	// table before the standard one.
	if strings.Index(h, "LTS End of life") > strings.Index(h, ">Platform support<") {
		t.Fatal("fixture no longer exercises table order")
	}
}

func TestSupportFailClosed(t *testing.T) {
	h := read(t, "support.html")
	cases := map[string]struct {
		mut  func(string) string
		want string
	}{
		"month name":          {rep("<td>Mar 2032</td>", "<td>Smarch 2032</td>"), pd.KindCell},
		"iso month":           {rep("<td>Mar 2032</td>", "<td>2032-03</td>"), pd.KindCell},
		"day without comma":   {rep("<td>Nov 1, 2032</td>", "<td>Nov 1 2032</td>"), pd.KindCell},
		"Until without line":  {rep("<td>Until 1.76 GA</td>", "<td>Until GA</td>"), pd.KindCell},
		"Sept":                {rep("<td>Dec 2031</td>", "<td>Sept 2031</td>"), pd.KindCell},
		"day 31 of April":     {rep("<td>Nov 1, 2032</td>", "<td>Apr 31, 2032</td>"), pd.KindCell},
		"bad minor":           {rep("<td>1.73</td>", "<td>1.x</td>"), pd.KindCell},
		"swapped header":      {rep("<th>AKS GA</th>", "<th>End of life</th>"), pd.KindHeader},
		"missing column":      {rep("<th>Platform-initiated upgrade</th>", ""), pd.KindHeader},
		"six cells":           {rep("<td>Jun 2033</td></tr>", "</tr>"), pd.KindRow},
		"lines out of order":  {rep("<td>1.73</td>", "<td>1.71</td>"), pd.KindRow},
		"tables disagree":     {rep("<td>Mar 2032</td><td>Until 1.76 GA</td>", "<td>Apr 2032</td><td>Until 1.76 GA</td>"), pd.KindConflict},
		"date order":          {rep("<td>Mar 2033</td>", "<td>Mar 2031</td>"), pd.KindRow},
		"empty bytes":         {func(string) string { return "" }, pd.KindEmpty},
		"js shell, no table":  {func(string) string { return "<html><body><div id=app></div><script>load()</script></body></html>" }, pd.KindEmpty},
		"header span":         {rep("<th>AKS GA</th>", `<th colspan="2">AKS GA</th>`), pd.KindHeader},
		"marker in data cell": {rep("<td>Mar 2032</td>", "<td>Mar 2032<sup>1</sup></td>"), pd.KindRow},
		"unclosed table":      {rep("</table>\n</body>", "\n</body>"), pd.KindStructure},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			// The LTS-only duplicate of a standard row needs the same mutation
			// in the first matching table only; rep touches the first match.
			s, err := ParseSupport([]byte(c.mut(h)))
			if err == nil {
				t.Fatalf("accepted: %d+%d rows", len(s.Standard), len(s.LTS))
			}
			if len(s.Standard)+len(s.LTS) != 0 {
				t.Fatal("partial output on error")
			}
			if got := kind(t, err); got != c.want {
				t.Fatalf("kind %s, want %s (%v)", got, c.want, err)
			}
		})
	}
	// A missing table is a reject, never a fallback to another table.
	noLTS := func(s string) string {
		i := strings.Index(s, "LTS End of life")
		a := strings.LastIndex(s[:i], "<table>")
		b := strings.Index(s[i:], "</table>") + i + 8
		return s[:a] + s[b:]
	}
	if _, err := ParseSupport([]byte(noLTS(h))); kind(t, err) != pd.KindHeader {
		t.Fatal("missing LTS table accepted")
	}
}

func TestSupportExcerptsFailClosed(t *testing.T) {
	h := read(t, "support.html")
	s, _ := ParseSupport([]byte(h))
	bodies, _ := s.Bodies()
	if _, err := DeriveSupport(nil); kind(t, err) != pd.KindEmpty {
		t.Fatal("no excerpts accepted")
	}
	for name, mut := range map[string]func(string) string{
		"format":     func(b string) string { return strings.Replace(b, "aks-support/v1", "aks-support/v9", 1) },
		"token":      func(b string) string { return strings.Replace(b, "std 1.72 2030-12", "std 1.72 2030-12-99", 1) },
		"quarter":    func(b string) string { return strings.Replace(b, "std 1.72 2030-12", "std 1.72 2030-Q4", 1) },
		"until line": func(b string) string { return strings.Replace(b, "until:1.76", "until:x", 1) },
		"short":      func(b string) string { return strings.Replace(b, " 2033-06\n", "\n", 1) },
		"kind":       func(b string) string { return strings.Replace(b, "std 1.72", "ext 1.72", 1) },
	} {
		xs := derivetest.Excerpts(t, "aks", "aks-support", supURL, "supported-versions", []byte(h), []string{mut(bodies[0])})
		if _, err := DeriveSupport(xs); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	for name, u := range map[string]string{
		"host": "https://docs.aws.amazon.com" + SupportPath,
		"path": "https://" + SupportHost + "/en-us/azure/other",
	} {
		xs := derivetest.Excerpts(t, "aks", "aks-support", u, "supported-versions", []byte(h), bodies[:1])
		if _, err := DeriveSupport(xs); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	good := derivetest.Excerpts(t, "aks", "aks-support", supURL, "supported-versions", []byte(h), bodies)
	tam := []pd.Excerpt{{Entry: good[0].Entry, Data: []byte(strings.Replace(string(good[0].Data), "2030-12", "2030-11", 1))}}
	if _, err := DeriveSupport(tam); err == nil {
		t.Fatal("tampered excerpt accepted")
	}
}

func TestReleases(t *testing.T) {
	raw := read(t, "releases.json")
	r, err := ParseReleases([]byte(raw), true)
	if err != nil {
		t.Fatal(err)
	}
	if r.Complete {
		t.Fatal("more pages exist: history must be flagged incomplete")
	}
	if len(r.Releases) != 4 || len(r.Skipped) != 1 || r.Skipped[0].Tag != "AppNet-2032-02-19" || r.Skipped[0].Reason != SkipTagGrammar {
		t.Fatalf("%+v", r)
	}
	for _, x := range r.Releases {
		want := x.Tag == "2032-02-12" // preview only from the name text, the flag is unused
		if x.Prerelease != want {
			t.Fatalf("%s prerelease=%v", x.Tag, x.Prerelease)
		}
	}
	bodies, err := r.Bodies()
	if err != nil {
		t.Fatal(err)
	}
	derivetest.Golden(t, "testdata/releases-bodies.golden.json", bodies)
	xs := derivetest.Excerpts(t, "aks", "aks-releases", relURL, "releases", []byte(raw), bodies)
	got, err := DeriveReleases(xs)
	if err != nil || got.Complete || !reflect.DeepEqual(got.Releases, r.Releases) {
		t.Fatalf("%v %+v", err, got)
	}
	full, _ := ParseReleases([]byte(raw), false)
	b2, _ := full.Bodies()
	g2, err := DeriveReleases(derivetest.Excerpts(t, "aks", "aks-releases", relURL, "releases", []byte(raw), b2))
	if err != nil || !g2.Complete {
		t.Fatalf("%v %+v", err, g2)
	}
	// The flag alone also makes a prerelease.
	flag := strings.Replace(raw, `"prerelease": false`, `"prerelease": true`, 1)
	if r2, _ := ParseReleases([]byte(flag), false); !r2.Releases[0].Prerelease {
		t.Fatal("prerelease flag ignored")
	}
}

func TestReleasesFailClosed(t *testing.T) {
	raw := read(t, "releases.json")
	for name, c := range map[string]struct {
		in   string
		want string
	}{
		"empty body":    {"", pd.KindEmpty},
		"404 json":      {`{"message":"Not Found"}`, pd.KindStructure},
		"no releases":   {`[]`, pd.KindEmpty},
		"not json":      {"<html>", pd.KindStructure},
		"bad published": {strings.Replace(raw, "2032-03-16T12:00:00Z", "yesterday", 1), pd.KindRow},
		"invalid tag":   {strings.Replace(raw, `"2032-03-02"`, `"2032-02-31"`, 1), pd.KindCell},
		"tag order":     {strings.Replace(raw, `"tag_name": "2032-03-02"`, `"tag_name": "2032-03-20"`, 1), pd.KindRow},
		"publish order": {strings.Replace(raw, "2032-03-03T12:00:00Z", "2032-03-30T12:00:00Z", 1), pd.KindRow},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := ParseReleases([]byte(c.in), false)
			if err == nil {
				t.Fatalf("accepted %+v", r)
			}
			if len(r.Releases) != 0 {
				t.Fatal("partial output")
			}
			if got := kind(t, err); got != c.want {
				t.Fatalf("kind %s, want %s", got, c.want)
			}
		})
	}
	good, _ := ParseReleases([]byte(raw), false)
	b, _ := good.Bodies()
	for name, mut := range map[string]func(string) string{
		"format":  func(s string) string { return strings.Replace(s, "aks-releases/v1", "aks-releases/v2", 1) },
		"order":   func(s string) string { return strings.Replace(s, "release 2032-03-02", "release 2032-03-20", 1) },
		"kind":    func(s string) string { return strings.Replace(s, "preview ", "beta ", 1) },
		"invalid": func(s string) string { return strings.Replace(s, "2032-03-14 2032-03-16", "2032-03-14 2032-13-16", 1) },
	} {
		xs := derivetest.Excerpts(t, "aks", "aks-releases", relURL, "releases", []byte(raw), []string{mut(b[0])})
		if _, err := DeriveReleases(xs); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
