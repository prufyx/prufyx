// SPDX-License-Identifier: AGPL-3.0-only

package gke

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/distribution"
	pd "github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive/derivetest"
)

// Synthetic data only: pages and feeds in testdata and below repeat the
// structure of the anchored sources; every value is invented.

const schedURL = "https://cloud.google.com" + SchedulePath
const feedURL = "https://cloud.google.com" + FeedPath

func page(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/schedule.html")
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

func mustBodies(t *testing.T, s Schedule) []string {
	t.Helper()
	b, err := s.Bodies()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestScheduleGolden(t *testing.T) {
	html := page(t)
	s, err := ParseSchedule([]byte(html))
	if err != nil {
		t.Fatal(err)
	}
	bodies := mustBodies(t, s)
	derivetest.Golden(t, "testdata/schedule-bodies.golden.json", bodies)
	xs := derivetest.Excerpts(t, "gke", "gke-schedule", schedURL, "release-schedule", []byte(html), bodies)
	f, err := DeriveSchedule(xs)
	if err != nil {
		t.Fatal(err)
	}
	derivetest.Golden(t, "testdata/schedule-facts.golden.json", f)
	f2, _ := DeriveSchedule(xs)
	if !reflect.DeepEqual(f, f2) {
		t.Fatal("derivation is not deterministic")
	}
	rev := strings.Repeat("a", 40)
	rec := distribution.Record{Distribution: "gke", ControlPlane: distribution.ControlPlaneManaged, Lifecycle: f.Lifecycle, Channels: f.Channels,
		Evidence: distribution.Evidence{State: distribution.StateActive, ReviewedAt: "2026-10-01T00:00:00Z", ValidUntil: "2026-12-30T00:00:00Z",
			Sources: []constraintengine.SourceEvidence{{ID: "x", URL: "https://github.com/prufyx/prufyx/blob/" + rev + "/cli/knowledge/provider-excerpts/gke/gke-schedule-a.txt", Revision: rev, ContentDigest: xs[0].Entry.SHA256, StartLine: 9, EndLine: 10}}}}
	if err := rec.Validate(); err != nil {
		t.Fatalf("record: %v", err)
	}
	for _, l := range f.Lifecycle {
		if l.ExtendedEnd != "" && (l.ExtendedRequiresOptIn == nil || !*l.ExtendedRequiresOptIn) {
			t.Fatalf("%s: extended end without opt-in true", l.Line)
		}
	}
}

func TestScheduleCellSemantics(t *testing.T) {
	h := page(t)
	s, err := ParseSchedule([]byte(h))
	if err != nil {
		t.Fatal(err)
	}
	f, err := DeriveSchedule(derivetest.Excerpts(t, "gke", "gke-schedule", schedURL, "release-schedule", []byte(h), mustBodies(t, s)))
	if err != nil {
		t.Fatal(err)
	}
	get := func(line string) distribution.Lifecycle {
		for _, l := range f.Lifecycle {
			if l.Line == line {
				return l
			}
		}
		t.Fatalf("no %s", line)
		return distribution.Lifecycle{}
	}
	if l := get("1.71"); l.Precision != "day" || l.StandardEnd != "2032-03-15" {
		t.Fatalf("1.71: %+v", l)
	}
	if l := get("1.75"); l.Precision != "month" || l.StandardEnd != "2033-09" || l.ExtendedEnd != "2034-06" {
		t.Fatalf("1.75 (a day coarsens to the row's month): %+v", l)
	}
	if l := get("1.76"); l.ExtendedEnd != "" || l.ExtendedRequiresOptIn != nil || l.StandardEnd != "2033-12-06" || l.Precision != "day" {
		t.Fatalf("1.76 (TBD extended end is left out): %+v", l)
	}
	for _, c := range f.Channels {
		if c.Line == "1.76" && c.Channel == "rapid" && (c.Precision != "month" || c.AutoUpgrade != "2032-11") {
			t.Fatalf("italic estimate not demoted: %+v", c)
		}
		if c.Line == "1.75" && c.Channel == "stable" && (c.Precision != "month" || c.AutoUpgrade != "2033-01" || c.Available != "2032-10") {
			t.Fatalf("1.75 stable: %+v", c)
		}
	}
	for i := 1; i < len(f.Channels); i++ {
		a, b := f.Channels[i-1], f.Channels[i]
		if a.Line == b.Line && a.Channel >= b.Channel {
			t.Fatal("channels not ascending")
		}
	}
}

func TestScheduleFailClosed(t *testing.T) {
	h := page(t)
	sup4 := `<sup id="fnref4"><a href="#fn4" rel="footnote">4</a></sup>`
	type tc struct {
		mut  func(string) string
		want string
	}
	rep := func(old, new string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				panic("fixture does not contain " + old)
			}
			return strings.Replace(s, old, new, 1)
		}
	}
	cases := map[string]tc{
		"month 13":               {rep("2032-09"+sup4, "2032-13"+sup4), pd.KindCell},
		"quarter 5":              {rep("2033-Q3", "2033-Q5"), pd.KindCell},
		"day 32":                 {rep("2033-04-12", "2033-04-32"), pd.KindCell},
		"TBA in a date cell":     {rep("<td>2034-02-01</td>", "<td>TBA</td>"), pd.KindCell},
		"unknown marker 6":       {rep(">4</a></sup></td><td>2033-04-12", ">6</a></sup></td><td>2033-04-12"), pd.KindMarker},
		"bad first cell":         {rep("<td>1.73</td>", "<td>1.7x</td>"), pd.KindRow},
		"renamed header":         {rep("End of extended support", "End of ext support"), pd.KindHeader},
		"swapped sub-header":     {rep("<th>Available<sup>1</sup></th>", "<th>Auto Upgrade<sup>1</sup></th>"), pd.KindHeader},
		"lost rowspan":           {rep(`<th rowspan="2">Minor`, `<th>Minor`), pd.KindHeader},
		"lost colspan":           {rep(`<th colspan="2">Rapid`, `<th>Rapid`), pd.KindHeader},
		"row with 10 cells":      {rep("<td>2034-02-01</td></tr>", "</tr>"), pd.KindRow},
		"row with 12 cells":      {rep("<td>2034-02-01</td></tr>", "<td>2034-02-01</td><td>x</td></tr>"), pd.KindRow},
		"span in data row":       {rep("<td>1.72</td>", `<td colspan="1" rowspan="2">1.72</td>`), pd.KindRow},
		"available after auto":   {rep("<td>2031-01-05</td><td>2031-02-02</td>", "<td>2031-03-05</td><td>2031-02-02</td>"), pd.KindRow},
		"std end after ext end":  {rep("<td>2032-03-15</td><td>2033-01-26</td>", "<td>2033-03-15</td><td>2033-01-26</td>"), pd.KindRow},
		"rows out of order":      {rep("<td>1.72</td>", "<td>1.70</td>"), pd.KindRow},
		"empty bytes":            {func(string) string { return "" }, pd.KindEmpty},
		"404 page without table": {func(string) string { return "<html><body>Not found</body></html>" }, pd.KindEmpty},
		"unterminated table":     {rep("</table>", ""), pd.KindStructure},
		"unsupported tag":        {rep("<td>1.71</td>", "<td><img src=x>1.71</td>"), pd.KindStructure},
		"nested table":           {rep("<td>1.71</td>", "<td><table></table>1.71</td>"), pd.KindStructure},
		"duplicate table": {func(s string) string {
			i := strings.Index(s, "<table>")
			j := strings.Index(s, "</table>") + 8
			return s[:j] + s[i:j] + s[j:]
		}, pd.KindHeader},
		"no data rows": {func(s string) string {
			i := strings.Index(s, "<tbody>")
			j := strings.Index(s, "</tbody>")
			return s[:i] + s[j+8:]
		}, pd.KindEmpty},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := ParseSchedule([]byte(c.mut(h)))
			if err == nil {
				t.Fatalf("accepted; %d rows", len(s.Rows))
			}
			if len(s.Rows) != 0 {
				t.Fatal("partial output on error")
			}
			if got := kind(t, err); got != c.want {
				t.Fatalf("kind %s, want %s (%v)", got, c.want, err)
			}
		})
	}
	if _, err := ParseSchedule([]byte(h)); err != nil {
		t.Fatal(err)
	}
}

func TestScheduleExcerptsFailClosed(t *testing.T) {
	h := page(t)
	s, _ := ParseSchedule([]byte(h))
	bodies := mustBodies(t, s)
	good := derivetest.Excerpts(t, "gke", "gke-schedule", schedURL, "release-schedule", []byte(h), bodies)
	if _, err := DeriveSchedule(nil); kind(t, err) != pd.KindEmpty {
		t.Fatal("no excerpts must fail")
	}
	bad := []pd.Excerpt{{Entry: good[0].Entry, Data: []byte(strings.Replace(string(good[0].Data), "2031-01-05", "2031-01-06", 1))}}
	if _, err := DeriveSchedule(bad); err == nil {
		t.Fatal("tampered excerpt accepted")
	}
	body := func(mut func(string) string) []pd.Excerpt {
		return derivetest.Excerpts(t, "gke", "gke-schedule", schedURL, "release-schedule", []byte(h), []string{mut(bodies[0])})
	}
	for name, mut := range map[string]func(string) string{
		"other format": func(b string) string { return strings.Replace(b, "gke-schedule/v1", "gke-schedule/v2", 1) },
		"bad token":    func(b string) string { return strings.Replace(b, "2031-01-05", "2031-01-5", 1) },
		"short row":    func(b string) string { return strings.Replace(b, " 2033-01-26", "", 1) },
		"impossible":   func(b string) string { return strings.Replace(b, "2031-01-05", "2031-02-30", 1) },
		"bad line":     func(b string) string { return strings.Replace(b, "1.71 ", "1.7x ", 1) },
		"order":        func(b string) string { return strings.Replace(b, "\n1.72 ", "\n1.60 ", 1) },
		"invariant":    func(b string) string { return strings.Replace(b, "2031-01-05 2031-02-02", "2031-03-05 2031-02-02", 1) },
	} {
		if _, err := DeriveSchedule(body(mut)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	for name, x := range map[string]pd.Excerpt{
		"provider": derivetest.Excerpts(t, "eks", "gke-schedule", schedURL, "release-schedule", []byte(h), bodies)[0],
		"host":     derivetest.Excerpts(t, "gke", "gke-schedule", "https://learn.microsoft.com"+SchedulePath, "release-schedule", []byte(h), bodies)[0],
		"path":     derivetest.Excerpts(t, "gke", "gke-schedule", "https://cloud.google.com/other", "release-schedule", []byte(h), bodies)[0],
	} {
		if _, err := DeriveSchedule([]pd.Excerpt{x}); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestScheduleSplitsLongTables(t *testing.T) {
	var rows []Row
	for i := 0; i < 20; i++ {
		d, _ := pd.ParseISO("2031-01-05")
		r := Row{Line: fmt.Sprintf("1.%d", 20+i)}
		for k := range r.Dates {
			r.Dates[k] = d
		}
		rows = append(rows, r)
	}
	bodies, err := (Schedule{Rows: rows}).Bodies()
	if err != nil || len(bodies) < 2 {
		t.Fatalf("expected several bodies: %v %d", err, len(bodies))
	}
	for _, b := range bodies {
		if len(b) > MaxBody || !strings.HasPrefix(b, ScheduleFormat+"\n") {
			t.Fatal("body over cap or without format line")
		}
	}
	xs := derivetest.Excerpts(t, "gke", "gke-schedule", schedURL, "release-schedule", []byte("x"), bodies)
	f, err := DeriveSchedule(xs)
	if err != nil || len(f.Lifecycle) != 20 {
		t.Fatalf("%v %d", err, len(f.Lifecycle))
	}
	xs[0], xs[1] = xs[1], xs[0]
	if _, err := DeriveSchedule(xs); err == nil {
		t.Fatal("unordered excerpts accepted")
	}
}

// ---- feed ----

func feed(n int, mut func(i int, title, updated, content *string)) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><id>tag:example,2032:feed</id><updated>2032-03-30T00:00:00-07:00</updated>`)
	for i := 0; i < n; i++ {
		day := 30 - i
		mon := "March"
		num := 3
		if day < 1 {
			day += 28
			mon, num = "February", 2
		}
		title := fmt.Sprintf("%s %02d, 2032", mon, day)
		updated := fmt.Sprintf("2032-%02d-%02dT00:00:00-08:00", num, day)
		content := fmt.Sprintf(`<h2>%s</h2><h3>Rapid channel</h3><p>The following versions are now available in the Rapid channel:</p><ul><li>1.71.%d-gke.%d000</li><li>1.72.%d-gke.%d000</li></ul><p>In version 1.99.9-gke.99 and later, a feature appears.</p>`, title, i, i+1, i, i+2)
		if i == 0 {
			content += `<h3>Stable channel</h3><p>The following versions are now available in the Stable channel: 1.70.3-gke.77, 1.70.3-gke.77, 1.71.0-gke.500+preview</p>`
		}
		if mut != nil {
			mut(i, &title, &updated, &content)
		}
		fmt.Fprintf(&b, `<entry><title>%s</title><id>tag:example,2032:%d</id><updated>%s</updated><content type="html"><![CDATA[%s]]></content></entry>`, title, i, updated, content)
	}
	b.WriteString(`</feed>`)
	return b.String()
}

func TestFeedGolden(t *testing.T) {
	raw := feed(30, nil)
	es, err := ParseFeed([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 30 || es[0].Day != "2032-03-30" {
		t.Fatalf("%d entries, first %s", len(es), es[0].Day)
	}
	var first []string
	for _, r := range es[0].Releases {
		first = append(first, fmt.Sprintf("%s %s %v", r.Channel, r.Version, r.Prerelease))
	}
	want := []string{"rapid 1.71.0-gke.1000 false", "rapid 1.72.0-gke.2000 false", "stable 1.70.3-gke.77 false", "stable 1.71.0-gke.500 true"}
	if !reflect.DeepEqual(first, want) {
		t.Fatalf("got %v", first)
	}
	var xs []pd.Excerpt
	for i := len(es) - 1; i >= 0; i-- {
		xs = append(xs, derivetest.Excerpts(t, "gke", "gke-feed-"+es[i].Day, feedURL, "feed-"+es[i].Day, []byte(raw), []string{EntryBody(es[i])})...)
	}
	rel, err := DeriveFeed(xs)
	if err != nil {
		t.Fatal(err)
	}
	derivetest.Golden(t, "testdata/feed-last-releases.golden.json", rel[len(rel)-4:])
	pre := 0
	for _, r := range rel {
		if r.Prerelease {
			pre++
			if strings.Contains(r.Version, "+") {
				t.Fatal("preview marker leaked into version")
			}
		}
	}
	if pre != 1 {
		t.Fatalf("%d previews", pre)
	}
}

func TestFeedFailClosed(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want string
	}{
		"empty":        {"", pd.KindEmpty},
		"not xml":      {"<html><body>404</body>", pd.KindStructure},
		"29 entries":   {feed(29, nil), pd.KindIncomplete},
		"zero entries": {feed(0, nil), pd.KindIncomplete},
		"title mismatch": {feed(30, func(i int, ti, u, c *string) {
			if i == 3 {
				*ti = "March 01, 2032"
			}
		}), pd.KindRow},
		"day order": {feed(30, func(i int, ti, u, c *string) {
			if i == 3 {
				*u = "2032-03-31T00:00:00-08:00"
				*ti = "March 31, 2032"
			}
		}), pd.KindRow},
		"bad timestamp": {feed(30, func(i int, ti, u, c *string) {
			if i == 2 {
				*u = "soon"
			}
		}), pd.KindRow},
		"unknown channel": {feed(30, func(i int, ti, u, c *string) {
			if i == 1 {
				*c += `<p>The following versions are now available in the No channel: 1.60.1-gke.5</p>`
			}
		}), pd.KindCell},
		"unknown suffix": {feed(30, func(i int, ti, u, c *string) {
			if i == 1 {
				*c += `<p>The following versions are now available in the Regular channel: 1.71.1-gke.9+nightly</p>`
			}
		}), pd.KindCell},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			es, err := ParseFeed([]byte(c.raw))
			if err == nil || es != nil {
				t.Fatalf("accepted %d entries", len(es))
			}
			if got := kind(t, err); got != c.want {
				t.Fatalf("kind %s, want %s", got, c.want)
			}
		})
	}
}

func TestFeedPreviewNeverStable(t *testing.T) {
	e := Entry{Day: "2032-03-30", Releases: []Release{{Day: "2032-03-30", Channel: "stable", Version: "1.71.0-gke.500", Prerelease: true}}}
	xs := derivetest.Excerpts(t, "gke", "gke-feed-x", feedURL, "feed-2032-03-30", []byte("x"), []string{EntryBody(e)})
	rel, err := DeriveFeed(xs)
	if err != nil || len(rel) != 1 || !rel[0].Prerelease {
		t.Fatalf("%v %+v", err, rel)
	}
	for name, body := range map[string]string{
		"channel": FeedFormat + "\nday 2032-03-30\nnone 1.71.0-gke.5\n",
		"suffix":  FeedFormat + "\nday 2032-03-30\nstable 1.71.0-gke.5+nightly\n",
		"repeat":  FeedFormat + "\nday 2032-03-30\nstable 1.71.0-gke.5 1.71.0-gke.5\n",
		"day":     FeedFormat + "\nday 2032-02-30\nstable 1.71.0-gke.5\n",
		"order":   FeedFormat + "\nday 2032-03-30\nstable 1.71.0-gke.5\nrapid 1.71.0-gke.6\n",
		"format":  "format other\nday 2032-03-30\nstable 1.71.0-gke.5\n",
	} {
		xs := derivetest.Excerpts(t, "gke", "gke-feed-x", feedURL, "feed-2032-03-30", []byte("x"), []string{body})
		if _, err := DeriveFeed(xs); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	a := derivetest.Excerpts(t, "gke", "gke-feed-a", feedURL, "feed-a", []byte("x"), []string{EntryBody(Entry{Day: "2032-03-30"})})
	b := derivetest.Excerpts(t, "gke", "gke-feed-b", feedURL, "feed-b", []byte("x"), []string{EntryBody(Entry{Day: "2032-03-29"})})
	if _, err := DeriveFeed(append(a, b...)); err == nil {
		t.Fatal("descending days accepted")
	}
}
