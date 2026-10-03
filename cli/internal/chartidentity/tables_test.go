// SPDX-License-Identifier: AGPL-3.0-only

package chartidentity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

const (
	rev    = "0123456789abcdef0123456789abcdef01234567"
	digest = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
)

func src() []Source {
	return []Source{{ID: "chart-yaml", URL: "https://github.com/acme/widget/blob/" + rev + "/chart/Chart.yaml", Revision: rev, ContentDigest: digest, StartLine: 3, EndLine: 4}}
}

func slugComponent(t *testing.T) (string, string) {
	t.Helper()
	c, err := cncfcheck.Component("agones")
	if err != nil {
		t.Fatal(err)
	}
	return "agones", c
}

func sourceDoc(t *testing.T, mut func(*SourceTable)) []byte {
	t.Helper()
	project, comp := slugComponent(t)
	tab := SourceTable{Schema: SourcesSchema, Records: []SourceRecord{
		{RepoURL: "https://charts.example.com/stable", Chart: "agones", Component: comp, Project: project,
			Evidence: SourceEvidence{State: StateActive, ReviewedAt: "2030-01-01T00:00:00Z", ValidUntil: "2030-06-01T00:00:00Z", Sources: src()}},
		{RepoURL: "https://charts.example.com/stable", Chart: "agones-extra", Component: comp, Project: project,
			Evidence: SourceEvidence{State: StateActive, ReviewedAt: "2030-01-01T00:00:00Z", ValidUntil: "2030-06-01T00:00:00Z", Sources: src()}},
	}}
	if mut != nil {
		mut(&tab)
	}
	raw, err := json.Marshal(tab)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func appRecord(comp, chart, cv, av string) AppVersionRecord {
	return AppVersionRecord{Component: comp, Chart: chart, ChartVersion: cv, AppVersion: av,
		Evidence: AppVersionEvidence{Basis: BasisMechanical, Extractor: Extractor{ID: "chart.app-version", Version: "1.0.0", CodeDigest: digest},
			DerivedAt: "2030-01-01T00:00:00Z", ValidUntil: "2030-04-01T00:00:00Z", Sources: src()}}
}

func appDoc(t *testing.T, mut func(*AppVersionTable)) []byte {
	t.Helper()
	_, comp := slugComponent(t)
	tab := AppVersionTable{Schema: AppVersionsSchema, Records: []AppVersionRecord{
		appRecord(comp, "agones", "1.2.0", "1.30.0"), appRecord(comp, "agones", "1.3.0", "1.31.0"),
	}}
	if mut != nil {
		mut(&tab)
	}
	raw, err := json.Marshal(tab)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestChartIdentityStrict(t *testing.T) {
	if _, err := ParseSources(sourceDoc(t, nil)); err != nil {
		t.Fatalf("valid sources rejected: %v", err)
	}
	if _, err := ParseAppVersions(appDoc(t, nil)); err != nil {
		t.Fatalf("valid app versions rejected: %v", err)
	}
	srcBad := map[string]func(*SourceTable){
		"schema":       func(t *SourceTable) { t.Schema = "x" },
		"unsorted":     func(t *SourceTable) { t.Records[0], t.Records[1] = t.Records[1], t.Records[0] },
		"duplicate":    func(t *SourceTable) { t.Records[1] = t.Records[0] },
		"unnormalised": func(t *SourceTable) { t.Records[0].RepoURL = "https://Charts.example.com/stable/" },
		"bad project":  func(t *SourceTable) { t.Records[0].Project = "no-such-project" },
		"wrong subject": func(t *SourceTable) {
			t.Records[0].Component = "pkg:github/other/thing"
		},
		"bad state":  func(t *SourceTable) { t.Records[0].Evidence.State = "maybe" },
		"window":     func(t *SourceTable) { t.Records[0].Evidence.ValidUntil = t.Records[0].Evidence.ReviewedAt },
		"no sources": func(t *SourceTable) { t.Records[0].Evidence.Sources = nil },
		"mutable url": func(t *SourceTable) {
			t.Records[0].Evidence.Sources[0].URL = "https://github.com/acme/widget/blob/main/chart/Chart.yaml"
		},
		"bad digest": func(t *SourceTable) { t.Records[0].Evidence.Sources[0].ContentDigest = "sha256:zz" },
		"bad span":   func(t *SourceTable) { t.Records[0].Evidence.Sources[0].EndLine = 1 },
		"null":       func(t *SourceTable) { t.Records = nil },
		"too many": func(t *SourceTable) {
			t.Records = make([]SourceRecord, maxRecords+1)
		},
	}
	for name, mut := range srcBad {
		if _, err := ParseSources(sourceDoc(t, func(tab *SourceTable) {
			// Fresh source slices so mutations do not alias.
			for i := range tab.Records {
				tab.Records[i].Evidence.Sources = src()
			}
			mut(tab)
		})); !errors.Is(err, ErrInvalid) {
			t.Errorf("sources %s: want ErrInvalid, got %v", name, err)
		}
	}
	appBad := map[string]func(*AppVersionTable){
		"schema":      func(t *AppVersionTable) { t.Schema = "x" },
		"unsorted":    func(t *AppVersionTable) { t.Records[0], t.Records[1] = t.Records[1], t.Records[0] },
		"duplicate":   func(t *AppVersionTable) { t.Records[1] = t.Records[0] },
		"prerelease":  func(t *AppVersionTable) { t.Records[0].AppVersion = "1.30.0-rc.1" },
		"build":       func(t *AppVersionTable) { t.Records[0].AppVersion = "1.30.0+x" },
		"latest":      func(t *AppVersionTable) { t.Records[0].AppVersion = "latest" },
		"v prefix":    func(t *AppVersionTable) { t.Records[0].AppVersion = "v1.30.0" },
		"chart v":     func(t *AppVersionTable) { t.Records[0].ChartVersion = "v1.2.0" },
		"leading 0":   func(t *AppVersionTable) { t.Records[0].ChartVersion = "01.2.0" },
		"range":       func(t *AppVersionTable) { t.Records[0].ChartVersion = ">=1.2.0" },
		"basis":       func(t *AppVersionTable) { t.Records[0].Evidence.Basis = "reviewed" },
		"extractor":   func(t *AppVersionTable) { t.Records[0].Evidence.Extractor.CodeDigest = "sha256:1" },
		"derivedAt":   func(t *AppVersionTable) { t.Records[0].Evidence.DerivedAt = "yesterday" },
		"window":      func(t *AppVersionTable) { t.Records[0].Evidence.ValidUntil = "2029-01-01T00:00:00Z" },
		"time offset": func(t *AppVersionTable) { t.Records[0].Evidence.DerivedAt = "2030-01-01T00:00:00+01:00" },
		"too many":    func(t *AppVersionTable) { t.Records = make([]AppVersionRecord, maxRecords+1) },
		"null":        func(t *AppVersionTable) { t.Records = nil },
	}
	for name, mut := range appBad {
		if _, err := ParseAppVersions(appDoc(t, func(tab *AppVersionTable) {
			for i := range tab.Records {
				tab.Records[i].Evidence.Sources = src()
			}
			mut(tab)
		})); !errors.Is(err, ErrInvalid) {
			t.Errorf("app versions %s: want ErrInvalid, got %v", name, err)
		}
	}
	// Unknown fields, trailing data and garbage are rejected.
	for name, raw := range map[string]string{
		"unknown top":    `{"schema":"` + SourcesSchema + `","records":[],"extra":1}`,
		"trailing":       `{"schema":"` + SourcesSchema + `","records":[]} {}`,
		"empty":          ``,
		"not json":       `nope`,
		"unknown record": strings.Replace(string(sourceDoc(t, nil)), `"chart":`, `"bogus":1,"chart":`, 1),
	} {
		if _, err := ParseSources([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("sources %s: got %v", name, err)
		}
	}
	for name, raw := range map[string]string{
		"unknown top":    `{"schema":"` + AppVersionsSchema + `","records":[],"extra":1}`,
		"unknown record": strings.Replace(string(appDoc(t, nil)), `"appVersion":`, `"bogus":1,"appVersion":`, 1),
		"unknown evid":   strings.Replace(string(appDoc(t, nil)), `"basis":`, `"x":1,"basis":`, 1),
	} {
		if _, err := ParseAppVersions([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("app versions %s: got %v", name, err)
		}
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	tab, err := ParseAppVersions(appDoc(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	a, err := tab.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tab2, err := ParseAppVersions(a)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := tab2.Marshal()
	if string(a) != string(b) {
		t.Fatal("canonical bytes not stable")
	}
}

func TestNormalizeRepoURL(t *testing.T) {
	ok := map[string]string{
		"https://charts.example.com":             "https://charts.example.com",
		"https://Charts.Example.COM/":            "https://charts.example.com",
		"https://charts.example.com/stable/":     "https://charts.example.com/stable",
		"https://github.com/acme/widget.git":     "https://github.com/acme/widget",
		"https://github.com/acme/widget.git/":    "https://github.com/acme/widget",
		"HTTPS://github.com/Acme/Widget":         "https://github.com/Acme/Widget",
		"oci://ghcr.io/acme/charts":              "oci://ghcr.io/acme/charts",
		"oci://GHCR.io/acme/charts/":             "oci://ghcr.io/acme/charts",
		"oci://localhost:5000/charts":            "oci://localhost:5000/charts",
		"https://charts.example.com/a.b_c-d~e+f": "https://charts.example.com/a.b_c-d~e+f",
	}
	for in, want := range ok {
		got, err := NormalizeRepoURL(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v want %q", in, got, err, want)
		}
		if again, err := NormalizeRepoURL(got); err != nil || again != got {
			t.Errorf("%q not idempotent: %q %v", in, again, err)
		}
	}
	for _, in := range []string{
		"", "http://charts.example.com", "ftp://x.example.com", "file:///x", "charts.example.com", "https://",
		"https://user@charts.example.com", "https://user:pw@charts.example.com", "https://charts.example.com?x=1", "https://charts.example.com/a?",
		"https://charts.example.com/a#f", "oci://ghcr.io/acme?x=1", "https://charts.example.com//a", "https://charts.example.com/a//b",
		"https://charts.example.com/../a", "https://charts.example.com/./a", "https://charts.example.com/a%2Fb", "https://charts.example.com/a b",
		"https://charts.example.com/a\x00", "https://[::1]/a", "https://charts.example.com:99999999/a", "https://-bad.example.com", "oci:ghcr.io/x",
		"https://charts.example.com/.git", "https://charts.example.com/a\\b",
	} {
		if got, err := NormalizeRepoURL(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		} else if !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: error does not wrap ErrInvalid: %v", in, err)
		}
	}
}

func TestLookupFreshness(t *testing.T) {
	st, err := ParseSources(sourceDoc(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time { v, _ := time.Parse(timeLayout, s); return v }
	c, ok, err := st.ComponentFor("https://CHARTS.example.com/stable/", "agones", at("2030-03-01T00:00:00Z"))
	if err != nil || !ok || c.Project != "agones" {
		t.Fatalf("fresh lookup: %+v %v %v", c, ok, err)
	}
	if _, ok, _ := st.ComponentFor("https://charts.example.com/stable", "agones", at("2030-06-01T00:00:00Z")); ok {
		t.Fatal("record usable at validUntil")
	}
	if _, ok, _ := st.ComponentFor("https://charts.example.com/stable", "agones", at("2031-01-01T00:00:00Z")); ok {
		t.Fatal("expired source record usable")
	}
	if _, ok, _ := st.ComponentFor("https://charts.example.com/stable", "other", at("2030-03-01T00:00:00Z")); ok {
		t.Fatal("unknown chart found")
	}
	if _, _, err := st.ComponentFor("http://charts.example.com/stable", "agones", at("2030-03-01T00:00:00Z")); err == nil {
		t.Fatal("bad repo URL must be an error")
	}
	withdrawn, err := ParseSources(sourceDoc(t, func(tab *SourceTable) {
		tab.Records[0].Evidence.State = StateWithdrawn
		tab.Records[0].Evidence.Sources = src()
		tab.Records[1].Evidence.Sources = src()
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := withdrawn.ComponentFor("https://charts.example.com/stable", "agones", at("2030-03-01T00:00:00Z")); ok {
		t.Fatal("withdrawn record usable")
	}

	_, comp := slugComponent(t)
	av, err := ParseAppVersions(appDoc(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, err := av.AppVersionFor(comp, "agones", "v1.3.0", at("2030-02-01T00:00:00Z")); err != nil || !ok || v != "1.31.0" {
		t.Fatalf("app version: %q %v %v", v, ok, err)
	}
	if _, ok, _ := av.AppVersionFor(comp, "agones", "1.3.0", at("2030-04-01T00:00:00Z")); ok {
		t.Fatal("expired app version usable")
	}
	for _, cv := range []string{"1.3.0-rc.1", "latest", "", "1.3", "vv1.3.0"} {
		if _, ok, _ := av.AppVersionFor(comp, "agones", cv, at("2030-02-01T00:00:00Z")); ok {
			t.Fatalf("chart version %q found", cv)
		}
	}
	if _, ok, _ := av.AppVersionFor(comp, "agones", "1.9.9", at("2030-02-01T00:00:00Z")); ok {
		t.Fatal("unknown version found")
	}
}

func TestEmbeddedTablesEmpty(t *testing.T) {
	s, a, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Records) != 0 || len(a.Records) != 0 {
		t.Fatalf("embedded tables must ship empty: %d, %d", len(s.Records), len(a.Records))
	}
	if _, ok, err := ComponentFor("https://charts.example.com", "x", time.Now()); ok || err != nil {
		t.Fatalf("empty table lookup: %v %v", ok, err)
	}
	if _, ok, err := AppVersionFor("pkg:github/a/b", "x", "1.0.0", time.Now()); ok || err != nil {
		t.Fatalf("empty table lookup: %v %v", ok, err)
	}
}

func FuzzLoadTables(f *testing.F) {
	f.Add([]byte(`{"schema":"` + SourcesSchema + `","records":[]}`))
	f.Add([]byte(`{"schema":"` + AppVersionsSchema + `","records":[]}`))
	f.Add([]byte(`{"records":[{"repoURL":1}]}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if s, err := ParseSources(raw); err == nil {
			if _, err := s.Marshal(); err != nil {
				t.Fatalf("valid source table does not marshal: %v", err)
			}
		}
		if a, err := ParseAppVersions(raw); err == nil {
			out, err := a.Marshal()
			if err != nil {
				t.Fatalf("valid app-version table does not marshal: %v", err)
			}
			if _, err := ParseAppVersions(out); err != nil {
				t.Fatalf("marshal output rejected: %v", err)
			}
		}
		if n, err := NormalizeRepoURL(string(raw)); err == nil {
			if again, err := NormalizeRepoURL(n); err != nil || again != n {
				t.Fatalf("normalisation not idempotent: %q -> %q", n, again)
			}
		}
	})
}

func TestSortAppVersions(t *testing.T) {
	recs := []AppVersionRecord{
		appRecord("pkg:github/b/b", "x", "1.0.0", "1.0.0"), appRecord("pkg:github/a/a", "y", "1.0.0", "1.0.0"),
		appRecord("pkg:github/a/a", "x", "2.0.0", "1.0.0"), appRecord("pkg:github/a/a", "x", "1.0.0", "1.0.0"),
	}
	SortAppVersions(recs)
	var got []string
	for _, r := range recs {
		got = append(got, r.Component+" "+r.Chart+" "+r.ChartVersion)
	}
	want := "pkg:github/a/a x 1.0.0,pkg:github/a/a x 2.0.0,pkg:github/a/a y 1.0.0,pkg:github/b/b x 1.0.0"
	if strings.Join(got, ",") != want {
		t.Fatalf("order: %v", got)
	}
}
