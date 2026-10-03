// SPDX-License-Identifier: AGPL-3.0-only

package chartversions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

var fixedDigest = "sha256:" + strings.Repeat("ab", 32)

func fixedOptions() Options {
	return Options{
		DerivedAt:  time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
		ValidUntil: time.Date(2030, 4, 2, 3, 4, 5, 0, time.UTC),
		Extractor:  chartidentity.Extractor{ID: ExtractorID, Version: ExtractorVersion, CodeDigest: fixedDigest},
	}
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s differs from golden:\n%s", name, got)
	}
}

func TestDeriveFixture(t *testing.T) {
	state := buildMirror(t, standardReleases(), true)
	table, report, err := Derive(openReader(t, state), fixtureMapping(), fixedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Records) != 2 || table.Records[0].ChartVersion != "1.2.0" || table.Records[0].AppVersion != "1.30.0" ||
		table.Records[1].ChartVersion != "1.3.0" || table.Records[1].AppVersion != "1.31.0" {
		t.Fatalf("records: %+v", table.Records)
	}
	e := report.Entries[0]
	if e.Matched != 3+1 || e.Derived != 2 || len(e.Withheld) != 2 {
		t.Fatalf("report: %+v", e)
	}
	if e.Withheld[0].Tag != "v1.3.1-rc.1" || !strings.Contains(e.Withheld[0].Reason, "not a strict X.Y.Z") ||
		e.Withheld[1].Tag != "v1.4.0" || !strings.Contains(e.Withheld[1].Reason, `appVersion "latest"`) {
		t.Fatalf("withheld: %+v", e.Withheld)
	}
	raw, err := table.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "app-versions.golden.json", raw)
	rb, _ := json.MarshalIndent(report, "", "  ")
	golden(t, "report.golden.json", append(rb, '\n'))
}

func TestDeriveProvenance(t *testing.T) {
	state := buildMirror(t, standardReleases(), true)
	r := openReader(t, state)
	table, _, err := Derive(r, fixtureMapping(), fixedOptions())
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := extract.ParseRepo(fixtureRepo)
	for _, rec := range table.Records {
		s := rec.Evidence.Sources[0]
		data, err := r.Read(repo, s.Revision, "chart/Chart.yaml")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if s.ContentDigest != "sha256:"+hex.EncodeToString(sum[:]) {
			t.Fatalf("digest of %s is not the whole-file sha256", rec.ChartVersion)
		}
		if s.URL != "https://github.com/acme/widget/blob/"+s.Revision+"/chart/Chart.yaml" {
			t.Fatalf("url: %s", s.URL)
		}
		lines := strings.Split(string(data), "\n")
		if !strings.HasPrefix(lines[s.StartLine-1], "version:") || !strings.HasPrefix(lines[s.EndLine-1], "appVersion:") {
			t.Fatalf("span %d-%d covers %q .. %q", s.StartLine, s.EndLine, lines[s.StartLine-1], lines[s.EndLine-1])
		}
		if s.StartLine != 4 || s.EndLine != 5 {
			t.Fatalf("span %d-%d", s.StartLine, s.EndLine)
		}
	}
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, func() time.Time { return time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC) }, &out, &errb)
	return code, out.String(), errb.String()
}

func writeMapping(t *testing.T) string {
	t.Helper()
	raw, _ := json.Marshal(fixtureMapping())
	p := filepath.Join(t.TempDir(), "mapping.json")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDeriveReproducible(t *testing.T) {
	state := buildMirror(t, standardReleases(), true)
	mapping := writeMapping(t)
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	for _, p := range []string{a, b} {
		if code, out, errs := runCLI(t, "derive", "--mirror", state, "--mapping", mapping, "--out", p); code != 0 {
			t.Fatalf("derive: %d %s %s", code, out, errs)
		}
	}
	ra, _ := os.ReadFile(a)
	rb, _ := os.ReadFile(b)
	if !bytes.Equal(ra, rb) || len(ra) == 0 {
		t.Fatal("two derivations differ")
	}
	if code, out, errs := runCLI(t, "verify", "--mirror", state, "--mapping", mapping, "--out", a); code != 0 || !strings.Contains(out, "verified 2 records") {
		t.Fatalf("verify: %d %s %s", code, out, errs)
	}
	// Verification does not depend on the wall clock.
	code, _, _ := runCLI(t, "verify", "--mirror", state, "--mapping", mapping, "--out", a, "--valid-days", "5")
	if code != 0 {
		t.Fatal("verify must take its times from the table")
	}
}

func TestVerifyDetectsChange(t *testing.T) {
	state := buildMirror(t, standardReleases(), true)
	mapping := writeMapping(t)
	out := filepath.Join(t.TempDir(), "t.json")
	if code, o, e := runCLI(t, "derive", "--mirror", state, "--mapping", mapping, "--out", out); code != 0 {
		t.Fatalf("derive: %s %s", o, e)
	}
	raw, _ := os.ReadFile(out)
	// Change the application version of the first record by one digit; the
	// table stays valid, only the mirror disagrees.
	i := bytes.Index(raw, []byte(`"appVersion": "1.30.0"`))
	if i < 0 {
		t.Fatal("fixture shape changed")
	}
	raw[i+len(`"appVersion": "1.3`)] = '1'
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "verify", "--mirror", state, "--mapping", mapping, "--out", out); code != 1 {
		t.Fatalf("verify accepted an altered table: %d", code)
	}
	// A pure formatting change is also caught: bytes must match exactly.
	raw[i+len(`"appVersion": "1.3`)] = '0'
	if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(t, "verify", "--mirror", state, "--mapping", mapping, "--out", out); code != 1 {
		t.Fatalf("verify accepted extra bytes: %d", code)
	}
}

func TestDeriveWithholdsAndFailures(t *testing.T) {
	rels := []release{
		{"v1.0.0", map[string]string{"chart/Chart.yaml": chartYAML("other", "1.0.0", "1.0.0")}},                                // wrong name
		{"v1.1.0", map[string]string{"chart/Chart.yaml": chartYAML("widget", "1.0.9", "1.1.0")}},                               // version != tag
		{"v1.2.0", map[string]string{"chart/Chart.yaml": "name: widget\nversion: 1.2.0\n"}},                                    // no appVersion
		{"v1.3.0", map[string]string{"chart/Chart.yaml": "name: widget\nversion: 1.3.0\nversion: 1.3.0\nappVersion: 1.3.0\n"}}, // duplicate key
		{"v1.4.0", map[string]string{"chart/Chart.yaml": "name: widget\nversion: 1.4.0\nappVersion: 1.4\n"}},                   // two-part
		{"v1.5.0", map[string]string{"README.md": "x\n"}},                                                                      // Chart.yaml moved away
		{"v1.6.0", map[string]string{"chart/Chart.yaml": "name: widget\nversion: 1.6.0\nappVersion: [1.6.0]\n"}},               // not scalar
		{"v1.7.0", map[string]string{"chart/Chart.yaml": "name: widget\nversion: 1.7.0\nappVersion: 1.7.0\n"}},                 // good
		{"v1.8.0", map[string]string{"chart/Chart.yaml": "name: widget\nversion: 1.8.0\nappVersion: 1.7.0\n---\nx: 1\n"}},      // two documents
		{"v2", map[string]string{"chart/Chart.yaml": chartYAML("widget", "2", "2")}},
	}
	state := buildMirror(t, rels, true)
	table, report, err := Derive(openReader(t, state), fixtureMapping(), fixedOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Records) != 1 || table.Records[0].ChartVersion != "1.7.0" {
		t.Fatalf("records: %+v", table.Records)
	}
	if got := len(report.Entries[0].Withheld); got != 9 {
		t.Fatalf("withheld %d: %+v", got, report.Entries[0].Withheld)
	}
	for _, w := range report.Entries[0].Withheld {
		if w.Reason == "" {
			t.Fatalf("withheld without a reason: %+v", w)
		}
	}
}

func TestDeriveMissingBlobIsAnError(t *testing.T) {
	state := buildMirror(t, standardReleases(), false)
	if _, _, err := Derive(openReader(t, state), fixtureMapping(), fixedOptions()); err == nil {
		t.Fatal("a mirror without the blobs must fail, not withhold")
	}
}

func TestMappingStrict(t *testing.T) {
	good := `{"schema":"` + MappingSchema + `","entries":[{"component":"pkg:github/acme/widget","chart":"widget","repo":"github.com/acme/widget","chartPath":"chart","tagPattern":"v{version}"}]}`
	if _, err := ParseMapping([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(string) string{
		"unknown field": func(s string) string { return strings.Replace(s, `"chart":`, `"x":1,"chart":`, 1) },
		"schema":        func(s string) string { return strings.Replace(s, MappingSchema, "x", 1) },
		"no token":      func(s string) string { return strings.Replace(s, "v{version}", "v", 1) },
		"two tokens":    func(s string) string { return strings.Replace(s, "v{version}", "{version}{version}", 1) },
		"dotdot":        func(s string) string { return strings.Replace(s, `"chartPath":"chart"`, `"chartPath":"../chart"`, 1) },
		"upper repo":    func(s string) string { return strings.Replace(s, "github.com/acme", "github.com/Acme", 1) },
		"other host":    func(s string) string { return strings.Replace(s, "github.com/acme", "gitlab.com/acme", 1) },
		"bad component": func(s string) string { return strings.Replace(s, "pkg:github/acme/widget", "widget", 1) },
		"trailing":      func(s string) string { return s + "{}" },
		"regex chars":   func(s string) string { return strings.Replace(s, "v{version}", "v.*{version}", 1) },
	} {
		if _, err := ParseMapping([]byte(mut(good))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	dup := strings.Replace(good, `]}`, `,`+good[strings.Index(good, `{"component"`):len(good)-2]+`]}`, 1)
	if _, err := ParseMapping([]byte(dup)); err == nil {
		t.Error("duplicate entry accepted")
	}
}

func TestTagMatch(t *testing.T) {
	e := Entry{TagPattern: "widget-{version}"}
	for tag, want := range map[string]string{"widget-1.2.3": "1.2.3", "widget-v1.2.3": "v1.2.3", "widget-1.2.3-rc.1": "1.2.3-rc.1"} {
		if got, ok := e.match(tag); !ok || got != want {
			t.Errorf("%s: %q %v", tag, got, ok)
		}
	}
	for _, tag := range []string{"widget-", "widget", "v1.2.3", "widget-1.2.3/x", "widget- 1"} {
		if _, ok := e.match(tag); ok {
			t.Errorf("%s matched", tag)
		}
	}
}

func TestCLIRejectsBadUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"derive"}, {"derive", "--mirror", "x", "--mapping", "y", "--out", "z", "extra"}, {"derive", "--mirror", "x", "--mapping", "y", "--out", "z", "--valid-days", "0"}} {
		if code, _, _ := runCLI(t, args...); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
}

func TestCodeDigest(t *testing.T) {
	d, err := CodeDigest()
	if err != nil || !strings.HasPrefix(d, "sha256:") || len(d) != len("sha256:")+64 {
		t.Fatalf("%q %v", d, err)
	}
}
