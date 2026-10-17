// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// helmDir writes a manifest and the named files (mode 0600) into a fresh
// directory.
func helmDir(t *testing.T, contents map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	contents["manifest.yaml"] = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: default}\n"
	for name, content := range contents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func embeddedKnowledge(t *testing.T) Knowledge {
	t.Helper()
	embedded, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	return embedded
}

func TestParseChartFlags(t *testing.T) {
	t.Parallel()
	request, err := ParseArgs([]string{"--chart", "keda=keda@https://kedacore.github.io/charts", "--helm-values", "a.yaml", "--helm-values=b.yaml", "--helm-set", "x=1", "--helm-values-complete", "--to", "keda=2.16.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(request.Charts, map[string]string{"keda": "keda@https://kedacore.github.io/charts"}) || !reflect.DeepEqual(request.HelmValues, []string{"a.yaml", "b.yaml"}) ||
		!reflect.DeepEqual(request.HelmSet, []string{"x=1"}) || request.HelmValuesComplete == nil || !*request.HelmValuesComplete {
		t.Fatalf("request %+v", request)
	}
	for _, bad := range [][]string{
		{"--chart", "keda"}, {"--chart", "=keda"}, {"--chart", "keda="}, {"--chart", "keda=@x"}, {"--chart", "keda=a b"},
		{"--chart", "kubernetes=kubernetes"}, {"--chart", "keda=keda", "--chart", "keda=other"},
		{"--helm-values", "-"}, {"--helm-values", ""}, {"--helm-set", ""},
		{"--helm-values-complete", "--helm-values-complete"}, {"--helm-values-complete=maybe"},
		{"--set-string", "a=b"}, {"--set-file", "a=b"}, {"--set-json", "a={}"}, {"--values", "a.yaml"}, {"-f", "a.yaml"},
	} {
		if _, err := ParseArgs(bad); !isUsage(err) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}

// TestChartDeclarationRefusals: every chart declaration that cannot be
// resolved exactly, or values that cannot be read exactly, is a usage
// error; nothing is evaluated.
func TestChartDeclarationRefusals(t *testing.T) {
	t.Parallel()
	knowledge := embeddedKnowledge(t)
	dir := helmDir(t, map[string]string{
		"ok.yaml": "a: 1\n", "on.yaml": "on: 1\n", "alias.yaml": "a: &x {b: 1}\nc: *x\n", "dup.yaml": "a: 1\na: 2\n",
		"two.yaml": "a: 1\n---\nb: 2\n", "list.yaml": "- a\n",
	})
	base := []string{filepath.Join(dir, "manifest.yaml"), "--now", testNow, "--from", "keda=2.15.0", "--to", "keda=2.16.0"}
	for name, tc := range map[string]struct {
		args []string
		text string
	}{
		"unknown chart":          {[]string{"--chart", "keda=kedax"}, `no current reviewed chart source ties "keda" to chart "kedax"; charts with one: keda`},
		"project without charts": {[]string{"--chart", "argo=argo-cd", "--to", "argo=2.0.0"}, "unknown component"},
		"no chart in table":      {[]string{"--chart", "etcd=etcd", "--to", "etcd=3.6.0"}, `and "etcd" has none`},
		"expired row":            {[]string{"--chart", "keda=keda", "--now", "2027-02-01T00:00:00Z"}, "withdrawn or expired"},
		"wrong source":           {[]string{"--chart", "keda=keda@https://example.com/charts"}, "is not a reviewed source"},
		"no target":              {[]string{"--chart", "metallb=metallb"}, "has no target chart version"},
		"values without chart":   {[]string{"--helm-values", filepath.Join(dir, "ok.yaml")}, "need exactly one chart declaration"},
		"values for two charts":  {[]string{"--chart", "keda=keda", "--chart", "metallb=metallb", "--to", "metallb=0.15.0", "--helm-values", filepath.Join(dir, "ok.yaml")}, "need exactly one chart declaration"},
		"yaml 1.1 key":           {[]string{"--chart", "keda=keda", "--helm-values", filepath.Join(dir, "on.yaml")}, "INPUT NOT ACCEPTED: Helm values file"},
		"alias":                  {[]string{"--chart", "keda=keda", "--helm-values", filepath.Join(dir, "alias.yaml")}, "INPUT NOT ACCEPTED: Helm values file"},
		"duplicate key":          {[]string{"--chart", "keda=keda", "--helm-values", filepath.Join(dir, "dup.yaml")}, "INPUT NOT ACCEPTED: Helm values file"},
		"two documents":          {[]string{"--chart", "keda=keda", "--helm-values", filepath.Join(dir, "two.yaml")}, "INPUT NOT ACCEPTED: Helm values file"},
		"list root":              {[]string{"--chart", "keda=keda", "--helm-values", filepath.Join(dir, "list.yaml")}, "INPUT NOT ACCEPTED: Helm values file"},
		"missing file":           {[]string{"--chart", "keda=keda", "--helm-values", filepath.Join(dir, "missing.yaml")}, "INPUT NOT ACCEPTED"},
		"set list index":         {[]string{"--chart", "keda=keda", "--helm-set", "a[0]=x"}, "--helm-set assignment 1 is not accepted"},
		"set two assignments":    {[]string{"--chart", "keda=keda", "--helm-set", "a=1,b=2"}, "--helm-set assignment 1 is not accepted"},
		"set list value":         {[]string{"--chart", "keda=keda", "--helm-set", "a={x,y}"}, "--helm-set assignment 1 is not accepted"},
		"set no value":           {[]string{"--chart", "keda=keda", "--helm-set", "a"}, "--helm-set assignment 1 is not accepted"},
		"set value never echoed": {[]string{"--chart", "keda=keda", "--helm-set", "ok=1", "--helm-set", "a[0]=hunter2"}, "--helm-set assignment 2 is not accepted"},
		"set through a value":    {[]string{"--chart", "keda=keda", "--helm-values", filepath.Join(dir, "ok.yaml"), "--helm-set", "a.b=2"}, "--helm-set assignment 1: its key passes through a value that is not a mapping"},
	} {
		args := append(append([]string{}, base...), tc.args...)
		if tc.args[len(tc.args)-1] == "2027-02-01T00:00:00Z" {
			args = append([]string{filepath.Join(dir, "manifest.yaml"), "--from", "keda=2.15.0", "--to", "keda=2.16.0"}, tc.args...)
		}
		_, err := scan(t, knowledge, args...)
		if !isUsage(err) || !strings.Contains(err.Error(), tc.text) || strings.Contains(err.Error(), "hunter") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := os.Chmod(filepath.Join(dir, "ok.yaml"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := scan(t, knowledge, append(base, "--chart", "keda=keda", "--helm-values", filepath.Join(dir, "ok.yaml"))...); !isUsage(err) || !strings.Contains(err.Error(), "writable by other users") {
		t.Errorf("writable values file: %v", err)
	}
}

// TestChartHopWithoutChartRules: the embedded knowledge holds no chart rule
// yet, so a declared chart hop evaluates nothing and says so; the versions
// are shown as chart versions, the custom-resource route never runs on
// them, and the values are identified only by digest.
func TestChartHopWithoutChartRules(t *testing.T) {
	t.Parallel()
	knowledge := embeddedKnowledge(t)
	dir := helmDir(t, map[string]string{"values.yaml": "image: {tag: x}\nsecret: hunter2\n"})
	args := []string{filepath.Join(dir, "manifest.yaml"), "--now", testNow, "--chart", "keda=keda", "--from", "keda=2.15.0", "--to", "keda=2.16.0",
		"--helm-values", filepath.Join(dir, "values.yaml"), "--helm-set", "token=hunter3", "--helm-values-complete"}
	result := mustScan(t, knowledge, args...)
	report := result.Report
	if report.Verdict != scanreport.VerdictUnknown || len(report.Passes) != 0 || len(report.Findings) != 0 {
		t.Fatalf("verdict %s %+v %+v", report.Verdict, report.Passes, report.Findings)
	}
	if len(report.Gaps) != 1 || !strings.Contains(report.Gaps[0].Detail, "keda chart keda: only its values and Kubernetes-version rules are checked") {
		t.Fatalf("gaps %+v", report.Gaps)
	}
	path := report.Paths[0]
	if path.Chart == nil || path.Chart.Source != "https://kedacore.github.io/charts" || path.Hops[0].Status != scanreport.HopNoData {
		t.Fatalf("path %+v", path)
	}
	values := report.Provenance.HelmValues
	if len(values) != 1 || values[0].Chart != "keda" || len(values[0].Files) != 1 || values[0].Sets != 1 || !values[0].Declared || !strings.HasPrefix(values[0].Digest, "sha256:") {
		t.Fatalf("provenance %+v", values)
	}
	raw := jsonOf(t, report)
	if strings.Contains(string(raw), "hunter") {
		t.Fatal("a value reached the report")
	}
	if _, err := scanreport.DecodeJSON(raw); err != nil {
		t.Fatal(err)
	}
	again := mustScan(t, knowledge, args...)
	if string(jsonOf(t, again.Report)) != string(raw) {
		t.Fatal("not deterministic")
	}
	redacted := mustScan(t, knowledge, append(args, "--redact")...).Report
	if strings.Contains(string(jsonOf(t, redacted)), dir) {
		t.Fatal("a values path survived --redact")
	}
	conformReport(t, "chart", report)
	conformReport(t, "chart-redacted", redacted)

	// Without --chart the same versions are an application hop.
	app := mustScan(t, knowledge, filepath.Join(dir, "manifest.yaml"), "--now", testNow, "--from", "keda=2.15.0", "--to", "keda=2.16.0").Report
	if app.Paths[0].Chart != nil || app.Inventory[0].Chart != "" || app.Provenance.HelmValues != nil || strings.Contains(string(jsonOf(t, app)), `"chart"`) {
		t.Fatalf("application hop carries chart fields: %s", jsonOf(t, app))
	}
}

// TestChartUniverseIgnoresPolicy: the universe is computed from every rule
// that reads the fact; a rule that reads it other than as its set condition
// leaves it unresolved.
func TestChartUniverseOf(t *testing.T) {
	t.Parallel()
	const fact = "component.keda.chart_keda_values_paths_set"
	rules := []cncfcheck.ScanRule{
		{Facts: []string{fact}, SetFact: fact, SetMembers: []string{"b", "a"}, Basis: "mechanical"},
		{Facts: []string{fact}, SetFact: fact, SetMembers: []string{"a", "c"}, Basis: "lead"},
		{Facts: []string{"other"}, SetFact: "other", SetMembers: []string{"x"}},
	}
	got := universeOf(rules, fact)
	if !got.Resolved || !reflect.DeepEqual(got.Members, []string{"a", "b", "c"}) {
		t.Fatalf("universe %+v", got)
	}
	rules = append(rules, cncfcheck.ScanRule{Facts: []string{fact}, SetFact: ""})
	if got := universeOf(rules, fact); got.Resolved {
		t.Fatal("a rule reading the fact outside a set condition left the universe resolved")
	}
	if got := universeOf(rules[:2], "component.none"); !got.Resolved || len(got.Members) != 0 {
		t.Fatalf("empty universe %+v", got)
	}
	_ = cncfprepare.HelmUniverse{}
}
