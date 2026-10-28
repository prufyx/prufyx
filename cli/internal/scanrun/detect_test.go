// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// fakeCharts is a reviewed chart table of one chart per project:
// "argo-cd" has chart "argo-cd" (component "c1"), where chart version 7.1.0
// installs 2.12.0. "split" has one chart that resolves to two components.
type fakeCharts struct{}

func (fakeCharts) Charts(slug string, _ time.Time) []string {
	switch slug {
	case "argo-cd":
		return []string{"argo-cd"}
	case "istio":
		return []string{"gateway", "istiod"}
	case "split":
		return []string{"split"}
	}
	return nil
}

func (fakeCharts) Component(slug, _ string, _ time.Time) (string, bool) {
	return "c1", slug == "argo-cd" || slug == "istio"
}

func (fakeCharts) AppVersion(component, chart, chartVersion string, _ time.Time) (string, bool) {
	if component == "c1" && chart == "argo-cd" && chartVersion == "7.1.0" {
		return "2.12.0", true
	}
	if component == "c1" && (chart == "gateway" || chart == "istiod") && chartVersion == "1.22.0" {
		return "1.22.0", true
	}
	return "", false
}

func workload(labels, templateLabels map[string]any) intake.Document {
	return object("apps/v1", "Deployment", labels, templateLabels)
}

func object(apiVersion, kind string, labels, templateLabels map[string]any) intake.Document {
	value := map[string]any{"metadata": map[string]any{"labels": labels}}
	if templateLabels != nil {
		value["spec"] = map[string]any{"template": map[string]any{"metadata": map[string]any{"labels": templateLabels}}}
	}
	return intake.Document{APIVersion: apiVersion, Kind: kind, Name: "x", Value: value}
}

func appLabels(name, version string) map[string]any {
	return map[string]any{labelAppName: name, labelAppVersion: version}
}

func TestDetectVersions(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		docs     []intake.Document
		slug     string
		version  string
		signals  []string
		conflict bool
		present  bool
	}{
		{name: "app label", docs: []intake.Document{workload(appLabels("argo-cd", "2.12.0"), nil)}, slug: "argo-cd", version: "2.12.0", signals: []string{signalAppLabel}, present: true},
		{name: "leading v", docs: []intake.Document{workload(appLabels("argo-cd", "v2.12.0"), nil)}, slug: "argo-cd", version: "2.12.0", signals: []string{signalAppLabel}, present: true},
		{name: "template labels", docs: []intake.Document{workload(nil, appLabels("argo-cd", "2.12.0"))}, slug: "argo-cd", version: "2.12.0", signals: []string{signalAppLabel}, present: true},
		{name: "helm chart label", docs: []intake.Document{workload(map[string]any{labelHelmChart: "argo-cd-7.1.0"}, nil)}, slug: "argo-cd", version: "2.12.0", signals: []string{signalHelmChart}, present: true},
		{name: "both signals agree", docs: []intake.Document{workload(map[string]any{labelHelmChart: "argo-cd-7.1.0", labelAppName: "argo-cd", labelAppVersion: "2.12.0"}, nil)}, slug: "argo-cd", version: "2.12.0", signals: []string{signalAppLabel, signalHelmChart}, present: true},
		{name: "same version in many documents", docs: []intake.Document{workload(appLabels("argo-cd", "2.12.0"), appLabels("argo-cd", "2.12.0")), workload(appLabels("argo-cd", "2.12.0"), nil)}, slug: "argo-cd", version: "2.12.0", signals: []string{signalAppLabel}, present: true},

		{name: "conflict between documents", docs: []intake.Document{workload(appLabels("argo-cd", "2.12.0"), nil), workload(appLabels("argo-cd", "2.13.1"), nil)}, slug: "argo-cd", conflict: true, present: true},
		{name: "conflict between signals", docs: []intake.Document{workload(map[string]any{labelHelmChart: "argo-cd-7.1.0", labelAppName: "argo-cd", labelAppVersion: "2.11.0"}, nil)}, slug: "argo-cd", conflict: true, present: true},
		{name: "usable beside latest", docs: []intake.Document{workload(appLabels("argo-cd", "2.12.0"), nil), workload(appLabels("argo-cd", "latest"), nil)}, slug: "argo-cd", conflict: true, present: true},
		{name: "usable beside unmapped chart version", docs: []intake.Document{workload(appLabels("argo-cd", "2.12.0"), nil), workload(map[string]any{labelHelmChart: "argo-cd-9.9.9"}, nil)}, slug: "argo-cd", conflict: true, present: true},

		{name: "latest", docs: []intake.Document{workload(appLabels("argo-cd", "latest"), nil)}, slug: "argo-cd", present: true},
		{name: "prerelease", docs: []intake.Document{workload(appLabels("argo-cd", "2.12.0-rc1"), nil)}, slug: "argo-cd", present: true},
		{name: "two part version", docs: []intake.Document{workload(appLabels("argo-cd", "2.12"), nil)}, slug: "argo-cd", present: true},
		{name: "digest", docs: []intake.Document{workload(appLabels("argo-cd", "sha256:0123456789abcdef"), nil)}, slug: "argo-cd", present: true},
		{name: "chart version unmapped", docs: []intake.Document{workload(map[string]any{labelHelmChart: "argo-cd-9.9.9"}, nil)}, slug: "argo-cd", present: true},
		{name: "chart with prerelease version", docs: []intake.Document{workload(map[string]any{labelHelmChart: "argo-cd-7.1.0-rc.1"}, nil)}, slug: "argo-cd"},
		{name: "chart resolves to two components", docs: []intake.Document{workload(map[string]any{labelHelmChart: "split-1.0.0"}, nil)}, slug: "split", present: true},

		{name: "statefulset", docs: []intake.Document{object("apps/v1", "StatefulSet", appLabels("argo-cd", "2.12.0"), nil)}, slug: "argo-cd", version: "2.12.0", signals: []string{signalAppLabel}, present: true},
		{name: "daemonset template", docs: []intake.Document{object("apps/v1", "DaemonSet", nil, appLabels("argo-cd", "2.12.0"))}, slug: "argo-cd", version: "2.12.0", signals: []string{signalAppLabel}, present: true},
		{name: "configmap ignored", docs: []intake.Document{object("v1", "ConfigMap", appLabels("argo-cd", "2.12.0"), nil)}, slug: "argo-cd"},
		{name: "crd ignored", docs: []intake.Document{object("apiextensions.k8s.io/v1", "CustomResourceDefinition", appLabels("argo-cd", "2.12.0"), nil)}, slug: "argo-cd"},
		{name: "job ignored", docs: []intake.Document{object("batch/v1", "Job", appLabels("argo-cd", "2.12.0"), appLabels("argo-cd", "2.12.0"))}, slug: "argo-cd"},
		{name: "deployment of another group ignored", docs: []intake.Document{object("example.com/v1", "Deployment", appLabels("argo-cd", "2.12.0"), nil)}, slug: "argo-cd"},
		{name: "non control plane chart gives no istio version", docs: []intake.Document{workload(map[string]any{labelHelmChart: "gateway-1.22.0"}, nil)}, slug: "istio"},
		{name: "control plane chart named like the project only", docs: []intake.Document{workload(map[string]any{labelHelmChart: "istiod-1.22.0"}, nil)}, slug: "istio"},
		{name: "name is not the project", docs: []intake.Document{workload(appLabels("argocd-server", "2.12.0"), nil)}, slug: "argo-cd"},
		{name: "name prefix only", docs: []intake.Document{workload(appLabels("argo-cd-extra", "2.12.0"), nil)}, slug: "argo-cd"},
		{name: "other project chart", docs: []intake.Document{workload(map[string]any{labelHelmChart: "other-7.1.0"}, nil)}, slug: "argo-cd"},
		{name: "name without version", docs: []intake.Document{workload(map[string]any{labelAppName: "argo-cd"}, nil)}, slug: "argo-cd"},
		{name: "non-string label", docs: []intake.Document{workload(map[string]any{labelAppName: "argo-cd", labelAppVersion: 2.12}, nil)}, slug: "argo-cd"},
		{name: "no labels", docs: []intake.Document{{Kind: "ConfigMap", Value: map[string]any{"data": map[string]any{}}}}, slug: "argo-cd"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, present := detectVersions(test.docs, []string{test.slug}, fakeCharts{}, now)[test.slug]
			if present != test.present {
				t.Fatalf("present = %v, want %v (%+v)", present, test.present, got)
			}
			if got.Version != test.version || got.Conflict != test.conflict {
				t.Fatalf("version %q conflict %v, want %q %v", got.Version, got.Conflict, test.version, test.conflict)
			}
			if test.version != "" && !reflect.DeepEqual(got.Signals, test.signals) {
				t.Fatalf("signals %v, want %v", got.Signals, test.signals)
			}
			if test.conflict && got.Version != "" {
				t.Fatal("a conflict must not carry a version")
			}
		})
	}
}

func TestDetectCurrent(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	lookup := func() (chartLookup, error) { return fakeCharts{}, nil }
	docs := []intake.Document{
		workload(appLabels("argo-cd", "2.12.0"), nil),
		workload(appLabels("kubernetes", "1.30.0"), nil),
		workload(appLabels("split", "1.0.0"), nil),
	}
	flag := scanconfig.Value[string]{Value: "2.0.0", Set: true, Source: scanconfig.FromFlag}
	target := scanconfig.Value[string]{Value: "9.9.9", Set: true, Source: scanconfig.FromFlag}
	t.Run("detected and noted", func(t *testing.T) {
		effective := scanconfig.Effective{Target: map[string]scanconfig.Value[string]{"argo-cd": target}}
		report := &scanreport.Report{}
		if err := detectCurrent(&effective, nil, docs, now, report, lookup); err != nil {
			t.Fatal(err)
		}
		got := effective.Current["argo-cd"]
		if got.Value != "2.12.0" || got.Source != scanconfig.FromDetection || !got.Set {
			t.Fatalf("current = %+v", got)
		}
		if len(report.Notes) != 1 || !strings.Contains(report.Notes[0], signalAppLabel) || !strings.Contains(report.Notes[0], "2.12.0") {
			t.Fatalf("notes = %v", report.Notes)
		}
		if len(report.Gaps) != 0 {
			t.Fatalf("gaps = %v", report.Gaps)
		}
	})
	t.Run("flag wins over detection", func(t *testing.T) {
		effective := scanconfig.Effective{
			Current: map[string]scanconfig.Value[string]{"argo-cd": flag},
			Target:  map[string]scanconfig.Value[string]{"argo-cd": target},
		}
		report := &scanreport.Report{}
		if err := detectCurrent(&effective, nil, docs, now, report, lookup); err != nil {
			t.Fatal(err)
		}
		if effective.Current["argo-cd"] != flag || len(report.Notes) != 0 {
			t.Fatalf("current = %+v notes = %v", effective.Current["argo-cd"], report.Notes)
		}
	})
	t.Run("kubernetes is never detected", func(t *testing.T) {
		effective := scanconfig.Effective{Target: map[string]scanconfig.Value[string]{"kubernetes": target}}
		report := &scanreport.Report{}
		if err := detectCurrent(&effective, nil, docs, now, report, lookup); err != nil {
			t.Fatal(err)
		}
		if _, ok := effective.Current["kubernetes"]; ok || len(report.Notes) != 0 {
			t.Fatalf("current = %v notes = %v", effective.Current, report.Notes)
		}
	})
	t.Run("declared chart hop is left alone", func(t *testing.T) {
		effective := scanconfig.Effective{Target: map[string]scanconfig.Value[string]{"argo-cd": target}}
		report := &scanreport.Report{}
		if err := detectCurrent(&effective, map[string]*chartDeclaration{"argo-cd": {}}, docs, now, report, lookup); err != nil {
			t.Fatal(err)
		}
		if _, ok := effective.Current["argo-cd"]; ok {
			t.Fatal("a chart hop took a detected application version")
		}
	})
	t.Run("conflict is a gap and no version", func(t *testing.T) {
		effective := scanconfig.Effective{Target: map[string]scanconfig.Value[string]{"argo-cd": target}}
		report := &scanreport.Report{}
		conflicting := append([]intake.Document{workload(appLabels("argo-cd", "2.13.0"), nil)}, docs...)
		if err := detectCurrent(&effective, nil, conflicting, now, report, lookup); err != nil {
			t.Fatal(err)
		}
		if _, ok := effective.Current["argo-cd"]; ok {
			t.Fatal("a conflict produced a version")
		}
		if len(report.Gaps) != 1 || report.Gaps[0].Reason != scanreport.ReasonVersionConflict || len(report.Notes) != 1 {
			t.Fatalf("gaps = %v notes = %v", report.Gaps, report.Notes)
		}
	})
	t.Run("nothing detected keeps the version undeclared", func(t *testing.T) {
		effective := scanconfig.Effective{Target: map[string]scanconfig.Value[string]{"argo-cd": target}}
		report := &scanreport.Report{}
		latest := []intake.Document{workload(appLabels("argo-cd", "latest"), nil)}
		if err := detectCurrent(&effective, nil, latest, now, report, lookup); err != nil {
			t.Fatal(err)
		}
		if len(effective.Current) != 0 || len(report.Notes) != 0 || len(report.Gaps) != 0 {
			t.Fatalf("current = %v notes = %v gaps = %v", effective.Current, report.Notes, report.Gaps)
		}
	})
}

func TestDetectSeenCountsLabelSets(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	// One label set carrying two signals counts once; a second set counts again.
	docs := []intake.Document{
		workload(map[string]any{labelHelmChart: "argo-cd-7.1.0", labelAppName: "argo-cd", labelAppVersion: "2.12.0"}, appLabels("argo-cd", "2.12.0")),
	}
	got := detectVersions(docs, []string{"argo-cd"}, fakeCharts{}, now)["argo-cd"]
	if got.Version != "2.12.0" || got.Seen != 2 {
		t.Fatalf("version %q seen %d, want 2.12.0 and 2", got.Version, got.Seen)
	}
}

func TestDropShadowedNotDetected(t *testing.T) {
	report := &scanreport.Report{Gaps: []scanreport.Gap{
		scanreport.NewGap("a", nil, scanreport.GapVersionConflict, "a"),
		scanreport.NewGap("a", nil, scanreport.GapVersionNotDetected, "a"),
		scanreport.NewGap("b", nil, scanreport.GapVersionNotDetected, "b"),
	}}
	dropShadowedNotDetected(report)
	if len(report.Gaps) != 2 || report.Gaps[0].Reason != scanreport.ReasonVersionConflict || report.Gaps[1].Component != "b" {
		t.Fatalf("gaps = %+v", report.Gaps)
	}
}
