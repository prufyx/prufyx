// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/chartidentity"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanconfig"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Detection reads the current version of a target project from the labels
// of the manifests the scan already holds. It adds no input and no network
// access, never overrides a declared version, and reads a version only from
// evidence that names the project exactly:
//
//   - app.kubernetes.io/name equal to the project name, with a strict X.Y.Z
//     app.kubernetes.io/version (one leading "v" allowed);
//   - helm.sh/chart "<chart>-<chart version>" where the chart is named like
//     the project (a project's other charts, such as a gateway chart, say
//     nothing about its control plane) and the reviewed chart table maps
//     that chart version to an application version.
//
// Only the labels of workloads (apps/v1 Deployment, StatefulSet, DaemonSet
// and their pod templates) are read; a CRD, ConfigMap or Job label is not
// evidence of what runs.
//
// Two different versions, or a usable version beside an unusable signal
// (latest, a pre-release, an unmapped chart version), detect nothing and
// leave a gap: a version is never guessed.
const (
	labelAppName    = "app.kubernetes.io/name"
	labelAppVersion = "app.kubernetes.io/version"
	labelHelmChart  = "helm.sh/chart"

	signalAppLabel  = labelAppVersion + " label"
	signalHelmChart = labelHelmChart + " label"
)

// chartLookup is the reviewed chart knowledge detection reads.
type chartLookup interface {
	// Charts lists the usable chart names of the project.
	Charts(slug string, now time.Time) []string
	// Component is the single component the project's chart resolves to.
	Component(slug, chart string, now time.Time) (string, bool)
	// AppVersion is the application version the reviewed table gives for a
	// chart version.
	AppVersion(component, chart, chartVersion string, now time.Time) (string, bool)
}

type embeddedCharts struct {
	sources  *chartidentity.SourceTable
	versions *chartidentity.AppVersionTable
}

func loadEmbeddedCharts() (embeddedCharts, error) {
	sources, versions, err := chartidentity.LoadEmbedded()
	return embeddedCharts{sources: sources, versions: versions}, err
}

func (e embeddedCharts) Charts(slug string, now time.Time) []string {
	return e.sources.ProjectChart(slug, "", now).Charts
}

func (e embeddedCharts) Component(slug, chart string, now time.Time) (string, bool) {
	component := ""
	for _, row := range e.sources.ProjectChart(slug, chart, now).Usable {
		if component != "" && row.Component != component {
			return "", false
		}
		component = row.Component
	}
	return component, component != ""
}

func (e embeddedCharts) AppVersion(component, chart, chartVersion string, now time.Time) (string, bool) {
	version, ok, err := e.versions.AppVersionFor(component, chart, chartVersion, now)
	return version, ok && err == nil
}

// detection is what the manifests say about one project's current version.
type detection struct {
	// Version is the detected version; empty when none was detected.
	Version string
	// Signals names the signals that produced it, sorted.
	Signals []string
	// Seen counts the distinct label sets that carry usable evidence.
	Seen int
	// Conflict is true when evidence exists but is ambiguous: the usable
	// versions differ, or a usable version stands beside an unusable signal.
	Conflict bool
	// Versions lists the distinct usable versions seen (conflict only).
	Versions []string
	// Unusable counts the signals that name the project but give no usable
	// version.
	Unusable int
}

// workloadKinds are the kinds whose labels may carry a detection signal.
var workloadKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true}

// labelSets returns the labels of a workload's object and of its pod
// template. Only string values are read.
func labelSets(document intake.Document) []map[string]string {
	var sets []map[string]string
	if !workloadKinds[document.Kind] || !strings.HasPrefix(document.APIVersion, "apps/") {
		return nil
	}
	for _, path := range [][]string{{"metadata", "labels"}, {"spec", "template", "metadata", "labels"}} {
		var node any = document.Value
		for _, key := range path {
			object, ok := node.(map[string]any)
			if !ok {
				node = nil
				break
			}
			node = object[key]
		}
		raw, ok := node.(map[string]any)
		if !ok {
			continue
		}
		set := map[string]string{}
		for key, value := range raw {
			if text, ok := value.(string); ok {
				set[key] = text
			}
		}
		sets = append(sets, set)
	}
	return sets
}

// detectVersions detects the current version of each project from the
// documents. The result has an entry only for a project with evidence.
func detectVersions(documents []intake.Document, slugs []string, charts chartLookup, now time.Time) map[string]detection {
	out := map[string]detection{}
	for _, slug := range slugs {
		var names []string
		for _, name := range charts.Charts(slug, now) {
			if name == slug {
				names = append(names, name)
			}
		}
		sets := 0
		type seen struct{ version, signal string }
		var found []seen
		unusable := 0
		for _, document := range documents {
			for _, labels := range labelSets(document) {
				before := len(found)
				if labels[labelAppName] == slug {
					if text, present := labels[labelAppVersion]; present {
						if version, ok := chartidentity.NormalizeVersion(text); ok {
							found = append(found, seen{version, signalAppLabel})
						} else {
							unusable++
						}
					}
				}
				value := labels[labelHelmChart]
				for _, name := range names {
					rest, ok := strings.CutPrefix(value, name+"-")
					if !ok {
						continue
					}
					if _, valid := chartidentity.NormalizeVersion(rest); !valid {
						continue
					}
					component, resolved := charts.Component(slug, name, now)
					app, mapped := "", false
					if resolved {
						app, mapped = charts.AppVersion(component, name, rest, now)
					}
					if mapped {
						found = append(found, seen{app, signalHelmChart})
					} else {
						unusable++
					}
					break
				}
				if len(found) > before {
					sets++
				}
			}
		}
		if len(found) == 0 && unusable == 0 {
			continue
		}
		versions := map[string]bool{}
		signals := map[string]bool{}
		for _, item := range found {
			versions[item.version] = true
			signals[item.signal] = true
		}
		result := detection{Seen: sets, Unusable: unusable}
		switch {
		case len(found) == 0:
			// Only unusable signals: nothing is detected and nothing is
			// ambiguous; the version simply stays undeclared.
		case len(versions) > 1 || unusable > 0:
			result.Conflict = true
			for version := range versions {
				result.Versions = append(result.Versions, version)
			}
			sort.Strings(result.Versions)
		default:
			for version := range versions {
				result.Version = version
			}
			for signal := range signals {
				result.Signals = append(result.Signals, signal)
			}
			sort.Strings(result.Signals)
		}
		out[slug] = result
	}
	return out
}

// detectCurrent fills in the current version of target projects that
// declare none, from the manifests. A version given by a flag or the
// configuration file is never replaced, Kubernetes is never detected (its
// version is the cluster's, not a label's), and a declared chart hop keeps
// its chart versions. Each detection or ambiguity is stated in a note, and
// an ambiguity is also a gap.
func detectCurrent(effective *scanconfig.Effective, declaredCharts map[string]*chartDeclaration, documents []intake.Document, now time.Time, report *scanreport.Report, charts func() (chartLookup, error)) error {
	var slugs []string
	for slug := range effective.Target {
		if _, declared := effective.Current[slug]; declared || slug == kubernetesSlug || declaredCharts[slug] != nil {
			continue
		}
		slugs = append(slugs, slug)
	}
	if len(slugs) == 0 || len(documents) == 0 {
		return nil
	}
	sort.Strings(slugs)
	lookup, err := charts()
	if err != nil {
		return ErrIntegrity
	}
	detected := detectVersions(documents, slugs, lookup, now)
	for _, slug := range slugs {
		result, ok := detected[slug]
		switch {
		case !ok:
		case result.Conflict:
			report.Notes = append(report.Notes, scanreport.Text(scanreport.NoteVersionAmbiguous, slug, strings.Join(result.Versions, ", "), result.Unusable))
			report.Gaps = append(report.Gaps, scanreport.NewGap(slug, nil, scanreport.GapVersionConflict, slug))
		case result.Version != "":
			if effective.Current == nil {
				effective.Current = map[string]scanconfig.Value[string]{}
			}
			effective.Current[slug] = scanconfig.Value[string]{Value: result.Version, Set: true, Source: scanconfig.FromDetection}
			report.Notes = append(report.Notes, scanreport.Text(scanreport.NoteVersionDetected, slug, result.Version, strings.Join(result.Signals, ", "), result.Seen, slug))
		}
	}
	return nil
}

// dropShadowedNotDetected removes the "not detected" gap of a project whose
// manifests gave conflicting signals: the conflict gap already says why.
func dropShadowedNotDetected(report *scanreport.Report) {
	conflicted := map[string]bool{}
	for _, gap := range report.Gaps {
		if gap.Reason == scanreport.ReasonVersionConflict {
			conflicted[gap.Component] = true
		}
	}
	if len(conflicted) == 0 {
		return
	}
	kept := report.Gaps[:0]
	for _, gap := range report.Gaps {
		if gap.Reason == scanreport.ReasonVersionNotDetected && conflicted[gap.Component] {
			continue
		}
		kept = append(kept, gap)
	}
	report.Gaps = kept
}
