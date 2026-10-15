// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
)

// TargetsSchema identifies targets.json.
const TargetsSchema = "prufyx.io/helm-values-targets/v1"

// targetsJSON is the reviewed chart table. It is data, not code, but it is
// embedded next to the code and covered by the extractor's code digest, so
// any change to it is a new extractor version and is reviewed as one.
//
//go:embed targets.json
var targetsJSON []byte

// Target is one reviewed chart: the catalog project it installs, the
// repository and directory that hold the chart's source, the chart
// repository it is published to, and the tags that name its releases.
type Target struct {
	// Project is the catalog project slug, also the rule id prefix.
	Project string
	// Name is the public name used in descriptions.
	Name string
	// Repo is the repository key, github.com/<owner>/<name>.
	Repo string
	// Component is the rule subject component (the catalog identity).
	Component string
	// FactProject is the project part of the set fact id.
	FactProject string
	// Chart is the published chart identity: the normalised chart
	// repository URL and the chart name. It is the rule subject's chart.
	Chart constraintengine.ChartRef
	// ChartPath is the chart directory in Repo.
	ChartPath string
	// TagPrefix precedes the chart version in a release tag ("v",
	// "helm-chart-", ""). The version in the tag must be the version
	// Chart.yaml declares at the tag's commit.
	TagPrefix string
	// MinFrom is the first earlier line (major, minor) a pair may start
	// from.
	MinFrom [2]int
}

// Targets is the reviewed chart table, ordered by project.
var Targets = mustLoadTargets(targetsJSON)

// ExtractorID is the extractor id of the target: one per chart, since a
// run reads one repository.
func (t Target) ExtractorID() string { return IDPrefix + t.Project + "." + t.Chart.Name }

// FactID is the values-path set fact of the target's chart.
func (t Target) FactID() string {
	return "component." + t.FactProject + ".chart_" + t.Chart.Name + "_values_paths_set"
}

type targetsFile struct {
	Schema  string       `json:"schema"`
	Targets []targetJSON `json:"targets"`
}

type targetJSON struct {
	Project     string    `json:"project"`
	Name        string    `json:"name"`
	Repo        string    `json:"repo"`
	Component   string    `json:"component"`
	FactProject string    `json:"factProject"`
	Chart       chartJSON `json:"chart"`
	TagPrefix   string    `json:"tagPrefix"`
	MinFrom     string    `json:"minFrom"`
}

type chartJSON struct {
	Source string `json:"source"`
	Name   string `json:"name"`
	Path   string `json:"path"`
}

var (
	projectRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	factProjectRE = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)*$`)
	chartNameRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	tagPrefixRE   = regexp.MustCompile(`^([a-z][a-z0-9-]{0,62})?$`)
	lineRE        = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)
	componentRE   = regexp.MustCompile(`^pkg:github/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
)

func mustLoadTargets(raw []byte) []Target {
	ts, err := LoadTargets(raw)
	if err != nil {
		panic("helmvalues: targets.json: " + err.Error())
	}
	return ts
}

// LoadTargets decodes and validates a targets document. Unknown fields,
// unsorted or duplicate projects, chart identities not in normal form and
// chart paths that are not clean repository paths are refused.
func LoadTargets(raw []byte) ([]Target, error) {
	var doc targetsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data")
	}
	if doc.Schema != TargetsSchema {
		return nil, fmt.Errorf("schema %q, want %q", doc.Schema, TargetsSchema)
	}
	if len(doc.Targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	var out []Target
	seen := map[string]string{}
	for i, tj := range doc.Targets {
		t, err := tj.target()
		if err != nil {
			return nil, fmt.Errorf("target %d (%s): %w", i, tj.Project, err)
		}
		if i > 0 && doc.Targets[i-1].Project >= t.Project {
			return nil, fmt.Errorf("targets are not sorted by project at %s", t.Project)
		}
		for _, k := range []string{"project " + t.Project, "fact " + t.FactID(), "chart " + t.Chart.Source + " " + t.Chart.Name} {
			if prev, dup := seen[k]; dup {
				return nil, fmt.Errorf("%s is used by %s and %s", k, prev, t.Project)
			}
			seen[k] = t.Project
		}
		out = append(out, t)
	}
	return out, nil
}

func (tj targetJSON) target() (Target, error) {
	t := Target{Project: tj.Project, Name: tj.Name, Repo: tj.Repo, Component: tj.Component, FactProject: tj.FactProject,
		Chart: constraintengine.ChartRef{Source: tj.Chart.Source, Name: tj.Chart.Name}, ChartPath: tj.Chart.Path, TagPrefix: tj.TagPrefix}
	switch {
	case !projectRE.MatchString(t.Project):
		return Target{}, fmt.Errorf("project %q", t.Project)
	case strings.TrimSpace(t.Name) == "" || len(t.Name) > 64:
		return Target{}, fmt.Errorf("name %q", t.Name)
	case !componentRE.MatchString(t.Component):
		return Target{}, fmt.Errorf("component %q", t.Component)
	case !factProjectRE.MatchString(t.FactProject) || len(t.FactProject) > 64:
		return Target{}, fmt.Errorf("factProject %q", t.FactProject)
	case !chartNameRE.MatchString(t.Chart.Name) || !constraintengine.ValidChartRef(t.Chart):
		return Target{}, fmt.Errorf("chart %+v is not a normalised chart identity", t.Chart)
	case !cleanRepoPath(t.ChartPath):
		return Target{}, fmt.Errorf("chart path %q", t.ChartPath)
	case !tagPrefixRE.MatchString(t.TagPrefix):
		return Target{}, fmt.Errorf("tag prefix %q", t.TagPrefix)
	}
	if _, err := extract.ParseRepo(t.Repo); err != nil || t.Repo != strings.ToLower(t.Repo) {
		return Target{}, fmt.Errorf("repo %q", t.Repo)
	}
	if len(IDPrefix+t.Project+"."+t.Chart.Name) > 128 {
		return Target{}, fmt.Errorf("extractor id too long")
	}
	m := lineRE.FindStringSubmatch(tj.MinFrom)
	if m == nil {
		return Target{}, fmt.Errorf("minFrom %q", tj.MinFrom)
	}
	t.MinFrom[0], _ = strconv.Atoi(m[1])
	t.MinFrom[1], _ = strconv.Atoi(m[2])
	return t, nil
}

func cleanRepoPath(p string) bool {
	return p != "" && p != "." && !strings.HasPrefix(p, "/") && !strings.HasSuffix(p, "/") && path.Clean(p) == p && !strings.HasPrefix(p, "../") && p != ".."
}
