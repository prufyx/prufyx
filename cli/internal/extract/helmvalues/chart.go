// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/helmvaluespath"
)

// chartMeta is what the extractor reads from Chart.yaml.
type chartMeta struct {
	Name    string
	Version string // strict X.Y.Z after removing one leading "v"
	// KubeVersion is the kubeVersion constraint as written, "" when
	// absent; KubeVersionLine is its line.
	KubeVersion     string
	KubeVersionLine int
	// Dependencies are the names and aliases of the declared
	// dependencies: the top-level values keys Helm fills with subchart
	// values.
	Dependencies []string
}

var strictVersionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// normalVersion removes one leading "v" and accepts strict X.Y.Z only:
// pre-releases, build metadata and two-part versions are not guessed at.
func normalVersion(v string) (string, bool) {
	v = strings.TrimPrefix(v, "v")
	return v, strictVersionRE.MatchString(v)
}

// parseChartYAML reads Chart.yaml in the strict subset. name and version
// must be strings; kubeVersion, when present, a string; dependencies, when
// present, a list of mappings each with a string name and optional string
// alias.
func parseChartYAML(data []byte) (chartMeta, error) {
	root, v, err := helmvaluespath.DecodeYAML(data)
	if err != nil {
		return chartMeta{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return chartMeta{}, fmt.Errorf("Chart.yaml is not a mapping")
	}
	var c chartMeta
	name, ok := m["name"].(string)
	if !ok || name == "" {
		return chartMeta{}, fmt.Errorf("Chart.yaml has no string name")
	}
	c.Name = name
	raw, ok := m["version"].(string)
	if !ok {
		return chartMeta{}, fmt.Errorf("Chart.yaml has no string version")
	}
	if c.Version, ok = normalVersion(raw); !ok {
		return chartMeta{}, fmt.Errorf("Chart.yaml version %q is not X.Y.Z", raw)
	}
	if kv, present := m["kubeVersion"]; present && kv != nil {
		s, ok := kv.(string)
		if !ok {
			return chartMeta{}, fmt.Errorf("Chart.yaml kubeVersion is not a string")
		}
		c.KubeVersion, c.KubeVersionLine = s, helmvaluespath.MappingLine(root, "kubeVersion")
	}
	deps, err := dependencyKeys(m["dependencies"])
	if err != nil {
		return chartMeta{}, fmt.Errorf("Chart.yaml: %w", err)
	}
	c.Dependencies = deps
	return c, nil
}

// dependencyKeys returns the sorted names and aliases of a dependencies
// list (Chart.yaml, or requirements.yaml of an apiVersion v1 chart).
func dependencyKeys(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("dependencies is not a list")
	}
	var out []string
	for _, item := range list {
		d, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("a dependency is not a mapping")
		}
		name, ok := d["name"].(string)
		if !ok || name == "" {
			return nil, fmt.Errorf("a dependency has no string name")
		}
		out = append(out, name)
		if a, present := d["alias"]; present && a != nil {
			alias, ok := a.(string)
			if !ok || alias == "" {
				return nil, fmt.Errorf("a dependency alias is not a string")
			}
			out = append(out, alias)
		}
	}
	sort.Strings(out)
	return compactStrings(out), nil
}

func compactStrings(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// minimumRE is the one kubeVersion shape a rule is derived from: a single
// lower bound that admits pre-release versions (the "-0" suffix), so a
// cluster version with a vendor suffix (1.30.2-gke.1) is admitted exactly
// when its X.Y.Z is. Missing minor and patch parts are 0.
var minimumRE = regexp.MustCompile(`^\s*>=\s*v?(0|[1-9][0-9]{0,8})(?:\.(0|[1-9][0-9]{0,8})(?:\.(0|[1-9][0-9]{0,8}))?)?(-0)?\s*$`)

// KubeMinimum is the parse of a kubeVersion constraint.
type KubeMinimum struct {
	// Constraint is the constraint as written.
	Constraint string `json:"constraint"`
	// Minimum is the X.Y.Z lower bound, "" when the constraint is absent
	// or not a single lower bound.
	Minimum string `json:"minimum,omitempty"`
	// PreRelease reports the "-0" suffix.
	PreRelease bool `json:"preRelease"`
	// Shape is "absent", "minimum" or "other".
	Shape string `json:"shape"`
}

// parseKubeVersion classifies a kubeVersion constraint. Any upper bound,
// "||", "~", "^", wildcard, hyphen range or exact match is "other": Helm
// refuses versions such a constraint excludes that a lower bound alone
// would admit, so no rule is derived from it.
func parseKubeVersion(c string) KubeMinimum {
	k := KubeMinimum{Constraint: c, Shape: "absent"}
	if strings.TrimSpace(c) == "" {
		return k
	}
	m := minimumRE.FindStringSubmatch(c)
	if m == nil {
		k.Shape = "other"
		return k
	}
	parts := [3]string{m[1], m[2], m[3]}
	for i := range parts {
		if parts[i] == "" {
			parts[i] = "0"
		}
	}
	k.Shape, k.Minimum, k.PreRelease = "minimum", parts[0]+"."+parts[1]+"."+parts[2], m[4] != ""
	return k
}

// compareVersions compares two strict X.Y.Z versions.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		x, _ := strconv.ParseUint(pa[i], 10, 64)
		y, _ := strconv.ParseUint(pb[i], 10, 64)
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
	}
	return 0
}

// present reports whether the defaults hold path, null included: Helm keeps a
// chart's own null default through the merge, so the key exists for the schema.
func present(values any, path []string) bool {
	_, ok := helmvaluespath.ValueAt(values, path)
	return ok
}
