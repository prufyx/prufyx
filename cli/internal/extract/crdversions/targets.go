// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import "regexp"

// Target is one reviewed source entry: where a catalog project keeps the
// rendered CustomResourceDefinition manifests it ships, and which release
// tags form pairs. The paths are part of the extractor code: a project that
// moves its manifests makes the listed paths incomplete, which withholds the
// pair rather than turning a move into a removal.
type Target struct {
	// Project is the catalog project slug, also the rule id prefix.
	Project string
	// Name is the public project name used in descriptions.
	Name string
	// Repo is the repository key, github.com/<owner>/<name>.
	Repo string
	// Component is the rule subject component (the catalog identity).
	Component string
	// FactProject is the project part of the set fact id
	// component.<FactProject>.custom_resource_versions_set.
	FactProject string
	// TagPrefix is the prefix of final release tags ("v" or "").
	TagPrefix string
	// MinFrom is the first earlier release (major, minor) a pair may start
	// from: the first release at which the listed paths were checked.
	MinFrom [2]int
	// Paths are the CRD manifest locations, read at both tags of a pair.
	Paths []PathSpec
}

// PathSpec is a file, or a directory whose files with names matching Match
// are read (not recursively). Every listed path must exist at both tags.
type PathSpec struct {
	Path  string
	Dir   bool
	Match *regexp.Regexp
}

// yamlFiles matches the YAML file names of a directory.
var yamlFiles = regexp.MustCompile(`^[^.][^/]*\.ya?ml$`)

// Targets is the reviewed source table, ordered by project.
var Targets = []Target{
	{
		Project: "argo-cd", Name: "Argo CD", Repo: "github.com/argoproj/argo-cd", Component: "pkg:github/argoproj/argo-cd",
		FactProject: "argo_cd", TagPrefix: "v", MinFrom: [2]int{2, 14},
		Paths: []PathSpec{{Path: "manifests/crds", Dir: true, Match: yamlFiles}},
	},
	{
		Project: "istio", Name: "Istio", Repo: "github.com/istio/istio", Component: "pkg:github/istio/istio",
		FactProject: "istio", TagPrefix: "", MinFrom: [2]int{1, 24},
		Paths: []PathSpec{{Path: "manifests/charts/base/files/crd-all.gen.yaml"}},
	},
	{
		Project: "strimzi", Name: "Strimzi", Repo: "github.com/strimzi/strimzi-kafka-operator", Component: "pkg:github/strimzi/strimzi-kafka-operator",
		FactProject: "strimzi", TagPrefix: "", MinFrom: [2]int{0, 51},
		Paths: []PathSpec{{Path: "install/cluster-operator", Dir: true, Match: regexp.MustCompile(`^[0-9]{3}-Crd-[A-Za-z0-9-]+\.yaml$`)}},
	},
}

// TargetFor returns the target of a project slug.
func TargetFor(project string) (Target, bool) {
	for _, t := range Targets {
		if t.Project == project {
			return t, true
		}
	}
	return Target{}, false
}

// FactID is the set fact a target's rules read.
func (t Target) FactID() string {
	return "component." + t.FactProject + ".custom_resource_versions_set"
}

// ExtractorID is the extractor id of one target.
func (t Target) ExtractorID() string { return IDPrefix + t.Project }
