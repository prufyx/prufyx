// SPDX-License-Identifier: AGPL-3.0-only

// Package gitops reads the GitOps objects of a repository that intake has
// already decoded and groups what they deploy by environment.
//
// The package never renders, templates, fetches or executes anything: it does
// not run Helm or kustomize, it does not contact a cluster or any server, and
// it reads no file by itself, because every byte comes through intake. It never
// decodes SOPS-encrypted content: an encrypted document is skipped and
// reported as a gap, and nothing it holds reaches the result. Secret payloads
// are already removed by intake.
//
// It understands Flux HelmRelease, HelmRepository, OCIRepository, GitRepository
// and Kustomization objects, Argo CD Application objects (an ApplicationSet is
// only reported), Chart.yaml dependencies, kustomization files and the images
// named by plain workloads. An environment is one root Flux Kustomization or
// one root Argo CD Application, followed through local paths only: a path that
// is absolute, climbs out of the repository, or names another repository is a
// gap, never a guess. A reference that cannot be resolved is reported as a Gap
// and the environment is still returned, so a result never looks more complete
// than it is. Every walk is bounded; reaching a bound is a gap too.
package gitops

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// Bounds. Reaching one is reported as a CLOSURE_LIMIT gap.
const (
	MaxEnvironments = 256  // environments in a result
	MaxReleases     = 4096 // releases per environment
	MaxImages       = 4096 // image pins per environment
	MaxGaps         = 4096 // gaps per list
	MaxDepth        = 32   // references followed one after another
	MaxSources      = 64   // sources of one Argo CD Application
	MaxFieldBytes   = 256  // bytes of any identity field or gap detail
	MaxPatchBytes   = 4096 // bytes of one inline patch that is evaluated
)

// workBudget bounds the number of steps one Analyze call takes over all
// environments, so a hostile repository cannot make the walks quadratic.
var workBudget = 2000000

// Gap reasons. The vocabulary is closed.
const (
	GeneratedApplicationsNotEvaluated = "GENERATED_APPLICATIONS_NOT_EVALUATED"
	RemoteReferenceNotResolved        = "REMOTE_REFERENCE_NOT_RESOLVED"
	ValuesFromNotResolved             = "VALUES_FROM_NOT_RESOLVED"
	ValueFilesNotResolved             = "VALUE_FILES_NOT_RESOLVED"
	Encrypted                         = "ENCRYPTED"
	PatchNotEvaluated                 = "PATCH_NOT_EVALUATED"
	ChartVersionNotPinned             = "CHART_VERSION_NOT_PINNED"
	SourceNotFound                    = "SOURCE_NOT_FOUND"
	ClosureLimit                      = "CLOSURE_LIMIT"
)

// Release kinds.
const (
	KindHelmRelease     = "HelmRelease"
	KindApplication     = "Application"
	KindChartDependency = "ChartDependency"
)

// Options configures Analyze.
type Options struct {
	// Root is the display path of the repository root, as given to
	// intake.Open. Paths in Flux and Argo CD objects are relative to it. When
	// empty, the deepest directory that holds every input file is used.
	Root string
	// SelfRepoURLs lists the URLs under which this repository is known. An
	// Argo CD source whose repoURL is in the list is followed as a local
	// path; the list is empty by default, so every Argo CD path source is a
	// gap. Only the host is lower-cased, and a trailing ".git" and "/" are
	// ignored when comparing.
	SelfRepoURLs []string
}

// Repo is the result of Analyze.
type Repo struct {
	Environments []Environment
	Gaps         []Gap
}

// Environment is the closure of one root object.
type Environment struct {
	Name     string
	Root     intake.Source
	Releases []Release
	Images   []ImagePin
	Gaps     []Gap
}

// Release is one Helm chart deployment or dependency named by the repository.
type Release struct {
	Kind         string // HelmRelease, Application or ChartDependency
	Chart        string
	ChartVersion string // verbatim; a range is never resolved
	RepoURL      string
	SourceRef    string // "Kind/namespace/name" of the Flux source, when there is one
	Namespace    string
	ReleaseName  string
	Values       map[string]any // inline values only
	Source       intake.Source
}

// ImagePin is a container image named by a workload or by an images list.
type ImagePin struct {
	Image  string // without tag and digest
	Tag    string
	Digest string
	Source intake.Source
}

// Gap says what could not be resolved and where.
type Gap struct {
	Reason string
	Source intake.Source
	Detail string // at most MaxFieldBytes bytes; never file content
}

// Analyze groups the GitOps objects of ws by environment. It never fails and
// never panics: every refusal is a Gap.
func Analyze(ws intake.Workspace, opts Options) Repo {
	a := newAnalysis(ws, opts)
	return a.run()
}

func clip(s string) string {
	if len(s) <= MaxFieldBytes {
		return s
	}
	cut := MaxFieldBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func sortGaps(gaps []Gap) []Gap {
	sort.SliceStable(gaps, func(i, j int) bool {
		a, b := gaps[i], gaps[j]
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.Source != b.Source {
			return srcLess(a.Source, b.Source)
		}
		return a.Detail < b.Detail
	})
	out := gaps[:0]
	for i, g := range gaps {
		if i > 0 && g == gaps[i-1] {
			continue
		}
		out = append(out, g)
	}
	return out
}

func srcLess(a, b intake.Source) bool {
	if a.Display != b.Display {
		return a.Display < b.Display
	}
	if a.Document != b.Document {
		return a.Document < b.Document
	}
	if a.Item != b.Item {
		return a.Item < b.Item
	}
	return a.Digest < b.Digest
}

func groupOf(apiVersion string) string {
	if i := strings.IndexByte(apiVersion, '/'); i >= 0 {
		return apiVersion[:i]
	}
	return ""
}

func intakeNone() intake.Source { return intake.Source{Item: -1} }
