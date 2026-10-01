// SPDX-License-Identifier: AGPL-3.0-only

// Package onecommand is the one-command fast path: it collects a local, read-only current-state bundle from a
// kubeconfig the operator already trusts, and reports which of the 194
// registered native check routes (checkroutemetadata.descriptorSet) are
// applicable to what was actually found.
//
// It authors zero new compatibility claims and runs no check itself: it
// never invents a caller declaration, never treats a missing declaration as
// a default, and never reports a check as having passed because it could
// not run. Its whole contribution is the applicability classification
// described in cli/docs/one-command-flow.md; any check an operator then
// runs stays on the existing, already-reviewed cncf.go / project.go routes.
package onecommand

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/localcollector"
	"github.com/prufyx/prufyx/cli/internal/observation"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
)

const (
	Schema = "prufyx.io/one-command-flow-report/v1alpha1"

	// Applicability outcomes. Exactly one is assigned per check per context.
	ApplicableFullySatisfied       = "APPLICABLE_FULLY_SATISFIED"
	ApplicableNeedsDeclaration     = "APPLICABLE_NEEDS_DECLARATION"
	NotApplicableVersionMismatch   = "NOT_APPLICABLE_VERSION_MISMATCH"
	NotApplicableComponentAbsent   = "NOT_APPLICABLE_COMPONENT_ABSENT"
	IndeterminateNotObservable     = "INDETERMINATE_NOT_OBSERVABLE"
	IndeterminatePartialCollection = "INDETERMINATE_PARTIAL_COLLECTION"

	freshnessPolicyID = "prufyx.io.one-command-flow-same-run.v1"
	freshnessMaxAge   = time.Hour

	// Aggregate reason codes. The aggregate is the constraint engine's own
	// recomputed verdict whenever a scope declaration was supplied, and an
	// honest "not asked" otherwise. It is never SAFE.
	reasonScopeNotSupplied = "SCOPE_DECLARATION_NOT_SUPPLIED"
	reasonScopeResolved    = "SCOPE_COMPLETENESS_RESOLVED"

	maxScopeInputBytes = 1 << 20
)

const scopeNotSuppliedNote = "No component scope was declared, so no whole-upgrade or scoped aggregate is derivable: the per-check applicability below is a triage aid, not a compatibility verdict. Pass --scope-input FILE with an operator-declared constraint input carrying a scope declaration to get a scope-completeness aggregate over the attested rule corpus."

const scopeSuppliedNote = "This aggregate is the constraint engine's own recomputed scope-completeness verdict over the declared component set only. It is never SAFE: SCOPE_COMPLETE_PASS states only that every applicable reviewed constraint for the declared components was evaluated and passed, with everything not evaluated enumerated per component in scopeAssessment.check.scopeCompleteness. The declared scope was validated against the caller's own declared bundle, not against observed cluster state."

// observableComponents is the closed, small correspondence between a native
// check route's catalog project slug and the componentId that
// localcollector's already-reviewed component-configuration adapter registry
// can identify from container images. It is not a new compatibility claim:
// it only says "the catalog's 'cilium' project and the collector's
// 'pkg:oci/cilium/cilium' adapter identify the same upstream project", which
// both already-reviewed sources independently assert.
//
// Every catalog project not listed here has no observation basis at all in
// the current collector: its checks are always INDETERMINATE_NOT_OBSERVABLE.
var observableComponents = map[string]string{
	"prometheus":     "pkg:oci/prometheus/prometheus",
	"cilium":         "pkg:oci/cilium/cilium",
	"argo-cd":        "pkg:oci/argoproj/argo-cd",
	"argo-workflows": "pkg:oci/argoproj/argo-workflows",
}

const kubernetesProject = "kubernetes"

// Options drives one collection-and-classification run. It intentionally
// mirrors localcollector.Options for the collection half; nothing here
// widens what the collector is allowed to read.
type Options struct {
	OutputRoot                    string
	Kubeconfig                    string
	Contexts                      []string
	AcknowledgeExecRisk           bool
	AllowPartial                  bool
	ExecEnv                       []string
	Kubectl                       string
	ComponentConfigurationProfile string
	Now                           func() time.Time
	Random                        io.Reader
	// Runner overrides the collector's kubectl invocation. Production callers
	// leave this nil, which the collector resolves to its own ExecRunner.
	// Tests inject a fake to classify against synthetic API responses without
	// a real cluster or kubectl binary.
	Runner localcollector.Runner
	// ScopeInput is an optional path to an operator-declared constraint input
	// carrying a scope declaration. With it, the aggregate becomes the
	// constraint engine's own scope-completeness verdict over the attested
	// rule corpus; without it the aggregate stays UNKNOWN. It is never
	// synthesised from collected state: a scope declaration is the operator's
	// statement to make, and an absent one is not a default.
	ScopeInput string
}

// Report is the combined, single-file output of the one-command flow.
type Report struct {
	Schema       string              `json:"schema"`
	GeneratedAt  string              `json:"generatedAt"`
	Collector    CollectorSummary    `json:"collector"`
	RouteCatalog RouteCatalogInfo    `json:"routeCatalog"`
	Contexts     []ContextAssessment `json:"contexts"`
	Aggregate    AggregateNote       `json:"aggregate"`
	// ScopeAssessment is present only when the operator declared a component
	// scope. It carries the engine's enumerated per-component evidence,
	// including every rule that was not evaluated and why.
	ScopeAssessment *projectcheck.ScopeReport `json:"scopeAssessment,omitempty"`
}

type CollectorSummary struct {
	OutputRoot   string `json:"outputRoot"`
	ContextCount int    `json:"contextCount"`
}

type RouteCatalogInfo struct {
	TotalNativeRoutes int `json:"totalNativeRoutes"`
}

type ContextAssessment struct {
	ContextHash      string               `json:"contextHash"`
	RunDirectory     string               `json:"runDirectory"`
	CollectionStatus string               `json:"collectionStatus"`
	BundleDigest     string               `json:"bundleDigest"`
	Summary          ApplicabilitySummary `json:"summary"`
	Checks           []CheckAssessment    `json:"checks"`
}

type ApplicabilitySummary struct {
	ApplicableFullySatisfied       int `json:"applicableFullySatisfied"`
	ApplicableNeedsDeclaration     int `json:"applicableNeedsDeclaration"`
	NotApplicableVersionMismatch   int `json:"notApplicableVersionMismatch"`
	NotApplicableComponentAbsent   int `json:"notApplicableComponentAbsent"`
	IndeterminateNotObservable     int `json:"indeterminateNotObservable"`
	IndeterminatePartialCollection int `json:"indeterminatePartialCollection"`
}

type Declaration struct {
	Flag        string `json:"flag"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

type CheckAssessment struct {
	Project             string        `json:"project"`
	Component           string        `json:"component"`
	RuleID              string        `json:"ruleId"`
	From                string        `json:"from"`
	To                  string        `json:"to"`
	Applicability       string        `json:"applicability"`
	Reason              string        `json:"reason"`
	ObservedVersion     string        `json:"observedVersion,omitempty"`
	MissingDeclarations []Declaration `json:"missingDeclarations,omitempty"`
	Command             []string      `json:"command,omitempty"`
	Result              *RunResult    `json:"result,omitempty"`
}

// RunResult is reserved for a future ApplicableFullySatisfied check: one
// with zero caller declarations beyond the version pair itself. As of the
// current 194-route catalog this bucket is empty and verified so (see
// TestNoNativeRouteIsFullySatisfiedByVersionAlone and
// cli/docs/one-command-flow.md); execution is deliberately not wired yet,
// so this field is always nil today. It is not omitted from the schema so
// a caller does not need a schema change the day a zero-declaration route
// is added.
type RunResult struct {
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout"`
}

type AggregateNote struct {
	Assessment string `json:"assessment"`
	ReasonCode string `json:"reasonCode"`
	Note       string `json:"note"`
}

// ExitCode mirrors the collector's own convention: 0 clean, 6 partial
// observation accepted, 2 usage/setup failure, 3 integrity failure.
const (
	ExitOK        = 0
	ExitUsage     = 2
	ExitIntegrity = 3
	ExitPartial   = 6
)

// Run collects a current bundle from each declared kubeconfig context and
// classifies every one of the 194 native check routes against it. It never
// mutates cluster state and never opens any network path beyond the
// Kubernetes API the collector already uses.
//
// The collector is invoked once per context, never once for all of them:
// internal/observation.Import (a reviewed, unmodified boundary this package
// does not touch) refuses to import an observation root whose index
// declares more than one context. That existing constraint, not a choice
// made here, is why each context gets its own collection run and its own
// private output directory.
func Run(ctx context.Context, opts Options, stdout, stderr io.Writer) (Report, int) {
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.Random == nil {
		opts.Random = rand.Reader
	}
	if len(opts.Contexts) == 0 {
		fmt.Fprintln(stderr, "At least one kubeconfig context is required.")
		return Report{}, ExitUsage
	}
	collectedAt := opts.Now().UTC().Truncate(time.Second)
	nowForEvaluation := opts.Now().UTC()
	if nowForEvaluation.Before(collectedAt) {
		nowForEvaluation = collectedAt
	}

	outputRoot := opts.OutputRoot
	if outputRoot == "" {
		created, err := os.MkdirTemp("", "prufyx-assess-")
		if err != nil {
			fmt.Fprintln(stderr, "Cannot create a private working directory for the collected bundle.")
			return Report{}, ExitUsage
		}
		outputRoot = created
	}

	catalog, err := checkroutemetadata.Discover("", "", "")
	if err != nil {
		fmt.Fprintln(stderr, "Check-route catalog integrity failure.")
		return Report{}, ExitIntegrity
	}
	routes := nativeRoutes(catalog)

	report := Report{
		Schema:       Schema,
		GeneratedAt:  opts.Now().UTC().Format(time.RFC3339),
		Collector:    CollectorSummary{OutputRoot: outputRoot, ContextCount: len(opts.Contexts)},
		RouteCatalog: RouteCatalogInfo{TotalNativeRoutes: len(routes)},
		Contexts:     make([]ContextAssessment, 0, len(opts.Contexts)),
		Aggregate: AggregateNote{
			Assessment: "UNKNOWN",
			ReasonCode: reasonScopeNotSupplied,
			Note:       scopeNotSuppliedNote,
		},
	}

	if opts.ScopeInput != "" {
		scope, code := assessDeclaredScope(opts.ScopeInput, nowForEvaluation, stderr)
		if code != ExitOK {
			return Report{}, code
		}
		reason := scope.Check.ScopeCompleteness.UnresolvedReason
		if reason == "" {
			reason = reasonScopeResolved
		}
		report.Aggregate = AggregateNote{Assessment: scope.Assessment, ReasonCode: reason, Note: scopeSuppliedNote}
		report.ScopeAssessment = &scope
	}

	for _, contextName := range opts.Contexts {
		assessment, exitCode := assessOneContext(ctx, opts, contextName, outputRoot, collectedAt, nowForEvaluation, routes, stdout, stderr)
		if exitCode != ExitOK {
			return Report{}, exitCode
		}
		report.Contexts = append(report.Contexts, assessment)
	}
	return report, ExitOK
}

// assessDeclaredScope evaluates the operator's declared scope against the
// whole attested rule corpus. It authors nothing: the declaration comes from
// the operator's own file, the rules and the completeness attestation come
// from the reviewed embedded pack, and the aggregate is the engine's own —
// re-derived by constraintengine.MarshalReport before it is accepted here.
func assessDeclaredScope(path string, now time.Time, stderr io.Writer) (projectcheck.ScopeReport, int) {
	raw, err := currentbundle.ReadBoundedFile(path, maxScopeInputBytes)
	if err != nil {
		fmt.Fprintln(stderr, "Cannot read the declared scope input file.")
		return projectcheck.ScopeReport{}, ExitUsage
	}
	scope, err := projectcheck.AssessScope(raw, now.UTC().Truncate(time.Second))
	if err != nil {
		fmt.Fprintln(stderr, "The declared scope input was rejected: it must be an operator-declared constraint input carrying a scope declaration whose components exactly match its own declared bundle and are known to the embedded rule corpus.")
		return projectcheck.ScopeReport{}, ExitUsage
	}
	if scope.Check.ScopeCompleteness == nil {
		fmt.Fprintln(stderr, "Scope-completeness evidence is unavailable for the declared scope.")
		return projectcheck.ScopeReport{}, ExitIntegrity
	}
	if _, err := projectcheck.MarshalScopeReport(scope); err != nil {
		fmt.Fprintln(stderr, "Scope assessment integrity failure.")
		return projectcheck.ScopeReport{}, ExitIntegrity
	}
	return scope, ExitOK
}

func assessOneContext(ctx context.Context, opts Options, contextName, outputRoot string, collectedAt, now time.Time, routes []checkroutemetadata.Check, stdout, stderr io.Writer) (ContextAssessment, int) {
	collectorOpts := localcollector.Options{
		OutputRoot:                    outputRoot,
		Kubeconfig:                    opts.Kubeconfig,
		Contexts:                      []string{contextName},
		IncludeComponentConfiguration: true,
		ComponentConfigurationProfile: opts.ComponentConfigurationProfile,
		AllowPartial:                  true, // this package classifies partial results honestly instead of the collector refusing them; see the per-context gate below.
		AcknowledgeExecRisk:           opts.AcknowledgeExecRisk,
		ExecEnv:                       opts.ExecEnv,
		Kubectl:                       opts.Kubectl,
		Now:                           func() time.Time { return collectedAt },
		Random:                        opts.Random,
	}
	runDir, code := (localcollector.Collector{Runner: opts.Runner}).Collect(ctx, collectorOpts, stdout, stderr)
	if code != 0 {
		// AllowPartial is forced true above, so the only way Collect fails here
		// is a genuine setup/integrity problem, never a partial observation.
		return ContextAssessment{}, ExitUsage
	}
	if runDir == "" {
		fmt.Fprintln(stderr, "Collector produced no observation directory.")
		return ContextAssessment{}, ExitUsage
	}
	index, err := readIndex(runDir)
	if err != nil || len(index.Contexts) != 1 {
		fmt.Fprintln(stderr, "Cannot read the collector's observation index.")
		return ContextAssessment{}, ExitIntegrity
	}
	entry := index.Contexts[0]
	if entry.CollectionStatus == "partial_for_declared_surface" && !opts.AllowPartial {
		fmt.Fprintf(stderr, "Context %s: observation is partial; rerun with --allow-partial to classify checks anyway (absence conclusions are downgraded to indeterminate instead of asserted).\n", entry.ContextHash)
		return ContextAssessment{}, ExitPartial
	}

	root, err := observation.OpenPath(runDir)
	if err != nil {
		fmt.Fprintf(stderr, "Cannot open the observation root for context %s.\n", entry.ContextHash)
		return ContextAssessment{}, ExitIntegrity
	}
	defer root.Close()

	artifact, err := currentbundle.BuildObservation(ctx, root, currentbundle.Options{
		CapturedAt:           collectedAt,
		Now:                  now,
		RequireSourceCapture: true,
		FreshnessPolicy:      currentbundle.FreshnessPolicy{ID: freshnessPolicyID, MaxAge: freshnessMaxAge},
	})
	if err != nil {
		fmt.Fprintf(stderr, "Cannot build the current bundle for context %s: %v\n", entry.ContextHash, err)
		return ContextAssessment{}, ExitIntegrity
	}
	bundle := artifact.Bundle
	partial := bundle.SourceCollectionStatus == "partial_for_declared_surface"

	assessment := ContextAssessment{
		ContextHash:      entry.ContextHash,
		RunDirectory:     runDir,
		CollectionStatus: entry.CollectionStatus,
		BundleDigest:     artifact.Digest,
		Checks:           make([]CheckAssessment, 0, len(routes)),
	}
	for _, route := range routes {
		checkAssessment := classify(route, bundle, partial)
		assessment.Checks = append(assessment.Checks, checkAssessment)
		tally(&assessment.Summary, checkAssessment.Applicability)
	}
	sort.Slice(assessment.Checks, func(i, j int) bool {
		if assessment.Checks[i].Project != assessment.Checks[j].Project {
			return assessment.Checks[i].Project < assessment.Checks[j].Project
		}
		return assessment.Checks[i].RuleID < assessment.Checks[j].RuleID
	})
	return assessment, ExitOK
}

func tally(summary *ApplicabilitySummary, applicability string) {
	switch applicability {
	case ApplicableFullySatisfied:
		summary.ApplicableFullySatisfied++
	case ApplicableNeedsDeclaration:
		summary.ApplicableNeedsDeclaration++
	case NotApplicableVersionMismatch:
		summary.NotApplicableVersionMismatch++
	case NotApplicableComponentAbsent:
		summary.NotApplicableComponentAbsent++
	case IndeterminateNotObservable:
		summary.IndeterminateNotObservable++
	case IndeterminatePartialCollection:
		summary.IndeterminatePartialCollection++
	}
}

func classify(route checkroutemetadata.Check, bundle currentbundle.CurrentBundle, contextPartial bool) CheckAssessment {
	base := CheckAssessment{
		Project:   route.Project,
		Component: route.Component,
		RuleID:    route.RuleID,
		From:      route.From,
		To:        route.To,
		Command:   renderCommand(route.NativeDescriptor.Command),
	}

	if route.Project == kubernetesProject {
		return classifyKubernetes(base, route, bundle, contextPartial)
	}
	componentID, observable := observableComponents[route.Project]
	if !observable {
		base.Applicability = IndeterminateNotObservable
		base.Reason = "This check's target project is not one of the components the collector's reviewed adapter registry can identify from container images. Presence, absence, and version are all unknown from collected state; determine applicability manually with the expert-path command shown below."
		return base
	}
	component, found := findComponent(bundle, componentID)
	if !found {
		if contextPartial {
			base.Applicability = IndeterminatePartialCollection
			base.Reason = "The component was not found, but this context's collection was partial (a declared API read failed or was rejected). Absence is not confirmed; rerun collection without omissions before concluding this check does not apply."
			return base
		}
		base.Applicability = NotApplicableComponentAbsent
		base.Reason = "The component was not observed running in this cluster context."
		return base
	}
	base.ObservedVersion = component.Version.Value
	if component.Version.State != "exact" || !route.Transition().IsAnchorFrom(component.Version.Value) {
		base.Applicability = NotApplicableVersionMismatch
		base.Reason = "The component is present but its observed version does not match this check's declared origin version."
		return base
	}
	return withDeclarations(base, route)
}

func classifyKubernetes(base CheckAssessment, route checkroutemetadata.Check, bundle currentbundle.CurrentBundle, contextPartial bool) CheckAssessment {
	kube := bundle.Environment.Kubernetes
	if kube.State != "observed" {
		base.Applicability = IndeterminatePartialCollection
		base.Reason = "The Kubernetes server version was not observed in this context (the /version read failed or was omitted)."
		return base
	}
	base.ObservedVersion = kube.Value
	if !route.Transition().IsAnchorFrom(kube.Value) {
		base.Applicability = NotApplicableVersionMismatch
		base.Reason = "The observed Kubernetes server version does not match this check's declared origin version."
		return base
	}
	_ = contextPartial // Kubernetes version comes from a base query attempted for every context; a partial collection elsewhere does not weaken a positive read here.
	return withDeclarations(base, route)
}

func withDeclarations(base CheckAssessment, route checkroutemetadata.Check) CheckAssessment {
	missing := missingDeclarations(route.NativeDescriptor.Command)
	if len(missing) == 0 {
		base.Applicability = ApplicableFullySatisfied
		base.Reason = "The observed version matches this check's declared transition, and the route requires no caller declaration beyond the version pair. This build does not yet dispatch it automatically (see the design note); run the command above to get its verdict."
		return base
	}
	base.Applicability = ApplicableNeedsDeclaration
	base.Reason = "The observed version matches this check's declared transition, but the route requires operator declarations that cannot be observed from cluster state. Supply exactly the flags below."
	base.MissingDeclarations = missing
	return base
}

func findComponent(bundle currentbundle.CurrentBundle, componentID string) (currentbundle.CanonicalComponent, bool) {
	for _, component := range bundle.Planes.Observed.Components {
		if component.ComponentID == componentID {
			return component, true
		}
	}
	return currentbundle.CanonicalComponent{}, false
}

// missingDeclarations returns every argument in a native descriptor's command
// that is not a literal or a timestamp the collector can already supply
// (--now). Never invents a value for any of these; that is the caller's
// declaration to make.
func missingDeclarations(command []checkroutemetadata.Argument) []Declaration {
	declarations := make([]Declaration, 0, len(command))
	for _, arg := range command {
		description := ""
		switch arg.Kind {
		case "file_placeholder":
			description = "A caller-supplied file declaring a resource or configuration. This is content the collector does not gather: it is either an intent declaration (what you plan to configure) or a resource shape the collector deliberately does not retain."
		case "name_placeholder":
			description = "A caller-declared name (for example a container, distribution, or resource name) that disambiguates which observed object the check should evaluate."
		case "boolean_operator_declaration":
			description = "A caller-declared true/false intent flag. It is never inferred or defaulted from cluster state; an absent declaration is not a false."
		default:
			continue
		}
		declarations = append(declarations, Declaration{Flag: arg.Name, Kind: arg.Kind, Description: description})
	}
	return declarations
}

// renderCommand renders a native descriptor's command template as a
// human-readable argv, substituting FILE/NAME/true|false placeholders. It
// does not resolve any of them; it is a copy/paste starting point for the
// operator, identical in shape to `prufyx catalog checks`.
func renderCommand(command []checkroutemetadata.Argument) []string {
	if len(command) == 0 {
		return nil
	}
	out := make([]string, 0, len(command)*2)
	for _, arg := range command {
		switch arg.Kind {
		case "literal":
			out = append(out, arg.Literal)
		case "file_placeholder":
			out = append(out, arg.Name, "FILE")
		case "name_placeholder":
			out = append(out, arg.Name, "NAME")
		case "boolean_operator_declaration":
			out = append(out, arg.Name+"=true|false")
		case "timestamp_placeholder":
			out = append(out, arg.Name, "RFC3339")
		}
	}
	return out
}

func nativeRoutes(result checkroutemetadata.Result) []checkroutemetadata.Check {
	routes := make([]checkroutemetadata.Check, 0, len(result.Checks))
	for _, check := range result.Checks {
		if check.NativeDescriptor.State == checkroutemetadata.DescriptorExact {
			routes = append(routes, check)
		}
	}
	return routes
}

type contextIndexEntry struct {
	Directory        string `json:"directory"`
	ContextHash      string `json:"contextHash"`
	CollectionStatus string `json:"collectionStatus"`
	OmissionCount    int    `json:"omissionCount"`
}

type indexFile struct {
	Schema      string              `json:"schema"`
	GeneratedAt string              `json:"generatedAt"`
	Contexts    []contextIndexEntry `json:"contexts"`
}

func readIndex(runDir string) (indexFile, error) {
	data, err := currentbundle.ReadBoundedFile(filepath.Join(runDir, "index.json"), 1<<20)
	if err != nil {
		return indexFile{}, err
	}
	var index indexFile
	if err := json.Unmarshal(data, &index); err != nil {
		return indexFile{}, err
	}
	if len(index.Contexts) == 0 {
		return indexFile{}, fmt.Errorf("observation index declares no contexts")
	}
	return index, nil
}

// MarshalReport emits deterministic, indented JSON.
func MarshalReport(report Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
