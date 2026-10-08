// SPDX-License-Identifier: AGPL-3.0-only

package onecommand

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/localcollector"
)

// fakeRunner answers every kubectl invocation with a synthetic response built
// from the requested resource, so classification can be tested without a
// real cluster or kubectl binary. It never receives a real credential: the
// collector itself resolves and snapshots the kubeconfig before any Runner
// call, exactly as it does in production.
type fakeRunner struct {
	t *testing.T
	// failQuery, when non-empty, makes every call whose argv contains this
	// substring fail, producing a partial collection.
	failQuery string
}

func (f *fakeRunner) Run(_ context.Context, argv, _ []string, timeout time.Duration) (localcollector.CommandResult, error) {
	f.t.Helper()
	joined := strings.Join(argv, " ")
	if f.failQuery != "" && strings.Contains(joined, f.failQuery) {
		return localcollector.CommandResult{Exit: 1, Class: "authorization_rbac_forbidden"}, nil
	}
	return localcollector.CommandResult{Stdout: fakeKubectlResponse(joined), Exit: 0}, nil
}

// fakeKubectlResponse mirrors the shape localcollector's fake test runner
// uses: every base query gets an empty, well-formed list except the ones
// this test cares about (server version and Deployments, which carry one
// synthetic Prometheus workload at a known version).
func fakeKubectlResponse(joined string) []byte {
	var value any
	switch {
	case strings.Contains(joined, "--raw=/version"):
		value = map[string]any{"gitVersion": "v1.31.0"}
	case strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": []any{}}
	case strings.Contains(joined, "--raw=/apis"):
		value = map[string]any{"groups": []any{}}
	case strings.Contains(joined, "--raw=/api") && !strings.Contains(joined, "customresourcedefinitions"):
		value = map[string]any{"versions": []any{"v1"}}
	case strings.Contains(joined, " deployments.apps "):
		value = map[string]any{"items": []any{
			map[string]any{
				"kind": "Deployment",
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
					"containers": []any{map[string]any{
						"image": "quay.io/prometheus/prometheus:2.55.1",
						"args":  []any{"--log.level=info"},
					}},
				}}},
			},
		}}
	default:
		value = map[string]any{"items": []any{}}
	}
	raw, _ := json.Marshal(value)
	return raw
}

const testKubeconfigYAML = "apiVersion: v1\nkind: Config\nclusters: []\ncontexts: []\nusers: []\n"

func writeFakeKubeconfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(testKubeconfigYAML+"# test-kubeconfig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func baseTestOptions(t *testing.T, runner localcollector.Runner) Options {
	t.Helper()
	return Options{
		OutputRoot:          t.TempDir(),
		Kubeconfig:          writeFakeKubeconfig(t),
		Contexts:            []string{"test-context"},
		AcknowledgeExecRisk: true,
		Kubectl:             os.Args[0],
		Now:                 func() time.Time { return time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC) },
		Random:              strings.NewReader(strings.Repeat("r", 64)),
		Runner:              runner,
	}
}

func findCheck(t *testing.T, checks []CheckAssessment, project, from string) CheckAssessment {
	t.Helper()
	for _, c := range checks {
		if c.Project == project && c.From == from {
			return c
		}
	}
	t.Fatalf("no check found for project=%s from=%s", project, from)
	return CheckAssessment{}
}

func TestRunClassifiesThreeWaySplit(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t})
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run failed: code=%d stderr=%s", code, stderr.String())
	}
	if report.RouteCatalog.TotalNativeRoutes != 194 {
		t.Fatalf("totalNativeRoutes=%d want 194", report.RouteCatalog.TotalNativeRoutes)
	}
	// Without a declared component scope there is no auditable applicable set,
	// so the aggregate must stay UNKNOWN however many routes classified as
	// applicable. An applicability classification is never a verdict.
	if report.Aggregate.Assessment != "UNKNOWN" || report.Aggregate.ReasonCode != reasonScopeNotSupplied {
		t.Fatalf("aggregate=%q/%q, want UNKNOWN with no scope declaration", report.Aggregate.Assessment, report.Aggregate.ReasonCode)
	}
	if report.ScopeAssessment != nil {
		t.Fatal("a scope assessment appeared without a scope declaration")
	}
	if len(report.Contexts) != 1 {
		t.Fatalf("contexts=%d want 1", len(report.Contexts))
	}
	ctxReport := report.Contexts[0]
	if ctxReport.CollectionStatus != "complete_for_declared_surface" {
		t.Fatalf("collectionStatus=%q", ctxReport.CollectionStatus)
	}
	if len(ctxReport.Checks) != 194 {
		t.Fatalf("checks=%d want 194", len(ctxReport.Checks))
	}

	// Prometheus is observed at exactly 2.55.1 with a recognized predicate
	// (--log.level), so the alertmanager-api-v1-removed check at that exact
	// origin is applicable but needs the declarations the collector cannot
	// supply (an Alertmanager config file, plus completeness declarations).
	promCheck := findCheck(t, ctxReport.Checks, "prometheus", "2.55.1")
	if promCheck.Applicability != ApplicableNeedsDeclaration {
		t.Fatalf("prometheus 2.55.1 applicability=%q reason=%q", promCheck.Applicability, promCheck.Reason)
	}
	if promCheck.ObservedVersion != "2.55.1" {
		t.Fatalf("prometheus observedVersion=%q", promCheck.ObservedVersion)
	}
	foundFileFlag := false
	for _, d := range promCheck.MissingDeclarations {
		if d.Flag == "--alertmanager-config" && d.Kind == "file_placeholder" {
			foundFileFlag = true
		}
	}
	if !foundFileFlag {
		t.Fatalf("expected --alertmanager-config in missing declarations: %+v", promCheck.MissingDeclarations)
	}

	// Prometheus origins other than 2.55.1 do not match what was observed.
	mismatch := findCheck(t, ctxReport.Checks, "prometheus", "3.9.1")
	if mismatch.Applicability != NotApplicableVersionMismatch {
		t.Fatalf("prometheus 3.9.1 applicability=%q", mismatch.Applicability)
	}

	// Cilium was never observed in this synthetic cluster at all.
	for _, c := range ctxReport.Checks {
		if c.Project != "cilium" {
			continue
		}
		if c.Applicability != NotApplicableComponentAbsent {
			t.Fatalf("cilium %s applicability=%q, want NOT_APPLICABLE_COMPONENT_ABSENT", c.RuleID, c.Applicability)
		}
	}

	// Kubernetes itself was observed at 1.31.0, matching the one registered
	// kubernetes-project check's origin.
	kube := findCheck(t, ctxReport.Checks, "kubernetes", "1.31.0")
	if kube.Applicability != ApplicableNeedsDeclaration {
		t.Fatalf("kubernetes 1.31.0 applicability=%q reason=%q", kube.Applicability, kube.Reason)
	}

	// A project neither the collector's adapter registry nor the reviewed
	// image registry identifies (e.g. loki) is always indeterminate, never a
	// claimed absence.
	for _, c := range ctxReport.Checks {
		if c.Project == "loki" && c.Applicability != IndeterminateNotObservable {
			t.Fatalf("loki %s applicability=%q, want INDETERMINATE_NOT_OBSERVABLE", c.RuleID, c.Applicability)
		}
	}

	// Summary counts must add up to the total.
	s := ctxReport.Summary
	total := s.ApplicableFullySatisfied + s.ApplicableNeedsDeclaration + s.NotApplicableVersionMismatch + s.NotApplicableComponentAbsent + s.IndeterminateNotObservable + s.IndeterminatePartialCollection
	if total != 194 {
		t.Fatalf("summary total=%d want 194 (%+v)", total, s)
	}
	if s.ApplicableFullySatisfied != 0 {
		t.Fatalf("applicableFullySatisfied=%d, want 0 for the current catalog (see TestNoNativeRouteIsFullySatisfiedByVersionAlone)", s.ApplicableFullySatisfied)
	}

	raw, err := MarshalReport(report)
	if err != nil || !json.Valid(raw) {
		t.Fatalf("MarshalReport: %v", err)
	}
	// Never write raw context names into the report.
	if strings.Contains(string(raw), "test-context") {
		t.Fatal("raw context name escaped into the report")
	}
}

func TestRunRejectsEmptyContexts(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t})
	opts.Contexts = nil
	var stdout, stderr bytes.Buffer
	_, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitUsage {
		t.Fatalf("code=%d want ExitUsage", code)
	}
}

func TestRunPartialCollectionDefaultsToRefusing(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t, failQuery: "storageclasses.storage.k8s.io"})
	var stdout, stderr bytes.Buffer
	_, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitPartial {
		t.Fatalf("code=%d want ExitPartial; stderr=%s", code, stderr.String())
	}
}

func TestRunPartialCollectionDowngradesAbsenceButNotPositiveEvidence(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t, failQuery: "storageclasses.storage.k8s.io"})
	opts.AllowPartial = true
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	checks := report.Contexts[0].Checks
	for _, c := range checks {
		if c.Project == "cilium" && c.Applicability != IndeterminatePartialCollection {
			t.Fatalf("cilium %s applicability=%q, want INDETERMINATE_PARTIAL_COLLECTION under partial collection", c.RuleID, c.Applicability)
		}
	}
	// A component that WAS positively observed keeps its conclusion; a
	// failed, unrelated read elsewhere does not weaken positive evidence.
	prom := findCheck(t, checks, "prometheus", "2.55.1")
	if prom.Applicability != ApplicableNeedsDeclaration {
		t.Fatalf("prometheus 2.55.1 applicability=%q under unrelated partial collection, want unchanged", prom.Applicability)
	}
}

// TestNoNativeRouteIsFullySatisfiedByVersionAlone documents and enforces a
// core finding of the design: every one of the 194 native check routes
// requires at least one caller declaration (a file, a name, or a boolean
// intent flag) beyond the --from/--to version pair. If this ever stops being
// true, ApplicableFullySatisfied stops being a dead bucket and the design
// note's "0 of 194" claim needs updating alongside this test.
func TestNoNativeRouteIsFullySatisfiedByVersionAlone(t *testing.T) {
	result, err := checkroutemetadata.Discover("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	routes := nativeRoutes(result)
	if len(routes) != 194 {
		t.Fatalf("native routes=%d want 194", len(routes))
	}
	for _, route := range routes {
		if len(missingDeclarations(route.NativeDescriptor.Command)) == 0 {
			t.Fatalf("route %s/%s is fully satisfiable by version alone; update onecommand's fully-satisfied handling and the design note", route.Project, route.RuleID)
		}
	}
}

// rangedKubernetesRoute is a synthetic kubernetes-project check anchored at
// 1.24.0 -> 1.25.0 with a reviewed range covering same-line patches either
// side of the anchor. It carries no native descriptor, so the only thing
// under test is the version gate in classifyKubernetes.
func rangedKubernetesRoute() checkroutemetadata.Check {
	return checkroutemetadata.Check{
		Project: kubernetesProject,
		From:    "1.24.0",
		To:      "1.25.0",
		Range: &constraintengine.VersionRange{
			From: constraintengine.VersionBound{Gte: "1.24.0", Lt: "1.25.0"},
			To:   constraintengine.VersionBound{Gte: "1.25.0", Lt: "1.26.0"},
			// A release-boundary range: C = 1.25.0 is REMOVED_IN_RELEASE on
			// both boundary bounds, the shape of the shipped removals.
			Bounds: []constraintengine.RangeBound{
				{Bound: "from.gte", Basis: constraintengine.BasisPreviousMinorLine, SourceID: "s"},
				{Bound: "from.lt", Basis: constraintengine.BasisRemovedInRelease, SourceID: "s"},
				{Bound: "to.gte", Basis: constraintengine.BasisRemovedInRelease, SourceID: "s"},
				{Bound: "to.lt", Basis: constraintengine.BasisReviewedThroughMinorLine, SourceID: "s"},
			},
		},
		NativeDescriptor: checkroutemetadata.Route{State: checkroutemetadata.DescriptorNone},
	}
}

func kubernetesObservedBundle(value string) currentbundle.CurrentBundle {
	return currentbundle.CurrentBundle{Environment: currentbundle.Environment{Kubernetes: currentbundle.FieldValue{State: "observed", Value: value}}}
}

// TestClassifyKubernetesRangeApplicability: anchor 1.24.0 -> 1.25.0, change
// version C = 1.25.0, origin range [1.24.0,1.25.0), target range [1.25.0,1.26.0).
// NOT_APPLICABLE only when the hop provably does not cross C; a hop that
// crosses C but is wider than the reviewed range is INDETERMINATE.
func TestClassifyKubernetesRangeApplicability(t *testing.T) {
	route := rangedKubernetesRoute()
	cases := []struct {
		name, observed, to, want string
		needsTo                  bool
	}{
		{"anchor origin, no target", "1.24.0", "", ApplicableFullySatisfied, false},
		{"anchor origin, matching target", "1.24.0", "1.25.0", ApplicableFullySatisfied, false},
		{"anchor origin, contradictory target still the anchor hop", "1.24.0", "9.9.9", ApplicableFullySatisfied, false},
		{"in range, no target", "1.24.17", "", ApplicableNeedsDeclaration, true},
		{"in range, target at C", "1.24.17", "1.25.0", ApplicableNeedsDeclaration, false},
		{"in range, target above C", "1.24.5", "1.25.9", ApplicableNeedsDeclaration, false},
		{"target below C: does not cross", "1.24.17", "1.24.99", NotApplicableVersionMismatch, false},
		{"target equals origin", "1.24.17", "1.24.17", NotApplicableVersionMismatch, false},
		{"downgrade", "1.24.17", "1.23.0", NotApplicableVersionMismatch, false},
		{"crosses C, past reviewed range", "1.24.17", "1.26.0", IndeterminateHopOutsideReviewedRange, false},
		{"crosses C, multi-minor target", "1.24.17", "1.35.6", IndeterminateHopOutsideReviewedRange, false},
		{"origin at C (already past)", "1.25.0", "1.25.4", NotApplicableVersionMismatch, false},
		// BOUNDARY-1: an origin below the range may still be upgraded across
		// C = 1.25.0, so it is never excluded when the target reaches C.
		{"origin below range, target above C", "1.23.9", "1.25.1", IndeterminateHopOutsideReviewedRange, false},
		{"origin below range, target at C", "1.23.9", "1.25.0", IndeterminateHopOutsideReviewedRange, false},
		{"origin far below range, wide target", "1.20.15", "1.30.2", IndeterminateHopOutsideReviewedRange, false},
		{"origin below range, no target", "1.23.9", "", ApplicableNeedsDeclaration, true},
		{"origin below range, target below C", "1.23.9", "1.24.5", NotApplicableVersionMismatch, false},
		{"origin below range, target equals origin", "1.23.9", "1.23.9", NotApplicableVersionMismatch, false},
		{"origin below range, downgrade", "1.23.9", "1.22.0", NotApplicableVersionMismatch, false},
		{"origin far above", "1.35.6", "1.36.0", NotApplicableVersionMismatch, false},
		{"unparseable origin v-prefix", "v1.24.17", "1.25.1", IndeterminateVersionUnparseable, false},
		{"unparseable origin eks suffix", "1.24.17-eks-abc", "1.25.1", IndeterminateVersionUnparseable, false},
	}
	for _, tc := range cases {
		got := classifyKubernetes(CheckAssessment{Project: route.Project, From: route.From, To: route.To}, route, kubernetesObservedBundle(tc.observed), false, tc.to)
		if got.Applicability != tc.want {
			t.Errorf("%s: applicability=%q, want %q", tc.name, got.Applicability, tc.want)
		}
		hasTo := false
		for _, d := range got.MissingDeclarations {
			hasTo = hasTo || d.Flag == "--to"
		}
		if hasTo != tc.needsTo {
			t.Errorf("%s: --to declaration present=%v, want %v", tc.name, hasTo, tc.needsTo)
		}
	}
}

// The reviewer's malformed targets never reach classification: the assess
// flag rejects them as a usage error (see communityapp). If one did reach it
// anyway, it must not become NOT_APPLICABLE.
func TestClassifyMalformedTargetNeverNotApplicable(t *testing.T) {
	route := rangedKubernetesRoute()
	for _, to := range []string{"1.25", "v1.25.1", "1.25.1-gke.100", "1.25.1-rc.0", "garbage"} {
		got := classifyKubernetes(CheckAssessment{}, route, kubernetesObservedBundle("1.24.17"), false, to)
		if got.Applicability == NotApplicableVersionMismatch {
			t.Errorf("to=%q: malformed target produced NOT_APPLICABLE", to)
		}
	}
}

func TestRangeHopRendersTheOperatorsOwnCommand(t *testing.T) {
	route := rangedKubernetesRoute()
	route.NativeDescriptor = checkroutemetadata.Route{State: checkroutemetadata.DescriptorExact, Command: []checkroutemetadata.Argument{
		{Kind: "literal", Literal: "check"}, {Kind: "literal", Literal: "--from"}, {Kind: "literal", Literal: "1.24.0"}, {Kind: "literal", Literal: "--to"}, {Kind: "literal", Literal: "1.25.0"}}}
	base := CheckAssessment{Command: renderCommand(route.NativeDescriptor.Command)}
	got := classifyKubernetes(base, route, kubernetesObservedBundle("1.24.17"), false, "1.25.3")
	if strings.Join(got.Command, " ") != "check --from 1.24.17 --to 1.25.3" || got.MatchMode != "range" {
		t.Fatalf("command=%v mode=%q", got.Command, got.MatchMode)
	}
	anchor := classifyKubernetes(base, route, kubernetesObservedBundle("1.24.0"), false, "")
	if strings.Join(anchor.Command, " ") != "check --from 1.24.0 --to 1.25.0" || anchor.MatchMode != "" {
		t.Fatalf("anchor command=%v mode=%q", anchor.Command, anchor.MatchMode)
	}
}

// assess --to is a Kubernetes target: a ranged component route never consumes
// it, so a Kubernetes target cannot turn a component check NOT_APPLICABLE.
func TestComponentRouteIgnoresKubernetesTarget(t *testing.T) {
	route := rangedKubernetesRoute()
	route.Project = "cilium"
	for _, to := range []string{"", "1.30.4"} {
		got := classifyOrigin(CheckAssessment{}, route, true, "1.24.17", "", false, "mismatch")
		if got.Applicability != ApplicableNeedsDeclaration || !strings.Contains(got.Reason, "native check") {
			t.Fatalf("to=%q component classified %q: %s", to, got.Applicability, got.Reason)
		}
	}
	// via classify(), a Kubernetes --to is not forwarded to component routes
	got := classifyOrigin(CheckAssessment{}, route, false, "1.24.17", "", false, "mismatch")
	if got.Applicability != IndeterminateVersionUnparseable {
		t.Fatalf("inexact component version: %q", got.Applicability)
	}
}

// A rule without a range is unchanged: only the anchor origin applies, and
// --to never widens it.
func TestClassifyKubernetesExactRuleIgnoresTarget(t *testing.T) {
	route := rangedKubernetesRoute()
	route.Range = nil
	for _, to := range []string{"", "1.25.1"} {
		got := classifyKubernetes(CheckAssessment{Project: route.Project}, route, kubernetesObservedBundle("1.24.17"), false, to)
		if got.Applicability != NotApplicableVersionMismatch {
			t.Fatalf("exact rule, to=%q: %q", to, got.Applicability)
		}
	}
}

// Mutation check: each mutant of the reviewed range must flip at least one
// row of a fixed probe table, so the table is not vacuous.
func TestClassifyRangeMutationCheck(t *testing.T) {
	probes := [][2]string{{"1.24.17", ""}, {"1.24.17", "1.24.99"}, {"1.24.17", "1.25.0"}, {"1.24.17", "1.25.9"}, {"1.24.17", "1.26.0"}, {"1.24.17", "1.26.5"}, {"1.25.0", "1.25.4"}, {"1.23.9", "1.25.1"}, {"1.24.0", "1.25.1"}, {"1.22.0", "1.25.1"}}
	render := func(r checkroutemetadata.Check) string {
		out := ""
		for _, p := range probes {
			out += classifyKubernetes(CheckAssessment{}, r, kubernetesObservedBundle(p[0]), false, p[1]).Applicability + "|"
		}
		return out
	}
	route := rangedKubernetesRoute()
	baseline := render(route)
	mutate := func(f func(v *constraintengine.VersionRange)) checkroutemetadata.Check {
		m := route
		v := *route.Range
		f(&v)
		m.Range = &v
		return m
	}
	mutants := map[string]checkroutemetadata.Check{
		"from.lt widened past C": mutate(func(v *constraintengine.VersionRange) { v.From.Lt = "1.25.1" }),
		"to.gte lowered below C": mutate(func(v *constraintengine.VersionRange) { v.To.Gte = "1.24.50" }),
		"to.gte raised past C":   mutate(func(v *constraintengine.VersionRange) { v.To.Gte = "1.25.3" }),
		"to.lt widened":          mutate(func(v *constraintengine.VersionRange) { v.To.Lt = "1.27.0" }),
		"to.lt narrowed":         mutate(func(v *constraintengine.VersionRange) { v.To.Lt = "1.25.5" }),
		"from.gte lowered":       mutate(func(v *constraintengine.VersionRange) { v.From.Gte = "1.22.0" }),
		"from.gte raised":        mutate(func(v *constraintengine.VersionRange) { v.From.Gte = "1.24.20" }),
		"release bounds dropped": mutate(func(v *constraintengine.VersionRange) { v.Bounds = nil }),
		"boundary basis not a release": mutate(func(v *constraintengine.VersionRange) {
			v.Bounds = append([]constraintengine.RangeBound(nil), v.Bounds...)
			v.Bounds[2].Basis = constraintengine.BasisTargetSeries
		}),
		"range dropped": func() checkroutemetadata.Check { m := route; m.Range = nil; return m }(),
	}
	for name, m := range mutants {
		if render(m) == baseline {
			t.Errorf("mutant %q survived", name)
		}
	}
}

func TestMissingDeclarationsSkipsLiteralsAndTimestamps(t *testing.T) {
	command := []checkroutemetadata.Argument{
		{Kind: "literal", Literal: "check"},
		{Kind: "literal", Literal: "cncf"},
		{Kind: "literal", Literal: "--project"},
		{Kind: "literal", Literal: "widget"},
		{Name: "--widget-config", Kind: "file_placeholder"},
		{Name: "--widget-name", Kind: "name_placeholder"},
		{Name: "--widget-required", Kind: "boolean_operator_declaration", AllowedValues: []string{"true", "false"}},
		{Name: "--now", Kind: "timestamp_placeholder"},
	}
	declarations := missingDeclarations(command)
	if len(declarations) != 3 {
		t.Fatalf("declarations=%+v want 3", declarations)
	}
	byFlag := map[string]Declaration{}
	for _, d := range declarations {
		byFlag[d.Flag] = d
	}
	if byFlag["--widget-config"].Kind != "file_placeholder" || byFlag["--widget-config"].Description == "" {
		t.Fatalf("file declaration missing or undescribed: %+v", byFlag["--widget-config"])
	}
	if byFlag["--widget-name"].Kind != "name_placeholder" {
		t.Fatalf("name declaration wrong: %+v", byFlag["--widget-name"])
	}
	if byFlag["--widget-required"].Kind != "boolean_operator_declaration" {
		t.Fatalf("boolean declaration wrong: %+v", byFlag["--widget-required"])
	}
}

func TestRenderCommandSubstitutesPlaceholders(t *testing.T) {
	command := []checkroutemetadata.Argument{
		{Kind: "literal", Literal: "check"},
		{Name: "--widget-config", Kind: "file_placeholder"},
		{Name: "--widget-name", Kind: "name_placeholder"},
		{Name: "--widget-required", Kind: "boolean_operator_declaration"},
		{Name: "--now", Kind: "timestamp_placeholder"},
	}
	got := renderCommand(command)
	want := []string{"check", "--widget-config", "FILE", "--widget-name", "NAME", "--widget-required=true|false", "--now", "RFC3339"}
	if len(got) != len(want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got=%v want=%v", got, want)
		}
	}
}

// lokiScopeInputJSON is an operator-declared constraint input whose scope
// declares exactly one component the embedded rule corpus is attested for, with
// every fact its reviewed rules read declared explicitly.
const lokiScopeInputJSON = `{
  "schema": "prufyx.io/operator-declared-constraint-input/v1alpha1",
  "authority": "OPERATOR_DECLARED_MINIMIZED",
  "scope": {"declaration": "OPERATOR_DECLARED_COMPLETE_COMPONENT_SET", "components": ["pkg:github/grafana/loki"]},
  "current": {"components": [{"component": "pkg:github/grafana/loki", "version": "2.9.8", "facts": []}]},
  "proposed": {"components": [{"component": "pkg:github/grafana/loki", "version": "3.0.0", "facts": [
    {"id": "component.loki.compactor_legacy_shared_store_present", "state": "declared", "boolValue": false},
    {"id": "component.loki.structured_metadata_requires_tsdb_v13", "state": "declared", "boolValue": false}
  ]}]}
}`

func writeScopeInput(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope-input.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestDeclaredScopeReachesScopeCompletePass is the aggregate this command
// could not reach before: a genuinely complete, genuinely attested component
// set, compiled deterministically from the engine's own enumerated evidence.
func TestDeclaredScopeReachesScopeCompletePass(t *testing.T) {
	opts := baseTestOptions(t, &fakeRunner{t: t})
	opts.ScopeInput = writeScopeInput(t, lokiScopeInputJSON)
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run failed: code=%d stderr=%s", code, stderr.String())
	}
	if report.Aggregate.Assessment != "SCOPE_COMPLETE_PASS" {
		t.Fatalf("aggregate=%q/%q", report.Aggregate.Assessment, report.Aggregate.ReasonCode)
	}
	if report.Aggregate.ReasonCode != reasonScopeResolved {
		t.Fatalf("reasonCode=%q", report.Aggregate.ReasonCode)
	}
	scope := report.ScopeAssessment
	if scope == nil || scope.Check.ScopeCompleteness == nil {
		t.Fatal("no scope evidence accompanied the aggregate")
	}
	if !scope.Check.ScopeCompleteness.Resolved || len(scope.Check.ScopeCompleteness.Components) != 1 {
		t.Fatalf("scope block=%+v", scope.Check.ScopeCompleteness)
	}
	if !scope.Check.ScopeCompleteness.Components[0].CorpusAttested {
		t.Fatal("the reached verdict was not backed by a corpus attestation")
	}
	// The corpus was unfiltered: the rules outside this scope are enumerated
	// as out of scope rather than silently absent.
	if scope.Check.ScopeCompleteness.OutOfScopeRules != scope.CorpusRuleCount-2 {
		t.Fatalf("outOfScopeRules=%d corpusRuleCount=%d", scope.Check.ScopeCompleteness.OutOfScopeRules, scope.CorpusRuleCount)
	}
	raw, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"assessment": "SAFE"`) {
		t.Fatal("report carried SAFE")
	}
	if !strings.Contains(string(raw), "scopeAssessment") {
		t.Fatal("the aggregate was reported without its evidence")
	}
}

// TestDeclaredScopeWithAnUndeclaredFactStaysUnknown: absence of evidence is
// UNKNOWN. Nothing about a live collection may fill in a fact the operator did
// not declare.
func TestDeclaredScopeWithAnUndeclaredFactStaysUnknown(t *testing.T) {
	body := strings.Replace(lokiScopeInputJSON,
		`{"id": "component.loki.structured_metadata_requires_tsdb_v13", "state": "declared", "boolValue": false}`,
		`{"id": "component.loki.structured_metadata_requires_tsdb_v13", "state": "missing"}`, 1)
	opts := baseTestOptions(t, &fakeRunner{t: t})
	opts.ScopeInput = writeScopeInput(t, body)
	var stdout, stderr bytes.Buffer
	report, code := Run(context.Background(), opts, &stdout, &stderr)
	if code != ExitOK {
		t.Fatalf("Run failed: code=%d stderr=%s", code, stderr.String())
	}
	if report.Aggregate.Assessment != "UNKNOWN" {
		t.Fatalf("aggregate=%q, want UNKNOWN when a required fact was not declared", report.Aggregate.Assessment)
	}
	if report.ScopeAssessment == nil || report.ScopeAssessment.Check.ScopeCompleteness.Resolved {
		t.Fatal("an unresolved scope was reported as resolved")
	}
}

// TestRejectedScopeInputFailsLoudly: a scope declaration that does not match
// its own declared bundle is a caller error, not an evidence gap. It must not
// degrade quietly into an UNKNOWN verdict that looks like honest uncertainty.
func TestRejectedScopeInputFailsLoudly(t *testing.T) {
	for name, body := range map[string]string{
		"no scope declaration": strings.Replace(lokiScopeInputJSON, `"scope": {"declaration": "OPERATOR_DECLARED_COMPLETE_COMPONENT_SET", "components": ["pkg:github/grafana/loki"]},`, "", 1),
		"unknown component":    strings.ReplaceAll(lokiScopeInputJSON, "pkg:github/grafana/loki", "pkg:github/example/absent"),
		"not JSON":             "{",
	} {
		t.Run(name, func(t *testing.T) {
			opts := baseTestOptions(t, &fakeRunner{t: t})
			opts.ScopeInput = writeScopeInput(t, body)
			var stdout, stderr bytes.Buffer
			if _, code := Run(context.Background(), opts, &stdout, &stderr); code != ExitUsage {
				t.Fatalf("code=%d, want ExitUsage; stderr=%s", code, stderr.String())
			}
		})
	}
}

// crossingKubernetesRoute is a synthetic kubernetes check anchored at
// 1.24.0 -> 1.25.0 whose rule carries a removal crossing at C = 1.25.0
// reviewed below 1.36.0, with or without the reviewed range.
func crossingKubernetesRoute(withRange bool) checkroutemetadata.Check {
	route := rangedKubernetesRoute()
	if !withRange {
		route.Range = nil
	}
	route.Crossing = &constraintengine.CrossingSpec{
		Change:  constraintengine.CrossingChange{Version: "1.25.0", Basis: constraintengine.BasisRemovedInRelease, SourceID: "src"},
		Horizon: constraintengine.CrossingHorizon{Lt: "1.36.0", Basis: constraintengine.BasisReviewedThroughMinorLine, SourceID: "src"},
	}
	return route
}

// TestClassifyKubernetesCrossingApplicability: a hop that crosses the
// removal release C is never NOT_APPLICABLE. The reviewer's two probes (a
// crossing-only rule observed at 1.24.17, and a crossing plus range rule
// observed at 1.21.5, both with --to 1.30.2) used to be reported
// NOT_APPLICABLE_VERSION_MISMATCH although the engine blocks the hop.
func TestClassifyKubernetesCrossingApplicability(t *testing.T) {
	cases := []struct {
		name      string
		withRange bool
		observed  string
		to        string
		want      string
		mode      string
		needsTo   bool
	}{
		{"crossing only, probe: 1.24.17 to 1.30.2", false, "1.24.17", "1.30.2", ApplicableNeedsDeclaration, "crossing", false},
		{"crossing and range, probe: 1.21.5 to 1.30.2", true, "1.21.5", "1.30.2", ApplicableNeedsDeclaration, "crossing", false},
		{"crossing and range, 1.24.17 to 1.30.2", true, "1.24.17", "1.30.2", ApplicableNeedsDeclaration, "crossing", false},
		{"crossing only, no target", false, "1.24.17", "", ApplicableNeedsDeclaration, "crossing", true},
		{"crossing and range, far origin, no target", true, "1.21.5", "", ApplicableNeedsDeclaration, "crossing", true},
		{"crossing only, target at C", false, "1.24.17", "1.25.0", ApplicableNeedsDeclaration, "crossing", false},
		{"crossing only, target below C", false, "1.24.17", "1.24.99", NotApplicableVersionMismatch, "crossing", false},
		{"crossing only, downgrade", false, "1.24.17", "1.23.0", NotApplicableVersionMismatch, "crossing", false},
		{"crossing only, target at the cap", false, "1.24.17", "1.36.0", IndeterminateHopOutsideReviewedRange, "crossing", false},
		{"crossing only, target beyond the cap", false, "1.24.17", "1.40.1", IndeterminateHopOutsideReviewedRange, "crossing", false},
		{"crossing only, origin at C", false, "1.25.0", "1.30.2", NotApplicableVersionMismatch, "", false},
		{"crossing only, origin above C", false, "1.28.1", "1.30.2", NotApplicableVersionMismatch, "", false},
		{"crossing and range, in range and target range keeps range", true, "1.24.17", "1.25.9", ApplicableNeedsDeclaration, "range", false},
	}
	for _, tc := range cases {
		route := crossingKubernetesRoute(tc.withRange)
		got := classifyKubernetes(CheckAssessment{Project: route.Project, From: route.From, To: route.To}, route, kubernetesObservedBundle(tc.observed), false, tc.to)
		if got.Applicability != tc.want {
			t.Errorf("%s: applicability=%q, want %q (%s)", tc.name, got.Applicability, tc.want, got.Reason)
		}
		if tc.want != NotApplicableVersionMismatch && got.MatchMode != tc.mode {
			t.Errorf("%s: matchMode=%q, want %q", tc.name, got.MatchMode, tc.mode)
		}
		hasTo := false
		for _, d := range got.MissingDeclarations {
			hasTo = hasTo || d.Flag == "--to"
		}
		if hasTo != tc.needsTo {
			t.Errorf("%s: --to declaration present=%v, want %v", tc.name, hasTo, tc.needsTo)
		}
		if tc.want == ApplicableNeedsDeclaration && tc.mode == "crossing" && tc.to != "" && !strings.Contains(got.Reason, "never passes") {
			t.Errorf("%s: reason lacks the block-only disclosure: %s", tc.name, got.Reason)
		}
	}
	// Without a crossing the same observed version stays NOT_APPLICABLE: the
	// crossing row is what changes the answer.
	plain := crossingKubernetesRoute(false)
	plain.Crossing = nil
	if got := classifyKubernetes(CheckAssessment{}, plain, kubernetesObservedBundle("1.24.17"), false, "1.30.2"); got.Applicability != NotApplicableVersionMismatch {
		t.Errorf("rule without crossing or range: %q", got.Applicability)
	}
}

// BOUNDARY-1: the match mode of an origin below the range is
// boundary-unreviewed while the hop is open or crosses C, and empty when the
// hop provably does not cross C.
func TestClassifyBoundaryOriginMatchMode(t *testing.T) {
	route := rangedKubernetesRoute()
	for _, tc := range []struct{ to, applicability, mode string }{
		{"", ApplicableNeedsDeclaration, "boundary-unreviewed"},
		{"1.25.1", IndeterminateHopOutsideReviewedRange, "boundary-unreviewed"},
		{"1.24.5", NotApplicableVersionMismatch, ""},
	} {
		got := classifyKubernetes(CheckAssessment{}, route, kubernetesObservedBundle("1.23.9"), false, tc.to)
		if got.Applicability != tc.applicability || got.MatchMode != tc.mode {
			t.Errorf("to=%q: %q/%q, want %q/%q", tc.to, got.Applicability, got.MatchMode, tc.applicability, tc.mode)
		}
	}
	// A range that does not pin a release boundary keeps the old exclusion.
	series := rangedKubernetesRoute()
	v := *series.Range
	v.Bounds = append([]constraintengine.RangeBound(nil), v.Bounds...)
	v.Bounds[1].Basis, v.Bounds[2].Basis = constraintengine.BasisUpgradeFromSeries, constraintengine.BasisTargetSeries
	series.Range = &v
	if got := classifyKubernetes(CheckAssessment{}, series, kubernetesObservedBundle("1.23.9"), false, "1.25.1"); got.Applicability != NotApplicableVersionMismatch {
		t.Errorf("range without a release boundary: %q", got.Applicability)
	}
	// The component path takes no --to, so an origin below the range needs
	// the native check's own target.
	component := rangedKubernetesRoute()
	component.Project = "cilium"
	got := classifyOrigin(CheckAssessment{}, component, true, "1.23.9", "", false, "mismatch")
	if got.Applicability != ApplicableNeedsDeclaration || !strings.Contains(got.Reason, "native check") {
		t.Errorf("component origin below range: %q %s", got.Applicability, got.Reason)
	}
}

// BOUNDARY-1 on the shipped pack: a cluster at 1.20.x assessed with --to
// 1.22.x must not report the 13 removals of 1.22 as not applicable.
func TestShippedPackBoundaryOriginIsNotHidden(t *testing.T) {
	discovered, err := checkroutemetadata.Discover("kubernetes", "", "")
	if err != nil {
		t.Fatal(err)
	}
	removals := 0
	for _, route := range discovered.Checks {
		if route.Project != kubernetesProject || route.Range == nil || route.Range.To.Gte != "1.22.0" {
			continue
		}
		removals++
		bundle := kubernetesObservedBundle("1.20.15")
		hop := classify(route, bundle, false, "1.22.3")
		if hop.Applicability != IndeterminateHopOutsideReviewedRange || hop.MatchMode != "boundary-unreviewed" {
			t.Errorf("%s 1.20.15 -> 1.22.3: %q/%q", route.RuleID, hop.Applicability, hop.MatchMode)
		}
		if open := classify(route, bundle, false, ""); open.Applicability != ApplicableNeedsDeclaration {
			t.Errorf("%s 1.20.15, no --to: %q", route.RuleID, open.Applicability)
		}
		if short := classify(route, bundle, false, "1.21.9"); short.Applicability != NotApplicableVersionMismatch {
			t.Errorf("%s 1.20.15 -> 1.21.9: %q", route.RuleID, short.Applicability)
		}
	}
	if removals < 13 {
		t.Fatalf("the shipped pack holds %d removals pinned at 1.22.0, want at least 13", removals)
	}
}
