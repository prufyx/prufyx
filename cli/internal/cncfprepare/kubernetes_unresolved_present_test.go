// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

// Documents beside the readable ones that cannot be read or placed: a
// templated document, a values file, an object whose kind is not a
// Kubernetes kind and a list with invalid metadata.
const (
	unreadableTemplated = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .Release.Name }}'}\n"
	unreadableValues    = "replicas: 2\n"
	unreadableKind      = "apiVersion: v1\nkind: configMap\nmetadata: {name: x}\n"
	cronjobRemoved      = "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: nightly}\n"
)

func yamlDocs(docs ...string) []byte { return []byte(strings.Join(docs, "---\n")) }

// A readable document at a removed version is present whatever else the set
// holds: its fact is declared true. Every other fact stays unsupported, and
// the set keeps the reason it is unresolved.
func TestK8sRemovedAPIsUnresolvedSetKeepsPresentFact(t *testing.T) {
	for name, tc := range map[string]struct {
		raw    []byte
		reason Reason
	}{
		"templated document":       {yamlDocs(cronjobRemoved, unreadableTemplated), ReasonKubernetesTemplated},
		"values file":              {yamlDocs(unreadableValues, cronjobRemoved), ReasonKubernetesUnresolved},
		"not a Kubernetes kind":    {yamlDocs(cronjobRemoved, unreadableKind), ReasonKubernetesUnresolved},
		"templated and values":     {yamlDocs(unreadableValues, cronjobRemoved, unreadableTemplated), ReasonKubernetesTemplated},
		"list with bad metadata":   {yamlDocs(cronjobRemoved, "apiVersion: v1\nkind: List\nmetadata: {continue: 1}\nitems:\n- {apiVersion: v1, kind: Service, metadata: {name: s}}\n"), ReasonKubernetesUnresolved},
		"removed version in items": {yamlDocs(unreadableTemplated, "apiVersion: v1\nkind: List\nitems:\n- {apiVersion: batch/v1beta1, kind: CronJob, metadata: {name: n}}\n"), ReasonKubernetesTemplated},
	} {
		t.Run(name, func(t *testing.T) {
			prepared := prepareK8s(t, tc.raw, from125, to125, true)
			if prepared.State != StateUnknown || prepared.Reason != tc.reason {
				t.Fatalf("state %s reason %s", prepared.State, prepared.Reason)
			}
			facts := k8sProposedFacts(t, prepared)
			wantBool(t, facts, factCronJob, true)
			for _, id := range []string{factEndpoint, factEvent, factHPA125, factPDB, factPSP, factRuntime} {
				wantUnsupported(t, facts, id)
			}
		})
	}
}

// The unresolved set never declares a fact false, and declares nothing true
// unless a readable document proves it: with the removed version only in
// the unreadable document, under an open scope, in a paginated list, beside
// an unreviewed version of the same kind, or behind the target guard, every
// fact stays unsupported.
func TestK8sRemovedAPIsUnresolvedSetNeverDeclaresWithoutReadableWitness(t *testing.T) {
	type declaration struct {
		distribution    string
		apply, complete bool
	}
	full := declaration{"official_upstream", true, true}
	for name, tc := range map[string]struct {
		raw []byte
		declaration
	}{
		"removed version only in the template": {yamlDocs("apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: a}\n", "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: '{{ x }}'}\n"), full},
		"migrated documents beside a template": {yamlDocs("apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: a}\n", unreadableTemplated), full},
		"scope not declared complete":          {yamlDocs(cronjobRemoved, unreadableTemplated), declaration{"official_upstream", true, false}},
		"apply not declared":                   {yamlDocs(cronjobRemoved, unreadableTemplated), declaration{"official_upstream", false, true}},
		"custom distribution":                  {yamlDocs(cronjobRemoved, unreadableTemplated), declaration{"custom_build", true, true}},
		"paginated list":                       {yamlDocs(unreadableTemplated, "apiVersion: v1\nkind: List\nmetadata: {continue: next}\nitems:\n- {apiVersion: batch/v1beta1, kind: CronJob, metadata: {name: n}}\n"), full},
		"unreviewed version of the same kind":  {yamlDocs(cronjobRemoved, "apiVersion: batch/v2alpha1\nkind: CronJob\nmetadata: {name: b}\n", unreadableTemplated), full},
		"removed version in a bad list":        {yamlDocs(unreadableValues, "apiVersion: v1\nkind: List\nmetadata: {continue: 1}\nitems:\n- {apiVersion: batch/v1beta1, kind: CronJob, metadata: {name: n}}\n"), full},
	} {
		t.Run(name, func(t *testing.T) {
			prepared, err := PrepareKubernetesRemovedAPIs(tc.raw, from125, to125, tc.distribution, tc.apply, tc.complete)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.State != StateUnknown {
				t.Fatalf("state %s reason %s", prepared.State, prepared.Reason)
			}
			for id, fact := range k8sProposedFacts(t, prepared) {
				if fact.State != "unsupported" {
					t.Fatalf("fact %s = %+v, want unsupported", id, fact)
				}
			}
		})
	}
}

// The documents route and the byte route agree, and the documents route
// names the readable document that made the fact true.
func TestK8sScanUnresolvedSetNamesReadableWitness(t *testing.T) {
	raw := yamlDocs(cronjobRemoved, unreadableTemplated)
	workspace := crWorkspace(t, raw)
	scan, err := PrepareKubernetesScan(workspace, from125, to125, "official_upstream", true, true)
	if err != nil {
		t.Fatal(err)
	}
	bytes := prepareK8s(t, raw, from125, to125, true)
	if string(scan.Prepared.CanonicalInputJSON) != string(bytes.CanonicalInputJSON) || scan.Prepared.State != bytes.State || scan.Prepared.Reason != bytes.Reason {
		t.Fatalf("routes differ:\n%s\n%s", scan.Prepared.CanonicalInputJSON, bytes.CanonicalInputJSON)
	}
	sources := scan.Sources[factCronJob]
	if len(sources) != 1 || sources[0].Document != 0 || len(scan.Sources) != 1 {
		t.Fatalf("sources %+v", scan.Sources)
	}
}

// The flow-control route follows the same rule for its one fact.
func TestPrepareKubernetesFlowControlUnresolvedSetKeepsPresentFact(t *testing.T) {
	removed := "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: a}\n"
	served := "apiVersion: flowcontrol.apiserver.k8s.io/v1\nkind: FlowSchema\nmetadata: {name: b}\n"
	unreviewed := "apiVersion: flowcontrol.apiserver.k8s.io/v9\nkind: FlowSchema\nmetadata: {name: c}\n"
	for name, tc := range map[string]struct {
		raw      []byte
		complete bool
		reason   Reason
		present  bool
	}{
		"removed beside a template":       {yamlDocs(removed, unreadableTemplated), true, ReasonKubernetesTemplated, true},
		"removed beside a values file":    {yamlDocs(removed, unreadableValues), true, ReasonKubernetesUnresolved, true},
		"served beside a template":        {yamlDocs(served, unreadableTemplated), true, ReasonKubernetesTemplated, false},
		"removed, scope open":             {yamlDocs(removed, unreadableTemplated), false, ReasonKubernetesTemplated, false},
		"removed beside unreviewed":       {yamlDocs(removed, unreviewed, unreadableTemplated), true, ReasonKubernetesTemplated, false},
		"removed only in the template":    {yamlDocs(served, "apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\nmetadata: {name: '{{ x }}'}\n"), true, ReasonKubernetesTemplated, false},
		"removed in a paginated list too": {yamlDocs(unreadableTemplated, "apiVersion: v1\nkind: List\nmetadata: {continue: next}\nitems:\n- {apiVersion: flowcontrol.apiserver.k8s.io/v1beta3, kind: FlowSchema, metadata: {name: n}}\n"), true, ReasonKubernetesTemplated, false},
	} {
		t.Run(name, func(t *testing.T) {
			prepared, err := PrepareKubernetesFlowControl(tc.raw, "1.31.0", "1.32.0", "official_upstream", true, tc.complete)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != tc.reason {
				t.Fatalf("prepared %+v err %v", prepared, err)
			}
			fact := k8sProposedFacts(t, prepared)[KubernetesFlowControlFact]
			switch {
			case tc.present && (fact.State != "declared" || fact.BoolValue == nil || !*fact.BoolValue):
				t.Fatalf("fact %+v, want declared true", fact)
			case !tc.present && fact.State != "unsupported":
				t.Fatalf("fact %+v, want unsupported", fact)
			}
		})
	}
}
