// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

const strimziFact = "component.strimzi.custom_resource_versions_set"

func crObject(api, kind, name string) string {
	return fmt.Sprintf("apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n  namespace: kafka\n", api, kind, name)
}

func crDocs(docs ...string) []byte { return []byte(strings.Join(docs, "---\n")) }

func crWorkspace(t *testing.T, raw []byte) intake.Workspace {
	t.Helper()
	ws, err := intake.Decode("manifests.yaml", raw)
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

// crFact decodes the single declared fact of a prepared input.
func crFact(t *testing.T, prepared Prepared) inputFact {
	t.Helper()
	var input inputEnvelope
	if err := json.Unmarshal(prepared.CanonicalInputJSON, &input); err != nil {
		t.Fatal(err)
	}
	if len(input.Current.Components) != 1 || len(input.Current.Components[0].Facts) != 0 || len(input.Proposed.Components) != 1 || len(input.Proposed.Components[0].Facts) != 1 {
		t.Fatalf("input shape %s", prepared.CanonicalInputJSON)
	}
	return input.Proposed.Components[0].Facts[0]
}

func prepareCR(t *testing.T, raw []byte, project string, complete bool) CustomResourceScan {
	t.Helper()
	scan, err := PrepareCustomResourceVersions(crWorkspace(t, raw), project, "0.51.0", "1.0.0", complete)
	if err != nil {
		t.Fatal(err)
	}
	return scan
}

var (
	kafkaV1beta2 = crObject("kafka.strimzi.io/v1beta2", "Kafka", "main")
	kafkaV1      = crObject("kafka.strimzi.io/v1", "Kafka", "main")
	topicV1      = crObject("kafka.strimzi.io/v1", "KafkaTopic", "events")
	podSet       = crObject("core.strimzi.io/v1beta2", "StrimziPodSet", "pods")
	deployment   = crObject("apps/v1", "Deployment", "app")
	configMap    = crObject("v1", "ConfigMap", "settings")
	route        = crObject("gateway.networking.k8s.io/v1", "HTTPRoute", "web")
	virtualSvc   = crObject("networking.istio.io/v1", "VirtualService", "web")
	certificate  = crObject("monitoring.coreos.com/v1", "ServiceMonitor", "tls")
)

func TestCustomResourceVersionsComplete(t *testing.T) {
	raw := crDocs(deployment, kafkaV1beta2, topicV1, configMap, route, virtualSvc, podSet, topicV1)
	scan := prepareCR(t, raw, "strimzi", true)
	fact := crFact(t, scan.Prepared)
	want := []string{"core.strimzi.io/v1beta2/StrimziPodSet", "kafka.strimzi.io/v1/KafkaTopic", "kafka.strimzi.io/v1beta2/Kafka"}
	if fact.ID != strimziFact || fact.State != "declared" || fact.SetValue == nil || !fact.SetValue.Complete || !reflect.DeepEqual(fact.SetValue.Members, want) {
		t.Fatalf("fact %+v", fact)
	}
	if scan.Prepared.State != StatePrepared || scan.Prepared.Reason != ReasonCustomResourcesComplete || scan.Fact != strimziFact || len(scan.Unattributed) != 0 {
		t.Fatalf("scan %+v", scan)
	}
	if got := scan.Members["kafka.strimzi.io/v1/KafkaTopic"]; len(got) != 2 || got[0].Document != 2 || got[1].Document != 7 {
		t.Fatalf("topic sources %+v", got)
	}
	if got := scan.Members["kafka.strimzi.io/v1beta2/Kafka"]; len(got) != 1 || got[0].Document != 1 || got[0].Line == 0 {
		t.Fatalf("kafka sources %+v", got)
	}
	if !strings.Contains(string(scan.Prepared.CanonicalInputJSON), `"component":"pkg:github/strimzi/strimzi-kafka-operator","version":"1.0.0"`) {
		t.Fatalf("input %s", scan.Prepared.CanonicalInputJSON)
	}
	// Istio's own objects form Istio's set, never Strimzi's.
	istio := prepareCR(t, raw, "istio", true)
	if f := crFact(t, istio.Prepared); f.ID != "component.istio.custom_resource_versions_set" || !f.SetValue.Complete || !reflect.DeepEqual(f.SetValue.Members, []string{"networking.istio.io/v1/VirtualService"}) {
		t.Fatalf("istio fact %+v", f)
	}
	// A project without objects in the input declares an empty, complete set.
	argo := prepareCR(t, raw, "argo-cd", true)
	if f := crFact(t, argo.Prepared); f.ID != "component.argo_cd.custom_resource_versions_set" || !f.SetValue.Complete || len(f.SetValue.Members) != 0 {
		t.Fatalf("argo fact %+v", f)
	}
}

// Without the scope declaration the members are still declared, so a
// removed version blocks, but the set is never complete.
func TestCustomResourceVersionsIncompleteScope(t *testing.T) {
	scan := prepareCR(t, crDocs(kafkaV1beta2, topicV1), "strimzi", false)
	fact := crFact(t, scan.Prepared)
	if fact.SetValue == nil || fact.SetValue.Complete || len(fact.SetValue.Members) != 2 || scan.Prepared.Reason != ReasonCustomResourcesScopeIncomplete {
		t.Fatalf("fact %+v reason %s", fact, scan.Prepared.Reason)
	}
	clean := prepareCR(t, crDocs(kafkaV1), "strimzi", false)
	if f := crFact(t, clean.Prepared); f.SetValue.Complete {
		t.Fatal("incomplete scope declared complete")
	}
}

// An object of a group the table does not attribute to exactly one project
// joins no set and keeps every set incomplete; a suffix match never
// attributes it.
func TestCustomResourceVersionsUnattributedGroups(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown group":  certificate,
		"strimzi suffix": crObject("access.strimzi.io/v1alpha1", "KafkaAccess", "a"),
		"x-k8s.io":       crObject("cluster.x-k8s.io/v1beta1", "Cluster", "c"),
		"k8s.io alone":   crObject("k8s.io/v1", "Thing", "t"),
	} {
		t.Run(name, func(t *testing.T) {
			for _, project := range CustomResourceProjects() {
				scan := prepareCR(t, crDocs(kafkaV1, doc), project, true)
				fact := crFact(t, scan.Prepared)
				if fact.SetValue == nil || fact.SetValue.Complete || scan.Prepared.Reason != ReasonCustomResourcesUnattributed || len(scan.Unattributed) != 1 || scan.Unattributed[0].Document != 1 {
					t.Fatalf("%s: fact %+v reason %s unattributed %v", project, fact, scan.Prepared.Reason, scan.Unattributed)
				}
				for _, member := range fact.SetValue.Members {
					if !strings.HasPrefix(member, "kafka.strimzi.io/") {
						t.Fatalf("%s: unattributed object became member %s", project, member)
					}
				}
			}
		})
	}
}

func TestCustomResourceVersionsAmbiguousGroup(t *testing.T) {
	projects := customresources.Projects()
	// Istio also lists kafka.strimzi.io: the group is ambiguous.
	for i := range projects {
		if projects[i].Slug == "istio" {
			projects[i].Groups = append(projects[i].Groups, customresources.Group{Name: "kafka.strimzi.io"})
		}
	}
	index := customresources.NewIndex(projects)
	for _, project := range []string{"strimzi", "istio"} {
		scan, err := prepareCustomResourceVersions(index, crWorkspace(t, crDocs(kafkaV1beta2, podSet)), project, "0.51.0", "1.0.0", true)
		if err != nil {
			t.Fatal(err)
		}
		fact := crFact(t, scan.Prepared)
		if fact.SetValue == nil || fact.SetValue.Complete || scan.Prepared.Reason != ReasonCustomResourcesUnattributed || len(scan.Unattributed) != 1 {
			t.Fatalf("%s: fact %+v reason %s", project, fact, scan.Prepared.Reason)
		}
		for _, member := range fact.SetValue.Members {
			if strings.HasPrefix(member, "kafka.strimzi.io/") {
				t.Fatalf("%s: ambiguous group attributed: %s", project, member)
			}
		}
	}
}

// argoproj.io is listed for argo-cd only (the catalog project is the whole
// Argo project): objects of other Argo components join argo-cd's set by
// group. If a second project ever listed the group, it would become
// ambiguous and these objects would join no set (see the table's note).
func TestCustomResourceVersionsSharedArgoGroup(t *testing.T) {
	application := crObject("argoproj.io/v1alpha1", "Application", "app")
	rollout := crObject("argoproj.io/v1alpha1", "Rollout", "web")
	scan := prepareCR(t, crDocs(application, rollout), "argo-cd", true)
	f := crFact(t, scan.Prepared)
	if !f.SetValue.Complete || !reflect.DeepEqual(f.SetValue.Members, []string{"argoproj.io/v1alpha1/Application", "argoproj.io/v1alpha1/Rollout"}) {
		t.Fatalf("argo-cd fact %+v", f)
	}
	if owner, attribution := customresources.DefaultIndex().Owner("argoproj.io"); attribution != customresources.Owned || owner != "argo-cd" {
		t.Fatalf("argoproj.io: %q %v", owner, attribution)
	}
	shared := customresources.Projects()
	shared = append(shared, customresources.Project{Slug: "argo-workflows", FactProject: "argo_workflows", Component: "pkg:github/argoproj/argo-workflows", Groups: []customresources.Group{{Name: "argoproj.io"}}})
	ambiguous, err := prepareCustomResourceVersions(customresources.NewIndex(shared), crWorkspace(t, crDocs(application)), "argo-cd", "2.14.0", "3.0.0", true)
	if err != nil {
		t.Fatal(err)
	}
	if f := crFact(t, ambiguous.Prepared); f.SetValue.Complete || len(f.SetValue.Members) != 0 || len(ambiguous.Unattributed) != 1 {
		t.Fatalf("shared argoproj.io: %+v", f)
	}
}

func TestCustomResourceVersionsPaginatedList(t *testing.T) {
	list := `{"apiVersion":"v1","kind":"List","metadata":{"continue":"next"},"items":[{"apiVersion":"kafka.strimzi.io/v1","kind":"Kafka","metadata":{"name":"a","namespace":"k"}}]}`
	scan := prepareCR(t, []byte(list), "strimzi", true)
	if f := crFact(t, scan.Prepared); f.SetValue == nil || f.SetValue.Complete || scan.Prepared.Reason != ReasonCustomResourcesPaginated || len(f.SetValue.Members) != 1 {
		t.Fatalf("fact %+v reason %s", f, scan.Prepared.Reason)
	}
}

// An apply set that cannot be resolved, with no member among the documents
// that were read, declares no set at all.
func TestCustomResourceVersionsUnresolvedSet(t *testing.T) {
	for name, tc := range map[string]struct {
		raw    []byte
		reason Reason
	}{
		"templated":                {crDocs(kafkaV1beta2, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}\n"), ReasonCustomResourcesRendering},
		"values":                   {crDocs("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n", "replicas: 3\nimage: x\n"), ReasonCustomResourcesUnresolved},
		"bad kind":                 {crDocs("apiVersion: v1\nkind: configMap\nmetadata:\n  name: x\n"), ReasonCustomResourcesUnresolved},
		"empty file":               {[]byte("# nothing\n"), ReasonCustomResourcesUnresolved},
		"items under another kind": {crDocs("apiVersion: kafka.strimzi.io/v1\nkind: Kafkalist\nmetadata:\n  name: l\nitems:\n- apiVersion: kafka.strimzi.io/v1beta2\n  kind: Kafka\n  metadata:\n    name: hidden\n"), ReasonCustomResourcesUnresolved},
		"empty items array":        {crDocs("apiVersion: example.io/v1\nkind: Bag\nmetadata:\n  name: b\nitems: []\n"), ReasonCustomResourcesUnresolved},
	} {
		t.Run(name, func(t *testing.T) {
			scan := prepareCR(t, tc.raw, "strimzi", true)
			fact := crFact(t, scan.Prepared)
			if fact.State != "unsupported" || fact.SetValue != nil || scan.Prepared.State != StateUnknown || scan.Prepared.Reason != tc.reason || len(scan.Members) != 0 {
				t.Fatalf("fact %+v scan %+v", fact, scan.Prepared)
			}
		})
	}
}

// An apply set that cannot be resolved still declares the members of the
// documents that were read, as a set that is never complete: a forbidden
// member present decides, and nothing is taken as absent.
func TestCustomResourceVersionsUnresolvedSetKeepsReadMembers(t *testing.T) {
	templatedScalar := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .Values.name }}'}\n"
	for name, tc := range map[string]struct {
		raw      []byte
		complete bool
		reason   Reason
	}{
		"templated document":     {crDocs(kafkaV1beta2, templatedScalar), true, ReasonCustomResourcesRendering},
		"templated, scope open":  {crDocs(kafkaV1beta2, templatedScalar), false, ReasonCustomResourcesRendering},
		"values document":        {crDocs(kafkaV1beta2, "replicas: 3\nimage: x\n"), true, ReasonCustomResourcesUnresolved},
		"not a Kubernetes kind":  {crDocs(kafkaV1beta2, "apiVersion: v1\nkind: configMap\nmetadata:\n  name: x\n"), true, ReasonCustomResourcesUnresolved},
		"templated and unshaped": {crDocs(kafkaV1beta2, templatedScalar, "replicas: 3\n"), true, ReasonCustomResourcesRendering},
		// An object with items is left out: its own kind is no member and
		// the objects in its items are never read.
		"items under another kind":       {crDocs(kafkaV1beta2, "apiVersion: kafka.strimzi.io/v1\nkind: Kafkalist\nmetadata:\n  name: l\nitems:\n- apiVersion: kafka.strimzi.io/v1\n  kind: Kafka\n  metadata:\n    name: hidden\n"), true, ReasonCustomResourcesUnresolved},
		"empty items under another kind": {crDocs(kafkaV1beta2, "apiVersion: example.io/v1\nkind: Bundle\nmetadata:\n  name: b\nitems: []\n"), true, ReasonCustomResourcesUnresolved},
	} {
		t.Run(name, func(t *testing.T) {
			scan := prepareCR(t, tc.raw, "strimzi", tc.complete)
			fact := crFact(t, scan.Prepared)
			if fact.State != "declared" || fact.SetValue == nil || fact.SetValue.Complete || !reflect.DeepEqual(fact.SetValue.Members, []string{"kafka.strimzi.io/v1beta2/Kafka"}) {
				t.Fatalf("fact %+v", fact)
			}
			if scan.Prepared.State != StateUnknown || scan.Prepared.Reason != tc.reason || len(scan.Members["kafka.strimzi.io/v1beta2/Kafka"]) != 1 {
				t.Fatalf("state %s reason %s members %+v", scan.Prepared.State, scan.Prepared.Reason, scan.Members)
			}
		})
	}
}

func TestCustomResourceVersionsBounds(t *testing.T) {
	// One v1 List holds the objects: a file holds at most 256 documents.
	list := func(n int) []byte {
		var items []string
		for i := 0; i < n; i++ {
			items = append(items, fmt.Sprintf(`{"apiVersion":"kafka.strimzi.io/v%d","kind":"Kafka","metadata":{"name":"k","namespace":"n"}}`, i+1))
		}
		return []byte(`{"apiVersion":"v1","kind":"List","items":[` + strings.Join(items, ",") + `]}`)
	}
	scan := prepareCR(t, list(257), "strimzi", true)
	if f := crFact(t, scan.Prepared); f.State != "unsupported" || scan.Prepared.Reason != ReasonCustomResourcesTooMany {
		t.Fatalf("257 members: %+v %s", f, scan.Prepared.Reason)
	}
	scan = prepareCR(t, list(256), "strimzi", true)
	if f := crFact(t, scan.Prepared); f.State != "declared" || len(f.SetValue.Members) != 256 || !f.SetValue.Complete {
		t.Fatalf("256 members: %+v", f)
	}
	long := crObject("kafka.strimzi.io/v1"+strings.Repeat("a", 120), "Kafka", "k")
	scan = prepareCR(t, crDocs(kafkaV1, long), "strimzi", true)
	if f := crFact(t, scan.Prepared); f.SetValue == nil || f.SetValue.Complete || scan.Prepared.Reason != ReasonCustomResourcesMemberInvalid || !reflect.DeepEqual(f.SetValue.Members, []string{"kafka.strimzi.io/v1/Kafka"}) {
		t.Fatalf("unrepresentable member: %+v %s", f, scan.Prepared.Reason)
	}
}

func TestCustomResourceVersionsArguments(t *testing.T) {
	ws := crWorkspace(t, crDocs(kafkaV1))
	for _, tc := range []struct{ project, from, to string }{
		{"kubernetes", "1.30.0", "1.31.0"}, {"flux", "1.0.0", "1.1.0"}, {"strimzi", "1.0.0", "1.0.0"}, {"strimzi", "x", "1.0.0"},
	} {
		if _, err := PrepareCustomResourceVersions(ws, tc.project, tc.from, tc.to, true); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v accepted", tc)
		}
	}
	if got := CustomResourceProjects(); !reflect.DeepEqual(got, []string{"argo-cd", "cert-manager", "cilium", "crossplane", "istio", "keda", "kuma", "kyverno", "longhorn", "rook", "strimzi", "velero"}) {
		t.Fatalf("projects %v", got)
	}
	if fact, ok := CustomResourceVersionsFact("strimzi"); !ok || fact != strimziFact {
		t.Fatal("strimzi fact")
	}
	if _, ok := CustomResourceVersionsFact("kubernetes"); ok {
		t.Fatal("kubernetes has a custom-resource fact")
	}
	// The byte route reads one file exactly as the workspace route does.
	raw := crDocs(kafkaV1beta2, topicV1)
	prepared, err := PrepareCustomResourceVersionsBytes(raw, "strimzi", "0.51.0", "1.0.0", true)
	if err != nil {
		t.Fatal(err)
	}
	scan := prepareCR(t, raw, "strimzi", true)
	if string(prepared.CanonicalInputJSON) != string(scan.Prepared.CanonicalInputJSON) || prepared.InputDigest != scan.Prepared.InputDigest || prepared.SourceDigest != digestBytes(raw) {
		t.Fatal("byte route differs")
	}
	if _, err := PrepareCustomResourceVersionsBytes(nil, "strimzi", "0.51.0", "1.0.0", true); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty input accepted")
	}
}

// An object of a non-List kind with a top-level items array is left out of
// the documents that were read: beside a forbidden member the set still
// holds that member (and blocks), the object is neither a member nor an
// unattributed document, and an object at a removed version that carries
// items is never a member at all. An unresolved set with no member of the
// project keeps no unattributed documents, so nothing else is reported
// about it.
func TestCustomResourceVersionsUnresolvedSetEdges(t *testing.T) {
	templated := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ .Values.name }}'}\n"
	bundle := "apiVersion: example.io/v1\nkind: Bundle\nmetadata:\n  name: b\nitems: []\n"
	for name, tc := range map[string]struct {
		raw    []byte
		reason Reason
	}{
		"beside a removed member":                {crDocs(kafkaV1beta2, bundle), ReasonCustomResourcesUnresolved},
		"beside a removed member and a template": {crDocs(kafkaV1beta2, templated, bundle), ReasonCustomResourcesRendering},
	} {
		items := prepareCR(t, tc.raw, "strimzi", true)
		fact := crFact(t, items.Prepared)
		if fact.State != "declared" || fact.SetValue == nil || fact.SetValue.Complete || !reflect.DeepEqual(fact.SetValue.Members, []string{"kafka.strimzi.io/v1beta2/Kafka"}) || items.Prepared.Reason != tc.reason || len(items.Unattributed) != 0 {
			t.Fatalf("%s: fact %+v reason %s unattributed %+v", name, fact, items.Prepared.Reason, items.Unattributed)
		}
	}
	witness := prepareCR(t, crDocs("apiVersion: kafka.strimzi.io/v1beta2\nkind: Kafka\nmetadata:\n  name: k\nitems: []\n"), "strimzi", true)
	if fact := crFact(t, witness.Prepared); fact.State != "unsupported" || len(witness.Members) != 0 || witness.Prepared.Reason != ReasonCustomResourcesUnresolved {
		t.Fatalf("items object as witness: fact %+v reason %s", fact, witness.Prepared.Reason)
	}
	unattributed := prepareCR(t, crDocs("apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nmetadata:\n  name: tls\n", templated), "strimzi", true)
	if fact := crFact(t, unattributed.Prepared); fact.State != "unsupported" || len(unattributed.Unattributed) != 0 || unattributed.Prepared.Reason != ReasonCustomResourcesRendering {
		t.Fatalf("unattributed: fact %+v unattributed %+v", fact, unattributed.Unattributed)
	}
}
