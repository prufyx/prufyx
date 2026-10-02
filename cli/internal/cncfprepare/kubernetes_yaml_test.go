// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"reflect"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

// The quickstart apply set, exactly as the documented file is written. Its
// digests were produced before YAML intake existed; a change to either means
// JSON input no longer reaches the engine unchanged.
const k8sQuickstartJSON = `{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "apiVersion": "batch/v1beta1",
      "kind": "CronJob",
      "metadata": { "name": "nightly-report", "namespace": "default" },
      "spec": {
        "schedule": "0 2 * * *",
        "jobTemplate": {
          "spec": { "template": { "spec": { "containers": [{"name": "report", "image": "example/report:1.0"}], "restartPolicy": "OnFailure" } } }
        }
      }
    }
  ]
}
`

const k8sQuickstartYAML = `# rendered output
apiVersion: batch/v1beta1
kind: CronJob
metadata:
  name: nightly-report
  namespace: default
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: report
              image: example/report:1.0
          restartPolicy: OnFailure
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
  namespace: default
`

func TestKubernetesQuickstartJSONDigestsAreUnchanged(t *testing.T) {
	prepared, err := PrepareKubernetesRemovedAPIs([]byte(k8sQuickstartJSON), "1.24.0", "1.25.0", "official_upstream", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.SourceDigest != "sha256:74b724b3dbe66cdea762575500e4fce48a5469b669668a7108280e026456a355" ||
		prepared.InputDigest != "sha256:619e1cfad17ce822d3ad4d36b1cdc3ef3024e9ec37720096f2af8076b92660b2" {
		t.Fatalf("digests changed: %s %s", prepared.SourceDigest, prepared.InputDigest)
	}
}

func TestKubernetesYAMLMatchesJSONVerdicts(t *testing.T) {
	fromJSON, err := PrepareKubernetesRemovedAPIs([]byte(k8sList(k8sDoc("batch/v1beta1", "CronJob"), k8sDoc("v1", "ConfigMap"))), from125, to125, "official_upstream", true, true)
	if err != nil {
		t.Fatal(err)
	}
	fromYAML, err := PrepareKubernetesRemovedAPIs([]byte(k8sQuickstartYAML), from125, to125, "official_upstream", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if fromJSON.InputDigest != fromYAML.InputDigest || !reflect.DeepEqual(fromJSON.CanonicalInputJSON, fromYAML.CanonicalInputJSON) || fromJSON.State != fromYAML.State || fromJSON.Reason != fromYAML.Reason {
		t.Fatalf("verdicts differ:\n%s\n%s", fromJSON.CanonicalInputJSON, fromYAML.CanonicalInputJSON)
	}
	if fromJSON.SourceDigest == fromYAML.SourceDigest {
		t.Fatal("raw digests must differ for different raw bytes")
	}
	if fromYAML.Reason != ReasonKubernetesRemovedGVKPresent {
		t.Fatalf("reason %s", fromYAML.Reason)
	}
}

func TestKubernetesYAMLShapes(t *testing.T) {
	cronJobList := "apiVersion: batch/v1\nkind: CronJobList\nitems:\n- metadata: {name: a}\n"
	cases := []struct {
		name   string
		raw    string
		reason Reason
		state  State
	}{
		{"multi-document present", "apiVersion: v1\nkind: ConfigMap\n---\napiVersion: batch/v1beta1\nkind: CronJob\n", ReasonKubernetesRemovedGVKPresent, StatePrepared},
		{"typed list is flattened", "apiVersion: batch/v1beta1\nkind: CronJobList\nitems:\n- metadata: {name: a}\n", ReasonKubernetesRemovedGVKPresent, StatePrepared},
		{"typed list served version", cronJobList, ReasonKubernetesRemovedGVKAbsent, StatePrepared},
		{"json null is accepted", `{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"creationTimestamp":null,"name":"a"}}`, ReasonKubernetesRemovedGVKAbsent, StatePrepared},
		{"template in comment is ignored", "# {{ comment }}\napiVersion: batch/v1\nkind: CronJob\n", ReasonKubernetesRemovedGVKAbsent, StatePrepared},
		{"templated scalar", "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: \"${NAME}\"}\n", ReasonKubernetesTemplated, StateUnknown},
		{"raw template file", "{{- if .Values.on }}\napiVersion: batch/v1\nkind: CronJob\n{{- end }}\n", ReasonKubernetesTemplated, StateUnknown},
		{"nested list", "apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: List, items: [{apiVersion: v1, kind: Pod}]}\n", ReasonKubernetesUnresolved, StateUnknown},
		{"values file beside manifest", "apiVersion: batch/v1\nkind: CronJob\n---\nreplicas: 2\n", ReasonKubernetesUnresolved, StateUnknown},
		{"pagination in yaml list", "apiVersion: v1\nkind: List\nmetadata: {continue: abc}\nitems:\n- {apiVersion: v1, kind: Pod}\n", ReasonKubernetesPagination, StateUnknown},
		{"bad list metadata", "apiVersion: v1\nkind: List\nmetadata: {continue: 1}\nitems:\n- {apiVersion: v1, kind: Pod}\n", ReasonKubernetesUnresolved, StateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareKubernetesRemovedAPIs([]byte(tc.raw), from125, to125, "official_upstream", true, true)
			if err != nil {
				t.Fatal(err)
			}
			if prepared.Reason != tc.reason || prepared.State != tc.state {
				t.Fatalf("got %s/%s want %s/%s", prepared.State, prepared.Reason, tc.state, tc.reason)
			}
		})
	}
	for _, bad := range []string{"a: [", "a: &x 1\nb: *x\n", "kind: x\nKind: y\n", "a: 1\na: 2\n"} {
		if _, err := PrepareKubernetesRemovedAPIs([]byte(bad), from125, to125, "official_upstream", true, true); err != ErrInvalid {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

func TestKubernetesFlowControlAcceptsYAML(t *testing.T) {
	prepared, err := PrepareKubernetesFlowControl([]byte("apiVersion: flowcontrol.apiserver.k8s.io/v1beta3\nkind: FlowSchema\n---\napiVersion: v1\nkind: Service\n"), "1.31.0", "1.32.0", "official_upstream", true, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonKubernetesRemovedWitness {
		t.Fatalf("%+v %v", prepared, err)
	}
	prepared, err = PrepareKubernetesFlowControl([]byte("apiVersion: v1\nkind: Service\n---\nx: {{ y }}\n"), "1.31.0", "1.32.0", "official_upstream", true, true)
	if err != nil || prepared.Reason != ReasonKubernetesTemplated {
		t.Fatalf("%+v %v", prepared, err)
	}
}

func TestIntakeBoundsMatchTheJSONDecoder(t *testing.T) {
	if intake.MaxDepth != maxJSONDepth || intake.MaxObjectMembers != maxObjectMembers || intake.MaxArrayItems != maxArrayItems {
		t.Fatal("intake bounds differ from the strict JSON decoder bounds")
	}
}
