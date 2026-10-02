// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func summary(w Workspace) []string {
	var out []string
	for _, d := range w.Documents {
		out = append(out, fmt.Sprintf("doc %d/%d %s %s %s/%s", d.Source.Document, d.Source.Item, d.APIVersion, d.Kind, d.Namespace, d.Name))
	}
	for _, o := range w.Omissions {
		out = append(out, fmt.Sprintf("omit %d/%d %s", o.Source.Document, o.Source.Item, o.Reason))
	}
	return out
}

func TestDecodeShapes(t *testing.T) {
	cases := map[string]struct {
		in   string
		want []string
	}{
		"single":                    {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a, namespace: n}\n", []string{"doc 0/-1 v1 ConfigMap n/a"}},
		"separators and empties":    {"---\n---\napiVersion: v1\nkind: Pod\n---\n# nothing\n---\napiVersion: v1\nkind: Service\n", []string{"doc 0/-1 v1 Pod /", "doc 1/-1 v1 Service /"}},
		"v1 list":                   {"apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: Pod}\n- {apiVersion: apps/v1, kind: Deployment}\n", []string{"doc 0/0 v1 Pod /", "doc 0/1 apps/v1 Deployment /"}},
		"typed list infers items":   {"apiVersion: apps/v1\nkind: DeploymentList\nitems:\n- metadata: {name: web}\n", []string{"doc 0/0 apps/v1 Deployment /web"}},
		"typed list explicit items": {"apiVersion: apps/v1\nkind: DeploymentList\nitems:\n- {apiVersion: apps/v1, kind: Deployment}\n", []string{"doc 0/0 apps/v1 Deployment /"}},
		"nested list":               {"apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: Pod}\n- {apiVersion: v1, kind: List, items: [{apiVersion: v1, kind: Pod}]}\n", []string{"doc 0/0 v1 Pod /", "omit 0/1 NESTED_LIST"}},
		"core list not v1":          {"apiVersion: v2\nkind: List\nitems: [{apiVersion: v1, kind: Pod}]\n", []string{"omit 0/-1 LIST_SHAPE_UNRESOLVED"}},
		"empty list":                {"apiVersion: v1\nkind: List\nitems: []\n", []string{"omit 0/-1 LIST_SHAPE_UNRESOLVED"}},
		"values file":               {"replicas: 2\nimage: {tag: x}\n", []string{"omit 0/-1 NOT_KUBERNETES_SHAPED"}},
		"scalar document":           {"hello\n", []string{"omit 0/-1 NOT_KUBERNETES_SHAPED"}},
		"list item missing":         {"apiVersion: v1\nkind: List\nitems:\n- {name: x}\n", []string{"omit 0/0 NOT_KUBERNETES_SHAPED"}},
		"json":                      {`{"apiVersion":"v1","kind":"Pod","metadata":{"creationTimestamp":null,"name":"p"}}`, []string{"doc 0/-1 v1 Pod /p"}},
		"timestamp":                 {"apiVersion: v1\nkind: Pod\nmetadata:\n  annotations: {when: 2026-01-02}\n", []string{"doc 0/-1 v1 Pod /"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w, err := Decode("x.yaml", []byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if got := summary(w); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestDecodeProvenance(t *testing.T) {
	w, err := Decode("rendered/a.yaml", []byte("apiVersion: v1\nkind: Pod\n---\napiVersion: v1\nkind: List\nitems: [{apiVersion: v1, kind: Pod}]\n"))
	if err != nil || len(w.Documents) != 2 {
		t.Fatal(w, err)
	}
	if w.Documents[0].Source.Display != "rendered/a.yaml" || !strings.HasPrefix(w.Documents[0].Source.Digest, "sha256:") || len(w.Documents[0].Source.Digest) != 71 {
		t.Fatalf("source %+v", w.Documents[0].Source)
	}
	if w.Documents[0].Source.Digest != w.Documents[1].Source.Digest || w.Documents[1].Source.Document != 1 || w.Documents[1].Source.Item != 0 {
		t.Fatalf("sources %+v %+v", w.Documents[0].Source, w.Documents[1].Source)
	}
}

func TestDecodeRemovesSecretPayloads(t *testing.T) {
	const payload = "s3cr3t-payload-Zm9v"
	in := `apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Secret
  metadata:
    name: a
    annotations:
      kubectl.kubernetes.io/last-applied-configuration: '{"data":{"k":"` + payload + `"}}'
  data: {k: ` + payload + `}
  stringData: {k: ` + payload + `}
---
apiVersion: v1
kind: SecretList
items:
- metadata: {name: b}
  data: {k: ` + payload + `}
---
apiVersion: v1
kind: Secret
metadata: {name: c}
stringData: {k: ` + payload + `}
`
	w, err := Decode("s.yaml", []byte(in))
	if err != nil || len(w.Documents) != 3 {
		t.Fatal(w, err)
	}
	if dump := fmt.Sprintf("%#v|%+v", w.Documents, w.Omissions); strings.Contains(dump, payload) {
		t.Fatalf("payload retained: %s", dump)
	}
	for _, d := range w.Documents {
		if d.Kind != "Secret" || d.Name == "" {
			t.Fatalf("metadata lost: %+v", d)
		}
		if _, found := d.Value["data"]; found {
			t.Fatal("data kept")
		}
		if _, found := d.Value["stringData"]; found {
			t.Fatal("stringData kept")
		}
	}
}

func TestDecodeSecretPayloadNotRetainedInTemplatedOrNestedOmissions(t *testing.T) {
	in := "apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: List\n  items:\n  - {apiVersion: v1, kind: Secret, data: {k: PAYLOADX}}\n"
	w, err := Decode("s.yaml", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%#v%+v", w.Documents, w.Omissions), "PAYLOADX") {
		t.Fatal("payload retained")
	}
}

func TestDecodeTemplating(t *testing.T) {
	cases := map[string][]string{
		"apiVersion: v1\nkind: Pod\nmetadata: {name: \"{{ .Values.name }}\"}\n":                     {"omit 0/-1 TEMPLATED"},
		"apiVersion: v1\nkind: Pod\nmetadata: {name: ok}\nspec: {image: \"${IMAGE}\"}\n":            {"omit 0/-1 TEMPLATED"},
		"apiVersion: v1\nkind: Pod\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: '{{ x }}'\n": {"doc 0/-1 v1 Pod /", "omit 1/-1 TEMPLATED"},
		"apiVersion: v1\nkind: Pod\n# {{ only a comment }}\n":                                       {"doc 0/-1 v1 Pod /"},
		"apiVersion: v1\nkind: Pod\nreplicas: {{ .Values.replicas }}\n":                             {"omit 0/-1 UNPARSEABLE"},
		"{{- if .Values.x }}\napiVersion: v1\nkind: Pod\n{{- end }}\n":                              {"omit 0/-1 UNPARSEABLE"},
	}
	for in, want := range cases {
		w, err := Decode("t.yaml", []byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := summary(w); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	for _, in := range []string{"a: [", "", "a: &x 1\nb: *x\n", "kind: Pod\nKind: Pod\n"} {
		if _, err := Decode("t.yaml", []byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestDecodeBounds(t *testing.T) {
	var deep strings.Builder
	for i := 0; i < MaxDepth+2; i++ {
		deep.WriteString(strings.Repeat(" ", i) + "a:\n")
	}
	docs := strings.Repeat("apiVersion: v1\nkind: Pod\n---\n", MaxDocuments+1)
	for name, in := range map[string]string{"depth": deep.String(), "documents": docs, "members": "a: [" + strings.Repeat("1,", MaxArrayItems+1) + "1]"} {
		if _, err := Decode("t.yaml", []byte(in)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDecodeDeterministic(t *testing.T) {
	in := []byte("apiVersion: v1\nkind: List\nitems:\n- {apiVersion: v1, kind: Pod, metadata: {name: a}}\n- {apiVersion: v1, kind: Pod, metadata: {name: b}}\n")
	a, _ := Decode("x", in)
	b, _ := Decode("x", in)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("not deterministic")
	}
}
