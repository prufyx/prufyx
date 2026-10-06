// SPDX-License-Identifier: AGPL-3.0-only

package servedapis

import (
	"strings"
	"testing"
	"time"
)

const evidence = `{"basis":"reviewed","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[{"id":"s","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":40,"endLine":49}]}`

func doc(line, apis string) string {
	return `{"component":"` + KubernetesComponent + `","line":"` + line + `","completeness":"` + Completeness + `","apis":` + apis + `,"evidence":` + evidence + `}`
}

func TestParseAcceptsAndIndexes(t *testing.T) {
	records, err := Parse([]byte("[" + doc("1.28", `["apps/v1 Deployment","v1 ConfigMap"]`) + "," + doc("1.29", `["apps/v1 Deployment","v1 ConfigMap"]`) + "]"))
	if err != nil {
		t.Fatal(err)
	}
	ix := NewIndex(records)
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	if status, ok := ix.For(KubernetesComponent, "1.29", at("2026-10-04T00:00:00Z")); !ok || !status.Current() {
		t.Fatalf("%+v %v", status, ok)
	}
	if status, _ := ix.For(KubernetesComponent, "1.29", at("2026-12-20T00:00:00Z")); status.Current() {
		t.Fatal("a record is stale at validUntil")
	}
	if status, _ := ix.For(KubernetesComponent, "1.29", at("2026-09-01T00:00:00Z")); status.Current() {
		t.Fatal("a record is not usable before reviewedAt")
	}
	if _, ok := ix.For(KubernetesComponent, "1.30", at("2026-10-04T00:00:00Z")); ok {
		t.Fatal("no record for 1.30")
	}
	if _, err := Marshal(records); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejects(t *testing.T) {
	good := doc("1.29", `["v1 ConfigMap"]`)
	cases := map[string]string{
		"empty document":      `[]`,
		"not an array":        good,
		"unknown member":      strings.Replace(good, `"apis"`, `"extra":1,"apis"`, 1),
		"repeated member":     strings.Replace(good, `"apis"`, `"line":"1.30","apis"`, 1),
		"case-folded member":  strings.Replace(good, `"apis"`, `"Apis":[],"apis"`, 1),
		"null member":         strings.Replace(good, `"apis":["v1 ConfigMap"]`, `"apis":null`, 1),
		"missing member":      strings.Replace(good, `"completeness":"`+Completeness+`",`, ``, 1),
		"wrong completeness":  strings.Replace(good, Completeness, "COMPLETE", 1),
		"other component":     strings.Replace(good, KubernetesComponent, "pkg:github/etcd-io/etcd", 1),
		"bad line":            strings.Replace(good, `"1.29"`, `"1.029"`, 1),
		"no apis":             doc("1.29", `[]`),
		"unsorted apis":       doc("1.29", `["v1 Secret","v1 ConfigMap"]`),
		"duplicate apis":      doc("1.29", `["v1 ConfigMap","v1 ConfigMap"]`),
		"version only":        doc("1.29", `["v1"]`),
		"lowercase kind":      doc("1.29", `["v1 configmap"]`),
		"two spaces":          doc("1.29", `["v1  ConfigMap"]`),
		"window over 90 days": strings.Replace(good, "2026-12-20", "2027-03-01", 1),
		"unknown basis":       strings.Replace(good, `"reviewed"`, `"trusted"`, 1),
	}
	for name, raw := range cases {
		if name != "not an array" {
			raw = "[" + raw + "]"
		}
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte("[" + doc("1.30", `["v1 ConfigMap"]`) + "," + doc("1.29", `["v1 ConfigMap"]`) + "]")); err == nil {
		t.Error("records out of order accepted")
	}
	if _, err := Parse([]byte("[" + good + "," + good + "]")); err == nil {
		t.Error("two records for one scope accepted")
	}
	if _, err := Parse([]byte("[" + good + "]x")); err == nil {
		t.Error("trailing data accepted")
	}
}
