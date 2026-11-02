// SPDX-License-Identifier: AGPL-3.0-only

// crdgvk reads multi-document YAML on stdin.
//
//	(no flag)  prints the CRD versions as JSON [{G,V,K,Served,Store}]
//	-strip     prints apiextensions.k8s.io/v1 CRDs with schemas relaxed to "preserve unknown fields",
//	           conversion/subresources/printer columns removed, so any object applies (live probes only)
//	-sample    prints one minimal custom resource per served version of every CRD
//
// Any read, parse or shape failure exits non-zero with a message on stderr and NOTHING on stdout: the caller
// must never see a partial list (a shorter expected set would hide a removed GVK).
//
// run.sh copies this file to cli/cmd/crdgvkqa/main.go inside the scratch checkout and builds it with
// GOFLAGS=-mod=vendor, so it uses the module's vendored gopkg.in/yaml.v3.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type gvk struct {
	G, V, K       string
	Served, Store bool
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "crdgvk: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	strip := flag.Bool("strip", false, "relax CRD schemas")
	sample := flag.Bool("sample", false, "emit sample custom resources")
	flag.Parse()
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail("read stdin: %v", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	out := []gvk{}
	var docs []any
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if err != io.EOF {
				fail("yaml: %v", err)
			}
			break
		}
		if d == nil || d["kind"] != "CustomResourceDefinition" {
			continue
		}
		spec, _ := d["spec"].(map[string]any)
		names, _ := spec["names"].(map[string]any)
		g, _ := spec["group"].(string)
		k, _ := names["kind"].(string)
		vs, _ := spec["versions"].([]any)
		if spec != nil && g == "" && k == "" && len(vs) == 0 && spec["version"] == nil {
			continue // generator placeholder (empty group, kind and versions): it declares no version
		}
		if g == "" || k == "" {
			fail("CustomResourceDefinition without spec.group or spec.names.kind")
		}
		if len(vs) == 0 {
			v, ok := spec["version"].(string)
			if !ok || v == "" {
				fail("CustomResourceDefinition %s/%s has no versions", g, k)
			}
			out = append(out, gvk{g, v, k, true, true})
		}
		for _, x := range vs {
			m, _ := x.(map[string]any)
			n, _ := m["name"].(string)
			if n == "" {
				fail("CustomResourceDefinition %s/%s has a version without a name", g, k)
			}
			s, _ := m["served"].(bool)
			st, _ := m["storage"].(bool)
			out = append(out, gvk{g, n, k, s, st})
			if *sample && s {
				obj := map[string]any{"apiVersion": g + "/" + n, "kind": k,
					"metadata": map[string]any{"name": "qa-probe"}}
				if spec["scope"] != "Cluster" {
					obj["metadata"].(map[string]any)["namespace"] = "default"
				}
				docs = append(docs, obj)
			}
			if *strip {
				m["schema"] = map[string]any{"openAPIV3Schema": map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}}
				delete(m, "subresources")
				delete(m, "additionalPrinterColumns")
				delete(m, "selectableFields")
			}
		}
		if *strip && d["apiVersion"] == "apiextensions.k8s.io/v1" {
			delete(spec, "conversion")
			delete(d, "status")
			if md, ok := d["metadata"].(map[string]any); ok {
				delete(md, "creationTimestamp")
			}
			docs = append(docs, d)
		}
	}
	if *strip || *sample {
		var buf bytes.Buffer
		for _, d := range docs {
			b, err := yaml.Marshal(d)
			if err != nil {
				fail("marshal: %v", err)
			}
			fmt.Fprintf(&buf, "---\n%s", b)
		}
		if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
			fail("write: %v", err)
		}
		return
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(out); err != nil {
		fail("encode: %v", err)
	}
	if _, err := os.Stdout.Write(buf.Bytes()); err != nil {
		fail("write: %v", err)
	}
}
