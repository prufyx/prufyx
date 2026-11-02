// SPDX-License-Identifier: AGPL-3.0-only

// crdgvk reads multi-document YAML on stdin.
//
//	(no flag)  prints the CRD versions as JSON [{G,V,K,Served,Store}]
//	-strip     prints apiextensions.k8s.io/v1 CRDs with schemas relaxed to "preserve unknown fields",
//	           conversion/subresources/printer columns removed, so any object applies (live probes only)
//	-sample    prints one minimal custom resource per served version of every CRD
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

func main() {
	strip := flag.Bool("strip", false, "relax CRD schemas")
	sample := flag.Bool("sample", false, "emit sample custom resources")
	flag.Parse()
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	out := []gvk{}
	var docs []any
	for {
		var d map[string]any
		if err := dec.Decode(&d); err != nil {
			if err != io.EOF {
				fmt.Fprintln(os.Stderr, "yaml:", err)
				os.Exit(1)
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
		if g == "" || k == "" {
			fmt.Fprintln(os.Stderr, "CRD group or kind missing")
			os.Exit(1)
		}
		vs, _ := spec["versions"].([]any)
		if len(vs) == 0 && spec["version"] == nil {
			fmt.Fprintln(os.Stderr, "CRD versions missing")
			os.Exit(1)
		}
		if len(vs) == 0 {
			if v, ok := spec["version"].(string); ok {
				out = append(out, gvk{g, v, k, true, true})
			}
		}
		for _, x := range vs {
			m, _ := x.(map[string]any)
			n, _ := m["name"].(string)
			s, validServed := m["served"].(bool)
			if n == "" || !validServed {
				fmt.Fprintln(os.Stderr, "CRD version name or served flag invalid")
				os.Exit(1)
			}
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
		for _, d := range docs {
			b, _ := yaml.Marshal(d)
			fmt.Printf("---\n%s", b)
		}
		return
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
