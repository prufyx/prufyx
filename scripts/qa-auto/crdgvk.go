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
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/k8sremovals"
)

type gvk struct {
	G, V, K       string
	Served, Store bool
}

const kubernetesComponent = "pkg:github/kubernetes/kubernetes"

// removalFactMap maps every Kubernetes fact to its removed GVKs. A registry fact of the Kubernetes component
// that is not a removed-GVK presence fact gets an explicit empty list (it has no removal members). A
// removed-GVK presence fact appears only with members; one without members, and any fact the registry does
// not define, stays absent, so the caller cannot tell it from an unknown fact and must treat it as unknown.
func removalFactMap(defs []constraintengine.FactDefinition) map[string][]string {
	facts := map[string][]string{}
	for _, removals := range k8sremovals.ByTargetMinor() {
		for _, removal := range removals {
			for _, kind := range removal.Kinds {
				facts[removal.Fact] = append(facts[removal.Fact], removal.Group+"/"+removal.Removed+"/"+kind)
			}
		}
	}
	for _, removal := range k8sremovals.RemovedVersions() {
		if removal.Line == "1.32" {
			for _, kind := range removal.Kinds {
				facts[cncfprepare.KubernetesFlowControlFact] = append(facts[cncfprepare.KubernetesFlowControlFact], removal.Group+"/"+removal.Version+"/"+kind)
			}
		}
	}
	for _, def := range defs {
		if def.Component != kubernetesComponent || strings.HasSuffix(def.ID, "_removed_gvk_present") {
			continue
		}
		if _, ok := facts[def.ID]; !ok {
			facts[def.ID] = []string{}
		}
	}
	return facts
}

func main() {
	strip := flag.Bool("strip", false, "relax CRD schemas")
	sample := flag.Bool("sample", false, "emit sample custom resources")
	removalFacts := flag.Bool("removal-facts", false, "emit Kubernetes removal fact GVKs")
	flag.Parse()
	if *removalFacts {
		facts := removalFactMap(cncfcheck.CompiledFactDefinitions())
		if err := json.NewEncoder(os.Stdout).Encode(facts); err != nil {
			os.Exit(1)
		}
		return
	}
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	out := []gvk{}
	var docs []any
	// As the extractor: one definition per metadata.name and per group and kind, whatever versions each copy lists.
	seenName, seenKind := map[string]bool{}, map[string]bool{}
	for {
		var document any
		if err := dec.Decode(&document); err != nil {
			if err != io.EOF {
				fmt.Fprintln(os.Stderr, "yaml:", err)
				os.Exit(1)
			}
			break
		}
		if document == nil {
			continue
		}
		d, isMapping := document.(map[string]any)
		if !isMapping {
			fmt.Fprintln(os.Stderr, "a document is not a mapping")
			os.Exit(1)
		}
		apiVersion, _ := d["apiVersion"].(string)
		kind, _ := d["kind"].(string)
		// As the extractor: list items are not read, so a list could hide a definition.
		if strings.HasSuffix(kind, "List") {
			fmt.Fprintln(os.Stderr, "a List document: list items are not read")
			os.Exit(1)
		}
		if kind != "CustomResourceDefinition" {
			if strings.HasPrefix(apiVersion, "apiextensions.k8s.io/") {
				fmt.Fprintln(os.Stderr, "an apiextensions.k8s.io document that is not a CustomResourceDefinition")
				os.Exit(1)
			}
			continue
		}
		// As the extractor (parse.go): apiextensions.k8s.io/v1, or a complete v1beta1 definition; nothing else is read.
		if apiVersion != "apiextensions.k8s.io/v1" && apiVersion != "apiextensions.k8s.io/v1beta1" {
			fmt.Fprintln(os.Stderr, "CRD apiVersion is not read")
			os.Exit(1)
		}
		spec, _ := d["spec"].(map[string]any)
		names, _ := spec["names"].(map[string]any)
		g, _ := spec["group"].(string)
		k, _ := names["kind"].(string)
		if g == "" || k == "" {
			fmt.Fprintln(os.Stderr, "CRD group or kind missing")
			os.Exit(1)
		}
		metadata, _ := d["metadata"].(map[string]any)
		name, _ := metadata["name"].(string)
		if seenKind[g+"/"+k] || (name != "" && seenName[name]) {
			fmt.Fprintf(os.Stderr, "CustomResourceDefinition %q of kind %q is defined more than once\n", name, g+"/"+k)
			os.Exit(1)
		}
		seenKind[g+"/"+k], seenName[name] = true, true
		seenVersion := map[string]bool{}
		// The spec.version-only form states no served line: it is not read.
		vs, _ := spec["versions"].([]any)
		if len(vs) == 0 {
			fmt.Fprintln(os.Stderr, "CRD has no spec.versions list")
			os.Exit(1)
		}
		if single, present := spec["version"]; present && apiVersion == "apiextensions.k8s.io/v1beta1" {
			first, _ := vs[0].(map[string]any)
			firstName, _ := first["name"].(string)
			if v, _ := single.(string); v == "" || v != firstName {
				fmt.Fprintln(os.Stderr, "CRD spec.version is not the name of the first spec.versions entry")
				os.Exit(1)
			}
		}
		for _, x := range vs {
			m, _ := x.(map[string]any)
			n, _ := m["name"].(string)
			s, validServed := m["served"].(bool)
			st, validStorage := m["storage"].(bool)
			if n == "" || !validServed || !validStorage {
				fmt.Fprintln(os.Stderr, "CRD version name, served or storage flag invalid")
				os.Exit(1)
			}
			if seenVersion[n] {
				fmt.Fprintln(os.Stderr, "CRD version listed more than once")
				os.Exit(1)
			}
			seenVersion[n] = true
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
	var output bytes.Buffer
	if *strip || *sample {
		for _, d := range docs {
			b, err := yaml.Marshal(d)
			if err != nil {
				fmt.Fprintln(os.Stderr, "marshal:", err)
				os.Exit(1)
			}
			fmt.Fprintf(&output, "---\n%s", b)
		}
	} else if err := json.NewEncoder(&output).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(output.Bytes()); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
}
