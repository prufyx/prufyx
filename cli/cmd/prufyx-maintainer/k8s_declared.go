// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/k8sdeclared"
)

// runK8sDeclared writes, or with --check verifies, the table of Kubernetes
// versions declared by upstream per project release. Without --check it
// reads the public GitHub API (refresh). With --check it never uses the
// network: it validates the committed files' schema and citation
// completeness, re-derives every declared value from the cited verbatim
// lines, matches the reviewed projects list, and requires both files to be
// exactly what the recorded data renders to. It cannot re-read upstream, so
// it does not prove the recorded file digests against upstream bytes.
func runK8sDeclared(args []string) error {
	flags := flag.NewFlagSet("k8s-declared", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	projects := flags.String("projects", "", "reviewed projects, sources and tags (JSON)")
	out := flags.String("out", "", "generated JSON")
	md := flags.String("md", "", "generated Markdown")
	check := flags.Bool("check", false, "verify the committed files offline")
	only := flags.String("only", "", "refresh only these comma-separated projects (scratch outputs)")
	cacheDir := flags.String("cache-dir", "", "refresh: keep or reuse raw API responses here")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *projects == "" || *out == "" || *md == "" {
		return &commandError{code: 2, message: "k8s declared: usage: prufyx-maintainer k8s-declared --projects FILE --out FILE --md FILE [--check]", err: err}
	}
	if *check && (*only != "" || *cacheDir != "") {
		return &commandError{code: 2, message: "k8s declared: --check is offline and takes no refresh options"}
	}
	raw, err := os.ReadFile(*projects)
	if err != nil {
		return &commandError{code: 2, message: "k8s declared: projects file unreadable", err: err}
	}
	in, err := k8sdeclared.DecodeInput(raw)
	if err != nil {
		return &commandError{code: 2, message: "k8s declared: " + err.Error(), err: err}
	}
	if *check {
		curJSON, curMD, err := readOutputPair(*out, *md)
		if err != nil {
			return &commandError{code: 2, message: "k8s declared: committed outputs unreadable", err: err}
		}
		var doc k8sdeclared.Output
		dec := json.NewDecoder(bytes.NewReader(curJSON))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil || dec.More() {
			return &commandError{code: 2, message: "k8s declared: committed JSON is not the schema", err: err}
		}
		if err := k8sdeclared.Verify(doc, &in, raw); err != nil {
			return &commandError{code: 2, message: "k8s declared: " + err.Error(), err: err}
		}
		canon, err := k8sdeclared.Marshal(doc)
		if err != nil || !bytes.Equal(canon, curJSON) || string(curMD) != k8sdeclared.Markdown(doc) {
			return &commandError{code: 2, message: "k8s declared: generated output is stale"}
		}
		return nil
	}
	var sel map[string]bool
	if *only != "" {
		sel = map[string]bool{}
		for _, p := range strings.Split(*only, ",") {
			sel[p] = true
		}
	}
	fetcher := &k8sdeclared.APIFetcher{Token: os.Getenv("GITHUB_TOKEN"), CacheDir: *cacheDir}
	doc, err := k8sdeclared.Build(in, raw, fetcher, sel)
	if err != nil {
		return &commandError{code: 2, message: "k8s declared: refresh rejected", err: err}
	}
	if sel == nil {
		if err := k8sdeclared.Verify(doc, &in, raw); err != nil {
			return &commandError{code: 2, message: "k8s declared: refreshed data fails its own check: " + err.Error(), err: err}
		}
	}
	jsonRaw, err := k8sdeclared.Marshal(doc)
	if err != nil {
		return &commandError{code: 2, message: "k8s declared: cannot encode", err: err}
	}
	if err := writeOutputPair(*out, jsonRaw, *md, []byte(k8sdeclared.Markdown(doc))); err != nil {
		return &commandError{code: 2, message: "k8s declared: cannot commit generated outputs: " + err.Error(), err: err}
	}
	return nil
}
