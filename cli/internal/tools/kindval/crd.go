// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// fetcher reads one repository file at a commit; tests substitute a fake.
type fetcher func(ctx context.Context, repo, commit, path string) ([]byte, error)

// maxManifestBytes bounds one fetched manifest file.
const maxManifestBytes = 64 << 20

// httpFetcher reads raw files from GitHub for "github.com/owner/name"
// repositories, pinned by commit.
func httpFetcher(ctx context.Context, repo, commit, path string) ([]byte, error) {
	const prefix = "github.com/"
	if !strings.HasPrefix(repo, prefix) || strings.Count(repo, "/") != 2 {
		return nil, fmt.Errorf("repository %q is not github.com/owner/name", repo)
	}
	if len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" {
		return nil, fmt.Errorf("commit %q is not a full lowercase hex commit", commit)
	}
	if strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return nil, fmt.Errorf("path %q is not a plain repository path", path)
	}
	url := "https://raw.githubusercontent.com/" + strings.TrimPrefix(repo, prefix) + "/" + commit + "/" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, maxManifestBytes)
	}
	return data, nil
}

// crdFromObject reads the fields this tool compares from a decoded
// CustomResourceDefinition; ok is false for any other object.
func crdFromObject(obj map[string]any) (CRDDef, bool) {
	if str(obj, "kind") != "CustomResourceDefinition" {
		return CRDDef{}, false
	}
	meta, _ := obj["metadata"].(map[string]any)
	spec, _ := obj["spec"].(map[string]any)
	names, _ := spec["names"].(map[string]any)
	def := CRDDef{Name: str(meta, "name"), Group: str(spec, "group"), Kind: str(names, "kind"), Scope: str(spec, "scope")}
	versions, _ := spec["versions"].([]any)
	for _, v := range versions {
		m, _ := v.(map[string]any)
		served, _ := m["served"].(bool)
		storage, _ := m["storage"].(bool)
		def.Versions = append(def.Versions, CRDVersion{Name: str(m, "name"), Served: served, Storage: storage})
	}
	if def.Name == "" || def.Group == "" || def.Kind == "" {
		return CRDDef{}, false
	}
	return def, true
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// crdDocuments splits a manifest file into its CustomResourceDefinition
// documents (re-encoded one per document) and their definitions. Other
// documents are left out, so a file that also holds workloads installs only
// its definitions.
func crdDocuments(data []byte) ([][]byte, []CRDDef, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs [][]byte
	var defs []CRDDef
	for {
		var obj map[string]any
		err := dec.Decode(&obj)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("manifest: %w", err)
		}
		def, ok := crdFromObject(obj)
		if !ok {
			continue
		}
		enc, err := yaml.Marshal(obj)
		if err != nil {
			return nil, nil, err
		}
		docs = append(docs, enc)
		defs = append(defs, def)
	}
	return docs, defs, nil
}

// releaseManifest fetches a release's files and returns the combined CRD
// manifest, the definitions and the per-file record.
func releaseManifest(ctx context.Context, fetch fetcher, repo string, rel CRDRelease) ([]byte, []CRDDef, []FetchedFile, error) {
	var combined bytes.Buffer
	var defs []CRDDef
	var files []FetchedFile
	for _, path := range rel.Files {
		data, err := fetch(ctx, repo, rel.Commit, path)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s@%s: %w", path, rel.Commit, err)
		}
		sum := sha256.Sum256(data)
		docs, fileDefs, err := crdDocuments(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s@%s: %w", path, rel.Commit, err)
		}
		for _, d := range docs {
			combined.WriteString("---\n")
			combined.Write(d)
		}
		defs = append(defs, fileDefs...)
		files = append(files, FetchedFile{Path: path, SHA256: "sha256:" + hex.EncodeToString(sum[:]), CRDs: len(fileDefs)})
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	return combined.Bytes(), defs, files, nil
}

func crdNames(defs []CRDDef) []string {
	names := make([]string, 0, len(defs))
	for _, d := range defs {
		names = append(names, d.Name)
	}
	sort.Strings(names)
	return names
}

// probeObjects asks the server for a dry-run create of a minimal object of
// every declared version of every definition (served or not).
func probeObjects(ctx context.Context, k kube, defs []CRDDef) []ObjectTry {
	var out []ObjectTry
	for _, d := range defs {
		for _, v := range d.Versions {
			var b strings.Builder
			fmt.Fprintf(&b, "apiVersion: %s/%s\nkind: %s\nmetadata:\n  name: kindval-probe\n", d.Group, v.Name, d.Kind)
			if d.Scope != "Cluster" {
				b.WriteString("  namespace: default\n")
			}
			try := k.dryRunCreate(ctx, []byte(b.String()))
			out = append(out, ObjectTry{Member: d.Group + "/" + v.Name + "/" + d.Kind, Outcome: try.Outcome, Message: try.Message})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Member < out[j].Member })
	return out
}

// unionDefs merges the declared versions of two definition lists by CRD
// name, so a release can be probed for the versions another release
// declared (the removed ones answer "not served").
func unionDefs(a, b []CRDDef) []CRDDef {
	byName := map[string]*CRDDef{}
	var order []string
	for _, list := range [][]CRDDef{a, b} {
		for _, d := range list {
			cur, ok := byName[d.Name]
			if !ok {
				copied := d
				copied.Versions = append([]CRDVersion(nil), d.Versions...)
				byName[d.Name] = &copied
				order = append(order, d.Name)
				continue
			}
			for _, v := range d.Versions {
				seen := false
				for _, have := range cur.Versions {
					seen = seen || have.Name == v.Name
				}
				if !seen {
					cur.Versions = append(cur.Versions, v)
				}
			}
		}
	}
	sort.Strings(order)
	out := make([]CRDDef, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// installRelease applies a release's CRDs, waits for them and records what
// the cluster holds and answers. probe lists the definitions whose versions
// are tried (at least the installed ones).
func installRelease(ctx context.Context, k kube, manifest []byte, defs []CRDDef, files []FetchedFile, probe []CRDDef) CRDReleaseState {
	state := CRDReleaseState{Files: files}
	if err := k.apply(ctx, manifest); err != nil {
		state.Error = err.Error()
		return state
	}
	names := crdNames(defs)
	if err := k.waitEstablished(ctx, names); err != nil {
		state.Error = err.Error()
		return state
	}
	got, err := k.getCRDs(ctx, names)
	if err != nil {
		state.Error = err.Error()
		return state
	}
	state.CRDs = got
	state.Objects = probeObjects(ctx, k, unionDefs(got, probe))
	return state
}

// runPair installs the From release's CRDs, probes them, tries the To
// release in place (as an upgrade would), and, when the server refuses the
// in-place change, reinstalls To from scratch so its own state is still
// observed. The pair's CRDs are removed afterwards.
func runPair(ctx context.Context, k kube, fetch fetcher, pair CRDPair) CRDPairResult {
	res := CRDPairResult{ID: pair.ID, Project: pair.Project}
	fromManifest, fromDefs, fromFiles, err := releaseManifest(ctx, fetch, pair.Repo, pair.From)
	if err != nil {
		res.Error = "from: " + err.Error()
		return res
	}
	toManifest, toDefs, toFiles, err := releaseManifest(ctx, fetch, pair.Repo, pair.To)
	if err != nil {
		res.Error = "to: " + err.Error()
		return res
	}
	all := crdNames(append(append([]CRDDef(nil), fromDefs...), toDefs...))
	defer func() {
		if err := k.deleteCRDs(ctx, all); err != nil && res.Error == "" {
			res.Error = "cleanup: " + err.Error()
		}
	}()
	res.From = installRelease(ctx, k, fromManifest, fromDefs, fromFiles, nil)
	if res.From.Error != "" {
		return res
	}
	res.InPlace.Attempted = true
	if err := k.apply(ctx, toManifest); err != nil {
		res.InPlace.Message = firstLine(err.Error())
		if err := k.deleteCRDs(ctx, all); err != nil {
			res.Error = "reinstall: " + err.Error()
			return res
		}
	} else {
		res.InPlace.Succeeded = true
	}
	res.To = installRelease(ctx, k, toManifest, toDefs, toFiles, fromDefs)
	return res
}
