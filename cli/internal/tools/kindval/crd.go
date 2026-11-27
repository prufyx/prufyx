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
	"path"
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

// missingCRDField names the first field a cited definition lacks, "" when it
// is complete: a name, a group, a kind and at least one version, each named.
func missingCRDField(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	spec, _ := obj["spec"].(map[string]any)
	names, _ := spec["names"].(map[string]any)
	switch {
	case str(meta, "name") == "":
		return "metadata.name"
	case str(spec, "group") == "":
		return "spec.group"
	case str(names, "kind") == "":
		return "spec.names.kind"
	}
	versions, _ := spec["versions"].([]any)
	if len(versions) == 0 {
		return "spec.versions"
	}
	for _, v := range versions {
		if m, _ := v.(map[string]any); str(m, "name") == "" {
			return "spec.versions[].name"
		}
	}
	return ""
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// leftOut lists, as "group/Kind" (the core group is empty), the only objects
// a cited file may hold next to definitions: applying one installs no API, so
// leaving it out changes no answer. Every other object is refused. An
// APIService is not listed: it can move a group to an aggregated server, which
// must not read as a removal.
var leftOut = map[string]bool{
	"/ConfigMap": true, "/Namespace": true, "/Secret": true, "/Service": true, "/ServiceAccount": true,
	"apps/DaemonSet": true, "apps/Deployment": true, "apps/StatefulSet": true,
	"batch/CronJob": true, "batch/Job": true,
	"rbac.authorization.k8s.io/ClusterRole": true, "rbac.authorization.k8s.io/ClusterRoleBinding": true,
	"rbac.authorization.k8s.io/Role": true, "rbac.authorization.k8s.io/RoleBinding": true,
	"admissionregistration.k8s.io/MutatingWebhookConfiguration":     true,
	"admissionregistration.k8s.io/ValidatingWebhookConfiguration":   true,
	"admissionregistration.k8s.io/ValidatingAdmissionPolicy":        true,
	"admissionregistration.k8s.io/ValidatingAdmissionPolicyBinding": true,
	"policy/PodDisruptionBudget":                                    true,
	"networking.k8s.io/NetworkPolicy":                               true,
	"autoscaling/HorizontalPodAutoscaler":                           true,
	"scheduling.k8s.io/PriorityClass":                               true,
}

// Causes of a refusal: one fixed text each.
const (
	causeTypeMeta       = "apiVersion or kind is missing, empty or not a string"
	causeAPIVersion     = "apiVersion is not a version or group/version"
	causeForeignCRD     = "CustomResourceDefinition outside the apiextensions.k8s.io group"
	causeIncompleteCRD  = "CustomResourceDefinition lacks a required field"
	causeKind           = "document is of a kind this check may not leave out"
	causeDuplicate      = "CustomResourceDefinition name is defined more than once, first"
	causeKustomization  = "kustomization is not a plain list of resources"
	causeResource       = "kustomization lists a resource that is not another cited file"
	causeNoDefinition   = "the file holds no CustomResourceDefinition"
	causeEmptyOfRelease = "the release holds no CustomResourceDefinition"
)

// refusal is a cited release this tool will not read in part. Its text holds
// the fixed cause, positions (counted from 1) and the missing field only:
// stored error texts are classified by pattern, so nothing read from a
// document may appear in it. The values are kept beside it.
type refusal struct {
	cause     string
	file, doc int
	field     string
	// firstFile is where a repeated definition name was first seen.
	firstFile                     int
	apiVersion, kind, name, entry string
}

func (r *refusal) Error() string {
	var at []string
	if r.file > 0 {
		at = append(at, fmt.Sprintf("file %d", r.file))
	}
	if r.doc > 0 {
		at = append(at, fmt.Sprintf("document %d", r.doc))
	}
	msg := r.cause
	if r.firstFile > 0 {
		msg += fmt.Sprintf(" in file %d", r.firstFile)
	}
	if r.field != "" {
		msg += ": " + r.field
	}
	if len(at) > 0 {
		msg = strings.Join(at, ", ") + ": " + msg
	}
	return msg
}

// splitDocuments reads every document of a manifest file. Each one is a
// complete CustomResourceDefinition (returned re-encoded, with its
// definition), an object listed in leftOut (counted in skipped), empty, or an
// error: nothing is dropped silently.
func splitDocuments(data []byte) (docs [][]byte, defs []CRDDef, skipped map[string]int, err error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for index := 1; ; index++ {
		var obj map[string]any
		err := dec.Decode(&obj)
		if errors.Is(err, io.EOF) {
			return docs, defs, skipped, nil
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("manifest: %w", err)
		}
		if obj == nil {
			continue
		}
		apiVersion, kind := str(obj, "apiVersion"), str(obj, "kind")
		refuse := func(cause, field string) ([][]byte, []CRDDef, map[string]int, error) {
			return nil, nil, nil, &refusal{cause: cause, doc: index, field: field, apiVersion: apiVersion, kind: kind}
		}
		if apiVersion == "" {
			return refuse(causeTypeMeta, "apiVersion")
		}
		if kind == "" {
			return refuse(causeTypeMeta, "kind")
		}
		group, version, grouped := strings.Cut(apiVersion, "/")
		if !grouped {
			group, version = "", apiVersion
		}
		if (grouped && group == "") || version == "" || strings.Contains(version, "/") {
			return refuse(causeAPIVersion, "")
		}
		if kind != "CustomResourceDefinition" {
			key := group + "/" + kind
			if !leftOut[key] {
				return refuse(causeKind, "")
			}
			if skipped == nil {
				skipped = map[string]int{}
			}
			skipped[key]++
			continue
		}
		if group != "apiextensions.k8s.io" {
			return refuse(causeForeignCRD, "")
		}
		if missing := missingCRDField(obj); missing != "" {
			return refuse(causeIncompleteCRD, missing)
		}
		def, ok := crdFromObject(obj)
		if !ok {
			return refuse(causeIncompleteCRD, "")
		}
		enc, err := yaml.Marshal(obj)
		if err != nil {
			return nil, nil, nil, err
		}
		docs = append(docs, enc)
		defs = append(defs, def)
	}
}

// crdDocuments splits a manifest file into its CustomResourceDefinition
// documents (re-encoded one per document) and their definitions, under the
// rules of splitDocuments, so a file that also holds workloads installs only
// its definitions.
func crdDocuments(data []byte) ([][]byte, []CRDDef, error) {
	docs, defs, _, err := splitDocuments(data)
	return docs, defs, err
}

// kustomizationKey is how an inert kustomization is counted in a file record.
const kustomizationKey = "kustomize.config.k8s.io/Kustomization"

func isKustomizationFile(file string) bool {
	switch path.Base(file) {
	case "kustomization.yaml", "kustomization.yml", "Kustomization":
		return true
	}
	return false
}

// inertKustomization accepts a kustomization that only lists files which are
// themselves cited: one document with apiVersion, kind and a non-empty list of
// local relative resources, and no other key. Anything that could rewrite or
// add objects, and any entry naming a directory, the file itself, a remote
// source or an uncited file, is refused.
func inertKustomization(data []byte, file string, cited []string) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var found []map[string]any
	for {
		var obj map[string]any
		err := dec.Decode(&obj)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return &refusal{cause: causeKustomization}
		}
		if obj != nil {
			found = append(found, obj)
		}
	}
	if len(found) != 1 || len(found[0]) != 3 || found[0]["apiVersion"] != "kustomize.config.k8s.io/v1beta1" || found[0]["kind"] != "Kustomization" {
		return &refusal{cause: causeKustomization}
	}
	entries, ok := found[0]["resources"].([]any)
	if !ok || len(entries) == 0 {
		return &refusal{cause: causeKustomization}
	}
	others := map[string]bool{}
	for _, f := range cited {
		others[f] = f != file
	}
	for _, e := range entries {
		entry, ok := e.(string)
		// The raw text is checked first: path.Join drops a trailing "/" or
		// "/.", which names a directory.
		last := entry[strings.LastIndex(entry, "/")+1:]
		if !ok || last == "" || last == "." || last == ".." || strings.HasPrefix(entry, "/") || remoteResource(entry) || !others[path.Join(path.Dir(file), entry)] {
			return &refusal{cause: causeResource, entry: entry}
		}
	}
	return nil
}

// remoteResource reports a kustomize resource that names another source.
func remoteResource(s string) bool {
	for _, prefix := range []string{"git@", "github.com/", "gitlab.com/", "bitbucket.org/", "@", "oci:", "file:"} {
		if strings.HasPrefix(strings.TrimSpace(s), prefix) {
			return true
		}
	}
	return strings.Contains(s, "://") || strings.Contains(s, "?ref=")
}

// fetchError marks a failure to read a cited file (network, HTTP status): the
// evidence was not reached, which is no statement about the release.
type fetchError struct{ err error }

func (e *fetchError) Error() string { return e.err.Error() }
func (e *fetchError) Unwrap() error { return e.err }

// releaseManifest fetches a release's files and returns the combined CRD
// manifest, the definitions and the per-file record. The release is refused as
// a whole when a file cannot be read completely, a definition name repeats, a
// file other than an inert kustomization holds no definition, or none of the
// files holds one.
func releaseManifest(ctx context.Context, fetch fetcher, repo string, rel CRDRelease) ([]byte, []CRDDef, []FetchedFile, error) {
	var combined bytes.Buffer
	var defs []CRDDef
	var files []FetchedFile
	definedIn := map[string]int{}
	for i, file := range rel.Files {
		refused := func(err error) ([]byte, []CRDDef, []FetchedFile, error) {
			var r *refusal
			if errors.As(err, &r) {
				r.file = i + 1
			}
			return nil, nil, nil, fmt.Errorf("%s@%s: %w", file, rel.Commit, err)
		}
		data, err := fetch(ctx, repo, rel.Commit, file)
		if err != nil {
			return nil, nil, nil, &fetchError{fmt.Errorf("%s@%s: %w", file, rel.Commit, err)}
		}
		sum := sha256.Sum256(data)
		record := FetchedFile{Path: file, SHA256: "sha256:" + hex.EncodeToString(sum[:])}
		if isKustomizationFile(file) {
			// Recorded as cited, never applied.
			if err := inertKustomization(data, file, rel.Files); err != nil {
				return refused(err)
			}
			record.Skipped = map[string]int{kustomizationKey: 1}
			files = append(files, record)
			continue
		}
		docs, fileDefs, skipped, err := splitDocuments(data)
		if err != nil {
			return refused(err)
		}
		for _, d := range fileDefs {
			if first := definedIn[d.Name]; first > 0 {
				return refused(&refusal{cause: causeDuplicate, firstFile: first, name: d.Name})
			}
			definedIn[d.Name] = i + 1
		}
		if len(fileDefs) == 0 {
			return refused(&refusal{cause: causeNoDefinition})
		}
		for _, d := range docs {
			combined.WriteString("---\n")
			combined.Write(d)
		}
		defs = append(defs, fileDefs...)
		record.CRDs, record.Skipped = len(fileDefs), skipped
		files = append(files, record)
	}
	if len(defs) == 0 {
		return nil, nil, nil, &refusal{cause: causeEmptyOfRelease}
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
		state.InstallError = installError(err)
		if ladderClass(state.InstallError, err) {
			state.InstallError.ApplyLadder = runLadder(ctx, k, manifest)
		}
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
// release in place (as an upgrade would) and records the answer, then
// installs To from scratch and probes it: what a release's manifests serve
// is a statement about the manifests alone, and a plain apply neither
// removes a definition To dropped nor succeeds when a stored version goes.
// The pair's CRDs are removed afterwards.
func runPair(ctx context.Context, k kube, fetch fetcher, pair CRDPair) CRDPairResult {
	res, _ := runPairFields(ctx, k, fetch, pair)
	return res
}

// runPairFields is runPair that also runs the pair's crd-field claims: each
// object is sent after From is installed, again after To is applied in place
// (when the apply is accepted) and again after the fresh install of To, whose
// answer decides.
func runPairFields(ctx context.Context, k kube, fetch fetcher, pair CRDPair) (res CRDPairResult, fields []CRDFieldResult) {
	res = CRDPairResult{ID: pair.ID, Project: pair.Project, FromTag: pair.From.Tag, ToTag: pair.To.Tag}
	runs := newFieldRuns(pair)
	defer func() {
		if res.Error != "" {
			failFields(runs, res.Error, nil)
		}
		fields = fieldResults(runs)
	}()
	fromManifest, fromDefs, fromFiles, err := releaseManifest(ctx, fetch, pair.Repo, pair.From)
	if err != nil {
		res.Error = "from: " + err.Error()
		return res, nil
	}
	toManifest, toDefs, toFiles, err := releaseManifest(ctx, fetch, pair.Repo, pair.To)
	if err != nil {
		res.Error = "to: " + err.Error()
		return res, nil
	}
	all := crdNames(append(append([]CRDDef(nil), fromDefs...), toDefs...))
	defer func() {
		if err := k.deleteCRDs(ctx, all); err != nil && res.Error == "" {
			res.Error = "cleanup: " + err.Error()
		}
	}()
	res.From = installRelease(ctx, k, fromManifest, fromDefs, fromFiles, nil)
	if res.From.Error != "" {
		failFields(runs, "from: "+res.From.Error, res.From.InstallError)
		return res, nil
	}
	fieldsAtFrom(ctx, k, runs, res.From.CRDs)
	res.InPlace.Attempted = true
	if err := k.apply(ctx, toManifest); err != nil {
		res.InPlace.Message = firstLine(err.Error())
	} else {
		res.InPlace.Succeeded = true
		fieldsAtTo(ctx, k, runs, false, nil)
	}
	for _, f := range runs {
		f.res.InPlace = "refused"
		if res.InPlace.Succeeded {
			f.res.InPlace = "applied"
		}
	}
	toNames := map[string]bool{}
	for _, d := range toDefs {
		toNames[d.Name] = true
	}
	for _, d := range fromDefs {
		if !toNames[d.Name] {
			res.InPlace.Leftover = append(res.InPlace.Leftover, d.Name)
		}
	}
	sort.Strings(res.InPlace.Leftover)
	if err := k.deleteCRDs(ctx, all); err != nil {
		res.Error = "reinstall: " + err.Error()
		return res, nil
	}
	res.To = installRelease(ctx, k, toManifest, toDefs, toFiles, fromDefs)
	if res.To.Error != "" {
		failFields(runs, "to: "+res.To.Error, res.To.InstallError)
	} else {
		fieldsAtTo(ctx, k, runs, true, res.To.CRDs)
	}
	return res, nil
}

// runSingle installs one release's CRDs on its own, probes them and removes
// them again, so the next release starts from a fresh state. A release whose
// files were fetched but cannot be read or hold no definitions is Unavailable
// (nothing was installed); a failed fetch, install or cleanup is an Error.
func runSingle(ctx context.Context, k kube, fetch fetcher, single CRDSingle) CRDReleaseResult {
	res := CRDReleaseResult{ID: single.ID, Project: single.Project, Tag: single.Release.Tag}
	manifest, defs, files, err := releaseManifest(ctx, fetch, single.Repo, single.Release)
	if err != nil {
		var fe *fetchError
		if errors.As(err, &fe) {
			res.Error = "fetch: " + err.Error()
		} else {
			res.Unavailable = err.Error()
		}
		return res
	}
	if len(defs) == 0 {
		res.Unavailable = "the files cited for the release hold no CustomResourceDefinition"
		return res
	}
	names := crdNames(defs)
	defer func() {
		if err := k.deleteCRDs(ctx, names); err != nil && res.Error == "" {
			res.Error = "cleanup: " + err.Error()
		}
	}()
	res.State = installRelease(ctx, k, manifest, defs, files, nil)
	return res
}
