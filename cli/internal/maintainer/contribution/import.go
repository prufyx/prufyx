// SPDX-License-Identifier: AGPL-3.0-only

package contribution

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxMetadataBytes = 16 << 20

type ImportOptions struct {
	CorpusRoot, CollectionIndex, ExpectedIndexDigest, Output string
	Check                                                    bool
}

func ImportSelectedSourceRecords(o ImportOptions) error {
	indexRaw, e := safeRead(o.CollectionIndex, maxMetadataBytes)
	if e != nil || !shaRE.MatchString(o.ExpectedIndexDigest) || digest(indexRaw) != o.ExpectedIndexDigest {
		return ErrRejected
	}
	v, e := decode(indexRaw, maxMetadataBytes)
	if e != nil {
		return e
	}
	idx, e := object(v, "schema", "authority", "candidateStatus", "aggregate", "shards", "limitations", "preservation", "baseAcceptedIndexPath", "baseAcceptedIndexSHA256", "baseRootAcceptancePath", "baseRootAcceptanceSHA256", "baseStrictCLIIndexPath", "baseStrictCLIIndexSHA256")
	if e != nil || idx["schema"] != "prufyx.io/private-source-corpus-proposed-aggregate-index/v1" || idx["authority"] != "LOCAL_VERIFIED_RETAINED_SHARDS_NOT_RULE_OR_RUNTIME_PROOF" || idx["candidateStatus"] != "ROOT_ACCEPTED_PRIVATE_REFERENCE_ONLY" {
		return ErrRejected
	}
	shards, ok := idx["shards"].([]any)
	if !ok || len(shards) == 0 {
		return ErrRejected
	}
	agg, ok := idx["aggregate"].(map[string]any)
	if !ok || !exactKeys(agg, "logicalRecordCount", "distinctProjectCount", "deduplicatedObjectCount", "deduplicatedByteLength", "objectLengthConflicts") {
		return ErrRejected
	}
	conflicts, ok := agg["objectLengthConflicts"].([]any)
	if !ok || len(conflicts) != 0 {
		return ErrRejected
	}
	for _, k := range []string{"logicalRecordCount", "distinctProjectCount", "deduplicatedObjectCount", "deduplicatedByteLength"} {
		n, ok := numberInt(agg[k])
		if !ok || n < 1 {
			return ErrRejected
		}
	}
	records := []any{}
	ids := map[string]bool{}
	projects := map[string]bool{}
	seenShards := map[string]bool{}
	root, e := filepath.Abs(o.CorpusRoot)
	if e != nil {
		return ErrRejected
	}
	for _, sv := range shards {
		s, ok := sv.(map[string]any)
		if !ok {
			return ErrRejected
		}
		required := []string{"name", "manifestPath", "manifestFileSHA256", "canonicalManifestDigest", "recordCount", "projectCount", "uniqueObjectCount", "uniqueByteLength", "withinSingleShardVerifierCaps"}
		optional := map[string]bool{"verificationReceiptPath": true, "verificationReceiptSHA256": true, "builderReceiptPath": true, "builderReceiptSHA256": true, "independentPostCaptureReviewPath": true, "independentPostCaptureReviewSHA256": true, "independentPreCaptureReviewPath": true, "independentPreCaptureReviewSHA256": true, "candidateStatus": true}
		for _, k := range required {
			if _, ok := s[k]; !ok {
				return ErrRejected
			}
		}
		for k := range s {
			if !contains(required, k) && !optional[k] {
				return ErrRejected
			}
		}
		name, ok := s["name"].(string)
		if !ok || name == "" || seenShards[name] {
			return ErrRejected
		}
		seenShards[name] = true
		if state, exists := s["candidateStatus"]; exists && state != "ROOT_ACCEPTED_PRIVATE_REFERENCE_ONLY" {
			return ErrRejected
		}
		if _, ok := s["withinSingleShardVerifierCaps"].(bool); !ok {
			return ErrRejected
		}
		for _, k := range []string{"recordCount", "projectCount", "uniqueObjectCount", "uniqueByteLength"} {
			n, ok := numberInt(s[k])
			if !ok || n < 1 {
				return ErrRejected
			}
		}
		canonicalDigest, ok := s["canonicalManifestDigest"].(string)
		if !ok || !shaRE.MatchString(canonicalDigest) {
			return ErrRejected
		}
		rel, ok := s["manifestPath"].(string)
		expected, ok2 := s["manifestFileSHA256"].(string)
		if !ok || !ok2 || filepath.IsAbs(rel) {
			return ErrRejected
		}
		path := filepath.Clean(filepath.Join(root, rel))
		if path != root && !strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return ErrRejected
		}
		raw, e := safeRead(path, maxMetadataBytes)
		if e != nil || digest(raw) != expected {
			return ErrRejected
		}
		mv, e := decode(raw, maxMetadataBytes)
		if e != nil {
			return e
		}
		m, e := object(mv, "schema", "revision", "authority", "records")
		revision, revOK := m["revision"].(string)
		if e != nil || !revOK || revision == "" || m["schema"] != "prufyx.io/public-source-corpus/v1" || m["authority"] != "DECLARED_PUBLIC_SOURCE_BYTES_NOT_RULE_OR_RUNTIME_PROOF" {
			return ErrRejected
		}
		rs, ok := m["records"].([]any)
		if !ok {
			return ErrRejected
		}
		expectedRecords, _ := numberInt(s["recordCount"])
		if len(rs) != expectedRecords {
			return ErrRejected
		}
		shardProjects := map[string]bool{}
		for _, rv := range rs {
			out, e := normalizeRecord(rv)
			if e != nil {
				return e
			}
			id := out["id"].(string)
			if ids[id] {
				return ErrRejected
			}
			ids[id] = true
			projects[out["projectID"].(string)] = true
			shardProjects[out["projectID"].(string)] = true
			records = append(records, out)
		}
		expectedProjects, _ := numberInt(s["projectCount"])
		if len(shardProjects) != expectedProjects {
			return ErrRejected
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].(map[string]any)["id"].(string) < records[j].(map[string]any)["id"].(string)
	})
	rc, _ := numberInt(agg["logicalRecordCount"])
	pc, _ := numberInt(agg["distinctProjectCount"])
	if rc != len(records) || pc != len(projects) {
		return ErrRejected
	}
	rendered, e := canonical(map[string]any{"schema": "prufyx.io/selected-source-records/v1", "provenance": map[string]any{"collectionIndexDigest": digest(indexRaw), "referenceState": "reference_only", "licenseState": "license_unreviewed"}, "records": records}, true)
	if e != nil {
		return e
	}
	if o.Check {
		old, e := safeRead(o.Output, maxMetadataBytes)
		if e != nil || string(old) != string(rendered) {
			return ErrRejected
		}
		return nil
	}
	return writeNewOrReplace(o.Output, rendered)
}
func exactKeys(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func normalizeRecord(v any) (map[string]any, error) {
	r, e := object(v, "id", "project", "source", "capture", "declarations")
	if e != nil {
		return nil, e
	}
	id, e := stringField(r, "id", 160)
	if e != nil {
		return nil, e
	}
	p, e := object(r["project"], "slug", "canonicalRepositoryURL")
	if e != nil {
		return nil, e
	}
	slug, e := stringField(p, "slug", 80)
	if e != nil || !slugRE.MatchString(slug) {
		return nil, ErrRejected
	}
	canonical, _ := p["canonicalRepositoryURL"].(string)
	if !githubRepo(canonical) {
		return nil, ErrRejected
	}
	s, e := object(r["source"], "repositoryURL", "immutableURL", "commit", "version", "sourceKind", "fileDigest", "byteLength", "spans")
	if e != nil {
		return nil, e
	}
	repo, _ := s["repositoryURL"].(string)
	immutable, _ := s["immutableURL"].(string)
	commit, _ := s["commit"].(string)
	fd, _ := s["fileDigest"].(string)
	version, versionOK := s["version"].(string)
	sourceKind, kindOK := s["sourceKind"].(string)
	length, ok := numberInt(s["byteLength"])
	if !githubRepo(repo) || !immutableURL(immutable, commit) || !commitRE.MatchString(commit) || !shaRE.MatchString(fd) || !versionOK || version == "" || len(version) > 128 || !kindOK || !oneOf(sourceKind, "changelog", "helm_chart", "migration_guide", "release_note", "repository_metadata", "source_code") || !ok || length < 1 || length > 1<<20 {
		return nil, ErrRejected
	}
	spans, ok := s["spans"].([]any)
	if !ok || len(spans) == 0 {
		return nil, ErrRejected
	}
	normalized := make([]any, 0, len(spans))
	for _, x := range spans {
		m, e := object(x, "startLine", "endLine", "spanDigest")
		if e != nil {
			return nil, e
		}
		start, a := numberInt(m["startLine"])
		end, b := numberInt(m["endLine"])
		sd, c := m["spanDigest"].(string)
		if !a || !b || !c || start < 1 || end < start || end > 10_000_000 || !shaRE.MatchString(sd) {
			return nil, ErrRejected
		}
		normalized = append(normalized, map[string]any{"startLine": start, "endLine": end, "spanDigest": sd})
	}
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].(map[string]any)["startLine"].(int) < normalized[j].(map[string]any)["startLine"].(int)
	})
	return map[string]any{"id": id, "projectID": slug, "canonicalRepositoryURL": canonical, "repositoryURL": repo, "immutableURL": immutable, "commit": commit, "version": version, "sourceKind": sourceKind, "contentDigest": fd, "byteLength": length, "spans": normalized}, nil
}
func writeNewOrReplace(path string, data []byte) error {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		return ErrRejected
	}
	tmp, e := os.CreateTemp(filepath.Dir(path), ".selected-source-*")
	if e != nil {
		return ErrRejected
	}
	name := tmp.Name()
	defer os.Remove(name)
	if e = tmp.Chmod(0600); e == nil {
		_, e = tmp.Write(data)
	}
	if closeErr := tmp.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return ErrRejected
	}
	if e = os.Rename(name, path); e != nil {
		return ErrRejected
	}
	return nil
}
