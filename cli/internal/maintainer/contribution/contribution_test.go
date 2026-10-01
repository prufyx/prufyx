// SPDX-License-Identifier: AGPL-3.0-only

package contribution

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAcceptedCandidatesAndRejectExtraField(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	landscape := filepath.Join(root, "internal", "cncfcheck", "data", "landscape-projects.json")
	for _, name := range []string{"synthetic-new-identity-packet.json", "tikv-8.5.8-gcp-v2-wif-backup-candidate.json"} {
		path := filepath.Join(root, "examples", "contributions", name)
		got, err := Validate(ValidateOptions{PacketPath: path, LandscapePath: landscape})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var receipt map[string]any
		if json.Unmarshal(got, &receipt) != nil || receipt["consistency"] != "VALID" || receipt["workflowState"] != "CANDIDATE" {
			t.Fatalf("unexpected receipt: %s", got)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(root, "examples", "contributions", "synthetic-new-identity-packet.json"))
	var packet map[string]any
	json.Unmarshal(raw, &packet)
	packet["customerConfiguration"] = "private"
	tmp := filepath.Join(t.TempDir(), "packet.json")
	b, _ := json.Marshal(packet)
	os.WriteFile(tmp, b, 0600)
	if _, err := Validate(ValidateOptions{PacketPath: tmp, LandscapePath: landscape}); err == nil {
		t.Fatal("accepted open schema")
	}
}

func TestScaffoldIsPrivateExclusiveAndBounded(t *testing.T) {
	parent, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(parent, "tikv.json")
	opts := ScaffoldOptions{Kind: "existing_project_target_preflight", ProjectSlug: "tikv", DisplayName: "TiKV", Repository: "https://github.com/tikv/tikv", TargetVersion: "8.5.8", Operation: "gcs-full-backup-wif", Output: path}
	if err := Scaffold(opts); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if err := Scaffold(opts); err == nil {
		t.Fatal("overwrote scaffold")
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"schema":"prufyx.io/upstream-evidence-packet/v2"`) {
		t.Fatal("wrong scaffold")
	}
}

func TestCandidateDiscoveryIsSortedPathFreeAndRejectsSymlink(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	dir := t.TempDir()
	landscape := filepath.Join(root, "internal", "cncfcheck", "data", "landscape-projects.json")
	for _, pair := range [][2]string{{"tikv-8.5.8-gcp-v2-wif-backup-candidate.json", "z.json"}, {"synthetic-new-identity-packet.json", "a.json"}} {
		b, _ := os.ReadFile(filepath.Join(root, "examples", "contributions", pair[0]))
		os.WriteFile(filepath.Join(dir, pair[1]), b, 0600)
	}
	got, err := ValidateCandidates(dir, landscape)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), dir) || strings.Contains(string(got), "a.json") {
		t.Fatalf("leaked path: %s", got)
	}
	if err := os.Symlink(filepath.Join(dir, "a.json"), filepath.Join(dir, "unsafe.json")); err == nil {
		if _, err = ValidateCandidates(dir, landscape); err == nil {
			t.Fatal("accepted symlink")
		}
	}
}

func TestNormalizeRecordPreservesReferenceOnlyProvenanceFields(t *testing.T) {
	record := map[string]any{"id": "record-1", "project": map[string]any{"slug": "tikv", "canonicalRepositoryURL": "https://github.com/tikv/tikv"}, "source": map[string]any{"repositoryURL": "https://github.com/tikv/tikv", "immutableURL": "https://github.com/tikv/tikv/blob/3f446cfa9eb1d5c653031d261e185911495d0359/src/config/mod.rs", "commit": "3f446cfa9eb1d5c653031d261e185911495d0359", "version": "8.5.8", "sourceKind": "source_code", "fileDigest": "sha256:" + strings.Repeat("a", 64), "byteLength": json.Number("10"), "spans": []any{map[string]any{"startLine": json.Number("2"), "endLine": json.Number("3"), "spanDigest": "sha256:" + strings.Repeat("b", 64)}}}, "capture": map[string]any{"capturedAt": "x", "object": "x"}, "declarations": map[string]any{"packetDigest": nil, "ruleIDs": []any{}}}
	got, err := normalizeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if got["projectID"] != "tikv" || got["contentDigest"] == nil {
		t.Fatalf("bad normalization: %#v", got)
	}
}

func TestRepositoryCandidateSetPassesAsCandidatesOnly(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	got, err := ValidateCandidates(filepath.Join(root, "examples", "contributions"), filepath.Join(root, "internal", "cncfcheck", "data", "landscape-projects.json"))
	if err != nil {
		t.Fatal(err)
	}
	var summary map[string]any
	if json.Unmarshal(got, &summary) != nil || summary["supportAdmission"] != "NOT_ADMITTED" {
		t.Fatalf("unexpected summary: %s", got)
	}
}

func TestSelectLinesRequiresRawLFAndExactBounds(t *testing.T) {
	got, ok := selectLines([]byte("one\ntwo\nthree\n"), 2, 3)
	if !ok || string(got) != "two\nthree" {
		t.Fatalf("unexpected span %q", got)
	}
	if _, ok := selectLines([]byte("one\r\ntwo\r\n"), 1, 1); ok {
		t.Fatal("accepted CRLF source")
	}
}

func TestVerifySourcesAcceptedV2(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	got, err := VerifySources(ValidateOptions{PacketPath: filepath.Join(root, "examples", "contributions", "tikv-8.5.8-gcp-v2-wif-backup-candidate.json"), LandscapePath: filepath.Join(root, "internal", "cncfcheck", "data", "landscape-projects.json")}, filepath.Join(root, "examples", "corpus", "objects"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte(`"verification":"LOCAL_DECLARED_PUBLIC_SOURCE_BYTES_MATCHED"`)) || !bytes.Contains(got, []byte(`"admissionState":"NOT_ADMITTED"`)) {
		t.Fatalf("unexpected receipt: %s", got)
	}
}

func TestPacketNestedParityRejections(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	landscape := filepath.Join(root, "internal", "cncfcheck", "data", "landscape-projects.json")
	load := func(name string) map[string]any {
		raw, _ := os.ReadFile(filepath.Join(root, "examples", "contributions", name))
		v, e := decode(raw, MaxPacketBytes)
		if e != nil {
			t.Fatal(e)
		}
		return v.(map[string]any)
	}
	tests := []struct {
		name, file string
		mutate     func(map[string]any)
	}{
		{"v1 source commit binding", "buildpacks-lifecycle-0.16.5-to-0.17.7-candidate.json", func(p map[string]any) {
			s := p["sources"].([]any)[0].(map[string]any)
			old := s["commit"].(string)
			s["commit"] = "0123456789abcdef0123456789abcdef01234567"
			s["immutableURL"] = strings.Replace(s["immutableURL"].(string), old, s["commit"].(string), 1)
		}},
		{"kubeflow guide cardinality", "kubeflow-kfp-sdk-1.8.22-to-2.0.0-candidate.json", func(p map[string]any) {
			sources := p["sources"].([]any)
			guide := sources[len(sources)-1].(map[string]any)
			clone := map[string]any{}
			for k, v := range guide {
				clone[k] = v
			}
			clone["id"] = "duplicate-guide"
			p["sources"] = append(sources, clone)
		}},
		{"duplicate limitation", "synthetic-new-identity-packet.json", func(p map[string]any) { a := p["limitations"].([]any); p["limitations"] = append(a, a[0]) }},
		{"multiline declaration", "synthetic-new-identity-packet.json", func(p map[string]any) {
			p["declaration"].(map[string]any)["statement"] = "first\nsecond"
		}},
		{"control in limitation", "synthetic-new-identity-packet.json", func(p map[string]any) {
			p["limitations"] = []any{"contains\ta tab"}
		}},
		{"new identity source repository", "synthetic-new-identity-packet.json", func(p map[string]any) {
			s := p["sources"].([]any)[0].(map[string]any)
			repository := p["project"].(map[string]any)["canonicalRepositoryURL"].(string)
			s["immutableURL"] = strings.Replace(s["immutableURL"].(string), repository, "https://github.com/unrelated/repository", 1)
		}},
		{"reviewer kind", "synthetic-new-identity-packet.json", func(p map[string]any) {
			p["review"].(map[string]any)["claimedReviewer"].(map[string]any)["kind"] = "service"
		}},
		{"license enum", "synthetic-new-identity-packet.json", func(p map[string]any) { p["attribution"].(map[string]any)["licenseAssertion"] = "APPROVED" }},
		{"v2 role", "tikv-8.5.8-gcp-v2-wif-backup-candidate.json", func(p map[string]any) {
			p["sources"].([]any)[0].(map[string]any)["evidenceRole"] = "operator_action_guidance"
		}},
		{"v2 fixed target commit", "tikv-8.5.8-gcp-v2-wif-backup-candidate.json", func(p map[string]any) {
			p["tagBindings"].([]any)[0].(map[string]any)["commit"] = "0123456789abcdef0123456789abcdef01234567"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := load(tt.file)
			tt.mutate(p)
			if _, e := ValidatePacket(p, landscape); e == nil {
				t.Fatal("accepted invalid packet")
			}
		})
	}
}

func TestCanonicalEscapesNonASCIILikeLegacyPackets(t *testing.T) {
	raw, err := canonical(map[string]any{"name": "café 😀"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"name":"caf\u00e9 \ud83d\ude00"}` {
		t.Fatalf("unexpected canonical JSON: %s", raw)
	}
}

func TestCanonicalRejectsEncoderFailuresWithoutOutput(t *testing.T) {
	raw, err := canonical(map[string]any{"not-a-json-number": math.Inf(1)}, true)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected rejected error, got %v", err)
	}
	if len(raw) != 0 {
		t.Fatalf("returned canonical output after encoder failure: %q", raw)
	}
}

func TestImportSelectedSourceRecordsAcceptedAggregateAndCheck(t *testing.T) {
	dir := t.TempDir()
	manifestDir := filepath.Join(dir, "shard")
	os.Mkdir(manifestDir, 0700)
	shaA := "sha256:" + strings.Repeat("a", 64)
	shaB := "sha256:" + strings.Repeat("b", 64)
	record := map[string]any{"id": "record-1", "project": map[string]any{"slug": "tikv", "canonicalRepositoryURL": "https://github.com/tikv/tikv"}, "source": map[string]any{"repositoryURL": "https://github.com/tikv/tikv", "immutableURL": "https://github.com/tikv/tikv/blob/3f446cfa9eb1d5c653031d261e185911495d0359/src/config/mod.rs", "commit": "3f446cfa9eb1d5c653031d261e185911495d0359", "version": "8.5.8", "sourceKind": "source_code", "fileDigest": shaA, "byteLength": json.Number("10"), "spans": []any{map[string]any{"startLine": json.Number("2"), "endLine": json.Number("3"), "spanDigest": shaB}}}, "capture": map[string]any{"capturedAt": "2026-01-01T00:00:00Z", "object": "sha256/a"}, "declarations": map[string]any{"packetDigest": nil, "ruleIDs": []any{}}}
	manifest := map[string]any{"schema": "prufyx.io/public-source-corpus/v1", "revision": "test", "authority": "DECLARED_PUBLIC_SOURCE_BYTES_NOT_RULE_OR_RUNTIME_PROOF", "records": []any{record}}
	manifestRaw, _ := canonical(manifest, true)
	manifestPath := filepath.Join(manifestDir, "manifest.json")
	os.WriteFile(manifestPath, manifestRaw, 0600)
	index := map[string]any{"schema": "prufyx.io/private-source-corpus-proposed-aggregate-index/v1", "authority": "LOCAL_VERIFIED_RETAINED_SHARDS_NOT_RULE_OR_RUNTIME_PROOF", "candidateStatus": "ROOT_ACCEPTED_PRIVATE_REFERENCE_ONLY", "aggregate": map[string]any{"logicalRecordCount": json.Number("1"), "distinctProjectCount": json.Number("1"), "deduplicatedObjectCount": json.Number("1"), "deduplicatedByteLength": json.Number("10"), "objectLengthConflicts": []any{}}, "shards": []any{map[string]any{"name": "one", "manifestPath": "shard/manifest.json", "manifestFileSHA256": digest(manifestRaw), "canonicalManifestDigest": shaA, "recordCount": json.Number("1"), "projectCount": json.Number("1"), "uniqueObjectCount": json.Number("1"), "uniqueByteLength": json.Number("10"), "withinSingleShardVerifierCaps": true}}, "limitations": []any{"local"}, "preservation": map[string]any{}, "baseAcceptedIndexPath": "x", "baseAcceptedIndexSHA256": shaA, "baseRootAcceptancePath": "x", "baseRootAcceptanceSHA256": shaA, "baseStrictCLIIndexPath": "x", "baseStrictCLIIndexSHA256": shaA}
	indexRaw, _ := canonical(index, true)
	indexPath := filepath.Join(dir, "index.json")
	os.WriteFile(indexPath, indexRaw, 0600)
	out := filepath.Join(dir, "out.json")
	opts := ImportOptions{CorpusRoot: dir, CollectionIndex: indexPath, ExpectedIndexDigest: digest(indexRaw), Output: out}
	if e := ImportSelectedSourceRecords(opts); e != nil {
		t.Fatal(e)
	}
	opts.Check = true
	if e := ImportSelectedSourceRecords(opts); e != nil {
		t.Fatal(e)
	}
	rendered, _ := os.ReadFile(out)
	if !bytes.Contains(rendered, []byte(`"referenceState":"reference_only"`)) || !bytes.Contains(rendered, []byte(`"licenseState":"license_unreviewed"`)) {
		t.Fatalf("lost provenance: %s", rendered)
	}
}
