// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func buildSplit(t *testing.T, revision string) (ExternalTarget, map[string][]byte) {
	t.Helper()
	index, projects, err := BuildEmbeddedExternalTargets(revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	byProject := map[string][]byte{}
	for _, project := range projects {
		slug, ok := ProjectFromTargetPath(project.Path)
		if !ok {
			t.Fatalf("bad target path %s", project.Path)
		}
		byProject[slug] = project.Bytes
	}
	return index, byProject
}

func reencodeIndex(t *testing.T, raw []byte, mutate func(*externalIndexDocument)) []byte {
	t.Helper()
	var document externalIndexDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	mutate(&document)
	out, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSplitTargetsCoverThePackExactlyAndAreDeterministic(t *testing.T) {
	index, projects := buildSplit(t, "3")
	again, projectsAgain := buildSplit(t, "3")
	if !bytes.Equal(index.Bytes, again.Bytes) || len(projects) != len(projectsAgain) {
		t.Fatal("build is not deterministic")
	}
	parsed, err := ParseExternalIndex(index.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, entry := range parsed.Entries() {
		bundle, err := AdmitExternalProjectTarget(parsed, entry.Project, projects[entry.Project])
		if err != nil {
			t.Fatalf("%s: %v", entry.Project, err)
		}
		total += len(bundle.pack.Entries)
	}
	if total != len(base.pack.Entries) || len(parsed.Entries()) != len(projects) {
		t.Fatalf("split covers %d of %d entries", total, len(base.pack.Entries))
	}
}

func TestParseExternalIndexRejectsMalformedIndexes(t *testing.T) {
	index, _ := buildSplit(t, "3")
	cases := map[string][]byte{
		"non-canonical": append(append([]byte(nil), index.Bytes...), ' '),
		"unsorted": reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) {
			d.Projects[0], d.Projects[1] = d.Projects[1], d.Projects[0]
		}),
		"duplicate": reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) { d.Projects[1] = d.Projects[0] }),
		"unknown project": reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) {
			d.Projects[0].Project, d.Projects[0].TargetPath = "aaa-not-a-project", ProjectTargetPath("aaa-not-a-project")
		}),
		"foreign path": reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) { d.Projects[0].TargetPath = ProjectTargetPath(d.Projects[1].Project) }),
		"oversize":     reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) { d.Projects[0].Length = MaxExternalTargetBytes + 1 }),
		"empty":        reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) { d.Projects = []ExternalIndexEntry{} }),
		"engine": reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) {
			d.EngineCapabilityDigest = "sha256:" + string(bytes.Repeat([]byte("0"), 64))
		}),
		"bad revision":  reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) { d.Projects[0].Revision = "0" }),
		"wrong schema":  reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) { d.Schema = "prufyx.io/cncf-knowledge-index/v2" }),
		"unknown field": bytes.Replace(index.Bytes, []byte(`"projects":`), []byte(`"extra":1,"projects":`), 1),
	}
	for name, raw := range cases {
		if _, err := ParseExternalIndex(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAdmitExternalProjectTargetBindsIndexEntry(t *testing.T) {
	index, projects := buildSplit(t, "3")
	parsed, err := ParseExternalIndex(index.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	entries := parsed.Entries()
	a, b := entries[0].Project, entries[1].Project
	if _, err := AdmitExternalProjectTarget(parsed, a, projects[b]); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("another project's target admitted: %v", err)
	}
	if _, err := AdmitExternalProjectTarget(parsed, "visual-studio-code-kubernetes-tools", projects[a]); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("target for a project outside the index admitted: %v", err)
	}
	// An index entry that binds project a to b's exact bytes must still be
	// rejected because the entries belong to b.
	base, err := load()
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := ParseExternalBundle(projects[b])
	if err != nil {
		t.Fatal(err)
	}
	admission, _ := foreign.Admission()
	lying := reencodeIndex(t, index.Bytes, func(d *externalIndexDocument) {
		d.Projects[0].Length, d.Projects[0].Digest = int64(len(projects[b])), digest(projects[b])
		d.Projects[0].RuleDigest, d.Projects[0].EvidenceExpiresAt, d.Projects[0].Revision = admission.RuleDigest, admission.EvidenceExpiresAt, admission.Revision
	})
	lyingIndex, err := parseExternalIndex(lying, &base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitExternalProjectTarget(lyingIndex, a, projects[b]); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("foreign entries admitted under project %s: %v", a, err)
	}
	// Revision and rule digest must match the index entry.
	other, otherProjects := buildSplit(t, "4")
	otherIndex, err := ParseExternalIndex(other.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdmitExternalProjectTarget(otherIndex, a, projects[a]); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("stale revision admitted: %v", err)
	}
	if _, err := AdmitExternalProjectTarget(otherIndex, a, otherProjects[a]); err != nil {
		t.Fatal(err)
	}
}

func TestBuildFromPreviousIndexKeepsUnchangedRevisions(t *testing.T) {
	index, _ := buildSplit(t, "3")
	next, projects, err := BuildEmbeddedExternalTargetsFrom("4", index.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseExternalIndex(next.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range parsed.Entries() {
		if entry.Revision != "3" {
			t.Fatalf("unchanged %s moved to %s", entry.Project, entry.Revision)
		}
	}
	if admission, _ := parsed.Admission(); admission.Revision != "4" || len(projects) != len(parsed.Entries()) {
		t.Fatalf("index admission %+v", admission)
	}
	if _, _, err := BuildEmbeddedExternalTargetsFrom("3", index.Bytes); err == nil {
		t.Fatal("non-increasing index revision accepted")
	}
}

func TestTargetSizeAlarmBytesRoundsUp(t *testing.T) {
	if got := TargetSizeAlarmBytes(); got != 838861 {
		t.Fatalf("alarm bytes %d", got)
	}
}

func TestEmptyExternalBundleHasNoRules(t *testing.T) {
	bundle, err := EmptyExternalBundle("2", "operator_provided")
	if err != nil {
		t.Fatal(err)
	}
	if admission, _ := bundle.Admission(); admission.HasRule || admission.Revision != "2" {
		t.Fatalf("empty bundle admission %+v", admission)
	}
}
