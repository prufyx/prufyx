// SPDX-License-Identifier: AGPL-3.0-only

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package communityapp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgerelease"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
)

// withdrawnPublishedEvidence reads the shipped data file itself and returns
// the earliest evidence end of everything a package for oldestClient carries
// (every rule and record of every state, both catalogs), the earliest over
// the cri-o items, and the end of the withdrawn CRI-O rule.
func withdrawnPublishedEvidence(t *testing.T, oldestClient string) (index, project, record time.Time) {
	t.Helper()
	raw, err := os.ReadFile("../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	type item struct {
		ID         string `json:"id"`
		Component  string `json:"component"`
		FactFamily string `json:"factFamily"`
		Evidence   struct {
			State      string `json:"state"`
			ValidUntil string `json:"validUntil"`
		} `json:"evidence"`
	}
	var pack struct {
		Entries []struct {
			Project string `json:"project"`
			Rule    item   `json:"rule"`
		} `json:"entries"`
		LineAttestations []item `json:"lineAttestations"`
		PathPolicies     []item `json:"pathPolicies"`
		ServedAPIs       []item `json:"servedAPIs"`
	}
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	listedShips, err := cncfcheck.ListedFamilyShips(oldestClient)
	if err != nil {
		t.Fatal(err)
	}
	add := func(of bool, value item) {
		end, err := time.Parse(time.RFC3339, value.Evidence.ValidUntil)
		if err != nil || end.Location() != time.UTC {
			t.Fatalf("unreadable validUntil %q: %v", value.Evidence.ValidUntil, err)
		}
		if index.IsZero() || end.Before(index) {
			index = end
		}
		if of && (project.IsZero() || end.Before(project)) {
			project = end
		}
	}
	found := 0
	for _, entry := range pack.Entries {
		add(entry.Project == "cri-o", entry.Rule)
		if entry.Rule.ID == "cri-o.artifact-short-name-rejected.1-35" {
			found++
			if entry.Project != "cri-o" || entry.Rule.Evidence.State != "withdrawn" {
				t.Fatalf("the CRI-O record is %q of %q", entry.Rule.Evidence.State, entry.Project)
			}
			if record, err = time.Parse(time.RFC3339, entry.Rule.Evidence.ValidUntil); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, section := range [][]item{pack.LineAttestations, pack.PathPolicies, pack.ServedAPIs} {
		for _, value := range section {
			if value.FactFamily == "changelog.listed_entries" && !listedShips {
				continue
			}
			add(value.Component == "pkg:github/cri-o/cri-o", value)
		}
	}
	if found != 1 || index.IsZero() || project.IsZero() {
		t.Fatalf("%d CRI-O records, index end %s, project end %s", found, index, project)
	}
	return index, project, record
}

// A package the release publisher signs from the embedded knowledge, with
// throwaway keys, ends with the earliest shipped evidence; its cri-o target
// carries the end of the re-reviewed withdrawn record, and a check from the
// imported store still answers UNKNOWN (RULE_EVIDENCE_WITHDRAWN).
func TestPublisherReleaseWithdrawnRecordExpiry(t *testing.T) {
	dir, err := filepath.EvalSymlinks(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	const pass = "throwaway withdrawn passphrase 12"
	keys := filepath.Join(dir, "keys")
	initialized, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: keys, RootExpires: time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339), RootPassphrase: []byte("root key passphrase 123456"), Passphrase: []byte(pass)})
	if err != nil {
		t.Fatal(err)
	}
	pinProjects(t, initialized.RootDigest)
	passFile := writeKnowledgeReleaseFile(t, dir, "pass", []byte(pass))

	pinRaw, err := os.ReadFile("../../knowledge/oldest-supported-client.txt")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(pinRaw), "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "ref=") || !strings.HasPrefix(lines[1], "version=") {
		t.Fatalf("pin file is not one ref= and one version= line: %q", pinRaw)
	}
	oldest := strings.TrimPrefix(lines[1], "version=")
	if oldest == "" || lines[0] == "ref=" {
		t.Fatalf("pin file has an empty value: %q", pinRaw)
	}

	now := time.Now().UTC()
	out := filepath.Join(dir, "release")
	result, err := knowledgerelease.Run(knowledgerelease.Options{
		Revision: "81", Version: 1, Root: filepath.Join(keys, "root.json"), RootDigest: initialized.RootDigest,
		TargetsKey: filepath.Join(keys, "targets.key.pem"), SnapshotKey: filepath.Join(keys, "snapshot.key.pem"), TimestampKey: filepath.Join(keys, "timestamp.key.pem"),
		PassphraseFile: passFile, FirstRelease: true, OldestClient: oldest, OutputDir: out, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}

	wantIndex, wantProject, wantRecord := withdrawnPublishedEvidence(t, oldest)
	t.Logf("wantIndex %s, wantCrio %s, cri-o record %s", wantIndex.Format(time.RFC3339), wantProject.Format(time.RFC3339), wantRecord.Format(time.RFC3339))
	if result.EvidenceExpiresAt != wantIndex.Format(time.RFC3339) {
		t.Errorf("release evidence ends %s, want %s", result.EvidenceExpiresAt, wantIndex.Format(time.RFC3339))
	}
	wantExpires := now.Add(knowledgerelease.ContentLifetime)
	if wantIndex.Before(wantExpires) {
		wantExpires = wantIndex
	}
	if got := wantExpires.Truncate(time.Second).Format(time.RFC3339); result.Expires != got {
		t.Errorf("release expires %s, want %s", result.Expires, got)
	}

	indexTarget, targets, _, err := cncfcheck.BuildEmbeddedExternalTargetsPinned("81", nil, oldest)
	if err != nil {
		t.Fatal(err)
	}
	if got := releaseDigest(indexTarget.Bytes); got != result.IndexDigest {
		t.Fatalf("built index %s is not the signed index %s", got, result.IndexDigest)
	}
	index, err := cncfcheck.ParseExternalIndex(indexTarget.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := index.Entry("cri-o")
	if !ok {
		t.Fatal("the index lists no cri-o target")
	}
	var crioTarget []byte
	for _, target := range targets {
		if target.Path == entry.TargetPath {
			crioTarget = target.Bytes
		}
	}
	admitted, err := cncfcheck.AdmitExternalProjectTarget(index, "cri-o", crioTarget)
	if err != nil {
		t.Fatal(err)
	}
	projectAdmission, err := admitted.Admission()
	if err != nil {
		t.Fatal(err)
	}
	if want := wantProject.Format(time.RFC3339); entry.EvidenceExpiresAt != want || projectAdmission.EvidenceExpiresAt != want {
		t.Errorf("cri-o evidence ends: entry %s, target %s, want %s", entry.EvidenceExpiresAt, projectAdmission.EvidenceExpiresAt, want)
	}
	indexAdmission, err := index.Admission()
	if err != nil {
		t.Fatal(err)
	}
	if want := wantIndex.Format(time.RFC3339); indexAdmission.EvidenceExpiresAt != want {
		t.Errorf("index evidence ends %s, want %s", indexAdmission.EvidenceExpiresAt, want)
	}
	// Not fatal: the import and the check below are proved on any data.
	if floor := time.Date(2027, 1, 1, 6, 54, 28, 0, time.UTC); wantRecord.Before(floor) {
		t.Errorf("the CRI-O record ends %s, before %s", wantRecord.Format(time.RFC3339), floor.Format(time.RFC3339))
	}

	packageRaw, err := os.ReadFile(filepath.Join(out, "cncf-projects-81.tar"))
	if err != nil {
		t.Fatal(err)
	}
	const url = "https://metadata.example.test/cncf-projects-81.tar"
	store := filepath.Join(dir, "store")
	code, update, stderr := runReleasePlanUpdate(t, []string{
		"--profile", "cncf-projects", "--source", url, "--package-out", filepath.Join(dir, "got.tar"), "--db-root", store,
		"--expected-revision", "81", "--expected-bundle-digest", result.IndexDigest,
		"--bootstrap-root", filepath.Join(out, "root.json"), "--bootstrap-root-digest", initialized.RootDigest, "--format", "json",
	}, func(_ context.Context, source string) ([]byte, error) {
		if source != url {
			t.Fatalf("source=%q", source)
		}
		return packageRaw, nil
	})
	if code != ExitOK || stderr != "" || update.Status != "IMPORTED" || update.ImportReceipt == nil || update.ImportReceipt.TrustReceipt.TargetDigest != result.IndexDigest {
		t.Fatalf("update code=%d out=%+v stderr=%q", code, update, stderr)
	}
	receipt := *update.ImportReceipt
	imported := ""
	for _, project := range receipt.ProjectTargets {
		if project.Project == "cri-o" {
			imported = project.Digest
		}
	}
	if imported != releaseDigest(crioTarget) {
		t.Fatalf("imported cri-o target %q, built %q", imported, releaseDigest(crioTarget))
	}

	request := writeKnowledgeReleaseFile(t, dir, "image-status-request.json", []byte(`{"image":{"image":"widget:v1"}}`))
	code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cri-o", "--image-status-request", request,
		"--from", "1.34.0", "--to", "1.35.0", "--artifact-operation", "named-reference-resolution",
		"--knowledge-db", store, "--knowledge-revision", "81", "--knowledge-bundle-digest", receipt.TrustReceipt.TargetDigest,
		"--knowledge-trust-receipt-digest", receipt.TrustReceiptDigest, "--format", "json")
	if code != ExitUnknown || stderr != "" {
		t.Fatalf("check code=%d stderr=%q out=%s", code, stderr, report)
	}
	var db cncfknowledge.Report
	if err := json.Unmarshal([]byte(report), &db); err != nil {
		t.Fatalf("report: %v\n%s", err, report)
	}
	claims := db.Check.Check.Claims
	if len(claims) != 1 || claims[0].RuleID != "cri-o.artifact-short-name-rejected.1-35" || claims[0].Status != "UNKNOWN" || claims[0].ReasonCode != "RULE_EVIDENCE_WITHDRAWN" {
		t.Fatalf("claims %+v", claims)
	}
	binding := db.Knowledge.ProjectTarget
	if db.Knowledge.Origin != "external_signed_local" || binding == nil || binding.Status != "present" || binding.Project != "cri-o" || binding.Digest != imported || db.Check.KnowledgePackDigest != binding.Digest {
		t.Fatalf("report origin=%q project=%+v pack=%q", db.Knowledge.Origin, binding, db.Check.KnowledgePackDigest)
	}
}
