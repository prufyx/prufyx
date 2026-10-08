// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// EXTPACK: a per-project database whose targets carry records. The store
// verifies them like rules, keeps them per project, and its rollback floors
// refuse a target that drops its records under the revision it had.

const recordsServedSection = `[{"component":"pkg:github/kubernetes/kubernetes","line":"1.29","completeness":"COMPLETE_SERVED_API_LIST_FOR_LINE","apis":["apps/v1 Deployment","v1 ConfigMap"],"evidence":{"basis":"reviewed","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[{"id":"s","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":40,"endLine":49}]}}]`

// packWithServedList is the shipped CNCF pack plus one served-API list.
func packWithServedList(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../cncfcheck/data/rules.json")
	if err != nil {
		t.Fatal(err)
	}
	var pack map[string]json.RawMessage
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatal(err)
	}
	pack["servedAPIs"] = json.RawMessage(recordsServedSection)
	pack["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha10"`)
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func targetsFromPack(t *testing.T, pack []byte, revision string) map[string][]byte {
	t.Helper()
	index, projects, err := cncfcheck.BuildExternalTargetsFromPack(pack, revision)
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string][]byte{index.Path: index.Bytes}
	for _, project := range projects {
		targets[project.Path] = project.Bytes
	}
	return targets
}

// relabelProject puts raw (another envelope of project) under the index at
// indexRevision with entryRevision, setting every member of its entry and
// the index schema exactly as the publisher would.
func relabelProject(t *testing.T, indexRaw []byte, project string, raw []byte, indexRevision, entryRevision string) []byte {
	t.Helper()
	bundle, err := cncfcheck.ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	admission, err := bundle.Admission()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Schema                 string                         `json:"schema"`
		Revision               string                         `json:"revision"`
		Purpose                string                         `json:"purpose"`
		EngineCapabilityDigest string                         `json:"engineCapabilityDigest"`
		Projects               []cncfcheck.ExternalIndexEntry `json:"projects"`
	}
	if err := json.Unmarshal(indexRaw, &document); err != nil {
		t.Fatal(err)
	}
	document.Revision = indexRevision
	records := false
	for i := range document.Projects {
		e := &document.Projects[i]
		if e.Project == project {
			e.Length, e.Digest, e.Revision, e.RuleDigest, e.EvidenceExpiresAt, e.Records = int64(len(raw)), digestBytes(raw), entryRevision, admission.RuleDigest, admission.EvidenceExpiresAt, admission.HasRecords
		}
		records = records || e.Records
	}
	document.Schema = cncfcheck.ExternalIndexSchema
	if records {
		document.Schema = cncfcheck.ExternalIndexSchemaRecords
	}
	out, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalIndex(out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestConstraintsProjectsCarryRecords: a package whose kubernetes target
// carries a served-API list imports, the opened project target holds it, and
// its import receipt binds the records (the index rule digest binds the
// records target's content digest).
func TestConstraintsProjectsCarryRecords(t *testing.T) {
	f := newProjectsFixture(t)
	targets := targetsFromPack(t, packWithServedList(t), "5")
	index := targets[ConstraintsProjectsIndexTargetPath]
	if !bytes.Contains(index, []byte(cncfcheck.ExternalIndexSchemaRecords)) {
		t.Fatal("the index is not a records index")
	}
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: targets})); err != nil {
		t.Fatalf("records package refused: %v", err)
	}
	opened, err := OpenSelectedCNCF(SelectionRequest{StoreRoot: f.store}, []string{"kubernetes"})
	if err != nil {
		t.Fatal(err)
	}
	target, ok := opened.ProjectTarget("kubernetes")
	if !ok || !bytes.Contains(target.Bytes(), []byte(`"servedAPIs"`)) {
		t.Fatal("the opened kubernetes target does not carry its served list")
	}
	plain := targetsFromPack(t, mustRead(t, "../cncfcheck/data/rules.json"), "5")
	if bytes.Equal(plain[ConstraintsProjectsIndexTargetPath], index) {
		t.Fatal("records did not change the index")
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestConstraintsProjectsRefuseDroppingRecordsAtTheSameRevision: after a
// database holds the kubernetes target with its records at revision 5, a
// later index that serves the kubernetes target without them under the same
// revision 5 is a rollback of that project and is refused; the last good
// selection is kept. Dropping them under a new revision is an ordinary
// update.
func TestConstraintsProjectsRefuseDroppingRecordsAtTheSameRevision(t *testing.T) {
	f := newProjectsFixture(t)
	withRecords := targetsFromPack(t, packWithServedList(t), "5")
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: withRecords})); err != nil {
		t.Fatal(err)
	}
	kept, err := loadSelectionAt(f.store)
	if err != nil {
		t.Fatal(err)
	}
	k8s := cncfcheck.ProjectTargetPath("kubernetes")
	plain5 := targetsFromPack(t, mustRead(t, "../cncfcheck/data/rules.json"), "5")
	stripped := map[string][]byte{}
	for name, raw := range withRecords {
		stripped[name] = raw
	}
	stripped[k8s] = plain5[k8s]
	stripped[ConstraintsProjectsIndexTargetPath] = relabelProject(t, withRecords[ConstraintsProjectsIndexTargetPath], "kubernetes", plain5[k8s], "6", "5")
	rejected, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: stripped}))
	if !errors.Is(err, ErrRollback) || !strings.Contains(err.Error(), k8s) {
		t.Fatalf("records dropped at the same revision accepted: %+v %v", rejected, err)
	}
	assertSelectionKept(t, f.store, kept, rejected)
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: targetsFromPack(t, mustRead(t, "../cncfcheck/data/rules.json"), "6")})); err != nil {
		t.Fatalf("an update without the records at a new revision refused: %v", err)
	}
}

// TestConstraintsProjectsRefuseForeignRecordTarget: a signed package that
// serves the kubernetes records envelope under the etcd path (the index
// relabelled to match) fails semantic admission and is not imported. A
// record alone moved into another project's target is refused by the same
// admission (cncfcheck TestProjectTargetRefusesForeignRecords).
func TestConstraintsProjectsRefuseForeignRecordTarget(t *testing.T) {
	f := newProjectsFixture(t)
	targets := targetsFromPack(t, packWithServedList(t), "5")
	// The kubernetes target's bytes under the etcd path, relabelled in the
	// index: same signature checks pass, admission must not.
	etcd := cncfcheck.ProjectTargetPath("etcd")
	if _, ok := targets[etcd]; !ok {
		t.Skip("no etcd target in the pack")
	}
	moved := map[string][]byte{}
	for name, raw := range targets {
		moved[name] = raw
	}
	moved[etcd] = targets[cncfcheck.ProjectTargetPath("kubernetes")]
	moved[ConstraintsProjectsIndexTargetPath] = relabelProject(t, targets[ConstraintsProjectsIndexTargetPath], "etcd", moved[etcd], "5", "5")
	if _, err := f.importPackage(f.write(t, knowledgefixture.ProjectsPackage{Targets: moved})); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("a foreign records target was imported: %v", err)
	}
}
