// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/customresources"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
	"github.com/prufyx/prufyx/cli/internal/projectcheck"
	"github.com/prufyx/prufyx/cli/internal/projectprepare"
)

type mariaDBTestIndex struct {
	Schema     string                         `json:"schema"`
	Revision   string                         `json:"revision"`
	Purpose    string                         `json:"purpose"`
	Capability string                         `json:"engineCapabilityDigest"`
	Projects   []cncfcheck.ExternalIndexEntry `json:"projects"`
	MinClient  string                         `json:"minClientVersion,omitempty"`
}

func mariaDBCRDTarget(t *testing.T, canary bool) ([]byte, []byte) {
	t.Helper()
	req, err := cncfcheck.ExternalProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	if canary {
		req, err = cncfcheck.MariaDBCanaryProfileRequirements()
		if err != nil {
			t.Fatal(err)
		}
	}
	p, ok := customresources.ProjectFor("mariadb-operator")
	if !ok {
		t.Fatal("catalog identity")
	}
	var envelope map[string]any
	if json.Unmarshal(mariaDBCanaryTarget(t), &envelope) != nil {
		t.Fatal("fixture")
	}
	pack := envelope["pack"].(map[string]any)
	entry := pack["entries"].([]any)[0].(map[string]any)
	evidence := entry["rule"].(map[string]any)["evidence"]
	// These CRD claims are synthetic test fixtures, unlike the frozen semantic
	// entry. Keep their evidence window relative to the actual verifier clock.
	evidence.(map[string]any)["reviewedAt"] = time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
	evidence.(map[string]any)["validUntil"] = time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	rule := map[string]any{"id": "mariadb-operator.synthetic-crd-removal", "operator": "forbid_set_member", "subject": map[string]any{"component": p.Component, "from": "26.3.0", "to": "26.6.0"}, "setCondition": map[string]any{"side": "proposed", "component": p.Component, "factId": p.FactID(), "members": []string{"k8s.mariadb.com/v1alpha1/MariaDB"}}, "evidence": evidence, "reasonCode": "CRD_VERSION_NOT_SERVED", "nextAction": "Synthetic fixture only; use the reviewed served version."}
	pack["entries"] = []any{map[string]any{"project": p.Slug, "description": "Synthetic test-only removal; not a published compatibility claim.", "requiredFacts": []any{map[string]any{"side": "proposed", "id": p.FactID(), "component": p.Component, "type": "set", "enumTokens": nil, "description": "Declared custom-resource versions."}}, "rule": rule}}
	pack["registryDigest"] = req.RegistryDigest
	envelope["engineCapabilityDigest"] = req.EngineCapabilityDigest
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalBundle(raw); err != nil {
		t.Fatal(err)
	}
	input := map[string]any{"schema": "prufyx.io/operator-declared-constraint-input/v1alpha1", "authority": "OPERATOR_DECLARED_MINIMIZED", "current": map[string]any{"components": []any{map[string]any{"component": p.Component, "version": "26.3.0", "facts": []any{}}}}, "proposed": map[string]any{"components": []any{map[string]any{"component": p.Component, "version": "26.6.0", "facts": []any{map[string]any{"id": p.FactID(), "state": "declared", "setValue": map[string]any{"members": []string{}, "complete": true}}}}}}}
	inputRaw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return raw, inputRaw
}

func TestMariaDBExternalReleasedClientProfiles(t *testing.T) {
	binary := os.Getenv("PRUFYX_TEST_RELEASED_CLIENT")
	if binary == "" {
		t.Skip("set PRUFYX_TEST_RELEASED_CLIENT to the retained released executable")
	}
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	legacy, input := mariaDBCRDTarget(t, false)
	canary, _ := mariaDBCRDTarget(t, true)
	store := filepath.Join(t.TempDir(), "store")
	root := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	xdg := t.TempDir()
	run := func(args ...string) (int, string) {
		cmd := exec.CommandContext(t.Context(), binary, args...)
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+xdg, "XDG_DATA_HOME="+xdg, "XDG_CACHE_HOME="+xdg)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return 0, string(out)
		}
		if e, ok := err.(*exec.ExitError); ok {
			return e.ExitCode(), string(out)
		}
		t.Fatal(err)
		return -1, ""
	}
	pack, err := repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: mariaDBTargets(t, legacy, "mariadb-operator")})
	if err != nil {
		t.Fatal(err)
	}
	path := writeCNCFFile(t, "legacy.tar", pack, 0o600)
	code, out := run("db", "import", path, "--profile", "cncf-projects", "--db-root", store, "--bootstrap-root", root, "--bootstrap-root-digest", repo.RootDigest, "--format", "json")
	if code != 0 {
		t.Fatalf("released legacy import exit=%d output=%s", code, out)
	}
	t.Logf("released legacy import exit=%d", code)
	inputPath := writeCNCFFile(t, "input.json", input, 0o600)
	code, out = run("check", "cncf", "--project", "mariadb-operator", "--input", inputPath, "--knowledge-db", store, "--format", "json")
	if code != 2 || !strings.Contains(out, `unknown project "mariadb-operator"`) {
		t.Fatalf("released MariaDB route changed exit=%d output=%s", code, out)
	}
	t.Logf("released MariaDB CRD import=0; check exit=%d unknown project; no decision", code)
	// Prove a genuinely supported legacy CNCF route independently. The
	// MariaDB import above never becomes a claimed semantic or CRD decision.
	legacyCNCF, err := knowledgefixture.GenerateConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var manifest knowledgefixture.Manifest
	if json.Unmarshal(legacyCNCF.Manifest, &manifest) != nil {
		t.Fatal("legacy manifest")
	}
	cncfStore := filepath.Join(t.TempDir(), "store")
	cncfRoot := writeCNCFFile(t, "cncf-root.json", legacyCNCF.Root, 0o600)
	cncfPack := writeCNCFFile(t, "cncf.tar", legacyCNCF.Revision2, 0o600)
	code, out = run("db", "import", cncfPack, "--profile", "cncf", "--db-root", cncfStore, "--bootstrap-root", cncfRoot, "--bootstrap-root-digest", manifest.BootstrapRoot.Digest, "--format", "json")
	if code != 0 {
		t.Fatalf("released CNCF import exit=%d output=%s", code, out)
	}
	cncfInput := writeCNCFFile(t, "cncf-input.json", []byte(kyvernoInputFalse), 0o600)
	code, out = run("check", "cncf", "--project", "kyverno", "--input", cncfInput, "--knowledge-db", cncfStore, "--format", "json")
	if code != 0 || !strings.Contains(out, `"status":"PASS"`) || !strings.Contains(out, `"origin":"external_signed_local"`) {
		t.Fatalf("released supported CNCF check exit=%d output=%s", code, out)
	}
	t.Logf("released supported legacy CNCF kyverno check exit=%d scoped PASS", code)
	before, err := knowledge.InspectConstraintsProjects(store)
	if err != nil {
		t.Fatal(err)
	}
	targets := mariaDBTargets(t, canary, "mariadb-operator")
	var index mariaDBTestIndex
	_ = json.Unmarshal(targets[cncfcheck.ExternalIndexTargetPath], &index)
	for i, minClient := range []string{"v0.1.0-beta.1", ""} {
		index.MinClient = minClient
		targets[cncfcheck.ExternalIndexTargetPath], _ = json.Marshal(index)
		pack, err = repo.Package(knowledgefixture.ProjectsPackage{Version: int64(i + 2), Targets: targets})
		if err != nil {
			t.Fatal(err)
		}
		path = writeCNCFFile(t, "canary.tar", pack, 0o600)
		code, out = run("db", "import", path, "--profile", "cncf-projects", "--db-root", store, "--format", "json")
		if code != 15 {
			t.Fatalf("released incompatible import min=%q exit=%d output=%s", minClient, code, out)
		}
		after, err := knowledge.InspectConstraintsProjects(store)
		if err != nil {
			t.Fatal(err)
		}
		if before.TrustStateDigest != after.TrustStateDigest || before.SelectedBundleDigest != after.SelectedBundleDigest || before.SelectedRevision != after.SelectedRevision {
			t.Fatal("released incompatible profile advanced store")
		}
		t.Logf("released incompatible import min=%q exit=%d trust=%s selection=%s unchanged", minClient, code, after.TrustStateDigest, after.SelectedBundleDigest)
	}
}

func TestMariaDBExternalCurrentCRDProfiles(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	legacy, input := mariaDBCRDTarget(t, false)
	canary, _ := mariaDBCRDTarget(t, true)
	inputPath := writeCNCFFile(t, "input.json", input, 0o600)
	// Library integration only: generic check cncf still refuses this dataless
	// community catalog project before selecting an external store. This is
	// not client-visible CRD coverage or a new decided pair.
	for _, raw := range [][]byte{legacy, canary} {
		s, _, err := importMariaDBFixture(t, repo, mariaDBTargets(t, raw, "mariadb-operator"), nil)
		if err != nil {
			t.Fatal(err)
		}
		code, out, stderr := runCNCFCLI(t, "check", "cncf", "--project", "mariadb-operator", "--input", inputPath, "--knowledge-db", s, "--format", "json")
		if code != ExitUsage || out != "" || !strings.Contains(stderr, `unknown project "mariadb-operator"`) {
			t.Fatalf("generic CLI boundary changed code=%d out=%s stderr=%s", code, out, stderr)
		}
		report, err := cncfknowledge.EvaluateCurrent(cncfknowledge.Request{Selection: knowledge.SelectionRequest{StoreRoot: s}, Project: "mariadb-operator", Input: input, InputDigest: digestCommunityBytes(input)})
		if err != nil || cncfknowledge.ClaimExit(report) != ExitUnknown || len(report.Check.Check.Claims) != 1 || report.Check.Check.Claims[0].Status != "PASS" || report.Assessment != "UNKNOWN" || report.Knowledge.ProjectTarget == nil || report.Knowledge.ProjectTarget.Digest != digestCommunityBytes(raw) {
			t.Fatalf("library CRD profile report=%+v err=%v", report, err)
		}
	}
}

func mariaDBCanaryTarget(t *testing.T) []byte {
	t.Helper()
	raw, err := projectcheck.EmbeddedRulePack()
	if err != nil {
		t.Fatal(err)
	}
	_, entries, err := projectcheck.AdmittedPackView(raw)
	if err != nil {
		t.Fatal(err)
	}
	var selected json.RawMessage
	for _, entry := range entries {
		if bytes.Contains(entry, []byte(cncfcheck.MariaDBCanaryRuleID)) {
			selected = entry
		}
	}
	if selected == nil {
		t.Fatal("missing existing canary")
	}
	req, err := cncfcheck.MariaDBCanaryProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	value := map[string]any{"schema": req.Schema, "revision": "7", "purpose": "synthetic_test_only", "engineCapabilityDigest": req.EngineCapabilityDigest, "pack": map[string]any{"schema": req.PackSchema, "revision": "7", "policyId": req.PolicyID, "policyDigest": req.PolicyDigest, "landscapeFileDigest": req.LandscapeFileDigest, "registryDigest": req.RegistryDigest, "entries": []json.RawMessage{selected}}}
	raw, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cncfcheck.ParseExternalBundle(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func mariaDBTargets(t *testing.T, raw []byte, project string) map[string][]byte {
	t.Helper()
	b, err := cncfcheck.ParseExternalBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := b.Admission()
	if err != nil {
		t.Fatal(err)
	}
	entry := cncfcheck.ExternalIndexEntry{Project: project, TargetPath: cncfcheck.ProjectTargetPath(project), Revision: a.Revision, Length: int64(len(raw)), Digest: digestCommunityBytes(raw), RuleDigest: a.RuleDigest, EvidenceExpiresAt: a.EvidenceExpiresAt, Records: a.HasRecords}
	schema := cncfcheck.ExternalIndexSchema
	if a.HasRecords {
		schema = cncfcheck.ExternalIndexSchemaRecords
	}
	if cncfcheck.IsCommunityProject(project) {
		entry.Catalog = cncfcheck.CatalogCommunity
		schema = cncfcheck.ExternalIndexSchemaCommunity
	}
	index, err := json.Marshal(mariaDBTestIndex{Schema: schema, Revision: "7", Purpose: a.Purpose, Capability: a.EngineCapabilityDigest, Projects: []cncfcheck.ExternalIndexEntry{entry}})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{cncfcheck.ExternalIndexTargetPath: index, entry.TargetPath: raw}
}

func importMariaDBFixture(t *testing.T, repo *knowledgefixture.ProjectsRepository, targets map[string][]byte, replacement map[string][]byte) (string, knowledge.ImportReceipt, error) {
	t.Helper()
	pack, err := repo.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: targets, Replace: replacement})
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(t.TempDir(), "store")
	root := writeCNCFFile(t, "root.json", repo.Root, 0o600)
	path := writeCNCFFile(t, "package.tar", pack, 0o600)
	receipt, err := knowledge.ImportConstraintsProjects(knowledge.ImportRequest{StoreRoot: store, PackagePath: path, BootstrapRootPath: root, BootstrapRootDigest: repo.RootDigest})
	return store, receipt, err
}

func TestMariaDBExternalSignedSelection(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repo, err := knowledgefixture.NewProjectsRepository(now)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	target := mariaDBCanaryTarget(t)
	store, receipt, err := importMariaDBFixture(t, repo, mariaDBTargets(t, target, "mariadb-operator"), nil)
	if err != nil || receipt.Status != "IMPORTED" {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	for _, tc := range []struct {
		name, raw string
		want      int
	}{
		{"fixed", mariadbOperatorTestResource, ExitOK},
		{"broken", strings.Replace(mariadbOperatorTestResource, `"autoUpdateDataPlane":true`, `"autoUpdateDataPlane":false`, 1), ExitBlocked},
		{"missing", strings.Replace(mariadbOperatorTestResource, `"autoUpdateDataPlane":true`, "", 1), ExitUnknown},
		{"null", strings.Replace(mariadbOperatorTestResource, `"autoUpdateDataPlane":true`, `"autoUpdateDataPlane":null`, 1), ExitUnknown},
		{"invalid-galera", strings.Replace(mariadbOperatorTestResource, `"enabled":true`, `"enabled":"true"`, 1), ExitUnknown},
		{"standalone", strings.Replace(mariadbOperatorTestResource, `"enabled":true`, `"enabled":false`, 1), ExitUnknown},
		{"replication", strings.Replace(mariadbOperatorTestResource, `"galera":`, `"replication":{"enabled":true},"galera":`, 1), ExitUnknown},
		{"invalid-replication", strings.Replace(mariadbOperatorTestResource, `"galera":`, `"replication":{"enabled":null},"galera":`, 1), ExitUnknown},
		{"phase", mariadbOperatorTestResource, ExitUnknown},
		{"complete", mariadbOperatorTestResource, ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "resource.json", []byte(tc.raw), 0o600)
			args := []string{"check", "project", "--project", "mariadb-operator", "--mariadb-resource", path, "--from", "26.3.0", "--to", "26.6.0", "--knowledge-db", store, "--format", "json"}
			if tc.name != "phase" {
				args = append(args, "--pre-operator-update")
			}
			if tc.name != "complete" {
				args = append(args, "--resource-complete")
			}
			code, out, stderr := runCNCFCLI(t, args...)
			want := tc.want
			// The semantic evidence window is frozen, not renewed by a test.
			expires, _ := time.Parse(time.RFC3339, "2026-12-12T08:16:03Z")
			if !now.Before(expires) {
				want = ExitUnknown
			}
			if code != want || stderr != "" || strings.Contains(out, "PRIVATE_OPERATOR_NATIVE") {
				t.Fatalf("code=%d out=%s stderr=%s", code, out, stderr)
			}
			var report cncfknowledge.Report
			if json.Unmarshal([]byte(out), &report) != nil {
				t.Fatal(out)
			}
			if report.Assessment != "UNKNOWN" || report.Knowledge.Origin != "external_signed_local" || report.Knowledge.TrustReceiptDigest != receipt.TrustReceiptDigest || report.Knowledge.ProjectTarget == nil || report.Knowledge.ProjectTarget.Digest != digestCommunityBytes(target) || len(report.Check.Check.Claims) != 1 || len(report.Check.Check.Claims[0].Sources) != 8 {
				t.Fatalf("binding=%s", out)
			}
			prepared, _ := projectprepare.PrepareMariaDBOperatorResource([]byte(tc.raw), "26.3.0", "26.6.0", tc.name != "complete", tc.name != "phase")
			if report.Check.InputFileDigest != prepared.InputDigest {
				t.Fatal("input digest not bound")
			}
			code, out, _ = runCNCFCLI(t, append(args, "--now", "2026-09-13T09:00:00Z")...)
			if code != ExitUsage || out != "" {
				t.Fatal("external caller clock accepted")
			}
		})
	}
	// Retained same-input/current-context replay has the same selected bindings.
	prepared, _ := projectprepare.PrepareMariaDBOperatorResource([]byte(mariadbOperatorTestResource), "26.3.0", "26.6.0", true, true)
	selected, err := knowledge.OpenSelectedCNCF(knowledge.SelectionRequest{StoreRoot: store}, []string{"mariadb-operator"})
	if err != nil {
		t.Fatal(err)
	}
	input := cncfknowledge.CheckInput{Project: "mariadb-operator", SelectedRuleID: cncfcheck.MariaDBCanaryRuleID, Input: prepared.CanonicalInputJSON, InputDigest: prepared.InputDigest}
	a, err := cncfknowledge.EvaluateVerified(selected, input)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cncfknowledge.EvaluateVerified(selected, input)
	if err != nil {
		t.Fatal(err)
	}
	araw, _ := cncfknowledge.MarshalReport(a)
	braw, _ := cncfknowledge.MarshalReport(b)
	if !bytes.Equal(araw, braw) {
		t.Fatal("same verified context changed")
	}
	// Tampering persisted selection never invokes the embedded evaluator.
	var saved string
	err = filepath.WalkDir(store, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			raw, _ := os.ReadFile(path)
			if bytes.Equal(raw, target) {
				saved = path
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved == "" {
		t.Fatal("retained target not found")
	}
	if err := os.WriteFile(saved, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeCNCFFile(t, "resource.json", []byte(mariadbOperatorTestResource), 0o600)
	code, out, _ := runCNCFCLI(t, "check", "project", "--project", "mariadb-operator", "--mariadb-resource", path, "--from", "26.3.0", "--to", "26.6.0", "--knowledge-db", store, "--format", "json")
	if code != ExitIntegrity || out != "" {
		t.Fatalf("tamper fallback code=%d out=%s", code, out)
	}
}

func TestMariaDBExternalSignedBindingFailures(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	target := mariaDBCanaryTarget(t)
	for _, name := range []string{"target-digest", "wrong-project", "signature", "predicate", "guard", "source", "missing-index"} {
		t.Run(name, func(t *testing.T) {
			targets := mariaDBTargets(t, target, "mariadb-operator")
			var replacements map[string][]byte
			if name == "target-digest" {
				replacements = map[string][]byte{cncfcheck.ProjectTargetPath("mariadb-operator"): []byte(`{}`)}
			}
			if name == "wrong-project" {
				targets = mariaDBTargets(t, target, "gateway-api")
			}
			if name == "missing-index" {
				delete(targets, cncfcheck.ExternalIndexTargetPath)
			}
			if name == "predicate" || name == "guard" || name == "source" {
				var value map[string]any
				_ = json.Unmarshal(target, &value)
				rule := value["pack"].(map[string]any)["entries"].([]any)[0].(map[string]any)["rule"].(map[string]any)
				if name == "predicate" {
					rule["condition"].(map[string]any)["boolValue"] = true
				}
				if name == "guard" {
					rule["appliesWhen"] = []any{}
				}
				if name == "source" {
					rule["evidence"].(map[string]any)["sources"].([]any)[0].(map[string]any)["contentDigest"] = "sha256:" + strings.Repeat("0", 64)
				}
				changed, _ := json.Marshal(value)
				targets[cncfcheck.ProjectTargetPath("mariadb-operator")] = changed
				var index mariaDBTestIndex
				_ = json.Unmarshal(targets[cncfcheck.ExternalIndexTargetPath], &index)
				index.Projects[0].Digest = digestCommunityBytes(changed)
				index.Projects[0].Length = int64(len(changed))
				targets[cncfcheck.ExternalIndexTargetPath], _ = json.Marshal(index)
			}
			if name == "signature" {
				other, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				pack, err := other.Package(knowledgefixture.ProjectsPackage{Version: 1, Targets: targets})
				if err != nil {
					t.Fatal(err)
				}
				store := filepath.Join(t.TempDir(), "store")
				root := writeCNCFFile(t, "root.json", repo.Root, 0o600)
				path := writeCNCFFile(t, "other.tar", pack, 0o600)
				_, err = knowledge.ImportConstraintsProjects(knowledge.ImportRequest{StoreRoot: store, PackagePath: path, BootstrapRootPath: root, BootstrapRootDigest: repo.RootDigest})
				if err == nil {
					t.Fatal("wrong signer accepted")
				}
				return
			}
			_, receipt, err := importMariaDBFixture(t, repo, targets, replacements)
			if err == nil || receipt.Status == "IMPORTED" {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
}

func TestMariaDBExternalMissingCanarySignedIndex(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	_, projects, err := cncfcheck.BuildEmbeddedExternalTargets("7", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) == 0 {
		t.Fatal("no retained target")
	}
	project, ok := cncfcheck.ProjectFromTargetPath(projects[0].Path)
	if !ok || project == "mariadb-operator" {
		t.Fatal("retained other project")
	}
	var envelope map[string]any
	if json.Unmarshal(projects[0].Bytes, &envelope) != nil {
		t.Fatal("retained envelope")
	}
	req, err := cncfcheck.MariaDBCanaryProfileRequirements()
	if err != nil {
		t.Fatal(err)
	}
	envelope["engineCapabilityDigest"] = req.EngineCapabilityDigest
	envelope["pack"].(map[string]any)["registryDigest"] = req.RegistryDigest
	other, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	crd, _ := mariaDBCRDTarget(t, true)
	for _, tc := range []struct {
		name, project, status string
		raw                   []byte
	}{{"absent", project, "absent_from_index", other}, {"omitted-canary", "mariadb-operator", "present", crd}} {
		t.Run(tc.name, func(t *testing.T) {
			store, _, err := importMariaDBFixture(t, repo, mariaDBTargets(t, tc.raw, tc.project), nil)
			if err != nil {
				t.Fatal(err)
			}
			path := writeCNCFFile(t, "resource.json", []byte(mariadbOperatorTestResource), 0o600)
			code, out, stderr := runCNCFCLI(t, "check", "project", "--project", "mariadb-operator", "--mariadb-resource", path, "--from", "26.3.0", "--to", "26.6.0", "--resource-complete", "--pre-operator-update", "--knowledge-db", store, "--format", "json")
			var report cncfknowledge.Report
			if code != ExitUnknown || stderr != "" || json.Unmarshal([]byte(out), &report) != nil || len(report.Check.Check.Claims) != 0 || report.Knowledge.EngineCapabilityDigest != req.EngineCapabilityDigest || report.Knowledge.ProjectTarget == nil || report.Knowledge.ProjectTarget.Status != tc.status {
				t.Fatalf("code=%d out=%s stderr=%s", code, out, stderr)
			}
		})
	}
}

func TestMariaDBExternalHumanBinding(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	target := mariaDBCanaryTarget(t)
	store, receipt, err := importMariaDBFixture(t, repo, mariaDBTargets(t, target, "mariadb-operator"), nil)
	if err != nil {
		t.Fatal(err)
	}
	path := writeCNCFFile(t, "resource.json", []byte(mariadbOperatorTestResource), 0o600)
	code, out, stderr := runCNCFCLI(t, "check", "project", "--project", "mariadb-operator", "--mariadb-resource", path, "--from", "26.3.0", "--to", "26.6.0", "--resource-complete", "--pre-operator-update", "--knowledge-db", store, "--verbose")
	want := ExitOK
	expires, _ := time.Parse(time.RFC3339, "2026-12-12T08:16:03Z")
	if !time.Now().UTC().Before(expires) {
		want = ExitUnknown
	}
	if code != want || stderr != "" || !strings.Contains(out, receipt.TrustReceiptDigest) || !strings.Contains(out, digestCommunityBytes(target)) || !strings.Contains(out, "whole-upgrade assessment: UNKNOWN") || strings.Contains(out, "PRIVATE_OPERATOR_NATIVE") {
		t.Fatalf("human code=%d out=%s stderr=%s", code, out, stderr)
	}
}

// mariaDBFixtureRuleDigest uses the engine independently of target admission
// so an invalid semantic identity still has a correctly bound signed index.
func mariaDBFixtureRuleDigest(t *testing.T, envelope map[string]any, canary bool) string {
	t.Helper()
	definitions := cncfcheck.CompiledFactDefinitions()
	if canary {
		for _, id := range []string{projectprepare.MariaDBOperatorAutoUpdateFact, projectprepare.MariaDBOperatorGaleraFact, projectprepare.MariaDBOperatorReplicationFact, projectprepare.MariaDBOperatorPreUpdateFact, projectprepare.MariaDBOperatorResourceCompleteFact} {
			definitions = append(definitions, constraintengine.FactDefinition{ID: id, Component: projectprepare.MariaDBOperatorComponent, Type: constraintengine.FactBool})
		}
	}
	registry, err := constraintengine.NewCompiledRegistry(definitions)
	if err != nil {
		t.Fatal(err)
	}
	pack := envelope["pack"].(map[string]any)
	if registry.Digest() != pack["registryDigest"] {
		t.Fatal("fixture registry differs from selected profile")
	}
	rule, err := json.Marshal(pack["entries"].([]any)[0].(map[string]any)["rule"])
	if err != nil {
		t.Fatal(err)
	}
	rules := []json.RawMessage{rule}
	schema, err := constraintengine.RulesSchemaFor(rules)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"schema": schema, "revision": pack["revision"], "policyId": pack["policyId"], "policyDigest": pack["policyDigest"], "rules": rules})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := constraintengine.ParseRuleSet(raw, registry)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := parsed.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestMariaDBExternalReservedIDSubstitution(t *testing.T) {
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	for _, canary := range []bool{false, true} {
		name := "legacy"
		if canary {
			name = "canary"
		}
		t.Run(name, func(t *testing.T) {
			original, _ := mariaDBCRDTarget(t, canary)
			targets := mariaDBTargets(t, original, "mariadb-operator")
			_, receipt, err := importMariaDBFixture(t, repo, targets, nil)
			if err != nil || receipt.Status != "IMPORTED" {
				t.Fatalf("legitimate CRD import=%+v err=%v", receipt, err)
			}
			var envelope map[string]any
			if json.Unmarshal(original, &envelope) != nil {
				t.Fatal("fixture")
			}
			envelope["pack"].(map[string]any)["entries"].([]any)[0].(map[string]any)["rule"].(map[string]any)["id"] = cncfcheck.MariaDBCanaryRuleID
			forged, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cncfcheck.ParseExternalBundle(forged); err == nil {
				t.Error("direct reserved semantic ID substitution admitted")
			}
			var index mariaDBTestIndex
			if json.Unmarshal(targets[cncfcheck.ExternalIndexTargetPath], &index) != nil {
				t.Fatal("index")
			}
			index.Projects[0].Digest = digestCommunityBytes(forged)
			index.Projects[0].Length = int64(len(forged))
			index.Projects[0].RuleDigest = mariaDBFixtureRuleDigest(t, envelope, canary)
			targets[cncfcheck.ProjectTargetPath("mariadb-operator")] = forged
			targets[cncfcheck.ExternalIndexTargetPath], err = json.Marshal(index)
			if err != nil {
				t.Fatal(err)
			}
			_, receipt, err = importMariaDBFixture(t, repo, targets, nil)
			if err == nil || receipt.Status == "IMPORTED" {
				t.Errorf("valid-signed reserved semantic ID substitution admitted: status=%s err=%v", receipt.Status, err)
			}
		})
	}
}
