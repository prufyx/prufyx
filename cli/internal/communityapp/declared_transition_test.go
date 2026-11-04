// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/certmanagervalues"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
)

// The edited state is authored test input, never a captured upgrade output.
func declaredFixture(t *testing.T) (declaredRequest, string) {
	t.Helper()
	dir := t.TempDir()
	complete := true
	good := []string{`{"prometheus":{"servicemonitor":{"enabled":true}}}`, `{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","spec":{"endpointSelector":{}}}`, `{"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"example"}}`}
	bad := []string{`{"prometheus":{"servicemonitor":{"path":"/custom"}}}`, `{"apiVersion":"cilium.io/v2","kind":"CiliumNetworkPolicy","spec":{"ingress":[{"fromRequires":[{"matchLabels":{"example":"value"}}]}]}}`, `{"apiVersion":"batch/v1beta1","kind":"CronJob","metadata":{"name":"example"}}`}
	roles := []string{"cert-manager", "cilium", "kubernetes"}
	req := declaredRequest{Schema: declaredSchema, Context: declaredContext{Target: "synthetic-target", Intent: "declared upgrade", KnowledgeOrigin: "embedded", EvaluatedAt: supersedeids.ClockString(), TrustBases: cncfcheck.DefaultTrustPolicy().String(), CertManagerKnowledgeDigest: certmanagervalues.SourceContractDigest}}
	for i, name := range []string{"B0", "B1", "B2", "B3", "B4"} {
		m := declaredManifest{Schema: declaredSchema, Target: req.Context.Target, Intent: req.Context.Intent, Components: []declaredComponent{{"cert-manager", "1.20.3", "official-chart-merged-values"}, {"cilium", "1.18.6", "official-policy-set"}, {"kubernetes", "1.24.17", "official-rendered-apply-set"}}}
		if i >= 2 {
			m.Components[2].Version = "1.25.3"
		}
		if i >= 3 {
			m.Components[1].Version = "1.19.0"
		}
		if i >= 4 {
			m.Components[0].Version = "1.21.1"
		}
		a := declaredArtifact{Name: name, Manifest: m}
		for j, role := range roles {
			raw := good[j]
			if i == 0 {
				raw = bad[j]
			}
			entry := declaredEntry{Role: role, LogicalName: role + "-input", Length: len(raw), Digest: declaredHash([]byte(raw)), Complete: &complete, Distribution: "official_upstream", TargetApplyRequired: true}
			if role == "cert-manager" {
				entry.SchemaValidation = "required"
				entry.ChartDigest = certmanagervalues.CurrentChartDigest
				if i == 4 {
					entry.ChartDigest = certmanagervalues.TargetChartDigest
				}
			}
			path := name + "-" + role + ".json"
			if err := os.WriteFile(filepath.Join(dir, path), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			a.Manifest.Entries = append(a.Manifest.Entries, entry)
			a.Files = append(a.Files, declaredFile{role, entry.LogicalName, path})
		}
		req.Artifacts = append(req.Artifacts, a)
	}
	for i, component := range []string{"declared-edit", "kubernetes", "cilium", "cert-manager"} {
		before, after := req.Artifacts[i], req.Artifacts[i+1]
		b, _ := json.Marshal(before.Manifest)
		a, _ := json.Marshal(after.Manifest)
		s := declaredStage{Index: i, Component: component, Before: before.Name, After: after.Name, BeforeDigest: declaredHash(b), AfterDigest: declaredHash(a)}
		if component != "declared-edit" {
			for _, c := range before.Manifest.Components {
				if c.Name == component {
					s.From = c.Version
				}
			}
			for _, c := range after.Manifest.Components {
				if c.Name == component {
					s.To = c.Version
				}
			}
		}
		req.Stages = append(req.Stages, s)
	}
	// Obtain context assertions from a real engine issuance, independently of
	// the linkage evaluator; no caller report is handed to that evaluator.
	p, err := cncfprepare.PrepareCilium([]byte(good[1]), "1.18.6", "1.19.0", &complete)
	if err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339, req.Context.EvaluatedAt)
	r, err := cncfcheck.WithTrustPolicy(cncfcheck.DefaultTrustPolicy()).CheckFacts("cilium", []string{cncfprepare.CiliumRequiresFact}, p.CanonicalInputJSON, now)
	if err != nil {
		t.Fatal(err)
	}
	req.Context.PolicyID = r.Check.PolicyID
	req.Context.PolicyDigest = r.Check.PolicyDigest
	req.Context.KnowledgeRevision = r.KnowledgeRevision
	req.Context.KnowledgeDigest = r.KnowledgePackDigest
	return req, dir
}

func evaluateDeclaredFixture(t *testing.T, req declaredRequest, dir string) (declaredResult, map[string]admittedDeclaredArtifact) {
	t.Helper()
	a, err := admitDeclared(req, dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := evaluateDeclared(req, a)
	if err != nil {
		t.Fatal(err)
	}
	return r, a
}

func TestDeclaredRealRoutesReferenceLinkageAndReplay(t *testing.T) {
	req, dir := declaredFixture(t)
	r, a := evaluateDeclaredFixture(t, req, dir)
	if r.Status != "UNKNOWN" || len(r.Stages) != 4 || len(r.Omissions) != 5 {
		t.Fatalf("result %+v", r)
	}
	for i, s := range r.Stages {
		if s.Status != "UNKNOWN" {
			t.Fatalf("stage%d %+v", i, s)
		}
		if i > 0 && s.Stage.BeforeDigest != r.Stages[i-1].Stage.AfterDigest {
			t.Fatal("unlinked stage")
		}
	}
	for _, i := range []int{1, 2} {
		var report cncfcheck.Report
		if err := json.Unmarshal(r.Stages[i].Report, &report); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, c := range report.Check.Claims {
			if (i == 1 && c.RuleID == "kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0") || (i == 2 && c.RuleID == "cilium.nonempty-requires-rejected.1-19") {
				found = true
				if c.Status != "PASS" || len(c.Sources) == 0 {
					t.Fatalf("named claim %+v", c)
				}
				for _, source := range c.Sources {
					if source.URL == "" || source.Revision == "" || source.ContentDigest == "" || source.StartLine <= 0 || source.EndLine < source.StartLine {
						t.Fatal("incomplete citation")
					}
				}
				if i == 1 && c.Sources[0].ID != "lifecycle-batch-v1beta1-1-24-0" {
					t.Fatal("unrelated Kubernetes source")
				}
			}
		}
		if !found {
			t.Fatalf("missing named claim: %s", r.Stages[i].Report)
		}
		if r.Stages[i].SourceDigest == r.Stages[i].PreparedInputDigest || r.Stages[i].EngineInputDigest != report.Check.InputDigest || report.Check.RegistryDigest == req.Context.KnowledgeDigest {
			t.Fatal("digest meanings conflated")
		}
	}
	var cert certmanagervalues.Report
	if err := json.Unmarshal(r.Stages[3].Report, &cert); err != nil {
		t.Fatal(err)
	}
	if cert.Claim.Status != "PASS" || cert.Claim.ReasonCode != "CERT_MANAGER_REMOVED_MONITOR_VALUES_ABSENT" || len(cert.Sources) == 0 || !strings.Contains(strings.Join(r.Stages[3].Gaps, " "), "does not bind an evaluation clock") {
		t.Fatalf("cert %+v", cert)
	}
	raw, err := marshalDeclared(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := replayDeclared(req, a, raw); err != nil {
		t.Fatal(err)
	}
	r2, err := evaluateDeclared(req, a)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := marshalDeclared(r2)
	if !bytes.Equal(raw, raw2) {
		t.Fatal("unstable replay")
	}
	if bytes.Contains(raw, []byte("endpointSelector")) || bytes.Contains(raw, []byte("/custom")) {
		t.Fatal("raw document exported")
	}
}

func TestDeclaredOldInputsPreserveNamedBlockers(t *testing.T) {
	for _, stage := range []int{1, 2, 3} {
		t.Run([]string{"", "kubernetes", "cilium", "cert-manager"}[stage], func(t *testing.T) {
			req, dir := declaredFixture(t)
			s := req.Stages[stage]
			s.Index = 0
			s.Before = "B0"
			b, _ := json.Marshal(req.Artifacts[0].Manifest)
			s.BeforeDigest = declaredHash(b)
			req.Stages = []declaredStage{s}
			r, _ := evaluateDeclaredFixture(t, req, dir)
			if r.Status != "BLOCKED" || r.Stages[0].Status != "BLOCKED" {
				t.Fatalf("lost blocker %s", r.Stages[0].Report)
			}
			if stage == 3 {
				var c certmanagervalues.Report
				_ = json.Unmarshal(r.Stages[0].Report, &c)
				if c.Claim.ReasonCode != "CERT_MANAGER_REMOVED_MONITOR_VALUE_PRESENT" || len(c.Sources) == 0 {
					t.Fatal("wrong cert blocker")
				}
				return
			}
			var report cncfcheck.Report
			_ = json.Unmarshal(r.Stages[0].Report, &report)
			found := false
			for _, c := range report.Check.Claims {
				if c.Status == "BLOCKED" && len(c.Sources) > 0 && ((stage == 1 && c.RuleID == "kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0") || (stage == 2 && c.RuleID == "cilium.nonempty-requires-rejected.1-19")) {
					found = true
				}
			}
			if !found {
				t.Fatalf("wrong blocker %s", r.Stages[0].Report)
			}
		})
	}
}

func TestDeclaredTamperAndSubstitutionRejected(t *testing.T) {
	mutations := []struct {
		name   string
		change func(*declaredResult)
	}{
		{"artifact", func(r *declaredResult) { r.Artifacts[1].Digest = r.Artifacts[0].Digest }},
		{"endpoint", func(r *declaredResult) { r.Stages[1].Stage.To = "1.30.4" }},
		{"target", func(r *declaredResult) { r.Context.Target = "other" }},
		{"intent", func(r *declaredResult) { r.Context.Intent = "other" }},
		{"policy", func(r *declaredResult) { r.Context.PolicyDigest = "other" }},
		{"clock", func(r *declaredResult) { r.Context.EvaluatedAt = "2026-11-01T00:00:00Z" }},
		{"knowledge", func(r *declaredResult) { r.Context.KnowledgeDigest = "other" }},
		{"schema-mode", func(r *declaredResult) { r.Artifacts[3].Manifest.Entries[0].SchemaValidation = "disabled" }},
		{"report", func(r *declaredResult) { r.Stages[1].Report = r.Stages[2].Report }},
		{"order", func(r *declaredResult) { r.Stages[1], r.Stages[2] = r.Stages[2], r.Stages[1] }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			req, dir := declaredFixture(t)
			r, _ := evaluateDeclaredFixture(t, req, dir)
			tc.change(&r)
			if _, err := marshalDeclared(r); !errors.Is(err, cncfcheck.ErrIntegrity) {
				t.Fatalf("accepted mutation: %v", err)
			}
		})
	}
	t.Run("valid-report-other-input", func(t *testing.T) {
		req, dir := declaredFixture(t)
		r, _ := evaluateDeclaredFixture(t, req, dir)
		s := req.Stages[1]
		s.Index = 0
		s.Before = "B0"
		b, _ := json.Marshal(req.Artifacts[0].Manifest)
		s.BeforeDigest = declaredHash(b)
		req.Stages = []declaredStage{s}
		other, _ := evaluateDeclaredFixture(t, req, dir)
		r.Stages[1].Report = other.Stages[0].Report
		if _, err := marshalDeclared(r); !errors.Is(err, cncfcheck.ErrIntegrity) {
			t.Fatal("accepted genuine report substitution")
		}
	})
	t.Run("retained-bytes", func(t *testing.T) {
		req, dir := declaredFixture(t)
		r, a := evaluateDeclaredFixture(t, req, dir)
		raw, _ := marshalDeclared(r)
		v := a["B1"]
		v.inputs[2] = append(v.inputs[2], ' ')
		a["B1"] = v
		if err := replayDeclared(req, a, raw); !errors.Is(err, cncfcheck.ErrIntegrity) {
			t.Fatalf("accepted changed bytes: %v", err)
		}
	})
	t.Run("adjacent-state", func(t *testing.T) {
		req, dir := declaredFixture(t)
		a, err := admitDeclared(req, dir)
		if err != nil {
			t.Fatal(err)
		}
		req.Stages[1].Before = "B0"
		b, _ := json.Marshal(req.Artifacts[0].Manifest)
		req.Stages[1].BeforeDigest = declaredHash(b)
		if _, err := evaluateDeclared(req, a); !errors.Is(err, cncfcheck.ErrIntegrity) {
			t.Fatalf("accepted discontinuity %v", err)
		}
	})
	t.Run("context-replay", func(t *testing.T) {
		req, dir := declaredFixture(t)
		r, a := evaluateDeclaredFixture(t, req, dir)
		raw, _ := marshalDeclared(r)
		req.Context.TrustBases = "reviewed"
		if err := replayDeclared(req, a, raw); !errors.Is(err, cncfcheck.ErrIntegrity) {
			t.Fatalf("accepted changed policy selection %v", err)
		}
	})
}

func TestDeclaredMissingBindingsStayUnknown(t *testing.T) {
	req, dir := declaredFixture(t)
	// Remove Cilium completeness without inventing a false absence claim.
	req.Artifacts[2].Manifest.Entries[1].Complete = nil
	for i := range req.Stages {
		for _, side := range []struct {
			name   string
			digest *string
		}{{req.Stages[i].Before, &req.Stages[i].BeforeDigest}, {req.Stages[i].After, &req.Stages[i].AfterDigest}} {
			for _, a := range req.Artifacts {
				if a.Name == side.name {
					b, _ := json.Marshal(a.Manifest)
					*side.digest = declaredHash(b)
				}
			}
		}
	}
	r, _ := evaluateDeclaredFixture(t, req, dir)
	var c cncfcheck.Report
	_ = json.Unmarshal(r.Stages[2].Report, &c)
	for _, claim := range c.Check.Claims {
		if claim.Status == "PASS" {
			t.Fatal("missing completeness passed")
		}
	}
	if r.Status != "UNKNOWN" || !strings.Contains(strings.Join(r.Omissions, " "), "APP_ORDERING_NOT_VERIFIED") {
		t.Fatal("missing boundaries")
	}
	req.Context.KnowledgeOrigin = "external_declared"
	r, _ = evaluateDeclaredFixture(t, req, dir)
	for _, s := range r.Stages {
		if len(s.Report) != 0 {
			t.Fatal("silently fell back to embedded knowledge")
		}
	}
	req.Stages[0].Before = "missing"
	r, _ = evaluateDeclaredFixture(t, req, dir)
	if r.Stages[0].Status != "UNKNOWN" || len(r.Stages[0].Gaps) == 0 {
		t.Fatal("missing state not unknown")
	}
}

func TestDeclaredRealReevaluationRejectsStaleContext(t *testing.T) {
	changes := []struct {
		name   string
		change func(*declaredRequest)
	}{
		{"target", func(q *declaredRequest) {
			q.Context.Target = "other-target"
			for i := range q.Artifacts {
				q.Artifacts[i].Manifest.Target = q.Context.Target
			}
		}},
		{"intent", func(q *declaredRequest) {
			q.Context.Intent = "another-intent"
			for i := range q.Artifacts {
				q.Artifacts[i].Manifest.Intent = q.Context.Intent
			}
		}},
		{"policy", func(q *declaredRequest) { q.Context.PolicyDigest = "sha256:" + strings.Repeat("0", 64) }},
		{"clock", func(q *declaredRequest) { q.Context.EvaluatedAt = "2026-11-19T00:00:00Z" }},
		{"knowledge", func(q *declaredRequest) { q.Context.KnowledgeDigest = "sha256:" + strings.Repeat("0", 64) }},
		{"cert-contract", func(q *declaredRequest) { q.Context.CertManagerKnowledgeDigest = "sha256:" + strings.Repeat("0", 64) }},
		{"schema-mode", func(q *declaredRequest) { q.Artifacts[3].Manifest.Entries[0].SchemaValidation = "disabled" }},
		{"endpoint", func(q *declaredRequest) { q.Stages[1].To = "1.26.0" }},
		{"unsafe-order", func(q *declaredRequest) {
			q.Stages[1], q.Stages[2] = q.Stages[2], q.Stages[1]
			q.Stages[1].Index = 1
			q.Stages[2].Index = 2
		}},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			req, dir := declaredFixture(t)
			r, _ := evaluateDeclaredFixture(t, req, dir)
			receipt, _ := marshalDeclared(r)
			tc.change(&req)
			// Freshly admit the changed declarations, then exercise the actual
			// parsers and evaluators again. A prior receipt never authorizes them.
			for i := range req.Stages {
				for _, a := range req.Artifacts {
					b, _ := json.Marshal(a.Manifest)
					if a.Name == req.Stages[i].Before {
						req.Stages[i].BeforeDigest = declaredHash(b)
					}
					if a.Name == req.Stages[i].After {
						req.Stages[i].AfterDigest = declaredHash(b)
					}
				}
			}
			a, err := admitDeclared(req, dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := replayDeclared(req, a, receipt); !errors.Is(err, cncfcheck.ErrIntegrity) {
				t.Fatalf("stale receipt accepted: %v", err)
			}
		})
	}
}

func TestDeclaredCertTargetMultiplicityRejected(t *testing.T) {
	for _, wrongFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "wrong-first-valid-last", false: "valid-first-wrong-last"}[wrongFirst], func(t *testing.T) {
			req, dir := declaredFixture(t)
			a := &req.Artifacts[4]
			first, last := a.Manifest.Entries[0], a.Manifest.Entries[0]
			first.LogicalName = "a-values"
			last.LogicalName = "z-values"
			if wrongFirst {
				first.ChartDigest = "sha256:" + strings.Repeat("0", 64)
			} else {
				last.ChartDigest = "sha256:" + strings.Repeat("0", 64)
			}
			a.Manifest.Entries = append([]declaredEntry{first, last}, a.Manifest.Entries[1:]...)
			f := a.Files[0]
			f.LogicalName = first.LogicalName
			g := a.Files[0]
			g.LogicalName = last.LogicalName
			a.Files = append([]declaredFile{f, g}, a.Files[1:]...)
			manifest, _ := json.Marshal(a.Manifest)
			req.Stages[3].AfterDigest = declaredHash(manifest)
			// Both permutations have canonical (role, logicalName) order. Both
			// complete inputs remain admitted; neither may select a target by order.
			raw, _ := json.Marshal(req)
			if _, err := decodeDeclared(raw); err != nil {
				t.Fatal(err)
			}
			admitted, err := admitDeclared(req, dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(admitted["B4"].inputs) != 4 {
				t.Fatal("required inputs dropped")
			}
			if _, err := evaluateDeclared(req, admitted); !errors.Is(err, cncfcheck.ErrIntegrity) {
				t.Fatalf("ambiguous target accepted: %v", err)
			}
		})
	}
}

func TestDeclaredMissingTrustBasesDefaultAndBlocker(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-policy-clean", true: "missing-policy-blocked"}[blocked], func(t *testing.T) {
			req, dir := declaredFixture(t)
			req.Context.TrustBases = ""
			if blocked {
				s := req.Stages[1]
				s.Index = 0
				s.Before = "B0"
				b, _ := json.Marshal(req.Artifacts[0].Manifest)
				s.BeforeDigest = declaredHash(b)
				req.Stages = []declaredStage{s}
			}
			r, _ := evaluateDeclaredFixture(t, req, dir)
			if r.Context.TrustBases != "" {
				t.Fatal("invented caller policy")
			}
			index := 1
			status := "UNKNOWN"
			if blocked {
				index = 0
				status = "BLOCKED"
			}
			if r.Status != status || r.Stages[index].Status != status || !strings.Contains(strings.Join(r.Stages[index].Gaps, " "), "engine used its default policy") {
				t.Fatalf("missing policy result %+v", r)
			}
			var report cncfcheck.Report
			if err := json.Unmarshal(r.Stages[index].Report, &report); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, c := range report.Check.Claims {
				if c.RuleID == "kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0" {
					found = true
					want := "PASS"
					if blocked {
						want = "BLOCKED"
					}
					if c.Status != want || len(c.Sources) == 0 {
						t.Fatalf("named finding lost %+v", c)
					}
				}
			}
			if !found {
				t.Fatal("named finding missing")
			}
		})
	}
	for _, policy := range []string{"unrecognized", "reviewed,reviewed"} {
		t.Run("malformed-"+policy, func(t *testing.T) {
			req, dir := declaredFixture(t)
			req.Context.TrustBases = policy
			a, err := admitDeclared(req, dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := evaluateDeclared(req, a); !errors.Is(err, cncfcheck.ErrInvalid) {
				t.Fatalf("malformed policy accepted: %v", err)
			}
		})
	}
}

func TestDeclaredFileAdmissionAndCLI(t *testing.T) {
	req, dir := declaredFixture(t)
	raw, _ := json.Marshal(req)
	if _, err := decodeDeclared(raw); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1), append(raw, []byte(`{}`)...), bytes.Replace(raw, []byte(`"target":`), []byte(`"unknown":"x","target":`), 1)} {
		if _, err := decodeDeclared(invalid); err == nil {
			t.Fatal("accepted ambiguous request")
		}
	}
	path := filepath.Join(dir, "request.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := runPlan(t, "--declared-state", path); code != 11 || !strings.Contains(out, "NO_OBSERVED_STAGE_OUTPUT") {
		t.Fatalf("CLI %d %s %s", code, out, stderr)
	}
	for _, kind := range []string{"escape", "symlink", "hardlink", "public", "changed", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			req, dir := declaredFixture(t)
			file := &req.Artifacts[0].Files[0]
			path := filepath.Join(dir, file.Path)
			switch kind {
			case "escape":
				file.Path = "../outside.json"
			case "symlink":
				link := filepath.Join(dir, "linked.json")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				file.Path = "linked.json"
			case "hardlink":
				if err := os.Link(path, filepath.Join(dir, "hard.json")); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "changed":
				if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(path, bytes.Repeat([]byte(" "), declaredLimit+1), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := admitDeclared(req, dir); err == nil {
				t.Fatal("unsafe admission")
			}
		})
	}
}
