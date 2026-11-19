// SPDX-License-Identifier: AGPL-3.0-only

package qareport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	imgA = "kindest/node@sha256:6110314339b3b44d10da7d27881849a87e092124afab5956f2e10ecdb463b025"
	imgB = "kindest/node@sha256:c79602a44b4056d7e48dc20f7504350f1e87530fe953428b792def00bc1076dd"
	dig  = "57ba9461c014d6439c0c5db9dd21fa5cb1fe9e359a16f2c39bbb75e4ec9b93cf"
	cmt  = "28fc30c183e8c2c9af1d3a483bbec42a27378ba7"
)

// leaks are values put into every free field of the fixtures.
var leaks = []string{"leakhost-7", "10.9.8.7", "/srv/private/path", "leakuser-name", "worker-42", "free text note"}

func m3(mut func(m map[string]any)) []byte {
	check := func(app, class, result, verdict string, ids []string) map[string]any {
		return map[string]any{
			"app": app, "artifactDigests": map[string]string{"rendered.yaml": dig},
			"assertion": map[string]any{"command": "scan", "ids": ids, "verdict": verdict},
			"class":     class, "fromVersion": "6.0.0", "toVersion": "6.1.0", "logDigest": dig,
			"logPath": "/srv/private/path/leakhost-7.out",
			"oracle":  map[string]any{"type": "replay-on-target", "observed": "rejected on leakhost-7 10.9.8.7 free text note"},
			"project": "kubernetes", "result": result,
		}
	}
	m := map[string]any{
		"runId": "m3-x", "host": "leakhost-7", "k8sFrom": "1.25.16", "k8sTo": "1.26.15",
		"kindVersion": "from=v0.24.0 /srv/private/path", "startedAt": "2026-11-18T15:00:00Z", "finishedAt": "2026-11-18T15:17:10Z",
		"clusters": []map[string]string{{"kindNodeImage": imgA, "role": "from"}, {"kindNodeImage": imgB, "role": "to"}},
		"logs":     map[string]string{"x.out": dig}, "prufyxBinarySha256": dig, "prufyxCommit": cmt + " leakuser-name worker-42",
		"prufyxCommitSource": "build record leakhost-7",
		"checks": []map[string]any{
			check("podinfo", "correct", "confirmed", "BLOCKED kubernetes.served-api-removal.autoscaling-v2beta2.1-25-0-to-1-26-0 leakhost-7", []string{"kubernetes.served-api-removal.autoscaling-v2beta2.1-25-0-to-1-26-0"}),
			check("?", "gap", "gap", "NOT CHECKED API_VERSION_NOT_REVIEWED: 3 manifest(s) on 10.9.8.7", []string{"API_VERSION_NOT_REVIEWED"}),
			check("keda", "WRONG PASS", "refuted", "custom resources evaluated", nil),
		},
	}
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func first(m map[string]any) map[string]any { return m["checks"].([]map[string]any)[0] }

func writeRun(t *testing.T, root, name string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name, "RESULT.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaRefusal(t *testing.T) {
	cases := map[string]func(map[string]any){
		"unknown top-level field": func(m map[string]any) { m["notes"] = "x" },
		"unknown schema version":  func(m map[string]any) { m["schema"] = "qa-e2e-m9/RESULT/v2" },
		"unknown format":          func(m map[string]any) { delete(m, "clusters") },
		"unknown class":           func(m map[string]any) { first(m)["class"] = "mystery" },
		"class and result differ": func(m map[string]any) { first(m)["result"] = "gap" },
		"unknown verdict form": func(m map[string]any) {
			first(m)["assertion"].(map[string]any)["verdict"] = "SAFE to upgrade"
		},
		"unknown oracle type": func(m map[string]any) { first(m)["oracle"].(map[string]any)["type"] = "vibes" },
		"unknown id": func(m map[string]any) {
			first(m)["assertion"].(map[string]any)["ids"] = []string{"host.example.com"}
		},
		"unknown check field": func(m map[string]any) { first(m)["note"] = "leakhost-7" },
		"bad node image": func(m map[string]any) {
			m["clusters"] = []map[string]string{{"kindNodeImage": "registry.internal/node:latest", "role": "from"}, {"kindNodeImage": imgB, "role": "to"}}
		},
		"bad commit": func(m map[string]any) { m["prufyxCommit"] = "main" },
	}
	for name, mut := range cases {
		if _, err := ParseRun("m3-x", m3(mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseRun("m3-x", m3(nil)); err != nil {
		t.Fatalf("valid input refused: %v", err)
	}
	if _, err := ParseRun("Bad Name/..", m3(nil)); err == nil {
		t.Error("bad run id accepted")
	}
	_, err := ParseRun("m3-x", m3(func(m map[string]any) { m["notes"] = "leakhost-7" }))
	if err == nil || strings.Contains(err.Error(), "leakhost-7") {
		t.Errorf("error missing or echoes input: %v", err)
	}
	if _, err := Build(t.TempDir()); err == nil {
		t.Error("empty results directory accepted")
	}
}

func TestAllowlistNoLeak(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-x", m3(nil))
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	j, md, err := Render(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range leaks {
		for _, doc := range [][]byte{j, md} {
			if bytes.Contains(doc, []byte(leak)) {
				t.Errorf("%q reached the output", leak)
			}
		}
	}
	if !bytes.Contains(j, []byte(cmt)) || bytes.Contains(j, []byte(cmt+" ")) {
		t.Error("commit not reduced to the hash")
	}
	// A host-like value inside an allowlisted field is refused at render.
	writeRun(t, root, "m3-y", m3(func(m map[string]any) { first(m)["app"] = "pfspot1" }))
	rep, err = Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Render(rep); err == nil {
		t.Error("host-like value in an allowlisted field reached the output")
	}
}

func TestDeterminismAndOrder(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	writeRun(t, a, "m3-x", m3(nil))
	writeRun(t, a, "m3-a", m3(nil))
	writeRun(t, b, "m3-a", m3(nil))
	writeRun(t, b, "m3-x", m3(func(m map[string]any) {
		c := m["checks"].([]map[string]any)
		c[0], c[2] = c[2], c[0]
	}))
	var outs [][]byte
	for _, d := range []string{a, b, a} {
		rep, err := Build(d)
		if err != nil {
			t.Fatal(err)
		}
		j, md, err := Render(rep)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, append(j, md...))
	}
	if !bytes.Equal(outs[0], outs[1]) || !bytes.Equal(outs[0], outs[2]) {
		t.Error("output depends on input order")
	}
	if bytes.Contains(outs[0], []byte("2026-11-18")) {
		t.Error("a timestamp reached the output")
	}
}

func TestWordingAndCounts(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-x", m3(nil))
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if c := rep.Counts; c.Rows != 3 || c.Correct != 1 || c.Gap != 1 || c.WrongPass != 1 || c.FalseAlarm != 0 {
		t.Errorf("counts %+v", c)
	}
	j, md, err := Render(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range [][]byte{j, md} {
		low := strings.ToLower(string(doc))
		for _, w := range []string{"confirmed", "verified on kubernetes", "every version tested"} {
			if strings.Contains(low, w) {
				t.Errorf("denied wording %q", w)
			}
		}
	}
	if !strings.Contains(string(md), Header) {
		t.Error("fixed header missing")
	}
	// The renderer refuses denied wording even if it arrives through a field.
	rep.Runs[0].Checks[0].Reason = "CONFIRMED"
	if _, _, err := Render(rep); err == nil {
		t.Error("denied wording rendered")
	}
}

func supersede(t *testing.T, root, name, by string) {
	t.Helper()
	body := `{"superseded": true, "superseded_by": "` + by + `", "reason": "harness fault on leakhost-7 /srv/private/path"}`
	if err := os.WriteFile(filepath.Join(root, name, "SUPERSEDED.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSupersededExcluded(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-x", m3(nil))
	// The superseded run has a wrong PASS row and the RESULT-side keys.
	writeRun(t, root, "m3-x-try1", m3(func(m map[string]any) {
		m["superseded"], m["superseded_by"], m["supersede_reason"] = true, "m3-x", "leakhost-7 note"
	}))
	supersede(t, root, "m3-x-try1", "m3-x")
	// A directory with only SUPERSEDED.json (aborted run, no RESULT) is counted too.
	if err := os.MkdirAll(filepath.Join(root, "aborted"), 0o755); err != nil {
		t.Fatal(err)
	}
	supersede(t, root, "aborted", "m3-x")
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Runs) != 1 || rep.SupersededExcluded != 2 || len(rep.SupersededBy) != 1 || rep.SupersededBy[0] != "m3-x" {
		t.Fatalf("runs=%d excluded=%d by=%v", len(rep.Runs), rep.SupersededExcluded, rep.SupersededBy)
	}
	if rep.Counts.WrongPass != 1 || rep.Counts.Rows != 3 {
		t.Errorf("excluded run leaked into the counts: %+v", rep.Counts)
	}
	j, md, err := Render(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "2 superseded runs excluded, replaced by the reruns: m3-x (excluded: aborted, m3-x-try1)") {
		t.Error("superseded line missing")
	}
	for _, leak := range leaks {
		if bytes.Contains(j, []byte(leak)) || bytes.Contains(md, []byte(leak)) {
			t.Errorf("%q reached the output", leak)
		}
	}
	if !strings.Contains(string(md), "Gap rows: 1 of 3.") {
		t.Error("gap line missing")
	}
}

func TestSupersededByMissingRefused(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-x", m3(nil))
	writeRun(t, root, "m3-y", m3(nil))
	supersede(t, root, "m3-y", "no-such-run")
	if _, err := Build(root); err == nil {
		t.Error("superseded_by naming a missing run accepted")
	}
	// Replaced by another superseded run is not a kept run either.
	supersede(t, root, "m3-y", "m3-z")
	writeRun(t, root, "m3-z", m3(nil))
	supersede(t, root, "m3-z", "m3-y")
	if _, err := Build(root); err == nil {
		t.Error("superseded_by naming a superseded run accepted")
	}
	// Unknown field in the marker file is refused.
	writeRun(t, root, "m3-w", m3(nil))
	if err := os.WriteFile(filepath.Join(root, "m3-w", "SUPERSEDED.json"), []byte(`{"superseded":true,"superseded_by":"m3-x","reason":"r","extra":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root); err == nil {
		t.Error("unknown marker field accepted")
	}
}

// TestCommittedReportFieldsMatchPatterns holds every field of the committed
// report to the strict patterns of the allowlist.
func TestCommittedReportFieldsMatchPatterns(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "generated", "qa-e2e.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != Schema || rep.Header != Header {
		t.Error("schema or header differ")
	}
	for _, id := range append(append([]string{}, rep.SupersededBy...), rep.SupersededRuns...) {
		if !reRunID.MatchString(id) {
			t.Errorf("run id %q", id)
		}
	}
	for _, r := range rep.Runs {
		if !reRunID.MatchString(r.ID) || !reK8s.MatchString(r.K8sFrom) || !reK8s.MatchString(r.K8sTo) ||
			!reImage.MatchString(r.NodeImageFrom) || !reImage.MatchString(r.NodeImageTo) || !reCommit.MatchString(r.PrufyxCommit) || len(r.PrufyxCommit) != 40 {
			t.Errorf("run %q header fields", r.ID)
		}
		for _, c := range r.Checks {
			if !reApp.MatchString(c.App) || !okVersion(c.From) || !okVersion(c.To) || !reCode.MatchString(c.Reason) ||
				(c.LogDigest != "" && !reSha.MatchString(c.LogDigest)) {
				t.Errorf("run %q check fields: %+v", r.ID, c)
			}
			switch c.Result {
			case FormCorrect, FormWrongPass, FormFalseAlarm, FormGap:
			default:
				t.Errorf("result %q", c.Result)
			}
			for _, id := range c.IDs {
				if !reRuleID.MatchString(id) && !reCode.MatchString(id) {
					t.Errorf("id %q", id)
				}
			}
			for _, a := range c.Artifacts {
				if !reArtName.MatchString(a.Name) || !reSha.MatchString(a.Sha256) {
					t.Errorf("artifact %+v", a)
				}
			}
		}
	}
	low := strings.ToLower(string(raw))
	for _, d := range deniedOutput {
		if strings.Contains(low, strings.ToLower(d)) {
			t.Errorf("denied string %q in the committed report", d)
		}
	}
}

func TestConverterFieldsKnownAndNeverOutput(t *testing.T) {
	const hostPath = "convhost.example.net:/home/convuser/summary.md"
	root := t.TempDir()
	writeRun(t, root, "m3-x", m3(func(m map[string]any) {
		m["convertedFrom"], m["summaryFile"] = hostPath, hostPath
		first(m)["sourceCited"] = "https://convhost.example.net/home/convuser/doc"
		first(m)["oracle"].(map[string]any)["typeSource"] = "convhost.example.net:/home/convuser/typesrc"
	}))
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	j, md, err := Render(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range [][]byte{j, md} {
		for _, v := range []string{"convhost", "convuser", "summary.md", "sourceCited", "convertedFrom", "summaryFile", "typeSource", "typesrc"} {
			if bytes.Contains(doc, []byte(v)) {
				t.Errorf("%q reached the output", v)
			}
		}
	}
	// The type is still checked.
	for name, mut := range map[string]func(map[string]any){
		"convertedFrom not a string": func(m map[string]any) { m["convertedFrom"] = 5 },
		"summaryFile not a string":   func(m map[string]any) { m["summaryFile"] = true },
		"sourceCited not a string":   func(m map[string]any) { first(m)["sourceCited"] = true },
		"typeSource not a string":    func(m map[string]any) { first(m)["oracle"].(map[string]any)["typeSource"] = 7 },
	} {
		if _, err := ParseRun("m3-x", m3(mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mark(t *testing.T, root, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name, "NOT-REPORTED.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const summaryShape = `{"catalog_inconsistencies": 3, "class_counts": {"a": 1}, "decided_pairs_vs_oracle": []}`

func TestNotReportedSummaryListedNotParsed(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m10-r01", []byte(summaryShape))
	writeRun(t, root, "m10-r02", []byte(summaryShape))
	mark(t, root, "m10-r01", `{"reportable": false, "reason_code": "summary-only"}`)
	mark(t, root, "m10-r02", `{"reportable": false, "reason_code": "summary-only"}`)
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Runs) != 1 || len(rep.NotReported) != 2 {
		t.Fatalf("runs=%d notReported=%v", len(rep.Runs), rep.NotReported)
	}
	_, md, err := Render(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "Not in this report: 2 runs (summary-only: m10-r01, m10-r02).") {
		t.Errorf("header line missing:\n%s", md)
	}
}

func TestUnmarkedUnknownShapeStillRefused(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m10-r01", []byte(summaryShape))
	if _, err := Build(root); err == nil {
		t.Fatal("unmarked summary shape accepted")
	}
}

func TestNotReportedBadMarkerRefused(t *testing.T) {
	for _, body := range []string{
		`{"reportable": false, "reason_code": "because"}`,
		`{"reportable": false, "reason_code": ""}`,
		`{"reportable": true, "reason_code": "other"}`,
		`{"reason_code": "other"}`,
		`{"reportable": false, "reason_code": "other", "reason": 5}`,
		`{"reportable": false, "reason_code": "other", "note": "free text"}`,
		`not json`,
	} {
		root := t.TempDir()
		writeRun(t, root, "m3-a", m3(nil))
		writeRun(t, root, "m10-r01", []byte(summaryShape))
		mark(t, root, "m10-r01", body)
		if _, err := Build(root); err == nil {
			t.Errorf("bad marker accepted: %s", body)
		}
	}
}

func TestNotReportedMarkerOnNormalRun(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m3-b", m3(nil))
	mark(t, root, "m3-b", `{"reportable": false, "reason_code": "harness-test"}`)
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Runs) != 1 || rep.Runs[0].ID != "m3-a" || len(rep.NotReported) != 1 || rep.NotReported[0].ID != "m3-b" || rep.NotReported[0].ReasonCode != "harness-test" {
		t.Fatalf("runs=%v notReported=%v", rep.Runs, rep.NotReported)
	}
}

func TestNotReportedResultKey(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m10-r01", []byte(`{"reportable": false, "class_counts": {}}`))
	rep, err := Build(root)
	if err != nil || len(rep.NotReported) != 1 || rep.NotReported[0].ReasonCode != "other" {
		t.Fatalf("err=%v rep=%v", err, rep)
	}
	writeRun(t, root, "m10-r02", []byte(`{"reportable": "no"}`))
	if _, err := Build(root); err == nil {
		t.Error("non-boolean reportable accepted")
	}
}

func TestNotReportedWithSupersedeRefused(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m10-r01", []byte(`{"reportable": false, "superseded": true, "superseded_by": "m3-a"}`))
	if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "both not reportable and superseded") {
		t.Fatalf("inline combination: %v", err)
	}
	root = t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m10-r01", []byte(summaryShape))
	mark(t, root, "m10-r01", `{"reportable": false, "reason_code": "summary-only"}`)
	supersede(t, root, "m10-r01", "m3-a")
	if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "both not reportable and superseded") {
		t.Fatalf("file combination: %v", err)
	}
}

func TestNotReportedNoticeLine(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m10-r01", []byte(summaryShape))
	mark(t, root, "m10-r01", `{"reportable": false, "reason_code": "summary-only"}`)
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	_, md, _ := Render(rep)
	if !strings.Contains(string(md), "Not-reported runs are not counted; their rows are not checked by this report.") {
		t.Error("notice line missing")
	}
}

func TestNotReportedReasonNeverOutput(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m10-r01", []byte(summaryShape))
	mark(t, root, "m10-r01", `{"reportable": false, "reason_code": "summary-only", "reason": "ran on pfspot1 192.168.1.5 /home/airstand/x /opt/prufyx"}`)
	rep, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	j, md, err := Render(rep)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"pfspot1", "192.168", "/home/", "airstand", "/opt/"} {
		if strings.Contains(string(j), w) || strings.Contains(string(md), w) {
			t.Errorf("reason leaked: %s", w)
		}
	}
}

func TestOracleTypeEnum(t *testing.T) {
	want := map[string]string{
		"replay-on-target": "replay on the target cluster",
		"in-place upgrade": "in-place upgrade on the cluster",
	}
	for typ, label := range want {
		run, err := ParseRun("m3-x", m3(func(m map[string]any) { first(m)["oracle"].(map[string]any)["type"] = typ }))
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if run.Checks[0].Oracle != label {
			t.Errorf("%s: label %q", typ, run.Checks[0].Oracle)
		}
	}
	for _, typ := range []string{"", "Replay-On-Target", "in-place  upgrade", "something else", "install-on-to", "in-place-upgrade", "served-API list", "install-on-from"} {
		if _, err := ParseRun("m3-x", m3(func(m map[string]any) { first(m)["oracle"].(map[string]any)["type"] = typ })); err == nil {
			t.Errorf("unknown oracle type %q accepted", typ)
		}
	}
}

func TestListRefusalsCollectsAllNeverValues(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m3-bad", m3(func(m map[string]any) {
		m["extraKey"] = "leakhost-7"
		first(m)["oracle"].(map[string]any)["type"] = "leakhost-7 /srv/private/path"
		first(m)["assertion"].(map[string]any)["command"] = "plan [leakhost-7]"
	}))
	writeRun(t, root, "m10-r01", []byte(summaryShape))
	refs, err := ListRefusals(root)
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, r := range refs {
		all.WriteString(r.Run + "|" + r.Message + "\n")
		if r.Run == "m3-a" {
			t.Errorf("clean run listed: %v", r)
		}
	}
	s := all.String()
	for _, w := range []string{`m3-bad|unknown field "extraKey"`, "m3-bad|check: unknown oracle type", "m3-bad|check: unknown command", "m10-r01|unknown input format"} {
		if !strings.Contains(s, w) {
			t.Errorf("missing %q in:\n%s", w, s)
		}
	}
	for _, v := range []string{"leakhost", "/srv/private"} {
		if strings.Contains(s, v) {
			t.Errorf("value %q printed", v)
		}
	}
	// Build still refuses the same input.
	if _, err := Build(root); err == nil {
		t.Error("Build accepted a refused set")
	}
}

func TestHarnessVerdictsAndRuleIDs(t *testing.T) {
	set := func(verdict string, ids []string) func(m map[string]any) {
		return func(m map[string]any) {
			first(m)["assertion"] = map[string]any{"command": "scan", "verdict": verdict, "ids": ids}
		}
	}
	ok := []struct {
		verdict string
		ids     []string
		code    string
	}{
		{"not flagged (scan verdict BLOCKED); kind listed as not evaluated", nil, "NOT_FLAGGED_SCAN_BLOCKED"},
		{"not flagged (scan verdict PASS)", nil, "NOT_FLAGGED_SCAN_PASS"},
		{"no finding for this app (scan verdict BLOCKED)", nil, "NO_FINDING_SCAN_BLOCKED"},
		{"2 of the app's old documents flagged by scan findings", nil, "OLD_DOCUMENTS_FLAGGED"},
		{"rc=0: cert-manager is catalogued but has no rules yet; request coverage: https://github.com/prufyx/prufyx/issues/new?template=project-knowledge.yml", nil, "CATALOGUED_NO_RULES_YET"},
		{"rc=0: embedded source-rule identities: 11", nil, "EMBEDDED_SOURCE_RULE_IDENTITIES"},
		{"rc=2: prufyx: unknown project \"gateway-api\"; list projects with `prufyx catalog cncf`", nil, "CHECK_UNKNOWN_PROJECT"},
		{"rc=2: prufyx: invalid native format check arguments; use --help", nil, "CHECK_INVALID_ARGUMENTS"},
		{"BLOCKED kyverno.crd-version-removal.updaterequests-kyverno-io.1-15-0-to-1-16-0", []string{"kyverno.crd-version-removal.updaterequests-kyverno-io.1-15-0-to-1-16-0"}, "BLOCKED"},
	}
	for _, c := range ok {
		run, err := ParseRun("m3-x", m3(set(c.verdict, c.ids)))
		if err != nil {
			t.Errorf("%q: %v", c.verdict, err)
			continue
		}
		if run.Checks[0].Reason != c.code {
			t.Errorf("%q: reason %q", c.verdict, run.Checks[0].Reason)
		}
	}
	bad := []struct {
		verdict string
		ids     []string
	}{
		{"not flagged (scan verdict MAYBE)", nil},
		{"rc=0: embedded source-rule identities: many", nil},
		{"rc=2: prufyx: unknown project \"x y /home/z\"; list projects with `prufyx catalog cncf`", nil},
		{"rc=0: x is catalogued but has no rules yet; request coverage: https://example.net/leak", nil},
		{"x of the app's old documents flagged by scan findings", nil},
		{"2 of the app's old documents flagged by scan findings leakhost-7", nil},
		{"BLOCKED x", []string{"leakhost-7.not-a-rule"}},
		{"BLOCKED x", []string{"Kyverno.crd.slug.1-1-1-to-2-2-2"}},
	}
	for _, c := range bad {
		if _, err := ParseRun("m3-x", m3(set(c.verdict, c.ids))); err == nil {
			t.Errorf("accepted: %q %v", c.verdict, c.ids)
		}
	}
}

func TestListRefusalsCrossRun(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "m3-a", m3(nil))
	writeRun(t, root, "m10-r01", []byte(summaryShape))
	mark(t, root, "m10-r01", `{"reportable": false, "reason_code": "summary-only"}`)
	writeRun(t, root, "m10-r00", []byte(summaryShape))
	supersede(t, root, "m10-r00", "m10-r01")
	writeRun(t, root, "m3-old", m3(nil))
	supersede(t, root, "m3-old", "m3-a")
	refs, err := ListRefusals(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Run != "m10-r00" || refs[0].Message != "a superseded run names a replacing run that is not a kept run" {
		t.Fatalf("refs=%v", refs)
	}
	if _, err := Build(root); err == nil {
		t.Error("Build accepted it")
	}
}
