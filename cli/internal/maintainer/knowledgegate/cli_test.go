// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Main(args, func(string) string { return "" }, &out, &errOut)
	return code, out.String() + errOut.String()
}

func TestCLI(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
		ruleOf(p.find(t, ids[1]))["nextAction"] = "Changed."
	})
	now := gateNow.Format(time.RFC3339)

	code, out := runCLI(t, "classify", "--base", base.Root, "--head", head.Root)
	if code != 0 || !strings.Contains(out, "tightening cncf "+ids[0]+" [withdraw]") || !strings.Contains(out, "1 tightening, 1 loosening") {
		t.Fatalf("classify: %d %s", code, out)
	}
	code, out = runCLI(t, "classify", "--base", base.Root, "--head", head.Root, "--json")
	var cls ClassifyOutput
	if code != 0 || json.Unmarshal([]byte(out), &cls) != nil || cls.Totals.Loosening != 1 || len(cls.ChainsChanged) != 0 {
		t.Fatalf("classify --json: %d %s", code, out)
	}

	if code, out = runCLI(t, "limits", "--base", base.Root, "--head", head.Root); code != 0 {
		t.Fatalf("limits: %d %s", code, out)
	}
	writeFile(t, filepath.Join(head.Root, "factory", "PAUSE"), nil)
	if code, out = runCLI(t, "limits", "--base", base.Root, "--head", head.Root); code != 1 || !strings.Contains(out, "kill switch") {
		t.Fatalf("limits paused: %d %s", code, out)
	}
	if err := os.Remove(filepath.Join(head.Root, "factory", "PAUSE")); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	report, summary := filepath.Join(dir, "report.json"), filepath.Join(dir, "summary.md")
	code, out = runCLI(t, "verify", "--base", base.Root, "--head", head.Root, "--now", now, "--report", report, "--summary", summary, "--author", "x")
	if code != 1 || !strings.Contains(out, "gate: FAIL") || !strings.Contains(out, "FAIL loosening") {
		t.Fatalf("verify: %d %s", code, out)
	}
	var r Report
	raw, err := os.ReadFile(report)
	if err != nil || json.Unmarshal(raw, &r) != nil || r.Result != "fail" || r.AutoMerge.Eligible || r.Schema != ReportSchema {
		t.Fatalf("report: %v %s", err, raw)
	}
	md, err := os.ReadFile(summary)
	if err != nil || !strings.Contains(string(md), "## Knowledge gate: FAIL") || !strings.Contains(string(md), "Automatic merge: not eligible") {
		t.Fatalf("summary: %v %s", err, md)
	}

	// Without the loosening change the same command passes.
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		ruleOf(p.find(t, ids[1]))["nextAction"] = ruleOf(readPack(t, base, cncfRulesPath).find(t, ids[1]))["nextAction"]
	})
	commits := filepath.Join(dir, "commits.json")
	rawCommits, err := json.Marshal(botCommits())
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, commits, rawCommits)
	bot := []string{"verify", "--base", base.Root, "--head", head.Root, "--now", now, "--source", "fixture:" + servedFixture, "--author", DefaultBotLogin}
	if code, out = runCLI(t, bot...); code != 0 || strings.Contains(out, "auto-merge: eligible") {
		t.Fatalf("verify tightening without provenance: %d %s", code, out)
	}
	if code, out = runCLI(t, append(bot, "--sender", DefaultBotLogin, "--head-sha", testHeadSHA, "--commits", commits)...); code != 0 || !strings.Contains(out, "auto-merge: eligible") {
		t.Fatalf("verify tightening: %d %s", code, out)
	}

	for _, args := range [][]string{
		{},
		{"nope"},
		{"classify", "--base", base.Root},
		{"classify", "--base", base.Root, "--head", filepath.Join(dir, "missing")},
		{"verify", "--base", base.Root, "--head", head.Root, "--source", "ftp"},
		{"verify", "--base", base.Root, "--head", head.Root, "--now", "yesterday"},
		{"verify", "--base", base.Root, "--head", head.Root, "--rerun-worklist", filepath.Join(dir, "missing.json")},
		{"limits", "--base", base.Root, "--head", head.Root, "--max-loosening", "0"},
		{"verify", "--base", base.Root, "--head", head.Root, "extra"},
	} {
		if code, out := runCLI(t, args...); code != 2 {
			t.Fatalf("%v: exit %d, want 2: %s", args, code, out)
		}
	}
}
