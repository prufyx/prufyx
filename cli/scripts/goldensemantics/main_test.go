// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const blockedReport = `{"schema":"prufyx.io/scan-report/v1alpha1","verdict":"BLOCKED","headline":"BLOCKED: 1 problem","summary":{"blockers":1,"gaps":1,"passes":10},"paths":[{"component":"kubernetes","hops":[{"index":1,"status":"BLOCKED","attestation":{"basis":"reviewed","validUntil":"2026-12-20T00:00:00Z"}},{"index":2,"status":"COVERED"}]}],"findings":[{"ruleId":"kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0","reasonCode":"REVIEWED_SOURCE_CONSTRAINT","fix":"Migrate the manifest."}],"gaps":[{"reason":"LINE_NOT_ATTESTED","detail":"x"}],"provenance":{"knowledgeDigest":"sha256:aaaa"}}`

// cosmeticReport says the same as blockedReport with the rule id, reason
// code, basis, fix text, date and digest of the mechanical rules.
var cosmeticReport = strings.NewReplacer(
	"kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0", "kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0",
	"REVIEWED_SOURCE_CONSTRAINT", "KUBERNETES_SERVED_API_REMOVED",
	`"basis":"reviewed"`, `"basis":"mechanical"`,
	"Migrate the manifest.", "Migrate the manifest to batch/v1.",
	"2026-12-20", "2027-01-27",
	"sha256:aaaa", "sha256:bbbb",
).Replace(blockedReport)

const blockedText = "BLOCKED: 1 problem must be fixed before this upgrade\n\nNOT CHECKED (1)\n  kubernetes   1 manifest(s)\n\nChecked 6 hops.\n"

type tree map[string]string

func write(t *testing.T, files tree) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func compare(t *testing.T, before, after tree, args ...string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append(append([]string{}, args...), write(t, before), write(t, after)), &stdout, &stderr)
	return code, stdout.String() + stderr.String()
}

// A change of ids, reason codes, basis, fix text, dates and digests is not a
// semantic change.
func TestCosmeticChangeIsAccepted(t *testing.T) {
	code, out := compare(t,
		tree{"scanrun/quickstart-blocked.json": blockedReport, "scanrun/quickstart-blocked.txt": blockedText},
		tree{"scanrun/quickstart-blocked.json": cosmeticReport, "scanrun/quickstart-blocked.txt": blockedText + "evaluated at 2026-11-20; knowledge sha256:bbbb\n"})
	if code != 0 || !strings.Contains(out, "no semantic difference") || !strings.Contains(out, "scanrun/quickstart-blocked.json") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

// A BLOCKED that becomes a PASS is refused, in every form the goldens take,
// and accepted only with the flag, which still prints it.
func TestBlockedBecomingPassIsRefusedWithoutTheFlag(t *testing.T) {
	passReport := strings.NewReplacer(`"verdict":"BLOCKED"`, `"verdict":"PASS"`, `"status":"BLOCKED"`, `"status":"COVERED"`, `"blockers":1`, `"blockers":0`, `"findings":[{"ruleId":"kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0","reasonCode":"REVIEWED_SOURCE_CONSTRAINT","fix":"Migrate the manifest."}]`, `"findings":[]`).Replace(blockedReport)
	passText := strings.Replace(blockedText, "BLOCKED: 1 problem must be fixed before this upgrade", "PASS FOR THE DECLARED SCOPE", 1)
	for name, files := range map[string][2]tree{
		"json":      {{"a.json": blockedReport}, {"a.json": passReport}},
		"text":      {{"a.txt": blockedText}, {"a.txt": passText}},
		"exit code": {{"a.exit": "01\n"}, {"a.exit": "00\n"}},
		"sarif level": {
			{"a.sarif": `{"runs":[{"results":[{"ruleId":"r","level":"error"}]}]}`},
			{"a.sarif": `{"runs":[{"results":[]}]}`},
		},
		"trailing exit code of a JSON stdout": {{"a.json": `{"assessment":"BLOCKED"}` + "\nexit 1\n"}, {"a.json": `{"assessment":"BLOCKED"}` + "\nexit 0\n"}},
		"a hop state":                         {{"a.json": blockedReport}, {"a.json": strings.Replace(blockedReport, `"status":"COVERED"`, `"status":"PARTIAL"`, 1)}},
		"a gap reason":                        {{"a.json": blockedReport}, {"a.json": strings.Replace(blockedReport, "LINE_NOT_ATTESTED", "EVIDENCE_EXPIRED", 1)}},
		"a new golden":                        {{}, {"new.json": blockedReport}},
		"a removed golden":                    {{"old.json": blockedReport}, {}},
	} {
		code, out := compare(t, files[0], files[1])
		if code != exitSemanticChange || !strings.Contains(out, "refused") {
			t.Errorf("%s: exit %d, want %d:\n%s", name, code, exitSemanticChange, out)
		}
		code, out = compare(t, files[0], files[1], "-allow-semantic-change")
		if code != 0 || !strings.Contains(out, "accepted by -allow-semantic-change") {
			t.Errorf("%s with the flag: exit %d:\n%s", name, code, out)
		}
	}
	// The report names the change.
	_, out := compare(t, tree{"a.json": blockedReport}, tree{"a.json": passReport})
	for _, want := range []string{"CHANGED  a.json", "- verdict=BLOCKED", "+ verdict=PASS", "before:", "after:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// The script's comparison step refuses the same fixture, and accepts it with
// --allow-semantic-change.
func TestRegenerateScriptRefusesASemanticChange(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go tool")
	}
	script, err := filepath.Abs(filepath.Join("..", "regenerate-pack-goldens.sh"))
	if err != nil {
		t.Fatal(err)
	}
	before := write(t, tree{"scanrun/quickstart-blocked.json": blockedReport})
	pass := strings.Replace(blockedReport, `"verdict":"BLOCKED"`, `"verdict":"PASS"`, 1)
	after := write(t, tree{"scanrun/quickstart-blocked.json": pass})
	cosmetic := write(t, tree{"scanrun/quickstart-blocked.json": cosmeticReport})
	runScript := func(args ...string) (int, string) {
		cmd := exec.Command("sh", append([]string{script}, args...)...)
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=vendor")
		out, err := cmd.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), string(out)
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	if code, out := runScript("--compare", before, after); code != exitSemanticChange || !strings.Contains(out, "- verdict=BLOCKED") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if code, out := runScript("--compare", before, after, "--allow-semantic-change"); code != 0 {
		t.Fatalf("with the flag: exit %d:\n%s", code, out)
	}
	if code, out := runScript("--allow-semantic-change", "--compare", before, after); code != 0 {
		t.Fatalf("with the flag first: exit %d:\n%s", code, out)
	}
	if code, out := runScript("--compare", before, cosmetic); code != 0 {
		t.Fatalf("cosmetic change: exit %d:\n%s", code, out)
	}
}

// Unchanged files are not listed and the real goldens compare equal to
// themselves.
func TestUnchangedGoldensAreNotListed(t *testing.T) {
	files := tree{"a.json": blockedReport, "b.txt": blockedText}
	code, out := compare(t, files, files)
	if code != 0 || strings.Contains(out, "a.json") || !strings.Contains(out, "no semantic difference (0 of 2") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, dir := range []string{"../../internal/scanrun/testdata", "../../internal/scanreport/testdata", "../../internal/communityapp/testdata/knowledge-age"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{dir, dir}, &stdout, &stderr); code != 0 {
			t.Fatalf("%s: exit %d:\n%s%s", dir, code, stdout.String(), stderr.String())
		}
	}
}

func TestUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"only-one"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if code := run([]string{"/does/not/exist", "/neither"}, &stdout, &stderr); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

// The signature of the real goldens carries the statuses and exit codes it
// is meant to guard.
func TestSignatureOfRealGoldens(t *testing.T) {
	raw, err := os.ReadFile("../../internal/scanrun/testdata/quickstart-blocked.json")
	if err != nil {
		t.Fatal(err)
	}
	summary := summarize(signature("quickstart-blocked.json", raw))
	for _, want := range []string{"verdict=BLOCKED", "status=BLOCKED", "status=COVERED"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary lacks %q: %s", want, summary)
		}
	}
	raw, err = os.ReadFile("../../internal/communityapp/testdata/knowledge-age/check-cncf-after.json")
	if err != nil {
		t.Fatal(err)
	}
	if summary := summarize(signature("check-cncf-after.json", raw)); !strings.Contains(summary, "exit=") {
		t.Errorf("no exit code in %s", summary)
	}
}
