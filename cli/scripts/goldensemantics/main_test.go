// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
		code, out = compare(t, files[0], files[1], "-allow-semantic-change=a.json,a.txt,a.exit,a.sarif,old.json,new.json")
		if code != 0 || !strings.Contains(out, "accepted by name") {
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
	if code, out := runScript("--compare", before, after, "--allow-semantic-change=quickstart-blocked.json"); code != 0 {
		t.Fatalf("with the flag: exit %d:\n%s", code, out)
	}
	if code, out := runScript("--allow-semantic-change=scanrun/quickstart-*.json", "--compare", before, after); code != 0 {
		t.Fatalf("with the flag first: exit %d:\n%s", code, out)
	}
	if code, out := runScript("--compare", before, after, "--allow-semantic-change=other.json"); code != exitSemanticChange {
		t.Fatalf("with another file named: exit %d:\n%s", code, out)
	}
	if code, out := runScript("--compare", before, after, "--allow-semantic-change"); code != 2 {
		t.Fatalf("with the bare flag: exit %d:\n%s", code, out)
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

// The flag accepts the files it names and nothing else; there is no form that
// accepts everything.
func TestAllowSemanticChangeAcceptsOnlyNamedFiles(t *testing.T) {
	pass := strings.Replace(blockedReport, `"verdict":"BLOCKED"`, `"verdict":"PASS"`, 1)
	before := tree{"x/knowledge-age-before.json": blockedReport, "x/knowledge-age-before.exit": "10\n", "x/other.json": blockedReport}
	after := tree{"x/knowledge-age-before.json": strings.Replace(blockedReport, `"verdict":"BLOCKED"`, `"verdict":"UNKNOWN"`, 1), "x/knowledge-age-before.exit": "11\n", "x/other.json": pass}

	code, out := compare(t, before, after, "-allow-semantic-change=knowledge-age-before.*")
	if code != exitSemanticChange || !strings.Contains(out, "refused") || !strings.Contains(out, "CHANGED  x/other.json") ||
		!strings.Contains(out, "ACCEPTED CHANGED  x/knowledge-age-before.json") || !strings.Contains(out, "ACCEPTED CHANGED  x/knowledge-age-before.exit") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "ACCEPTED CHANGED  x/other.json") {
		t.Fatalf("other.json accepted:\n%s", out)
	}
	for _, names := range []string{"knowledge-age-before.*,other.json", "x/knowledge-age-before.json,x/knowledge-age-before.exit,x/other.json", "x/*.json,x/*.exit"} {
		if code, out := compare(t, before, after, "-allow-semantic-change="+names); code != 0 || !strings.Contains(out, "accepted by name") {
			t.Errorf("%s: exit %d:\n%s", names, code, out)
		}
	}
	// A name matches whole segments of the tail only.
	if code, out := compare(t, before, after, "-allow-semantic-change=er.json,knowledge-age-before.*"); code != exitSemanticChange {
		t.Errorf("a partial name accepted a file: exit %d:\n%s", code, out)
	}
	// A name that matches no changed file is reported.
	code, out = compare(t, before, after, "-allow-semantic-change=knowledge-age-before.*,other.json,never.json")
	if code != 0 || !strings.Contains(out, `names "never.json"`) {
		t.Errorf("exit %d:\n%s", code, out)
	}
	// No bare form, no empty list, no bad pattern.
	for _, args := range [][]string{{"-allow-semantic-change="}, {"-allow-semantic-change=["}} {
		var stdout, stderr bytes.Buffer
		if code := run(append(append([]string{}, args...), write(t, before), write(t, after)), &stdout, &stderr); code != 2 {
			t.Errorf("%v: exit %d:\n%s%s", args, code, stdout.String(), stderr.String())
		}
	}
}

// Every field the signature claims to read is read: one mutant per field,
// each refused.
func TestEveryClaimedFieldIsCompared(t *testing.T) {
	batch := `{"schema":"prufyx.io/batch-check-report/v1alpha1","decision":"UNKNOWN","aggregateCategory":"PASS","items":[{"id":"item-001","outcome":"PASS","category":"PASS","categories":["PASS"],"reasonCode":"SCOPED_CLAIMS_PASS","report":{"assessment":"UNKNOWN","check":{"claims":[{"ruleId":"r","status":"PASS","evidenceFreshness":"current"}]}}}]}`
	scan := `{"verdict":"BLOCKED","headline":"BLOCKED: 1 problem must be fixed before this upgrade","inventory":[{"name":"kubernetes","covered":true}],"notices":[{"kind":"x","established":true}],"paths":[{"hops":[{"status":"BLOCKED","attestation":{"freshness":"current"}}]}],"gaps":[{"reason":"LINE_NOT_ATTESTED"}]}`
	sarif := `{"runs":[{"invocations":[{"executionSuccessful":true,"exitCode":10,"exitCodeDescription":"BLOCKED: 1 problem must be fixed before this upgrade"}],"results":[{"ruleId":"r","level":"error"}]}]}`
	human := "batch check: PASS\nitem-001: PASS (PASS; SCOPED_CLAIMS_PASS; knowledge embedded)\nitem-002: STALE (STALE_EVIDENCE; EVIDENCE_EXPIRED; knowledge embedded)\ncompatibility decision: UNKNOWN\n\nexit 0\n"
	text := "BLOCKED: 1 problem must be fixed before this upgrade\n\nNOT CHECKED (1)\n  kubernetes   1 manifest(s)\n\nChecked 6 hops, 2 documents, 1 component (1 covered). 10 checks passed (--show-passes).\n"
	markdown := "# BLOCKED: 1 problem must be fixed before this upgrade\n\n## PROBLEMS TO FIX (1)\n\n## PASSED (6)\n"
	for _, c := range []struct{ name, file, from, to string }{
		{"batch decision", "a.json", batch, strings.Replace(batch, `"decision":"UNKNOWN"`, `"decision":"PASS"`, 1)},
		{"batch aggregateCategory", "a.json", batch, strings.Replace(batch, `"aggregateCategory":"PASS"`, `"aggregateCategory":"BLOCKED"`, 1)},
		{"item outcome", "a.json", batch, strings.Replace(batch, `"outcome":"PASS"`, `"outcome":"BLOCKED"`, 1)},
		{"item category", "a.json", batch, strings.Replace(batch, `"category":"PASS"`, `"category":"UNKNOWN"`, 1)},
		{"item categories", "a.json", batch, strings.Replace(batch, `"categories":["PASS"]`, `"categories":["PASS","UNKNOWN"]`, 1)},
		{"claim evidenceFreshness", "a.json", batch, strings.Replace(batch, `"evidenceFreshness":"current"`, `"evidenceFreshness":"stale"`, 1)},
		{"headline", "a.json", scan, strings.Replace(scan, "BLOCKED: 1 problem must", "BLOCKED: 2 problems must", 1)},
		{"covered", "a.json", scan, strings.Replace(scan, `"covered":true`, `"covered":false`, 1)},
		{"established", "a.json", scan, strings.Replace(scan, `"established":true`, `"established":false`, 1)},
		{"attestation freshness", "a.json", scan, strings.Replace(scan, `"freshness":"current"`, `"freshness":"stale"`, 1)},
		{"gap reason outside gaps", "a.json", scan, strings.Replace(scan, `"gaps":[{"reason":"LINE_NOT_ATTESTED"}]`, `"gaps":[{"reason":"LINE_NOT_ATTESTED"}],"other":{"reason":"X"}`, 1)},
		{"exitCodeDescription", "a.sarif", sarif, strings.Replace(sarif, "BLOCKED: 1 problem must", "UNKNOWN: 1 gap must", 1)},
		{"executionSuccessful", "a.sarif", sarif, strings.Replace(sarif, `"executionSuccessful":true`, `"executionSuccessful":false`, 1)},
		{"human category word", "a.human", human, strings.Replace(human, "(STALE_EVIDENCE;", "(EVIDENCE_EXPIRED;", 1)},
		{"human STALE word", "a.human", human, strings.Replace(human, "item-002: STALE", "item-002: PASS", 1)},
		{"text checks passed", "a.txt", text, strings.Replace(text, "10 checks passed", "9 checks passed", 1)},
		{"text covered", "a.txt", text, strings.Replace(text, "(1 covered)", "(0 covered)", 1)},
		{"text problem count", "a.txt", text, strings.Replace(text, "1 problem must", "2 problems must", 1)},
		{"text NOT CHECKED count", "a.txt", text, strings.Replace(text, "NOT CHECKED (1)", "NOT CHECKED (2)", 1)},
		{"markdown PROBLEMS TO FIX count", "a.md", markdown, strings.Replace(markdown, "PROBLEMS TO FIX (1)", "PROBLEMS TO FIX (2)", 1)},
		{"markdown PASSED count", "a.md", markdown, strings.Replace(markdown, "PASSED (6)", "PASSED (5)", 1)},
	} {
		if c.from == c.to {
			t.Errorf("%s: the mutant did not change the golden", c.name)
			continue
		}
		code, out := compare(t, tree{c.file: c.from}, tree{c.file: c.to})
		if code != exitSemanticChange || !strings.Contains(out, "CHANGED  "+c.file) {
			t.Errorf("%s: exit %d, want %d:\n%s", c.name, code, exitSemanticChange, out)
		}
	}
	// And the unmutated pair is quiet.
	if code, out := compare(t, tree{"a.json": batch, "a.txt": text}, tree{"a.json": batch + "\n", "a.txt": text + "\n"}); code != 0 {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// The script takes its "before" from HEAD and refuses to start on a dirty
// golden directory, so that neither a rerun after its own refusal nor a
// `go test -update` by hand can absorb a semantic change.
func TestRegenerateScriptCannotBeBypassedByRerunning(t *testing.T) {
	for _, tool := range []string{"sh", "go", "git", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s", tool)
		}
	}
	scripts, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	cli := filepath.Join(repo, "cli")
	put := func(rel, content string) {
		path := filepath.Join(cli, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile := func(from, rel string) {
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		put(rel, string(raw))
	}
	copyFile(filepath.Join(scripts, "regenerate-pack-goldens.sh"), "scripts/regenerate-pack-goldens.sh")
	copyFile(filepath.Join(scripts, "goldensemantics", "main.go"), "scripts/goldensemantics/main.go")
	put("go.mod", "module scratch\n\ngo 1.22\n")
	pack := `{"entries":[]}`
	digest := func() string { sum := sha256.Sum256([]byte(pack)); return hex.EncodeToString(sum[:]) }
	put("internal/cncfcheck/data/rules.json", pack)
	put("internal/cncfcheck/set_rules_test.go", "package cncfcheck\n\nconst embeddedPackSHA256 = \""+strings.Repeat("0", 64)+"\"\n")
	// Three packages with the flags the script uses; only scanrun rewrites a golden,
	// from cli/next.json when it exists.
	put("internal/scanrun/g_test.go", `package scanrun

import (
	"flag"
	"os"
	"testing"
)

var update = flag.Bool("update", false, "")

func TestGolden(t *testing.T) {
	if !*update {
		return
	}
	if raw, err := os.ReadFile("../../next.json"); err == nil {
		if err := os.WriteFile("testdata/quickstart-blocked.json", raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
`)
	put("internal/scanreport/g_test.go", "package scanreport\n\nimport (\n\t\"flag\"\n\t\"testing\"\n)\n\nvar update = flag.Bool(\"update\", false, \"\")\n\nfunc TestG(t *testing.T) { _ = *update }\n")
	put("internal/communityapp/g_test.go", "package communityapp\n\nimport (\n\t\"flag\"\n\t\"testing\"\n)\n\nvar updateAge = flag.Bool(\"update-age\", false, \"\")\n\nfunc TestCheckOutputUnchangedNearExpiry(t *testing.T) { _ = *updateAge }\n")
	put("internal/scanrun/testdata/quickstart-blocked.json", blockedReport)
	put("internal/scanrun/testdata/other.json", blockedReport)
	put("internal/scanreport/testdata/markdown-blocked.md", "# BLOCKED: 1 problem\n")
	put("internal/communityapp/testdata/knowledge-age/check-cncf-after.human", "batch check: PASS\n\nexit 0\n")

	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return string(out)
	}
	git("init", "-q")
	git("add", "-A")
	git("commit", "-q", "-m", "base")
	script := func(args ...string) (int, string) {
		cmd := exec.Command("sh", append([]string{"scripts/regenerate-pack-goldens.sh", "--no-test"}, args...)...)
		cmd.Dir = cli
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off")
		out, err := cmd.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), string(out)
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, string(out)
	}
	discard := func() {
		git("checkout", "--", ".")
		git("clean", "-fdq")
		os.Remove(filepath.Join(cli, "next.json"))
	}
	changeVerdict := func() {
		put("next.json", strings.Replace(blockedReport, `"verdict":"BLOCKED"`, `"verdict":"PASS"`, 1))
		git("status", "--short") // the file is untracked on purpose; the script ignores it
	}
	golden := "internal/scanrun/testdata/quickstart-blocked.json"

	// Nothing changed: the pack digest pin is rewritten, no semantic difference.
	if code, out := script(); code != 0 || !strings.Contains(out, "no semantic difference") {
		t.Fatalf("clean run: exit %d:\n%s", code, out)
	}
	if !strings.Contains(git("diff", "--stat"), "set_rules_test.go") {
		t.Fatalf("the pin was not rewritten (digest %s):\n%s", digest(), git("status", "--short"))
	}
	discard()

	// A semantic change is refused, and refused again on a rerun, whose
	// "before" is not the files the first run left behind.
	changeVerdict()
	code, out := script()
	if code != exitSemanticChange || !strings.Contains(out, "refused") || !strings.Contains(out, "verdict=PASS") {
		t.Fatalf("first run: exit %d:\n%s", code, out)
	}
	if !strings.Contains(git("status", "--short"), "quickstart-blocked.json") {
		t.Fatal("the refused run left the golden untouched (the scenario needs it rewritten)")
	}
	for i := 0; i < 2; i++ {
		if code, out = script(); code == 0 || !strings.Contains(out, "refusing to start") {
			t.Fatalf("rerun %d after the refusal: exit %d:\n%s", i+1, code, out)
		}
	}
	// Naming the file does not get past a dirty tree either.
	if code, out = script("--allow-semantic-change=" + golden); code == 0 || !strings.Contains(out, "refusing to start") {
		t.Fatalf("named rerun on a dirty tree: exit %d:\n%s", code, out)
	}
	discard()

	// A manual `go test -update` (or a failed earlier run) leaves the same state.
	changeVerdict()
	cmd := exec.Command("go", "test", "-count=1", "./internal/scanrun", "-update")
	cmd.Dir = cli
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("manual update: %v\n%s", err, out)
	}
	if code, out = script(); code == 0 || !strings.Contains(out, "refusing to start") {
		t.Fatalf("after a manual -update: exit %d:\n%s", code, out)
	}
	discard()

	// Another file named: still refused. The right file named: accepted.
	changeVerdict()
	if code, out = script("--allow-semantic-change=internal/scanrun/testdata/other.json"); code != exitSemanticChange {
		t.Fatalf("wrong file named: exit %d:\n%s", code, out)
	}
	discard()
	changeVerdict()
	if code, out = script("--allow-semantic-change=" + golden); code != 0 || !strings.Contains(out, "accepted by name") {
		t.Fatalf("file named: exit %d:\n%s", code, out)
	}
	discard()
}
