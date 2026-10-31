// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"archive/tar"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// After an engine capability change the previous package is verified by the
// client of the commit that produced it. The two steps hold no secret, run
// only in that case, and use a pinned checkout without credentials.
func TestKnowledgePublishCapabilityChangeSteps(t *testing.T) {
	wf, raw := loadPublishWorkflow(t)
	steps := wf.Jobs["sign"].Steps
	prev := stepIndex(steps, "Find and verify the previous state")
	checkout := stepIndex(steps, "Check out the commit that produced the previous package")
	verify := stepIndex(steps, "Verify the previous package with the client that produced it")
	signed := stepIndex(steps, "Build, sign and verify")
	gate := stepIndex(steps, "Verify with the oldest supported client")
	if prev < 0 || checkout < 0 || verify < 0 || signed < 0 || gate < 0 {
		t.Fatalf("missing step: prev=%d checkout=%d verify=%d sign=%d gate=%d", prev, checkout, verify, signed, gate)
	}
	if !(prev < checkout && checkout < verify && verify < signed && signed < gate) {
		t.Errorf("order wrong: %d %d %d %d %d", prev, checkout, verify, signed, gate)
	}
	for _, i := range []int{checkout, verify} {
		st := steps[i]
		if st.If != "${{ steps.prev.outputs.mismatch == 'true' }}" {
			t.Errorf("%q: if = %q", st.Name, st.If)
		}
		if st.ContinueOnError != nil {
			t.Errorf("%q: must not set continue-on-error", st.Name)
		}
		for k, v := range st.Env {
			if secretsRef.MatchString(v) {
				t.Errorf("%q: env %s references secrets", st.Name, k)
			}
		}
		if secretsRef.MatchString(st.Run) || strings.Contains(st.Run, "github.token") || strings.Contains(st.Run, "GH_TOKEN") {
			t.Errorf("%q touches a token or secret", st.Name)
		}
	}
	co := steps[checkout]
	if !regexp.MustCompile(`^actions/checkout@[0-9a-f]{40}$`).MatchString(co.Uses) {
		t.Errorf("checkout %q is not pinned", co.Uses)
	}
	if v, ok := co.With["persist-credentials"].(bool); !ok || v {
		t.Error("checkout must set persist-credentials: false")
	}
	if co.With["ref"] != "${{ steps.prev.outputs.prev_sha }}" || co.With["path"] != "producing" {
		t.Errorf("checkout with = %v", co.With)
	}
	run := steps[verify].Run
	for _, want := range []string{"GOTOOLCHAIN=local", "db verify", "--expected-package-digest", "--bootstrap-root", "MODE=capability", "knowledge-publish-state.sh", "the feed keeps the last package"} {
		if !strings.Contains(run, want) {
			t.Errorf("verify run block lacks %q", want)
		}
	}
	// The pinned root is the one of this tree, never the producing commit's.
	if strings.Contains(run, "producing/cli/internal/knowledgepin") {
		t.Error("the producing commit's root must not be used")
	}
	// The signing step reads the state of either step and uses the first-release
	// layout in capability mode, with the next revision and TUF version.
	sr := steps[signed].Run
	if !strings.Contains(sr, `elif [ "${MODE}" = capability ]; then`) || !strings.Contains(sr, "layout=(--first-release)") {
		t.Error("the signing step lacks the capability layout")
	}
	i := strings.Index(sr, `elif [ "${MODE}" = capability ]; then`)
	j := strings.Index(sr[i:], "layout=(--first-release)")
	if block := sr[i : i+j]; !strings.Contains(block, "revision=$((PREV_REVISION + 1))") || !strings.Contains(block, "version=$((PREV_TUF + 1))") {
		t.Error("capability mode must continue the revision and the TUF version")
	}
	for _, k := range []string{"MODE", "PREV_REVISION", "PREV_TUF", "PREV_RULES", "PREV_CREATED", "PREV_INDEX"} {
		want := "steps.prevcap.outputs."
		if v := steps[signed].Env[k]; !strings.Contains(v, want) || !strings.Contains(v, "steps.prev.outputs.") {
			t.Errorf("sign env %s = %q", k, v)
		}
	}
	// A capability change never skips: the skip decision needs mode state.
	if !strings.Contains(sr, `[ "${MODE}" = state ]`) {
		t.Error("skip must stay limited to mode state")
	}
	// The gate accepts a clean refusal only, and only with a healthy old client.
	gr := steps[gate].Run
	for _, want := range []string{`[ "${MODE}" = capability ]`, `[ "${orc}" = 15 ]`, "too new for this prufyx", "KNOWLEDGE CAPABILITY MISMATCH", "${PREV_PKG}", "prev-receipt.json"} {
		if !strings.Contains(gr, want) {
			t.Errorf("gate run block lacks %q", want)
		}
	}
	// A registry or engine change must trigger a publish.
	for _, p := range []string{"cli/internal/customresources/table.json", "cli/internal/cncfcheck/data/**", "cli/internal/constraintengine/**"} {
		if !strings.Contains(raw, `- "`+p+`"`) {
			t.Errorf("push paths lack %s", p)
		}
	}
}

func tarWith(t *testing.T, names ...string) string {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, n := range names {
		body := []byte(`{"revision":"7"}`)
		if err := w.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "previous.tar")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKnowledgePublishStateScript(t *testing.T) {
	repo := repoRoot(t)
	for _, tool := range []string{"bash", "jq", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	if out, err := exec.Command("date", "-u", "-d", "@0", "+%s").CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "0" {
		t.Skip("GNU date required")
	}
	script := filepath.Join(repo, "scripts", "knowledge-publish-state.sh")
	index := "targets/knowledge/cncf/" + strings.Repeat("a", 64) + ".index.v1.json"
	run := func(t *testing.T, pkg, receipt, mode, prevTUF string) (string, string, error) {
		dir := t.TempDir()
		rf := filepath.Join(dir, "receipt.json")
		if err := os.WriteFile(rf, []byte(receipt), 0o600); err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(dir, "state")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		outFile := filepath.Join(dir, "out")
		cmd := exec.Command("bash", script)
		cmd.Env = append(os.Environ(), "PKG="+pkg, "RECEIPT="+rf, "MODE="+mode, "CREATED=2026-10-30T13:50:00Z", "PREV_TUF="+prevTUF, "STATE_DIR="+state, "MAX_INDEX_BYTES=1048576", "GITHUB_OUTPUT="+outFile)
		out, err := cmd.CombinedOutput()
		written, _ := os.ReadFile(outFile)
		return string(written), string(out), err
	}
	good := `{"knowledgeRevision":"7","timestamp":{"version":12},"ruleDigest":"sha256:` + strings.Repeat("b", 64) + `"}`
	t.Run("state", func(t *testing.T) {
		out, _, err := run(t, tarWith(t, index), good, "state", "")
		if err != nil || !strings.Contains(out, "mode=state\n") || !strings.Contains(out, "revision=7\n") || !strings.Contains(out, "tuf=12\n") || !strings.Contains(out, "index=") {
			t.Fatalf("err=%v out=%q", err, out)
		}
	})
	t.Run("capability mode is passed through", func(t *testing.T) {
		out, _, err := run(t, tarWith(t, index), good, "capability", "")
		if err != nil || !strings.Contains(out, "mode=capability\n") {
			t.Fatalf("err=%v out=%q", err, out)
		}
	})
	t.Run("recovery needs the stated TUF version", func(t *testing.T) {
		if _, msg, err := run(t, tarWith(t, index), good, "recovery", "13"); err == nil || !strings.Contains(msg, "previous_tuf_version does not match") {
			t.Fatalf("err=%v msg=%q", err, msg)
		}
		if _, _, err := run(t, tarWith(t, index), good, "recovery", "12"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("no index, two indexes, bad numbers", func(t *testing.T) {
		other := "targets/knowledge/cncf/" + strings.Repeat("c", 64) + ".index.v1.json"
		if _, msg, err := run(t, tarWith(t, "targets/other.json"), good, "state", ""); err == nil || !strings.Contains(msg, "exactly one index") {
			t.Fatalf("no index: err=%v msg=%q", err, msg)
		}
		if _, msg, err := run(t, tarWith(t, index, other), good, "state", ""); err == nil || !strings.Contains(msg, "exactly one index") {
			t.Fatalf("two indexes: err=%v msg=%q", err, msg)
		}
		bad := `{"knowledgeRevision":"0","timestamp":{"version":12},"ruleDigest":"x"}`
		if _, msg, err := run(t, tarWith(t, index), bad, "state", ""); err == nil || !strings.Contains(msg, "revision is not a positive integer") {
			t.Fatalf("bad revision: err=%v msg=%q", err, msg)
		}
	})
}
