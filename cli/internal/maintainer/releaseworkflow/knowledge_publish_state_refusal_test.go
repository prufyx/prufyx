// SPDX-License-Identifier: AGPL-3.0-only

package releaseworkflow

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeOldestGo stands in for `go build`: it writes, at the -o path, a client
// whose answer for the candidate and for the previous package comes from the
// environment.
const fakeOldestGo = `#!/usr/bin/env bash
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then out="$2"; fi
  shift
done
cat > "${out}" <<'CLIENT'
#!/usr/bin/env bash
case "$3" in
  */artifact/cncf-projects.tar) rc="${CAND_RC}"; msg="${CAND_MSG}" ;;
  *) rc="${OLD_RC}"; msg="${OLD_MSG}" ;;
esac
if [ "${rc}" = 0 ]; then echo '{"status":"VERIFIED"}'; else echo "${msg}" >&2; fi
exit "${rc}"
CLIENT
chmod 700 "${out}"
`

// The gate step is run as written in the workflow. A refusal of the candidate
// passes in mode state only when the previous package is refused the same way.
func TestKnowledgePublishOldestClientGateOutcomes(t *testing.T) {
	for _, tool := range []string{"bash", "jq", "grep"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	wf, _ := loadPublishWorkflow(t)
	steps := wf.Jobs["sign"].Steps
	gate := steps[stepIndex(steps, "Verify with the oldest supported client")]

	const mismatch = "prufyx: KNOWLEDGE CAPABILITY MISMATCH: built for a different engine capability"
	const minClient = mismatch + "; upgrade prufyx to >= v0.1.0-beta.3"
	const tooNew = "prufyx: the knowledge package is too new for this prufyx"
	const integrity = "prufyx: knowledge package verification failed"

	type tc struct {
		name, mode          string
		candRC, candMsg     string
		oldRC, oldMsg       string
		prevPkg, prevDigest string
		prevRevision        string
		pass, warn          bool
	}
	base := func(name string) tc {
		return tc{name: name, mode: "state", candRC: "15", candMsg: mismatch, oldRC: "15", oldMsg: mismatch,
			prevPkg: "/state/previous.tar", prevDigest: "sha256:aa", prevRevision: "12"}
	}
	var cases []tc
	add := func(name string, pass, warn bool, edit func(*tc)) {
		c := base(name)
		c.pass, c.warn = pass, warn
		edit(&c)
		cases = append(cases, c)
	}
	add("state: both refused for capability", true, true, func(*tc) {})
	add("state: candidate accepted", true, false, func(c *tc) { c.candRC = "0" })
	add("state: previous still readable", false, false, func(c *tc) { c.oldRC = "0" })
	for _, rc := range []string{"1", "2", "3", "139"} {
		rc := rc
		add("state: candidate exit "+rc, false, false, func(c *tc) { c.candRC = rc })
		add("state: previous exit "+rc, false, false, func(c *tc) { c.oldRC = rc })
	}
	add("state: candidate integrity text on exit 15", false, false, func(c *tc) { c.candMsg = integrity })
	add("state: previous integrity text on exit 15", false, false, func(c *tc) { c.oldMsg = integrity })
	add("state: candidate too new only", false, false, func(c *tc) { c.candMsg = tooNew })
	add("state: previous too new only", false, false, func(c *tc) { c.oldMsg = tooNew })
	add("state: candidate names a minimum client", false, false, func(c *tc) { c.candMsg = minClient })
	add("state: previous names a minimum client", false, false, func(c *tc) { c.oldMsg = minClient })
	add("state: no previous package", false, false, func(c *tc) { c.prevPkg = "" })
	add("state: no previous digest", false, false, func(c *tc) { c.prevDigest = "" })
	add("state: no previous revision", false, false, func(c *tc) { c.prevRevision = "" })
	for _, mode := range []string{"first", "recovery", ""} {
		mode := mode
		add("mode "+mode+": both refused", false, false, func(c *tc) { c.mode = mode })
	}
	add("capability: previous readable", true, false, func(c *tc) { c.mode, c.oldRC = "capability", "0" })
	add("capability: both refused", false, false, func(c *tc) { c.mode = "capability" })

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, d := range []string{"bin", "tmp/artifact", "ws/oldest/cli/internal/knowledgepin"} {
				if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(name, body string, mode os.FileMode) {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			write("bin/go", fakeOldestGo, 0o700)
			write("ws/oldest/cli/internal/knowledgepin/root.json", "{}", 0o600)
			write("gate.sh", gate.Run, 0o600)
			summary := filepath.Join(dir, "summary")
			cmd := exec.Command("bash", filepath.Join(dir, "gate.sh"))
			cmd.Env = append(os.Environ(),
				"PATH="+filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
				"RUNNER_TEMP="+filepath.Join(dir, "tmp"), "GITHUB_WORKSPACE="+filepath.Join(dir, "ws"), "GITHUB_STEP_SUMMARY="+summary,
				"OLDEST_REF="+strings.Repeat("0", 40), "OLDEST_VERSION=v0.1.0-beta.0", "PACKAGE_DIGEST=sha256:bb", "REVISION=13",
				"MODE="+c.mode, "PREV_PKG="+c.prevPkg, "PREV_DIGEST="+c.prevDigest, "PREV_REVISION="+c.prevRevision,
				"CAND_RC="+c.candRC, "CAND_MSG="+c.candMsg, "OLD_RC="+c.oldRC, "OLD_MSG="+c.oldMsg)
			out, err := cmd.CombinedOutput()
			if (err == nil) != c.pass {
				t.Fatalf("pass=%v, want %v: %v\n%s", err == nil, c.pass, err, out)
			}
			if !c.pass && !strings.Contains(string(out), "the feed keeps the last package") {
				t.Errorf("refusal message missing: %s", out)
			}
			written, _ := os.ReadFile(summary)
			if got := strings.Contains(string(written), "WARNING"); got != c.warn {
				t.Errorf("warning=%v, want %v: %s", got, c.warn, written)
			}
		})
	}
}

// The previous package reaches the gate from the verified state, in mode state
// only.
func TestKnowledgePublishStatePreviousOutputs(t *testing.T) {
	wf, _ := loadPublishWorkflow(t)
	steps := wf.Jobs["sign"].Steps
	run := steps[stepIndex(steps, "Find and verify the previous state")].Run
	script := strings.Index(run, "bash \"${GITHUB_WORKSPACE}/scripts/knowledge-publish-state.sh\"")
	guard := strings.Index(run, "if [ \"${mode}\" = state ]; then")
	if script < 0 || guard < script || strings.Index(run, "state_pkg=${pkg}") < guard || strings.Index(run, "state_digest=${expected_digest}") < guard {
		t.Error("state_pkg and state_digest must be written after verification, in mode state only")
	}
	env := steps[stepIndex(steps, "Verify with the oldest supported client")].Env
	for k, want := range map[string]string{
		"PREV_PKG":      "${{ steps.prevcap.outputs.pkg || steps.prev.outputs.state_pkg }}",
		"PREV_DIGEST":   "${{ steps.prevcap.outputs.digest || steps.prev.outputs.state_digest }}",
		"PREV_REVISION": "${{ steps.prevcap.outputs.revision || steps.prev.outputs.revision }}",
	} {
		if env[k] != want {
			t.Errorf("gate env %s = %q, want %q", k, env[k], want)
		}
	}
}
