// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

type inTotoExternalFixture struct {
	store, package2, package3 string
	manifest                  knowledgefixture.Manifest
	revision2                 knowledge.ImportReceipt
}

func makeInTotoExternalFixture(t *testing.T) inTotoExternalFixture {
	t.Helper()
	a, err := knowledgefixture.GenerateInTotoConstraints(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var m knowledgefixture.Manifest
	if json.Unmarshal(a.Manifest, &m) != nil {
		t.Fatal("manifest")
	}
	d := t.TempDir()
	store := filepath.Join(d, "store")
	if os.Mkdir(store, 0700) != nil {
		t.Fatal("store")
	}
	root := writeCNCFFile(t, "intoto-root.json", a.Root, 0600)
	p1 := writeCNCFFile(t, "intoto-r1.tar", a.Revision1, 0600)
	p2 := writeCNCFFile(t, "intoto-r2.tar", a.Revision2, 0600)
	p3 := writeCNCFFile(t, "intoto-r3.tar", a.Revision3, 0600)
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: p1, StoreRoot: store, BootstrapRootPath: root, BootstrapRootDigest: m.BootstrapRoot.Digest, ExpectedRevision: "1", ExpectedBundleDigest: m.Revisions[0].BundleDigest}); err != nil {
		t.Fatal(err)
	}
	return inTotoExternalFixture{store: store, package2: p2, package3: p3, manifest: m}
}
func (f *inTotoExternalFixture) import2(t *testing.T) {
	t.Helper()
	r, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: f.package2, StoreRoot: f.store, ExpectedRevision: "2", ExpectedBundleDigest: f.manifest.Revisions[1].BundleDigest})
	if err != nil {
		t.Fatal(err)
	}
	f.revision2 = r
}
func (f *inTotoExternalFixture) import3(t *testing.T) {
	t.Helper()
	if _, err := knowledge.ImportConstraints(knowledge.ImportRequest{PackagePath: f.package3, StoreRoot: f.store, ExpectedRevision: "3", ExpectedBundleDigest: f.manifest.Revisions[2].BundleDigest}); err != nil {
		t.Fatal(err)
	}
}
func inTotoExternalArgs(f inTotoExternalFixture, path, from, to, format string) []string {
	return []string{"check", "cncf", "--project", "in-toto", "--in-toto-run-argv", path, "--from", from, "--to", to, "--knowledge-db", f.store, "--format", format}
}

func TestInTotoRunRawExternalAuthorityAndHistoricalReplay(t *testing.T) {
	t.Parallel()
	f := makeInTotoExternalFixture(t)
	d := t.TempDir()
	real := filepath.Join(d, "real.json")
	realRaw := writeInTotoArgv(t, real, "--key", "REAL")
	code, out, errout := runCNCFCLI(t, inTotoExternalArgs(f, real, "2.2.0", "3.0.0", "human")...)
	if code != ExitUnknown || errout != "" || !strings.Contains(out, "no embedded rule was used") {
		t.Fatalf("no fallback code=%d err=%q out=%s", code, errout, out)
	}
	embedded := inTotoRawArgs(real, "2.2.0", "3.0.0", "human")
	code, out, errout = runCNCFCLI(t, embedded...)
	if code != ExitBlocked || errout != "" {
		t.Fatalf("embedded code=%d err=%q out=%s", code, errout, out)
	}

	f.import2(t)
	one, two := filepath.Join(d, "one.json"), filepath.Join(d, "two.json")
	raw1 := writeInTotoArgv(t, one, "--key", "ONE", "--key", "wrapped", "--", "later")
	raw2 := writeInTotoArgv(t, two, "--key", "TWO", "--signing-key", "wrapped", "--", "later")
	if bytes.Equal(raw1, raw2) {
		t.Fatal("raw variants equal")
	}
	a1 := append(inTotoExternalArgs(f, one, knowledgefixture.SyntheticInTotoFrom, knowledgefixture.SyntheticInTotoTo, "json"), "--in-toto-run-argv-digest", digestCommunityBytes(raw1))
	badRawPin := "sha256:" + strings.Repeat("0", 64)
	badCurrent := append(inTotoExternalArgs(f, one, knowledgefixture.SyntheticInTotoFrom, knowledgefixture.SyntheticInTotoTo, "json"), "--in-toto-run-argv-digest", badRawPin)
	code, out, errout = runCNCFCLI(t, badCurrent...)
	if code != ExitIntegrity || out != "" || errout != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("bad current raw pin code=%d stdout=%q stderr=%q", code, out, errout)
	}
	code, r1, errout := runCNCFCLI(t, a1...)
	if code != ExitBlocked || errout != "" {
		t.Fatalf("report1 code=%d err=%q out=%s", code, errout, r1)
	}
	a2 := append(inTotoExternalArgs(f, two, knowledgefixture.SyntheticInTotoFrom, knowledgefixture.SyntheticInTotoTo, "json"), "--in-toto-run-argv-digest", digestCommunityBytes(raw2))
	code, r2, errout := runCNCFCLI(t, a2...)
	if code != ExitBlocked || errout != "" {
		t.Fatalf("report2 code=%d err=%q out=%s", code, errout, r2)
	}
	var j1, j2 struct {
		Check struct {
			InputFileDigest string `json:"inputFileDigest"`
			Check           struct {
				Claims []json.RawMessage `json:"claims"`
			} `json:"check"`
		} `json:"check"`
	}
	if json.Unmarshal([]byte(r1), &j1) != nil || json.Unmarshal([]byte(r2), &j2) != nil || j1.Check.InputFileDigest == "" || j1.Check.InputFileDigest != j2.Check.InputFileDigest || len(j1.Check.Check.Claims) != 1 || !bytes.Equal(j1.Check.Check.Claims[0], j2.Check.Check.Claims[0]) {
		t.Fatal("canonical observation changed with opaque argv")
	}
	report := filepath.Join(d, "report.json")
	writeCNCFFileAt(t, report, []byte(r1))
	f.import3(t)
	replay := append(inTotoExternalArgs(f, two, knowledgefixture.SyntheticInTotoFrom, knowledgefixture.SyntheticInTotoTo, "human"), "--in-toto-run-argv-digest", digestCommunityBytes(raw2), "--knowledge-revision", "2", "--knowledge-bundle-digest", f.manifest.Revisions[1].BundleDigest, "--knowledge-trust-receipt-digest", f.revision2.TrustReceiptDigest, "--replay-report", report)
	for _, option := range []string{"--in-toto-run-argv-digest", "--knowledge-revision", "--knowledge-bundle-digest", "--knowledge-trust-receipt-digest"} {
		incomplete := omitCLIOption(replay, option)
		code, out, errout = runCNCFCLI(t, incomplete...)
		if code != ExitUsage || out != "" || errout == "" || strings.Contains(errout, two) {
			t.Fatalf("missing %s code=%d stdout=%q stderr=%q", option, code, out, errout)
		}
	}
	badReplay := append([]string(nil), replay...)
	for i := range badReplay {
		if badReplay[i] == "--in-toto-run-argv-digest" {
			badReplay[i+1] = badRawPin
		}
	}
	code, out, errout = runCNCFCLI(t, badReplay...)
	if code != ExitIntegrity || out != "" || errout != "prufyx: CNCF_PREPARATION_INTEGRITY_FAILURE\n" {
		t.Fatalf("bad replay raw pin code=%d stdout=%q stderr=%q", code, out, errout)
	}
	code, out, errout = runCNCFCLI(t, replay...)
	if code != ExitBlocked || errout != "" || !strings.Contains(out, "historical external in-toto-run replay: MATCH") || !strings.Contains(out, "saved report binds the minimized key-option observation") {
		t.Fatalf("replay code=%d err=%q out=%s", code, errout, out)
	}
	for _, value := range []string{string(realRaw), string(raw1), string(raw2), real, one, two, "PRIVATE_STEP", "/private/key", "private-command"} {
		if strings.Contains(r1, value) || strings.Contains(r2, value) || strings.Contains(out, value) {
			t.Fatalf("private argv leaked: %q", value)
		}
	}
	assertStoreDoesNotContain(t, f.store, []string{"PRIVATE_STEP", "/private/key", "private-command", one, two})
}

func omitCLIOption(args []string, option string) []string {
	out := make([]string, 0, len(args)-2)
	for i := 0; i < len(args); i++ {
		if args[i] == option {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}
