// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func harborCLIInput(declared bool, argv ...string) []byte {
	encoded, _ := json.Marshal(argv)
	return []byte(`{"apiVersion":"prufyx.io/harbor-installer-argv/v1alpha1","kind":"HarborInstallerArguments","effectiveArgvDeclared":` + map[bool]string{true: "true", false: "false"}[declared] + `,"argv":` + string(encoded) + `}`)
}

func TestHarborPreparationFeedsScopedCheck(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, status string
		argv         []string
		prepareCode  int
		checkCode    int
	}{
		{name: "removed option", status: "BLOCKED", argv: []string{"--with-chartmuseum"}, prepareCode: ExitOK, checkCode: ExitBlocked},
		{name: "complete absence", status: "PASS", argv: []string{"--with-notary", "--with-trivy"}, prepareCode: ExitOK, checkCode: ExitOK},
		{name: "help is unresolved", status: "UNKNOWN", argv: []string{"--help"}, prepareCode: ExitUnknown, checkCode: ExitUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := harborCLIInput(true, tc.argv...)
			path := writeCNCFFile(t, tc.name+".json", raw, 0o600)
			prepareArgs := []string{"prepare", "cncf", "--project", "harbor", "--input", path, "--from", "2.7.0", "--to", "2.8.0", "--format", "input", "--input-digest", cncfDigest(raw)}
			prepareCode, input, stderr := runCNCFCLI(t, prepareArgs...)
			if prepareCode != tc.prepareCode || stderr != "" || !strings.HasSuffix(input, "\n") {
				t.Fatalf("prepare code=%d stderr=%q input=%q", prepareCode, stderr, input)
			}
			preparedPath := writeCNCFFile(t, "prepared-"+tc.name+".json", []byte(input), 0o600)
			checkCode, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "harbor", "--input", preparedPath, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-11T23:30:00Z", "--format", "json")
			if checkCode != tc.checkCode || stderr != "" || !strings.Contains(output, `"status":"`+tc.status+`"`) {
				t.Fatalf("check code=%d stderr=%q output=%s", checkCode, stderr, output)
			}
		})
	}
}

func TestHarborLatestPreparationFeedsScopedCheck(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, from, status string
		argv               []string
		want               int
	}{
		{"removed option", "2.10.3", "BLOCKED", []string{"--with-chartmuseum"}, ExitBlocked},
		{"complete absence", "2.11.2", "PASS", []string{"--with-trivy"}, ExitOK},
		{"ambiguous help", "2.14.4", "UNKNOWN", []string{"--help"}, ExitUnknown},
		{"target-rejected notary", "2.13.5", "UNKNOWN", []string{"--with-notary"}, ExitUnknown},
	} {
		raw := harborCLIInput(true, tc.argv...)
		path := writeCNCFFile(t, "latest-"+tc.name+".json", raw, 0o600)
		prepareCode, input, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "harbor", "--input", path, "--from", tc.from, "--to", "2.15.2", "--format", "input", "--input-digest", cncfDigest(raw))
		if prepareCode != map[int]int{ExitOK: ExitOK, ExitBlocked: ExitOK, ExitUnknown: ExitUnknown}[tc.want] || stderr != "" {
			t.Fatalf("%s prepare=%d stderr=%q", tc.name, prepareCode, stderr)
		}
		preparedPath := writeCNCFFile(t, "latest-prepared-"+tc.name+".json", []byte(input), 0o600)
		checkCode, output, stderr := runCNCFCLI(t, "check", "cncf", "--project", "harbor", "--input", preparedPath, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-12T12:00:00Z", "--format", "json")
		if checkCode != tc.want || stderr != "" || !strings.Contains(output, "\"status\":\""+tc.status+"\"") {
			t.Fatalf("%s check=%d stderr=%q output=%s", tc.name, checkCode, stderr, output)
		}
	}
}

func TestHarborPreparationRejectsMalformedInputAndPinsBytes(t *testing.T) {
	t.Parallel()
	raw := harborCLIInput(true, "--with-chartmuseum")
	path := writeCNCFFile(t, "harbor-private.json", raw, 0o600)
	code, output, stderr := runCNCFCLI(t, "prepare", "cncf", "--project", "harbor", "--input", path, "--from", "2.7.0", "--to", "2.8.0", "--input-digest", "sha256:"+strings.Repeat("0", 64), "--format", "json")
	if code != ExitIntegrity || output != "" || !strings.Contains(stderr, "INTEGRITY_FAILURE") || strings.Contains(stderr, "with-chartmuseum") || strings.Contains(stderr, path) {
		t.Fatalf("wrong digest code=%d stderr=%q output=%q", code, stderr, output)
	}
	bad := writeCNCFFile(t, "harbor-bad.json", []byte(`{"apiVersion":"prufyx.io/harbor-installer-argv/v1alpha1","kind":"HarborInstallerArguments","effectiveArgvDeclared":true,"argv":["--with-chartmuseum","--with-chartmuseum"]}`), 0o600)
	code, output, stderr = runCNCFCLI(t, "prepare", "cncf", "--project", "harbor", "--input", bad, "--from", "2.7.0", "--to", "2.8.0", "--format", "json")
	if code != ExitUnknown || stderr != "" || !strings.Contains(output, `"state":"UNKNOWN"`) {
		t.Fatalf("duplicate argv code=%d stderr=%q output=%q", code, stderr, output)
	}
}
