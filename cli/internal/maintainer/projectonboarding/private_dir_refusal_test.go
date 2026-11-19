package projectonboarding

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestProject_NonPrivateDirectoryRefusalsSayWhyAndFix(t *testing.T) {
	dir := openDir(t)
	cases := map[string][]string{
		"init":       {"init", "--repository", "https://github.com/acme/sample", "--output", filepath.Join(dir, "r.json")},
		"init-exact": {"init", "--repository", "https://github.com/acme/sample", "--exact-tag", "v1.0.0", "--license-anchor-tag", "v1.0.0", "--output", filepath.Join(dir, "r.json")},
		"verify":     {"verify", "--snapshot", dir},
		"status":     {"status", "--snapshot", dir},
		"inspect":    {"inspect", "--snapshot", dir},
		"proposal":   {"proposal", "--snapshot", dir},
	}
	for name, args := range cases {
		var stderr bytes.Buffer
		code := Run(context.Background(), args, &bytes.Buffer{}, &stderr, Options{})
		got := stderr.String()
		if code != 2 || !strings.Contains(got, "INVALID_INPUT_OR_INTEGRITY_FAILURE") || !strings.Contains(got, "must be private (mode 0700") || !strings.Contains(got, "chmod 700 ") || !strings.Contains(got, dir) {
			t.Errorf("%s: code=%d stderr=%q", name, code, got)
		}
	}
	// sync with a non-private output parent
	req := filepath.Join(t.TempDir(), "req.json")
	var errOut bytes.Buffer
	if code := Run(context.Background(), []string{"init", "--repository", "https://github.com/acme/sample", "--output", req}, &bytes.Buffer{}, &errOut, Options{}); code != 0 {
		t.Skipf("private request setup unavailable: %q", errOut.String())
	}
	errOut.Reset()
	code := Run(context.Background(), []string{"sync", "--manifest", req, "--output-parent", dir}, &bytes.Buffer{}, &errOut, Options{})
	if code != 2 || !strings.Contains(errOut.String(), "chmod 700 ") {
		t.Errorf("sync: code=%d stderr=%q", code, errOut.String())
	}
}

func TestProject_MissingDirectoryKeepsGenericRefusal(t *testing.T) {
	var stderr bytes.Buffer
	missing := filepath.Join(t.TempDir(), "nope", "r.json")
	code := Run(context.Background(), []string{"init", "--repository", "https://github.com/acme/sample", "--output", missing}, &bytes.Buffer{}, &stderr, Options{})
	if code != 2 || stderr.String() != "project: INVALID_INPUT_OR_INTEGRITY_FAILURE\n" {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestProject_FixCommandIsShellSafe(t *testing.T) {
	base := t.TempDir()
	for name, want := range map[string]string{
		"a$(id)b":  "chmod 700 '",
		"a`id`b":   "chmod 700 '",
		"it's":     `'\''`,
		"nl\nname": "control characters; fix its permissions to 0700",
	} {
		dir := filepath.Join(base, name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		code := Run(context.Background(), []string{"status", "--snapshot", dir}, &bytes.Buffer{}, &stderr, Options{})
		got := stderr.String()
		if code != 2 || !strings.Contains(got, want) {
			t.Errorf("%q: code=%d stderr=%q", name, code, got)
		}
		if strings.Contains(name, "\n") && strings.Contains(got, "chmod") {
			t.Errorf("%q: copy-paste command printed: %q", name, got)
		}
		if strings.Contains(name, "$(") && !strings.Contains(got, "chmod 700 '"+dir+"'") {
			t.Errorf("%q: not single-quoted: %q", name, got)
		}
	}
}
