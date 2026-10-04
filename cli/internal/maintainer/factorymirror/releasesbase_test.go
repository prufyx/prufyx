// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mirrorArgs(t *testing.T, e *env, extra ...string) []string {
	t.Helper()
	reg := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(reg, []byte("repos:\n  - acme/widget\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return append([]string{"mirror", "--state", e.state, "--registry", reg, "--remote-base", fileBase(e.root)}, extra...)
}

// The test-only releases API base is refused unless the test flag that
// permits a file:// remote is also given, and must be a plain http(s) URL.
func TestTestReleasesAPIBaseNeedsItsGuard(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"f": "1"})
	getenv := func(string) string { return "" }
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no guard", []string{"--test-releases-api-base", "http://127.0.0.1:1"}, "needs --test-allow-file-remote"},
		{"credentials", []string{"--test-allow-file-remote", "--test-releases-api-base", "http://user:pw@127.0.0.1:1"}, "http(s) URL without credentials"},
		{"scheme", []string{"--test-allow-file-remote", "--test-releases-api-base", "file:///tmp"}, "http(s) URL"},
		{"query", []string{"--test-allow-file-remote", "--test-releases-api-base", "http://127.0.0.1:1/?x=1"}, "http(s) URL"},
	} {
		var stdout, stderr bytes.Buffer
		code := Main(mirrorArgs(t, e, tc.args...), nil, getenv, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), tc.want) {
			t.Fatalf("%s: code %d stderr %q", tc.name, code, stderr.String())
		}
	}
	if _, err := os.Stat(filepath.Join(e.state, "mirror")); err == nil {
		t.Fatal("a refused invocation cloned something")
	}
	if got, err := validateTestAPIBase("", false); err != nil || got != "" {
		t.Fatalf("no flag must be accepted without a guard: %q %v", got, err)
	}
}

// With the guard, release metadata comes from the given base and the
// credential goes there, never to api.github.com.
func TestTestReleasesAPIBaseServesReleases(t *testing.T) {
	fake := newGHFake(t, [][]map[string]any{{rel(2, "v2", false), rel(1, "v1", false)}})
	e := newEnv(t, "github.com/acme/widget")
	e.remote["github.com/acme/widget"].commit("one", map[string]string{"f": "1"})
	e.remote["github.com/acme/widget"].tag("v1", false)
	getenv := func(k string) string {
		if k == "GITHUB_TOKEN" {
			return "standin-token"
		}
		return ""
	}
	var stdout, stderr bytes.Buffer
	args := mirrorArgs(t, e, "--test-allow-file-remote", "--test-releases-api-base", fake.srv.URL+"/")
	if code := Main(args, nil, getenv, &stdout, &stderr); code != 0 {
		t.Fatalf("mirror: %d %s", code, stderr.String())
	}
	var res Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil || res.Cloned != 1 {
		t.Fatalf("%v %s", err, stdout.String())
	}
	rel := e.index().Repos["github.com/acme/widget"].Releases
	if rel.Status != ReleasesKnown || len(rel.Items) != 2 || rel.Items[0].Tag != "v2" {
		t.Fatalf("releases not read from the test base: %+v", rel)
	}
	if len(fake.auth) == 0 || fake.auth[0] != "Bearer standin-token" {
		t.Fatalf("credential not sent to the test base: %v", fake.auth)
	}
}
