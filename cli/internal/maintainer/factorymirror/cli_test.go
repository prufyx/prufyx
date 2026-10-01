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

func TestMainDeriveMirrorStatusAckEndToEnd(t *testing.T) {
	e := newEnv(t, k1)
	u := e.remote[k1]
	c1 := u.commit("one", map[string]string{"f": "1"})
	u.tag("v1", false)
	dir := t.TempDir()
	reg := filepath.Join(dir, "registry.yaml")
	if err := os.WriteFile(reg, []byte("repos:\n  - acme/widget\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "derived.yaml")
	var stdout, stderr bytes.Buffer
	getenv := func(string) string { return "" }
	if code := Main([]string{"registry", "derive", "--out", out, "--extra", reg}, nil, getenv, &stdout, &stderr); code != 0 {
		t.Fatalf("derive: %d %s", code, stderr.String())
	}
	if raw, _ := os.ReadFile(out); !strings.Contains(string(raw), "github.com/acme/widget") {
		t.Fatalf("%s", raw)
	}
	args := []string{"mirror", "--state", e.state, "--registry", out, "--remote-base", fileBase(e.root)}
	stdout.Reset()
	// The CLI builds its own git runner restricted to the base's scheme.
	if code := Main(args, nil, getenv, &stdout, &stderr); code != 0 {
		t.Fatalf("mirror: %d %s", code, stderr.String())
	}
	var res Result
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil || res.Cloned != 1 {
		t.Fatalf("%v %s", err, stdout.String())
	}
	if !strings.Contains(stderr.String(), "release metadata is recorded as unknown") {
		t.Fatalf("missing-credential notice absent: %s", stderr.String())
	}
	// Second run: nothing to do.
	stdout.Reset()
	if code := Main(args, nil, getenv, &stdout, &stderr); code != 0 {
		t.Fatal("second run failed")
	}
	_ = json.Unmarshal(stdout.Bytes(), &res)
	if res.Unchanged != 1 {
		t.Fatalf("%+v", res)
	}
	// Mutation, status, ack.
	u.commit("two", map[string]string{"f": "2"})
	u.tag("v1", false)
	stdout.Reset()
	Main(args, nil, getenv, &stdout, &stderr)
	_ = json.Unmarshal(stdout.Bytes(), &res)
	if res.NewAlarms != 1 || res.OpenAlarms != 1 {
		t.Fatalf("%+v", res)
	}
	stdout.Reset()
	if code := Main([]string{"status", "--state", e.state}, nil, getenv, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"github.com/acme/widget"`) || !strings.Contains(stdout.String(), c1) {
		t.Fatalf("status: %d %s", code, stdout.String())
	}
	if code := Main([]string{"ack", "--state", e.state, "--repo", "acme/widget"}, nil, getenv, &stdout, &stderr); code != 2 {
		t.Fatal("ack without a note must be rejected")
	}
	if code := Main([]string{"ack", "--state", e.state, "--repo", "acme/widget", "--note", "checked"}, nil, getenv, &stdout, &stderr); code != 0 {
		t.Fatalf("ack failed: %s", stderr.String())
	}
	if code := Main([]string{"bogus"}, nil, getenv, &stdout, &stderr); code != 2 {
		t.Fatal("unknown command accepted")
	}
	if code := Main([]string{"mirror", "--state", e.state}, nil, getenv, &stdout, &stderr); code != 2 {
		t.Fatal("missing registry accepted")
	}
}
