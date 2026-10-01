// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	args := []string{"mirror", "--state", e.state, "--registry", out, "--remote-base", fileBase(e.root), "--test-allow-file-remote"}
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

func TestMirrorRejectsUnsafeRemoteBases(t *testing.T) {
	e := newEnv(t, k1)
	e.remote[k1].commit("one", map[string]string{"f": "1"})
	reg := filepath.Join(t.TempDir(), "registry.yaml")
	if err := os.WriteFile(reg, []byte("repos:\n  - acme/widget\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	getenv := func(string) string { return "" }
	for _, base := range []string{
		"ext::sh -c 'touch " + marker + "' %s ",
		"ext::touch " + marker + "/",
		"git://example.invalid/",
		"ssh://example.invalid/",
		"http://example.invalid/",
		"HTTPS://example.invalid/",
		"https://example.invalid/ -oProxyCommand=x/",
		"file://" + e.root + "/", // needs the explicit test flag
	} {
		args := []string{"mirror", "--state", e.state, "--registry", reg, "--remote-base", base}
		var stdout, stderr bytes.Buffer
		code := Main(args, nil, getenv, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("remote base %q accepted: code %d %s", base, code, stderr.String())
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("transport helper ran")
	}
	if _, err := os.Stat(filepath.Join(e.state, "mirror")); err == nil {
		t.Fatal("something was cloned")
	}
}

func TestRunRejectsUnsafeRemoteBaseWithDefaultGit(t *testing.T) {
	for _, base := range []string{"ext::sh -c x ", "file:///tmp/"} {
		_, err := Run(context.Background(), Options{StateDir: t.TempDir(), Repos: []Repo{mustRepo(t, k1)}, RemoteBase: base})
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("base %q: %v", base, err)
		}
	}
}
