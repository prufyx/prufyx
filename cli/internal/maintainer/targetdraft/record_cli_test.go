// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRunRecordRoundTripAndRefusals(t *testing.T) {
	source, in, want := recordGitFixture(t)
	dir := t.TempDir()
	target, row := filepath.Join(dir, "target.json"), filepath.Join(dir, "row.json")
	if err := os.WriteFile(target, want.A, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(row, want.TableRow, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--dir", source.Dir, "--slug", in.Slug, "--name", in.Name, "--repo", in.Repo, "--tags", strings.Join(in.Tags, ","), "--expected-target", target, "--expected-row", row, "--collapse-directories"}
	var out, errOut bytes.Buffer
	if err := runRecord(args, &out, &errOut); err != nil {
		t.Fatalf("record: %v %s", err, errOut.String())
	}
	recorded, err := RecordDraft(in, source, want.A, want.TableRow)
	if err != nil {
		t.Fatal(err)
	}
	var env recordEnvelope
	body := bytes.TrimSpace(out.Bytes())
	if err := json.Unmarshal(body, &env); err != nil ||
		env.Schema != recordEnvelopeSchema ||
		!bytes.Equal(body, mustRecordJSON(t, env)) ||
		env.Rules != "" {
		t.Fatal("invalid canonical record envelope")
	}
	for _, field := range []struct {
		name string
		got  []byte
		want []byte
	}{
		{"recipe", mustRecordDecode(t, env.Recipe), recorded.Recipe},
		{"facts bundle", mustRecordDecode(t, env.FactsBundle), recorded.FactsBundle},
		{"target", mustRecordDecode(t, env.Target), recorded.Target},
		{"report", mustRecordDecode(t, env.Report), recorded.Report},
		{"table row", mustRecordDecode(t, env.TableRow), recorded.TableRow},
		{"changelog", mustRecordDecode(t, env.Changelog), recorded.Changelog},
	} {
		if !bytes.Equal(field.got, field.want) {
			t.Fatalf("%s differs", field.name)
		}
	}
	recipe, err := ParseRecipe(mustRecordDecode(t, env.Recipe))
	if err != nil || recipe.Catalog != "cncf" {
		t.Fatalf("default catalog: %+v %v", recipe, err)
	}
	for _, bad := range [][]string{
		{"--dir", source.Dir},
		append(args, "extra"),
		append(args, "--unknown"),
		append(args, "--derive-duplicate-sources"),
		append(args, "--multi-prefix"),
		append(args, "--infer-install-paths"),
		append(args, "--check-install-path-copies"),
		append(args, "--skip-patch-fragments"),
	} {
		out.Reset()
		if err := runRecord(bad, &out, &errOut); err == nil || out.Len() != 0 {
			t.Fatal("accepted invalid args")
		}
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runRecord(replaceRecordArg(args, target, filepath.Join(dir, "link")), &out, &errOut); err == nil || out.Len() != 0 {
		t.Fatal("accepted symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runRecord(replaceRecordArg(args, target, fifo), &out, &errOut); err == nil || out.Len() != 0 {
		t.Fatal("accepted fifo")
	}
	out.Reset()
	if err := runRecord(replaceRecordArg(args, target, dir), &out, &errOut); err == nil || out.Len() != 0 {
		t.Fatal("accepted directory")
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), maxOutputBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runRecord(replaceRecordArg(args, target, big), &out, &errOut); err == nil || out.Len() != 0 {
		t.Fatal("accepted oversized")
	}
	if err := os.WriteFile(target, []byte("wrong"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runRecord(args, &out, &errOut); err == nil || out.Len() != 0 {
		t.Fatal("accepted mismatch")
	}
}
func mustRecordDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, e := base64.StdEncoding.Strict().DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func mustRecordJSON(t *testing.T, e recordEnvelope) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func replaceRecordArg(args []string, old, next string) []string {
	out := append([]string(nil), args...)
	for i := range out {
		if out[i] == old {
			out[i] = next
		}
	}
	return out
}
