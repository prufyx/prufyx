// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordDispatchExitContract(t *testing.T) {
	source, in, want := recordGitFixture(t)
	dir := t.TempDir()
	target, row := filepath.Join(dir, "target.json"), filepath.Join(dir, "row.json")
	if err := os.WriteFile(target, want.A, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(row, want.TableRow, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"record", "--dir", source.Dir, "--slug", in.Slug, "--name", in.Name, "--repo", in.Repo, "--tags", strings.Join(in.Tags, ","), "--expected-target", target, "--expected-row", row, "--collapse-directories"}
	var out, stderr bytes.Buffer
	if code := Run(args, &out, &stderr); code != 0 {
		t.Fatalf("record exit %d: %s", code, stderr.String())
	}
	var envelope recordEnvelope
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil || envelope.Schema != recordEnvelopeSchema {
		t.Fatalf("invalid record envelope: %v", err)
	}
	out.Reset()
	stderr.Reset()
	if code := Run([]string{"record"}, &out, &stderr); code != 2 || out.Len() != 0 {
		t.Fatalf("invalid arguments: exit %d", code)
	}
	out.Reset()
	stderr.Reset()
	badSlug := replaceRecordArg(args, in.Slug, "INVALID")
	if code := Run(badSlug, &out, &stderr); code != 1 || out.Len() != 0 {
		t.Fatalf("typed stop: exit %d", code)
	}
	if err := os.WriteFile(target, []byte("wrong"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	stderr.Reset()
	if code := Run(args, &out, &stderr); code != 1 || out.Len() != 0 {
		t.Fatalf("target mismatch: exit %d", code)
	}
}
