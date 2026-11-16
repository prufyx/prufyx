// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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
	if err := runRecord(args, &out, &errOut); err != nil || !bytes.Contains(out.Bytes(), []byte(recordEnvelopeSchema)) {
		t.Fatalf("record: %v %s", err, errOut.String())
	}
	for _, bad := range [][]string{{"--dir", source.Dir}, append(args, "extra")} {
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
	if err := os.WriteFile(target, []byte("wrong"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runRecord(args, &out, &errOut); err == nil || out.Len() != 0 {
		t.Fatal("accepted mismatch")
	}
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
