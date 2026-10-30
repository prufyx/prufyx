// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

// The pin is a package variable and t.Setenv forbids t.Parallel, so this test
// runs serially.
func TestDatabaseStatusDefaultStore(t *testing.T) {
	oldPin := pinnedRootDigest
	pinnedRootDigest = func(string) string { return "" }
	t.Cleanup(func() { pinnedRootDigest = oldPin })
	repo, err := knowledgefixture.NewProjectsRepository(time.Now().UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	raw := perProjectPackage(t, repo, 1, "4")
	root := writeCNCFFile(t, "root.json", repo.Root, 0o600)

	installed := t.TempDir() // XDG_DATA_HOME with an installed default store
	t.Setenv("XDG_DATA_HOME", installed)
	store := filepath.Join(installed, "prufyx", "knowledge", "cncf-projects")
	if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
		t.Fatal(err)
	}
	args, _ := updateCLIArgs(t, store, "retained.tar")
	args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", repo.RootDigest)
	for i := range args {
		if args[i] == "cncf" {
			args[i] = "cncf-projects"
		}
	}
	var out, errb bytes.Buffer
	fetch := func(context.Context, string) ([]byte, error) { return raw, nil }
	if code := (runtime{stdout: &out, stderr: &errb}).databaseUpdateWithFetches(context.Background(), args, fetch, fetch); code != ExitOK {
		t.Fatalf("update code=%d out=%s err=%s", code, out.String(), errb.String())
	}

	// Same as an explicit --db-root DIR: a missing leaf directory reports NO_SELECTION.
	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "prufyx", "knowledge"), 0o700); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		xdg  string
		args []string
		code int
		want string
	}{
		{"default store present", installed, []string{"--profile", "cncf-projects"}, ExitOK, "knowledge database state: READY"},
		{"default store absent", empty, []string{"--profile", "cncf-projects"}, ExitUnknown, "NO_SELECTION"},
		{"explicit db-root wins", empty, []string{"--profile", "cncf-projects", "--db-root", store}, ExitOK, "knowledge database state: READY"},
		{"explicit empty db-root still errors", installed, []string{"--profile", "cncf-projects", "--db-root", ""}, ExitUsage, ""},
		{"profile without default location", installed, []string{"--profile", "cncf"}, ExitUsage, ""},
		{"default profile without default location", installed, nil, ExitUsage, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", tc.xdg)
			var stdout, stderr bytes.Buffer
			code := runtime{stdout: &stdout, stderr: &stderr}.databaseStatus(tc.args)
			if code != tc.code || !strings.Contains(stdout.String(), tc.want) {
				t.Fatalf("code=%d want %d out=%s err=%s", code, tc.code, stdout.String(), stderr.String())
			}
		})
	}
}
