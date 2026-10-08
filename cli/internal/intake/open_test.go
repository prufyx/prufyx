// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/validation"
)

const cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n"

func root(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func write(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func names(w Workspace) []string {
	var out []string
	for _, d := range w.Documents {
		out = append(out, d.Name)
	}
	return out
}

func TestOpenWalkOrderAndFiltering(t *testing.T) {
	dir := root(t)
	write(t, filepath.Join(dir, "b.yaml"), fmt.Sprintf(cm, "b"), 0o600)
	write(t, filepath.Join(dir, "a.yml"), fmt.Sprintf(cm, "a"), 0o600)
	write(t, filepath.Join(dir, "sub", "c.json"), `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"c"}}`, 0o600)
	write(t, filepath.Join(dir, "sub", "deep", "d.YAML"), fmt.Sprintf(cm, "d"), 0o600)
	write(t, filepath.Join(dir, "notes.txt"), fmt.Sprintf(cm, "txt"), 0o600)
	write(t, filepath.Join(dir, ".git", "x.yaml"), fmt.Sprintf(cm, "git"), 0o600)
	write(t, filepath.Join(dir, ".terraform", "y", "z.yaml"), fmt.Sprintf(cm, "tf"), 0o600)
	var first Workspace
	for i := 0; i < 3; i++ {
		w, err := Open([]string{dir}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(names(w), ","); got != "a,b,c,d" {
			t.Fatalf("documents = %s", got)
		}
		if i == 0 {
			first = w
		} else if w.Digest != first.Digest || len(w.Files) != 4 {
			t.Fatalf("digest not deterministic")
		}
	}
	// Argument order does not change the result.
	w, err := Open([]string{filepath.Join(dir, "sub"), filepath.Join(dir, "b.yaml"), filepath.Join(dir, "a.yml"), filepath.Join(dir, "b.yaml")}, Options{})
	if err != nil || len(w.Files) != 4 || strings.Join(names(w), ",") != "a,b,c,d" {
		t.Fatalf("%v %v", names(w), err)
	}
	if w.Digest != first.Digest {
		t.Fatal("digest depends on argument order")
	}
}

func TestOpenDoesNotFollowSymlinks(t *testing.T) {
	dir, outside := root(t), root(t)
	write(t, filepath.Join(outside, "secret.yaml"), fmt.Sprintf(cm, "outside"), 0o600)
	write(t, filepath.Join(dir, "real.yaml"), fmt.Sprintf(cm, "real"), 0o600)
	if err := os.Symlink(filepath.Join(outside, "secret.yaml"), filepath.Join(dir, "link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linkdir")); err != nil {
		t.Fatal(err)
	}
	w, err := Open([]string{dir}, Options{})
	if err != nil || strings.Join(names(w), ",") != "real" {
		t.Fatalf("%v %v", names(w), err)
	}
	// Named directly, a symlink is refused; so is a symlinked directory and
	// a directory reached through a symlinked ancestor.
	for _, path := range []string{filepath.Join(dir, "link.yaml"), filepath.Join(dir, "linkdir"), filepath.Join(dir, "linkdir", "secret.yaml")} {
		if _, err := Open([]string{path}, Options{}); !errors.Is(err, ErrInput) {
			t.Fatalf("%s: %v", path, err)
		}
	}
	// The helpers refuse a symlink swapped in after the entry was listed.
	handle, err := validation.OpenInputDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	if f, err := validation.OpenEntryFile(handle, "link.yaml"); err == nil {
		f.Close()
		t.Fatal("symlink file opened")
	}
	if f, err := validation.OpenEntryDirectory(handle, "linkdir"); err == nil {
		f.Close()
		t.Fatal("symlink directory opened")
	}
}

func TestOpenDotDotStaysLexicalAndBounded(t *testing.T) {
	dir := root(t)
	write(t, filepath.Join(dir, "in", "a.yaml"), fmt.Sprintf(cm, "a"), 0o600)
	write(t, filepath.Join(dir, "sibling.yaml"), fmt.Sprintf(cm, "sibling"), 0o600)
	w, err := Open([]string{filepath.Join(dir, "in", "..", "in")}, Options{})
	if err != nil || strings.Join(names(w), ",") != "a" {
		t.Fatalf("%v %v", names(w), err)
	}
	if _, err := Open([]string{filepath.Join(dir, "missing", "..", "in")}, Options{}); err == nil {
		// Lexical cleaning is acceptable; the walk never leaves the named root.
		t.Log("lexically cleaned path accepted")
	}
}

func TestOpenLimits(t *testing.T) {
	dir := root(t)
	for i := 0; i < 3; i++ {
		write(t, filepath.Join(dir, fmt.Sprintf("f%d.yaml", i)), fmt.Sprintf(cm, fmt.Sprint(i)), 0o600)
	}
	size := int64(len(fmt.Sprintf(cm, "0")))
	multi := filepath.Join(t.TempDir(), "multi.yaml")
	write(t, multi, strings.Repeat("---\n"+fmt.Sprintf(cm, "x"), 5), 0o600)
	cases := []struct {
		name   string
		path   string
		limits Limits
	}{
		{"bytes per file", dir, Limits{FileBytes: size - 1}},
		{"bytes total", dir, Limits{TotalBytes: size*3 - 1}},
		{"files", dir, Limits{Files: 2}},
		{"documents", multi, Limits{Documents: 4}},
		{"documents across files", dir, Limits{Documents: 2}},
		{"YAML nodes", multi, Limits{Nodes: 10}},
	}
	for _, tc := range cases {
		_, err := Open([]string{tc.path}, Options{Limits: tc.limits})
		if !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), tc.name[:5]) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if _, err := Open([]string{dir}, Options{Limits: Limits{FileBytes: size, TotalBytes: size * 3, Files: 3, Documents: 3}}); err != nil {
		t.Fatalf("limits at the boundary: %v", err)
	}
	// Depth keeps its bound and is a decode error, not a limit.
	deep := filepath.Join(t.TempDir(), "deep.yaml")
	write(t, deep, nested(MaxDepth+2), 0o600)
	if _, err := Open([]string{deep}, Options{}); !errors.Is(err, ErrDecode) {
		t.Fatalf("depth: %v", err)
	}
}

func nested(n int) string {
	return strings.Repeat("[", n) + strings.Repeat("]", n) + "\n"
}

func TestOpenPermissionPolicies(t *testing.T) {
	cases := []struct {
		mode               os.FileMode
		strict, refuseWrit bool // accepted?
		readable           bool
	}{
		{0o600, true, true, false},
		{0o400, true, true, false},
		{0o640, false, true, true},
		{0o644, false, true, true},
		{0o664, false, false, false},
		{0o666, false, false, false},
	}
	for _, tc := range cases {
		path := filepath.Join(root(t), "f.yaml")
		write(t, path, fmt.Sprintf(cm, "x"), tc.mode)
		for policy, want := range map[PermissionPolicy]bool{Strict: tc.strict, RefuseWritable: tc.refuseWrit} {
			w, err := Open([]string{path}, Options{Permissions: policy})
			if (err == nil) != want {
				t.Errorf("mode %04o policy %d: err=%v want accepted=%v", tc.mode, policy, err, want)
				continue
			}
			if err != nil {
				if !errors.Is(err, ErrPermissions) {
					t.Errorf("mode %04o: %v", tc.mode, err)
				}
				continue
			}
			if got := len(w.Notices) == 1; got != tc.readable {
				t.Errorf("mode %04o policy %d: notices %v", tc.mode, policy, w.Notices)
			}
			if tc.readable && w.Notices[0] != "note: 1 input file is readable by other users; use --input-permissions strict to refuse them" {
				t.Errorf("notice %q", w.Notices[0])
			}
			if w.Files[0].Mode != tc.mode {
				t.Errorf("record mode %v", w.Files[0].Mode)
			}
		}
	}
}

func TestOpenStdin(t *testing.T) {
	w, err := Open([]string{"-", "-"}, Options{Permissions: Strict, Stdin: strings.NewReader(fmt.Sprintf(cm, "in"))})
	if err != nil || len(w.Documents) != 1 || w.Files[0].Display != "-" || w.Files[0].Policy != ModeNotApplicable || len(w.Notices) != 0 {
		t.Fatalf("%+v %v", w, err)
	}
	_, err = Open([]string{"-"}, Options{Limits: Limits{FileBytes: 8}, Stdin: strings.NewReader(fmt.Sprintf(cm, "in"))})
	if !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
}

func TestOpenRejectsBadArguments(t *testing.T) {
	for _, paths := range [][]string{nil, {""}, {filepath.Join(root(t), "missing")}} {
		if _, err := Open(paths, Options{}); !errors.Is(err, ErrInput) {
			t.Errorf("%q: %v", paths, err)
		}
	}
}

func TestOpenSecretStaysStripped(t *testing.T) {
	path := filepath.Join(root(t), "s.yaml")
	write(t, path, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  k: dG9rZW4=\nstringData:\n  k: token\n", 0o600)
	w, err := Open([]string{path}, Options{})
	if err != nil || fmt.Sprint(w.Documents[0].Value) == "" || strings.Contains(fmt.Sprintf("%+v", w), "dG9rZW4") {
		t.Fatalf("%v", err)
	}
}

// FuzzOpenRandomTrees builds a random tree and checks that Open either
// succeeds or ends in a bounded, typed rejection, never a panic.
func FuzzOpenRandomTrees(f *testing.F) {
	for seed := int64(0); seed < 8; seed++ {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		rng := rand.New(rand.NewSource(seed))
		dir := root(t)
		bodies := []string{fmt.Sprintf(cm, "x"), "a: [", "{{ .Values.x }}", "", "- 1\n- 2\n", "a: &x 1\nb: *x\n", "---\n---\n", "kind: List\napiVersion: v1\nitems: []\n", strings.Repeat("a", 300)}
		exts := []string{".yaml", ".yml", ".json", ".txt", ""}
		for i, n := 0, rng.Intn(12); i < n; i++ {
			parts := []string{}
			for d, depth := 0, rng.Intn(3); d < depth; d++ {
				parts = append(parts, []string{"a", "b", ".hidden", "c"}[rng.Intn(4)])
			}
			parts = append(parts, fmt.Sprintf("f%d%s", rng.Intn(6), exts[rng.Intn(len(exts))]))
			path := filepath.Join(append([]string{dir}, parts...)...)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				continue
			}
			mode := []os.FileMode{0o600, 0o400, 0o644, 0o666}[rng.Intn(4)]
			_ = os.WriteFile(path, []byte(bodies[rng.Intn(len(bodies))]), 0o600)
			_ = os.Chmod(path, mode)
			if rng.Intn(5) == 0 {
				_ = os.Symlink(path, path+".yaml")
			}
		}
		limits := Limits{FileBytes: int64(1 + rng.Intn(400)), TotalBytes: int64(1 + rng.Intn(2000)), Files: 1 + rng.Intn(8), Documents: 1 + rng.Intn(6), Nodes: 1 + rng.Intn(60)}
		for _, policy := range []PermissionPolicy{Strict, RefuseWritable} {
			w, err := Open([]string{dir}, Options{Permissions: policy, Limits: limits})
			if err != nil {
				if !errors.Is(err, ErrLimit) && !errors.Is(err, ErrPermissions) && !errors.Is(err, ErrDecode) && !errors.Is(err, ErrInput) {
					t.Fatalf("unbounded error: %v", err)
				}
				continue
			}
			if len(w.Files) > limits.Files || len(w.Documents)+len(w.Omissions) > 0 && w.Digest == "" {
				t.Fatalf("limits not enforced: %+v", w.Files)
			}
		}
	})
}

// A refusal from a platform without secure file input keeps its cause (18-m2).
func TestOpenFailureKeepsTheUnsupportedPlatformCause(t *testing.T) {
	err := openFailure("m.yaml", validation.ErrUnsupportedPlatform)
	if !errors.Is(err, ErrInput) || !errors.Is(err, validation.ErrUnsupportedPlatform) || !strings.Contains(err.Error(), "pipe the manifest on standard input") {
		t.Fatalf("got %v", err)
	}
	if err := openFailure("m.yaml", os.ErrNotExist); !errors.Is(err, ErrInput) || errors.Is(err, validation.ErrUnsupportedPlatform) || strings.Contains(err.Error(), "Windows") {
		t.Fatalf("got %v", err)
	}
}
