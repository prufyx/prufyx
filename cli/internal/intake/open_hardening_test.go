// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not stop root")
	}
}

func hasReason(w Workspace, display string, reason Reason) bool {
	for _, o := range w.Omissions {
		if o.Source.Display == display && o.Reason == reason {
			return true
		}
	}
	return false
}

func TestOpenUnreadableEntriesAreHardErrors(t *testing.T) {
	skipIfRoot(t)
	dir := root(t)
	write(t, filepath.Join(dir, "a.yaml"), fmt.Sprintf(cm, "a"), 0o600)
	locked := filepath.Join(dir, "z.yaml")
	write(t, locked, fmt.Sprintf(cm, "z"), 0o600)
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := Open([]string{dir}, Options{}); !errors.Is(err, ErrInput) || !strings.Contains(err.Error(), locked) {
		t.Fatalf("unreadable file: %v", err)
	}
	if err := os.Chmod(locked, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	write(t, filepath.Join(sub, "b.yaml"), fmt.Sprintf(cm, "b"), 0o600)
	if err := os.Chmod(sub, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(sub, 0o700)
	if _, err := Open([]string{dir}, Options{}); !errors.Is(err, ErrInput) || !strings.Contains(err.Error(), sub) {
		t.Fatalf("unreadable directory: %v", err)
	}
}

func TestOpenSymlinksAndSpecialFilesAreVisibleOmissions(t *testing.T) {
	dir, outside := root(t), root(t)
	write(t, filepath.Join(outside, "secret.yaml"), fmt.Sprintf(cm, "outside"), 0o600)
	write(t, filepath.Join(dir, "real.yaml"), fmt.Sprintf(cm, "real"), 0o600)
	link, linkDir := filepath.Join(dir, "link.yaml"), filepath.Join(dir, "linkdir")
	if err := os.Symlink(filepath.Join(outside, "secret.yaml"), link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// A pipe without a manifest name is not input and is not reported.
	if err := syscall.Mkfifo(filepath.Join(dir, "other.pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := Open([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names(w), ",") != "real" || len(w.Files) != 1 {
		t.Fatalf("read %v", names(w))
	}
	if !hasReason(w, link, ReasonSymlinkNotFollowed) || !hasReason(w, linkDir, ReasonSymlinkNotFollowed) || !hasReason(w, fifo, ReasonNotRegularFile) || len(w.Omissions) != 3 {
		t.Fatalf("omissions %+v", w.Omissions)
	}
	// Named directly, a pipe is refused without being opened.
	if _, err := Open([]string{fifo}, Options{}); !errors.Is(err, ErrInput) {
		t.Fatalf("named fifo: %v", err)
	}
}

func TestOpenStdinAndFileNamedDashAreDistinct(t *testing.T) {
	dir := root(t)
	write(t, filepath.Join(dir, "-"), fmt.Sprintf(cm, "file"), 0o600)
	t.Chdir(dir)
	for _, paths := range [][]string{{"-", "./-"}, {"./-", "-"}} {
		w, err := Open(paths, Options{Stdin: strings.NewReader(fmt.Sprintf(cm, "stdin"))})
		if err != nil {
			t.Fatal(err)
		}
		if len(w.Files) != 2 || len(w.Documents) != 2 {
			t.Fatalf("%v: files %+v", paths, w.Files)
		}
		displays := w.Files[0].Display + "," + w.Files[1].Display
		if displays != "-,./-" {
			t.Fatalf("displays %s", displays)
		}
	}
}

func TestOpenStdinIsReadOnce(t *testing.T) {
	w, err := Open([]string{"-", "-"}, Options{Stdin: strings.NewReader(fmt.Sprintf(cm, "in"))})
	if err != nil || len(w.Files) != 1 || len(w.Documents) != 1 {
		t.Fatalf("%+v %v", w.Files, err)
	}
}

func TestOpenSameFileUnderTwoSpellingsIsOneRecord(t *testing.T) {
	dir := root(t)
	write(t, filepath.Join(dir, "a.yaml"), fmt.Sprintf(cm, "a"), 0o600)
	t.Chdir(dir)
	single, err := Open([]string{"a.yaml"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(dir, "a.yaml")
	for _, paths := range [][]string{{"a.yaml", abs, "."}, {abs, ".", "a.yaml"}, {".", abs, "a.yaml"}} {
		w, err := Open(paths, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(w.Files) != 1 || len(w.Documents) != 1 || w.Digest != single.Digest || w.Files[0].Display != abs && w.Files[0].Display != "a.yaml" {
			t.Fatalf("%v: %+v", paths, w.Files)
		}
		// The lexically smallest spelling is kept, whatever the order.
		if w.Documents[0].Source.Display != w.Files[0].Display {
			t.Fatalf("%v: kept %q, document %q", paths, w.Files[0].Display, w.Documents[0].Source.Display)
		}
		if w.Files[0].Display != min(abs, "a.yaml") {
			t.Fatalf("%v: kept %q", paths, w.Files[0].Display)
		}
	}
}

func TestOpenHardLinks(t *testing.T) {
	dir := root(t)
	write(t, filepath.Join(dir, "a.yaml"), fmt.Sprintf(cm, "a"), 0o600)
	if err := os.Link(filepath.Join(dir, "a.yaml"), filepath.Join(dir, "b.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open([]string{dir}, Options{}); !errors.Is(err, ErrPermissions) || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("strict: %v", err)
	}
	w, err := Open([]string{dir}, Options{Permissions: RefuseWritable})
	if err != nil || len(w.Files) != 1 || w.Files[0].Display != filepath.Join(dir, "a.yaml") {
		t.Fatalf("refuse-writable: %+v %v", w.Files, err)
	}
}

func TestOpenStrictRequiresOwnFiles(t *testing.T) {
	path := filepath.Join(root(t), "f.yaml")
	write(t, path, fmt.Sprintf(cm, "x"), 0o600)
	real := effectiveUID
	defer func() { effectiveUID = real }()
	effectiveUID = func() uint64 { return real() + 1 }
	if _, err := Open([]string{path}, Options{}); !errors.Is(err, ErrPermissions) || !strings.Contains(err.Error(), "another user") {
		t.Fatalf("strict: %v", err)
	}
	// The mode-only policy does not look at the owner.
	if _, err := Open([]string{path}, Options{Permissions: RefuseWritable}); err != nil {
		t.Fatalf("refuse-writable: %v", err)
	}
	effectiveUID = real
	if _, err := Open([]string{path}, Options{}); err != nil {
		t.Fatalf("own file: %v", err)
	}
}

func TestOpenOwnerOnlyModesAreAccepted(t *testing.T) {
	for mode, want := range map[os.FileMode]bool{0o700: true, 0o500: true, 0o750: false, 0o705: false} {
		path := filepath.Join(root(t), "f.yaml")
		write(t, path, fmt.Sprintf(cm, "x"), 0o600)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() != 0 && mode&0o400 == 0 {
			continue // the owner cannot read it
		}
		_, err := Open([]string{path}, Options{})
		if (err == nil) != want {
			t.Errorf("mode %04o: %v", mode, err)
		}
	}
}

func TestOpenListItemsCountTowardDocuments(t *testing.T) {
	path := filepath.Join(root(t), "l.yaml")
	items := strings.Repeat("- {apiVersion: v1, kind: ConfigMap, metadata: {name: x}}\n", 5)
	write(t, path, "apiVersion: v1\nkind: List\nitems:\n"+items, 0o600)
	if _, err := Open([]string{path}, Options{Limits: Limits{Documents: 4}}); !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), "documents") {
		t.Fatalf("over: %v", err)
	}
	w, err := Open([]string{path}, Options{Limits: Limits{Documents: 5}})
	if err != nil || len(w.Documents) != 5 {
		t.Fatalf("at the bound: %d %v", len(w.Documents), err)
	}
}

func TestOpenNodeBudgetIsSharedAcrossFiles(t *testing.T) {
	dir := root(t)
	body := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n" // 1 map + 3 keys... counted by the decoder
	for _, n := range []string{"a", "b", "c"} {
		write(t, filepath.Join(dir, n+".yaml"), fmt.Sprintf(body, n), 0o600)
	}
	// Room for one file but not for three: the budget is shared, not per file.
	raw, err := os.ReadFile(filepath.Join(dir, "a.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	budget := structuralTokens(raw) + 1
	if _, err := Open([]string{filepath.Join(dir, "a.yaml")}, Options{Limits: Limits{Nodes: budget}}); err != nil {
		t.Fatalf("one file: %v", err)
	}
	if _, err := Open([]string{dir}, Options{Limits: Limits{Nodes: budget}}); !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), "nodes") {
		t.Fatalf("three files: %v", err)
	}
}

func TestOpenSecretStaysStrippedValues(t *testing.T) {
	path := filepath.Join(root(t), "s.yaml")
	write(t, path, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\ndata:\n  k: dG9rZW4=\nstringData:\n  k: plain-token-value\n", 0o600)
	w, err := Open([]string{path}, Options{})
	if err != nil || len(w.Documents) != 1 {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v", w)
	for _, leaked := range []string{"dG9rZW4", "plain-token-value", "stringData"} {
		if strings.Contains(dump, leaked) {
			t.Fatalf("%q survived in %s", leaked, dump)
		}
	}
	if _, ok := w.Documents[0].Value["data"]; ok {
		t.Fatal("data kept")
	}
}

// A flow sequence of one-byte scalars is the densest input for the YAML
// decoder: about two nodes per three bytes. It must be refused before the
// decoder builds a tree, so allocation stays small whatever the file size.
func TestOpenDenseFlowSequenceIsRefusedCheaply(t *testing.T) {
	for _, size := range []int{2 << 20, 8 << 20} {
		path := filepath.Join(root(t), "dense.yaml")
		write(t, path, "["+strings.Repeat("1,", size/2-2)+"1]\n", 0o600)
		limits := Limits{FileBytes: int64(size) + 16, TotalBytes: 64 << 20}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := Open([]string{path}, Options{Limits: limits})
		runtime.ReadMemStats(&after)
		if !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), "nodes") {
			t.Fatalf("%d bytes: %v", size, err)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
			t.Fatalf("%d bytes: %d MiB allocated before refusal", size, allocated>>20)
		}
	}
	// The default per-file bound refuses the 8 MiB file before reading it.
	path := filepath.Join(root(t), "big.yaml")
	write(t, path, "["+strings.Repeat("1,", 4<<20-2)+"1]\n", 0o600)
	if _, err := Open([]string{path}, Options{}); !errors.Is(err, ErrLimit) {
		t.Fatalf("default limits: %v", err)
	}
}

func TestStructuralTokensBoundsRealNodeCount(t *testing.T) {
	for _, text := range []string{
		"[1,2,3]", "{a: 1, b: [2, 3]}", `{"a":1,"b":{"c":[1,2]}}`, "- a\n- b\n- - c\n  - d\n", "a: b\nc:\n  - d\n  - e: f\n",
		"- - - 1\n", "a: {b: c}\n", "---\na: 1\n---\nb: 2\n", "kind: List\nitems:\n- {a: 1}\n- {b: 2}\n",
	} {
		budget := 1000
		if _, err := decodeDocuments([]byte(text), decodeOptions{nodes: &budget}); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if used := 1000 - budget; structuralTokens([]byte(text)) < used {
			t.Errorf("%q: bound %d below %d nodes", text, structuralTokens([]byte(text)), used)
		}
	}
}

// Each limit ends a hostile input in a bounded rejection, and a legitimate
// input just under the bound is accepted and counted.
func TestOpenEachLimitFuzz(t *testing.T) {
	for seed := int64(0); seed < 40; seed++ {
		n := int(seed%7) + 2
		dir := root(t)
		total := int64(0)
		for i := 0; i < n; i++ {
			text := fmt.Sprintf(cm, fmt.Sprint(i)) + strings.Repeat("---\n"+fmt.Sprintf(cm, "x"), int(seed%3))
			write(t, filepath.Join(dir, fmt.Sprintf("f%d.yaml", i)), text, 0o600)
			total += int64(len(text))
		}
		w, err := Open([]string{dir}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		files, docs, bytes := len(w.Files), len(w.Documents), total
		cases := []struct {
			name   string
			ok     Limits
			over   Limits
			expect string
		}{
			{"files", Limits{Files: files}, Limits{Files: files - 1}, "files"},
			{"bytes total", Limits{TotalBytes: bytes}, Limits{TotalBytes: bytes - 1}, "bytes total"},
			{"documents", Limits{Documents: docs}, Limits{Documents: docs - 1}, "documents"},
		}
		for _, c := range cases {
			got, err := Open([]string{dir}, Options{Limits: c.ok})
			if err != nil || len(got.Files) != files || len(got.Documents) != docs {
				t.Fatalf("seed %d %s at bound: files %d docs %d err %v", seed, c.name, len(got.Files), len(got.Documents), err)
			}
			if _, err := Open([]string{dir}, Options{Limits: c.over}); !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), c.expect) {
				t.Fatalf("seed %d %s over: %v", seed, c.name, err)
			}
		}
		// Nodes: find the smallest passing budget and check the one below fails.
		least := 0
		for b := 1; b < 5000; b++ {
			if _, err := Open([]string{dir}, Options{Limits: Limits{Nodes: b}}); err == nil {
				least = b
				break
			}
		}
		if least == 0 {
			t.Fatalf("seed %d: no node budget accepted", seed)
		}
		if _, err := Open([]string{dir}, Options{Limits: Limits{Nodes: least - 1}}); least > 1 && !errors.Is(err, ErrLimit) {
			t.Fatalf("seed %d nodes: %v", seed, err)
		}
	}
}
