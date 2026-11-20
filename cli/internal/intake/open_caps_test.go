// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The default bounds are fixed: no flag, environment variable or input sets
// them. These tests use the real defaults.

func TestDefaultBoundsAreTheDocumentedValues(t *testing.T) {
	if DefaultFileBytes != 8<<20 || DefaultTotalBytes != 256<<20 || DefaultFiles != 16384 || DefaultDocuments != 65536 || DefaultNodes != 6000000 {
		t.Fatalf("defaults changed: %d %d %d %d %d", DefaultFileBytes, DefaultTotalBytes, DefaultFiles, DefaultDocuments, DefaultNodes)
	}
}

func configMapDoc(name string, valueBytes int) string {
	return fmt.Sprintf("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\ndata:\n  v: %q\n", name, strings.Repeat("x", valueBytes))
}

func requireLimit(t *testing.T, err error, name string) {
	t.Helper()
	if !errors.Is(err, ErrLimit) || !strings.Contains(err.Error(), "more than") || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "split the input") {
		t.Fatalf("want a refusal naming %q with the split workaround, got %v", name, err)
	}
}

// A rendered apply set of about 36 MB in files under the per-file bound was
// refused whole by the old 32 MiB total.
func TestOpenAdmitsA36MBApplySetUnderDefaultLimits(t *testing.T) {
	dir := root(t)
	var total int
	for f := 0; f < 5; f++ {
		var b strings.Builder
		for d := 0; b.Len() < 7_400_000; d++ {
			b.WriteString("---\n" + configMapDoc(fmt.Sprintf("c%d-%d", f, d), 100_000))
		}
		total += b.Len()
		write(t, filepath.Join(dir, fmt.Sprintf("chart%d.yaml", f)), b.String(), 0o600)
	}
	if total < 36_000_000 || total <= 32<<20 {
		t.Fatalf("input only %d bytes", total)
	}
	w, err := Open([]string{dir}, Options{})
	if err != nil {
		t.Fatalf("%d bytes refused: %v", total, err)
	}
	if len(w.Files) != 5 {
		t.Fatalf("files %d", len(w.Files))
	}
}

// A cluster export of 9000 objects (old bound 8192) in one file and 30000
// objects spread over files.
func TestOpenAdmitsClusterExportsPastTheOldDocumentBound(t *testing.T) {
	for _, tc := range []struct{ docs, files int }{{9000, 1}, {30000, 30}} {
		dir := root(t)
		for f := 0; f < tc.files; f++ {
			var b strings.Builder
			for d := f; d < tc.docs; d += tc.files {
				b.WriteString("---\n" + configMapDoc(fmt.Sprintf("o%d", d), 8))
			}
			write(t, filepath.Join(dir, fmt.Sprintf("f%03d.yaml", f)), b.String(), 0o600)
		}
		w, err := Open([]string{dir}, Options{})
		if err != nil || len(w.Documents) != tc.docs {
			t.Fatalf("%d documents: %d, %v", tc.docs, len(w.Documents), err)
		}
	}
}

func TestOpenDocumentBoundIsExactAndNamed(t *testing.T) {
	for _, tc := range []struct {
		docs int
		ok   bool
	}{{DefaultDocuments, true}, {DefaultDocuments + 1, false}} {
		dir := root(t)
		per := tc.docs / 8
		for f := 0; f < 8; f++ {
			n := per
			if f == 7 {
				n = tc.docs - 7*per
			}
			write(t, filepath.Join(dir, fmt.Sprintf("f%d.yaml", f)), strings.Repeat("---\napiVersion: v1\nkind: ConfigMap\n", n), 0o600)
		}
		w, err := Open([]string{dir}, Options{})
		if tc.ok {
			if err != nil || len(w.Documents) != tc.docs {
				t.Fatalf("at the bound: %d %v", len(w.Documents), err)
			}
			continue
		}
		requireLimit(t, err, "documents")
	}
}

func TestOpenFileCountBoundIsExactAndNamed(t *testing.T) {
	dir := root(t)
	for f := 0; f < DefaultFiles; f++ {
		write(t, filepath.Join(dir, fmt.Sprintf("f%05d.yaml", f)), "kind: ConfigMap\n", 0o600)
	}
	if w, err := Open([]string{dir}, Options{}); err != nil || len(w.Files) != DefaultFiles {
		t.Fatalf("at the bound: %v", err)
	}
	write(t, filepath.Join(dir, "zz-extra.yaml"), "kind: ConfigMap\n", 0o600)
	_, err := Open([]string{dir}, Options{})
	requireLimit(t, err, "files")
}

// A comment is one line of a single scalar-free node, so padding files with
// one long comment line reaches the byte bound without touching the others.
func TestOpenTotalByteBoundIsExactAndNamed(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 256 MiB")
	}
	dir := root(t)
	head := "kind: ConfigMap\n#"
	full := head + strings.Repeat("x", int(DefaultFileBytes)-len(head))
	for f := 0; f < int(DefaultTotalBytes/DefaultFileBytes); f++ {
		write(t, filepath.Join(dir, fmt.Sprintf("f%02d.yaml", f)), full, 0o600)
	}
	w, err := Open([]string{dir}, Options{})
	if err != nil || len(w.Files) != 32 {
		t.Fatalf("at the bound: %v", err)
	}
	write(t, filepath.Join(dir, "zz-one-byte.yaml"), "\n", 0o600)
	_, err = Open([]string{dir}, Options{})
	requireLimit(t, err, "bytes total")
	if !strings.Contains(err.Error(), "256 MiB") {
		t.Errorf("message does not state the bound: %v", err)
	}
}

// denseDocs is a file of flow sequences of one-byte scalars: the densest
// node-per-byte input that is valid.
func denseDocs(size int) string {
	row := "[" + strings.Repeat("1,", 2000) + "1]\n---\n"
	return strings.Repeat(row, size/len(row))
}

// The node budget is checked before decoding and is shared over all files, so
// a hostile set of dense files cannot make the decoder build more than the
// budget in total, whatever the byte bounds are.
func TestOpenNodeBombIsRefusedWithinTheNodeBudget(t *testing.T) {
	dir := root(t)
	write(t, filepath.Join(dir, "a.yaml"), denseDocs(7<<20), 0o600)
	write(t, filepath.Join(dir, "b.yaml"), denseDocs(7<<20), 0o600)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := Open([]string{dir}, Options{})
	runtime.ReadMemStats(&after)
	requireLimit(t, err, "YAML nodes")
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<30 {
		t.Fatalf("%d MiB allocated before the refusal", allocated>>20)
	}
	// Many files of dense input end at the same budget.
	many := root(t)
	for f := 0; f < 40; f++ {
		write(t, filepath.Join(many, fmt.Sprintf("d%02d.yaml", f)), denseDocs(1<<20), 0o600)
	}
	_, err = Open([]string{many}, Options{})
	requireLimit(t, err, "YAML nodes")
	// One file that cannot be a bounded document is refused by itself.
	single := filepath.Join(root(t), "bomb.yaml")
	write(t, single, "["+strings.Repeat("[],", (8<<20)/3-2)+"[]]\n", 0o600)
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := Open([]string{single}, Options{}); err == nil {
		t.Fatal("dense single file accepted")
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2<<30 {
		t.Fatalf("%d MiB allocated for one dense file", allocated>>20)
	}
}

// An input that uses most of the node budget is accepted within a generous
// memory and time ceiling (measured: about 100 bytes per node retained, 275
// at worst while one file is decoded).
func TestOpenNearBudgetInputStaysWithinCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("builds about 5 million nodes")
	}
	dir := root(t)
	var b strings.Builder
	const files, docs = 25, 1000
	for f := 0; f < files; f++ {
		b.Reset()
		for d := 0; d < docs; d++ {
			fmt.Fprintf(&b, "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: o%d-%d\ndata:\n", f, d)
			for k := 0; k < 90; k++ {
				fmt.Fprintf(&b, "  k%d: v\n", k)
			}
		}
		write(t, filepath.Join(dir, fmt.Sprintf("f%02d.yaml", f)), b.String(), 0o600)
	}
	runtime.GC()
	start := time.Now()
	w, err := Open([]string{dir}, Options{})
	elapsed := time.Since(start)
	if err != nil || len(w.Documents) != files*docs {
		t.Fatalf("%d documents, %v", len(w.Documents), err)
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	runtime.KeepAlive(w)
	if m.HeapAlloc > 1<<30 || m.Sys > 2<<30 {
		t.Errorf("heap %d MiB, process %d MiB", m.HeapAlloc>>20, m.Sys>>20)
	}
	if elapsed > 3*time.Minute {
		t.Errorf("took %v", elapsed)
	}
	t.Logf("%d documents in %v, heap %d MiB, process %d MiB", len(w.Documents), elapsed, m.HeapAlloc>>20, m.Sys>>20)
}

// The small profile only lowers: every bound is at or below the default.
func TestSmallLimitsOnlyLower(t *testing.T) {
	small, def := SmallLimits(), Limits{}.withDefaults()
	if small.FileBytes > def.FileBytes || small.TotalBytes >= def.TotalBytes || small.Files >= def.Files || small.Documents >= def.Documents || small.Nodes >= def.Nodes {
		t.Fatalf("small %+v is not below default %+v", small, def)
	}
}

// The node budget is exact: a file of N nodes passes with a budget of N and is
// refused, naming the nodes, with a budget of N-1.
func TestOpenNodeBudgetBoundaryIsExact(t *testing.T) {
	path := filepath.Join(root(t), "n.yaml")
	write(t, path, configMapDoc("n", 8), 0o600)
	budget := 1
	for ; budget < 1000; budget++ {
		if _, err := Open([]string{path}, Options{Limits: Limits{Nodes: budget}}); err == nil {
			break
		}
	}
	if budget == 1000 {
		t.Fatal("never admitted")
	}
	_, err := Open([]string{path}, Options{Limits: Limits{Nodes: budget - 1}})
	requireLimit(t, err, "YAML nodes")
}
