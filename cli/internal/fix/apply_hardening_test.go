// SPDX-License-Identifier: AGPL-3.0-only

//go:build darwin || linux

package fix

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func fileGroup(t *testing.T, path string) int {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(info.Sys().(*syscall.Stat_t).Gid)
}

func applyOne(root, file string, plan FilePlan) FileResult {
	return Apply([]Target{{Path: file, Plan: plan}}, ApplyOptions{Roots: []string{root}})[0]
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".prufyx-") {
			names = append(names, entry.Name())
		}
	}
	return names
}

func TestApplyKeepsTheGroup(t *testing.T) {
	root, file, plan := workspace(t, 0o640)
	dirGroup, fileGroupBefore := fileGroup(t, filepath.Dir(file)), fileGroup(t, file)
	candidates := []int{65534, 12345}
	if groups, err := os.Getgroups(); err == nil {
		candidates = append(groups, candidates...)
	}
	target := -1
	for _, gid := range candidates {
		if gid == dirGroup || gid == fileGroupBefore || gid == os.Getegid() {
			continue
		}
		if os.Chown(file, -1, gid) == nil {
			target = gid
			break
		}
	}
	if target < 0 {
		t.Skip("no second group to give the file")
	}
	if result := applyOne(root, file, plan); result.Err != nil || !result.Written {
		t.Fatalf("%+v", result)
	}
	if got := fileGroup(t, file); got != target {
		t.Fatalf("group is %d after the write, want %d", got, target)
	}
	info, _ := os.Lstat(file)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", info.Mode())
	}
}

func TestApplyRefusesWhenTheGroupCannotBeKept(t *testing.T) {
	root, file, plan := workspace(t, 0o644)
	original := fchownGroup
	fchownGroup = func(int, uint32) error { return errors.New("injected") }
	defer func() { fchownGroup = original }()
	before := listing(t, root)
	result := applyOne(root, file, plan)
	if ReasonOf(result.Err) != ReasonWriteFailed || result.Written || result.Diff != "" {
		t.Fatalf("%+v", result)
	}
	if listing(t, root) != before {
		t.Fatal("files changed or a temporary file was left")
	}
}

func TestApplyRefusesExtendedAttributes(t *testing.T) {
	root, file, plan := workspace(t, 0o644)
	name := "user.prufyx"
	if runtime.GOOS == "darwin" {
		name = "org.prufyx.test"
	}
	if err := unix.Setxattr(file, name, []byte("1"), 0); err != nil {
		t.Skipf("extended attributes are not available here: %v", err)
	}
	before := listing(t, root)
	result := applyOne(root, file, plan)
	if ReasonOf(result.Err) != ReasonUnsafeFile || result.Written {
		t.Fatalf("%+v", result)
	}
	if listing(t, root) != before {
		t.Fatal("files changed")
	}
}

func TestApplyRefusesWritableParentDirectories(t *testing.T) {
	refused := []os.FileMode{0o775, 0o757, 0o777, 0o770 | 0o002}
	for _, mode := range refused {
		t.Run(fmt.Sprintf("refused %o", mode), func(t *testing.T) {
			root, file, plan := workspace(t, 0o644)
			chmod(t, filepath.Dir(file), mode)
			before := listing(t, root)
			result := applyOne(root, file, plan)
			if ReasonOf(result.Err) != ReasonUnsafeFile || result.Written {
				t.Fatalf("%+v", result)
			}
			if listing(t, root) != before {
				t.Fatal("files changed")
			}
		})
	}
	for name, mode := range map[string]os.FileMode{
		"private":            0o700,
		"readable by others": 0o755,
		"sticky and open":    0o777 | os.ModeSticky,
		"sticky and group":   0o775 | os.ModeSticky,
	} {
		t.Run("allowed "+name, func(t *testing.T) {
			root, file, plan := workspace(t, 0o644)
			chmod(t, filepath.Dir(file), mode)
			if result := applyOne(root, file, plan); result.Err != nil || !result.Written {
				t.Fatalf("%+v", result)
			}
		})
	}
}

func TestApplyOwnerCheck(t *testing.T) {
	root, file, plan := workspace(t, 0o644)
	original := effectiveUID
	effectiveUID = func() int { return os.Geteuid() + 1 }
	defer func() { effectiveUID = original }()
	before := listing(t, root)
	result := applyOne(root, file, plan)
	if ReasonOf(result.Err) != ReasonUnsafeFile || result.Written {
		t.Fatalf("%+v", result)
	}
	if listing(t, root) != before {
		t.Fatal("files changed")
	}
}

func TestApplyTemporaryFileIsExclusive(t *testing.T) {
	fixed := func() (string, error) { return "0123456789abcdef", nil }
	original := tempSuffix
	tempSuffix = fixed
	defer func() { tempSuffix = original }()

	t.Run("existing file", func(t *testing.T) {
		root, file, plan := workspace(t, 0o644)
		temp := filepath.Join(filepath.Dir(file), ".job.yaml.prufyx-0123456789abcdef.tmp")
		if err := os.WriteFile(temp, []byte("precious precious precious precious precious precious\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := listing(t, root)
		result := applyOne(root, file, plan)
		if ReasonOf(result.Err) != ReasonWriteFailed || result.Written {
			t.Fatalf("%+v", result)
		}
		if listing(t, root) != before {
			t.Fatal("the existing file was used or removed")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		root, file, plan := workspace(t, 0o644)
		victim := filepath.Join(root, "victim.txt")
		if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		temp := filepath.Join(filepath.Dir(file), ".job.yaml.prufyx-0123456789abcdef.tmp")
		if err := os.Symlink(victim, temp); err != nil {
			t.Fatal(err)
		}
		before := listing(t, root)
		result := applyOne(root, file, plan)
		if ReasonOf(result.Err) != ReasonWriteFailed || result.Written {
			t.Fatalf("%+v", result)
		}
		if listing(t, root) != before {
			t.Fatal("the symlink was followed or removed")
		}
	})
}

func TestApplyReportsSyncErrors(t *testing.T) {
	t.Run("file sync fails", func(t *testing.T) {
		root, file, plan := workspace(t, 0o644)
		original := syncFile
		syncFile = func(int) error { return errors.New("injected") }
		defer func() { syncFile = original }()
		before := listing(t, root)
		result := applyOne(root, file, plan)
		if ReasonOf(result.Err) != ReasonWriteFailed || result.Written {
			t.Fatalf("%+v", result)
		}
		if listing(t, root) != before {
			t.Fatal("files changed or a temporary file was left")
		}
	})
	t.Run("directory sync fails", func(t *testing.T) {
		root, file, plan := workspace(t, 0o644)
		original := syncDir
		syncDir = func(int) error { return errors.New("injected") }
		defer func() { syncDir = original }()
		result := applyOne(root, file, plan)
		if ReasonOf(result.Err) != ReasonWriteFailed || !result.Written || result.Diff == "" {
			t.Fatalf("%+v", result)
		}
		if content, _ := os.ReadFile(file); !strings.Contains(string(content), "batch/v1 ") {
			t.Fatalf("the replacement is missing: %q", content)
		}
		if names := leftovers(t, filepath.Dir(file)); len(names) != 0 {
			t.Fatalf("leftovers %v", names)
		}
	})
	t.Run("sync primitive works on a file and a directory", func(t *testing.T) {
		root, file, _ := workspace(t, 0o644)
		f, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := syncDescriptor(int(f.Fd())); err != nil {
			t.Fatal(err)
		}
		d, err := os.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if err := syncDescriptor(int(d.Fd())); err != nil {
			t.Fatal(err)
		}
	})
}

// exhaust opens /dev/null until the descriptor limit is hit, then frees
// spare descriptors, so that exactly that many opens can still succeed.
func exhaust(t *testing.T, spare int) (release func()) {
	t.Helper()
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Skip(err)
	}
	original := limit
	var held []*os.File
	// Lower the soft limit to what is open now plus a margin, then fill it.
	listing, err := os.Open("/dev/fd")
	if err != nil {
		t.Skip(err)
	}
	names, err := listing.Readdirnames(-1)
	_ = listing.Close()
	if err != nil {
		t.Skip(err)
	}
	highest := 0
	for _, name := range names {
		var n int
		if _, err := fmt.Sscan(name, &n); err == nil && n > highest {
			highest = n
		}
	}
	limit.Cur = uint64(highest + 1 + 64)
	if original.Max != unix.RLIM_INFINITY && limit.Cur > original.Max {
		t.Skip("descriptor limit cannot be lowered")
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		t.Skip(err)
	}
	for {
		f, err := os.Open(os.DevNull)
		if err != nil {
			break
		}
		held = append(held, f)
	}
	for i := 0; i < spare && len(held) > 0; i++ {
		_ = held[len(held)-1].Close()
		held = held[:len(held)-1]
	}
	return func() {
		for _, f := range held {
			_ = f.Close()
		}
		_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &original)
	}
}

func TestApplyDescriptorExhaustion(t *testing.T) {
	t.Run("reported with its own reason", func(t *testing.T) {
		root, file, plan := workspace(t, 0o644)
		before := listing(t, root)
		release := exhaust(t, 0)
		result := applyOne(root, file, plan)
		release()
		if ReasonOf(result.Err) != ReasonDescriptorLimit || result.Written {
			t.Fatalf("%+v", result)
		}
		if listing(t, root) != before {
			t.Fatal("files changed")
		}
	})
	t.Run("temporary file creation", func(t *testing.T) {
		root, file, plan := workspace(t, 0o644)
		original := beforeRename
		beforeRename = func(*os.File, string) error { return nil }
		defer func() { beforeRename = original }()
		// Exactly enough descriptors for the checks, none for the temporary
		// file: found by trying increasing allowances.
		var got Reason
		for spare := 1; spare <= 8; spare++ {
			release := exhaust(t, spare)
			result := applyOne(root, file, plan)
			release()
			if result.Written {
				break
			}
			got = ReasonOf(result.Err)
			if got != ReasonDescriptorLimit {
				t.Fatalf("spare %d: %+v", spare, result)
			}
		}
		if got != ReasonDescriptorLimit {
			t.Fatalf("no allowance produced the limit; last reason %q", got)
		}
		if names := leftovers(t, filepath.Dir(file)); len(names) != 0 {
			t.Fatalf("leftovers %v", names)
		}
	})
	t.Run("a large batch holds few descriptors", func(t *testing.T) {
		root, _, plan := workspace(t, 0o644)
		dir := filepath.Join(root, "manifests")
		var targets []Target
		for i := 0; i < 150; i++ {
			path := filepath.Join(dir, fmt.Sprintf("job-%03d.yaml", i))
			writeMode(t, path, applySource, 0o644)
			targets = append(targets, Target{Path: path, Plan: plan})
		}
		release := exhaust(t, 12)
		results := Apply(targets, ApplyOptions{Roots: []string{root}})
		release()
		for i, result := range results {
			if result.Err != nil || !result.Written {
				t.Fatalf("target %d: %+v", i, result)
			}
		}
	})
}

func TestApplyRecomputesTheDiff(t *testing.T) {
	root, file, plan := workspace(t, 0o644)
	forged := plan
	forged.Diff = "(benign)"
	before := listing(t, root)
	result := applyOne(root, file, forged)
	if ReasonOf(result.Err) != ReasonInvalidEdit || result.Written || result.Diff != "" {
		t.Fatalf("%+v", result)
	}
	if listing(t, root) != before {
		t.Fatal("files changed")
	}
	// A plan whose edits no request produces is refused on disk too.
	src := []byte(applySource)
	evil, err := Plan("manifests/job.yaml", src, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(applySource, "batch/v1beta1")
	evil.Edits = []Edit{{File: "manifests/job.yaml", StartByte: start, EndByte: start + len("batch/v1beta1"), Replacement: "evil/v1"}}
	evil.Diff = "(benign)"
	result = applyOne(root, file, evil)
	if ReasonOf(result.Err) != ReasonInvalidEdit || result.Written || result.Diff != "" {
		t.Fatalf("%+v", result)
	}
	if listing(t, root) != before {
		t.Fatal("files changed")
	}
	// A genuine apply reports the diff of what it applied.
	result = applyOne(root, file, plan)
	if result.Err != nil || !result.Written || result.Diff != plan.Diff || result.Diff == "" {
		t.Fatalf("%+v", result)
	}
}

// A target is checked first and written later; the file may be swapped in
// between, also for one with the same bytes.
func TestApplyDetectsASwapBetweenCheckAndWrite(t *testing.T) {
	root, first, plan := workspace(t, 0o644)
	second := filepath.Join(filepath.Dir(first), "second.yaml")
	writeMode(t, second, applySource, 0o644)
	original := beforeRename
	calls := 0
	beforeRename = func(*os.File, string) error {
		calls++
		if calls != 1 {
			return nil
		}
		replacement := second + ".new"
		if err := os.WriteFile(replacement, []byte(applySource), 0o644); err != nil {
			return err
		}
		return os.Rename(replacement, second)
	}
	defer func() { beforeRename = original }()
	results := Apply([]Target{{Path: first, Plan: plan}, {Path: second, Plan: plan}}, ApplyOptions{Roots: []string{root}})
	if results[0].Err != nil || !results[0].Written {
		t.Fatalf("first: %+v", results[0])
	}
	if ReasonOf(results[1].Err) != ReasonFileChanged || results[1].Written {
		t.Fatalf("second: %+v", results[1])
	}
	if content, _ := os.ReadFile(second); string(content) != applySource {
		t.Fatalf("the swapped file was written: %q", content)
	}
	if names := leftovers(t, filepath.Dir(first)); len(names) != 0 {
		t.Fatalf("leftovers %v", names)
	}
}
