// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type supervisedTestIdentity struct {
	Dev uint64
	Ino uint64
}

func supervisedTestMemfd(t *testing.T, raw []byte, seals int, writable bool) *os.File {
	t.Helper()
	fd, err := unix.MemfdCreate("supervised-fixture", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "supervised fixture")
	if _, err = f.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = f.Chmod(0500); err != nil {
		t.Fatal(err)
	}
	if seals != 0 {
		if _, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
			t.Fatal(err)
		}
	}
	if writable {
		return f
	}
	ro, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", fd), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return os.NewFile(uintptr(ro), "read-only supervised fixture")
}

func supervisedTestProbe(t *testing.T, git bool) bool {
	t.Helper()
	path := os.Getenv("SUPERVISED_PROBE_EXECUTABLE")
	var cmd *exec.Cmd
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if git {
		cmd = exec.Command("git", "-c", `alias.supervised-probe=!cd "$SUPERVISED_PROBE_CWD" && exec "$SUPERVISED_PROBE_EXECUTABLE" -test.run=^TestSupervisedInheritedProbe$ -test.count=1`, "supervised-probe")
	} else {
		cmd = exec.Command(path, "-test.run=^TestSupervisedInheritedProbe$", "-test.count=1")
	}
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SUPERVISED_PROBE=1", "SUPERVISED_FD_IDENTITIES=" + os.Getenv("SUPERVISED_FD_IDENTITIES"), "SUPERVISED_PROBE_EXECUTABLE=" + path, "SUPERVISED_PROBE_CWD=" + cwd}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return false
	}
	if !bytes.Contains(out, []byte("inherited-supervised-object")) {
		t.Fatalf("probe failed without a detected inherited object: %v %s", err, out)
	}
	return true
}

func TestSupervisedInheritedProbe(t *testing.T) {
	if os.Getenv("SUPERVISED_PROBE") != "1" {
		return
	}
	var wanted []supervisedTestIdentity
	if err := json.Unmarshal([]byte(os.Getenv("SUPERVISED_FD_IDENTITIES")), &wanted); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		fd, e := strconv.Atoi(entry.Name())
		if e != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil {
			continue
		}
		for _, id := range wanted {
			if uint64(st.Dev) == id.Dev && st.Ino == id.Ino {
				fmt.Fprintln(os.Stderr, "inherited-supervised-object")
				os.Exit(23)
			}
		}
	}
	os.Exit(0)
}

func TestSupervisedDescriptorWorker(t *testing.T) {
	mode := os.Getenv("SUPERVISED_DESCRIPTOR_WORKER")
	if mode == "" {
		return
	}
	if mode == "positive-detector" {
		if !supervisedTestProbe(t, false) {
			t.Fatal("detector missed intentionally inherited inputs")
		}
		os.Exit(0)
	}
	if mode == "early-error" {
		var out, errs bytes.Buffer
		code := approvalMain([]string{"sign-supervised", "--unknown-fixture-option"}, approvalEnv{}, DefaultLayout(), &out, &errs)
		if code != 2 || supervisedTestProbe(t, false) {
			t.Fatalf("early error leaked descriptors code=%d err=%s", code, errs.String())
		}
		os.Exit(0)
	}
	var hashes [5]string
	if err := json.Unmarshal([]byte(os.Getenv("SUPERVISED_HASHES")), &hashes); err != nil {
		t.Fatal(err)
	}
	flags := supervisedFlags{executable: hashes[0], draft: hashes[1], keys: hashes[2], export: hashes[3], daily: hashes[4]}
	inputs, err := claimSupervisedInputs()
	if inputs != nil {
		defer inputs.close()
	}
	if err == nil {
		var a, b, c, d []byte
		a, b, c, d, err = inputs.read(flags)
		if err == nil && (!bytes.Equal(a, []byte("fixture draft")) || !bytes.Equal(b, []byte("fixture keys\n")) || !bytes.Equal(c, []byte("fixture export")) || !bytes.Equal(d, []byte("fixture daily"))) {
			t.Fatal("owned input bytes differ")
		}
	}
	if mode == "valid" || mode == "offset" {
		if err != nil {
			t.Fatal(err)
		}
		// Probe while input descriptors are still open: closure alone would
		// not prove close-on-exec protects Git/source subprocesses.
		if supervisedTestProbe(t, false) || supervisedTestProbe(t, true) {
			t.Fatal("validated inputs inherited by child")
		}
		if err = inputs.files[0].SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err = inputs.files[0].Write([]byte("fixture-ready")); err != nil {
			t.Fatal(err)
		}
	} else if err == nil {
		t.Fatal("invalid descriptor request accepted")
	}
	inputs.close()
	if supervisedTestProbe(t, false) {
		t.Fatal("refused request retained input objects")
	}
}

func TestSupervisedInputDescriptors(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	allSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	for _, mode := range []string{"valid", "offset", "positive-detector", "early-error", "swapped", "alias", "writable", "unsealed", "future-write-only", "bad-hash", "oversized", "missing"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer reader.Close()
			raw := [][]byte{program, []byte("fixture draft"), []byte("fixture keys\n"), []byte("fixture export"), []byte("fixture daily")}
			var hashes [5]string
			extra := []*os.File{writer}
			for i, b := range raw {
				hashes[i] = strings.TrimPrefix(CandidateDigest(b), "sha256:")
				seals := allSeals
				writable := false
				if i == 1 {
					switch mode {
					case "writable":
						writable = true
					case "unsealed":
						seals = 0
					case "future-write-only":
						seals = unix.F_SEAL_FUTURE_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
					case "oversized":
						b = bytes.Repeat([]byte{'x'}, maxOnboardingBytes+1)
					}
				}
				extra = append(extra, supervisedTestMemfd(t, b, seals, writable))
			}
			defer func() {
				for _, f := range extra {
					if f != nil {
						_ = f.Close()
					}
				}
			}()
			if mode == "swapped" {
				extra[2], extra[3] = extra[3], extra[2]
			}
			if mode == "alias" {
				_ = extra[3].Close()
				extra[3] = extra[2]
			}
			if mode == "bad-hash" {
				hashes[1] = strings.Repeat("0", 64)
			}
			if mode == "missing" {
				_ = extra[5].Close()
				extra[5] = nil
			}
			if mode == "offset" {
				for _, f := range extra[1:] {
					if _, e = f.Seek(0, io.SeekEnd); e != nil {
						t.Fatal(e)
					}
				}
			}
			var identities []supervisedTestIdentity
			for _, f := range extra {
				if f == nil {
					continue
				}
				var st unix.Stat_t
				if e = unix.Fstat(int(f.Fd()), &st); e != nil {
					t.Fatal(e)
				}
				identities = append(identities, supervisedTestIdentity{Dev: uint64(st.Dev), Ino: st.Ino})
			}
			ids, _ := json.Marshal(identities)
			sum, _ := json.Marshal(hashes)
			cmd := exec.Command("/proc/self/fd/4", "-test.run=^TestSupervisedDescriptorWorker$", "-test.count=1")
			keyRead, keyWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer keyRead.Close()
			defer keyWrite.Close()
			cmd.Stdin = keyRead
			cmd.ExtraFiles = extra
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SUPERVISED_DESCRIPTOR_WORKER=" + mode, "SUPERVISED_HASHES=" + string(sum), "SUPERVISED_FD_IDENTITIES=" + string(ids), "SUPERVISED_PROBE_EXECUTABLE=" + executable}
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			_ = writer.Close()
			if e = cmd.Wait(); e != nil {
				t.Fatalf("%s: %v %s", mode, e, out.String())
			}
		})
	}
}

// A flag-looking legacy value must never select or adopt the supervised ABI.
func TestSupervisedDispatchPreservesLegacyValues(t *testing.T) {
	for _, args := range [][]string{
		{"approval", "sign", "--key", "--admission-supervised"},
		{"approval", "public-key", "--key", "--admission-draft-sha256"},
		{"project", "sign-supervised"},
	} {
		if handled, _ := SupervisedApprovalMain(args, nil, io.Discard, io.Discard); handled {
			t.Fatalf("legacy command selected supervised descriptors: %v", args)
		}
	}
}
