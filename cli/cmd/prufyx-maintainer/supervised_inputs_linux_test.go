// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSupervisedOuterEntryWorker(t *testing.T) {
	if os.Getenv("SUPERVISED_OUTER_WORKER") != "1" {
		return
	}
	var args []string
	var identities [][2]uint64
	if err := json.Unmarshal([]byte(os.Getenv("SUPERVISED_OUTER_ARGS")), &args); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(os.Getenv("SUPERVISED_OUTER_IDENTITIES")), &identities); err != nil {
		t.Fatal(err)
	}
	count := func() int {
		entries, e := os.ReadDir("/proc/self/fd")
		if e != nil {
			t.Fatal(e)
		}
		found := 0
		for _, entry := range entries {
			fd, e := strconv.Atoi(entry.Name())
			if e != nil {
				continue
			}
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil {
				continue
			}
			for _, id := range identities {
				if uint64(st.Dev) == id[0] && st.Ino == id[1] {
					found++
				}
			}
		}
		return found
	}
	if count() != 6 {
		t.Fatal("descriptor detector positive control failed")
	}
	var out, errs bytes.Buffer
	err := run(args, &out, &errs)
	var command *commandError
	if !errors.As(err, &command) || command.code != 2 {
		t.Fatalf("invalid supervised command escaped refusal: %v", err)
	}
	if count() != 0 {
		t.Fatalf("outer validation returned with transferred objects open: %s", errs.String())
	}
}

func TestSupervisedOuterEntry(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"unknown-option":            {"approval", "sign-supervised", "--unknown-fixture-option"},
		"duplicate-before-dispatch": {"approval", "sign-supervised", "--identity", "fixture", "--identity", "duplicate"},
		"partial-bindings":          {"approval", "sign-supervised", "--admission-draft-sha256", "incomplete"},
		"empty-body":                {"approval", "sign-supervised"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var files []*os.File
			var identities [][2]uint64
			for i := 0; i < 6; i++ {
				f, e := os.CreateTemp(t.TempDir(), "transport-marker")
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				if _, e = f.Write([]byte("fixture descriptor " + strconv.Itoa(i))); e != nil {
					t.Fatal(e)
				}
				files = append(files, f)
				var st unix.Stat_t
				if e = unix.Fstat(int(f.Fd()), &st); e != nil {
					t.Fatal(e)
				}
				identities = append(identities, [2]uint64{uint64(st.Dev), st.Ino})
			}
			raw, _ := json.Marshal(args)
			ids, _ := json.Marshal(identities)
			cmd := exec.Command(executable, "-test.run=^TestSupervisedOuterEntryWorker$", "-test.count=1")
			cmd.ExtraFiles = files
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SUPERVISED_OUTER_WORKER=1", "SUPERVISED_OUTER_ARGS=" + string(raw), "SUPERVISED_OUTER_IDENTITIES=" + string(ids)}
			if out, e := cmd.CombinedOutput(); e != nil {
				t.Fatalf("%s: %v %s", name, e, out)
			}
		})
	}
}
