// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package knowledgegate

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"golang.org/x/sys/unix"
)

type supervisedAdmissionFixture struct {
	Args                         []string
	Upstream, Batch, Mode, Reads string
}

type supervisedProbeSource struct {
	*obSource
	t *testing.T
}

func (s *supervisedProbeSource) List(repo extract.RepoRef, commit, dir string) ([]extract.TreeEntry, error) {
	if supervisedTestProbe(s.t, false) {
		return nil, fmt.Errorf("source child inherited supervised input")
	}
	return s.obSource.List(repo, commit, dir)
}

func TestSupervisedAdmissionWorker(t *testing.T) {
	if os.Getenv("SUPERVISED_ADMISSION_WORKER") == "" {
		return
	}
	var cfg supervisedAdmissionFixture
	if err := json.Unmarshal([]byte(os.Getenv("SUPERVISED_ADMISSION_WORKER")), &cfg); err != nil {
		t.Fatal(err)
	}
	reads := 0
	var out, errs bytes.Buffer
	src := Source(&supervisedProbeSource{obSource: &obSource{FixtureReader: extract.FixtureReader{Root: cfg.Upstream}, perList: 1}, t: t})
	if cfg.Mode == "source-failure" {
		src = &failedAdmissionSource{Source: src, out: &out, frame: []byte("untrusted human output, never readiness")}
	}
	env := approvalEnv{stdin: os.Stdin, now: func() time.Time { return gateNow }, random: bytes.NewReader(make([]byte, 128)), confirm: func(string) (string, error) { return cfg.Batch, nil }, onboardingSource: src,
		checkStdin: func(r io.Reader) error { reads++; return checkKeyStdin(r) }}
	code := approvalMain(cfg.Args, env, DefaultLayout(), &out, &errs)
	if err := os.WriteFile(cfg.Reads, []byte(fmt.Sprintf("%d", reads)), 0600); err != nil {
		t.Fatal(err)
	}
	if cfg.Mode == "valid" {
		if code != 0 || reads != 1 {
			t.Fatalf("real admission code=%d key reads=%d errors=%s", code, reads, errs.String())
		}
	} else if code != 2 || reads != 0 {
		t.Fatalf("refused admission code=%d key reads=%d errors=%s", code, reads, errs.String())
	}
	if supervisedTestProbe(t, false) {
		t.Fatal("API returned without closing transferred input objects")
	}
}

func TestSupervisedAdmission(t *testing.T) {
	a := newAdmissionFixture(t, nil)
	draft, err := json.Marshal(a.f.draft)
	if err != nil {
		t.Fatal(err)
	}
	export := a.env.binding.Export
	export.DraftDigest = CandidateDigest(draft)
	binding, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := a.opts.Base.Read(a.opts.Layout.ApprovalKeysPath, maxApprovalBytes*4)
	if err != nil {
		t.Fatal(err)
	}
	daily, err := json.Marshal(a.opts.OnboardingGit.DailyCommits)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(a.bot.private)
	if err != nil {
		t.Fatal(err)
	}
	dummyKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	allSeals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	for _, mode := range []string{"valid", "owner", "pathname", "key-file", "source-failure", "malformed-binding", "malformed-daily", "wrong-pin"} {
		t.Run(mode, func(t *testing.T) {
			raw := [][]byte{program, draft, keys, binding, daily}
			if mode == "malformed-binding" {
				raw[3] = []byte(`{"planDigest":"not-a-complete-binding"}`)
			}
			if mode == "malformed-daily" {
				raw[4] = []byte("null")
			}
			reader, writer, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer reader.Close()
			if e = reader.SetReadDeadline(time.Now().Add(5 * time.Minute)); e != nil {
				t.Fatal(e)
			}
			keyRead, keyWrite, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer keyWrite.Close()
			extra := []*os.File{writer}
			var hashes [5]string
			for i, b := range raw {
				extra = append(extra, supervisedTestMemfd(t, b, allSeals, false))
				hashes[i] = strings.TrimPrefix(CandidateDigest(b), "sha256:")
			}
			defer func() {
				for _, f := range extra {
					_ = f.Close()
				}
			}()
			var identities []supervisedTestIdentity
			for _, f := range extra {
				var st unix.Stat_t
				if e = unix.Fstat(int(f.Fd()), &st); e != nil {
					t.Fatal(e)
				}
				identities = append(identities, supervisedTestIdentity{Dev: uint64(st.Dev), Ino: st.Ino})
			}
			g := a.opts.OnboardingGit
			dir := t.TempDir()
			output := filepath.Join(dir, "onboarding", a.f.draft.BatchID+".json")
			if e = os.MkdirAll(filepath.Dir(output), 0700); e != nil {
				t.Fatal(e)
			}
			args := []string{"sign-supervised", "--base", a.opts.Base.Root, "--head", a.opts.Head.Root, "--keys-digest", a.opts.ApprovalKeysDigest, "--identity", botLogin, "--key-stdin", "--expected-key-id", ApprovalKeyID(a.bot.public), "--admission-source", "github", "--admission-git-dir", g.GitDir, "--admission-base", g.BaseCommit, "--admission-head", g.HeadCommit, "--admission-paused", "false", "--admission-observed-at", rfc(g.ObservedAt), "--output", output}
			for i, name := range []string{"executable", "draft", "keys", "export", "daily"} {
				args = append(args, "--admission-"+name+"-sha256", hashes[i])
			}
			if mode == "owner" {
				for i, v := range args {
					if v == "--identity" {
						args[i+1] = obOwner
					}
				}
			}
			if mode == "wrong-pin" {
				for i, v := range args {
					if v == "--keys-digest" {
						args[i+1] = CandidateDigest([]byte("different fixture pin"))
					}
				}
			}
			if mode == "pathname" {
				args = append(args, "--onboarding", filepath.Join(dir, "unused-draft"))
			}
			if mode == "key-file" {
				args = append(args, "--key", filepath.Join(dir, "unused-key"))
			}
			cfg := supervisedAdmissionFixture{Args: args, Upstream: a.f.upstream, Batch: a.f.draft.BatchID, Mode: mode, Reads: filepath.Join(dir, "key-read-count")}
			cfgRaw, _ := json.Marshal(cfg)
			ids, _ := json.Marshal(identities)
			cmd := exec.Command("/proc/self/fd/4", "-test.run=^TestSupervisedAdmissionWorker$", "-test.count=1")
			cmd.ExtraFiles = extra
			cmd.Stdin = keyRead
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SUPERVISED_ADMISSION_WORKER=" + string(cfgRaw), "SUPERVISED_PROBE_EXECUTABLE=" + executable, "SUPERVISED_FD_IDENTITIES=" + string(ids)}
			var log bytes.Buffer
			cmd.Stdout = &log
			cmd.Stderr = &log
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			_ = writer.Close()
			_ = keyRead.Close()
			want := readinessExpected(a)
			want.Binding.Export = export
			_, readyErr := ReadOnboardingReadiness(reader, want)
			if mode == "valid" {
				if readyErr != nil {
					_ = keyWrite.Close()
					_ = cmd.Wait()
					t.Fatalf("real admission emitted no valid readiness: %v %s", readyErr, log.String())
				}
				if _, e = keyWrite.Write(dummyKey); e != nil {
					t.Fatal(e)
				}
			} else if readyErr == nil {
				_ = keyWrite.Close()
				_ = cmd.Wait()
				t.Fatal("refused input emitted readiness")
			}
			_ = keyWrite.Close()
			if e = cmd.Wait(); e != nil {
				t.Fatalf("%s: %v %s", mode, e, log.String())
			}
			count, e := os.ReadFile(cfg.Reads)
			if e != nil {
				t.Fatal(e)
			}
			if mode != "valid" {
				if string(count) != "0" {
					t.Fatal("private-key input checked before admitted readiness")
				}
				if _, e = os.Stat(output); !os.IsNotExist(e) {
					t.Fatal("refused input wrote an approval")
				}
				return
			}
			if string(count) != "1" {
				t.Fatal("valid key input count differs")
			}
			signed, e := os.ReadFile(output)
			if e != nil {
				t.Fatal(e)
			}
			envelope, e := decodeOnboarding(signed)
			if e != nil {
				t.Fatal(e)
			}
			if envelope.Schema != OnboardingSchemaV2 {
				t.Fatal("supervised bot route downgraded")
			}
			if e = verifyOnboardingSignature(envelope, a.keys, gateNow); e != nil {
				t.Fatal(e)
			}
		})
	}
}
