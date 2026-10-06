// SPDX-License-Identifier: AGPL-3.0-only

package knowledgerelease

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
)

const testPassphrase = "throwaway release test passphrase 1"

// fixture creates throwaway keys in t.TempDir(); nothing here is a real key.
func fixture(t *testing.T) Options {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(parent, "keys")
	init, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: keys, RootExpires: time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339), Passphrase: []byte(testPassphrase)})
	if err != nil {
		t.Fatal(err)
	}
	pass := filepath.Join(parent, "pass")
	if err := os.WriteFile(pass, []byte(testPassphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Options{
		Revision: "91", Version: 1,
		Root: filepath.Join(keys, "root.json"), RootDigest: init.RootDigest,
		TargetsKey: filepath.Join(keys, "targets.key.pem"), SnapshotKey: filepath.Join(keys, "snapshot.key.pem"), TimestampKey: filepath.Join(keys, "timestamp.key.pem"),
		PassphraseFile: pass, PackageURL: "https://metadata.example.test/cncf-91.tar",
		OutputDir: filepath.Join(parent, "out"), Now: time.Now().UTC(),
	}
}

func TestReleaseIsDeterministicAndExpiresWithKnowledgeValidity(t *testing.T) {
	a := fixture(t)
	ra, err := Run(a)
	if err != nil {
		t.Fatal(err)
	}
	if ra.Expires == "" || len(ra.Files) != 7 || ra.Receipt.Status != "VERIFIED_FOR_PACKAGING" || ra.Receipt.KnowledgeRevision != "91" {
		t.Fatalf("unexpected result %+v", ra)
	}
	// Same keys and inputs into a second directory give identical bytes.
	b := a
	b.OutputDir = filepath.Join(filepath.Dir(a.OutputDir), "out2")
	if _, err := Run(b); err != nil {
		t.Fatal(err)
	}
	for _, name := range ra.Files {
		x, _ := os.ReadFile(filepath.Join(a.OutputDir, name))
		y, _ := os.ReadFile(filepath.Join(b.OutputDir, name))
		if len(x) == 0 || !bytes.Equal(x, y) {
			t.Fatalf("%s not reproducible", name)
		}
	}
}

func TestReleaseRejections(t *testing.T) {
	cases := map[string]func(*Options){
		"relative output":     func(o *Options) { o.OutputDir = "out" },
		"zero version":        func(o *Options) { o.Version = 0 },
		"bad revision":        func(o *Options) { o.Revision = "x" },
		"expiry beyond rules": func(o *Options) { o.Expires = "2999-01-01T00:00:00Z" },
		"already expired":     func(o *Options) { o.Now = time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC) },
		"wrong root digest":   func(o *Options) { o.RootDigest = "sha256:" + string(bytes.Repeat([]byte("0"), 64)) },
		"non-https url":       func(o *Options) { o.PackageURL = "http://metadata.example.test/x.tar" },
		"missing key":         func(o *Options) { o.SnapshotKey = filepath.Join(filepath.Dir(o.Root), "absent.pem") },
		"swapped role keys":   func(o *Options) { o.TargetsKey, o.SnapshotKey = o.SnapshotKey, o.TargetsKey },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := fixture(t)
			mutate(&o)
			if _, err := Run(o); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	t.Run("loose passphrase file", func(t *testing.T) {
		o := fixture(t)
		if err := os.Chmod(o.PassphraseFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Run(o); err == nil {
			t.Fatal("expected rejection")
		}
	})
	t.Run("existing output", func(t *testing.T) {
		o := fixture(t)
		if err := os.Mkdir(o.OutputDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Run(o); err == nil {
			t.Fatal("expected rejection")
		}
	})
}
