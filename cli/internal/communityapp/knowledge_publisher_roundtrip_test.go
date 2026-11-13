// SPDX-License-Identifier: AGPL-3.0-only

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package communityapp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgerelease"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgesign"
)

// The release publisher builds a signed package from the embedded knowledge;
// the client imports it with throwaway keys and must reach the same verdicts
// as the embedded knowledge for the same inputs.
func TestPublisherReleaseRoundTripMatchesEmbeddedVerdicts(t *testing.T) {
	dir, err := filepath.EvalSymlinks(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	const pass = "throwaway roundtrip passphrase 12"
	keys := filepath.Join(dir, "keys")
	initialized, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: keys, RootExpires: time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339), RootPassphrase: []byte("root key passphrase 123456"), Passphrase: []byte(pass)})
	if err != nil {
		t.Fatal(err)
	}
	pinProjects(t, initialized.RootDigest)
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte(pass), 0o600); err != nil {
		t.Fatal(err)
	}
	const url = "https://metadata.example.test/cncf-projects-81.tar"
	out := filepath.Join(dir, "release")
	result, err := knowledgerelease.Run(knowledgerelease.Options{
		Revision: "81", Version: 1, Root: filepath.Join(keys, "root.json"), RootDigest: initialized.RootDigest,
		TargetsKey: filepath.Join(keys, "targets.key.pem"), SnapshotKey: filepath.Join(keys, "snapshot.key.pem"), TimestampKey: filepath.Join(keys, "timestamp.key.pem"),
		PassphraseFile: passFile, FirstRelease: true, OutputDir: out, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	packageRaw, err := os.ReadFile(filepath.Join(out, "cncf-projects-81.tar"))
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"constraints.v1.json", "cncf-81.tar", "cncf-81.release-plan.json"} {
		if _, err := os.Stat(filepath.Join(out, retired)); !os.IsNotExist(err) {
			t.Fatalf("retired producer artifact %s: %v", retired, err)
		}
	}

	store := filepath.Join(dir, "store")
	code, update, stderr := runReleasePlanUpdate(t, []string{
		"--profile", "cncf-projects", "--source", url, "--package-out", filepath.Join(dir, "got.tar"), "--db-root", store,
		"--expected-revision", "81", "--expected-bundle-digest", result.IndexDigest,
		"--bootstrap-root", filepath.Join(out, "root.json"), "--bootstrap-root-digest", initialized.RootDigest, "--format", "json",
	}, func(_ context.Context, source string) ([]byte, error) {
		if source != url {
			t.Fatalf("source=%q", source)
		}
		return packageRaw, nil
	})
	if code != ExitOK || stderr != "" || update.Status != "IMPORTED" || update.ImportReceipt == nil || update.ImportReceipt.TrustReceipt.KnowledgeRevision != "81" || result.Revision != "81" {
		t.Fatalf("update code=%d out=%+v stderr=%q", code, update, stderr)
	}
	receipt := *update.ImportReceipt
	verified := result.Receipt.Verification
	trusted := receipt.TrustReceipt
	if update.Profile != "cncf-projects" || update.PackageDigest != result.PackageDigest || trusted.TargetDigest != result.IndexDigest || trusted.EngineCapabilityDigest != verified.EngineCapabilityDigest || trusted.Root.Digest != verified.Root.Digest || trusted.Targets.Digest != verified.Targets.Digest || trusted.Snapshot.Digest != verified.Snapshot.Digest || trusted.Timestamp.Digest != verified.Timestamp.Digest || !reflect.DeepEqual(receipt.ProjectTargets, verified.ProjectTargets) {
		t.Fatalf("client import lost publisher identities: %+v", receipt)
	}
	projectDigest := ""
	for _, project := range verified.ProjectTargets {
		if project.Project == "kyverno" {
			projectDigest = project.Digest
		}
	}
	if projectDigest == "" {
		t.Fatal("publisher omitted the Kyverno project target")
	}

	for name, input := range map[string]string{"pass": kyvernoInputFalse, "blocked": kyvernoInputTrue, "unknown": kyvernoInputUnknown} {
		raw := []byte(input)
		inputPath := writeKnowledgeReleaseFile(t, dir, "in-"+name+".json", raw)
		base := []string{"check", "cncf", "--project", "kyverno", "--input", inputPath, "--input-digest", releaseDigest(raw), "--format", "json"}
		ec, eout, _ := runCommunity(t, append(base[:len(base):len(base)], "--now", time.Now().UTC().Truncate(time.Second).Format(time.RFC3339))...)
		dc, dout, _ := runCommunity(t, append(base[:len(base):len(base)], "--knowledge-db", store, "--knowledge-revision", "81",
			"--knowledge-bundle-digest", receipt.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", receipt.TrustReceiptDigest)...)
		var emb struct {
			Check struct {
				Claims []struct{ RuleID, Status, ReasonCode string } `json:"claims"`
			} `json:"check"`
		}
		var db cncfknowledge.Report
		if json.Unmarshal([]byte(eout), &emb) != nil || json.Unmarshal([]byte(dout), &db) != nil {
			t.Fatalf("%s: unparsable reports ec=%d dc=%d\n%.300s\n%.100s", name, ec, dc, eout, dout)
		}
		if ec != dc || len(emb.Check.Claims) != len(db.Check.Check.Claims) || len(db.Check.Check.Claims) == 0 {
			t.Fatalf("%s: exit embedded=%d db=%d (%d/%d claims) %.400s", name, ec, dc, len(emb.Check.Claims), len(db.Check.Check.Claims), eout)
		}
		for i, c := range db.Check.Check.Claims {
			e := emb.Check.Claims[i]
			if c.RuleID != e.RuleID || c.Status != e.Status || c.ReasonCode != e.ReasonCode {
				t.Fatalf("%s: verdict differs embedded=%+v db=%+v", name, e, c)
			}
		}
		binding := db.Knowledge.ProjectTarget
		if db.Knowledge.Origin != "external_signed_local" || binding == nil || binding.Status != "present" || binding.Project != "kyverno" || binding.Digest != projectDigest || db.Check.KnowledgePackDigest != binding.Digest {
			t.Fatalf("%s: db origin=%q project=%+v", name, db.Knowledge.Origin, binding)
		}
	}
}
