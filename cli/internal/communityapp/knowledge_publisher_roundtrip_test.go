// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgereleaseplan"
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
	initialized, err := knowledgesign.Init(knowledgesign.InitOptions{KeyDir: keys, RootExpires: time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339), Passphrase: []byte(pass)})
	if err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(dir, "pass")
	if err := os.WriteFile(passFile, []byte(pass), 0o600); err != nil {
		t.Fatal(err)
	}
	const url = "https://metadata.example.test/cncf-81.tar"
	out := filepath.Join(dir, "release")
	result, err := knowledgerelease.Run(knowledgerelease.Options{
		Revision: "81", Version: 1, Root: filepath.Join(keys, "root.json"), RootDigest: initialized.RootDigest,
		TargetsKey: filepath.Join(keys, "targets.key.pem"), SnapshotKey: filepath.Join(keys, "snapshot.key.pem"), TimestampKey: filepath.Join(keys, "timestamp.key.pem"),
		PassphraseFile: passFile, PackageURL: url, OutputDir: out, Now: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	packageRaw, err := os.ReadFile(filepath.Join(out, "cncf-81.tar"))
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(out, "cncf-81.release-plan.json")
	planRaw, _ := os.ReadFile(planPath)
	if _, err := knowledgereleaseplan.Parse(planRaw); err != nil {
		t.Fatal(err)
	}

	store := filepath.Join(dir, "store")
	code, update, stderr := runReleasePlanUpdate(t, []string{
		"--release-plan", planPath, "--package-out", filepath.Join(dir, "got.tar"), "--db-root", store,
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
		if db.Knowledge.Origin != "external_signed_local" {
			t.Fatalf("%s: db origin=%q", name, db.Knowledge.Origin)
		}
	}
}
