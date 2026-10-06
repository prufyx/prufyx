// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefixture"
)

func TestSPIFFEX509SVIDEmbeddedOwnFileFixAndPrivacy(t *testing.T) {
	t.Parallel()
	dir := privateDir(t)
	certPath := filepath.Join(dir, "private-certificate.pem")
	writePrivate(t, certPath, makeCertificate(t, "https://private-canary.example/secret", false))
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	code, out, errout := runCommunity(t, "check", "spiffe-x509-svid", "--certificate", certPath, "--now", now)
	if code != ExitBlocked || !strings.Contains(out, "SPIFFE_URI_SAN_SCHEME_NOT_SPIFFE") || strings.Contains(out, "private-canary") || errout != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errout)
	}
	sameCommand := []string{"check", "spiffe-x509-svid", "--certificate", certPath, "--now", now, "--format", "json"}
	code, out, errout = runCommunity(t, sameCommand...)
	if code != ExitBlocked || !strings.Contains(out, "SPIFFE_URI_SAN_SCHEME_NOT_SPIFFE") || errout != "" {
		t.Fatalf("JSON before fix code=%d out=%q err=%q", code, out, errout)
	}
	writePrivate(t, certPath, makeCertificate(t, "spiffe://private-canary.example/workload", false))
	code, out, errout = runCommunity(t, sameCommand...)
	if code != ExitOK || !strings.Contains(out, "SPIFFE_PUBLIC_LEAF_URI_SAN_PROFILE_SATISFIED") || strings.Contains(out, "private-canary") || strings.Contains(out, certPath) || errout != "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errout)
	}
}

func TestSPIFFEX509SVIDExternalNoFallbackAdvanceReplayAndPins(t *testing.T) {
	t.Parallel()
	artifacts, err := knowledgefixture.GenerateSPIFFEX509SVID(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	dir := privateDir(t)
	root := writePublic(t, dir, knowledgefixture.RootName, artifacts.Root)
	rev1 := writePublic(t, dir, knowledgefixture.Revision1Name, artifacts.Revision1)
	rev2 := writePublic(t, dir, knowledgefixture.Revision2Name, artifacts.Revision2)
	rev3 := writePublic(t, dir, knowledgefixture.Revision3Name, artifacts.Revision3)
	db := filepath.Join(dir, "store")
	rootDigest := spiffeTestDigest(artifacts.Root)
	importRevision := func(path string, bootstrap bool) knowledge.ImportReceipt {
		args := []string{"db", "import", path, "--db-root", db, "--profile", "spiffe-x509-svid", "--format", "json"}
		if bootstrap {
			args = append(args, "--bootstrap-root", root, "--bootstrap-root-digest", rootDigest)
		}
		code, out, errout := runCommunity(t, args...)
		if code != 0 || errout != "" {
			t.Fatalf("import code=%d out=%q err=%q", code, out, errout)
		}
		var receipt knowledge.ImportReceipt
		if json.Unmarshal([]byte(out), &receipt) != nil {
			t.Fatalf("bad import %q", out)
		}
		return receipt
	}
	r1 := importRevision(rev1, true)
	certPath := filepath.Join(dir, "private-certificate.pem")
	failing := makeCertificate(t, "https://private-canary.example/secret", false)
	writePrivate(t, certPath, failing)
	code, out, errout := runCommunity(t, "check", "spiffe-x509-svid", "--certificate", certPath, "--knowledge-db", db, "--format", "json")
	if code != ExitUnknown || !strings.Contains(out, "PROFILE_NO_APPLICABLE_RULE") || strings.Contains(out, "SPIFFE_URI_SAN_SCHEME_NOT_SPIFFE") || errout != "" {
		t.Fatalf("empty no-fallback code=%d out=%q err=%q r1=%+v", code, out, errout, r1)
	}
	r2 := importRevision(rev2, false)
	code, out, errout = runCommunity(t, "check", "spiffe-x509-svid", "--certificate", certPath, "--knowledge-db", db, "--knowledge-revision", r2.TrustReceipt.KnowledgeRevision, "--knowledge-bundle-digest", r2.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", r2.TrustReceiptDigest, "--format", "json")
	if code != ExitBlocked || !strings.Contains(out, "SPIFFE_URI_SAN_SCHEME_NOT_SPIFFE") || strings.Contains(out, "private-canary") || strings.Contains(out, spiffeTestDigest(failing)) || errout != "" {
		t.Fatalf("active code=%d out=%q err=%q", code, out, errout)
	}
	assertTreeExcludes(t, db, []string{"private-canary", "https://private-canary.example/secret", spiffeTestDigest(failing), certPath})
	reportPath := filepath.Join(dir, "saved-report.json")
	writePrivate(t, reportPath, []byte(out))
	rawPin := spiffeTestDigest(failing)
	_ = importRevision(rev3, false)
	metadataEquivalent := makeCertificate(t, "https://other-private.example/elsewhere", false)
	writePrivate(t, certPath, metadataEquivalent)
	code, out, errout = runCommunity(t, "check", "spiffe-x509-svid", "--certificate", certPath, "--certificate-digest", spiffeTestDigest(metadataEquivalent), "--knowledge-db", db, "--replay-report", reportPath, "--knowledge-revision", r2.TrustReceipt.KnowledgeRevision, "--knowledge-bundle-digest", r2.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", r2.TrustReceiptDigest, "--format", "json")
	if code != ExitBlocked || !strings.Contains(out, `"status":"MATCH"`) || strings.Contains(out, "private-canary") || strings.Contains(out, "other-private.example") || errout != "" {
		t.Fatalf("replay code=%d out=%q err=%q", code, out, errout)
	}
	code, _, _ = runCommunity(t, "check", "spiffe-x509-svid", "--certificate", certPath, "--certificate-digest", rawPin, "--knowledge-db", db, "--replay-report", reportPath, "--knowledge-revision", r2.TrustReceipt.KnowledgeRevision, "--knowledge-bundle-digest", r2.TrustReceipt.TargetDigest, "--knowledge-trust-receipt-digest", r2.TrustReceiptDigest)
	if code != ExitIntegrity {
		t.Fatalf("wrong raw pin code=%d", code)
	}
}

func assertTreeExcludes(t *testing.T, root string, forbidden []string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, value := range forbidden {
			if strings.Contains(string(raw), value) {
				t.Fatalf("store member %s contains forbidden input value", entry.Name())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSPIFFEX509SVIDModeAndFlagBoundaries(t *testing.T) {
	t.Parallel()
	dir := privateDir(t)
	certPath := filepath.Join(dir, "private-certificate.pem")
	writePrivate(t, certPath, makeCertificate(t, "spiffe://example.org/workload", false))
	reportPath := filepath.Join(dir, "report.json")
	writePrivate(t, reportPath, []byte("{}\n"))
	now := time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	digest := spiffeTestDigest(mustRead(t, certPath))
	cases := [][]string{
		{"check", "spiffe-x509-svid", "--certificate", certPath},
		{"check", "spiffe-x509-svid", "--certificate", certPath, "--now", now, "--knowledge-db", filepath.Join(dir, "store")},
		{"check", "spiffe-x509-svid", "--certificate", certPath, "--now", now, "--knowledge-revision", "1"},
		{"check", "spiffe-x509-svid", "--certificate", certPath, "--replay-report", reportPath},
		{"check", "spiffe-x509-svid", "--certificate", certPath, "--certificate-digest", digest, "--knowledge-db", filepath.Join(dir, "store"), "--replay-report", reportPath, "--knowledge-revision", "1", "--knowledge-bundle-digest", digest},
		{"check", "spiffe-x509-svid", "--certificate", certPath, "--now", "2027-01-01T00:00:00+00:00"},
	}
	for _, args := range cases {
		if code, _, _ := runCommunity(t, args...); code != ExitUsage {
			t.Fatalf("args=%q code=%d", args, code)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runCommunity(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errout bytes.Buffer
	code := Run(context.Background(), args, &out, &errout, "dev")
	return code, out.String(), errout.String()
}
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func writePrivate(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}
func writePublic(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func spiffeTestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func makeCertificate(t *testing.T, uri string, isCA bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PRIVATE-SUBJECT-CANARY"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
