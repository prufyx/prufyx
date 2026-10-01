// SPDX-License-Identifier: AGPL-3.0-only

package validation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeAuthorityFixture(t *testing.T, name, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifiedInputsBindExactAcceptedBytes(t *testing.T) {
	policyRaw := `{"apiVersion":"prufyx.io/validation/v1alpha1","kind":"PolicyReference","schemaVersion":"1.0.0","policyId":"p","revision":"r","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	policyPath := writeAuthorityFixture(t, "policy.json", policyRaw)
	policy, err := ReadVerifiedPolicyReference(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	gotDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := mustDigest(t, []byte(policyRaw)), policy.digest; got != want || gotDigest != want {
		t.Fatalf("policy did not retain exact accepted digest: got=%q want=%q", policy.digest, got)
	}

	proposalRaw := `{"apiVersion":"prufyx.io/validation/v1alpha1","kind":"ProposedBundle","schemaVersion":"1.0.0","bundleId":"b","policyRef":{"apiVersion":"prufyx.io/validation/v1alpha1","kind":"PolicyReference","schemaVersion":"1.0.0","policyId":"p","revision":"r","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"components":[{"component":"pkg:oci/prometheus/prometheus","version":"3.14.0","profile":"generic"}]}`
	proposalPath := writeAuthorityFixture(t, "proposal.json", proposalRaw)
	proposal, err := ReadVerifiedProposedBundle(proposalPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := mustDigest(t, []byte(proposalRaw)), proposal.digest; got != want {
		t.Fatalf("proposal did not retain exact accepted digest: got=%q want=%q", got, want)
	}

	// JSON whitespace is accepted by the strict parser but is still part of
	// the exact descriptor identity. It must not collapse to a re-marshaled
	// semantic digest.
	variantRaw := strings.Replace(proposalRaw, `,"bundleId":"b"`, ",\n  \"bundleId\": \"b\"", 1)
	variantPath := writeAuthorityFixture(t, "proposal-variant.json", variantRaw)
	variant, err := ReadVerifiedProposedBundle(variantPath)
	if err != nil {
		t.Fatal(err)
	}
	if proposal.digest == variant.digest {
		t.Fatal("distinct accepted byte encodings collapsed to one authority digest")
	}

	// The retained bytes are private and defensive: corrupting a same-package
	// copy cannot silently change the accepted digest or keep it valid.
	proposal.raw[0] = ' '
	if proposal.Valid() {
		t.Fatal("mutated retained bytes remained valid")
	}
}

func mustDigest(t *testing.T, raw []byte) string {
	t.Helper()
	return DigestBytes(raw)
}
