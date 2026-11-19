package knowledge

import (
	"errors"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledge/sealed"
)

// sealedForTest builds a sealed.Target from raw bytes by pinning them to
// their own digest. It exists only in tests; production code reaches a
// sealed.Target through sealed.Download (TUF verification) or sealed.Pinned
// (digest bound at verification time).
func sealedForTest(raw []byte) sealed.Target {
	t, err := sealed.Pinned(raw, digestBytes(raw))
	if err != nil {
		panic(err)
	}
	return t
}

// TestEveryAdmitPathReceivesSealedTarget documents the verify-before-read
// guarantee. It is enforced by the compiler: AdmitFunc, every profile admit
// function, checkMinClient and verifySplitTargets accept only sealed.Target,
// whose field is unexported, so code outside package sealed cannot wrap raw
// bytes into one and a call with []byte does not compile. A test cannot
// prove "does not compile"; this one checks that each profile's admit is an
// AdmitFunc and that the only constructors verify what they are given.
func TestEveryAdmitPathReceivesSealedTarget(t *testing.T) {
	profiles := []profileSpec{constraintsProfile(), spiffeX509SVIDProfile(), cloudEventsStructuredJSONProfile(), tikvGCPV2WIFBackupProfile(), constraintsProjectsProfile()}
	for _, p := range profiles {
		var admit AdmitFunc = p.admit
		if admit == nil {
			t.Fatalf("profile %s has no admit function", p.cliName)
		}
		// Not a verified target: a parse failure, never a panic or admission.
		if _, err := admit(sealedForTest([]byte("not json"))); err == nil {
			t.Fatalf("profile %s admitted garbage", p.cliName)
		}
	}
	var checkMin func(sealed.Target) error = checkMinClient
	if err := checkMin(sealedForTest([]byte("{}"))); err != nil {
		t.Fatalf("checkMinClient on an index without a minimum: %v", err)
	}
	// Negative: pinned construction fails closed on a digest mismatch.
	if _, err := sealed.Pinned([]byte("a"), digestBytes([]byte("b"))); !errors.Is(err, sealed.ErrDigest) {
		t.Fatalf("pinned accepted a wrong digest: %v", err)
	}
	if _, err := sealed.Pinned([]byte("a"), ""); !errors.Is(err, sealed.ErrDigest) {
		t.Fatalf("pinned accepted an empty digest: %v", err)
	}
}
