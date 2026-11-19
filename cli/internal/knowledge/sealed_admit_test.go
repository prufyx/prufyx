package knowledge

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/knowledge/internal/seal"
	"github.com/prufyx/prufyx/cli/internal/knowledge/sealed"
)

// sealedForTest builds a sealed.Target from raw bytes by pinning them to
// their own digest. It exists only in tests; production code reaches a
// sealed.Target through seal.Download (TUF verification) or seal.Pinned
// (digest bound at verification time).
func sealedForTest(raw []byte) sealed.Target {
	t, err := seal.Pinned(raw, digestBytes(raw))
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
	if _, err := seal.Pinned([]byte("a"), digestBytes([]byte("b"))); !errors.Is(err, seal.ErrDigest) {
		t.Fatalf("pinned accepted a wrong digest: %v", err)
	}
	if _, err := seal.Pinned([]byte("a"), ""); !errors.Is(err, seal.ErrDigest) {
		t.Fatalf("pinned accepted an empty digest: %v", err)
	}
}

// TestSealConstructorsUnreachableOutsideKnowledge compiles a probe file that
// imports the constructor package from a sibling package (knowledgecheck),
// injected through a build overlay so nothing is written to the tree. The
// compiler must reject it under Go's internal-package rule.
func TestSealConstructorsUnreachableOutsideKnowledge(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain required for the import-restriction check: %v", err)
	}
	dir := t.TempDir()
	probe := filepath.Join(dir, "probe.go")
	src := "package knowledgecheck\n\nimport _ \"github.com/prufyx/prufyx/cli/internal/knowledge/internal/seal\"\n"
	if err := os.WriteFile(probe, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := filepath.Abs(filepath.Join("..", "knowledgecheck", "zz_seal_probe.go"))
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlay, []byte(`{"Replace":{"`+target+`":"`+probe+`"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goBin, "build", "-overlay", overlay, "-o", os.DevNull, "../knowledgecheck")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "use of internal package") {
		t.Fatalf("outside package could import the seal constructors: err=%v out=%s", err, out)
	}
}
