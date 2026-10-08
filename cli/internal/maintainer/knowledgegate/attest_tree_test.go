// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/maintainer/corpusattest"
)

// A mechanical change applied to a candidate tree leaves the committed
// attestation stale and the gate fails on it. Regenerating with
// "corpus-attestation generate --tree" binds the attestation to the tree's
// own pack bytes, after which the gate reaches the verdict CI reaches:
// pass, with no attestation or generated-file failure.
func TestGateReachesVerdictAfterAttestationFromTree(t *testing.T) {
	base, head, _ := mechanicalTrees(t, nil)
	// Make the head's attestation stale, as it is straight after an
	// extract apply that changed only the pack.
	for _, spec := range DefaultLayout().Packs {
		raw, err := os.ReadFile(filepath.Join(base.Root, filepath.FromSlash(spec.AttestationPath)))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(head.Root, filepath.FromSlash(spec.AttestationPath)), raw)
	}
	opts := Options{Base: base, Head: head, Source: extract.FixtureReader{Root: servedFixture}, Author: DefaultBotLogin}
	requireFail(t, runGate(t, opts), "attestation/cncf")

	for _, pack := range []string{corpusattest.PackCNCF, corpusattest.PackCommunity} {
		var stdout, stderr bytes.Buffer
		if code := corpusattest.Run([]string{"generate", "--pack", pack, "--tree", head.Root}, &stdout, &stderr, "unused"); code != 0 {
			t.Fatalf("%s: generate --tree exit=%d stderr=%s", pack, code, stderr.String())
		}
	}
	requirePass(t, runGate(t, opts))
}
