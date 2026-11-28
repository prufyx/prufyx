// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import "testing"

// A valid approval of the rule whose range changes, even a narrowing one, is
// no authority for the pack level raise.
func TestOptInSchemaRuleApprovalOnlyRefused(t *testing.T) {
	t.Parallel()
	f := rangeChangeFixture(t)
	requireCode(t, runApproval(t, nil, signNow, f.signArgs("--key", f.key.keyFile(t, 0o600))...), 0, "approval written")
	r := runGate(t, Options{Base: f.base, Head: f.head, ApprovalKeysDigest: f.keysDigest, Author: DefaultBotLogin})
	if c := change(t, r, f.id); !c.OK || c.Proof != ProofApproval {
		t.Fatalf("rule change %+v", c)
	}
	requireSchemaRefused(t, r, "no owner approval of the pack level raise")
}
