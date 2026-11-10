// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Historical envelopes, produced and signed by the code before onboarding v3
// existed (main 2bb23f4a), with fixed test keys. They must verify unchanged.
const (
	histOwnerPub = "c86d01ad8b2fb694b22ff60e3c9d9e7ed90db5604772b74450d40913b9a9cbaf"
	histBotPub   = "2df04125f0015afb47ce853aef8772094ff9498c14cb1b9e12973c2927da0fa6"
	histV1KeyID  = "sha256:e577275f191892ed88311038fd26de52488a74e0852efc97c3a46687a4a050d8"
	histV2KeyID  = "sha256:2d3bb9ef976d407955e4188df05c25f511cd1fe3c85fe70fc221c4d8f8e66261"
)

const histV1Envelope = `{
  "schema": "prufyx.io/knowledge-onboarding-batch/v1",
  "record": {
    "base": {
      "packRevision": "rev.1",
      "registryDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "tableDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "targetsDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "batchId": "ob-20261003-1",
    "candidateId": "pr-1",
    "changeSetDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "decidedAt": "2026-10-03T11:00:00Z",
    "decision": "approve",
    "head": {
      "packRevision": "rev.1",
      "registryDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "tableDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "targetsDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "identity": "airstand",
    "nonce": "0123456789abcdef0123456789abcdef",
    "notAfter": "2026-10-04T11:00:00Z",
    "projects": [
      {
        "artifacts": [
          {
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "path": "a/b.json"
          }
        ],
        "catalog": "cncf",
        "facts": [
          "component.x.custom_resource_versions_set"
        ],
        "groups": [
          "x.example.com"
        ],
        "kind": "new",
        "proof": {
          "claims": {
            "confirmed": 1,
            "ledger": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "refuted": 0,
            "undetermined": 0
          },
          "pair": {
            "fromCommit": "00000000000000000000000000000000000a1000",
            "fromTag": "v1",
            "toCommit": "00000000000000000000000000000000000a1100",
            "toTag": "v2"
          },
          "scan": []
        },
        "slug": "x"
      }
    ],
    "sample": [
      0
    ],
    "summaryDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "keyId": "sha256:e577275f191892ed88311038fd26de52488a74e0852efc97c3a46687a4a050d8",
  "signature": "xXWMTrTvvPQZ2NjkdV/aO8/aN+P1BYnK63g7XYyjAlU7MlKvgK2OkclAOWOPqHGp7WUSBxzC69UUkR8rR5boCA=="
}
`

const histV2Envelope = `{
  "schema": "prufyx.io/knowledge-onboarding-batch/v2",
  "record": {
    "admissionBinding": {
      "profile": {
        "schema": "prufyx.io/published-gate-admission-profile/v1",
        "repository": "o/r",
        "baseCommit": "cccccccccccccccccccccccccccccccccccccccc",
        "baseTree": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "keysDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "identity": "tier-bot",
        "keyId": "k",
        "keyNotAfter": "2027-01-01T00:00:00Z",
        "tier": "onboarding-bot",
        "kind": "new",
        "maxProjects": 5,
        "maxBatchesWindow": 0,
        "maxProjectsWindow": 0,
        "windowSeconds": 0,
        "maxValiditySeconds": 0,
        "keyMarginSeconds": 0,
        "automationLogin": "",
        "maxLoosening": 0,
        "maxWithdrawPercent": 0,
        "maxWithdrawProject": 0,
        "maxDailyLoosening": 0,
        "restBudget": 0,
        "pauseRequiredFalse": false
      },
      "export": {
        "planDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "manifestDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "draftDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "factsDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "bundleDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "exportLineHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "publicLineHash": "cccccccccccccccccccccccccccccccccccccccc"
      },
      "unsignedCommit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "unsignedTree": "cccccccccccccccccccccccccccccccccccccccc",
      "changes": [
        {
          "path": "a/b.json",
          "status": "A",
          "base": {
            "mode": "",
            "blob": "",
            "digest": ""
          },
          "head": {
            "mode": "100644",
            "blob": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          }
        }
      ],
      "observedAt": "2026-10-03T11:00:00Z",
      "dailyCommits": [
        {
          "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "parent": "cccccccccccccccccccccccccccccccccccccccc",
          "author": null
        }
      ],
      "dailyCount": 0,
      "historyDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "base": {
      "packRevision": "rev.1",
      "registryDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "tableDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "targetsDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "batchId": "ob-20261003-1",
    "candidateId": "pr-1",
    "changeSetDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "decidedAt": "2026-10-03T11:00:00Z",
    "decision": "approve",
    "head": {
      "packRevision": "rev.1",
      "registryDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "tableDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "targetsDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "identity": "tier-bot",
    "nonce": "0123456789abcdef0123456789abcdef",
    "notAfter": "2026-10-04T11:00:00Z",
    "projects": [
      {
        "artifacts": [
          {
            "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "path": "a/b.json"
          }
        ],
        "catalog": "cncf",
        "facts": [
          "component.x.custom_resource_versions_set"
        ],
        "groups": [
          "x.example.com"
        ],
        "kind": "new",
        "proof": {
          "claims": {
            "confirmed": 1,
            "ledger": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "refuted": 0,
            "undetermined": 0
          },
          "pair": {
            "fromCommit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "fromTag": "v1",
            "toCommit": "cccccccccccccccccccccccccccccccccccccccc",
            "toTag": "v2"
          },
          "scan": []
        },
        "slug": "x"
      }
    ],
    "sample": [
      0
    ],
    "summaryDigest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "keyId": "sha256:2d3bb9ef976d407955e4188df05c25f511cd1fe3c85fe70fc221c4d8f8e66261",
  "signature": "43qSm80oXHQpGKkFHpwm/134E7VfKo44n4GWXfNDrbm6Fcy1M55uWQnxpT/HR9xmZ0sSVOefPE6ms7Kz6yO/BA=="
}
`

var histNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func histKeys() ApprovalKeys {
	return ApprovalKeys{
		Schema: ApprovalKeysSchema, Role: ApprovalKeyRole, Owners: []string{obOwner}, Bots: []string{"tier-bot"},
		Keys: []ApprovalKey{
			{KeyID: histV1KeyID, PublicKey: histOwnerPub, NotAfter: "2027-10-01T00:00:00Z"},
			{KeyID: histV2KeyID, PublicKey: histBotPub, NotAfter: "2027-01-01T00:00:00Z", Tier: ApprovalTierOnboardingBot},
		},
	}
}

// A real v1 and a real v2 envelope, signed before v3 existed, still decode and
// verify byte for byte on the v3 code; their signed bytes are unchanged.
func TestOnboardingHistoricalEnvelopesVerify(t *testing.T) {
	t.Parallel()
	keys := histKeys()

	v1, err := decodeOnboarding([]byte(histV1Envelope))
	if err != nil {
		t.Fatalf("historical v1 refused: %v", err)
	}
	if v1.Schema != OnboardingSchema || v1.KeyID != histV1KeyID || len(v1.Record.adds) != 0 {
		t.Fatalf("historical v1 decoded as %+v", v1)
	}
	if err := verifyOnboardingSignature(v1, keys, histNow); err != nil {
		t.Fatalf("historical v1 does not verify: %v", err)
	}
	// The envelope re-encodes to the very same file.
	again, err := json.MarshalIndent(v1, "", "  ")
	if err != nil || string(append(again, '\n')) != histV1Envelope {
		t.Fatalf("historical v1 re-encodes differently (%v)", err)
	}
	if b, err := SignedOnboardingBytes(v1.Record); err != nil || !bytes.HasPrefix(b, []byte("prufyx.io/knowledge-onboarding-batch/v1\x00{\"base\":")) {
		t.Fatalf("v1 signed bytes: %v", err)
	}

	v2, err := decodeOnboarding([]byte(histV2Envelope))
	if err != nil {
		t.Fatalf("historical v2 refused: %v", err)
	}
	if v2.Schema != OnboardingSchemaV2 || v2.KeyID != histV2KeyID || v2.binding == nil || len(v2.Record.adds) != 0 {
		t.Fatalf("historical v2 decoded as %+v", v2)
	}
	if err := verifyOnboardingSignature(v2, keys, histNow); err != nil {
		t.Fatalf("historical v2 does not verify: %v", err)
	}
	rec2 := OnboardingRecordV2{OnboardingRecord: v2.Record, AdmissionBinding: *v2.binding}
	b2, err := SignedOnboardingV2Bytes(rec2)
	if err != nil || string(b2) != goldenV2Bytes {
		t.Fatalf("v2 signed bytes moved (%v)", err)
	}
	// The v2 file is the same record the golden literal covers.
	if g := goldenV2Record(); !jsonEqual(t, g, rec2) {
		t.Fatal("historical v2 record differs from the golden record")
	}
}

func jsonEqual(t *testing.T, a, b any) bool {
	t.Helper()
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	return bytes.Equal(x, y)
}

// Tampering with a historical envelope, or presenting it under another
// schema or key tier, is refused.
func TestOnboardingHistoricalEnvelopesTamperRefused(t *testing.T) {
	t.Parallel()
	keys := histKeys()
	for name, tc := range map[string]struct{ raw, from, to string }{
		"v1 nonce":         {histV1Envelope, "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdee"},
		"v1 batch id":      {histV1Envelope, "ob-20261003-1", "ob-20261003-2"},
		"v2 nonce":         {histV2Envelope, "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdee"},
		"v2 unsigned tree": {histV2Envelope, strings.Repeat("c", 40), strings.Repeat("d", 40)},
	} {
		raw := strings.Replace(tc.raw, tc.from, tc.to, 1)
		if raw == tc.raw {
			t.Fatalf("%s: nothing replaced", name)
		}
		env, err := decodeOnboarding([]byte(raw))
		if err != nil {
			continue // refused at decoding: fail closed as well
		}
		if err := verifyOnboardingSignature(env, keys, histNow); err == nil {
			t.Errorf("%s: tampered envelope verifies", name)
		}
	}
	// v1 presented as v2 or v3, v2 presented as v1 or v3: refused before or at
	// the signature, never verified.
	for name, tc := range map[string]struct{ raw, from, to string }{
		"v1 as v2": {histV1Envelope, OnboardingSchema, OnboardingSchemaV2},
		"v1 as v3": {histV1Envelope, OnboardingSchema, OnboardingSchemaV3},
		"v2 as v1": {histV2Envelope, OnboardingSchemaV2, OnboardingSchema},
		"v2 as v3": {histV2Envelope, OnboardingSchemaV2, OnboardingSchemaV3},
	} {
		raw := strings.Replace(tc.raw, `"`+tc.from+`"`, `"`+tc.to+`"`, 1)
		env, err := decodeOnboarding([]byte(raw))
		if err != nil {
			continue
		}
		if err := verifyOnboardingSignature(env, keys, histNow); err == nil {
			t.Errorf("%s: relabelled envelope verifies", name)
		}
	}
	// A historical key at a later time than its pin is expired; the owner key
	// does not verify the bot's v2 envelope and the reverse.
	v1, _ := decodeOnboarding([]byte(histV1Envelope))
	if err := verifyOnboardingSignature(v1, keys, time.Date(2027, 10, 2, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Error("expired owner key verifies")
	}
	swapped := keys
	swapped.Keys = []ApprovalKey{{KeyID: histV1KeyID, PublicKey: histBotPub, NotAfter: "2027-10-01T00:00:00Z"}}
	if err := verifyOnboardingSignature(v1, swapped, histNow); err == nil {
		t.Error("v1 verifies under another public key")
	}
}
