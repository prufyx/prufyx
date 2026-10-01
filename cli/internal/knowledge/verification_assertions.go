// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"encoding/json"
	"fmt"
	"reflect"
)

const (
	trustReceiptV1 = "prufyx.io/knowledge-trust-receipt/v1"
	trustReceiptV2 = "prufyx.io/knowledge-trust-receipt/v2"
	pendingV1      = "prufyx.io/knowledge-import-pending/v1"
	pendingV2      = "prufyx.io/knowledge-import-pending/v2"
)

// VerificationAssertionsDigest returns the SHA-256 identity used by opt-in v2
// pending and trust receipts. It validates and hashes the compact JSON encoding
// of the typed assertions; it does not verify a package or authorize trust.
func VerificationAssertionsDigest(assertions VerificationAssertions) (string, error) {
	return verificationAssertionsDigest(&assertions)
}

func verificationAssertionsDigest(assertions *VerificationAssertions) (string, error) {
	if assertions == nil {
		return "", nil
	}
	state := trustState{
		APIVersion:        trustStateAPIVersion,
		InitialRootDigest: assertions.PublisherInitialRootDigest,
		RootHistory:       append([]RootHistoryEntry(nil), assertions.RootHistory...),
		Root:              assertions.Root,
		Timestamp:         assertions.Timestamp,
		Snapshot:          assertions.Snapshot,
		Targets:           assertions.Targets,
	}
	if validateTrustState(state) != nil || assertions.TargetPath == "" || assertions.Purpose == "" {
		return "", fmt.Errorf("expected verification assertions: %w", ErrInvalid)
	}
	for _, role := range []RoleReceipt{assertions.Root, assertions.Timestamp, assertions.Snapshot, assertions.Targets} {
		if role.Version < 1 {
			return "", fmt.Errorf("expected verification role assertions: %w", ErrInvalid)
		}
	}
	if normalized, err := normalizeDigest(assertions.EngineCapabilityDigest); err != nil || normalized != assertions.EngineCapabilityDigest {
		return "", fmt.Errorf("expected verification capability: %w", ErrInvalid)
	}
	canonical, err := json.Marshal(*assertions)
	if err != nil {
		return "", fmt.Errorf("expected verification assertions: %w", ErrInvalid)
	}
	return digestBytes(canonical), nil
}

func verificationTrustMatches(assertions *VerificationAssertions, state trustState) bool {
	return assertions != nil &&
		assertions.PublisherInitialRootDigest == state.InitialRootDigest &&
		reflect.DeepEqual(assertions.RootHistory, state.RootHistory) &&
		assertions.Root == state.Root && assertions.Timestamp == state.Timestamp &&
		assertions.Snapshot == state.Snapshot && assertions.Targets == state.Targets
}

func verificationAdmissionMatches(assertions *VerificationAssertions, targetPath string, admission Admission) bool {
	return assertions != nil && assertions.TargetPath == targetPath &&
		assertions.Purpose == admission.Purpose &&
		assertions.EngineCapabilityDigest == admission.EngineCapabilityDigest
}

func receiptAssertionVersion(receipt TrustReceipt) bool {
	switch receipt.APIVersion {
	case trustReceiptV1:
		return receipt.ExpectedVerificationAssertionsDigest == ""
	case trustReceiptV2:
		normalized, err := normalizeDigest(receipt.ExpectedVerificationAssertionsDigest)
		return err == nil && normalized == receipt.ExpectedVerificationAssertionsDigest
	default:
		return false
	}
}
