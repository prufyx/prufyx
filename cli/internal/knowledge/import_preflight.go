// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"fmt"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

// ValidateImportAssertions validates only operator-supplied import assertions
// and an optional bootstrap root. It does not read PackagePath or StoreRoot,
// perform package/TUF verification, or contact a network. Callers can use it
// before fetching or creating any persistent state.
func ValidateImportAssertions(req ImportRequest) error {
	if req.ExpectedVerification != nil && (req.ExpectedPackageDigest == "" || req.ExpectedRevision == "" || req.ExpectedBundleDigest == "") {
		return fmt.Errorf("verification assertions require exact package, revision, and bundle identities: %w", ErrInvalid)
	}
	if req.ExpectedRevision != "" {
		if _, err := parseRevision(req.ExpectedRevision); err != nil {
			return fmt.Errorf("expected revision: %w", err)
		}
	}
	for _, assertion := range []struct {
		name  string
		value string
	}{
		{name: "expected bundle digest", value: req.ExpectedBundleDigest},
		{name: "expected package digest", value: req.ExpectedPackageDigest},
	} {
		if assertion.value == "" {
			continue
		}
		if _, err := normalizeDigest(assertion.value); err != nil {
			return fmt.Errorf("%s: %w", assertion.name, err)
		}
	}
	if _, err := verificationAssertionsDigest(req.ExpectedVerification); err != nil {
		return err
	}
	if (req.BootstrapRootPath == "") != (req.BootstrapRootDigest == "") {
		return fmt.Errorf("bootstrap root path and digest must be supplied together: %w", ErrInvalid)
	}
	if req.BootstrapRootPath == "" {
		return nil
	}
	expected, err := normalizeDigest(req.BootstrapRootDigest)
	if err != nil {
		return fmt.Errorf("bootstrap root digest: %w", err)
	}
	raw, info, err := currentbundle.ReadBoundedFileInfo(req.BootstrapRootPath, 128<<10)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return fmt.Errorf("bootstrap root admission: %w", ErrIntegrity)
	}
	if digestBytes(raw) != expected {
		return fmt.Errorf("bootstrap root digest mismatch: %w", ErrIntegrity)
	}
	return nil
}
