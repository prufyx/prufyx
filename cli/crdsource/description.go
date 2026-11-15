// SPDX-License-Identifier: AGPL-3.0-only

// Package crdsource exposes bounded source-shape checks to local callers.
package crdsource

import "github.com/prufyx/prufyx/cli/internal/extract/crdversions"

// DescriptionMarkersOnly reports marker placement only. It does not establish
// CRD structural or install-surface validity.
func DescriptionMarkersOnly(data []byte) (bool, error) {
	return crdversions.DescriptionMarkersOnly(data)
}
