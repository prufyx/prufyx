// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis

// ParseSpecForTest exposes parseSpec to the external parity test. A _test.go
// file is not part of the extractor's code digest.
var ParseSpecForTest = parseSpec
