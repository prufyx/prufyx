// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"strings"
	"testing"
)

// A long fix never cuts the step disclosure of a crossed-line finding from
// the SARIF message.
func TestSarifResultMessageKeepsStepDisclosure(t *testing.T) {
	step := "Decided on the step 1.24.17 -> 1.25, which an in-place upgrade takes to enter Kubernetes 1.25."
	finding := Finding{Title: "CronJob batch/v1beta1", Fix: strings.Repeat("migrate the object. ", 80) + step, CrossedLine: &CrossedLine{Line: "1.25"}}
	message := resultMessage(finding)
	if len(message) > sarifMessageMax || !strings.HasSuffix(message, step) {
		t.Fatalf("%d bytes: %q", len(message), message)
	}
	finding.CrossedLine = nil
	if message := resultMessage(finding); len(message) != sarifMessageMax {
		t.Fatalf("%d bytes", len(message))
	}
}
