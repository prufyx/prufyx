// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"errors"
	"strings"
	"testing"
)

// TestPackRecordsRefusesServedAPIs: a pack with a served-API list section is
// refused by the record reader (and so by evidence repin and reattest), not
// read with its citations left unrenewed. A pack without it reads.
func TestPackRecordsRefusesServedAPIs(t *testing.T) {
	const withoutSection = `{"schema":"prufyx.io/cncf-source-rule-pack/v1alpha9","entries":[]}`
	records, err := PackRecords([]byte(withoutSection))
	if err != nil || len(records) != 0 {
		t.Fatalf("control: %v %v", records, err)
	}
	const withSection = `{"schema":"prufyx.io/cncf-source-rule-pack/v1alpha10","entries":[],"servedAPIs":[]}`
	_, err = PackRecords([]byte(withSection))
	if !errors.Is(err, errRejected) || !strings.Contains(err.Error(), "served-API lists") {
		t.Fatalf("a pack with served-API lists was read: %v", err)
	}
}
