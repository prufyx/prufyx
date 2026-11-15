// SPDX-License-Identifier: AGPL-3.0-only

package crdsource

import "testing"

func TestDescriptionMarkersOnlyWithoutMarker(t *testing.T) {
	ok, err := DescriptionMarkersOnly([]byte("apiVersion: v1\nkind: ConfigMap\n"))
	if err != nil || ok {
		t.Fatalf("ok=%t err=%v", ok, err)
	}
}
