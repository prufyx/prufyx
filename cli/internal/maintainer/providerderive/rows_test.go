// SPDX-License-Identifier: AGPL-3.0-only

package providerderive

import (
	"errors"
	"strings"
	"testing"
)

func TestDriftIDSharedShape(t *testing.T) {
	err := DriftID("k3s", KindConflict, "x1", "bad %d", 3)
	var de *DriftError
	if !errors.As(err, &de) || !errors.Is(err, ErrDrift) {
		t.Fatalf("not a shared DriftError: %v", err)
	}
	if de.Source != "k3s" || de.Kind != KindConflict || !strings.Contains(de.Detail, `excerpt "x1": bad 3`) {
		t.Fatalf("unexpected fields: %+v", de)
	}
}

func TestParseBodyHeaderIsDrift(t *testing.T) {
	_, _, err := ParseBody("k3s", "x1", []string{"tag: v1.0.0+k3s1"})
	var de *DriftError
	if !errors.As(err, &de) || de.Kind != KindHeader {
		t.Fatalf("want header drift, got %v", err)
	}
}
