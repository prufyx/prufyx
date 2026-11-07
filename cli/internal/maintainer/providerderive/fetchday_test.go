// SPDX-License-Identifier: AGPL-3.0-only

package providerderive

import (
	"errors"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/maintainer/providerexcerpt"
)

func TestFetchDay(t *testing.T) {
	d, err := FetchDay("x", providerexcerpt.Entry{FetchedAt: "2026-11-07T23:59:59-02:00"})
	if err != nil || d != "2026-11-08" {
		t.Fatalf("%q %v", d, err)
	}
	for _, bad := range []string{"", "2026-11-07", "yesterday"} {
		_, err := FetchDay("x", providerexcerpt.Entry{FetchedAt: bad})
		var de *DriftError
		if !errors.Is(err, ErrDrift) || !errors.As(err, &de) || de.Kind != KindExcerpt {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
