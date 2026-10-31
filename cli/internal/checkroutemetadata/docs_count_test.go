// SPDX-License-Identifier: AGPL-3.0-only

package checkroutemetadata

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The registry's route count moves with every route-adding change, so the user
// docs type none: a doc that states one would go stale unnoticed.
var docRouteCount = regexp.MustCompile(`\*\*\d+ registered native check routes\*\*|\b\d{3}(?:-route| routes| native check routes| registered native)|0 of \d{3}\b`)

func TestDocsTypeNoRouteCount(t *testing.T) {
	for _, name := range []string{"quickstart.md", "one-command-flow.md"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
		if err != nil {
			t.Fatal(err)
		}
		if m := docRouteCount.Find(raw); m != nil {
			t.Errorf("%s types a native route count (%q); the registry count moves with every route, leave it out", name, m)
		}
	}
}
