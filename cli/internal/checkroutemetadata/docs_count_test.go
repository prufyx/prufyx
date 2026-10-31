// SPDX-License-Identifier: AGPL-3.0-only

package checkroutemetadata

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The route counts the docs state are pinned to the registry: a doc that
// types a stale number fails here, and no number is typed in this test.
var docRouteCount = regexp.MustCompile(`\*\*(\d+) registered native check routes\*\*|\b(\d{3})(?:-route| routes| native| registered| of those)|0 of (\d{3})`)

func TestDocsRouteCountMatchesRegistry(t *testing.T) {
	result, err := Discover("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	bound := 0
	for _, item := range result.Checks {
		if item.NativeDescriptor.State == DescriptorExact {
			bound++
		}
	}
	for _, name := range []string{"quickstart.md", "one-command-flow.md"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, m := range docRouteCount.FindAllStringSubmatch(string(raw), -1) {
			for _, g := range m[1:] {
				if g == "" {
					continue
				}
				found++
				if n, _ := strconv.Atoi(g); n != bound {
					t.Errorf("%s states %d native routes, the registry binds %d", name, n, bound)
				}
			}
		}
		if found == 0 {
			t.Errorf("%s states no native route count; the pin has nothing to check", name)
		}
	}
}
