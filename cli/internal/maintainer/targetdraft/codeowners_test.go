// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ownerOnlyPaths are the verifier package (every file in it), the command
// wiring that dispatches it, and the recipe tree. A data PR
// must not be able to change the check that judges it, so each is owner-only
// in CODEOWNERS. This test pins the lines so they cannot be dropped silently
// (and the test itself sits on an owner-only path).
var ownerOnlyPaths = []string{
	"/cli/internal/maintainer/targetdraft/",
	"/cli/cmd/prufyx-maintainer/main.go",
	"/cli/knowledge/target-recipes/",
}

// codeownerLines returns pattern -> owners for every non-comment line.
func codeownerLines(text string) map[string][]string {
	out := map[string][]string{}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		f := strings.Fields(ln)
		out[f[0]] = f[1:] // a later line for the same pattern wins, as in CODEOWNERS
	}
	return out
}

func missingOwnerOnly(text string) []string {
	lines := codeownerLines(text)
	var miss []string
	for _, p := range ownerOnlyPaths {
		if o := lines[p]; len(o) != 1 || o[0] != "@airstand" {
			miss = append(miss, p)
		}
	}
	return miss
}

func TestCodeownersPinsTheVerifierAndRecipes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", ".github", "CODEOWNERS"))
	if err != nil {
		t.Fatal(err)
	}
	if m := missingOwnerOnly(string(raw)); len(m) != 0 {
		t.Fatalf("not owner-only in CODEOWNERS: %v", m)
	}
}

func TestCodeownersCheckDetectsEveryBreak(t *testing.T) {
	var all strings.Builder
	for _, p := range ownerOnlyPaths {
		all.WriteString(p + " @airstand\n")
	}
	if m := missingOwnerOnly(all.String()); len(m) != 0 {
		t.Fatal(m)
	}
	for _, p := range ownerOnlyPaths {
		// Line dropped.
		if m := missingOwnerOnly(strings.Replace(all.String(), p+" @airstand\n", "", 1)); len(m) != 1 || m[0] != p {
			t.Fatalf("drop %s: %v", p, m)
		}
		// Commented out.
		if m := missingOwnerOnly(strings.Replace(all.String(), p+" @airstand\n", "# "+p+" @airstand\n", 1)); len(m) != 1 {
			t.Fatalf("comment %s: %v", p, m)
		}
		// A second owner or another owner.
		if m := missingOwnerOnly(strings.Replace(all.String(), p+" @airstand\n", p+" @airstand @other\n", 1)); len(m) != 1 {
			t.Fatalf("extra owner %s: %v", p, m)
		}
		if m := missingOwnerOnly(strings.Replace(all.String(), p+" @airstand\n", p+" @other\n", 1)); len(m) != 1 {
			t.Fatalf("other owner %s: %v", p, m)
		}
		// Overridden later by an unowned line.
		if m := missingOwnerOnly(all.String() + p + "\n"); len(m) != 1 {
			t.Fatalf("override %s: %v", p, m)
		}
	}
}
