// SPDX-License-Identifier: AGPL-3.0-only

package extractcli

import (
	"sort"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract"
)

// Test 21 (A4): the mechanical allowlist and the catalog agree both ways. The
// allowlist keys are id prefixes; this binary holds the real list (the
// framework tests extend it with a stand-in, which this package never sees).
func TestMechanicalAllowlistMatchesCatalog(t *testing.T) {
	keys := extract.MechanicalExtractorPrefixes()
	if len(keys) == 0 {
		t.Fatal("empty allowlist")
	}
	catalog := Catalog()
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	keyUsed := map[string]int{}
	for _, id := range ids {
		ex := catalog[id].New(0)
		_, emitter := ex.(extract.MechanicalEmitter)
		var matches []string
		for _, k := range keys {
			if strings.HasPrefix(id, k) {
				matches = append(matches, k)
				keyUsed[k]++
			}
		}
		switch {
		case emitter && len(matches) != 1:
			t.Errorf("mechanical emitter %s matches %d allowlist keys %v, want exactly 1", id, len(matches), matches)
		case !emitter && len(matches) != 0:
			t.Errorf("catalogued extractor %s is not a MechanicalEmitter but matches allowlist keys %v", id, matches)
		}
		if emitter && len(ex.(extract.MechanicalEmitter).MechanicalFamilies()) == 0 {
			t.Errorf("%s declares no mechanical family", id)
		}
	}
	for _, k := range keys {
		if keyUsed[k] == 0 {
			t.Errorf("allowlist key %q matches no catalogued extractor", k)
		}
		for _, other := range keys {
			if other != k && strings.HasPrefix(other, k) {
				t.Errorf("allowlist key %q is a prefix of key %q", k, other)
			}
		}
	}
	// A class-5 draft adapter id is never on the allowlist.
	for _, k := range keys {
		if strings.HasPrefix("class5.", k) || strings.HasPrefix(k, "class5.") {
			t.Errorf("allowlist key %q covers class-5 adapters", k)
		}
	}
	// No catalogued extractor attests lines under a class-5 id.
	for _, id := range ids {
		if strings.HasPrefix(id, "class5.") {
			t.Errorf("class-5 adapter %s is catalogued in P1", id)
		}
	}
}
