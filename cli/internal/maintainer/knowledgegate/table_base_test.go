// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/customresources"
)

// legacyOf rewrites a table in the older spelling that has no unowned member.
func legacyOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	projects, reserved, _, err := customresources.LoadTable(raw)
	if err != nil {
		t.Fatal(err)
	}
	old, err := customresources.CanonicalLegacyTable(projects, reserved)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(old, []byte(`"unowned"`)) {
		t.Fatal("the older spelling carries the unowned member")
	}
	return old
}

// A base that predates the unowned member is a valid comparison base for a
// head in the current spelling; the head itself is held to the current
// spelling, and a base in the older spelling is accepted only exactly.
func TestReadTableTreeAcceptsOlderBaseOnly(t *testing.T) {
	t.Parallel()
	ol := DefaultLayout().Onboarding
	rel := filepath.FromSlash(ol.TablePath)
	f := newCommunityFixture(t, ocDefault)
	headRaw, err := f.head.Read(ol.TablePath, MaxFileBytes)
	if err != nil {
		t.Fatal(err)
	}
	old := legacyOf(t, headRaw)

	// Old base, new head: the change is read as an onboarding change.
	writeFile(t, filepath.Join(f.base.Root, rel), old)
	cls, err := Classify(DefaultLayout(), f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := ChangedPaths(f.base, f.head)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newOnboardingState(DefaultLayout(), f.base, f.head, cls, paths); err != nil {
		t.Fatalf("a base in the older spelling was refused: %v", err)
	}

	// The older spelling read as the base: the empty unowned list.
	tr, err := readTableTree(f.base, ol.TablePath, true)
	if err != nil || len(tr.unowned) != 0 {
		t.Fatalf("base read: %v", err)
	}
	// The same file as a head is refused.
	if _, err := readTableTree(f.base, ol.TablePath, false); err == nil || !strings.Contains(err.Error(), "canonical spelling") {
		t.Fatalf("a head in the older spelling was accepted: %v", err)
	}
	// A head in the older spelling fails the whole onboarding read.
	writeFile(t, filepath.Join(f.head.Root, rel), old)
	if _, err := newOnboardingState(DefaultLayout(), f.base, f.head, cls, paths); err == nil {
		t.Fatal("a head table in the older spelling was admitted")
	}
	// Any other deviation of the base is still refused.
	for name, raw := range map[string][]byte{
		"extra newline": append(append([]byte{}, old...), '\n'),
		"trailing":      append(append([]byte{}, old...), ' '),
		"reindented":    bytes.ReplaceAll(old, []byte("\n  "), []byte("\n    ")),
	} {
		writeFile(t, filepath.Join(f.base.Root, rel), raw)
		if _, err := readTableTree(f.base, ol.TablePath, true); err == nil {
			t.Errorf("%s: a base with another deviation was accepted", name)
		}
	}
}
