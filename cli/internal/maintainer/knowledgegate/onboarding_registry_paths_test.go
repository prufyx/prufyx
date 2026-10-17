// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"path/filepath"
	"testing"
)

// An onboarding batch and a registry-member change are two ways to move the
// pack's registryDigest. A change that carries both is refused with one
// stable reason, whichever of the two the other checks would admit, and the
// registryDigest member is admitted by neither.
func TestOnboardingBatchRefusesRegistryMemberPath(t *testing.T) {
	t.Parallel()
	headFile := func(f *onboardingFixture, rel string) string {
		return filepath.Join(f.head.Root, filepath.FromSlash(rel))
	}
	edits := map[string]func(t *testing.T, f *onboardingFixture){
		"packagedDefinitions changed": func(t *testing.T, f *onboardingFixture) {
			src := registrySource(t)
			writeFile(t, headFile(f, cncfRegistrySource), []byte(withAdded(src)))
			writeFile(t, filepath.Join(f.base.Root, filepath.FromSlash(cncfRegistrySource)), []byte(src))
		},
		"registry-member approval added": func(t *testing.T, f *onboardingFixture) {
			writeFile(t, registryApprovalFile(f.head), []byte("{}\n"))
		},
	}
	for name, edit := range edits {
		for _, order := range []string{"edited then signed", "signed then edited"} {
			t.Run(name+"/"+order, func(t *testing.T) {
				f := newOnboardingFixture(t)
				if order == "signed then edited" {
					f.sign(t, f.record(t))
					edit(t, f)
				} else {
					edit(t, f)
					f.refresh()
					rec, _ := f.tryRecord(t)
					if rec.BatchID == "" {
						t.Skip("the head cannot be read as an onboarding change")
					}
					f.sign(t, rec)
				}
				r := f.gate(t)
				requireFail(t, r, RegistryPathsConflict)
				for _, c := range r.Changes {
					if c.Member == "registryDigest" && c.OK {
						t.Fatalf("registryDigest admitted beside two registry paths: %+v", c)
					}
				}
			})
		}
	}
}
