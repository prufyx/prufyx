// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// The usage text of the custom-resource flags names only projects the
// command accepts: a CNCF project, or a community project the embedded
// knowledge holds data for. A community project without data is refused by
// the same command and is not listed.
func TestCNCFCustomResourceProjectsListWhatTheCommandAccepts(t *testing.T) {
	listed := map[string]bool{}
	for _, slug := range cncfCustomResourceProjects() {
		listed[slug] = true
	}
	if len(listed) == 0 {
		t.Fatal("no custom-resource project listed")
	}
	for _, slug := range cncfprepare.CustomResourceProjects() {
		_, cncf := cncfprepare.CustomResourceVersionsFact(slug)
		known := false
		if !cncf {
			var err error
			if known, err = cncfcheck.CommunityProjectHasData(slug); err != nil {
				t.Fatalf("%s: %v", slug, err)
			}
		}
		if want := cncf || known; listed[slug] != want {
			t.Errorf("%s: listed=%v, accepted by the command=%v", slug, listed[slug], want)
		}
	}
}
