// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// The usage text of the custom-resource flags names only projects the
// command reads: a community project is refused by the same command.
func TestCNCFCustomResourceProjectsExcludeCommunity(t *testing.T) {
	got := cncfCustomResourceProjects()
	if len(got) == 0 {
		t.Fatal("no CNCF custom-resource project listed")
	}
	for _, slug := range got {
		if _, ok := cncfprepare.CustomResourceVersionsFact(slug); !ok {
			t.Errorf("%s is listed but has no CNCF custom-resource fact", slug)
		}
		if _, community := cncfprepare.CommunityCustomResourceProject(slug); community {
			t.Errorf("%s is a community project and must not be listed", slug)
		}
	}
	if strings.Contains(strings.Join(got, ","), "gateway-api") {
		t.Error("gateway-api (community) must not be listed")
	}
}
