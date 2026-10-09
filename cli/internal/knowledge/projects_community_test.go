// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// The per-project layout carries a community project's target under its own
// path prefix, and only there.
func TestSplitPackageMemberNamesCarryCommunityTargets(t *testing.T) {
	sha := hexOf("community")
	for _, name := range []string{
		"targets/knowledge/community/projects/" + sha + ".gateway-api.v1.json",
		"targets/knowledge/community/projects/" + sha + ".kueue.v1.json",
	} {
		if !packageMemberName(name, ConstraintsProjectsIndexTargetPath) {
			t.Fatalf("valid community member %q rejected", name)
		}
		if packageMemberName(name, ConstraintsTargetPath) {
			t.Fatalf("community member %q accepted by the single-target layout", name)
		}
	}
	for _, name := range []string{
		"targets/knowledge/community/projects/" + sha + ".Gateway-Api.v1.json",
		"targets/knowledge/community/projects/" + sha + ".gateway_api.v1.json",
		"targets/knowledge/community/projects/x/" + sha + ".gateway-api.v1.json",
		"targets/knowledge/community/projects/../" + sha + ".gateway-api.v1.json",
		"targets/knowledge/community/" + sha + ".gateway-api.v1.json",
		"targets/knowledge/communities/projects/" + sha + ".gateway-api.v1.json",
		"targets/knowledge/other/projects/" + sha + ".gateway-api.v1.json",
	} {
		if packageMemberName(name, ConstraintsProjectsIndexTargetPath) {
			t.Fatalf("odd member %q accepted", name)
		}
	}
}

func TestSplitTargetsRoleAdmitsCommunityTargetsAtTheirOwnPath(t *testing.T) {
	profile := constraintsProjectsProfile()
	hash := metadata.Hashes{"sha256": make([]byte, sha256Size)}
	role := func(paths ...string) *metadata.Metadata[metadata.TargetsType] {
		r := metadata.Targets(time.Now().Add(time.Hour))
		r.Signed.Targets[profile.targetPath] = &metadata.TargetFiles{Length: 10, Hashes: hash, Path: profile.targetPath}
		for _, p := range paths {
			r.Signed.Targets[p] = &metadata.TargetFiles{Length: 10, Hashes: hash, Path: p}
		}
		return r
	}
	if err := validateSplitTargetsRole(role(cncfcheck.ProjectTargetPath("kubernetes"), cncfcheck.ProjectTargetPath("gateway-api")), profile); err != nil {
		t.Fatalf("community target at its path rejected: %v", err)
	}
	for _, wrong := range []string{
		// The community project under the CNCF prefix, a CNCF project under
		// the community prefix, and a slug in neither catalog.
		"knowledge/cncf/projects/gateway-api.v1.json",
		"knowledge/community/projects/kubernetes.v1.json",
		"knowledge/community/projects/not-a-project.v1.json",
	} {
		if err := validateSplitTargetsRole(role(wrong), profile); !errors.Is(err, ErrIntegrity) {
			t.Fatalf("%s accepted: %v", wrong, err)
		}
	}
}
