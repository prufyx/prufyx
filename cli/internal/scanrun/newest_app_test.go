// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

type stubAppKnowledge struct {
	version string
	found   bool
	status  upgradepath.Status
}

func (s stubAppKnowledge) NewestAttestedRelease(string, time.Time) (string, string, bool) {
	return "1.2", s.version, s.found
}

func (s stubAppKnowledge) PathPolicyFor(string, time.Time) upgradepath.Status { return s.status }

// attestationOnly has line attestations but no path policies.
type attestationOnly struct{ stubAppKnowledge }

func (attestationOnly) PathPolicyFor() {}

func TestNewestAppReleaseNeedsAttestationAndPolicy(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	current := upgradepath.Status{Found: true, Freshness: upgradepath.FreshnessCurrent}
	stale := upgradepath.Status{Found: true, Freshness: "stale"}

	if v, err := newestAppRelease(stubAppKnowledge{version: "1.2.7", found: true, status: current}, "app", "pkg:github/x/app", now); err != nil || v != "1.2.7" {
		t.Fatalf("attestation and policy: %q %v", v, err)
	}
	for name, k := range map[string]stubAppKnowledge{
		"no policy":    {version: "1.2.7", found: true},
		"stale policy": {version: "1.2.7", found: true, status: stale},
	} {
		_, err := newestAppRelease(k, "app", "pkg:github/x/app", now)
		if err == nil || !strings.Contains(err.Error(), "no reviewed upgrade path policy for app: give an exact version with --to app=X.Y.Z") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := newestAppRelease(attestationOnly{stubAppKnowledge{version: "1.2.7", found: true}}, "app", "c", now); err == nil || !strings.Contains(err.Error(), "no reviewed upgrade path policy") {
		t.Fatalf("knowledge without policies: %v", err)
	}
	if _, err := newestAppRelease(stubAppKnowledge{found: false, status: current}, "app", "c", now); err == nil || !strings.Contains(err.Error(), "no current reviewed release line of app") {
		t.Fatalf("no attestation: %v", err)
	}
}
