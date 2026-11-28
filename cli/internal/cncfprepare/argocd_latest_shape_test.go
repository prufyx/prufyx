// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"net/url"
	"strings"
	"testing"
)

// argoOCIShapeV352 is IsHelmOciRepo from argo-cd v3.5.2 (util/helm/client.go
// lines 446-453, commit e258ee23c3e52266d407572f4bcdfe7d9ed36cb5).
func argoOCIShapeV352(repoURL string) bool {
	if repoURL == "" {
		return false
	}
	parsed, err := url.Parse(repoURL)
	return err == nil && parsed.Host == ""
}

// argoOCIShapeV358 is IsHelmOciRepo from argo-cd v3.5.8 (util/helm/client.go
// lines 446-456, commit 71576a24e898f50c9bf5e31b6930d81d4ac7717d).
func argoOCIShapeV358(repoURL string) bool {
	if repoURL == "" || strings.Contains(repoURL, "://") {
		return false
	}
	parsed, err := url.ParseRequestURI("dummy://" + repoURL)
	return err == nil && parsed.Host != ""
}

func TestArgoOCIRepositoryShapeAgreesAcrossReleases(t *testing.T) {
	hosts := []string{"registry", "Registry", "registry.example.com", "a.b-c.d", "r1.example.com", "reg.1example.com", "localhost", "x-y.example"}
	ports := []string{"", ":5000", ":80", ":0", ":65535", ":99999"}
	paths := []string{"", "/charts", "/team/charts", "/a.b_c~d-e", "/9"}
	accepted := 0
	for _, h := range hosts {
		for _, p := range ports {
			for _, path := range paths {
				value := h + p + path
				if !safeArgoOCIRepository(value) {
					t.Fatalf("in-scope shape %q refused", value)
				}
				accepted++
				if !argoOCIShapeV352(value) || !argoOCIShapeV358(value) {
					t.Fatalf("shape %q recognised differently: v3.5.2=%v v3.5.8=%v", value, argoOCIShapeV352(value), argoOCIShapeV358(value))
				}
			}
		}
	}
	if accepted == 0 {
		t.Fatal("no shapes exercised")
	}
}

func TestArgoOCIRepositoryShapeRefusesDivergentForms(t *testing.T) {
	// Each form is recognised differently by v3.5.2 and v3.5.8, or is not a
	// plain DNS-name reference; all must stay out of scope.
	for _, value := range []string{
		"192.168.100.150:1843", "10.0.0.1:5000/a", "[::1]:5000", "[::1]", "reg_istry:5000", "1host:5000",
		"9registry.example.com:5000", "-x.example:5000", "user@host:5000", "host:abc", "host:", "host:5000#f",
		"host.example:50x/a", "host:123456", "/abs/path", "a b", "host:5000?x", "host//x", "host/a b", "host/%41",
		"oci://host", "http://host", "host/", "",
	} {
		if safeArgoOCIRepository(value) {
			t.Fatalf("divergent or out-of-scope form %q admitted", value)
		}
	}
	for _, value := range []string{"192.168.100.150:1843", "10.0.0.1:5000/a", "[::1]:5000", "reg_istry:5000", "1host:5000", "user@host:5000", "-x.example:5000"} {
		if argoOCIShapeV352(value) == argoOCIShapeV358(value) {
			t.Fatalf("reference form %q no longer differs between releases", value)
		}
	}
}
