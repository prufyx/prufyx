// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"testing"
)

func TestEnforceRevisionFloorNeverReportsFeedBehind(t *testing.T) {
	const a, b = "sha256:aa", "sha256:bb"
	for name, tc := range map[string]struct {
		floor, floorDigest, next, digest string
		want                             error
		behind                           bool
	}{
		"no floor":                   {"", "", "3", a, nil, false},
		"newer":                      {"3", a, "4", b, nil, false},
		"same revision same digest":  {"3", a, "3", a, nil, false},
		"older is a plain rollback":  {"3", a, "2", b, ErrRollback, false},
		"same revision other digest": {"3", a, "3", b, ErrRollback, false},
	} {
		err := enforceRevisionFloor(tc.floor, tc.floorDigest, tc.next, tc.digest)
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) || errors.Is(err, ErrFeedBehind) != tc.behind {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if !errors.Is(ErrFeedBehind, ErrRollback) || !errors.Is(ErrPinnedRootMismatch, ErrIntegrity) {
		t.Fatal("sentinels must keep their parent classes")
	}
}

func TestValidateImportAssertionsBootstrapRootBytes(t *testing.T) {
	root := []byte(`{"signed":{}}`)
	digest := digestBytes(root)
	for name, tc := range map[string]struct {
		req ImportRequest
		ok  bool
	}{
		"bytes and matching digest": {ImportRequest{BootstrapRoot: root, BootstrapRootDigest: digest}, true},
		"bytes without digest":      {ImportRequest{BootstrapRoot: root}, false},
		"digest without root":       {ImportRequest{BootstrapRootDigest: digest}, false},
		"bytes with other digest":   {ImportRequest{BootstrapRoot: root, BootstrapRootDigest: digestBytes([]byte("x"))}, false},
		"bytes and path":            {ImportRequest{BootstrapRoot: root, BootstrapRootPath: "/x", BootstrapRootDigest: digest}, false},
		"oversized bytes":           {ImportRequest{BootstrapRoot: make([]byte, 128<<10+1), BootstrapRootDigest: digest}, false},
	} {
		if err := ValidateImportAssertions(tc.req); (err == nil) != tc.ok {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}
