// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import "testing"

// A Landscape repository with a mixed-case organization or name still gives
// the lowercase package URL the constraint engine admits; no catalog project
// needs a special case for it.
func TestSubjectComponentIsLowercase(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ project, repository, want string }{
		{"wasmcloud", "https://github.com/wasmCloud/wasmCloud", "pkg:github/wasmcloud/wasmcloud"},
		{"cubefs", "https://github.com/cubeFS/cubefs", "pkg:github/cubefs/cubefs"},
		{"kai-scheduler", "https://github.com/kai-scheduler/KAI-Scheduler", "pkg:github/kai-scheduler/kai-scheduler"},
		{"keda", "https://github.com/kedacore/keda", "pkg:github/kedacore/keda"},
		{"x", "https://example.com/Org/Repo", ""},
	} {
		if got := subjectComponent(c.project, c.repository); got != c.want {
			t.Errorf("subjectComponent(%q, %q) = %q, want %q", c.project, c.repository, got, c.want)
		}
	}
}
