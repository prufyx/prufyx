// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestInstallError(t *testing.T) {
	invalid := `Error from server (Invalid): error when creating "STDIN": CustomResourceDefinition.apiextensions.k8s.io "widgets.example.test" is invalid: spec.versions[0].schema: Required value
Error from server (Invalid): error when creating "STDIN": CustomResourceDefinition.apiextensions.k8s.io "gadgets.example.test" is invalid: x
`
	many := strings.Repeat("Error from server (Invalid): line\n", InstallErrorMaxLines+10)
	for name, tc := range map[string]struct {
		err  error
		want *InstallError // nil: not a rejection
	}{
		"invalid": {&applyError{1, strings.TrimSpace(invalid)}, &InstallError{Phase: "apply", Exit: 1,
			Lines: strings.Split(strings.TrimSpace(invalid), "\n"), CRDs: []string{"widgets.example.test", "gadgets.example.test"}}},
		"typed patch": {&applyError{1, `failed to create typed patch object (/widgets.example.test; apiextensions.k8s.io/v1, Kind=CustomResourceDefinition): .spec.x: field not declared in schema`},
			&InstallError{Phase: "apply", Exit: 1, Lines: []string{`failed to create typed patch object (/widgets.example.test; apiextensions.k8s.io/v1, Kind=CustomResourceDefinition): .spec.x: field not declared in schema`}, CRDs: []string{"widgets.example.test"}}},
		"server colon": {&applyError{1, "Error from server: failed to create typed patch object (/fleets.example.test; apiextensions.k8s.io/v1, Kind=CustomResourceDefinition): errors:\n  .spec.x: field not declared in schema"},
			&InstallError{Phase: "apply", Exit: 1, Lines: []string{"Error from server: failed to create typed patch object (/fleets.example.test; apiextensions.k8s.io/v1, Kind=CustomResourceDefinition): errors:", ".spec.x: field not declared in schema"}, CRDs: []string{"fleets.example.test"}}},
		"capped":             {&applyError{1, many}, nil},
		"connection refused": {&applyError{1, `The connection to the server 127.0.0.1:1 was refused - did you specify the right host or port?`}, nil},
		"unable to connect":  {&applyError{1, `Unable to connect to the server: dial tcp 127.0.0.1:1: connect: connection refused`}, nil},
		"server timeout":     {&applyError{1, `Error from server (Timeout): request did not complete within requested timeout`}, nil},
		"unavailable":        {&applyError{1, `Error from server (ServiceUnavailable): the server is currently unable to handle the request`}, nil},
		"killed":             {&applyError{-1, `signal: killed`}, nil},
		"other exit":         {&applyError{2, `Error from server (Invalid): x`}, nil},
		"not an apply":       {fmt.Errorf("fetch: HTTP 503"), nil},
	} {
		got := installError(tc.err)
		if name == "capped" {
			if got == nil || len(got.Lines) != InstallErrorMaxLines {
				t.Errorf("capped: %+v", got)
			}
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", name, got, tc.want)
		}
	}
}

// A refused apply is install-rejected with the structured error; an apply
// that never reached the server stays install-failed.
func TestInstallRejectedVersusFailed(t *testing.T) {
	run := func(stderr string, exit int) CRDReleaseState {
		r := func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
			return nil, []byte(stderr), exit
		}
		return installRelease(context.Background(), kube{run: r, kubeconfig: "kc"}, []byte("x"), nil, nil, nil)
	}
	st := run(`Error from server (Invalid): error when creating "STDIN": CustomResourceDefinition.apiextensions.k8s.io "a.b.test" is invalid: y`, 1)
	if st.Error == "" || st.InstallError == nil || st.InstallError.Phase != "apply" || !reflect.DeepEqual(st.InstallError.CRDs, []string{"a.b.test"}) {
		t.Fatalf("rejected: %+v", st)
	}
	st = run("The connection to the server was refused", 1)
	if st.Error == "" || st.InstallError != nil {
		t.Fatalf("unreachable: %+v", st)
	}
}
