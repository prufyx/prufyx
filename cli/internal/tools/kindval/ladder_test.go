// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestLadderClass(t *testing.T) {
	for name, tc := range map[string]struct {
		lines []string
		want  bool
	}{
		"typed patch": {[]string{"Error from server: failed to create typed patch object (/a.b; apiextensions.k8s.io/v1, Kind=CustomResourceDefinition): errors:", ".spec.x: field not declared in schema"}, true},
		"strict":      {[]string{`error: error validating "STDIN": error validating data: unknown field "spec.x"`}, true},
		"structural":  {[]string{`Error from server (Invalid): CustomResourceDefinition.apiextensions.k8s.io "a.b" is invalid: must be empty to be structural`}, false},
	} {
		if got := ladderClass(&InstallError{Lines: tc.lines}); got != tc.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
	if ladderClass(nil) {
		t.Error("nil")
	}
}

func TestDroppedPaths(t *testing.T) {
	got := droppedPaths([]string{
		`Warning: unknown field "spec.versions[0].x"`,
		`Warning: unknown field "spec.versions[0].x"`,
		`  .spec.y: field not declared in schema`,
		`other`,
	})
	if want := []string{"spec.versions[0].x", ".spec.y"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

// The ladder runs only after an unknown-field rejection, with server dry
// runs, and leaves the verdict (Error, reason) as the server-side apply set it.
func TestInstallReleaseLadder(t *testing.T) {
	typed := "Error from server: failed to create typed patch object (/f.test; apiextensions.k8s.io/v1, Kind=CustomResourceDefinition): errors:\n.spec.x: field not declared in schema"
	structural := `Error from server (Invalid): CustomResourceDefinition.apiextensions.k8s.io "f.test" is invalid: must be empty to be structural`
	run := func(first string) (CRDReleaseState, [][]string) {
		var calls [][]string
		r := func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
			calls = append(calls, args)
			j := strings.Join(args, " ")
			switch {
			case strings.Contains(j, "--server-side"):
				return nil, []byte(first), 1
			case strings.Contains(j, "--validate=strict"):
				return nil, []byte(`error: error validating "STDIN": unknown field "spec.x"`), 1
			case strings.Contains(j, "--validate=warn"):
				return nil, []byte(`Warning: unknown field "spec.x"`), 0
			}
			return nil, nil, 0
		}
		return installRelease(context.Background(), kube{run: r, kubeconfig: "kc"}, []byte("x"), nil, nil, nil), calls
	}
	st, calls := run(typed)
	if st.Error != "kubectl apply: exit 1: "+typed || st.InstallError == nil || len(calls) != 3 {
		t.Fatalf("state %+v calls %d", st, len(calls))
	}
	l := st.InstallError.ApplyLadder
	if len(l) != 2 || l[0].Exit != 1 || l[0].Accepted || l[1].Exit != 0 || !l[1].Accepted || !reflect.DeepEqual(l[1].Dropped, []string{"spec.x"}) {
		t.Errorf("ladder %+v", l)
	}
	for _, c := range calls[1:] {
		if !strings.Contains(strings.Join(c, " "), "--dry-run=server") {
			t.Errorf("not a dry run: %v", c)
		}
	}
	st, calls = run(structural)
	if st.InstallError == nil || st.InstallError.ApplyLadder != nil || len(calls) != 1 {
		t.Errorf("wrong class ran ladder: %+v %d", st.InstallError, len(calls))
	}
}

func TestLadderAccepted(t *testing.T) {
	if !ladderAccepted(1, []string{`Error from server (AlreadyExists): error when creating "STDIN": x already exists`, `Warning: unknown field "a"`}) {
		t.Error("AlreadyExists only")
	}
	if ladderAccepted(1, []string{`Error from server (BadRequest): strict decoding error: unknown field "a"`}) {
		t.Error("strict error")
	}
	if ladderAccepted(1, []string{`error: error validating "STDIN": unknown field "a"`}) {
		t.Error("validating error")
	}
	if !ladderAccepted(0, nil) {
		t.Error("exit 0")
	}
}
