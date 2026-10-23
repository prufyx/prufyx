// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"errors"
	"testing"
)

func TestKubeletSkewUnsupportedVectors(t *testing.T) {
	for name, tc := range map[string]struct {
		minimum, maximum, target [3]uint64
		present, resolved        bool
	}{
		"inside the window":        {[3]uint64{1, 33, 0}, [3]uint64{1, 33, 0}, [3]uint64{1, 36, 0}, false, true},
		"four minors behind":       {[3]uint64{1, 33, 0}, [3]uint64{1, 33, 0}, [3]uint64{1, 37, 0}, true, true},
		"patch ignored":            {[3]uint64{1, 33, 9}, [3]uint64{1, 33, 9}, [3]uint64{1, 36, 0}, false, true},
		"two behind below 1.25":    {[3]uint64{1, 22, 0}, [3]uint64{1, 22, 0}, [3]uint64{1, 25, 0}, true, true},
		"newer than the target":    {[3]uint64{1, 35, 0}, [3]uint64{1, 37, 0}, [3]uint64{1, 36, 0}, true, true},
		"equal to the target":      {[3]uint64{1, 36, 0}, [3]uint64{1, 36, 0}, [3]uint64{1, 36, 0}, false, true},
		"minimum on another major": {[3]uint64{2, 0, 0}, [3]uint64{2, 0, 0}, [3]uint64{1, 36, 0}, false, false},
		"maximum on another major": {[3]uint64{1, 35, 0}, [3]uint64{2, 0, 0}, [3]uint64{1, 36, 0}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			present, resolved := KubeletSkewUnsupported(tc.minimum, tc.maximum, tc.target)
			if present != tc.present || resolved != tc.resolved {
				t.Fatalf("got (%v, %v), want (%v, %v)", present, resolved, tc.present, tc.resolved)
			}
		})
	}
}

func TestValidateKubeletVersionDeclarations(t *testing.T) {
	for name, tc := range map[string]struct {
		minimum, maximum string
		ok               bool
	}{
		"none":                {"", "", true},
		"minimum":             {"1.33.0", "", true},
		"equal maximum":       {"1.33.0", "1.33.0", true},
		"higher maximum":      {"1.33.0", "1.35.2", true},
		"v prefix":            {"v1.33.0", "", false},
		"build suffix":        {"1.33.0-eks", "", false},
		"pre-release minimum": {"1.36.0-rc.1", "", false},
		"pre-release maximum": {"1.33.0", "1.36.0-rc.1", false},
		"minor only":          {"1.33", "", false},
		"leading zero":        {"1.033.0", "", false},
		"maximum below":       {"1.34.0", "1.33.9", false},
		"maximum no minimum":  {"", "1.34.0", false},
		"bad maximum":         {"1.33.0", "1.34", false},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateKubeletVersionDeclarations(tc.minimum, tc.maximum)
			if (err == nil) != tc.ok {
				t.Fatalf("err %v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("err %v does not wrap ErrInvalid", err)
			}
		})
	}
}

func scanSkewFact(t *testing.T, declaration KubeletDeclaration, from, to, distribution string) (string, Prepared) {
	t.Helper()
	workspace := crWorkspace(t, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"))
	scan, err := PrepareKubernetesScan(workspace, from, to, distribution, true, true, declaration)
	if err != nil {
		t.Fatal(err)
	}
	view, found := k8sProposedFacts(t, scan.Prepared)[KubernetesKubeletSkewFact]
	return k8sFactState(view, found), scan.Prepared
}

func TestPrepareKubernetesScanKubeletFact(t *testing.T) {
	for name, tc := range map[string]struct {
		declaration KubeletDeclaration
		to          string
		distro      string
		want        string
	}{
		"no declaration":     {KubeletDeclaration{}, "1.36.0", "official_upstream", "absent-from-input"},
		"inside":             {KubeletDeclaration{Minimum: "1.33.0", Source: "flag"}, "1.36.0", "official_upstream", "false"},
		"outside":            {KubeletDeclaration{Minimum: "1.33.0", Source: "flag"}, "1.37.0", "official_upstream", "true"},
		"newer maximum":      {KubeletDeclaration{Minimum: "1.35.0", Maximum: "1.37.0"}, "1.36.0", "official_upstream", "true"},
		"other major":        {KubeletDeclaration{Minimum: "2.0.0"}, "1.36.0", "official_upstream", "unsupported"},
		"custom build":       {KubeletDeclaration{Minimum: "1.33.0"}, "1.36.0", "custom_build", "unsupported"},
		"distribution unset": {KubeletDeclaration{Minimum: "1.33.0"}, "1.36.0", "", "unsupported"},
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := scanSkewFact(t, tc.declaration, "1.35.0", tc.to, tc.distro)
			if got != tc.want {
				t.Fatalf("skew fact %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPrepareKubernetesScanKubeletDeclarationChangesOnlyTheSkewFact(t *testing.T) {
	_, plain := scanSkewFact(t, KubeletDeclaration{}, "1.35.0", "1.36.0", "official_upstream")
	_, declared := scanSkewFact(t, KubeletDeclaration{Minimum: "1.33.0", Source: "file"}, "1.35.0", "1.36.0", "official_upstream")
	if plain.State != declared.State || plain.Reason != declared.Reason || plain.SourceDigest != declared.SourceDigest {
		t.Fatalf("state %v/%v reason %v/%v", plain.State, declared.State, plain.Reason, declared.Reason)
	}
	if plain.InputDigest == declared.InputDigest {
		t.Fatal("the declared fact is not covered by the input digest")
	}
	_, again := scanSkewFact(t, KubeletDeclaration{Minimum: "1.33.0", Source: "flag"}, "1.35.0", "1.36.0", "official_upstream")
	if again.InputDigest != declared.InputDigest {
		t.Fatal("the declaration source leaked into the input digest")
	}
	before, after := k8sProposedFacts(t, plain), k8sProposedFacts(t, declared)
	if len(after) != len(before)+1 {
		t.Fatalf("facts %d -> %d, want exactly the skew fact added", len(before), len(after))
	}
	for id, view := range before {
		if got := after[id]; got.State != view.State {
			t.Fatalf("fact %s changed: %+v -> %+v", id, view, got)
		}
	}
}

func TestPrepareKubernetesScanRefusesInvalidKubeletDeclaration(t *testing.T) {
	workspace := crWorkspace(t, []byte("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"))
	for _, declaration := range []KubeletDeclaration{{Minimum: "v1.33.0"}, {Minimum: "1.33"}, {Maximum: "1.33.0"}, {Minimum: "1.34.0", Maximum: "1.33.0"}} {
		if _, err := PrepareKubernetesScan(workspace, "1.35.0", "1.36.0", "official_upstream", true, true, declaration); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: err %v", declaration, err)
		}
	}
}

// The flow-control route (a transition without reviewed removals) carries the
// fact too.
func TestPrepareKubernetesScanKubeletFactOnFlowControlRoute(t *testing.T) {
	got, _ := scanSkewFact(t, KubeletDeclaration{Minimum: "1.30.0"}, "1.31.0", "1.32.0", "official_upstream")
	if got != "false" {
		t.Fatalf("skew fact %q", got)
	}
}
