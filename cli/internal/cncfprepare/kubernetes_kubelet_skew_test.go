// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import "testing"

// skewFact prepares a selection that declares the lowest kubelet version (or
// none) and returns the state of the version-skew fact.
func skewFact(t *testing.T, minimum, from, to string) string {
	t.Helper()
	declarations := ""
	if minimum != "" {
		declarations = "declarations: {minimumKubeletVersion: \"" + minimum + "\"}\n"
	}
	raw := "apiVersion: " + KubernetesComponentSelectionAPIVersion + "\nkind: " + KubernetesComponentSelectionKind + "\n" + declarations +
		"sources: [{scope: kubelet, format: args, path: /private/selected/kubelet-args}]\n"
	selection, err := ParseKubernetesComponentSelection([]byte(raw))
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	prepared, err := PrepareKubernetesComponentConfig(selection, [][]byte{[]byte("- --node-ip=10.0.0.1\n")}, from, to, "official_upstream", k8sAllRegistered)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	view, found := k8sProposedFacts(t, prepared)[KubernetesKubeletSkewFact]
	return k8sFactState(view, found)
}

// The upstream policy allows a kubelet up to three minor versions older than
// kube-apiserver (two below 1.25) and never newer. The fact is the declared
// minimum kubelet against the target control plane version.
func TestKubeletSkewFact(t *testing.T) {
	for _, test := range []struct {
		name, minimum, from, to, want string
	}{
		{"three minors behind the target is allowed", "1.33.2", "1.35.2", "1.36.0", "false"},
		{"four minors behind the target is not", "1.32.3", "1.35.2", "1.36.0", "true"},
		{"same minor as the target", "1.36.0", "1.35.2", "1.36.0", "false"},
		{"patch level does not matter", "1.33.0", "1.35.0", "1.36.4", "false"},
		{"kubelet newer than the target", "1.37.0", "1.35.2", "1.36.0", "true"},
		{"edge of the window at 1.33", "1.30.2", "1.32.4", "1.33.0", "false"},
		{"below the window at 1.33", "1.29.9", "1.32.4", "1.33.0", "true"},
		{"below 1.25 only two minors are allowed", "1.22.0", "1.23.9", "1.24.0", "false"},
		{"below 1.25 three minors are too many", "1.21.0", "1.23.9", "1.24.0", "true"},
		{"no declaration leaves the fact out", "", "1.35.2", "1.36.0", "absent-from-input"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := skewFact(t, test.minimum, test.from, test.to); got != test.want {
				t.Fatalf("minimum %q, %s -> %s: %s, want %s", test.minimum, test.from, test.to, got, test.want)
			}
		})
	}
}

func TestKubeletSkewDeclarationIsStrict(t *testing.T) {
	base := "apiVersion: " + KubernetesComponentSelectionAPIVersion + "\nkind: " + KubernetesComponentSelectionKind + "\n"
	for name, value := range map[string]string{"minor only": `"1.33"`, "prefixed": `"v1.33.2"`, "suffixed": `"1.33.2-build.1"`, "number": "1.33", "empty": `""`, "bool": "true"} {
		raw := base + "declarations: {minimumKubeletVersion: " + value + "}\nsources: [{scope: kubelet, format: args, path: /a}]\n"
		if _, err := ParseKubernetesComponentSelection([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A different major than the target is not comparable: unresolved.
	if got := skewFact(t, "2.0.0", "1.35.2", "1.36.0"); got != "unsupported" {
		t.Fatalf("different major: %s", got)
	}
}
