// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import "testing"

func TestClassifyKubectlStderr(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ want, input string }{
		{"authentication_exec_plugin_failure", "error: exec plugin: executable /private/helper failed; token=private"},
		{"unauthorized", "Error from server (Unauthorized): private"},
		{"authorization_rbac_forbidden", "Error from server (Forbidden): private"},
		{"invalid_kubeconfig_context", `error: context "private" does not exist in kubeconfig`},
		{"tls_certificate", "Unable to connect to the server: x509: private"},
		{"dns", "Unable to connect to the server: dial tcp: lookup private: no such host"},
		{"transport_timeout_unreachable", "Unable to connect to the server: context deadline exceeded"},
		{"unsupported_not_found_api", "error: the server doesn't have a resource type private"},
		{"generic_api_read_failure", "arbitrary private failure"},
	} {
		if got := ClassifyKubectlStderr([]byte(tc.input)); got != tc.want {
			t.Errorf("ClassifyKubectlStderr(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestClassifyDoesNotInterpretControlledLine(t *testing.T) {
	t.Parallel()
	input := []byte("\x1b[31mError from server (Forbidden): private\x1b[0m")
	if got := ClassifyKubectlStderr(input); got != "generic_api_read_failure" {
		t.Fatalf("controlled line classified as %q", got)
	}
}
