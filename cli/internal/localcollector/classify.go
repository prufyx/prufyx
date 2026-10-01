// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import "strings"

const maxStderrBytes = 64 << 10

func ClassifyKubectlStderr(raw []byte) string {
	if len(raw) > maxStderrBytes {
		raw = raw[:maxStderrBytes]
	}
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			return r
		}
		return ' '
	}, strings.ToValidUTF8(string(raw), "�"))
	lines := make([]string, 0)
	for _, line := range strings.Split(clean, "\n") {
		if strings.ContainsRune(line, '\x1b') {
			continue
		}
		lines = append(lines, strings.ToLower(strings.TrimSpace(line)))
	}
	hasPrefix := func(prefixes ...string) bool {
		for _, line := range lines {
			for _, prefix := range prefixes {
				if strings.HasPrefix(line, prefix) {
					return true
				}
			}
		}
		return false
	}
	hasShape := func(prefix string, fragments ...string) bool {
		for _, line := range lines {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			for _, fragment := range fragments {
				if strings.Contains(line, fragment) {
					return true
				}
			}
		}
		return false
	}
	if hasShape("error: exec plugin:", "executable", "failed", "invalid", "returned") || hasShape("unable to connect to the server: getting credentials: exec:", "executable", "failed") {
		return "authentication_exec_plugin_failure"
	}
	if hasPrefix("error from server (unauthorized):", "you must be logged in to the server (unauthorized)", "you must be logged in to the server (the server has asked for the client to provide credentials)", "the server has asked for the client to provide credentials") {
		return "unauthorized"
	}
	if hasPrefix("error from server (forbidden):") {
		return "authorization_rbac_forbidden"
	}
	if hasPrefix("error: invalid configuration:", "error: context ", "error: no context exists with the name", "error: current-context is not set") {
		for _, line := range lines {
			if strings.Contains(line, "does not exist") || strings.Contains(line, "no context exists") || strings.Contains(line, "invalid configuration:") || strings.Contains(line, "not set") {
				return "invalid_kubeconfig_context"
			}
		}
	}
	if hasPrefix("unable to connect to the server: x509:", "unable to connect to the server: tls:", "unable to connect to the server: certificate") {
		return "tls_certificate"
	}
	if hasShape("unable to connect to the server: dial tcp:", "lookup ", "no such host", "name or service not known") {
		return "dns"
	}
	if hasShape("unable to connect to the server:", "i/o timeout", "context deadline exceeded", "connection refused", "connection reset", "network is unreachable", "host is unreachable") {
		return "transport_timeout_unreachable"
	}
	if hasPrefix("error from server (notfound):", "error from server (unsupportedmediatype):", "error from server (methodnotallowed):", "error: the server doesn't have a resource type", "error: no matches for kind ", "the server could not find the requested resource") {
		return "unsupported_not_found_api"
	}
	return "generic_api_read_failure"
}
