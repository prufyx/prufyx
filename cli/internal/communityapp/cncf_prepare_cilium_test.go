// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"strings"
	"testing"
)

func ciliumPreparationArgs(path string) []string {
	return ciliumPreparationArgsFor(path, "1.18.6", "1.19.0")
}

func ciliumPreparationArgsFor(path, from, to string) []string {
	return []string{"prepare", "cncf", "--project", "cilium", "--input", path, "--from", from, "--to", to}
}

func ciliumPreparationResource(t *testing.T, requires []any, metadata map[string]any) []byte {
	return ciliumPreparationResourceKind(t, "CiliumNetworkPolicy", requires, metadata)
}

func ciliumPreparationResourceKind(t *testing.T, kind string, requires []any, metadata map[string]any) []byte {
	t.Helper()
	value := map[string]any{
		"apiVersion": "cilium.io/v2", "kind": kind,
		"metadata": map[string]any{"name": "private-cilium-policy"},
		"spec":     map[string]any{"ingress": []any{map[string]any{"fromRequires": requires}}},
	}
	if metadata != nil {
		listKind := kind + "List"
		value = map[string]any{
			"apiVersion": "cilium.io/v2", "kind": listKind, "metadata": metadata,
			"items": []any{value},
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCiliumPreparationFeedsExistingScopedRule(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                   string
		raw                    []byte
		from, to               string
		complete               bool
		prepareCode, checkCode int
		status                 string
	}{
		{"legacy witness blocks", ciliumPreparationResource(t, []any{map[string]any{}}, nil), "1.18.6", "1.19.0", false, ExitOK, ExitBlocked, "BLOCKED"},
		{"target CNP witness blocks", ciliumPreparationResource(t, []any{map[string]any{}}, nil), "1.18.13", "1.19.7", false, ExitOK, ExitBlocked, "BLOCKED"},
		{"target CCNP witness blocks", ciliumPreparationResourceKind(t, "CiliumClusterwideNetworkPolicy", []any{map[string]any{}}, nil), "1.18.13", "1.19.7", false, ExitOK, ExitBlocked, "BLOCKED"},
		{"target complete clean set passes scoped predicate", ciliumPreparationResource(t, []any{}, nil), "1.18.13", "1.19.7", true, ExitOK, ExitOK, "PASS"},
		{"target incomplete clean set remains unknown", ciliumPreparationResource(t, []any{}, nil), "1.18.13", "1.19.7", false, ExitUnknown, ExitUnknown, "UNKNOWN"},
		{"target partial clean list remains unknown", ciliumPreparationResource(t, []any{}, map[string]any{"continue": "private-continuation"}), "1.18.13", "1.19.7", true, ExitUnknown, ExitUnknown, "UNKNOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCNCFFile(t, "cilium.json", tc.raw, 0o600)
			args := ciliumPreparationArgsFor(path, tc.from, tc.to)
			if tc.complete {
				args = append(args, "--complete-cnp-ccnp-set", "true")
			}
			code, input, stderr := runCNCFCLI(t, append(args, "--format", "input", "--input-digest", cncfDigest(tc.raw))...)
			if code != tc.prepareCode || stderr != "" || !json.Valid([]byte(input)) || strings.Contains(input, "private-cilium-policy") || strings.Contains(input, "private-continuation") {
				t.Fatalf("prepare code=%d stderr=%q input=%s", code, stderr, input)
			}
			prepared := writeCNCFFile(t, "prepared.json", []byte(input), 0o600)
			code, report, stderr := runCNCFCLI(t, "check", "cncf", "--project", "cilium", "--input", prepared, "--input-digest", cncfDigest([]byte(input)), "--now", "2026-09-09T06:00:00Z", "--format", "json")
			if code != tc.checkCode || stderr != "" || !strings.Contains(report, `"status":"`+tc.status+`"`) || !strings.Contains(report, `"assessment":"UNKNOWN"`) || strings.Contains(report, "private-cilium-policy") || strings.Contains(report, "private-continuation") {
				t.Fatalf("check code=%d stderr=%q report=%s", code, stderr, report)
			}
		})
	}
}

func TestCiliumPreparationRejectsCrossProjectFlags(t *testing.T) {
	t.Parallel()
	raw := ciliumPreparationResource(t, []any{}, nil)
	path := writeCNCFFile(t, "cilium.json", raw, 0o600)
	for _, extra := range [][]string{{"--complete-cnp-ccnp-set", "yes"}, {"--distribution", "official_upstream"}, {"--requires-inherited-application-permissions", "true"}} {
		code, stdout, stderr := runCNCFCLI(t, append(ciliumPreparationArgs(path), extra...)...)
		if code != ExitUsage || stdout != "" || stderr != "prufyx: CILIUM_PREPARATION_INPUT_INVALID\n" {
			t.Fatalf("extra=%q code=%d stdout=%q stderr=%q", extra, code, stdout, stderr)
		}
	}
}

func TestCiliumPreparationHelpListsReviewedExactPairs(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := runCNCFCLI(t, "prepare", "cncf", "--help")
	if code != ExitOK || stderr != "" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	for _, pair := range []string{"--from 1.18.6 --to 1.19.0", "--from 1.18.13 --to 1.19.7"} {
		if !strings.Contains(stdout, "--project cilium --input FILE "+pair) {
			t.Fatalf("help does not list Cilium pair %q: %s", pair, stdout)
		}
	}
}
