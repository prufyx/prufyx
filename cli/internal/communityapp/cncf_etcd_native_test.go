// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"fmt"
	"strings"
	"testing"
)

const etcdCleanArgvInput = `{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=private-node"]}`
const etcdRemovedArgvInput = `{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=private-node","--enable-v2=true"]}`

func etcdNativeArgs(path, from, to string) []string {
	return []string{
		"check", "cncf", "--project", "etcd", "--native-resource", path,
		"--from", from, "--to", to, "--now", "2026-09-18T10:00:00Z", "--format", "json",
	}
}

// The native one-step route reuses the already-reviewed PrepareEtcd adapter;
// this exercises it end to end for the v2/proxy pair without a separate
// prepare step. The reviewed rule only ever proves presence of a removed
// v2/proxy flag; a clean argv (no witness) stays UNKNOWN rather than becoming
// a negative-presence PASS.
func TestEtcdNativeCheck_V2ProxyPairBoundedOutcomesAndPrivacy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, raw, reason string
		want              int
	}{
		{"removed flag blocks", etcdRemovedArgvInput, "REVIEWED_SOURCE_CONSTRAINT", ExitBlocked},
		{"clean argv stays unknown, never a negative-presence pass", etcdCleanArgvInput, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"unrecognized flag stays unknown", `{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--initial-cluster","--enable-v2=true"]}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
		{"declaration missing stays unknown", `{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":false,"argv":["--enable-v2=true"]}`, "RULE_FACT_UNAVAILABLE", ExitUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeCNCFFile(t, "etcd.json", []byte(test.raw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, etcdNativeArgs(path, "3.5.17", "3.6.0")...)
			if code != test.want || stderr != "" || !strings.Contains(stdout, test.reason) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) || strings.Contains(stdout, "private-") || strings.Contains(stdout, path) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if strings.Contains(stdout, `"status":"PASS"`) {
				t.Fatalf("negative-presence PASS emitted: %q", stdout)
			}
		})
	}
}

// The aggregate gate is unchanged by this route: even a scoped PASS keeps the
// whole-upgrade assessment UNKNOWN. 3.6.14 -> 3.7.1 is the one reviewed latest
// origin with no competing direct-minor-skip blocker, so a clean argv there
// can reach a full aggregate PASS.
func TestEtcdNativeCheck_KeepsWholeUpgradeAggregateUnknown(t *testing.T) {
	t.Parallel()
	raw := `{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=private-node"]}`
	path := writeCNCFFile(t, "etcd.json", []byte(raw), 0o600)
	code, stdout, stderr := runCNCFCLI(t, etcdNativeArgs(path, "3.6.14", "3.7.1")...)
	if code != ExitOK || stderr != "" || !strings.Contains(stdout, `"status":"PASS"`) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED") {
		t.Fatalf("missing whole-upgrade omission: %q", stdout)
	}
}

// All five reviewed 3.7.1 origins are routed through the same native path,
// checking only the finite reviewed removed experimental flag names. Four of
// the five origins also match the separate, unconditional direct-minor-skip
// blocker for the same pair (a multi-minor skip); that blocker is out of this
// batch's scope and keeps the aggregate BLOCKED regardless of the
// experimental-flags claim. Only 3.6.14 has no such blocker.
func TestEtcdNativeCheck_AllLatestOriginsAreRouted(t *testing.T) {
	t.Parallel()
	blockedRaw := `{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=private-node","--experimental-compact-hash-check-enabled=true"]}`
	cleanRaw := `{"apiVersion":"prufyx.io/etcd-effective-argv/v1alpha1","kind":"EtcdEffectiveArguments","effectiveArgvDeclared":true,"argv":["--name=private-node"]}`
	minorSkipOrigins := map[string]bool{"3.2.32": true, "3.3.27": true, "3.4.45": true, "3.5.33": true}
	for _, from := range []string{"3.2.32", "3.3.27", "3.4.45", "3.5.33", "3.6.14"} {
		t.Run(from, func(t *testing.T) {
			ruleID := fmt.Sprintf("etcd.experimental-flags-unsupported.%s-to-3-7-1", strings.ReplaceAll(from, ".", "-"))
			blocked := writeCNCFFile(t, "etcd-latest-blocked.json", []byte(blockedRaw), 0o600)
			code, stdout, stderr := runCNCFCLI(t, etcdNativeArgs(blocked, from, "3.7.1")...)
			if code != ExitBlocked || stderr != "" || !strings.Contains(stdout, ruleID) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s blocked code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
			clean := writeCNCFFile(t, "etcd-latest-clean.json", []byte(cleanRaw), 0o600)
			code, stdout, stderr = runCNCFCLI(t, etcdNativeArgs(clean, from, "3.7.1")...)
			if stderr != "" || !strings.Contains(stdout, ruleID) || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
				t.Fatalf("from=%s clean code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
			claimStart := strings.Index(stdout, `"ruleId":"`+ruleID+`"`)
			if claimStart < 0 || claimStart+400 > len(stdout) {
				t.Fatalf("from=%s clean: claim not found: %q", from, stdout)
			}
			claim := stdout[claimStart : claimStart+400]
			if !strings.Contains(claim, `"status":"PASS"`) {
				t.Fatalf("from=%s clean: this rule's own claim was not PASS: %q", from, claim)
			}
			if minorSkipOrigins[from] {
				// The unconditional direct-minor-skip blocker (out of this
				// batch's scope) still holds the aggregate BLOCKED, but this
				// route's own claim must still show PASS, never a false BLOCKED.
				if code != ExitBlocked {
					t.Fatalf("from=%s clean code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
				}
			} else if code != ExitOK || !strings.Contains(stdout, `"status":"PASS"`) {
				t.Fatalf("from=%s clean code=%d stdout=%q stderr=%q", from, code, stdout, stderr)
			}
		})
	}
}

func TestEtcdNativeCheck_RejectsMalformedWrongPairAndWrongRoute(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "etcd.json", []byte(etcdRemovedArgvInput), 0o600)
	code, stdout, stderr := runCNCFCLI(t, etcdNativeArgs(path, "3.5.17", "3.6.1")...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, `"assessment":"UNKNOWN"`) {
		t.Fatalf("wrong pair code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCNCFCLI(t, "check", "cncf", "--project", "kubernetes", "--native-resource", "PRIVATE-NOT-READ.json", "--from", "1.31.0", "--to", "1.32.0", "--now", "2026-09-18T10:00:00Z", "--format", "json")
	if code != ExitOK && code != ExitUnknown && code != ExitUsage {
		t.Fatalf("cross-project code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if strings.Contains(stderr, "PRIVATE-NOT-READ") || strings.Contains(stdout, "PRIVATE-NOT-READ") {
		t.Fatalf("cross-project leaked path: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestEtcdNativeCheck_RejectsIntegrityPinMismatch(t *testing.T) {
	t.Parallel()
	path := writeCNCFFile(t, "etcd.json", []byte(etcdRemovedArgvInput), 0o600)
	args := append(etcdNativeArgs(path, "3.5.17", "3.6.0"), "--native-resource-digest", cncfDigest([]byte(etcdCleanArgvInput)))
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitIntegrity || strings.Contains(stdout, "BLOCKED") || strings.Contains(stderr, path) {
		t.Fatalf("pin mismatch code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
