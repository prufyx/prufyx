// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	EtcdComponent  = "pkg:github/etcd-io/etcd"
	EtcdFact       = "component.etcd.removed_v2_proxy_flags_present"
	EtcdLatestFact = "component.etcd.experimental_flags_present"
	EtcdFrom       = "3.5.17"
	EtcdTo         = "3.6.0"
	EtcdLatestTo   = "3.7.1"
	EtcdAPI        = "prufyx.io/etcd-effective-argv/v1alpha1"
	EtcdKind       = "EtcdEffectiveArguments"
)

var ErrInvalidEtcd = ErrInvalid

const (
	ReasonEtcdArgvWitness         Reason = "ETCD_REMOVED_V2_PROXY_FLAG_WITNESS"
	ReasonEtcdArgvNoWitness       Reason = "ETCD_REMOVED_V2_PROXY_FLAG_NOT_DECLARED"
	ReasonEtcdUnsupportedPair     Reason = "UNSUPPORTED_VERSION_PAIR"
	ReasonEtcdAuthorityMissing    Reason = "EFFECTIVE_ARGV_DECLARATION_MISSING"
	ReasonEtcdArgvUnsupported     Reason = "EFFECTIVE_ARGV_UNSUPPORTED"
	ReasonEtcdExperimentalWitness Reason = "ETCD_TARGET_EXPERIMENTAL_FLAG_WITNESS"
	ReasonEtcdExperimentalAbsent  Reason = "ETCD_TARGET_EXPERIMENTAL_FLAG_ABSENT"
)

// The first etcd slice deliberately accepts only long, self-contained atoms.
// This prevents a value-taking or wrapper argument from changing the meaning of
// a later token. The set contains the flags registered by the reviewed 3.5.17
// etcd server; only the eight removed options have type-sensitive semantics.
var etcdKnownFlags = map[string]bool{
	"data-dir": true, "wal-dir": true, "max-snapshots": true, "max-wals": true, "name": true,
	"heartbeat-interval": true, "election-timeout": true, "initial-election-tick-advance": true,
	"backend-bbolt-freelist-type": true, "backend-batch-limit": true, "max-txn-ops": true,
	"max-request-bytes": true, "socket-reuse-port": true, "socket-reuse-address": true,
	"max-concurrent-streams": true, "discovery": true, "discovery-fallback": true,
	"discovery-proxy": true, "discovery-srv": true, "discovery-srv-name": true,
	"initial-cluster": true, "initial-cluster-token": true, "initial-cluster-state": true,
	"strict-reconfig-check": true, "pre-vote": true, "v2-deprecation": true,
	"cert-file": true, "key-file": true, "client-cert-file": true, "client-key-file": true,
	"client-cert-auth": true, "client-crl-file": true, "client-cert-allowed-hostname": true,
	"trusted-ca-file": true, "auto-tls": true, "peer-cert-file": true, "peer-key-file": true,
	"peer-client-cert-file": true, "peer-client-key-file": true, "peer-client-cert-auth": true,
	"peer-trusted-ca-file": true, "peer-auto-tls": true, "self-signed-cert-validity": true,
	"peer-crl-file": true, "peer-cert-allowed-cn": true, "peer-cert-allowed-hostname": true,
	"cipher-suites": true, "experimental-peer-skip-client-san-verification": true,
	"tls-min-version": true, "tls-max-version": true, "host-whitelist": true, "logger": true,
	"log-outputs": true, "log-level": true, "enable-log-rotation": true,
	"log-rotation-config-json": true, "version": true, "auto-compaction-retention": true,
	"auto-compaction-mode": true, "enable-pprof": true, "metrics": true,
	"experimental-enable-distributed-tracing": true, "experimental-distributed-tracing-address": true,
	"experimental-distributed-tracing-service-name": true, "experimental-distributed-tracing-instance-id": true,
	"experimental-distributed-tracing-sampling-rate": true, "auth-token": true, "bcrypt-cost": true,
	"auth-token-ttl": true, "enable-grpc-gateway": true, "experimental-initial-corrupt-check": true,
	"experimental-compact-hash-check-enabled": true, "experimental-enable-lease-checkpoint": true,
	"experimental-enable-lease-checkpoint-persist": true, "experimental-compaction-batch-limit": true,
	"experimental-memory-mlock": true, "experimental-txn-mode-write-with-shared-buffer": true,
	"experimental-stop-grpc-service-on-defrag": true, "experimental-bootstrap-defrag-threshold-megabytes": true,
	"unsafe-no-fsync": true, "force-new-cluster": true,
}

var etcdRemovedFlags = map[string]bool{
	"enable-v2": true, "experimental-enable-v2v3": true, "proxy": true,
	"proxy-failure-wait": true, "proxy-refresh-interval": true,
	"proxy-dial-timeout": true, "proxy-write-timeout": true, "proxy-read-timeout": true,
}

// etcdTargetRemovedExperimentalFlags is the finite list in the reviewed 3.7
// upgrade guide. Unknown experimental spellings deliberately make the input
// unsupported rather than proving this target predicate false.
var etcdTargetRemovedExperimentalFlags = map[string]bool{
	"experimental-bootstrap-defrag-threshold-megabytes": true, "experimental-compact-hash-check-enabled": true,
	"experimental-compact-hash-check-time": true, "experimental-compaction-batch-limit": true,
	"experimental-compaction-sleep-interval": true, "experimental-corrupt-check-time": true,
	"experimental-distributed-tracing-address": true, "experimental-distributed-tracing-instance-id": true,
	"experimental-distributed-tracing-sampling-rate": true, "experimental-distributed-tracing-service-name": true,
	"experimental-downgrade-check-time": true, "experimental-enable-distributed-tracing": true,
	"experimental-enable-lease-checkpoint": true, "experimental-enable-lease-checkpoint-persist": true,
	"experimental-initial-corrupt-check": true, "experimental-memory-mlock": true,
	"experimental-peer-skip-client-san-verification": true, "experimental-snapshot-catchup-entries": true,
	"experimental-stop-grpc-service-on-defrag": true, "experimental-txn-mode-write-with-shared-buffer": true,
	"experimental-warning-apply-duration": true, "experimental-warning-unary-request-duration": true,
	"experimental-watch-progress-notify-interval": true,
}

// etcdLatestKnownFlags is the finite flag-name set registered by the reviewed
// 3.7.1 target's embed.Config.AddFlags and main config parser. config-file is
// intentionally excluded because it makes the direct argv declaration unable
// to establish the effective configuration. Ignored compatibility flags are
// also excluded: accepting one would say only that the target ignores it, not
// that this adapter has modelled the caller's intended effective arguments.
// Keep this independent of etcdKnownFlags: a 3.5 spelling cannot establish
// that the 3.7.1 parser accepts the proposed argv.
var etcdLatestKnownFlags = map[string]bool{
	"advertise-client-urls": true, "auth-token": true, "auth-token-ttl": true,
	"auto-compaction-mode": true, "auto-compaction-retention": true, "auto-tls": true,
	"backend-batch-interval": true, "backend-batch-limit": true, "backend-bbolt-freelist-type": true,
	"bcrypt-cost": true, "bootstrap-defrag-threshold-megabytes": true,
	"cert-file": true, "cipher-suites": true, "client-cert-allowed-hostname": true,
	"client-cert-auth": true, "client-cert-file": true, "client-crl-file": true, "client-key-file": true,
	"compact-hash-check-time": true, "compaction-batch-limit": true,
	"compaction-sleep-interval": true, "corrupt-check-time": true,
	"cors": true, "data-dir": true, "discovery-cacert": true, "discovery-cert": true,
	"discovery-dial-timeout": true, "discovery-endpoints": true, "discovery-fallback": true,
	"discovery-insecure-skip-tls-verify": true, "discovery-insecure-transport": true,
	"discovery-keepalive-time": true, "discovery-keepalive-timeout": true,
	"discovery-key": true, "discovery-password": true, "discovery-request-timeout": true,
	"discovery-srv": true, "discovery-srv-name": true, "discovery-token": true, "discovery-user": true,
	"distributed-tracing-address": true, "distributed-tracing-instance-id": true,
	"distributed-tracing-sampling-rate": true, "distributed-tracing-service-name": true,
	"downgrade-check-time": true, "election-timeout": true, "enable-distributed-tracing": true,
	"enable-grpc-gateway": true, "enable-log-rotation": true, "enable-pprof": true,
	"feature-gates": true, "force-new-cluster": true, "grpc-keepalive-interval": true,
	"grpc-keepalive-min-time": true, "grpc-keepalive-timeout": true, "heartbeat-interval": true,
	"host-whitelist": true, "initial-advertise-peer-urls": true, "initial-cluster": true,
	"initial-cluster-state": true, "initial-cluster-token": true, "initial-election-tick-advance": true,
	"key-file": true, "listen-client-http-urls": true, "listen-client-urls": true,
	"listen-metrics-urls": true, "listen-peer-urls": true, "log-format": true, "log-level": true,
	"log-outputs": true, "log-rotation-config-json": true, "logger": true, "max-concurrent-streams": true,
	"max-learners": true, "max-request-bytes": true, "max-snapshots": true, "max-txn-ops": true,
	"max-wals": true, "memory-mlock": true, "metrics": true, "name": true,
	"peer-auto-tls": true, "peer-cert-allowed-cn": true, "peer-cert-allowed-hostname": true,
	"peer-cert-file": true, "peer-client-cert-auth": true, "peer-client-cert-file": true,
	"peer-client-key-file": true, "peer-crl-file": true, "peer-key-file": true,
	"peer-skip-client-san-verification": true, "peer-trusted-ca-file": true, "pre-vote": true,
	"quota-backend-bytes": true, "raft-read-timeout": true, "raft-write-timeout": true,
	"self-signed-cert-validity": true, "snapshot-catchup-entries": true, "snapshot-count": true,
	"socket-reuse-address": true, "socket-reuse-port": true, "strict-reconfig-check": true,
	"tls-max-version": true, "tls-min-version": true, "trusted-ca-file": true,
	"unsafe-no-fsync": true, "v2-deprecation": true, "version": true, "wal-dir": true,
	"warning-apply-duration": true, "warning-unary-request-duration": true,
	"watch-progress-notify-interval": true,
}

func etcdLatestPair(from, to string) bool {
	if to != EtcdLatestTo {
		return false
	}
	return from == "3.6.14" || from == "3.5.33" || from == "3.4.45" || from == "3.3.27" || from == "3.2.32"
}

// PrepareEtcd derives one pair-specific removed-option fact from an explicitly
// operator-resolved direct etcd argv. It never executes or resolves argv.
func PrepareEtcd(raw []byte, from, to string) (Prepared, error) {
	if len(raw) == 0 || len(raw) > maxInputBytes || !utf8.Valid(raw) || !validVersionSyntax(from) || !validVersionSyntax(to) || from == to {
		return Prepared{}, ErrInvalidEtcd
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return Prepared{}, ErrInvalidEtcd
	}
	root, ok := value.(map[string]any)
	if !ok || allowFields(root, map[string]bool{"apiVersion": true, "kind": true, "effectiveArgvDeclared": true, "argv": true}) != nil {
		return Prepared{}, ErrInvalidEtcd
	}
	apiVersion, ok := root["apiVersion"].(string)
	if !ok || apiVersion != EtcdAPI {
		return Prepared{}, ErrInvalidEtcd
	}
	kind, ok := root["kind"].(string)
	if !ok || kind != EtcdKind {
		return Prepared{}, ErrInvalidEtcd
	}
	declared := false
	if rawDeclared, exists := root["effectiveArgvDeclared"]; exists {
		var ok bool
		declared, ok = rawDeclared.(bool)
		if !ok {
			return Prepared{}, ErrInvalidEtcd
		}
	}
	items, ok := root["argv"].([]any)
	if !ok || len(items) > 256 {
		return Prepared{}, ErrInvalidEtcd
	}
	argv := make([]string, len(items))
	for i, item := range items {
		text, ok := item.(string)
		if !ok || len(text) > 4096 {
			return Prepared{}, ErrInvalidEtcd
		}
		argv[i] = text
	}

	state := StateUnknown
	reason := ReasonEtcdAuthorityMissing
	var witness *bool
	if declared {
		if from == EtcdFrom && to == EtcdTo {
			reason = ReasonEtcdArgvNoWitness
			valid, found := inspectEtcdArgv(argv)
			if !valid {
				reason = ReasonEtcdArgvUnsupported
			} else if found {
				value := true
				witness = &value
				state = StatePrepared
				reason = ReasonEtcdArgvWitness
			}
		} else if etcdLatestPair(from, to) {
			valid, found := inspectEtcdLatestArgv(argv)
			if !valid {
				reason = ReasonEtcdArgvUnsupported
			} else {
				value := found
				witness = &value
				state = StatePrepared
				if found {
					reason = ReasonEtcdExperimentalWitness
				} else {
					reason = ReasonEtcdExperimentalAbsent
				}
			}
		} else {
			reason = ReasonEtcdUnsupportedPair
		}
	}
	factID := EtcdFact
	if etcdLatestPair(from, to) {
		factID = EtcdLatestFact
	}
	canonical, err := marshalComponentInput(EtcdComponent, from, to, []inputFact{{ID: factID, State: map[bool]string{true: "declared", false: "missing"}[witness != nil], BoolValue: witness}})
	if err != nil {
		return Prepared{}, ErrInvalidEtcd
	}
	return Prepared{CanonicalInputJSON: canonical, SourceDigest: digestBytes(raw), InputDigest: digestBytes(canonical), State: state, Reason: reason, Omissions: []string{"EFFECTIVE_ARGV_OPERATOR_DECLARED_NOT_LIVE_OBSERVATION", "CONFIG_ENV_WRAPPER_RESOLUTION_NOT_PERFORMED", OmissionNoWholeUpgrade}}, nil
}

func inspectEtcdLatestArgv(argv []string) (valid, found bool) {
	seen := map[string]bool{}
	for _, token := range argv {
		if token == "" || hasExpansion(token) || strings.Contains(token, "$") || strings.IndexFunc(token, func(r rune) bool { return r < 32 || r == 127 }) >= 0 || !strings.HasPrefix(token, "--") || len(token) <= 3 {
			return false, false
		}
		body := token[2:]
		equal := strings.IndexByte(body, '=')
		if equal <= 0 || equal == len(body)-1 {
			return false, false
		}
		name := body[:equal]
		if strings.HasPrefix(name, "-") || name == "config-file" || seen[name] {
			return false, false
		}
		seen[name] = true
		if etcdTargetRemovedExperimentalFlags[name] {
			found = true
			continue
		}
		if strings.HasPrefix(name, "experimental-") || !etcdLatestKnownFlags[name] {
			return false, false
		}
	}
	return true, found
}

// inspectEtcdArgv returns valid=false for any ambiguity and found=true only
// when at least one exact removed-option atom is present. A target-free but
// fully modelled vector intentionally returns found=false; it cannot prove
// absence because this adapter emits no false fact.
func inspectEtcdArgv(argv []string) (valid, found bool) {
	seen := map[string]bool{}
	for _, token := range argv {
		if token == "" || hasExpansion(token) || strings.Contains(token, "$") || strings.IndexFunc(token, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
			return false, false
		}
		if !strings.HasPrefix(token, "--") || len(token) <= 3 {
			return false, false
		}
		body := token[2:]
		equal := strings.IndexByte(body, '=')
		if equal <= 0 {
			return false, false
		}
		name, value := body[:equal], body[equal+1:]
		if strings.HasPrefix(name, "-") || value == "" && name != "experimental-enable-v2v3" {
			return false, false
		}
		if name == "config-file" || !etcdKnownFlags[name] && !etcdRemovedFlags[name] {
			return false, false
		}
		if etcdRemovedFlags[name] {
			if seen[name] || !validEtcdRemovedValue(name, value) {
				return false, false
			}
			seen[name] = true
			found = true
		}
	}
	return true, found
}

func validEtcdRemovedValue(name, value string) bool {
	switch name {
	case "enable-v2":
		return value == "true" || value == "false"
	case "proxy":
		return value == "off" || value == "readonly" || value == "on"
	case "experimental-enable-v2v3":
		if len(value) == 0 || len(value) > 128 {
			return false
		}
		return strings.IndexFunc(value, func(r rune) bool {
			return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("._:/-", r))
		}) < 0
	default:
		if len(value) == 0 || len(value) > 20 {
			return false
		}
		for _, r := range value {
			if r < '0' || r > '9' {
				return false
			}
		}
		_, err := strconv.ParseUint(value, 10, 64)
		return err == nil
	}
}
