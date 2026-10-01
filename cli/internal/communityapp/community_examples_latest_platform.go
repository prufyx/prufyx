// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (r runtime) runNATSLatestExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-nats-latest-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private NATS example directory: %w", err)
	}
	defer os.RemoveAll(work)

	blocked := []byte(`{"cluster":{"name":"edge cluster"}}`)
	clean := []byte(`{"server_name":"edge-west","gateway":{"name":"edge-gateway"}}`)
	unknown := []byte(`{"include":"private.conf","server_name":"edge-west"}`)
	var blockedCode, cleanCode, unknownCode int
	var report map[string]any
	for _, from := range []string{"2.12.15", "2.11.17", "2.10.29", "2.9.25", "2.8.4"} {
		blockedCode, report, err = r.checkNATSLatestExample(work, from, blocked)
		if err != nil || blockedCode != ExitBlocked || !communityClaim(report, "BLOCKED") {
			return communityExampleResult{}, fmt.Errorf("NATS %s ASCII-space witness did not produce scoped BLOCKED", from)
		}
		cleanCode, report, err = r.checkNATSLatestExample(work, from, clean)
		if err != nil || cleanCode != ExitOK || !communityClaim(report, "PASS") {
			return communityExampleResult{}, fmt.Errorf("NATS %s literal-name witness did not produce scoped PASS", from)
		}
		unknownCode, report, err = r.checkNATSLatestExample(work, from, unknown)
		if err != nil || unknownCode != ExitUnknown || !communityClaim(report, "UNKNOWN") {
			return communityExampleResult{}, fmt.Errorf("NATS %s unresolved include did not remain UNKNOWN", from)
		}
	}
	return communityExampleResult{Example: "cncf-nats-latest", BlockedExit: blockedCode, CleanExit: cleanCode, UnknownExit: unknownCode, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) checkNATSLatestExample(work, from string, raw []byte) (int, map[string]any, error) {
	path := filepath.Join(work, "nats-config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return 0, nil, fmt.Errorf("write private NATS configuration: %w", err)
	}
	var stdout bytes.Buffer
	child := r
	child.stdout = &stdout
	code := child.cncf([]string{"--project", "nats", "--nats-config", path, "--nats-config-digest", communityDigest(raw), "--from", from, "--to", "2.14.6", "--now", "2026-09-12T08:47:00Z", "--format", "json"})
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return code, nil, fmt.Errorf("decode NATS report: %w", err)
	}
	return code, report, nil
}

func (r runtime) runCephLatestExample() (communityExampleResult, error) {
	work, err := os.MkdirTemp("", "prufyx-community-ceph-latest-")
	if err != nil {
		return communityExampleResult{}, fmt.Errorf("create private Ceph example directory: %w", err)
	}
	defer os.RemoveAll(work)

	blocked := []byte(`{"id":7,"osd_objectstore":"filestore"}`)
	clean := []byte(`{"id":7,"osd_objectstore":"bluestore"}`)
	unknown := []byte(`{"id":7,"osd_objectstore":"memstore"}`)
	var blockedCode, cleanCode, unknownCode int
	var report map[string]any
	for _, from := range []string{"19.2.6", "18.2.8", "17.2.9", "16.2.15", "15.2.17"} {
		blockedCode, report, err = r.checkCephLatestExample(work, from, blocked)
		if err != nil || blockedCode != ExitBlocked || !communityClaim(report, "BLOCKED") {
			return communityExampleResult{}, fmt.Errorf("Ceph %s FileStore witness did not produce scoped BLOCKED", from)
		}
		cleanCode, report, err = r.checkCephLatestExample(work, from, clean)
		if err != nil || cleanCode != ExitOK || !communityClaim(report, "PASS") {
			return communityExampleResult{}, fmt.Errorf("Ceph %s BlueStore witness did not produce scoped PASS", from)
		}
		unknownCode, report, err = r.checkCephLatestExample(work, from, unknown)
		if err != nil || unknownCode != ExitUnknown || !communityClaim(report, "UNKNOWN") {
			return communityExampleResult{}, fmt.Errorf("Ceph %s unsupported backend did not remain UNKNOWN", from)
		}
	}
	return communityExampleResult{Example: "project-ceph-latest", BlockedExit: blockedCode, CleanExit: cleanCode, UnknownExit: unknownCode, Aggregate: "UNKNOWN", NetworkUsed: false, ClusterUsed: false, PrivateRetained: false, RuntimeObserved: false, ProcessExecuted: false, ScopedClaimOnly: true}, nil
}

func (r runtime) checkCephLatestExample(work, from string, raw []byte) (int, map[string]any, error) {
	path := filepath.Join(work, "selected-osd-metadata.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return 0, nil, fmt.Errorf("write private selected OSD metadata: %w", err)
	}
	var stdout bytes.Buffer
	child := r
	child.stdout = &stdout
	code := child.project([]string{"--project", "ceph", "--selected-osd-metadata", path, "--selected-osd-metadata-digest", communityDigest(raw), "--selected-osd-id", "7", "--selected-osd-metadata-complete", "--from", from, "--to", "20.2.4", "--now", "2026-09-12T09:20:00Z", "--format", "json"})
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return code, nil, fmt.Errorf("decode Ceph report: %w", err)
	}
	return code, report, nil
}
