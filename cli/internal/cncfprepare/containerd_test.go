// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"strconv"
	"testing"
)

func containerdConfig(version int, plugin, handler, runtimeType, extra string) string {
	return "version = " + strconv.Itoa(version) + "\n" + extra + "\n[plugins.\"" + plugin + "\".containerd.runtimes.\"" + handler + "\"]\nruntime_type = \"" + runtimeType + "\"\n"
}

func TestParseContainerdSelectedRuntime_V2AndV3(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, raw          string
		removed, supported bool
		reason             Reason
		invalid            bool
	}{
		{"v2-runtime-v1", containerdConfig(2, containerdConfigV2CRIPlugin, "legacy", ContainerdRuntimeV1Linux, ""), true, true, ReasonContainerdRemovedRuntime, false},
		{"v2-runc-v1", containerdConfig(2, containerdConfigV2CRIPlugin, "legacy", ContainerdRuncV1, ""), true, true, ReasonContainerdRemovedRuntime, false},
		{"v2-runc-v2", containerdConfig(2, containerdConfigV2CRIPlugin, "runc", ContainerdRuncV2, ""), false, true, ReasonContainerdRuncV2, false},
		{"v3-runtime-v1", containerdConfig(3, containerdConfigV3CRIRuntimePlugin, "legacy", ContainerdRuntimeV1Linux, ""), true, true, ReasonContainerdRemovedRuntime, false},
		{"v3-runc-v2", containerdConfig(3, containerdConfigV3CRIRuntimePlugin, "runc", ContainerdRuncV2, ""), false, true, ReasonContainerdRuncV2, false},
		{"imports", containerdConfig(2, containerdConfigV2CRIPlugin, "runc", ContainerdRuncV2, "imports = [\"/private/config.toml\"]"), false, false, ReasonContainerdImportsUnsupported, false},
		{"missing-handler", containerdConfig(2, containerdConfigV2CRIPlugin, "other", ContainerdRuncV2, ""), false, false, ReasonContainerdHandlerMissing, false},
		{"wrong-v2-section", containerdConfig(2, containerdConfigV3CRIRuntimePlugin, "runc", ContainerdRuncV1, ""), false, false, ReasonContainerdConfigUnsupported, false},
		{"wrong-v3-section", containerdConfig(3, containerdConfigV2CRIPlugin, "runc", ContainerdRuncV1, ""), false, false, ReasonContainerdConfigUnsupported, false},
		{"custom-runtime", containerdConfig(2, containerdConfigV2CRIPlugin, "custom", "io.example.custom.v2", ""), false, false, ReasonContainerdRuntimeTypeUnsupported, false},
		{"runtime-path", containerdConfig(2, containerdConfigV2CRIPlugin, "legacy", ContainerdRuncV1, "") + "runtime_path = \"/private/containerd-shim-runc-v1\"\n", false, false, ReasonContainerdRuntimePathUnsupported, false},
		{"missing-version", "[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\nruntime_type = \"io.containerd.runc.v1\"\n", false, false, ReasonContainerdConfigUnsupported, false},
		{"version-one", containerdConfig(1, containerdConfigV2CRIPlugin, "runc", ContainerdRuncV1, ""), false, false, ReasonContainerdConfigUnsupported, false},
		{"duplicate-key", "version=2\nversion=3\n", false, false, ReasonContainerdConfigUnsupported, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			removed, reason, supported, err := parseContainerdSelectedRuntime([]byte(tc.raw), "runc")
			if tc.name == "v2-runtime-v1" || tc.name == "v2-runc-v1" || tc.name == "v3-runtime-v1" || tc.name == "runtime-path" {
				removed, reason, supported, err = parseContainerdSelectedRuntime([]byte(tc.raw), "legacy")
			} else if tc.name == "custom-runtime" {
				removed, reason, supported, err = parseContainerdSelectedRuntime([]byte(tc.raw), "custom")
			}
			if (err != nil) != tc.invalid || removed != tc.removed || supported != tc.supported || reason != tc.reason {
				t.Fatalf("removed=%t supported=%t reason=%s err=%v", removed, supported, reason, err)
			}
		})
	}
}

func TestPrepareContainerdConfig_GuardsAndPrivacy(t *testing.T) {
	t.Parallel()
	raw := []byte(containerdConfig(2, containerdConfigV2CRIPlugin, "private-handler", ContainerdRuncV1, "") + "[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.\"private-handler\".options]\nBinaryName = \"/private/runc\"\n")
	for _, tc := range []struct {
		name                                             string
		complete, precedence, upstream, bundled, removed bool
		state                                            State
		reason                                           Reason
	}{
		{"blocked-fact", true, true, true, true, true, StatePrepared, ReasonContainerdRemovedRuntime},
		{"incomplete", false, true, true, true, false, StateUnknown, ReasonContainerdDeclarationsIncomplete},
		{"precedence", true, false, true, true, false, StateUnknown, ReasonContainerdDeclarationsIncomplete},
		{"custom-distribution", true, true, false, true, false, StateUnknown, ReasonContainerdDeclarationsIncomplete},
		{"custom-shim-scope", true, true, true, false, false, StateUnknown, ReasonContainerdDeclarationsIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			prepared, err := PrepareContainerdConfig(raw, "private-handler", ContainerdFrom, ContainerdTo, tc.complete, tc.precedence, tc.upstream, tc.bundled)
			if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if tc.state == StatePrepared && !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue":true`)) {
				t.Fatalf("removed fact absent: %s", prepared.CanonicalInputJSON)
			}
			for _, private := range [][]byte{[]byte("private-handler"), []byte("/private/runc"), []byte(ContainerdRuncV1)} {
				if bytes.Contains(prepared.CanonicalInputJSON, private) {
					t.Fatalf("private or raw selected value leaked: %q", private)
				}
			}
		})
	}

	wrong, err := PrepareContainerdConfig(raw, "private-handler", "1.7.27", ContainerdTo, true, true, true, true)
	if err != nil || wrong.State != StatePrepared || wrong.Reason != ReasonContainerdRemovedRuntime {
		t.Fatalf("wrong pair=%+v err=%v", wrong, err)
	}
}

func TestPrepareContainerdConfig_RuncV2ClearsOnlyScopedFact(t *testing.T) {
	t.Parallel()
	for _, version := range []int{2, 3} {
		plugin := containerdConfigV2CRIPlugin
		if version == 3 {
			plugin = containerdConfigV3CRIRuntimePlugin
		}
		prepared, err := PrepareContainerdConfig([]byte(containerdConfig(version, plugin, "runc", ContainerdRuncV2, "")), "runc", ContainerdFrom, ContainerdTo, true, true, true, true)
		if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonContainerdRuncV2 || !bytes.Contains(prepared.CanonicalInputJSON, []byte(`"boolValue":false`)) {
			t.Fatalf("version=%d prepared=%+v input=%s err=%v", version, prepared, prepared.CanonicalInputJSON, err)
		}
	}
}
