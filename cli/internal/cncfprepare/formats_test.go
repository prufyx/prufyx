// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

func TestPrepareDistributionManifestFormats(t *testing.T) {
	tests := []struct {
		name, raw, format string
	}{
		{"schema1 blocked witness", `{"schemaVersion":1,"name":"example/app","tag":"latest","architecture":"amd64","fsLayers":[{"blobSum":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],"history":[{"v1Compatibility":"{}"}],"signatures":[{"header":{"jwk":{}},"signature":"value","protected":"value"}]}`, DistributionFormatSchema1},
		{"docker schema2 fixed", `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":2,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","size":3,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`, DistributionFormatSchema2},
		{"oci fixed", `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":2,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","size":3,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`, DistributionFormatOCI},
		{"zero-layer schema2 format", `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":0,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[]}`, DistributionFormatSchema2},
		{"zero-layer oci format", `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","size":0,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[]}`, DistributionFormatOCI},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareDistributionManifest([]byte(test.raw), DistributionFrom, DistributionTo)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonDistributionFormatObserved {
				t.Fatalf("PrepareDistributionManifest() = %#v, %v", prepared, err)
			}
			if !strings.Contains(string(prepared.CanonicalInputJSON), `"enumValue":"`+test.format+`"`) || strings.Contains(string(prepared.CanonicalInputJSON), "example/app") {
				t.Fatalf("unexpected canonical input: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareDistributionManifestUnknownAndMalformed(t *testing.T) {
	unknown := []string{
		`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","manifests":[]}`,
		`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":null,"layers":[]}`,
		`{"schemaVersion":1,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","name":"example/app","tag":"latest","architecture":"amd64","fsLayers":[],"history":[],"config":{},"layers":[]}`,
		`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":0,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[],"fsLayers":[],"history":[]}`,
		`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":0,"digest":"not-a-digest"},"layers":[]}`,
	}
	for _, raw := range unknown {
		prepared, err := PrepareDistributionManifest([]byte(raw), DistributionFrom, DistributionTo)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonDistributionFormatUnsupported {
			t.Fatalf("unknown = %#v, %v", prepared, err)
		}
	}
	for _, raw := range []string{`{"schemaVersion":1`, `{"schemaVersion":1,"schemaVersion":2}`} {
		if _, err := PrepareDistributionManifest([]byte(raw), DistributionFrom, DistributionTo); err == nil {
			t.Fatalf("expected malformed input rejection: %s", raw)
		}
	}
}

func TestFormatPreparersExtractFactsOutsideInitialRuleEndpoints(t *testing.T) {
	distribution, err := PrepareDistributionManifest([]byte(`{"schemaVersion":1,"name":"example/app","tag":"latest","architecture":"amd64","fsLayers":[],"history":[]}`), "3.0.0", "4.0.0")
	if err != nil || distribution.State != StatePrepared || !strings.Contains(string(distribution.CanonicalInputJSON), `"enumValue":"docker_schema1"`) {
		t.Fatalf("distribution future pair = %#v, %v", distribution, err)
	}
	cni, err := PrepareCNISpecConfiguration([]byte(`{"cniVersion":"1.0.0","name":"dbnet","plugins":[{"type":"bridge"}]}`), "1.0.0", "2.0.0", CNISpecMigrationOperation)
	if err != nil || cni.State != StatePrepared || !strings.Contains(string(cni.CanonicalInputJSON), `"enumValue":"plugin_list"`) || !strings.Contains(string(cni.CanonicalInputJSON), `"enumValue":"1.0.0"`) {
		t.Fatalf("CNI future pair = %#v, %v", cni, err)
	}
}

func TestPrepareCNISpecConfigurationMigration(t *testing.T) {
	tests := []struct {
		name, raw, shape, version string
	}{
		{"legacy label and shape", `{"cniVersion":"0.4.0","name":"dbnet","type":"bridge","bridge":"cni0","ipam":{"type":"host-local"}}`, CNISpecShapeSingle, CNISpecFrom},
		{"target label but legacy shape", `{"cniVersion":"1.0.0","name":"dbnet","type":"bridge","bridge":"cni0"}`, CNISpecShapeSingle, CNISpecTo},
		{"target list fixed", `{"cniVersion":"1.0.0","name":"dbnet","disableCheck":false,"plugins":[{"type":"bridge","bridge":"cni0","ipam":{"type":"host-local"}},{"type":"portmap","capabilities":{"portMappings":true}}]}`, CNISpecShapeList, CNISpecTo},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareCNISpecConfiguration([]byte(test.raw), CNISpecFrom, CNISpecTo, CNISpecMigrationOperation)
			if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonCNISpecConfigurationObserved {
				t.Fatalf("PrepareCNISpecConfiguration() = %#v, %v", prepared, err)
			}
			canonical := string(prepared.CanonicalInputJSON)
			if !strings.Contains(canonical, `"enumValue":"`+test.shape+`"`) || !strings.Contains(canonical, `"enumValue":"`+test.version+`"`) || strings.Contains(canonical, "dbnet") || strings.Contains(canonical, "bridge") {
				t.Fatalf("unexpected canonical input: %s", canonical)
			}
		})
	}
}

func TestPrepareCNISpecConfigurationUnknownBoundaries(t *testing.T) {
	unknown := []string{
		`{"cniVersion":"1.0.0","name":"dbnet","type":"bridge","plugins":[{"type":"portmap"}]}`,
		`{"cniVersion":"1.0.0","name":"dbnet","plugins":[]}`,
		`{"cniVersion":"1.0.0","name":"dbnet","plugins":[{"type":null}]}`,
		`{"cniVersion":"1.1.0","name":"dbnet","plugins":[{"type":"bridge"}]}`,
		`{"cniVersion":"1.0.0","name":"dbnet","plugins":[{"type":"bridge"}],"disableCheck":"false"}`,
	}
	for _, raw := range unknown {
		prepared, err := PrepareCNISpecConfiguration([]byte(raw), CNISpecFrom, CNISpecTo, CNISpecMigrationOperation)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonCNISpecConfigurationUnsupported {
			t.Fatalf("unknown = %#v, %v", prepared, err)
		}
	}
	prepared, err := PrepareCNISpecConfiguration([]byte(`{"cniVersion":"1.0.0","name":"dbnet","plugins":[{"type":"bridge"}]}`), CNISpecFrom, CNISpecTo, "")
	if err != nil || prepared.State != StateUnknown || strings.Contains(string(prepared.CanonicalInputJSON), `"boolValue":true`) {
		t.Fatalf("missing operation = %#v, %v", prepared, err)
	}
	if _, err := PrepareCNISpecConfiguration([]byte(`{"cniVersion":"1.0.0","name":"dbnet"`), CNISpecFrom, CNISpecTo, CNISpecMigrationOperation); err == nil {
		t.Fatal("expected malformed JSON error")
	}
}
