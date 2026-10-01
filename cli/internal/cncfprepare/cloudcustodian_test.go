// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

func TestPrepareCloudCustodianJsonDiffScope(t *testing.T) {
	cases := []struct {
		name, raw string
		state     State
		reason    Reason
		present   string
	}{
		{"direct previous", `{"policies":[{"name":"access-key-review","resource":"aws.iam-access-key","filters":[{"type":"json-diff","selector":"previous"}]}]}`, StatePrepared, ReasonCloudCustodianJsonDiffPresent, `"boolValue":true`},
		{"direct date with selector value", `{"policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"date","selector_value":"2026-01-01"}]}]}`, StatePrepared, ReasonCloudCustodianJsonDiffPresent, `"boolValue":true`},
		{"complete empty filter list", `{"policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[]}]}`, StatePrepared, ReasonCloudCustodianJsonDiffAbsent, `"boolValue":false`},
		{"whitespace-only policy name", `{"policies":[{"name":"   ","resource":"iam-access-key","filters":[]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"padded policy name", `{"policies":[{"name":" access-key-review","resource":"iam-access-key","filters":[]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"control policy name", `{"policies":[{"name":"access-key\u0001review","resource":"iam-access-key","filters":[]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"missing filters", `{"policies":[{"name":"access-key-review","resource":"iam-access-key"}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"unrelated filter is not absence", `{"policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[{"type":"value","key":"tag:team","value":"x"}]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"nested filter is not direct", `{"policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[{"or":[{"type":"json-diff","selector":"previous"}]}]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"dynamic resource", `{"policies":[{"name":"access-key-review","resource":"${resource}","filters":[]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"variables", `{"policies":[{"name":"access-key-review","resource":"iam-access-key","vars":{"resource":"iam-access-key"},"filters":[]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"root variables", `{"vars":{"resource":"iam-access-key"},"policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"root include", `{"include":"private-policy.json","policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"unsupported root member", `{"policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[]}],"mode":"audit"}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"dynamic selector value", `{"policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"date","selector_value":"${today}"}]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"format selector value", `{"policies":[{"name":"access-key-review","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"date","selector_value":"{today}"}]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
		{"multiple policies", `{"policies":[{"name":"one","resource":"iam-access-key","filters":[]},{"name":"two","resource":"iam-access-key","filters":[]}]}`, StateUnknown, ReasonCloudCustodianUnsupported, `"state":"unsupported"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCloudCustodian([]byte(tc.raw), CloudCustodianFrom, CloudCustodianTo)
			if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason || !strings.Contains(string(prepared.CanonicalInputJSON), tc.present) {
				t.Fatalf("prepared=%+v err=%v input=%s", prepared, err, prepared.CanonicalInputJSON)
			}
			for _, secret := range []string{"access-key-review", "tag:team", "2026-01-01", "${resource}"} {
				if strings.Contains(string(prepared.CanonicalInputJSON), secret) {
					t.Fatalf("private policy value leaked: %q", secret)
				}
			}
		})
	}
}

func TestPrepareCloudCustodianRejectsMalformedAndAmbiguousJSON(t *testing.T) {
	for _, raw := range []string{
		`{"policies":[{"name":"one","resource":"iam-access-key","filters":[]},]}`,
		`{"policies":[{"name":"one","resource":"iam-access-key","filters":[],"filters":[]}]}`,
	} {
		if _, err := PrepareCloudCustodian([]byte(raw), CloudCustodianFrom, CloudCustodianTo); err == nil {
			t.Fatalf("malformed or duplicate input accepted: %s", raw)
		}
	}
	if prepared, err := PrepareCloudCustodian([]byte(`{"policies":[{"name":"one","resource":"iam-access-key","filters":[]}]}`), "0.9.49", CloudCustodianTo); err != nil || prepared.State != StateUnknown {
		t.Fatalf("unsupported pair = %+v err=%v", prepared, err)
	}
}

func TestPrepareCloudCustodianLatestPackageRoutes(t *testing.T) {
	blocked := []byte(`{"policies":[{"name":"one","resource":"iam-access-key","filters":[{"type":"json-diff","selector":"previous"}]}]}`)
	for _, from := range cloudCustodianLatestOrigins {
		prepared, err := PrepareCloudCustodian(blocked, from, CloudCustodianLatestTo)
		if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonCloudCustodianJsonDiffPresent || !strings.Contains(string(prepared.CanonicalInputJSON), `"version":"`+from+`"`) || !strings.Contains(string(prepared.CanonicalInputJSON), `"version":"0.9.52"`) {
			t.Fatalf("%s latest route = %+v, %v", from, prepared, err)
		}
	}
	for _, pair := range [][2]string{{"0.9.46", CloudCustodianLatestTo}, {"0.9.51", "0.9.53"}} {
		prepared, err := PrepareCloudCustodian(blocked, pair[0], pair[1])
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonCloudCustodianUnsupportedPair {
			t.Fatalf("unsupported pair %v = %+v, %v", pair, prepared, err)
		}
	}
	for _, tag := range []string{"0.9.47.0", "0.9.52.0"} {
		if _, err := PrepareCloudCustodian(blocked, tag, CloudCustodianLatestTo); err == nil {
			t.Fatalf("release tag %q accepted as package version", tag)
		}
	}
}
