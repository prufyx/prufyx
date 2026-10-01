// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrepareCoreDNSCorefileDirectFederation(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		state     State
		reason    Reason
		present   string
	}{
		{"direct", ". {\n federation\n}\n", StatePrepared, ReasonCoreDNSDirectivePresent, `"boolValue":true`},
		{"direct block", ". {\n federation example.org {\n proxy . 10.0.0.53\n }\n}\n", StatePrepared, ReasonCoreDNSDirectivePresent, `"boolValue":true`},
		{"realistic brace bodies", ".:53 {\n health {\n  lameduck 5s\n }\n ready\n kubernetes cluster.local {\n  pods insecure\n }\n forward . /etc/resolv.conf {\n  next federation\n }\n cache 30 {\n  success 9984\n }\n}\n", StatePrepared, ReasonCoreDNSDirectiveAbsent, `"boolValue":false`},
		{"comment is stripped first", ". {\n # federation {$PRIVATE} \"quoted\"\n forward . 1.1.1.1\n}\n", StatePrepared, ReasonCoreDNSDirectiveAbsent, `"boolValue":false`},
		{"argument is absent", ". {\n forward . federation\n}\n", StatePrepared, ReasonCoreDNSDirectiveAbsent, `"boolValue":false`},
		{"nested property is absent", ". {\n forward . {\n federation\n }\n}\n", StatePrepared, ReasonCoreDNSDirectiveAbsent, `"boolValue":false`},
		{"import is unknown", ". {\n import child\n}\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
		{"snippet is unknown", "(shared) {\n federation\n}\n. {\n import shared\n}\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
		{"substitution is unknown", ". {\n {$PLUGIN}\n}\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
		{"quoted is unknown", ". {\n forward . \"federation\"\n}\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
		{"direct followed by import is unknown", ". {\n federation\n import child\n}\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
		{"direct followed by unmatched brace is unknown", ". {\n federation\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
		{"direct followed by substitution is unknown", ". {\n federation\n {$PLUGIN}\n}\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
		{"direct followed by quote is unknown", ". {\n federation\n forward . \"private\"\n}\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
		{"multiple opening braces are unknown", ". {\n forward . { {\n }\n}\n", StateUnknown, ReasonCoreDNSInputUnsupported, `"state":"unsupported"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCoreDNSCorefile([]byte(tc.raw), "1.13.2", CoreDNSLatestTo, "official", true)
			if err != nil || prepared.State != tc.state || prepared.Reason != tc.reason || !bytes.Contains(prepared.CanonicalInputJSON, []byte(tc.present)) {
				t.Fatalf("prepared=%+v err=%v input=%s", prepared, err, prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareCoreDNSCorefileNestingLimit(t *testing.T) {
	raw := ". {\n" + strings.Repeat(" plugin {\n", coreDNSMaxNesting) + strings.Repeat(" }\n", coreDNSMaxNesting) + "}\n"
	prepared, err := PrepareCoreDNSCorefile([]byte(raw), "1.13.2", CoreDNSLatestTo, "official", true)
	if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonCoreDNSInputUnsupported {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
}

func TestPrepareCoreDNSCorefileGuardsAndPairs(t *testing.T) {
	for _, tc := range []struct {
		name, from, to, distribution string
		complete                     bool
		want                         Reason
	}{
		{"historical pair", CoreDNSFrom, CoreDNSTo, "official", true, ReasonCoreDNSDirectiveAbsent},
		{"wrong pair", "1.13.2", "1.14.6", "official", true, ReasonCoreDNSPairUnsupported},
		{"custom", "1.13.2", CoreDNSLatestTo, "custom", true, ReasonCoreDNSIncomplete},
		{"incomplete", "1.13.2", CoreDNSLatestTo, "official", false, ReasonCoreDNSIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := PrepareCoreDNSCorefile([]byte(". {\n forward . 1.1.1.1\n}\n"), tc.from, tc.to, tc.distribution, tc.complete)
			if err != nil || prepared.Reason != tc.want {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}
