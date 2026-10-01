// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"encoding/json"
	"strings"
	"testing"
)

func inTotoArgv(t *testing.T, values ...any) []byte {
	t.Helper()
	raw, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPrepareInTotoRunKeyArgument(t *testing.T) {
	tests := []struct {
		name  string
		argv  []any
		value string
	}{
		{"short legacy", []any{"in-toto-run", "-n", "build", "-k", "/private/legacy", "--", "make"}, InTotoRunKeyLegacy},
		{"long legacy opaque tail", []any{"in-toto-run", "--step-name", "build", "--key", "/private/legacy", "--", "tool", "--key", "wrapped", "--", "again"}, InTotoRunKeyLegacy},
		{"signing key", []any{"in-toto-run", "-n", "build", "--signing-key", "/private/new", "--", "make"}, InTotoRunKeySigning},
		{"opaque empty later argument", []any{"in-toto-run", "-n", "build", "--signing-key", "/private/new", "--", "make", ""}, InTotoRunKeySigning},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := PrepareInTotoRun(inTotoArgv(t, tc.argv...), InTotoFrom, InTotoTo)
			if err != nil || p.State != StatePrepared || p.Reason != ReasonInTotoRunArgumentObserved || !strings.Contains(string(p.CanonicalInputJSON), `"enumValue":"`+tc.value+`"`) {
				t.Fatalf("prepared=%+v err=%v input=%s", p, err, p.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareInTotoRunUnsupportedShapesStayUnknown(t *testing.T) {
	tests := [][]any{
		{"in-toto-record", "-n", "x", "-k", "k", "--", "cmd"},
		{"in-toto-run", "-k", "k", "-n", "x", "--", "cmd"},
		{"in-toto-run", "-n", "x", "--key=k", "--", "cmd"},
		{"in-toto-run", "-n", "x", "--gpg", "id", "--", "cmd"},
		{"in-toto-run", "-n", "x", "-k", "--", "cmd"},
		{"in-toto-run", "-n", "x", "-k", "k"},
		{"in-toto-run", "-n", "x", "-k", "k", "--"},
		{"in-toto-run", "-n", "x", "-k", "k", "--", ""},
		{"in-toto-run", "-n", "x", "-k", "k", "--signing-key", "s", "--", "cmd"},
		{"in-toto-run", "-n", "x", "-k", "k", "extra", "--", "cmd"},
		{"in-toto-run", "-n", "x", "-k", "k", "--", "cmd\nsecret"},
		{"in-toto-run", "-n", 7, "-k", "k", "--", "cmd"},
	}
	for i, argv := range tests {
		p, err := PrepareInTotoRun(inTotoArgv(t, argv...), InTotoFrom, InTotoTo)
		if err != nil || p.State != StateUnknown || p.Reason != ReasonInTotoRunArgumentsUnsupported || !strings.Contains(string(p.CanonicalInputJSON), `"state":"unsupported"`) {
			t.Fatalf("case %d prepared=%+v err=%v", i, p, err)
		}
	}
}

func TestPrepareInTotoRunRejectsMalformedEnvelope(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`["unterminated]`), []byte{0xff}} {
		if _, err := PrepareInTotoRun(raw, InTotoFrom, InTotoTo); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestPrepareInTotoRunObservationIsTupleIndependent(t *testing.T) {
	p, err := PrepareInTotoRun(inTotoArgv(t, "in-toto-run", "-n", "x", "-k", "private", "--", "cmd"), "8.1.0", "9.2.0")
	if err != nil || p.State != StatePrepared || !strings.Contains(string(p.CanonicalInputJSON), `"version":"8.1.0"`) {
		t.Fatalf("prepared=%+v err=%v", p, err)
	}
}
