// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"strings"
	"testing"
)

func TestScanNamesRefusedConstructAndLine(t *testing.T) {
	t.Parallel()
	head := "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\n"
	deep := "data:\n" + strings.Repeat(" ", 0) + "  a:\n"
	nest := strings.Repeat("[", 100) + strings.Repeat("]", 100)
	_ = deep
	cases := map[string]struct{ body, want string }{
		"anchor":      {head + "data:\n  k: &a v\n  j: *a\n", "line 5: YAML anchors and aliases are not supported"},
		"anchor only": {head + "data:\n  k: &a v\n", "line 5: YAML anchors and aliases are not supported"},
		"merge":       {head + "data:\n  <<: {a: b}\n", "line 5: YAML merge keys"},
		"deep flow":   {head + "data:\n  k: " + nest + "\n", "line 5: nesting deeper than 64 levels"},
		"dup":         {head + "data:\n  k: v\n  k: w\n", "line 6: duplicate mapping keys"},
		"not yaml":    {head + "data: [\n", "not valid YAML or JSON"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, paths := files(t, map[string]string{"bad.yaml": tc.body})
			_, err := scan(t, kubeletKnowledge(t), kubeletArgs(paths)...)
			var usageErr *UsageError
			if !errors.As(err, &usageErr) {
				t.Fatalf("error %v, want a usage error", err)
			}
			if !strings.Contains(usageErr.Message, tc.want) || !strings.Contains(usageErr.Message, "bad.yaml") {
				t.Fatalf("message %q, want file and %q", usageErr.Message, tc.want)
			}
		})
	}
}

func TestScanRefusedFileNameIsEscaped(t *testing.T) {
	t.Parallel()
	_, paths := files(t, map[string]string{"a\x1b[31mb.yaml": "k: &a v\n"})
	_, err := scan(t, kubeletKnowledge(t), kubeletArgs(paths)...)
	var usageErr *UsageError
	if !errors.As(err, &usageErr) {
		t.Fatalf("error %v, want a usage error", err)
	}
	for _, r := range usageErr.Message {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control character in %q", usageErr.Message)
		}
	}
}

func TestScanEmptyInputIsUsageRefusal(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{"comments": "# nothing\n", "empty docs": "---\n---\n", "zero bytes": ""} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, paths := files(t, map[string]string{"e.yaml": body})
			_, err := scan(t, kubeletKnowledge(t), kubeletArgs(paths)...)
			var usageErr *UsageError
			if !errors.As(err, &usageErr) || !strings.Contains(usageErr.Message, "no documents read from ") ||
				!strings.Contains(usageErr.Message, "pass rendered manifests (YAML or JSON)") {
				t.Fatalf("error %v, want the no-documents refusal", err)
			}
		})
	}
}
