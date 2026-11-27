// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import "testing"

func TestStaticHelperClosedAST(t *testing.T) {
	for _, body := range []string{
		" \t\r\n{{/* CustomResourceDefinition is mentioned, not emitted. */}}",
		`{{ define "check" }}{{ fail "CustomResourceDefinition is unavailable" }}{{ end }}`,
		`{{ define "check" }}{{ if and .Values.enabled (not .Values.disabled) }}{{ fail "unavailable" }}{{ else }}{{/* no output */}}{{ end }}{{ end }}`,
	} {
		if !staticHelperFile([]byte(body)) {
			t.Errorf("closed helper refused: %s", body)
		}
	}
	for _, body := range []string{
		"\u00a0{{/* CustomResourceDefinition */}}",
		"\x00{{/* CustomResourceDefinition */}}",
		`{{ define "check" }}{{ fail "unavailable" }}{{ end }}{{ define "unused" }}kind: CustomResourceDefinition{{ end }}`,
		`{{ define "check" }}{{ if .Values.enabled }}{{ fail "unavailable" }}{{ else }}kind: CustomResourceDefinition{{ end }}{{ end }}`,
		`{{ define "check" }}{{ fail "unavailable" }}{{ end }}{{ define "check" }}{{ end }}`,
		`{{ define "check" }}{{ if .Capabilities.APIVersions.Has "v1" }}{{ fail "unavailable" }}{{ end }}{{ end }}`,
	} {
		if staticHelperFile([]byte(body)) {
			t.Errorf("unproved helper accepted: %s", body)
		}
	}
}
