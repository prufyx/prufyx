// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"reflect"
	"strings"
	"testing"
)

const (
	invalidHead  = `The Gadget "kindval-field" is invalid: `
	strictHead   = `Error from server (BadRequest): error when creating "STDIN": Gadget in version "v1" cannot be handled as a Gadget: strict decoding error: `
	typeCauseFmt = `Invalid value: "string": %s in body must be of type integer: "string"`
)

func invalid(causes ...string) string {
	if len(causes) == 1 {
		return invalidHead + causes[0]
	}
	return invalidHead + "\n* " + strings.Join(causes, "\n* ")
}

func typeCause(path string) string {
	return path + ": " + strings.Replace(typeCauseFmt, "%s", path, 1)
}

// fieldAnswer tells a server answer from no answer: only the server's own
// words are an answer, and a webhook's refused connection is one.
func TestFieldAnswer(t *testing.T) {
	multi := invalid(`spec.a: Required value`, `spec.b: Unsupported value: "x": supported values: "y"`)
	long := invalidHead + "\n" + strings.Repeat("* spec.a: Required value\n", 200)
	cases := []struct {
		name    string
		exit    int
		stderr  string
		outcome string
		message string
	}{
		{"accepted", 0, "", ServerAccepted, ""},
		{"not run", -1, `exec: "kubectl": executable file not found in $PATH`, ServerError, `exec: "kubectl": executable file not found in $PATH`},
		{"connection refused", 1, "The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?", ServerError, "The connection to the server 127.0.0.1:6443 was refused - did you specify the right host or port?"},
		{"unable to connect", 1, "Unable to connect to the server: dial tcp: i/o timeout", ServerError, "Unable to connect to the server: dial tcp: i/o timeout"},
		{"client validation", 1, `error: error validating "STDIN": error validating data: ValidationError(Gadget.spec): unknown field "foo"; if you choose to ignore these errors, turn validation off with --validate=false`, ServerError, ""},
		{"webhook refused", 1, `Error from server (InternalError): error when creating "STDIN": Internal error occurred: conversion webhook for example.com/v1, Kind=Gadget failed: Post "https://svc:443/convert": dial tcp 10.96.0.1:443: connect: connection refused`, ServerRejected, ""},
		{"no matches", 1, `error: resource mapping not found for name: "kindval-field" namespace: "" from "STDIN": no matches for kind "Gadget" in version "example.com/v1"`, ServerNotServed, ""},
		{"invalid single line", 1, invalid(typeCause("spec.size")), ServerRejected, invalid(typeCause("spec.size"))},
		{"invalid multi line", 1, "\n" + multi + "\n\n", ServerRejected, multi},
		{"bounded", 1, long, ServerRejected, strings.TrimSpace(long)[:maxFieldMessage]},
		{"no sign of an answer", 1, "something went wrong", ServerError, "something went wrong"},
	}
	for _, c := range cases {
		got := fieldAnswer(c.exit, c.stderr)
		if got.Outcome != c.outcome {
			t.Errorf("%s: outcome %q, want %q", c.name, got.Outcome, c.outcome)
		}
		want := c.message
		if want == "" && c.outcome != ServerAccepted {
			want = strings.TrimSpace(c.stderr)
		}
		if got.Message != want {
			t.Errorf("%s: message %q, want %q", c.name, got.Message, want)
		}
	}
}

// matchField confirms a claim only from causes on its own path that read
// exactly as its change.
// canonicalPath writes a bracketed index or key as a dot segment and keeps
// everything else.
func TestCanonicalPath(t *testing.T) {
	for in, want := range map[string]string{
		"spec.ports[0].name":   "spec.ports.0.name",
		"spec.ports.0.name":    "spec.ports.0.name",
		"spec.matrix[0][12].x": "spec.matrix.0.12.x",
		"spec.labels.team":     "spec.labels.team",
		"spec.odd[x].y":        "spec.odd.x.y",
		"spec.labels[team]":    "spec.labels.team",
		"spec.odd[a.b].y":      "spec.odd[a.b].y",
		"spec.open[0":          "spec.open[0",
		"spec.ports[]":         "spec.ports[]",
	} {
		if got := canonicalPath(in); got != want {
			t.Errorf("canonicalPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchField(t *testing.T) {
	cases := []struct {
		name    string
		change  string
		path    string
		message string
		pattern string
		other   []string
		note    string // a substring of the note when pattern is ""
	}{
		// field-removed
		{"removed", ChangeFieldRemoved, "spec.foo", strictHead + `unknown field "spec.foo"`, patternUnknownField, nil, ""},
		{"removed with others", ChangeFieldRemoved, "spec.foo", strictHead + `unknown field "spec.bar", unknown field "spec.foo", duplicate field "spec.baz"`, patternUnknownField, []string{`unknown field "spec.bar"`, `duplicate field "spec.baz"`}, ""},
		{"removed other field", ChangeFieldRemoved, "spec.foo", strictHead + `unknown field "spec.bar"`, "", []string{`unknown field "spec.bar"`}, `no unknown field "spec.foo"`},
		{"removed ancestor", ChangeFieldRemoved, "spec.a.b", strictHead + `unknown field "spec.a"`, "", []string{`unknown field "spec.a"`}, "the ancestor spec.a is refused"},
		{"removed ancestor of array", ChangeFieldRemoved, "spec.ports[0].name", strictHead + `unknown field "spec.ports"`, "", []string{`unknown field "spec.ports"`}, "the ancestor spec.ports is refused"},
		{"removed string prefix", ChangeFieldRemoved, "spec.ab", strictHead + `unknown field "spec.a"`, "", []string{`unknown field "spec.a"`}, `no unknown field "spec.ab"`},
		{"removed array element", ChangeFieldRemoved, "spec.ports[0].name", strictHead + `unknown field "spec.ports[0].name"`, patternUnknownField, nil, ""},
		{"removed without BadRequest", ChangeFieldRemoved, "spec.foo", `Error from server (Invalid): strict decoding error: unknown field "spec.foo"`, "", nil, "no strict-decoding or schema refusal"},
		{"removed schema answer", ChangeFieldRemoved, "spec.foo", invalid(`spec.foo: Required value`), "", nil, "not as an unknown field"},
		// field-required-added
		{"required", ChangeRequiredAdded, "spec.a", invalid(`spec.a: Required value`), patternRequiredValue, nil, ""},
		{"required other body", ChangeRequiredAdded, "spec.a", invalid(`spec.a: Unsupported value: "x": supported values: "y"`), "", nil, "does not read as field-required-added"},
		{"required on strict answer", ChangeRequiredAdded, "spec.a", strictHead + `unknown field "spec.b"`, "", []string{`unknown field "spec.b"`}, `To refuses an unknown field: unknown field "spec.b"`},
		// field-type-changed
		{"type", ChangeTypeChanged, "spec.size", invalid(typeCause("spec.size")), patternTypeInvalid, nil, ""},
		{"type plain invalid", ChangeTypeChanged, "spec.size", invalid(`spec.size: Invalid value: 5: spec.size in body should be less than or equal to 3`), "", nil, "does not read as field-type-changed"},
		// enum-value-removed
		{"enum", ChangeEnumValueRemoved, "spec.mode", invalid(`spec.mode: Unsupported value: "Old": supported values: "New"`), patternUnsupportedValue, nil, ""},
		{"enum required", ChangeEnumValueRemoved, "spec.mode", invalid(`spec.mode: Required value`), "", nil, "does not read as enum-value-removed"},
		// validation-tightened
		{"tightened", ChangeValidationTightened, "spec.n", invalid(`spec.n: Invalid value: 9: spec.n in body should be less than or equal to 3`), patternInvalidValue, nil, ""},
		{"tightened CEL", ChangeValidationTightened, "spec.x", invalid(`spec.x: Invalid value: "string": must not be empty`), patternInvalidValue, nil, ""},
		{"tightened too long", ChangeValidationTightened, "spec.name", invalid(`spec.name: Too long: may not be more than 8 bytes`), patternTooLong, nil, ""},
		{"tightened too many", ChangeValidationTightened, "spec.items", invalid(`spec.items: Too many: 4: must have at most 3 items`), patternTooMany, nil, ""},
		{"tightened type error", ChangeValidationTightened, "spec.size", invalid(typeCause("spec.size")), "", nil, "looks like field-type-changed"},
		{"tightened required", ChangeValidationTightened, "spec.n", invalid(`spec.n: Required value`), "", nil, "does not read as validation-tightened"},
		// several causes
		{"one match and a sibling", ChangeRequiredAdded, "spec.a", invalid(`spec.b: Invalid value: "x": bad`, `spec.a: Required value`), patternRequiredValue, []string{`spec.b: Invalid value: "x": bad`}, ""},
		{"match and mismatch on the path", ChangeValidationTightened, "spec.a", invalid(`spec.a: Too long: may not be more than 8 bytes`, typeCause("spec.a")), "", nil, "looks like field-type-changed"},
		{"two matches on the path", ChangeValidationTightened, "spec.a", invalid(`spec.a: Too long: may not be more than 8 bytes`, `spec.a: Invalid value: "x": must match`), patternTooLong, nil, ""},
		{"same message on another path", ChangeRequiredAdded, "spec.a", invalid(`spec.b: Required value`), "", []string{`spec.b: Required value`}, "no cause on spec.a"},
		{"string prefix", ChangeRequiredAdded, "spec.a", invalid(`spec.ab: Required value`), "", []string{`spec.ab: Required value`}, "no cause on spec.a"},
		{"string prefix reversed", ChangeRequiredAdded, "spec.ab", invalid(`spec.a: Required value`), "", []string{`spec.a: Required value`}, "no cause on spec.ab"},
		{"descendant", ChangeRequiredAdded, "spec.a", invalid(`spec.a.b: Required value`), "", []string{`spec.a.b: Required value`}, "the descendant spec.a.b is refused"},
		{"ancestor", ChangeRequiredAdded, "spec.a.b", invalid(`spec.a: Required value`), "", []string{`spec.a: Required value`}, "the ancestor spec.a is refused"},
		{"array path", ChangeEnumValueRemoved, "spec.ports[0].name", invalid(`spec.ports[0].name: Unsupported value: "x": supported values: "y"`, `spec.ports[1].name: Required value`), patternUnsupportedValue, []string{`spec.ports[1].name: Required value`}, ""},
		{"array other element", ChangeEnumValueRemoved, "spec.ports[0].name", invalid(`spec.ports[10].name: Unsupported value: "x": supported values: "y"`), "", []string{`spec.ports[10].name: Unsupported value: "x": supported values: "y"`}, "no cause on spec.ports[0].name"},
		// Array indexes in both spellings: kube-openapi schema causes write
		// spec.ports.0.name, strict decoding and CEL spec.ports[0].name.
		{"kube-openapi index, bracket path", ChangeEnumValueRemoved, "spec.ports[0].name", invalid(`spec.ports.0.name: Unsupported value: "x": supported values: "y"`), patternUnsupportedValue, nil, ""},
		{"bracket index, dotted path", ChangeRequiredAdded, "spec.ports.0.name", invalid(`spec.ports[0].name: Required value`), patternRequiredValue, nil, ""},
		{"kube-openapi type error in nested arrays", ChangeTypeChanged, "spec.matrix[0][0].cell", invalid(typeCause("spec.matrix.0.0.cell")), patternTypeInvalid, nil, ""},
		{"kube-openapi other index", ChangeEnumValueRemoved, "spec.ports[0].name", invalid(`spec.ports.1.name: Unsupported value: "x": supported values: "y"`), "", []string{`spec.ports.1.name: Unsupported value: "x": supported values: "y"`}, "no cause on spec.ports[0].name"},
		{"kube-openapi index prefix", ChangeEnumValueRemoved, "spec.ports[1].name", invalid(`spec.ports.10.name: Unsupported value: "x": supported values: "y"`), "", []string{`spec.ports.10.name: Unsupported value: "x": supported values: "y"`}, "no cause on spec.ports[1].name"},
		{"kube-openapi field suffix", ChangeRequiredAdded, "spec.ports[0].name", invalid(`spec.ports.0.namex: Required value`), "", []string{`spec.ports.0.namex: Required value`}, "no cause on spec.ports[0].name"},
		{"kube-openapi ancestor element", ChangeValidationTightened, "spec.ports[0].name", invalid(`spec.ports.0: Invalid value: "object": rule failed`), "", []string{`spec.ports.0: Invalid value: "object": rule failed`}, "the ancestor spec.ports.0 is refused"},
		{"kube-openapi descendant", ChangeValidationTightened, "spec.ports[0]", invalid(`spec.ports.0.name: Too long: may not be more than 3 bytes`), "", []string{`spec.ports.0.name: Too long: may not be more than 3 bytes`}, "the descendant spec.ports.0.name is refused"},
		{"strict index in dotted spelling", ChangeFieldRemoved, "spec.ports[0].legacy", strictHead + `unknown field "spec.ports.0.legacy"`, patternUnknownField, nil, ""},
		{"map value", ChangeEnumValueRemoved, "spec.labels.team", invalid(`spec.labels.team: Unsupported value: "b": supported values: "a"`), patternUnsupportedValue, nil, ""},
		{"map value, CEL spelling", ChangeValidationTightened, "spec.labels.team", invalid(`spec.labels[team]: Invalid value: "string": must not be empty`), patternInvalidValue, nil, ""},
		{"map other key, CEL spelling", ChangeValidationTightened, "spec.labels.team", invalid(`spec.labels[teams]: Invalid value: "string": must not be empty`), "", []string{`spec.labels[teams]: Invalid value: "string": must not be empty`}, "no cause on spec.labels.team"},
		{"map other key", ChangeEnumValueRemoved, "spec.labels.team", invalid(`spec.labels.teams: Unsupported value: "b": supported values: "a"`), "", []string{`spec.labels.teams: Unsupported value: "b": supported values: "a"`}, "no cause on spec.labels.team"},
		// unparsed
		{"aggregate", ChangeRequiredAdded, "spec.a", invalidHead + `[spec.a: Required value, spec.b: Required value]`, "", nil, "aggregate"},
		{"no refusal", ChangeRequiredAdded, "spec.a", `Error from server (Forbidden): gadgets is forbidden`, "", nil, "no strict-decoding or schema refusal"},
		{"truncated", ChangeRequiredAdded, "spec.a", invalidHead + "\n" + strings.Repeat("* spec.a: Required value\n", 200)[:maxFieldMessage], "", nil, "truncated"},
		{"unknown change", "field-renamed", "spec.a", invalid(`spec.a: Required value`), "", nil, "unknown change"},
	}
	for _, c := range cases {
		got := matchField(c.change, c.path, c.message)
		if got.Pattern != c.pattern {
			t.Errorf("%s: pattern %q, want %q (note %q)", c.name, got.Pattern, c.pattern, got.Note)
		}
		if !reflect.DeepEqual(got.Other, c.other) {
			t.Errorf("%s: other %q, want %q", c.name, got.Other, c.other)
		}
		if c.pattern == "" && (got.Note == "" || !strings.Contains(got.Note, c.note)) {
			t.Errorf("%s: note %q, want it to contain %q", c.name, got.Note, c.note)
		}
	}
}
