// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	widgetFrom = CRDRelease{Tag: "v3.0.0", Commit: strings.Repeat("c", 40), Files: []string{"crds/widgets.yaml"}}
	widgetTo   = CRDRelease{Tag: "v4.0.0", Commit: strings.Repeat("d", 40), Files: []string{"crds/widgets.yaml"}}
)

// widgetRelease is a Widget definition whose spec has the given properties
// (YAML, indented for the spec's properties block) and required list.
func widgetRelease(release, props, required string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.fixture.example
  annotations:
    fixture/release: %s
spec:
  group: fixture.example
  scope: Namespaced
  names:
    kind: Widget
    plural: widgets
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            required: [%s]
            properties:
%s
`, release, required, props))
}

// fieldCluster holds the definitions applied to it as decoded objects and
// answers dry-run creates through answer, by the release whose definition is
// installed. lag makes the in-place answer the From one.
type fieldCluster struct {
	crds          map[string]map[string]any
	answer        func(release string, obj map[string]any) (string, int)
	refuseInPlace bool
	lag           bool
	inPlace       bool
	sent          []map[string]any
	strict        bool
}

func (f *fieldCluster) release() string {
	for _, c := range f.crds {
		meta, _ := c["metadata"].(map[string]any)
		ann, _ := meta["annotations"].(map[string]any)
		r, _ := ann["fixture/release"].(string)
		return r
	}
	return ""
}

func (f *fieldCluster) runner(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
	rest := args[2:]
	switch rest[0] {
	case "apply":
		if f.refuseInPlace && len(f.crds) > 0 {
			return nil, []byte(`The CustomResourceDefinition "widgets.fixture.example" is invalid: status.storedVersions[0]: Invalid value: "v1beta1": must appear in spec.versions`), 1
		}
		f.inPlace = len(f.crds) > 0
		dec := yaml.NewDecoder(strings.NewReader(string(stdin)))
		for {
			var obj map[string]any
			if err := dec.Decode(&obj); err != nil {
				break
			}
			if obj == nil {
				continue
			}
			meta, _ := obj["metadata"].(map[string]any)
			f.crds[meta["name"].(string)] = obj
		}
		return nil, nil, 0
	case "wait":
		return nil, nil, 0
	case "delete":
		for _, n := range rest[5:] {
			delete(f.crds, n)
		}
		f.inPlace = false
		return nil, nil, 0
	case "get":
		var items []any
		for _, n := range rest[4:] {
			c, ok := f.crds[n]
			if !ok {
				return nil, []byte("Error from server (NotFound): customresourcedefinitions.apiextensions.k8s.io \"" + n + "\" not found"), 1
			}
			items = append(items, c)
		}
		// One name: the object itself (getCRDs reads both forms).
		out, _ := json.Marshal(map[string]any{"kind": "List", "items": items})
		if len(items) == 1 {
			out, _ = json.Marshal(items[0])
		}
		return out, nil, 0
	case "create":
		var obj map[string]any
		if err := json.Unmarshal(stdin, &obj); err != nil {
			// A probe object (YAML) of the pair's version check.
			return nil, nil, 0
		}
		f.strict = f.strict || strings.Join(rest, " ") == "create --dry-run=server --validate=strict -f -"
		f.sent = append(f.sent, obj)
		release := f.release()
		if f.lag && f.inPlace {
			release = widgetFrom.Tag
		}
		msg, exit := f.answer(release, obj)
		return nil, []byte(msg), exit
	}
	return nil, []byte("unexpected kubectl " + strings.Join(rest, " ")), 1
}

func fieldClaim(id, path, change string, value any) Claim {
	c := Claim{ID: id, Kind: KindCRDField, Subject: Subject{Project: "fixture", Repo: "github.com/fixture/fixture", From: rawObject(widgetFrom), To: rawObject(widgetTo), CRD: "widgets.fixture.example", Group: "fixture.example", Version: "v1", Kind: "Widget", Path: path, Change: change}}
	if value != nil {
		c.Subject.Value = rawObject(value)
	}
	return c
}

// fieldCase runs one claim on a fake cluster and evaluates it.
type fieldCase struct {
	fromProps, toProps       string
	fromRequired, toRequired string
	claim                    Claim
	// to answers the object at To (From accepts unless from is set).
	to   func(obj map[string]any) (string, int)
	from func(obj map[string]any) (string, int)
}

func (tc fieldCase) run(t *testing.T, cluster *fieldCluster) (CRDFieldResult, ClaimResult, Results) {
	t.Helper()
	claims := Claims{Schema: ClaimsSchema, Claims: []Claim{tc.claim}}
	if err := claims.Validate(); err != nil {
		t.Fatal(err)
	}
	fetch := func(ctx context.Context, repo, commit, path string) ([]byte, error) {
		if commit == widgetFrom.Commit {
			return widgetRelease(widgetFrom.Tag, tc.fromProps, tc.fromRequired), nil
		}
		return widgetRelease(widgetTo.Tag, tc.toProps, tc.toRequired), nil
	}
	cluster.crds = map[string]map[string]any{}
	cluster.answer = func(release string, obj map[string]any) (string, int) {
		if release == widgetFrom.Tag {
			if tc.from != nil {
				return tc.from(obj)
			}
			return "", 0
		}
		return tc.to(obj)
	}
	pairs := claims.Pairs()
	if len(pairs) != 1 || len(pairs[0].Fields) != 1 {
		t.Fatalf("pairs %+v", pairs)
	}
	res, fields := runPairFields(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, pairs[0])
	if len(cluster.crds) != 0 {
		t.Fatalf("definitions left in the cluster: %v", cluster.crds)
	}
	if len(fields) != 1 {
		t.Fatalf("fields %+v", fields)
	}
	runs := Runs{Snapshots: map[string]Snapshot{}, CRD: []CRDRun{{Schema: CRDRunSchema, Line: "1.37", Image: "img@sha256:crd", ObservedImageDigests: []string{"img@sha256:crd"}, Pairs: []CRDPairResult{res}, Fields: fields}}}
	out := Evaluate(claims, runs, Provenance{}, time.Unix(0, 0))
	ev := newEvaluator(runs, Provenance{}, &Results{}, claims.Claims)
	return fields[0], ev.evaluate(tc.claim), out
}

func accept(map[string]any) (string, int) { return "", 0 }

func refuse(msg string) func(map[string]any) (string, int) {
	return func(map[string]any) (string, int) { return msg, 1 }
}

const (
	sizeInt     = "              size: {type: integer}\n"
	sizeString  = "              size: {type: string}\n"
	modeAB      = "              mode: {type: string, enum: [a, b]}\n"
	modeA       = "              mode: {type: string, enum: [a]}\n"
	nameFree    = "              name: {type: string}\n"
	nameShort   = "              name: {type: string, maxLength: 3}\n"
	legacy      = "              legacy: {type: string}\n"
	ownerString = "              owner: {type: string}\n"
)

func widgetInvalid(cause string) string { return `The Widget "kindval-field" is invalid: ` + cause }

// One confirmed and one refuted case per change type.
func TestFieldClaimsPerChange(t *testing.T) {
	cases := map[string]struct {
		tc      fieldCase
		outcome string
		pattern string
	}{
		"removed confirmed": {fieldCase{fromProps: legacy + nameFree, toProps: nameFree, claim: fieldClaim("c", "spec.legacy", ChangeFieldRemoved, nil),
			to: refuse(`Error from server (BadRequest): error when creating "STDIN": Widget in version "v1" cannot be handled as a Widget: strict decoding error: unknown field "spec.legacy"`)}, OutcomeConfirmed, "unknown-field"},
		"removed refuted": {fieldCase{fromProps: legacy, toProps: legacy, claim: fieldClaim("c", "spec.legacy", ChangeFieldRemoved, nil), to: accept}, OutcomeRefuted, ""},
		"required confirmed": {fieldCase{fromProps: ownerString + nameFree, toProps: ownerString + nameFree, toRequired: "owner", claim: fieldClaim("c", "spec.owner", ChangeRequiredAdded, nil),
			to: refuse(widgetInvalid("spec.owner: Required value"))}, OutcomeConfirmed, "required-value"},
		"required refuted": {fieldCase{fromProps: ownerString, toProps: ownerString, claim: fieldClaim("c", "spec.owner", ChangeRequiredAdded, nil), to: accept}, OutcomeRefuted, ""},
		"type confirmed": {fieldCase{fromProps: sizeString, toProps: sizeInt, claim: fieldClaim("c", "spec.size", ChangeTypeChanged, "large"),
			to: refuse(widgetInvalid(`spec.size: Invalid value: "string": spec.size in body must be of type integer: "string"`))}, OutcomeConfirmed, "type-invalid"},
		"type refuted": {fieldCase{fromProps: sizeString, toProps: sizeString, claim: fieldClaim("c", "spec.size", ChangeTypeChanged, "large"), to: accept}, OutcomeRefuted, ""},
		"enum confirmed": {fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
			to: refuse(widgetInvalid(`spec.mode: Unsupported value: "b": supported values: "a"`))}, OutcomeConfirmed, "unsupported-value"},
		"enum refuted": {fieldCase{fromProps: modeAB, toProps: modeAB, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"), to: accept}, OutcomeRefuted, ""},
		"tightened confirmed": {fieldCase{fromProps: nameFree, toProps: nameShort, claim: fieldClaim("c", "spec.name", ChangeValidationTightened, "longer"),
			to: refuse(widgetInvalid(`spec.name: Too long: may not be more than 3 bytes`))}, OutcomeConfirmed, "too-long"},
		"tightened refuted": {fieldCase{fromProps: nameFree, toProps: nameShort, claim: fieldClaim("c", "spec.name", ChangeValidationTightened, "abc"), to: accept}, OutcomeRefuted, ""},
	}
	for name, c := range cases {
		cluster := &fieldCluster{}
		f, got, res := c.tc.run(t, cluster)
		if got.Outcome != c.outcome || f.Pattern != c.pattern {
			t.Errorf("%s: %s %s pattern %q (%s); field %+v", name, got.Outcome, got.Reason, f.Pattern, got.Detail, f)
		}
		if !cluster.strict {
			t.Errorf("%s: the object was not sent with --validate=strict", name)
		}
		if f.ObjectDigest == "" || f.FromAnswer == nil || f.FromAnswer.Outcome != ServerAccepted || f.InPlace != "applied" || f.ToInPlace == nil || f.ToAnswer == nil {
			t.Errorf("%s: record %+v", name, f)
		}
		if c.outcome == OutcomeRefuted && (got.Reason != ReasonDisagreement || res.Totals.Medium != 1) {
			t.Errorf("%s: refuted without a MEDIUM finding: %+v", name, res.Findings)
		}
	}
}

// The object sets only the path, with required siblings filled: no other
// spec member is sent.
func TestFieldObjectSetsOnlyThePath(t *testing.T) {
	cluster := &fieldCluster{}
	tc := fieldCase{fromProps: sizeString + modeAB + nameFree, toProps: sizeInt + modeAB + nameFree, fromRequired: "mode", toRequired: "mode",
		claim: fieldClaim("c", "spec.size", ChangeTypeChanged, "large"),
		to:    refuse(widgetInvalid(`spec.size: Invalid value: "string": spec.size in body must be of type integer: "string"`))}
	tc.run(t, cluster)
	got, _ := json.Marshal(cluster.sent[0])
	want := `{"apiVersion":"fixture.example/v1","kind":"Widget","metadata":{"name":"kindval-field","namespace":"default"},"spec":{"mode":"a","size":"large"}}`
	if string(got) != want {
		t.Fatalf("object %s, want %s", got, want)
	}
}

// The undetermined and error paths, each with its reason.
func TestFieldClaimsUndetermined(t *testing.T) {
	strictUnknown := `Error from server (BadRequest): error when creating "STDIN": Widget in version "v1" cannot be handled as a Widget: strict decoding error: unknown field "spec.name"`
	cases := map[string]struct {
		tc      fieldCase
		outcome string
		reason  string
	}{
		"preserve-unknown ancestor": {fieldCase{fromProps: "              blob:\n                type: object\n                x-kubernetes-preserve-unknown-fields: true\n", toProps: nameFree,
			claim: fieldClaim("c", "spec.blob.inner", ChangeFieldRemoved, nil), to: accept}, OutcomeUndetermined, ReasonSchemaPermissive},
		"path absent at From": {fieldCase{fromProps: nameFree, toProps: nameFree, claim: fieldClaim("c", "spec.legacy", ChangeFieldRemoved, nil), to: accept}, OutcomeUndetermined, ReasonPathNotInFrom},
		"enum without value":  {fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, nil), to: accept}, OutcomeUndetermined, ReasonValueMissing},
		"From refuses": {fieldCase{fromProps: modeAB, toProps: modeAB, claim: fieldClaim("c", "spec.mode", ChangeValidationTightened, "c"),
			from: refuse(widgetInvalid(`spec.mode: Unsupported value: "c": supported values: "a", "b"`)), to: accept}, OutcomeUndetermined, ReasonFromRejected},
		"To refuses on another path": {fieldCase{fromProps: modeAB + nameFree, toProps: modeA + nameShort, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
			to: refuse(widgetInvalid(`spec.name: Too long: may not be more than 3 bytes`))}, OutcomeUndetermined, ReasonOtherRejection},
		"To refuses an unknown sibling": {fieldCase{fromProps: modeAB + nameFree, toProps: modeA, fromRequired: "name", claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
			to: refuse(strictUnknown)}, OutcomeUndetermined, ReasonOtherRejection},
		"server no answer at To": {fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
			to: func(map[string]any) (string, int) {
				return "Unable to connect to the server: dial tcp 127.0.0.1:6443: connect: connection refused", 1
			}}, OutcomeError, ReasonServerNoAnswer},
		"server no answer at From": {fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
			from: func(map[string]any) (string, int) { return "exec: kubectl: not found", -1 }, to: accept}, OutcomeError, ReasonServerNoAnswer},
		"accepted by a permissive To": {fieldCase{fromProps: legacy, toProps: "              legacy:\n                type: string\n                x-kubernetes-preserve-unknown-fields: true\n",
			claim: fieldClaim("c", "spec.legacy", ChangeFieldRemoved, nil), to: accept}, OutcomeUndetermined, ReasonSchemaPermissive},
		"type change on a path To dropped": {fieldCase{fromProps: sizeString, toProps: nameFree, claim: fieldClaim("c", "spec.size", ChangeTypeChanged, "large"),
			to: refuse(`Error from server (BadRequest): error when creating "STDIN": Widget in version "v1" cannot be handled as a Widget: strict decoding error: unknown field "spec.size"`)}, OutcomeUndetermined, ReasonOtherRejection},
	}
	for name, c := range cases {
		_, got, _ := c.tc.run(t, &fieldCluster{})
		if got.Outcome != c.outcome || got.Reason != c.reason {
			t.Errorf("%s: %s %q (%s), want %s %q", name, got.Outcome, got.Reason, got.Detail, c.outcome, c.reason)
		}
	}
}

// A refused in-place update: the fresh install of To decides, and the
// detail says so.
func TestFieldInPlaceRefusedUsesFreshInstall(t *testing.T) {
	cluster := &fieldCluster{refuseInPlace: true}
	tc := fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
		to: refuse(widgetInvalid(`spec.mode: Unsupported value: "b": supported values: "a"`))}
	f, got, _ := tc.run(t, cluster)
	if got.Outcome != OutcomeConfirmed || f.InPlace != "refused" || f.ToInPlace != nil || !strings.Contains(got.Detail, "in-place update was refused") {
		t.Fatalf("%+v %+v", got, f)
	}
}

// Right after an in-place update the server may still answer with the From
// schema: the fresh install decides; an in-place refusal the fresh install
// contradicts is no evidence.
func TestFieldInPlaceLag(t *testing.T) {
	tc := fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
		to: refuse(widgetInvalid(`spec.mode: Unsupported value: "b": supported values: "a"`))}
	f, got, _ := tc.run(t, &fieldCluster{lag: true})
	if got.Outcome != OutcomeConfirmed || f.ToInPlace.Outcome != ServerAccepted || !strings.Contains(got.Detail, "in-place dry run") {
		t.Fatalf("lag: %+v %+v", got, f)
	}
	// In place refuses, fresh accepts: a contradiction, not a refutation.
	tc.to = func(map[string]any) (string, int) { return "", 0 }
	cluster := &fieldCluster{}
	tc.claim.ID = "c2"
	cluster.answer = nil
	_, got, _ = fieldCase{fromProps: tc.fromProps, toProps: tc.toProps, claim: tc.claim, to: func(obj map[string]any) (string, int) {
		if cluster.inPlace {
			return widgetInvalid(`spec.mode: Unsupported value: "b": supported values: "a"`), 1
		}
		return "", 0
	}}.run(t, cluster)
	if got.Outcome != OutcomeUndetermined || got.Reason != ReasonOtherRejection {
		t.Fatalf("contradiction: %+v", got)
	}
}

// A refusal on the path as claimed, beside causes on other paths, confirms
// and lists the others in an INFO finding.
func TestFieldOtherCausesBesideTheMatch(t *testing.T) {
	tc := fieldCase{fromProps: modeAB + nameFree, toProps: modeA + nameShort, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
		to: refuse(widgetInvalid("\n* spec.mode: Unsupported value: \"b\": supported values: \"a\"\n* spec.owner: Required value"))}
	_, got, res := tc.run(t, &fieldCluster{})
	if got.Outcome != OutcomeConfirmed {
		t.Fatalf("%+v", got)
	}
	if f, ok := hasFinding(res, "c.also"); !ok || f.Severity != SeverityInfo || !strings.Contains(f.Message, "spec.owner: Required value") {
		t.Fatalf("findings %+v", res.Findings)
	}
}

// A failed From install makes every field claim of the pair an error.
func TestFieldInstallFailureIsAnError(t *testing.T) {
	claims := Claims{Schema: ClaimsSchema, Claims: []Claim{fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b")}}
	fetch := func(ctx context.Context, repo, commit, path string) ([]byte, error) {
		return nil, fmt.Errorf("HTTP 503")
	}
	cluster := &fieldCluster{crds: map[string]map[string]any{}}
	res, fields := runPairFields(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, claims.Pairs()[0])
	runs := Runs{CRD: []CRDRun{{Schema: CRDRunSchema, Image: "img@sha256:crd", Pairs: []CRDPairResult{res}, Fields: fields}}}
	got := reasonOf(runs, claims.Claims, "c")
	if got.Outcome != OutcomeError || got.Reason != ReasonInstallFailed {
		t.Fatalf("%+v %+v", got, fields)
	}
	if r := reasonOf(Runs{}, claims.Claims, "c"); r.Outcome != OutcomeUndetermined || r.Reason != ReasonNoRun {
		t.Fatalf("no run: %+v", r)
	}
}

// Claim validation of the new kind.
func TestValidateFieldClaims(t *testing.T) {
	good := fieldClaim("c", "spec.a.b", ChangeFieldRemoved, nil)
	if err := (Claims{Schema: ClaimsSchema, Claims: []Claim{good}}).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(c *Claim){
		"change":    func(c *Claim) { c.Subject.Change = "field-renamed" },
		"no path":   func(c *Claim) { c.Subject.Path = "" },
		"metadata":  func(c *Claim) { c.Subject.Path = "metadata.labels" },
		"empty seg": func(c *Claim) { c.Subject.Path = "spec..a" },
		"index":     func(c *Claim) { c.Subject.Path = "spec.a[0].b" },
		"crd group": func(c *Claim) { c.Subject.CRD = "widgets.other.example" },
		"no to":     func(c *Claim) { c.Subject.To = nil },
		"bad value": func(c *Claim) { c.Subject.Value = json.RawMessage(`{`) },
	} {
		c := fieldClaim("c", "spec.a.b", ChangeFieldRemoved, nil)
		mutate(&c)
		if err := (Claims{Schema: ClaimsSchema, Claims: []Claim{c}}).Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// fieldResultFor fabricates the recorded run of a crd-field claim whose To
// answer is msg ("" for accepted).
func fieldResultFor(c Claim, msg, toSchema string) CRDFieldResult {
	to := ServerTry{Outcome: ServerAccepted}
	if msg != "" {
		to = fieldAnswer(1, msg)
	}
	return CRDFieldResult{ID: c.ID, Change: c.Subject.Change, ServerPath: c.Subject.Path, ObjectDigest: "sha256:x", FromAnswer: &ServerTry{Outcome: ServerAccepted}, InPlace: "applied", ToInPlace: &to, ToAnswer: &to, ToSchema: toSchema}
}

// The crd-field controls decide their group: all as expected, a claim is
// confirmed by execution; one control off, the claim is void.
func TestV2FieldControls(t *testing.T) {
	plain := fieldClaim("plain", "spec.mode", ChangeEnumValueRemoved, "b")
	claims := v2Claims(t, lines3132, plain)
	runOf := func(broken string) Runs {
		run := CRDRun{Schema: CRDRunSchema, Line: "1.32", Image: "img@sha256:crd", ObservedImageDigests: []string{"img@sha256:crd"}}
		for _, c := range claims.Claims {
			var r CRDFieldResult
			switch {
			case c.ID == plain.ID:
				r = fieldResultFor(c, widgetInvalid(`spec.mode: Unsupported value: "b": supported values: "a"`), schemaPresent)
			case c.Control == ControlFalse || c.ID == broken:
				r = fieldResultFor(c, "", schemaPresent)
			case c.Subject.Change == ChangeFieldRemoved:
				r = fieldResultFor(c, `Error from server (BadRequest): error when creating "STDIN": X in version "v1" cannot be handled as a X: strict decoding error: unknown field "`+c.Subject.Path+`"`, schemaAbsent)
			default:
				r = fieldResultFor(c, `The X "kindval-field" is invalid: `+c.Subject.Path+`: Invalid value: "string": rule failed`, schemaPresent)
			}
			run.Fields = append(run.Fields, r)
		}
		return Runs{Snapshots: map[string]Snapshot{}, CRD: []CRDRun{run}}
	}
	res := Evaluate(claims, runOf(""), Provenance{}, time.Unix(0, 0))
	checkReasons(t, "field pass", res)
	if c := outcomes(res)["plain"]; c.Verdict != VerdictConfirmed {
		t.Fatalf("plain %+v controls %+v", c, res.Controls)
	}
	if s, _ := summaryOf(res, KindCRDField, ""); s.State != ControlStateOK || s.True < 2 || s.False < 2 {
		t.Fatalf("summary %+v", s)
	}
	var trueID string
	for _, c := range claims.Claims {
		if c.Control == ControlTrue {
			trueID = c.ID
		}
	}
	res = Evaluate(claims, runOf(trueID), Provenance{}, time.Unix(0, 0))
	if c := outcomes(res)["plain"]; c.Reason != ReasonCanaryFailed || c.Verdict != VerdictError {
		t.Fatalf("void %+v", c)
	}
}

// A map key reached through additionalProperties: a changed value schema
// confirms; a To that preserves unknown values there is permissive, never
// refuted.
func TestFieldMapKeys(t *testing.T) {
	labels := func(values string) string {
		return "              labels:\n                type: object\n                additionalProperties: {type: string, enum: [" + values + "]}\n"
	}
	claim := fieldClaim("c", "spec.labels.team", ChangeEnumValueRemoved, "b")
	_, got, _ := fieldCase{fromProps: labels("a, b"), toProps: labels("a"), claim: claim,
		to: refuse(widgetInvalid(`spec.labels.team: Unsupported value: "b": supported values: "a"`))}.run(t, &fieldCluster{})
	if got.Outcome != OutcomeConfirmed {
		t.Fatalf("map key: %+v", got)
	}
	permissive := "              labels:\n                type: object\n                additionalProperties:\n                  x-kubernetes-preserve-unknown-fields: true\n"
	_, got, _ = fieldCase{fromProps: labels("a, b"), toProps: permissive, claim: claim, to: accept}.run(t, &fieldCluster{})
	if got.Outcome != OutcomeUndetermined || got.Reason != ReasonSchemaPermissive {
		t.Fatalf("permissive map: %+v", got)
	}
}

// A To release that no longer defines the CRD, and a server that names the
// path unknown while To's schema still has it: other-rejection, never
// confirmed and never an install failure.
func TestFieldWiderOrInconsistentChanges(t *testing.T) {
	claim := fieldClaim("c", "spec.legacy", ChangeFieldRemoved, nil)
	cluster := &fieldCluster{crds: map[string]map[string]any{}}
	cluster.answer = func(string, map[string]any) (string, int) { return "", 0 }
	fetch := func(ctx context.Context, repo, commit, path string) ([]byte, error) {
		if commit == widgetFrom.Commit {
			return widgetRelease(widgetFrom.Tag, legacy, ""), nil
		}
		return []byte(strings.ReplaceAll(string(widgetRelease(widgetTo.Tag, legacy, "")), "widgets.fixture.example", "gizmos.fixture.example")), nil
	}
	claims := Claims{Schema: ClaimsSchema, Claims: []Claim{claim}}
	res, fields := runPairFields(context.Background(), kube{run: cluster.runner, kubeconfig: "kc"}, fetch, claims.Pairs()[0])
	runs := Runs{CRD: []CRDRun{{Schema: CRDRunSchema, Image: "img@sha256:crd", Pairs: []CRDPairResult{res}, Fields: fields}}}
	if got := reasonOf(runs, claims.Claims, "c"); got.Outcome != OutcomeUndetermined || got.Reason != ReasonOtherRejection || !strings.Contains(got.Detail, "defines no widgets.fixture.example") {
		t.Fatalf("dropped CRD: %+v", got)
	}
	if len(cluster.crds) != 0 {
		t.Fatalf("definitions left: %v", cluster.crds)
	}

	_, got, _ := fieldCase{fromProps: legacy, toProps: legacy, claim: claim,
		to: refuse(`Error from server (BadRequest): error when creating "STDIN": Widget in version "v1" cannot be handled as a Widget: strict decoding error: unknown field "spec.legacy"`)}.run(t, &fieldCluster{})
	if got.Outcome != OutcomeUndetermined || got.Reason != ReasonOtherRejection {
		t.Fatalf("unknown but present: %+v", got)
	}
}

// An API server that could not handle the request gave no answer.
func TestFieldAnswerServerUnavailable(t *testing.T) {
	for msg, want := range map[string]string{
		"Error from server (ServiceUnavailable): the server is currently unable to handle the request":                                           ServerError,
		"Error from server (Timeout): the server was unable to return a response in the time allotted":                                           ServerError,
		"Error from server (TooManyRequests): the server has received too many requests":                                                         ServerError,
		"Error from server (InternalError): Internal error occurred: etcdserver: request timed out":                                              ServerError,
		`Error from server (InternalError): conversion webhook for fixture.example/v2, Kind=Widget failed: Post "https://x": connection refused`: ServerRejected,
	} {
		if got := fieldAnswer(1, msg); got.Outcome != want {
			t.Errorf("%q: %s, want %s", msg, got.Outcome, want)
		}
	}
	_, got, _ := fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
		to: refuse("Error from server (ServiceUnavailable): the server is currently unable to handle the request")}.run(t, &fieldCluster{})
	if got.Outcome != OutcomeError || got.Reason != ReasonServerNoAnswer {
		t.Fatalf("%+v", got)
	}
}

// A pair without crd-field claims makes exactly the kubectl calls it made
// before: no strict dry run, no read of a single definition, no fields.
func TestPairWithoutFieldsIsUnchanged(t *testing.T) {
	cluster := &fakeCluster{crds: map[string]CRDDef{}}
	var calls []string
	record := func(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
		calls = append(calls, strings.Join(args[2:], " "))
		return cluster.runner(ctx, name, args, stdin)
	}
	res, fields := runPairFields(context.Background(), kube{run: record, kubeconfig: "kc"}, fixtureFetcher(false), gadgetClaims(true).Pairs()[0])
	if len(fields) != 0 || res.Error != "" {
		t.Fatalf("fields %+v res %+v", fields, res)
	}
	want := []string{
		"apply --server-side --force-conflicts -f -", "wait --for=condition=Established --timeout=120s crd gadgets.fixture.example", "get -o json crd gadgets.fixture.example",
		"create --dry-run=server -f -", "create --dry-run=server -f -",
		"apply --server-side --force-conflicts -f -",
		"delete --ignore-not-found --wait=true --timeout=180s crd gadgets.fixture.example gadgets.fixture.example",
		"apply --server-side --force-conflicts -f -", "wait --for=condition=Established --timeout=120s crd gadgets.fixture.example", "get -o json crd gadgets.fixture.example",
		"create --dry-run=server -f -", "create --dry-run=server -f -",
		"delete --ignore-not-found --wait=true --timeout=180s crd gadgets.fixture.example gadgets.fixture.example",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	data, _ := json.Marshal(CRDRun{Schema: CRDRunSchema, Pairs: []CRDPairResult{res}, Fields: fields})
	if strings.Contains(string(data), `"fields"`) {
		t.Fatalf("fields member written: %s", data)
	}
}

// Accepted while the path is absent from To's schema: strict field
// validation did not decide, so this is no refutation.
func TestFieldAcceptedButAbsentAtTo(t *testing.T) {
	_, got, res := fieldCase{fromProps: legacy + nameFree, toProps: nameFree, claim: fieldClaim("c", "spec.legacy", ChangeFieldRemoved, nil), to: accept}.run(t, &fieldCluster{})
	if got.Outcome != OutcomeUndetermined || got.Reason != ReasonOtherRejection || !strings.Contains(got.Detail, "accepted although the path is absent from the schema at v4.0.0") {
		t.Fatalf("%+v", got)
	}
	if res.Totals.Medium != 0 {
		t.Fatalf("findings %+v", res.Findings)
	}
}

// A claim under an array is confirmed by the kube-openapi spelling of the
// schema cause (spec.ports.0.name) as well as the bracket one.
func TestFieldArrayPathSpellings(t *testing.T) {
	ports := func(enum string) string {
		return "              ports:\n                type: array\n                items:\n                  type: object\n                  properties:\n                    proto: {type: string, enum: [" + enum + "]}\n"
	}
	for _, field := range []string{"spec.ports.0.proto", "spec.ports[0].proto"} {
		f, got, _ := fieldCase{fromProps: ports("tcp, udp"), toProps: ports("tcp"), claim: fieldClaim("c", "spec.ports.proto", ChangeEnumValueRemoved, "udp"),
			to: refuse(widgetInvalid(field + `: Unsupported value: "udp": supported values: "tcp"`))}.run(t, &fieldCluster{})
		if got.Outcome != OutcomeConfirmed || f.ServerPath != "spec.ports[0].proto" {
			t.Fatalf("%s: %+v %+v", field, got, f)
		}
	}
	_, got, _ := fieldCase{fromProps: ports("tcp, udp"), toProps: ports("tcp"), claim: fieldClaim("c", "spec.ports.proto", ChangeEnumValueRemoved, "udp"),
		to: refuse(widgetInvalid(`spec.ports.1.proto: Unsupported value: "udp": supported values: "tcp"`))}.run(t, &fieldCluster{})
	if got.Outcome != OutcomeUndetermined || got.Reason != ReasonOtherRejection {
		t.Fatalf("other index: %+v", got)
	}
}

// An in-place dry run without an answer leaves the fresh install to decide,
// without its cross-check; a fresh install without an answer is an error.
func TestFieldInPlaceNoAnswer(t *testing.T) {
	cluster := &fieldCluster{}
	tc := fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
		to: func(map[string]any) (string, int) {
			if cluster.inPlace {
				return "Unable to connect to the server: dial tcp 127.0.0.1:6443: connect: connection refused", 1
			}
			return widgetInvalid(`spec.mode: Unsupported value: "b": supported values: "a"`), 1
		}}
	f, got, _ := tc.run(t, cluster)
	if got.Outcome != OutcomeConfirmed || f.ToInPlace.Outcome != ServerError || !strings.Contains(got.Detail, "no cross-check") {
		t.Fatalf("%+v %+v", got, f)
	}
	const noAnswer = "Unable to connect to the server: dial tcp 127.0.0.1:6443: connect: connection refused"
	cluster = &fieldCluster{}
	f, got, _ = fieldCase{fromProps: modeAB, toProps: modeA, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"),
		to: func(map[string]any) (string, int) { return noAnswer, 1 }}.run(t, cluster)
	if f.ToInPlace == nil || f.ToInPlace.Outcome != ServerError || got.Outcome != OutcomeError || got.Reason != ReasonServerNoAnswer {
		t.Fatalf("fresh has no answer: %+v %+v", got, f)
	}
}

// The other accepted-but-absent cases, and an in-place dry run without an
// answer while the fresh install accepts: the fresh install decides.
func TestFieldAcceptedButAbsentOtherChanges(t *testing.T) {
	_, got, _ := fieldCase{fromProps: ownerString + nameFree, toProps: nameFree, claim: fieldClaim("c", "spec.owner", ChangeRequiredAdded, nil), to: accept}.run(t, &fieldCluster{})
	if got.Outcome != OutcomeUndetermined || got.Reason != ReasonOtherRejection || !strings.Contains(got.Detail, "a wider change than claimed") {
		t.Fatalf("required-added: %+v", got)
	}
	_, got, _ = fieldCase{fromProps: sizeString, toProps: nameFree, claim: fieldClaim("c", "spec.size", ChangeTypeChanged, "large"), to: accept}.run(t, &fieldCluster{})
	if got.Outcome != OutcomeUndetermined || got.Reason != ReasonOtherRejection || !strings.Contains(got.Detail, "strict field validation did not decide") {
		t.Fatalf("type-changed: %+v", got)
	}
	cluster := &fieldCluster{}
	_, got, _ = fieldCase{fromProps: modeAB, toProps: modeAB, claim: fieldClaim("c", "spec.mode", ChangeEnumValueRemoved, "b"), to: func(map[string]any) (string, int) {
		if cluster.inPlace {
			return "Unable to connect to the server: dial tcp 127.0.0.1:6443: connect: connection refused", 1
		}
		return "", 0
	}}.run(t, cluster)
	if got.Outcome != OutcomeRefuted || !strings.Contains(got.Detail, "no cross-check") {
		t.Fatalf("refuted without cross-check: %+v", got)
	}
}
