// SPDX-License-Identifier: AGPL-3.0-only

package projectprepare

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
)

func TestPrepareArgoWorkflowsServerWorkload(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
		want bool
	}{
		{"legacy-separated", `"server","--basehref","/private"`, true},
		{"legacy-inline", `"server","--basehref=/private"`, true},
		{"target-separated", `"server","--base-href","/private"`, false},
		{"target-inline", `"server","--base-href=/private"`, false},
		{"default", `"server"`, false},
		{"unrelated-inline", `"server","--auth-mode=server","--secure=false"`, false},
		{"legacy-with-unrelated-inline", `"server","--auth-mode=server","--basehref=/private"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := argoWorkflowsDeployment(tc.args, `"env":[]`)
			prepared, err := PrepareWorkload(ArgoWorkflowsProject, raw, ArgoWorkflowsFrom, ArgoWorkflowsTo, true)
			if err != nil || prepared.State != "PREPARED" {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			assertCanonicalFact(t, prepared.CanonicalInputJSON, ArgoWorkflowsFact, boolPointer(tc.want))
			if bytes.Contains(prepared.CanonicalInputJSON, []byte("private")) || bytes.Contains(prepared.CanonicalInputJSON, []byte("workflows-private")) {
				t.Fatal("raw workload content leaked")
			}
		})
	}
}

func TestPrepareArgoWorkflowsReviewedImageEntrypointDefault(t *testing.T) {
	raw := bytes.Replace(argoWorkflowsDeployment(`"server","--secure=false"`, `"env":[]`), []byte(`"command":["argo"],`), nil, 1)
	prepared, err := PrepareWorkload(ArgoWorkflowsProject, raw, ArgoWorkflowsFrom, ArgoWorkflowsTo, true)
	if err != nil || prepared.State != "PREPARED" {
		t.Fatalf("state=%q err=%v", prepared.State, err)
	}
	assertCanonicalFact(t, prepared.CanonicalInputJSON, ArgoWorkflowsFact, boolPointer(false))
	if !slices.Contains(prepared.Omissions, "COMMAND_DEFAULT_DERIVED_FROM_REVIEWED_IMAGE_ENTRYPOINT_SOURCE") {
		t.Fatalf("source-derived command was not disclosed: %v", prepared.Omissions)
	}

	explicit, err := PrepareWorkload(ArgoWorkflowsProject, argoWorkflowsDeployment(`"server"`, `"env":[]`), ArgoWorkflowsFrom, ArgoWorkflowsTo, true)
	if err != nil || slices.Contains(explicit.Omissions, "COMMAND_DEFAULT_DERIVED_FROM_REVIEWED_IMAGE_ENTRYPOINT_SOURCE") {
		t.Fatalf("explicit command mislabeled: err=%v omissions=%v", err, explicit.Omissions)
	}
}

func TestPrepareArgoWorkflowsLatestFiveOrigins(t *testing.T) {
	for _, from := range argoWorkflowsLatestOrigins {
		for _, tc := range []struct {
			name, args string
			want       bool
		}{
			{"legacy", `"server","--basehref=/private"`, true},
			{"target", `"server","--base-href=/private"`, false},
			{"absent", `"server"`, false},
		} {
			t.Run(from+"/"+tc.name, func(t *testing.T) {
				raw := []byte(fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"workflows-private"},"spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v4.1.3","command":["argo"],"args":[%s],"env":[]}]}}}}`, tc.args))
				prepared, err := PrepareWorkload(ArgoWorkflowsProject, raw, from, ArgoWorkflowsLatestTo, true)
				if err != nil || prepared.State != "PREPARED" {
					t.Fatalf("state=%q err=%v", prepared.State, err)
				}
				assertCanonicalFact(t, prepared.CanonicalInputJSON, ArgoWorkflowsFact, boolPointer(tc.want))
				if bytes.Contains(prepared.CanonicalInputJSON, []byte("private")) {
					t.Fatal("private argv leaked")
				}
			})
		}
	}
	wrongImage := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v4.1.2","command":["argo"],"args":["server"]}]}}}}`)
	prepared, err := PrepareWorkload(ArgoWorkflowsProject, wrongImage, "4.0.11", ArgoWorkflowsLatestTo, true)
	if err != nil || prepared.State != "UNKNOWN" {
		t.Fatalf("wrong target image state=%q err=%v", prepared.State, err)
	}
}

func TestPrepareArgoWorkflowsUnsupportedContextStaysUnknown(t *testing.T) {
	for _, tc := range []struct {
		name, args, command, image, environment string
	}{
		{"unknown-option", `"server","--auth-mode","client"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"unknown-empty-name", `"server","--=private"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"unknown-triple-dash", `"server","---=private"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"unknown-inline-file", `"server","--auth-mode=@private"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"legacy-inline-file", `"server","--basehref=@private"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"target-inline-file", `"server","--base-href=@private"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"delimiter", `"server","--"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"file-expansion", `"server","@private-args"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"value-expansion", `"server","--base-href","$(PRIVATE_PATH)"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
		{"wrapper", `"-c","argo server"`, `"/bin/sh"`, argoWorkflowsImage, `"env":[]`},
		{"custom-image", `"server"`, `"argo"`, "private.invalid/argo:v3.6.0", `"env":[]`},
		{"environment", `"server"`, `"argo"`, argoWorkflowsImage, `"env":[{"name":"PRIVATE","value":"secret"}]`},
		{"env-from", `"server"`, `"argo"`, argoWorkflowsImage, `"envFrom":[{"secretRef":{"name":"private"}}]`},
		{"environment-case-variant", `"server"`, `"argo"`, argoWorkflowsImage, `"Env":[]`},
		{"env-from-case-variant", `"server"`, `"argo"`, argoWorkflowsImage, `"envfrom":[]`},
		{"duplicate-target", `"server","--base-href=/one","--base-href=/two"`, `"argo"`, argoWorkflowsImage, `"env":[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"workflows-private"},"spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":%q,"command":[%s],"args":[%s],%s}]}}}}`, tc.image, tc.command, tc.args, tc.environment))
			prepared, err := PrepareWorkload(ArgoWorkflowsProject, raw, ArgoWorkflowsFrom, ArgoWorkflowsTo, true)
			if err != nil || prepared.State != "UNKNOWN" {
				t.Fatalf("state=%q err=%v", prepared.State, err)
			}
			assertCanonicalFact(t, prepared.CanonicalInputJSON, ArgoWorkflowsFact, nil)
		})
	}
}

func TestPrepareArgoWorkflowsAdmissionAndCompleteness(t *testing.T) {
	raw := argoWorkflowsDeployment(`"server"`, `"env":[]`)
	incomplete, err := PrepareWorkload(ArgoWorkflowsProject, raw, ArgoWorkflowsFrom, ArgoWorkflowsTo, false)
	if err != nil || incomplete.State != "UNKNOWN" {
		t.Fatalf("incomplete state=%q err=%v", incomplete.State, err)
	}
	for _, unsupported := range [][]byte{
		[]byte(`{"apiVersion":"apps/v1","kind":"StatefulSet","spec":{}}`),
		[]byte(`{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"sidecar"}]}}}}`),
		[]byte(`{"apiVersion":"apps/v1","kind":"Deployment","spec":{"template":{"spec":{"containers":[{"name":"argo-server","image":"quay.io/argoproj/argocli:v3.6.0","command":["argo"],"args":["server"]},{"name":"argo-server"}]}}}}`),
	} {
		prepared, err := PrepareWorkload(ArgoWorkflowsProject, unsupported, ArgoWorkflowsFrom, ArgoWorkflowsTo, true)
		if err != nil || prepared.State != "UNKNOWN" {
			t.Fatalf("unsupported state=%q err=%v", prepared.State, err)
		}
	}
	if _, err := PrepareWorkload(ArgoWorkflowsProject, []byte(`{"apiVersion":"apps/v1","apiVersion":"apps/v1"}`), ArgoWorkflowsFrom, ArgoWorkflowsTo, true); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
	if _, err := PrepareWorkload(ArgoWorkflowsProject, []byte(`{"apiVersion":`), ArgoWorkflowsFrom, ArgoWorkflowsTo, true); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	if _, err := PrepareWorkload("argo-cd", raw, ArgoWorkflowsFrom, ArgoWorkflowsTo, true); err == nil {
		t.Fatal("wrong project identity accepted")
	}
}

func argoWorkflowsDeployment(args, environment string) []byte {
	return []byte(fmt.Sprintf(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"workflows-private"},"spec":{"template":{"spec":{"containers":[{"name":"metrics","image":"private.invalid/sidecar"},{"name":"argo-server","image":"%s","command":["argo"],"args":[%s],%s}]}}}}`, argoWorkflowsImage, args, environment))
}
