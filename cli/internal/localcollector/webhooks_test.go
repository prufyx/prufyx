// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"os"
	"testing"
)

func decodeFixture(t *testing.T, name string) any {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	root, err := DecodeStrict(raw)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestProjectWebhooksKubernetes135Shape(t *testing.T) {
	root := decodeFixture(t, "webhooks-k8s-1.35.json")
	got, err := project("mutating-webhooks.json", root)
	if err != nil {
		t.Fatalf("realistic 1.35 webhook configurations rejected: %v", err)
	}
	rows := got.([]any)
	if len(rows) != 2 {
		t.Fatalf("rows=%d", len(rows))
	}
	var withHooks, empty int
	for _, row := range rows {
		hooks := at(row, "webhooks").([]any)
		if len(hooks) == 0 {
			empty++
			continue
		}
		withHooks++
		hook := hooks[0]
		if at(hook, "clientType") != "service" || at(hook, "failurePolicy") != "Fail" {
			t.Fatalf("hook=%v", hook)
		}
		for _, leaked := range []string{"matchConditions", "namespaceSelector", "caBundle", "name", "reinvocationPolicy"} {
			if _, ok := hook.(map[string]any)[leaked]; ok {
				t.Fatalf("unknown field %q leaked through the allow-list", leaked)
			}
		}
	}
	if withHooks != 1 || empty != 1 {
		t.Fatalf("withHooks=%d empty=%d", withHooks, empty)
	}
}

func TestProjectWebhooksStillFailClosed(t *testing.T) {
	cases := map[string]string{
		"hooks not array":   `{"items":[{"kind":"ValidatingWebhookConfiguration","webhooks":"x"}]}`,
		"rule not array":    `{"items":[{"kind":"ValidatingWebhookConfiguration","webhooks":[{"rules":[{"apiGroups":"x"}]}]}]}`,
		"wrong kind":        `{"items":[{"kind":"Secret","webhooks":[]}]}`,
		"hook not object":   `{"items":[{"kind":"ValidatingWebhookConfiguration","webhooks":["x"]}]}`,
		"items not a array": `{"items":{}}`,
	}
	for name, body := range cases {
		root, err := DecodeStrict([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := project("validating-webhooks.json", root); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
