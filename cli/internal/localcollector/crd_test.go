// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import "testing"

func validCRDPage() any {
	return map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinitionList", "metadata": map[string]any{"resourceVersion": "1", "continue": ""}, "items": []any{map[string]any{"spec": map[string]any{"group": "example.io", "names": map[string]any{"kind": "Example", "plural": "examples"}, "scope": "Namespaced", "versions": []any{map[string]any{"name": "v1", "served": true, "storage": true}}}}}}
}

func TestProjectCRDPage(t *testing.T) {
	page, err := projectCRDPage(validCRDPage(), 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || at(page.Items[0], "group") != "example.io" || at(page.Items[0], "versions") == nil {
		t.Fatalf("page=%#v", page)
	}
}

func TestProjectCRDPageRejectsDuplicateIdentity(t *testing.T) {
	root := validCRDPage()
	items := at(root, "items").([]any)
	root.(map[string]any)["items"] = append(items, items[0])
	if _, err := projectCRDPage(root, 50); err == nil {
		t.Fatal("duplicate CRD identity accepted")
	}
}

func TestMergeCRDPagesRejectsCrossPageDuplicate(t *testing.T) {
	page, _ := projectCRDPage(validCRDPage(), 50)
	if _, err := mergeCRDPages(append(page.Items, page.Items...)); err == nil {
		t.Fatal("cross-page duplicate accepted")
	}
}
