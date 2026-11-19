package intake

import (
	"reflect"
	"testing"
)

const descCRDHead = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: poolers.postgresql.cnpg.io}\nspec:\n  group: postgresql.cnpg.io\n  versions:\n  - name: v1\n    schema:\n      openAPIV3Schema:\n        type: object\n        properties:\n"

// Documentation text in a CRD schema description may hold literal braces;
// no other place does.
func TestDecodeCRDDescriptionTemplates(t *testing.T) {
	doc := []string{"doc 0/-1 apiextensions.k8s.io/v1 CustomResourceDefinition /poolers.postgresql.cnpg.io"}
	omit := []string{"omit 0/-1 TEMPLATED"}
	const ex = "Example: {{ .Values.x }} and {{ range .items }}"
	cases := map[string]struct {
		in   string
		want []string
	}{
		"top description":                {descCRDHead + "          spec:\n            type: object\n            description: \"" + ex + "\"\n", doc},
		"nested description":             {descCRDHead + "          spec:\n            type: object\n            properties:\n              a:\n                type: array\n                items:\n                  description: '{{ x }}'\n", doc},
		"property named description":     {descCRDHead + "          description:\n            type: string\n            description: '{{ x }}'\n", doc},
		"v1beta1 validation":             {"apiVersion: apiextensions.k8s.io/v1beta1\nkind: CustomResourceDefinition\nmetadata: {name: a.b}\nspec:\n  validation:\n    openAPIV3Schema:\n      description: '{{ x }}'\n", []string{"doc 0/-1 apiextensions.k8s.io/v1beta1 CustomResourceDefinition /a.b"}},
		"default templated":              {descCRDHead + "          spec:\n            type: string\n            default: '{{ .Values.x }}'\n", omit},
		"pattern templated":              {descCRDHead + "          spec:\n            type: string\n            pattern: '{{ x }}'\n", omit},
		"enum templated":                 {descCRDHead + "          spec:\n            enum: ['{{ x }}']\n", omit},
		"example templated":              {descCRDHead + "          spec:\n            example: '{{ x }}'\n", omit},
		"description key inside default": {descCRDHead + "          spec:\n            default: {description: '{{ x }}'}\n", omit},
		"templated property name":        {descCRDHead + "          '{{ x }}':\n            type: string\n", omit},
		"templated key":                  {descCRDHead + "          spec:\n            '{{ x }}': 1\n", omit},
		"description not string":         {descCRDHead + "          spec:\n            description: {a: '{{ x }}'}\n", omit},
		"templated crd name":             {"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: '{{ x }}'}\nspec: {}\n", omit},
		"description outside schema":     {"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: a.b, annotations: {description: '{{ x }}'}}\nspec: {}\n", omit},
		"spec description":               {"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: a.b}\nspec:\n  description: '{{ x }}'\n", omit},
		"conversion templated":           {descCRDHead + "          a: {type: string}\n  conversion: {strategy: '{{ x }}'}\n", omit},
		"other kind description":         {"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: a}\nspec:\n  versions:\n  - schema:\n      openAPIV3Schema:\n        description: '{{ x }}'\n", omit},
		"other group":                    {"apiVersion: example.com/v1\nkind: CustomResourceDefinition\nmetadata: {name: a.b}\nspec:\n  versions:\n  - schema:\n      openAPIV3Schema:\n        description: '{{ x }}'\n", omit},
	}
	// Lines of the cloudnative-pg chart CRD (Apache-2.0, cloudnative-pg/charts)
	// that QA e2e m11 reported; the text is documentation, shortened.
	cases["cloudnative-pg chart lines"] = struct {
		in   string
		want []string
	}{descCRDHead + "          podSelectorRefs:\n            description: |-\n              PodSelectorRefs resolve in pg_hba rules using the ${podselector:NAME} syntax.\n            items:\n              description: |-\n                Escape a literal ${...} as $${...}. The ${`image_root`} placeholder.\n              type: string\n            type: array\n", doc}
	for name, tc := range cases {
		w, err := Decode("t.yaml", []byte(tc.in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := summary(w); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %q want %q", name, got, tc.want)
		}
	}
}
