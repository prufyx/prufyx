// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// typedConstants returns the string values of every constant of the named
// type declared in the files matched by pattern (test files excluded).
func typedConstants(t *testing.T, pattern, typeName string) []string {
	t.Helper()
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		t.Fatalf("no files for %s", pattern)
	}
	var values []string
	for _, file := range matches {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				ident, ok := value.Type.(*ast.Ident)
				if !ok || ident.Name != typeName {
					continue
				}
				for _, v := range value.Values {
					if literal, ok := v.(*ast.BasicLit); ok && literal.Kind == token.STRING {
						text, _ := strconv.Unquote(literal.Value)
						if text != "" {
							values = append(values, text)
						}
					}
				}
			}
		}
	}
	return values
}

// engineReasons returns every RULE_* reason literal of the engine.
func engineReasons(t *testing.T) []string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join("..", "constraintengine", "*.go"))
	pattern := regexp.MustCompile(`^RULE_[A-Z0-9_]+$`)
	set := map[string]bool{}
	for _, file := range matches {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
				if text, err := strconv.Unquote(literal.Value); err == nil && pattern.MatchString(text) {
					set[text] = true
				}
			}
			return true
		})
	}
	var out []string
	for reason := range set {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

// TestGapCatalogComplete: every reason a Kubernetes scan can meet maps to a
// gap message of the catalog, or is explicitly a decided result. Reasons are
// read from the source: the Kubernetes preparation reasons, intake omission
// reasons, planner gaps, every engine reason, and the reasons the published
// Kubernetes rules give decided claims. The catalog and the vocabulary agree.
func TestGapCatalogComplete(t *testing.T) {
	enumerated := map[string]string{}
	add := func(origin string, values []string) {
		if len(values) == 0 {
			t.Fatalf("no reasons found in %s", origin)
		}
		for _, value := range values {
			enumerated[value] = origin
		}
	}
	add("preparation", typedConstants(t, filepath.Join("..", "cncfprepare", "kubernetes*.go"), "Reason"))
	add("intake", typedConstants(t, filepath.Join("..", "intake", "manifest.go"), "Reason"))
	add("planner", typedConstants(t, filepath.Join("..", "upgradepath", "upgradepath.go"), "Reason"))
	add("engine", engineReasons(t))
	var ruleReasons []string
	for _, raw := range packRules(t) {
		var rule struct {
			Subject struct {
				Component string `json:"component"`
			} `json:"subject"`
			ReasonCode string `json:"reasonCode"`
		}
		if err := json.Unmarshal(raw, &rule); err != nil {
			t.Fatal(err)
		}
		if rule.Subject.Component == kubernetesKey {
			ruleReasons = append(ruleReasons, rule.ReasonCode)
		}
	}
	for _, reason := range ruleReasons {
		if !decidedClaimReasons[reason] {
			t.Errorf("rule reason %s is not marked as a decided claim", reason)
		}
	}
	for reason, origin := range enumerated {
		outcome, found := reasonOutcomes[reason]
		switch {
		case !found && otherRouteReasons[reason]:
		case !found:
			t.Errorf("%s reason %s has no outcome", origin, reason)
		case outcome.decided, outcome.declarations:
		case outcome.gap == "":
			if !factReasons[reason] {
				t.Errorf("%s reason %s maps to nothing", origin, reason)
			}
		case scanreport.GapArgs(outcome.gap) < 0:
			t.Errorf("%s reason %s maps to %s, which is not in the catalog", origin, reason, outcome.gap)
		}
	}
	for reason := range reasonOutcomes {
		if _, found := enumerated[reason]; !found {
			t.Errorf("outcome for %s, which no source declares", reason)
		}
		if otherRouteReasons[reason] {
			t.Errorf("%s is both handled and marked as another route's", reason)
		}
	}
	vocabulary := map[string]bool{}
	for _, reason := range scanreport.GapReasons() {
		vocabulary[reason] = false
	}
	for _, key := range scanreport.GapKeys() {
		if _, known := vocabulary[key.Reason()]; !known {
			t.Errorf("key %s has a reason outside the vocabulary", key)
		}
		vocabulary[key.Reason()] = true
	}
	for reason, used := range vocabulary {
		if !used {
			t.Errorf("reason %s has no catalog text", reason)
		}
	}
	schema := readSchema(t)
	enum := schema.Defs["gap"].Properties["reason"].Enum
	if !equalSets(enum, scanreport.GapReasons()) {
		t.Errorf("schema gap reasons %v differ from the vocabulary", enum)
	}
}

func equalSets(a, b []string) bool {
	x, y := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, ",") == strings.Join(y, ",")
}

// schemaNode is the part of JSON Schema the report schema uses.
type schemaNode struct {
	Ref                  string                 `json:"$ref"`
	Type                 string                 `json:"type"`
	Required             []string               `json:"required"`
	Properties           map[string]*schemaNode `json:"properties"`
	Items                *schemaNode            `json:"items"`
	AdditionalProperties *bool                  `json:"additionalProperties"`
	Enum                 []string               `json:"enum"`
	Const                any                    `json:"const"`
	Defs                 map[string]*schemaNode `json:"$defs"`
	MaxLength            int                    `json:"maxLength"`
}

func readSchema(t *testing.T) *schemaNode {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "generated", "schemas", "scan-report-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema schemaNode
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	return &schema
}

// conform checks value against node: required members present, no member
// outside a closed object, enums and constants, string bounds, and the
// same for every nested object and array item.
func conform(t *testing.T, root, node *schemaNode, value any, at string) {
	t.Helper()
	if node.Ref != "" {
		name := strings.TrimPrefix(node.Ref, "#/$defs/")
		def, found := root.Defs[name]
		if !found {
			t.Fatalf("%s: unknown reference %s", at, node.Ref)
		}
		node = def
	}
	if len(node.Enum) > 0 {
		text, _ := value.(string)
		found := false
		for _, allowed := range node.Enum {
			found = found || text == allowed
		}
		if !found {
			t.Errorf("%s: %v not in %v", at, value, node.Enum)
		}
	}
	if node.Const != nil && node.Const != value {
		t.Errorf("%s: %v is not %v", at, value, node.Const)
	}
	if text, ok := value.(string); ok && node.MaxLength > 0 && len(text) > node.MaxLength {
		t.Errorf("%s: longer than %d", at, node.MaxLength)
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, name := range node.Required {
			if _, found := typed[name]; !found {
				t.Errorf("%s: required member %s missing", at, name)
			}
		}
		for name, member := range typed {
			child, found := node.Properties[name]
			if !found {
				if node.AdditionalProperties != nil && !*node.AdditionalProperties {
					t.Errorf("%s: member %s is not in the schema", at, name)
				}
				continue
			}
			conform(t, root, child, member, at+"."+name)
		}
	case []any:
		if node.Items != nil {
			for index, item := range typed {
				conform(t, root, node.Items, item, at+"["+strconv.Itoa(index)+"]")
			}
		}
	}
}

// TestScanJSONSchema: every JSON golden decodes strictly into the report
// types and conforms to the published schema.
func TestScanJSONSchema(t *testing.T) {
	schema := readSchema(t)
	goldens, err := filepath.Glob(filepath.Join(testdata, "*.json"))
	if err != nil || len(goldens) < 2 {
		t.Fatalf("goldens %v %v", goldens, err)
	}
	for _, path := range goldens {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		report, err := scanreport.DecodeJSON(raw)
		if err != nil {
			t.Fatalf("%s: strict decode: %v", path, err)
		}
		again, err := scanreport.MarshalJSON(report)
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("%s: does not round-trip", path)
		}
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		conform(t, schema, schema, value, filepath.Base(path))
	}
	// A member the types do not know is refused.
	if _, err := scanreport.DecodeJSON([]byte(`{"schema":"x","unknown":1}`)); err == nil {
		t.Fatal("unknown member accepted")
	}
}
