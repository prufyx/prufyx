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
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// reasonConstant is one string constant of a reason type.
type reasonConstant struct {
	name, value, file string
}

// packageReasons returns every string constant of the named type declared
// anywhere in the package directory (test files excluded), in either form:
// `X Type = "..."` or `X = Type("...")`, plus every untyped string constant
// whose name starts with "Reason" or "reason". It also returns, per file, the
// identifiers the file uses.
func packageReasons(t *testing.T, dir, typeName string) ([]reasonConstant, map[string]map[string]bool) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("no files in %s", dir)
	}
	var out []reasonConstant
	uses := map[string]map[string]bool{}
	for _, file := range matches {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		used := map[string]bool{}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				used[ident.Name] = true
			}
			return true
		})
		uses[filepath.Base(file)] = used
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				typed := false
				if ident, ok := value.Type.(*ast.Ident); ok && ident.Name == typeName {
					typed = true
				}
				for index, v := range value.Values {
					if index >= len(value.Names) {
						break
					}
					name := value.Names[index].Name
					var literal *ast.BasicLit
					switch expr := v.(type) {
					case *ast.BasicLit:
						if typed || value.Type == nil && strings.HasPrefix(strings.ToLower(name), "reason") {
							literal = expr
						}
					case *ast.CallExpr:
						if fun, ok := expr.Fun.(*ast.Ident); ok && fun.Name == typeName && len(expr.Args) == 1 {
							literal, _ = expr.Args[0].(*ast.BasicLit)
						}
					}
					if literal == nil || literal.Kind != token.STRING {
						continue
					}
					text, _ := strconv.Unquote(literal.Value)
					if text != "" {
						out = append(out, reasonConstant{name: name, value: text, file: filepath.Base(file)})
					}
				}
			}
		}
	}
	return out, uses
}

// typedConstants returns the reason values of a whole package.
func typedConstants(t *testing.T, dir, typeName string) []string {
	t.Helper()
	constants, _ := packageReasons(t, dir, typeName)
	var values []string
	for _, constant := range constants {
		values = append(values, constant.value)
	}
	return values
}

// kubernetesPreparationReasons are the preparation reasons the Kubernetes
// files declare or use, wherever in the package they are declared.
func kubernetesPreparationReasons(t *testing.T) []string {
	t.Helper()
	constants, uses := packageReasons(t, filepath.Join("..", "cncfprepare"), "Reason")
	var values []string
	for _, constant := range constants {
		reached := strings.HasPrefix(constant.file, "kubernetes")
		for file, used := range uses {
			reached = reached || strings.HasPrefix(file, "kubernetes") && used[constant.name]
		}
		if reached {
			values = append(values, constant.value)
		}
	}
	return values
}

// engineReasons returns every RULE_* reason literal of the engine and every
// reason constant it declares.
func engineReasons(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join("..", "constraintengine")
	matches, _ := filepath.Glob(filepath.Join(dir, "*.go"))
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
	for _, value := range typedConstants(t, dir, "Reason") {
		set[value] = true
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
	add("preparation", kubernetesPreparationReasons(t))
	add("intake", typedConstants(t, filepath.Join("..", "intake"), "Reason"))
	add("planner", typedConstants(t, filepath.Join("..", "upgradepath"), "Reason"))
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
		case !found && (otherRouteReasons[reason] || noticeReasons[reason]):
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
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(testdata), "..", "..", "docs", "generated", "schemas", "scan-report-v1alpha1.json"))
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
	if node.Type != "" && !jsonType(value, node.Type) {
		t.Errorf("%s: %v is not of type %s", at, value, node.Type)
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

func jsonType(value any, want string) bool {
	switch want {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := number.Int64()
		return err == nil
	}
	return false
}

// conformReport checks one report against the schema.
func conformReport(t *testing.T, name string, report scanreport.Report) {
	t.Helper()
	schema := readSchema(t)
	raw := jsonOf(t, report)
	if _, err := scanreport.DecodeJSON(raw); err != nil {
		t.Fatalf("%s: strict decode: %v", name, err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	conform(t, schema, schema, value, name)
}

// TestScanJSONSchemaRichReports: reports with every optional part (gaps,
// omitted documents, notes, hop reasons, a path gap, notices, alsoAt,
// extractor, redaction) conform to the schema.
func TestScanJSONSchemaRichReports(t *testing.T) {
	knowledge := newKnowledge(t, knowledgeOptions{lines: without(allLines, "1.28"), policy: "current", unchecked: true,
		synthetic: []string{noticeRule("kubernetes.synthetic-notice.1-25-0-to-1-26-0", "1.25.0", "1.26.0", lineRange("1.25", "1.26", "1.27"), currentWindow)}})
	dir, paths := files(t, map[string]string{"a.yaml": cronjobV1beta1, "chart.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: '{{ x }}'}\n"})
	if err := os.Chmod(paths[0], 0o644); err != nil {
		t.Fatal(err)
	}
	inDir(t, dir, func() {
		rich := mustScan(t, knowledge, ".", "--now", testNow, "--from", "kubernetes=1.24.17", "--to", "kubernetes=1.30.4", "--to", "etcd=3.6.0", "--redact").Report
		if len(rich.Gaps) < 3 || len(rich.Omitted) == 0 || len(rich.Notes) == 0 || len(rich.Notices) == 0 {
			t.Fatalf("report is not rich: %+v", rich.Summary)
		}
		golden(t, "rich-unknown.json", jsonOf(t, rich))
		conformReport(t, "rich", rich)
		downgrade := mustScan(t, knowledge, "a.yaml", "--now", testNow, "--from", "kubernetes=1.30.4", "--to", "kubernetes=1.29.1").Report
		conformReport(t, "downgrade", downgrade)
	})
	constructed := scanreport.Report{
		Inventory: []scanreport.Component{{Name: "kubernetes", Component: kubernetesKey, Current: "1.24.17", CurrentSource: "flag", Target: "1.30.4", TargetSource: "file", Covered: true}},
		Paths:     []scanreport.Path{{Component: "kubernetes", From: "1.24.17", To: "1.30.4", Policy: "sequential_minor", Hops: []scanreport.Hop{{Index: 1, From: scanreport.Endpoint{Version: "1.24.17"}, To: scanreport.Endpoint{Line: "1.25"}, Status: scanreport.HopBlocked, InputDigest: "sha256:" + strings.Repeat("a", 64), Attestation: &scanreport.Attestation{Line: "1.25", Family: "f", Basis: "reviewed", Freshness: "current", ValidUntil: "2026-12-20T00:00:00Z"}, Reasons: []string{"LINE_NOT_ATTESTED"}}}}},
		Findings: []scanreport.Finding{{RuleID: "r", Component: "kubernetes", Hop: scanreport.HopRef{Index: 1, From: "1.24.17", To: "1.25"}, AlsoAt: []scanreport.HopRef{{From: "1.24.17", To: "1.30.4", WholeUpgrade: true}}, Title: "t", Fix: "f", Match: "range", Basis: "mechanical", Extractor: "x@1",
			Locations: []scanreport.Location{{File: "a", Document: 0, Item: 2, Line: 3, Kind: "CronJob", Namespace: "n", Name: "c"}}, Citations: []constraintengine.SourceEvidence{{ID: "s", URL: "u", Revision: "r", ContentDigest: "d", StartLine: 1, EndLine: 2}}, RuleDigest: "d"}},
		Notices:    []scanreport.Notice{{RuleID: "n", Component: "kubernetes", Hop: scanreport.HopRef{Index: 1, From: "1.24.17", To: "1.25"}, AlsoAt: []scanreport.HopRef{{Index: 2, From: "1.25", To: "1.26"}}, Established: false, Reason: "RULE_EVIDENCE_STALE", Text: "x", Basis: "reviewed", Citations: []constraintengine.SourceEvidence{}}},
		Provenance: scanreport.Provenance{EvaluatedAt: testNow, InputDigest: "i", ConfigDigest: "c", KnowledgeOrigin: "embedded", KnowledgeRevision: "r", KnowledgeDigest: "k", EngineContractDigest: "e", Build: testBuild},
	}
	scanreport.Finalize(&constructed)
	conformReport(t, "constructed", constructed)
}

// TestScanSchemaRequiredFields: every report field that is always present
// in JSON (no omitempty) is required by the schema, and every optional one
// is not.
func TestScanSchemaRequiredFields(t *testing.T) {
	schema := readSchema(t)
	types := map[string]reflect.Type{
		"": reflect.TypeOf(scanreport.Report{}), "summary": reflect.TypeOf(scanreport.Summary{}), "component": reflect.TypeOf(scanreport.Component{}),
		"path": reflect.TypeOf(scanreport.Path{}), "hop": reflect.TypeOf(scanreport.Hop{}), "attestation": reflect.TypeOf(scanreport.Attestation{}),
		"hopRef": reflect.TypeOf(scanreport.HopRef{}), "location": reflect.TypeOf(scanreport.Location{}), "finding": reflect.TypeOf(scanreport.Finding{}),
		"gap": reflect.TypeOf(scanreport.Gap{}), "pass": reflect.TypeOf(scanreport.Pass{}), "notice": reflect.TypeOf(scanreport.Notice{}),
		"omitted": reflect.TypeOf(scanreport.Omitted{}), "provenance": reflect.TypeOf(scanreport.Provenance{}), "endpoint": reflect.TypeOf(scanreport.Endpoint{}),
		"citation": reflect.TypeOf(constraintengine.SourceEvidence{}), "build": reflect.TypeOf(testBuild),
	}
	for name, typ := range types {
		node := schema
		if name != "" {
			node = schema.Defs[name]
		}
		if node == nil {
			t.Fatalf("schema has no definition %s", name)
		}
		required := map[string]bool{}
		for _, field := range node.Required {
			required[field] = true
		}
		for index := 0; index < typ.NumField(); index++ {
			tag := typ.Field(index).Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			field, options, _ := strings.Cut(tag, ",")
			if _, known := node.Properties[field]; !known {
				t.Errorf("%s.%s is not in the schema", name, field)
			}
			if required[field] == strings.Contains(options, "omitempty") {
				t.Errorf("%s.%s: required %t, omitempty %t", name, field, required[field], strings.Contains(options, "omitempty"))
			}
		}
		if len(node.Properties) != typ.NumField() {
			t.Errorf("%s: schema has %d properties, type %d fields", name, len(node.Properties), typ.NumField())
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
