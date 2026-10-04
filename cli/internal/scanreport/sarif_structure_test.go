// SPDX-License-Identifier: AGPL-3.0-only

package scanreport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// validateSARIF checks the subset of SARIF 2.1.0 that scan emits: required
// properties and their types, closed objects (an unknown property is an
// error, except inside a "properties" bag), consistent rule references, and
// the constraints code scanning puts on locations. It is deliberately
// stricter than the schema.
func validateSARIF(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("trailing data")
	}
	v := &sarifValidator{}
	v.object("log", root, []string{"$schema", "version", "runs"}, nil, func(log map[string]any) {
		v.equal("log.version", log["version"], "2.1.0")
		v.equal("log.$schema", log["$schema"], sarifSchema)
		runs := v.array("log.runs", log["runs"])
		if len(runs) != 1 {
			v.fail("log.runs has %d runs, want 1", len(runs))
			return
		}
		v.run(runs[0])
	})
	if len(v.errs) > 0 {
		return fmt.Errorf("%s", strings.Join(v.errs, "; "))
	}
	return nil
}

type sarifValidator struct{ errs []string }

func (v *sarifValidator) fail(format string, args ...any) {
	v.errs = append(v.errs, fmt.Sprintf(format, args...))
}

func (v *sarifValidator) object(where string, value any, required, optional []string, body func(map[string]any)) {
	object, ok := value.(map[string]any)
	if !ok {
		v.fail("%s is not an object", where)
		return
	}
	allowed := map[string]bool{}
	for _, key := range append(append([]string{}, required...), optional...) {
		allowed[key] = true
	}
	for _, key := range required {
		if _, found := object[key]; !found {
			v.fail("%s lacks %s", where, key)
		}
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !allowed[key] {
			v.fail("%s has unknown property %s", where, key)
		}
	}
	if body != nil {
		body(object)
	}
}

func (v *sarifValidator) array(where string, value any) []any {
	array, ok := value.([]any)
	if !ok {
		v.fail("%s is not an array", where)
	}
	return array
}

func (v *sarifValidator) text(where string, value any) string {
	text, ok := value.(string)
	if !ok || text == "" {
		v.fail("%s is not a non-empty string", where)
	}
	return text
}

func (v *sarifValidator) equal(where string, value, want any) {
	if value != want {
		v.fail("%s is %v, want %v", where, value, want)
	}
}

func (v *sarifValidator) integer(where string, value any, min int64) int64 {
	number, ok := value.(json.Number)
	if !ok {
		v.fail("%s is not a number", where)
		return min
	}
	n, err := number.Int64()
	if err != nil || n < min {
		v.fail("%s is %s, want an integer >= %d", where, number, min)
	}
	return n
}

func (v *sarifValidator) message(where string, value any) {
	v.object(where, value, []string{"text"}, nil, func(m map[string]any) {
		if text := v.text(where+".text", m["text"]); len(text) > 1024 {
			v.fail("%s is %d bytes, over the 1024 code scanning shows", where, len(text))
		}
	})
}

var levelSet = map[string]bool{"error": true, "warning": true, "note": true, "none": true}

func (v *sarifValidator) level(where string, value any, allowError bool) {
	level, ok := value.(string)
	if !ok || !levelSet[level] || (level == "error" && !allowError) {
		v.fail("%s has level %v", where, value)
	}
}

func (v *sarifValidator) run(value any) {
	var ruleIDs []string
	v.object("run", value, []string{"tool", "invocations", "results", "properties"}, nil, func(run map[string]any) {
		v.object("run.tool", run["tool"], []string{"driver"}, nil, func(tool map[string]any) {
			v.object("driver", tool["driver"], []string{"name", "version", "informationUri", "rules"}, nil, func(driver map[string]any) {
				v.equal("driver.name", driver["name"], "prufyx")
				v.text("driver.version", driver["version"])
				if uri := v.text("driver.informationUri", driver["informationUri"]); !strings.HasPrefix(uri, "https://") {
					v.fail("driver.informationUri %q", uri)
				}
				seen := map[string]bool{}
				for i, rule := range v.array("driver.rules", driver["rules"]) {
					where := fmt.Sprintf("rules[%d]", i)
					v.object(where, rule, []string{"id", "shortDescription", "help", "defaultConfiguration", "properties"}, []string{"helpUri"}, func(r map[string]any) {
						id := v.text(where+".id", r["id"])
						if seen[id] {
							v.fail("%s repeats rule id %s", where, id)
						}
						seen[id] = true
						ruleIDs = append(ruleIDs, id)
						if i > 0 && ruleIDs[i-1] >= id {
							v.fail("%s is out of order", where)
						}
						v.object(where+".shortDescription", r["shortDescription"], []string{"text"}, nil, func(m map[string]any) { v.text(where+".shortDescription.text", m["text"]) })
						v.object(where+".help", r["help"], []string{"text"}, nil, func(m map[string]any) { v.text(where+".help.text", m["text"]) })
						v.object(where+".defaultConfiguration", r["defaultConfiguration"], []string{"level"}, nil, func(m map[string]any) { v.level(where+".level", m["level"], true) })
						if uri, found := r["helpUri"]; found && !regexp.MustCompile(`^https://[^\s]+$`).MatchString(fmt.Sprint(uri)) {
							v.fail("%s.helpUri %v", where, uri)
						}
						v.object(where+".properties", r["properties"], []string{"basis", "kind"}, nil, nil)
					})
				}
			})
		})
		v.object("run.properties", run["properties"], []string{"verdict", "headline", "summary", "evaluatedAt", "inputDigest", "knowledgeOrigin", "knowledgeRevision", "knowledgeDigest", "engineContractDigest", "networkUsed", "omissions"}, []string{"configDigest", "trustPolicy", "knowledgeStore"}, nil)
		for i, result := range v.array("run.results", run["results"]) {
			v.result(fmt.Sprintf("results[%d]", i), result, ruleIDs)
		}
		invocations := v.array("run.invocations", run["invocations"])
		if len(invocations) != 1 {
			v.fail("%d invocations", len(invocations))
			return
		}
		v.object("invocation", invocations[0], []string{"executionSuccessful", "exitCode", "exitCodeDescription", "startTimeUtc", "toolExecutionNotifications"}, nil, func(inv map[string]any) {
			if _, ok := inv["executionSuccessful"].(bool); !ok {
				v.fail("executionSuccessful is not a boolean")
			}
			v.integer("exitCode", inv["exitCode"], 0)
			if !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`).MatchString(fmt.Sprint(inv["startTimeUtc"])) {
				v.fail("startTimeUtc %v", inv["startTimeUtc"])
			}
			for i, n := range v.array("notifications", inv["toolExecutionNotifications"]) {
				where := fmt.Sprintf("notifications[%d]", i)
				v.object(where, n, []string{"level", "message", "descriptor", "properties"}, []string{"associatedRule"}, func(note map[string]any) {
					// A notification is never an error: nothing it reports is a blocker.
					v.level(where, note["level"], false)
					v.message(where+".message", note["message"])
					v.object(where+".descriptor", note["descriptor"], []string{"id"}, nil, func(m map[string]any) { v.text(where+".descriptor.id", m["id"]) })
					if ref, found := note["associatedRule"]; found {
						v.ruleRef(where+".associatedRule", ref, ruleIDs)
					}
					v.object(where+".properties", note["properties"], []string{"kind", "component"}, []string{"hop"}, nil)
				})
			}
		})
	})
}

func (v *sarifValidator) ruleRef(where string, ref any, ruleIDs []string) {
	v.object(where, ref, []string{"id", "index"}, nil, func(m map[string]any) {
		index := v.integer(where+".index", m["index"], 0)
		if int(index) >= len(ruleIDs) || ruleIDs[index] != m["id"] {
			v.fail("%s index %d does not point at rule %v", where, index, m["id"])
		}
	})
}

var uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

func (v *sarifValidator) result(where string, value any, ruleIDs []string) {
	v.object(where, value, []string{"ruleId", "ruleIndex", "level", "message", "properties"}, []string{"locations", "partialFingerprints"}, func(r map[string]any) {
		index := v.integer(where+".ruleIndex", r["ruleIndex"], 0)
		if int(index) >= len(ruleIDs) || ruleIDs[index] != r["ruleId"] {
			v.fail("%s ruleIndex %d does not point at rule %v", where, index, r["ruleId"])
		}
		v.equal(where+".level", r["level"], "error")
		v.message(where+".message", r["message"])
		v.object(where+".properties", r["properties"], []string{"component", "hop", "basis", "match"}, nil, nil)
		for i, location := range v.arrayOrNil(where+".locations", r["locations"]) {
			lw := fmt.Sprintf("%s.locations[%d]", where, i)
			v.object(lw, location, []string{"physicalLocation"}, []string{"logicalLocations"}, func(l map[string]any) {
				v.object(lw+".physicalLocation", l["physicalLocation"], []string{"artifactLocation"}, []string{"region"}, func(p map[string]any) {
					v.object(lw+".artifactLocation", p["artifactLocation"], []string{"uri", "uriBaseId"}, nil, func(a map[string]any) {
						uri := v.text(lw+".uri", a["uri"])
						v.equal(lw+".uriBaseId", a["uriBaseId"], "%SRCROOT%")
						if strings.HasPrefix(uri, "/") || strings.Contains(uri, "\\") || uriScheme.MatchString(uri) || strings.Contains(uri, "?") || strings.Contains(uri, "#") || strings.Contains(uri, " ") {
							v.fail("%s uri %q is not a relative path reference", lw, uri)
						}
						for _, segment := range strings.Split(uri, "/") {
							if segment == ".." || segment == "." || segment == "" {
								v.fail("%s uri %q has segment %q", lw, uri, segment)
							}
						}
					})
					if region, found := p["region"]; found {
						v.object(lw+".region", region, []string{"startLine"}, nil, func(m map[string]any) { v.integer(lw+".region.startLine", m["startLine"], 1) })
					}
				})
				for _, logical := range v.arrayOrNil(lw+".logicalLocations", l["logicalLocations"]) {
					v.object(lw+".logical", logical, []string{"name", "fullyQualifiedName", "kind"}, nil, nil)
				}
			})
		}
		if prints, found := r["partialFingerprints"]; found {
			v.object(where+".partialFingerprints", prints, []string{"prufyxResult/v1"}, nil, func(m map[string]any) {
				if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fmt.Sprint(m["prufyxResult/v1"])) {
					v.fail("%s fingerprint %v", where, m["prufyxResult/v1"])
				}
			})
		}
	})
}

func (v *sarifValidator) arrayOrNil(where string, value any) []any {
	if value == nil {
		return nil
	}
	return v.array(where, value)
}

// TestSARIFStructure: every golden validates, and hand-broken copies fail.
func TestSARIFStructure(t *testing.T) {
	var logs [][]byte
	for _, f := range fixtures(t) {
		raw, err := SARIF(f.report)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSARIF(raw); err != nil {
			t.Errorf("%s: %v", f.name, err)
		}
		golden, err := readGolden("sarif-" + f.name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err := validateSARIF(golden); err != nil {
			t.Errorf("golden %s: %v", f.name, err)
		}
		logs = append(logs, raw)
	}
	base := fullReportSARIF(t)
	breaks := map[string]func(log map[string]any){
		"missing version":     func(l map[string]any) { delete(l, "version") },
		"wrong version":       func(l map[string]any) { l["version"] = "2.0.0" },
		"wrong schema":        func(l map[string]any) { l["$schema"] = "https://example.test/sarif.json" },
		"two runs":            func(l map[string]any) { l["runs"] = append(l["runs"].([]any), l["runs"].([]any)[0]) },
		"unknown property":    func(l map[string]any) { l["extra"] = true },
		"bad ruleIndex":       func(l map[string]any) { first(l, "results")["ruleIndex"] = json.Number("1") },
		"ruleIndex too large": func(l map[string]any) { first(l, "results")["ruleIndex"] = json.Number("99") },
		"startLine zero":      func(l map[string]any) { region(l)["startLine"] = json.Number("0") },
		"startLine negative":  func(l map[string]any) { region(l)["startLine"] = json.Number("-1") },
		"startLine string":    func(l map[string]any) { region(l)["startLine"] = "3" },
		"absolute uri":        func(l map[string]any) { artifact(l)["uri"] = "/etc/passwd" },
		"parent uri":          func(l map[string]any) { artifact(l)["uri"] = "a/../../b.yaml" },
		"scheme uri":          func(l map[string]any) { artifact(l)["uri"] = "file:///x.yaml" },
		"backslash uri":       func(l map[string]any) { artifact(l)["uri"] = "a\\b.yaml" },
		"finding as warning":  func(l map[string]any) { first(l, "results")["level"] = "warning" },
		"notification error":  func(l map[string]any) { notification(l)["level"] = "error" },
		"missing message":     func(l map[string]any) { delete(first(l, "results"), "message") },
		"rule repeated":       func(l map[string]any) { rules := rulesOf(l); rules[1] = rules[0] },
		"missing driver name": func(l map[string]any) { delete(driverOf(l), "name") },
		"associated rule drift": func(l map[string]any) {
			notification(l)["associatedRule"] = map[string]any{"id": "kubernetes.notice-a", "index": json.Number("0")}
		},
	}
	names := make([]string, 0, len(breaks))
	for name := range breaks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		var log map[string]any
		decoder := json.NewDecoder(bytes.NewReader(base))
		decoder.UseNumber()
		if err := decoder.Decode(&log); err != nil {
			t.Fatal(err)
		}
		breaks[name](log)
		raw, _ := json.Marshal(log)
		if err := validateSARIF(raw); err == nil {
			t.Errorf("%s: broken log validated", name)
		}
	}
	if len(logs) != 4 {
		t.Fatal("fixtures")
	}
}

func fullReportSARIF(t *testing.T) []byte {
	raw, err := SARIF(fullReport())
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func runOf(l map[string]any) map[string]any { return l["runs"].([]any)[0].(map[string]any) }
func driverOf(l map[string]any) map[string]any {
	return runOf(l)["tool"].(map[string]any)["driver"].(map[string]any)
}
func rulesOf(l map[string]any) []any { return driverOf(l)["rules"].([]any) }
func first(l map[string]any, key string) map[string]any {
	return runOf(l)[key].([]any)[0].(map[string]any)
}
func physical(l map[string]any) map[string]any {
	return first(l, "results")["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
}
func region(l map[string]any) map[string]any { return physical(l)["region"].(map[string]any) }
func artifact(l map[string]any) map[string]any {
	return physical(l)["artifactLocation"].(map[string]any)
}
func notification(l map[string]any) map[string]any {
	for _, n := range runOf(l)["invocations"].([]any)[0].(map[string]any)["toolExecutionNotifications"].([]any) {
		if note := n.(map[string]any); note["associatedRule"] != nil {
			return note
		}
	}
	panic("no notification with an associated rule")
}
