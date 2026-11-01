// SPDX-License-Identifier: AGPL-3.0-only

package helmvalues

// A second account of what a chart's values and schema remove between two
// releases, written without the extractor's helpers: plain YAML and JSON
// decoding and a recursive walk over maps. The extractor's removals must
// equal it; where the extractor refuses a pair, it must claim nothing.

import (
	"context"
	"encoding/json"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/helmvalues/internal/memchart"
)

// --- the independent method ---

func refDecode(t *testing.T, doc string) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func refDecodeSchema(t *testing.T, doc string) map[string]any {
	t.Helper()
	if doc == "" {
		return nil
	}
	m := map[string]any{}
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// refUsed lists every dotted key whose value is not null, through maps.
func refUsed(m map[string]any, prefix string, out *[]string) {
	for k, v := range m {
		if v == nil {
			continue
		}
		*out = append(*out, prefix+k)
		if sub, ok := v.(map[string]any); ok {
			refUsed(sub, prefix+k+".", out)
		}
	}
}

// refSchemaKeys lists every dotted key a schema declares under properties.
func refSchemaKeys(s map[string]any, prefix string, out *[]string) {
	props, _ := s["properties"].(map[string]any)
	for k, v := range props {
		*out = append(*out, prefix+k)
		if sub, ok := v.(map[string]any); ok {
			refSchemaKeys(sub, prefix+k+".", out)
		}
	}
}

// refRemoved is the recursive map-diff of two values documents: the
// topmost keys the earlier one sets (not null) that the later one lacks or
// nulls.
func refRemoved(from, to map[string]any, prefix string, out *[]string) {
	for k, v := range from {
		if v == nil {
			continue
		}
		tv, ok := to[k]
		if !ok || tv == nil {
			*out = append(*out, prefix+k)
			continue
		}
		fm, fIsMap := v.(map[string]any)
		if !fIsMap {
			continue
		}
		tm, _ := tv.(map[string]any) // a later scalar leaves no key of the map
		refRemoved(fm, tm, prefix+k+".", out)
	}
}

var refPlainKeywords = map[string]bool{
	"type": true, "properties": true, "required": true, "additionalProperties": true, "patternProperties": true,
	"description": true, "title": true, "default": true, "$comment": true, "$schema": true,
}

// refPlain reports a schema object the reference can read: only the
// keywords above, and no type but object.
func refPlain(n map[string]any) bool {
	for k := range n {
		if !refPlainKeywords[k] {
			return false
		}
	}
	if ty, ok := n["type"]; ok && ty != "object" {
		return false
	}
	return true
}

// refRefused returns the shortest prefix of parts the schema refuses as a
// key of an object closed to its properties; ok is false when it refuses
// none or the reference cannot tell.
func refRefused(schema map[string]any, parts []string) (prefix []string, ok bool) {
	node := schema
	for i, k := range parts {
		if !refPlain(node) {
			return nil, false
		}
		props, _ := node["properties"].(map[string]any)
		if child, named := props[k]; named {
			cm, isMap := child.(map[string]any)
			if !isMap {
				return nil, false
			}
			node = cm
			continue
		}
		closed, isBool := node["additionalProperties"].(bool)
		if _, pat := node["patternProperties"]; isBool && !closed && !pat {
			return parts[:i+1], true
		}
		return nil, false
	}
	return nil, false
}

// refSet reports whether the values document holds the key path.
func refSet(m map[string]any, parts []string) bool {
	var cur any = m
	for _, k := range parts {
		cm, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		if cur, ok = cm[k]; !ok {
			return false
		}
	}
	// A null default counts: Helm keeps it through the merge, so the key
	// exists for the schema.
	return true
}

// refHard is the set of keys a user could set under the earlier chart that
// the later schema refuses outright.
func refHard(fromVals, fromSchema, toVals, toSchema map[string]any, subcharts []string) []string {
	if toSchema == nil {
		return nil
	}
	var cands []string
	refUsed(fromVals, "", &cands)
	if fromSchema != nil {
		refSchemaKeys(fromSchema, "", &cands)
	}
	set := map[string]bool{}
	for _, c := range cands {
		parts := strings.Split(c, ".")
		if parts[0] == "global" || slices.Contains(subcharts, parts[0]) {
			continue
		}
		prefix, ok := refRefused(toSchema, parts)
		if !ok || refSet(toVals, prefix) {
			continue
		}
		if fromSchema != nil {
			if earlier, refused := refRefused(fromSchema, prefix); refused && len(earlier) <= len(prefix) {
				continue
			}
		}
		set[strings.Join(prefix, ".")] = true
	}
	return refSortedKeys(set)
}

func refSortedKeys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- the extractor, end to end ---

type xcheckRun struct {
	hard, soft []string
	withheld   bool
	rules      int
}

func runPairFiles(t *testing.T, fromFiles, toFiles map[string]string) xcheckRun {
	t.Helper()
	tg := target(t, "keda")
	repo, err := extract.ParseRepo(tg.Repo)
	must(t, err)
	r := memchart.New()
	for p, c := range fromFiles {
		r.Put(c0, "keda/"+p, c)
	}
	for p, c := range toFiles {
		r.Put(c1, "keda/"+p, c)
	}
	pair := extract.VersionPair{Repo: repo, From: "90.0.0", FromTag: "v90.0.0", FromCommit: c0, To: "90.1.0", ToTag: "v90.1.0", ToCommit: c1}
	got, err := New(tg).Extract(context.Background(), r, pair)
	if _, ok := extract.IsWithheld(err); ok {
		return xcheckRun{hard: []string{}, soft: []string{}, withheld: true}
	}
	must(t, err)
	run := xcheckRun{hard: []string{}, soft: []string{}, rules: len(got.Candidates)}
	for _, c := range got.Candidates {
		if strings.HasSuffix(c.Rule.ID, "removed-values") {
			run.hard = append(run.hard, c.Rule.SetCondition.Members...)
		}
	}
	sort.Strings(run.hard)
	proof := got.Proof.(*PairProof)
	run.soft = append(run.soft, proof.Soft.DefaultsRemoved...)
	sort.Strings(run.soft)
	return run
}

func chartFiles(version, values, schema string) map[string]string {
	f := map[string]string{"Chart.yaml": "apiVersion: v2\nname: keda\nversion: " + version + "\n", "values.yaml": values}
	if schema != "" {
		f["values.schema.json"] = schema
	}
	return f
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

const (
	closedKeep = `{"type":"object","properties":{"a":{"type":"object","additionalProperties":false,"properties":{"keep":{}}}}}`
	openKeep   = `{"type":"object","properties":{"a":{"type":"object","properties":{"keep":{}}}}}`
)

func TestRemovalsMatchIndependentDiff(t *testing.T) {
	tests := []struct {
		name               string
		fromVals, fromSch  string
		toVals, toSch      string
		wantHard, wantSoft []string
		wantWithheld       bool
	}{
		{name: "scalar removed", fromVals: "a: {keep: 1, gone: 2}\n", toVals: "a: {keep: 1}\n", toSch: closedKeep,
			wantHard: []string{"a.gone"}, wantSoft: []string{"a.gone"}},
		{name: "nested map removed, topmost key is named", fromVals: "a: {keep: 1, gone: {deep: {er: 1}}}\n", toVals: "a: {keep: 1}\n", toSch: closedKeep,
			wantHard: []string{"a.gone"}, wantSoft: []string{"a.gone"}},
		{name: "list-valued key", fromVals: "a: {keep: 1, gone: [1, 2, {x: 1}]}\n", toVals: "a: {keep: 1}\n", toSch: closedKeep,
			wantHard: []string{"a.gone"}, wantSoft: []string{"a.gone"}},
		{name: "renamed key under a closed schema", fromVals: "a: {keep: 1, old: 2}\n",
			toVals: "a: {keep: 1, new: 2}\n", toSch: `{"properties":{"a":{"type":"object","additionalProperties":false,"properties":{"keep":{},"new":{}}}}}`,
			wantHard: []string{"a.old"}, wantSoft: []string{"a.old"}},
		{name: "renamed key under an open schema is still reported as removed", fromVals: "a: {keep: 1, old: 2}\n",
			toVals: "a: {keep: 1, new: 2}\n", toSch: `{"properties":{"a":{"type":"object","properties":{"keep":{},"new":{}}}}}`,
			wantHard: []string{}, wantSoft: []string{"a.old"}},
		{name: "key only in the earlier schema", fromVals: "x: 1\n", fromSch: `{"properties":{"a":{"type":"object","properties":{"old":{}}}}}`,
			toVals: "x: 1\n", toSch: closedKeep, wantHard: []string{"a.old"}, wantSoft: []string{}},
		{name: "flow style", fromVals: "{a: {keep: 1, gone: {x: [1, 2], w: z}}}\n", toVals: "{a: {keep: 1}}\n", toSch: closedKeep,
			wantHard: []string{"a.gone"}, wantSoft: []string{"a.gone"}},
		{name: "comments only", fromVals: "# first\na: {keep: 1}  # trailing\n", toVals: "a: {keep: 1}\n# last\n", toSch: closedKeep,
			wantHard: []string{}, wantSoft: []string{}},
		{name: "null earlier value is not a key", fromVals: "a: {keep: 1, gone: null}\n", toVals: "a: {keep: 1}\n", toSch: closedKeep,
			wantHard: []string{}, wantSoft: []string{}},
		{name: "later null default: a removed default, but the key still exists for the schema", fromVals: "a: {keep: 1, gone: 2}\n", toVals: "a: {keep: 1, gone: null}\n", toSch: closedKeep,
			wantHard: []string{}, wantSoft: []string{"a.gone"}},
		{name: "key still defaulted", fromVals: "a: {keep: 1, gone: 2}\n", toVals: "a: {keep: 1, gone: 2}\n", toSch: closedKeep,
			wantHard: []string{}, wantSoft: []string{}},
		{name: "key already refused by the earlier schema", fromVals: "a: {keep: 1, gone: 2}\n", fromSch: closedKeep, toVals: "a: {keep: 1}\n", toSch: closedKeep,
			wantHard: []string{}, wantSoft: []string{"a.gone"}},
		{name: "reference on the path", fromVals: "a: {keep: 1, gone: 2}\n", toVals: "a: {keep: 1}\n",
			toSch:    `{"properties":{"a":{"$ref":"#/definitions/x","additionalProperties":false,"properties":{"keep":{}}}}}`,
			wantHard: []string{}, wantSoft: []string{"a.gone"}},
		{name: "global values", fromVals: "global: {x: 1}\n", toVals: "z: 1\n", toSch: `{"additionalProperties":false,"properties":{"z":{}}}`,
			wantHard: []string{}, wantSoft: []string{"global"}},
		{name: "mapping became a scalar", fromVals: "a: {keep: 1, gone: 2}\n", toVals: "a: 5\n", toSch: `{"properties":{"a":{}}}`,
			wantHard: []string{}, wantSoft: []string{"a.gone", "a.keep"}},
		{name: "anchor alone is refused", fromVals: "a: &x {keep: 1, gone: 2}\n", toVals: "a: {keep: 1}\n", toSch: closedKeep,
			wantHard: []string{}, wantSoft: []string{}, wantWithheld: true},
		{name: "anchor and alias are refused, not read", fromVals: "a: &x {keep: 1, gone: 2}\nb: *x\n", toVals: "a: {keep: 1}\n", toSch: closedKeep,
			wantHard: []string{}, wantSoft: []string{}, wantWithheld: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			run := runPairFiles(t, chartFiles("90.0.0", tc.fromVals, tc.fromSch), chartFiles("90.1.0", tc.toVals, tc.toSch))
			if run.withheld != tc.wantWithheld {
				t.Fatalf("withheld %v, want %v", run.withheld, tc.wantWithheld)
			}
			// The independent method reads the same documents (leniently:
			// it resolves anchors).
			fv, tv := refDecode(t, tc.fromVals), refDecode(t, tc.toVals)
			refHardSet := refHard(fv, refDecodeSchema(t, tc.fromSch), tv, refDecodeSchema(t, tc.toSch), nil)
			var refSoft []string
			refRemoved(fv, tv, "", &refSoft)
			if refSoft == nil {
				refSoft = []string{}
			}
			sort.Strings(refSoft)
			if tc.wantWithheld {
				// Refusing is the safe direction: the extractor claims
				// nothing the reference does not, and here claims nothing.
				if len(run.hard) != 0 || run.rules != 0 || len(refHardSet) == 0 {
					t.Fatalf("withheld pair: extractor %v, reference %v", run.hard, refHardSet)
				}
				return
			}
			if !slices.Equal(run.hard, refHardSet) {
				t.Fatalf("hard removals: extractor %v, independent diff %v", run.hard, refHardSet)
			}
			if !slices.Equal(run.soft, refSoft) {
				t.Fatalf("defaults removed: extractor %v, independent diff %v", run.soft, refSoft)
			}
			if !slices.Equal(run.hard, tc.wantHard) || !slices.Equal(run.soft, tc.wantSoft) {
				t.Fatalf("expected hard %v soft %v, got hard %v soft %v", tc.wantHard, tc.wantSoft, run.hard, run.soft)
			}
		})
	}
}

// --- generated pairs ---

func genTree(rng *rand.Rand, depth int) map[string]any {
	m := map[string]any{}
	for i, n := 0, 1+rng.Intn(4); i < n; i++ {
		k := "k" + string(rune('0'+rng.Intn(6)))
		switch r := rng.Intn(10); {
		case r < 4 && depth < 3:
			m[k] = genTree(rng, depth+1)
		case r < 5:
			m[k] = []any{1, "x"}
		case r < 6:
			m[k] = nil
		case r < 8:
			m[k] = rng.Intn(100)
		default:
			m[k] = "s" + string(rune('a'+rng.Intn(5)))
		}
	}
	return m
}

func mutate(rng *rand.Rand, m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		switch r := rng.Intn(10); {
		case r < 2:
			continue
		case r < 3:
			out["r"+k] = v
			continue
		}
		if rng.Intn(12) == 0 {
			out[k] = nil
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			v = mutate(rng, sub)
		} else if rng.Intn(6) == 0 {
			v = rng.Intn(100)
		}
		out[k] = v
	}
	return out
}

// schemaFor closes every object to the keys m sets (a null key is not set),
// leaving some objects open.
func schemaFor(rng *rand.Rand, m map[string]any) map[string]any {
	props := map[string]any{}
	for k, v := range m {
		if v == nil {
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			props[k] = schemaFor(rng, sub)
			continue
		}
		props[k] = map[string]any{}
	}
	s := map[string]any{"type": "object", "properties": props}
	if rng.Intn(4) != 0 {
		s["additionalProperties"] = false
	}
	return s
}

func TestRemovalsMatchIndependentDiffGenerated(t *testing.T) {
	rng := rand.New(rand.NewSource(20261101))
	seenHard, seenSoft := 0, 0
	for i := 0; i < 300; i++ {
		from := genTree(rng, 0)
		to := mutate(rng, from)
		fromYAML, err := yaml.Marshal(from)
		must(t, err)
		toJSON, err := json.Marshal(to) // JSON is flow-style YAML
		must(t, err)
		toSchema, err := json.Marshal(schemaFor(rng, to))
		must(t, err)
		var fromSchema []byte
		if rng.Intn(2) == 0 {
			fromSchema, err = json.Marshal(schemaFor(rng, from))
			must(t, err)
		}
		run := runPairFiles(t, chartFiles("90.0.0", string(fromYAML), string(fromSchema)), chartFiles("90.1.0", string(toJSON), string(toSchema)))
		if run.withheld {
			t.Fatalf("case %d withheld:\nfrom %s\nto %s", i, fromYAML, toJSON)
		}
		fv, tv := refDecode(t, string(fromYAML)), refDecode(t, string(toJSON))
		wantHard := refHard(fv, refDecodeSchema(t, string(fromSchema)), tv, refDecodeSchema(t, string(toSchema)), nil)
		var wantSoft []string
		refRemoved(fv, tv, "", &wantSoft)
		sort.Strings(wantSoft)
		if len(wantSoft) == 0 {
			wantSoft = []string{}
		}
		if !slices.Equal(run.hard, wantHard) || !slices.Equal(run.soft, wantSoft) {
			t.Fatalf("case %d\nfrom %s\nto %s\nfrom schema %s\nto schema %s\nextractor hard %v soft %v\nindependent hard %v soft %v",
				i, fromYAML, toJSON, fromSchema, toSchema, run.hard, run.soft, wantHard, wantSoft)
		}
		if len(wantHard) > 0 {
			seenHard++
		}
		if len(wantSoft) > 0 {
			seenSoft++
		}
	}
	if seenHard < 30 || seenSoft < 100 {
		t.Fatalf("the generator exercised too little: %d hard, %d soft of 300", seenHard, seenSoft)
	}
}
