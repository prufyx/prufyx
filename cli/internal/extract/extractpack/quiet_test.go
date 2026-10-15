// SPDX-License-Identifier: AGPL-3.0-only

package extractpack_test

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

const (
	quietArgo   = "pkg:github/argoproj/argo-cd 90.2 crd.custom_resource_versions"
	quietArgoNo = "pkg:github/argoproj/argo-cd 90.1 crd.custom_resource_versions: lists rules"
)

func quietApply(t *testing.T, pack, run string, admit func(string, []byte) error) (*extractpack.Report, error) {
	t.Helper()
	return extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, QuietOnly: true, Admit: admit})
}

func schemaIn(t *testing.T, pack string) string {
	t.Helper()
	raw, _ := os.ReadFile(pack)
	var h struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h.Schema
}

// needsHigher admits a pack only above the v1alpha2 schema, so a merge that
// adds attestations has to bump it.
func needsHigher(_ string, raw []byte) error {
	var h struct {
		Schema string `json:"schema"`
	}
	_ = json.Unmarshal(raw, &h)
	if strings.HasSuffix(h.Schema, "v1alpha2") {
		return errors.New("needs a higher schema")
	}
	return nil
}

func TestQuietOnlyAddsTheQuietLineAndNoRules(t *testing.T) {
	run := runDir(t, cases[3], derivedAt)
	pack := prunedPack(t, "cncf", run)
	before, _ := os.ReadFile(pack)
	rep, err := quietApply(t, pack, run, needsHigher)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(rep.AttAdded, []string{quietArgo}) || !equalStrings(rep.AttSkipped, []string{quietArgoNo}) {
		t.Fatalf("report %+v", rep)
	}
	if len(rep.Added) != 0 || len(rep.Unchanged) != 0 || !rep.Changed || rep.SchemaFrom == rep.SchemaTo {
		t.Fatalf("report %+v", rep)
	}
	after, _ := os.ReadFile(pack)
	var b, a map[string]json.RawMessage
	if json.Unmarshal(before, &b) != nil || json.Unmarshal(after, &a) != nil {
		t.Fatal("pack unreadable")
	}
	if string(a["entries"]) != string(b["entries"]) {
		t.Fatal("quiet-lines-only changed the rules")
	}
	if schemaIn(t, pack) != rep.SchemaTo {
		t.Fatalf("schema %s, report %s", schemaIn(t, pack), rep.SchemaTo)
	}
	// A second apply finds the attestation already present.
	again, err := quietApply(t, pack, run, needsHigher)
	if err != nil || again.Changed || len(again.AttAdded) != 0 || !equalStrings(again.AttUnchanged, []string{quietArgo}) {
		t.Fatalf("second apply: %+v %v", again, err)
	}
	if now, _ := os.ReadFile(pack); string(now) != string(after) {
		t.Fatal("a second apply rewrote the pack")
	}
}

// A pack that already holds a rule for the empty-list line, and a run whose
// other attestations list rules: nothing is added and the file is untouched.
func TestQuietOnlySkipsLinesThePackHasRulesFor(t *testing.T) {
	run := runDir(t, cases[1], derivedAt)
	pack := packDir(t, "cncf")
	mustModifyPack(t, pack, func(es []map[string]any) []map[string]any {
		for _, e := range es {
			rule, _ := e["rule"].(map[string]any)
			if sub, _ := rule["subject"].(map[string]any); sub != nil && sub["to"] == "1.32.0" {
				c := map[string]any{}
				b, _ := json.Marshal(e)
				_ = json.Unmarshal(b, &c)
				cr := c["rule"].(map[string]any)
				cr["id"] = "kubernetes.served-api-removal.quiet-test.1-30-0-to-1-31-0"
				cr["subject"].(map[string]any)["from"] = "1.30.0"
				cr["subject"].(map[string]any)["to"] = "1.31.0"
				return append(es, c)
			}
		}
		t.Fatal("no rule to clone")
		return es
	})
	before, _ := os.ReadFile(pack)
	rep, err := quietApply(t, pack, run, admitAll)
	if err != nil {
		t.Fatal(err)
	}
	var held bool
	for _, s := range rep.AttSkipped {
		if s == "pkg:github/kubernetes/kubernetes 1.31 kubernetes.removed_served_gvk: the pack holds rules for this line" {
			held = true
		}
	}
	if !held || len(rep.AttSkipped) != 4 || len(rep.AttAdded) != 0 || len(rep.Added) != 0 || rep.Changed {
		t.Fatalf("report %+v", rep)
	}
	if after, _ := os.ReadFile(pack); string(after) != string(before) {
		t.Fatal("the pack changed although nothing was quiet to add")
	}
}

func TestQuietOnlyRefusesCombinations(t *testing.T) {
	run := runDir(t, cases[3], derivedAt)
	pack := prunedPack(t, "cncf", run)
	before, _ := os.ReadFile(pack)
	for name, o := range map[string]extractpack.Options{
		"withdraw":   {Withdraw: true},
		"rules-only": {RulesOnly: true},
	} {
		o.PackPath, o.RunDir, o.QuietOnly, o.Admit = pack, run, true, admitAll
		if _, err := extractpack.Apply(o); err == nil || !strings.Contains(err.Error(), "quiet-lines-only") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if after, _ := os.ReadFile(pack); string(after) != string(before) {
		t.Fatal("a refused combination changed the pack")
	}
}
