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

func schemaOf(t *testing.T, pack string) string {
	t.Helper()
	var d struct {
		Schema string `json:"schema"`
	}
	raw, _ := os.ReadFile(pack)
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d.Schema
}

// A pack carries exactly the schema of the highest-level feature it uses:
// when the merge needs a higher level, apply moves to the first level the
// loader admits, never further, and leaves the pack alone when none is.
func TestApplyMovesToTheSchemaLevelTheLoaderAdmits(t *testing.T) {
	run := runDir(t, cases[0], derivedAt)
	pack := prunedPack(t, "cncf", run)
	from := schemaOf(t, pack)
	prefix := from[:strings.LastIndex(from, "alpha")+len("alpha")]
	want := prefix + "10"
	var tried []string
	admit := func(_ string, raw []byte) error {
		var d struct{ Schema string }
		_ = json.Unmarshal(raw, &d)
		tried = append(tried, d.Schema)
		if d.Schema == want {
			return nil
		}
		return errors.New("refused")
	}
	rep, err := extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, Admit: admit})
	if err != nil {
		t.Fatal(err)
	}
	if rep.SchemaFrom != from || rep.SchemaTo != want || schemaOf(t, pack) != want {
		t.Fatalf("%+v %v", rep, tried)
	}
	if tried[len(tried)-1] != want {
		t.Fatalf("went past the first admitted level: %v", tried)
	}
	// None admitted: refused, file untouched.
	pack = prunedPack(t, "cncf", run)
	pre, _ := os.ReadFile(pack)
	_, err = extractpack.Apply(extractpack.Options{PackPath: pack, RunDir: run, SchemaLevels: 3, Admit: func(string, []byte) error { return errors.New("never") }})
	if !errors.Is(err, extractpack.ErrAdmission) {
		t.Fatalf("%v", err)
	}
	assertUnchanged(t, pack, pre)
}
