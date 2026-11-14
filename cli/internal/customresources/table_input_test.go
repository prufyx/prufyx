// SPDX-License-Identifier: AGPL-3.0-only

package customresources

import (
	"bytes"
	"strings"
	"testing"
)

// LoadTable reads exactly one document: only white space may follow it, and
// no member name may repeat or repeat under case folding.
func TestLoadTableInputShape(t *testing.T) {
	schemaLine := `"schema": "` + TableSchema + `",`
	dupKey := bytes.Replace(tableJSON, []byte(schemaLine), []byte(schemaLine+` "schema": "`+TableSchema+`",`), 1)
	foldKey := bytes.Replace(tableJSON, []byte(schemaLine), []byte(schemaLine+` "Schema": "`+TableSchema+`",`), 1)
	if bytes.Equal(dupKey, tableJSON) || bytes.Equal(foldKey, tableJSON) {
		t.Fatal("the fixture edit did not apply")
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want string // empty: accepted
	}{
		{"as embedded", tableJSON, ""},
		{"white space at the end", append(append([]byte(nil), tableJSON...), []byte("\n\n \t\r\n")...), ""},
		{"a second value", append(append([]byte(nil), tableJSON...), []byte("{}")...), "trailing data"},
		{"a stray closing bracket", append(append([]byte(nil), tableJSON...), []byte("]")...), "trailing data"},
		{"a stray closing brace", append(append([]byte(nil), tableJSON...), []byte("}")...), "trailing data"},
		{"a stray comma", append(append([]byte(nil), tableJSON...), []byte(",")...), "trailing data"},
		{"a repeated member name", dupKey, "ambiguous"},
		{"a member name repeated in another case", foldKey, "ambiguous"},
	} {
		_, _, err := LoadTable(tc.raw)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}
