// SPDX-License-Identifier: AGPL-3.0-only

package qareport

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	stCommit = "4ce5a8954017644c5420bae81d72b09b735c21f0"
	stSha    = "0d43576f2097092c8a3f203368a8edc0d605540c9757125dae116031f182e53a"
	stHead   = "run_id\thost\tchart\tchart_version\tk8s_from\tk8s_to\tdocs\tunserved_docs\tprufyx_exit\tprufyx_verdict\tblocked_docs\tclass\treasons\tsource_cited\n"
)

func stDigests() string {
	return "v1.25.0 " + stCommit + " " + stSha + "\n"
}

func stRow(mut func(f []string)) string {
	f := []string{"m9s-r01", "leakhost-7", "podinfo", "6.1.0|def", "1.24", "1.25", "18", "0", "0", "SCOPE_COMPLETE_PASS", "", "correct_pass", "|def|served-api-static", ""}
	if mut != nil {
		mut(f)
	}
	return strings.Join(f, "\t") + "\n"
}

func stFiles(t *testing.T, tsv, dig string) (string, string) {
	t.Helper()
	d := t.TempDir()
	a, b := filepath.Join(d, "r.tsv"), filepath.Join(d, "d.txt")
	if err := os.WriteFile(a, []byte(tsv), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte(dig), 0o644); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestServedAPIRefusal(t *testing.T) {
	url := "https://github.com/kubernetes/kubernetes/blob/" + stCommit + "/api/openapi-spec/swagger.json"
	cases := map[string]string{
		"extra column":   strings.Replace(stHead, "source_cited", "source_cited\tnote", 1) + stRow(nil),
		"renamed column": strings.Replace(stHead, "host", "hostname", 1) + stRow(nil),
		"short row":      stHead + "a\tb\n",
		"class":          stHead + stRow(func(f []string) { f[11] = "great" }),
		"verdict":        stHead + stRow(func(f []string) { f[9] = "BLOCKED" }),
		"reason code":    stHead + stRow(func(f []string) { f[12] = "NEW_CODE|def|served-api-static" }),
		"reason variant": stHead + stRow(func(f []string) { f[12] = "|opt|served-api-static" }),
		"hop":            stHead + stRow(func(f []string) { f[4] = "1.23" }),
		"no oracle":      stHead + stRow(func(f []string) { f[4], f[5] = "1.25", "1.26" }),
		"version":        stHead + stRow(func(f []string) { f[3] = "6.1.0-rc1|def" }),
		"chart":          stHead + stRow(func(f []string) { f[2] = "../x" }),
		"source":         stHead + stRow(func(f []string) { f[13] = "https://example.com/x" }),
		"unknown commit": stHead + stRow(func(f []string) { f[13] = strings.Replace(url, stCommit[:6], "ffffff", 1) }),
		"blocked docs":   stHead + stRow(func(f []string) { f[10] = "Kind/name" }),
		"duplicate":      stHead + stRow(nil) + stRow(nil),
		"no rows":        stHead,
	}
	for name, tsv := range cases {
		a, b := stFiles(t, tsv, stDigests())
		if _, err := BuildServedAPI(a, b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, dig := range map[string]string{"shape": "v1.25.0 x\n", "tag": "v1.25.1 " + stCommit + " " + stSha + "\n", "sha": "v1.25.0 " + stCommit + " abc\n", "dup": stDigests() + stDigests(), "empty": ""} {
		a, b := stFiles(t, stHead+stRow(nil), dig)
		if _, err := BuildServedAPI(a, b); err == nil {
			t.Errorf("digests %s: accepted", name)
		}
	}
	a, b := stFiles(t, stHead+stRow(nil)+stRow(func(f []string) {
		f[3], f[9], f[10], f[11], f[12] = "6.1.0|opt", "BLOCKED", "PodSecurityPolicy/leak-name", "correct_block", "API_VERSION_NOT_REVIEWED|opt|served-api-static"
		f[13] = url
	}), stDigests())
	if _, err := BuildServedAPI(a, b); err != nil {
		t.Fatal(err)
	}
}

func TestServedAPIOutputAllowlistAndCounts(t *testing.T) {
	url := "https://github.com/kubernetes/kubernetes/blob/" + stCommit + "/api/openapi-spec/swagger.json"
	tsv := stHead + stRow(nil) + stRow(func(f []string) { f[3], f[12] = "6.0.0|opt", "|opt|served-api-static" }) +
		stRow(func(f []string) {
			f[3], f[9], f[10], f[11], f[12], f[13] = "7.0.0|def", "BLOCKED", "PodSecurityPolicy/leak-name", "correct_block", "API_VERSION_NOT_REVIEWED|def|served-api-static", url
		}) +
		stRow(func(f []string) {
			f[3], f[9], f[11], f[12] = "8.0.0|def", "UNKNOWN", "gap", "DOCUMENTS_TEMPLATED,LINE_NOT_ATTESTED|def|served-api-static"
		}) +
		stRow(func(f []string) { f[3], f[9], f[11], f[12] = "5.0.0|def", "NOJSON", "error", "|def|served-api-static" })
	a, b := stFiles(t, tsv, stDigests())
	s, err := BuildServedAPI(a, b)
	if err != nil {
		t.Fatal(err)
	}
	rep := &Report{Schema: Schema, Header: Header, Runs: []Run{}, ServedAPI: s}
	j, md, err := Render(rep)
	if err != nil {
		t.Fatal(err)
	}
	if s.Rows != 5 || s.ByClass[0].Count != 2 || s.ByClass[1].Count != 1 || s.ByClass[4].Count != 1 || s.ByClass[5].Count != 1 {
		t.Errorf("counts %+v", s.ByClass)
	}
	for _, doc := range [][]byte{j, md} {
		for _, leak := range append(append([]string{}, leaks...), "leak-name", "PodSecurityPolicy", "m9s-r01", "api/openapi-spec", "github.com") {
			if bytes.Contains(doc, []byte(leak)) {
				t.Errorf("%q reached the output", leak)
			}
		}
	}
	if !bytes.Contains(md, []byte(ServedAPIStatement[1:])) || !bytes.Contains(md, []byte(stSha)) {
		t.Error("wording or oracle digest missing")
	}
	// determinism
	j2, md2, _ := Render(&Report{Schema: Schema, Header: Header, Runs: []Run{}, ServedAPI: s})
	if !bytes.Equal(j, j2) || !bytes.Equal(md, md2) {
		t.Error("not deterministic")
	}
	// kind counts are untouched by the second section
	if rep.Counts.Rows != 0 {
		t.Error("served-API rows leaked into the kind counts")
	}
	// host-like chart name is refused at render
	s.Checks[0].Chart = "pfspot1"
	if _, _, err := Render(rep); err == nil {
		t.Error("denied value reached the output")
	}
}
