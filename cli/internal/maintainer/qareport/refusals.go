// SPDX-License-Identifier: AGPL-3.0-only

package qareport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// Refusal is one distinct reason a run would be refused, with the number of
// rows (or 1 for the whole run) it applies to. Only fixed messages and schema
// key names are listed, never input values.
type Refusal struct {
	Run     string
	Message string
	Count   int
}

var (
	reUnknownField = regexp.MustCompile(`unknown field "([A-Za-z0-9_]{1,40})"`)
	reTailName     = regexp.MustCompile(`^[A-Za-z0-9_]{1,40}$`)
)

func dropKey(v any, name string) {
	switch t := v.(type) {
	case map[string]any:
		delete(t, name)
		for _, x := range t {
			dropKey(x, name)
		}
	case []any:
		for _, x := range t {
			dropKey(x, name)
		}
	}
}

// ListRefusals reads every run directory like Build but, instead of stopping at
// the first refusal, collects every distinct refusal per run. It is
// diagnostic only: it never produces report content. Unknown schema keys are
// listed by key name and then ignored so that later refusals show up too.
func ListRefusals(dir string) ([]Refusal, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("cannot read the results directory")
	}
	var out []Refusal
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("symlink in the results directory")
		}
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		add := func(m string, n int) { out = append(out, Refusal{Run: name, Message: m, Count: n}) }
		runDir := filepath.Join(dir, name)
		path := filepath.Join(runDir, "RESULT.json")
		var raw []byte
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil || !info.Mode().IsRegular() || info.Size() > maxInputSize:
			add("RESULT.json is not a regular file of bounded size", 1)
			continue
		default:
			if raw, err = os.ReadFile(path); err != nil {
				add("cannot read RESULT.json", 1)
				continue
			}
		}
		code, err := notReportedMark(runDir, raw)
		if err != nil {
			add(err.Error(), 1)
			continue
		}
		if code != "" {
			continue
		}
		by, body, err := supersededMark(runDir, raw)
		if err != nil {
			add(err.Error(), 1)
			continue
		}
		if by != "" || raw == nil {
			continue
		}
		var probe map[string]json.RawMessage
		if json.Unmarshal(body, &probe) != nil || probe["clusters"] == nil || probe["schema"] != nil {
			if _, err := ParseRun(name, body); err != nil {
				add(err.Error(), 1)
			}
			continue
		}
		out = append(out, listM3(name, body)...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Run != out[j].Run {
			return out[i].Run < out[j].Run
		}
		return out[i].Message < out[j].Message
	})
	return out, nil
}

func listM3(name string, body []byte) []Refusal {
	var generic map[string]any
	if json.Unmarshal(body, &generic) != nil {
		return []Refusal{{name, "input is not a JSON object", 1}}
	}
	var out []Refusal
	for i := 0; i < 64; i++ {
		b, _ := json.Marshal(generic)
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var f m3File
		err := dec.Decode(&f)
		if err == nil {
			break
		}
		m := reUnknownField.FindStringSubmatch(err.Error())
		if m == nil || !reTailName.MatchString(m[1]) {
			return append(out, Refusal{name, "input does not match the closed schema", 1})
		}
		out = append(out, Refusal{name, fmt.Sprintf("unknown field %q", m[1]), 1})
		dropKey(generic, m[1])
	}
	checks, _ := generic["checks"].([]any)
	generic["checks"] = []any{}
	if b, err := json.Marshal(generic); err == nil {
		if _, err := parseM3(name, b); err != nil {
			out = append(out, Refusal{name, err.Error(), 1})
		}
	}
	counts := map[string]int{}
	cb, _ := json.Marshal(checks)
	var cs []m3Check
	if json.Unmarshal(cb, &cs) != nil {
		return append(out, Refusal{name, "checks do not match the closed schema", 1})
	}
	for _, c := range cs {
		if _, ok := oracleTypes[c.Oracle.Type]; !ok {
			counts["unknown oracle type"]++
		}
		if consistent(c.Class, c.Result) != nil {
			counts["class and result disagree"]++
		}
		if !reApp.MatchString(c.App) {
			counts["app outside the allowlist pattern"]++
		}
		if !okVersion(c.From) || !okVersion(c.To) {
			counts["version outside the allowlist pattern"]++
		}
		if _, ok := commandLabel(c.Assertion.Command); !ok {
			counts["unknown command"]++
		}
		if _, err := form(c.Class); err != nil {
			counts["unknown result form"]++
		}
		if _, err := reasonCode(c.Assertion.Verdict); err != nil {
			counts["unknown verdict form"]++
		}
		for _, id := range c.Assertion.IDs {
			if !reRuleID.MatchString(id) && !reCode.MatchString(id) {
				counts["id outside the allowlist patterns"]++
				break
			}
		}
		if c.LogDigest != "" && !reSha.MatchString(c.LogDigest) {
			counts["log digest is not a sha256"]++
		}
		for n, d := range c.Artifacts {
			if !reArtName.MatchString(n) || !reSha.MatchString(d) {
				counts["artifact entry outside the allowlist patterns"]++
				break
			}
		}
	}
	for m, n := range counts {
		out = append(out, Refusal{name, "check: " + m, n})
	}
	return out
}
