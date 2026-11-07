// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	cncfRulesPath    = "cli/internal/cncfcheck/data/rules.json"
	projectRulesPath = "cli/internal/projectcheck/data/rules.json"
	projectsPath     = "cli/internal/projectcheck/data/projects.json"
)

var deltaTrees = []string{"cli/knowledge/", "cli/internal/cncfcheck/data/", "cli/internal/projectcheck/data/"}

// canonical returns the compact JSON of v with sorted object keys and no
// HTML escaping.
func canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("trailing data")
	}
	return nil
}

// keyed lists one array of a rules file as identity -> digests.
type keyed map[string][]string

func (k keyed) count() int {
	n := 0
	for _, v := range k {
		n += len(v)
	}
	return n
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func readArray(raw []byte, field string, ident func(map[string]any) string) (keyed, error) {
	var doc map[string]any
	if err := decodeJSON(raw, &doc); err != nil {
		return nil, err
	}
	out := keyed{}
	v, ok := doc[field]
	if !ok {
		return out, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s is not an array", field)
	}
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] is not an object", field, i)
		}
		b, err := canonical(m)
		if err != nil {
			return nil, err
		}
		id := ident(m)
		out[id] = append(out[id], digest(b))
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out, nil
}

func diffKeyed(path string, before, after keyed) RuleDelta {
	d := RuleDelta{Path: path, Before: before.count(), After: after.count(), Added: []string{}, Removed: []string{}, Changed: []string{}}
	ids := map[string]bool{}
	for k := range before {
		ids[k] = true
	}
	for k := range after {
		ids[k] = true
	}
	for id := range ids {
		b, a := before[id], after[id]
		switch {
		case len(b) == 0:
			d.Added = append(d.Added, id)
		case len(a) == 0:
			d.Removed = append(d.Removed, id)
		case strings.Join(b, ",") != strings.Join(a, ","):
			d.Changed = append(d.Changed, id)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Changed)
	return d
}

func ruleIdent(m map[string]any) string { return str(m, "project") + ": " + str(m, "description") }
func lineIdent(m map[string]any) string {
	return str(m, "component") + " " + str(m, "line") + " " + str(m, "factFamily")
}

type fileSpec struct {
	path  string
	field string
	ident func(map[string]any) string
}

var ruleFiles = []fileSpec{
	{cncfRulesPath, "entries", ruleIdent},
	{cncfRulesPath + "#lineAttestations", "lineAttestations", lineIdent},
	{projectRulesPath, "entries", ruleIdent},
}

func ruleDeltas(ctx context.Context, r repo, base, head string) ([]RuleDelta, error) {
	var out []RuleDelta
	for _, spec := range ruleFiles {
		path := strings.SplitN(spec.path, "#", 2)[0]
		var sides [2]keyed
		for i, rev := range []string{base, head} {
			raw, err := r.show(ctx, rev, path)
			if err != nil {
				return nil, fmt.Errorf("read %s at %s: %w", path, rev[:8], err)
			}
			k, err := readArray(raw, spec.field, spec.ident)
			if err != nil {
				return nil, fmt.Errorf("parse %s at %s: %w", path, rev[:8], err)
			}
			sides[i] = k
		}
		out = append(out, diffKeyed(spec.path, sides[0], sides[1]))
	}
	return out, nil
}

func projectSlugs(ctx context.Context, r repo, rev string) (map[string]bool, error) {
	raw, err := r.show(ctx, rev, projectsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s at %s: %w", projectsPath, rev[:8], err)
	}
	k, err := readArray(raw, "projects", func(m map[string]any) string { return str(m, "slug") })
	if err != nil {
		return nil, fmt.Errorf("parse %s at %s: %w", projectsPath, rev[:8], err)
	}
	set := map[string]bool{}
	for id := range k {
		set[id] = true
	}
	return set, nil
}

func projectDelta(ctx context.Context, r repo, base, head string) (ProjectDelta, error) {
	b, err := projectSlugs(ctx, r, base)
	if err != nil {
		return ProjectDelta{}, err
	}
	a, err := projectSlugs(ctx, r, head)
	if err != nil {
		return ProjectDelta{}, err
	}
	d := ProjectDelta{Added: []string{}, Removed: []string{}}
	for s := range a {
		if !b[s] {
			d.Added = append(d.Added, s)
		}
	}
	for s := range b {
		if !a[s] {
			d.Removed = append(d.Removed, s)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	return d, nil
}

const (
	readmeBegin = "<!-- coverage:begin -->"
	readmeEnd   = "<!-- coverage:end -->"
)

var numberRe = regexp.MustCompile(`[0-9]+(?:\.[0-9]+)?`)

// readmeRows parses the coverage block into label -> value cell.
func readmeRows(raw []byte) (map[string]string, error) {
	s := string(raw)
	if strings.Count(s, readmeBegin) != 1 || strings.Count(s, readmeEnd) != 1 {
		return nil, errors.New("README coverage block markers are missing or repeated")
	}
	i, j := strings.Index(s, readmeBegin), strings.Index(s, readmeEnd)
	if j < i {
		return nil, errors.New("README coverage block markers are out of order")
	}
	rows := map[string]string{}
	for _, line := range strings.Split(s[i+len(readmeBegin):j], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") || !strings.HasSuffix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != 2 {
			continue
		}
		label, value := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1])
		if strings.Trim(label, "-: ") == "" {
			continue
		}
		if _, dup := rows[label]; dup {
			return nil, fmt.Errorf("README coverage label %q is repeated", label)
		}
		rows[label] = value
	}
	if len(rows) == 0 {
		return nil, errors.New("README coverage block has no table rows")
	}
	return rows, nil
}

// decreased reports whether any number of value fell. Different counts of
// numbers cannot be compared and are reported as a decrease (fail closed).
func decreased(before, after string) bool {
	b, a := numberRe.FindAllString(before, -1), numberRe.FindAllString(after, -1)
	if len(b) != len(a) {
		return len(a) < len(b)
	}
	for i := range b {
		bv, e1 := strconv.ParseFloat(b[i], 64)
		av, e2 := strconv.ParseFloat(a[i], 64)
		if e1 != nil || e2 != nil || av < bv {
			return true
		}
	}
	return false
}

func readmeDeltas(ctx context.Context, r repo, base, head string) ([]ReadmeDelta, error) {
	var sides [2]map[string]string
	for i, rev := range []string{base, head} {
		raw, err := r.show(ctx, rev, "README.md")
		if err != nil {
			return nil, fmt.Errorf("read README.md at %s: %w", rev[:8], err)
		}
		rows, err := readmeRows(raw)
		if err != nil {
			return nil, fmt.Errorf("README.md at %s: %w", rev[:8], err)
		}
		sides[i] = rows
	}
	labels := map[string]bool{}
	for l := range sides[0] {
		labels[l] = true
	}
	for l := range sides[1] {
		labels[l] = true
	}
	out := []ReadmeDelta{}
	for l := range labels {
		b, bok := sides[0][l]
		a, aok := sides[1][l]
		if bok && aok && a == b {
			continue
		}
		d := ReadmeDelta{Label: l, Before: b, After: a}
		switch {
		case bok && !aok:
			d.Decrease = true
		case bok && aok:
			d.Decrease = decreased(b, a)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}
