// SPDX-License-Identifier: AGPL-3.0-only

package qareport

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ServedAPITitle names the second report section. It is separate from the kind
// runs and is never summed with them.
const ServedAPITitle = "Kubernetes served-API check against upstream API lists (no clusters)"

// ServedAPIStatement is the fixed wording of the second section.
const ServedAPIStatement = "checked against the API list the target Kubernetes version serves (upstream swagger); not a cluster run; display only"

// OracleSource names the oracle of every row of the second section.
const OracleSource = "upstream swagger of the target Kubernetes tag, pinned by digest"

// Result classes of the second section.
const (
	ClassCorrectPass  = "correct PASS"
	ClassCorrectBlock = "correct BLOCK"
	ClassWrongPass    = "wrong PASS"
	ClassFalseAlarm   = "false alarm"
	ClassGap          = "gap"
	ClassRefusal      = "tool refusal"
)

var classOrder = []string{ClassCorrectPass, ClassCorrectBlock, ClassWrongPass, ClassFalseAlarm, ClassGap, ClassRefusal}

// classInfo maps the recorded class to the public class and to the one verdict
// it may come with. Any other pair is refused.
var classInfo = map[string]struct{ public, verdict string }{
	"correct_pass":  {ClassCorrectPass, "SCOPE_COMPLETE_PASS"},
	"correct_block": {ClassCorrectBlock, "BLOCKED"},
	"wrong_pass":    {ClassWrongPass, "SCOPE_COMPLETE_PASS"},
	"false_alarm":   {ClassFalseAlarm, "BLOCKED"},
	"gap":           {ClassGap, "UNKNOWN"},
	"error":         {ClassRefusal, "NOJSON"},
}

var staticColumns = []string{"run_id", "host", "chart", "chart_version", "k8s_from", "k8s_to", "docs", "unserved_docs", "prufyx_exit", "prufyx_verdict", "blocked_docs", "class", "reasons", "source_cited"}

// staticReasonCodes are the reason codes the static sweep may record.
var staticReasonCodes = map[string]bool{
	"ALPHA_API_NOT_COVERED": true, "API_VERSION_NOT_REVIEWED": true, "API_VERSION_NOT_SERVED": true,
	"DECLARATION_MISSING": true, "DOCUMENTS_NOT_EVALUATED": true, "DOCUMENTS_TEMPLATED": true,
	"LINE_NOT_ATTESTED": true, "RULE_NOT_DECIDED": true,
}

var (
	reChartVersion = regexp.MustCompile(`^(v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})\|(def|opt)$`)
	reMinor        = regexp.MustCompile(`^1\.([0-9]{1,2})$`)
	reRunStatic    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	reTag          = regexp.MustCompile(`^v1\.([0-9]{1,2})\.0$`)
	// The recorded source column is cut at a fixed length, so a link may end early.
	reSourceURL = regexp.MustCompile(`^https://github\.com/kubernetes/kubernetes/blob/([0-9a-f]{1,40})(/[A-Za-z0-9_./-]{0,200})?$`)
	reDigits    = regexp.MustCompile(`^[0-9]{1,6}$`)
)

// OracleList is one pinned upstream swagger.
type OracleList struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
	Sha256 string `json:"swaggerSha256"`
}

// ServedRow is one checked case: only allowlisted fields.
type ServedRow struct {
	Chart   string   `json:"chart"`
	Version string   `json:"chartVersion"`
	From    string   `json:"k8sFrom"`
	To      string   `json:"k8sTo"`
	Class   string   `json:"result"`
	Reasons []string `json:"reasonCodes"`
}

// ServedCount is a count of rows for one key.
type ServedCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// ServedAPIReport is the second section. Its counts stand alone.
type ServedAPIReport struct {
	Title     string        `json:"title"`
	Statement string        `json:"statement"`
	Oracle    string        `json:"oracleSource"`
	Lists     []OracleList  `json:"oracleLists"`
	Rows      int           `json:"rows"`
	Charts    int           `json:"charts"`
	ByClass   []ServedCount `json:"countsByResult"`
	ByReason  []ServedCount `json:"countsByReasonCode"`
	ByHop     []ServedCount `json:"countsByHop"`
	ByChart   []ServedCount `json:"countsByChart"`
	Checks    []ServedRow   `json:"checks"`
}

func minorOf(s string) (int, bool) {
	m := reMinor.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.Atoi(m[1])
	return n, true
}

func readBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxInputSize {
		return nil, errors.New("input is not a regular file of bounded size")
	}
	return os.ReadFile(path)
}

// parseDigests reads lines "<tag> <commit> <sha256>"; any other shape is refused.
func parseDigests(raw []byte) (map[int]OracleList, error) {
	out := map[int]OracleList{}
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		f := strings.Split(line, " ")
		if len(f) != 3 {
			return nil, errors.New("swagger digest line has the wrong shape")
		}
		m := reTag.FindStringSubmatch(f[0])
		if m == nil || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(f[1]) || !reSha.MatchString(f[2]) {
			return nil, errors.New("swagger digest line has an invalid field")
		}
		n, _ := strconv.Atoi(m[1])
		if _, dup := out[n]; dup {
			return nil, errors.New("duplicate swagger digest tag")
		}
		out[n] = OracleList{Tag: f[0], Commit: f[1], Sha256: f[2]}
	}
	if len(out) == 0 {
		return nil, errors.New("no swagger digests")
	}
	return out, nil
}

// BuildServedAPI reads the closed-schema TSV of the static sweep and the pinned
// swagger digest list. Unknown columns, classes, reason codes, versions or
// source links are refused.
func BuildServedAPI(tsvPath, digestPath string) (*ServedAPIReport, error) {
	rawD, err := readBounded(digestPath)
	if err != nil {
		return nil, fmt.Errorf("swagger digests: %v", err)
	}
	digests, err := parseDigests(rawD)
	if err != nil {
		return nil, err
	}
	rawT, err := readBounded(tsvPath)
	if err != nil {
		return nil, fmt.Errorf("served-API results: %v", err)
	}
	if bytes.IndexByte(rawT, '\r') >= 0 {
		return nil, errors.New("served-API results: carriage return")
	}
	lines := strings.Split(strings.TrimRight(string(rawT), "\n"), "\n")
	if strings.Join(strings.Split(lines[0], "\t"), ",") != strings.Join(staticColumns, ",") {
		return nil, errors.New("served-API results: header is not the closed column list")
	}
	rep := &ServedAPIReport{Title: ServedAPITitle, Statement: ServedAPIStatement, Oracle: OracleSource, Checks: []ServedRow{}}
	byClass, byReason, byHop, byChart := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	seen := map[string]bool{}
	used := map[int]bool{}
	for i, line := range lines[1:] {
		bad := func(why string) error { return fmt.Errorf("served-API results: row %d: %s", i+2, why) }
		f := strings.Split(line, "\t")
		if len(f) != len(staticColumns) {
			return nil, bad("wrong number of columns")
		}
		if !reRunStatic.MatchString(f[0]) || f[1] == "" || len(f[1]) > 64 {
			return nil, bad("run id or host field invalid")
		}
		if !reApp.MatchString(f[2]) || f[2] == "*" || f[2] == "?" {
			return nil, bad("chart name outside the pattern")
		}
		cv := reChartVersion.FindStringSubmatch(f[3])
		if cv == nil {
			return nil, bad("chart version outside the pattern")
		}
		from, ok1 := minorOf(f[4])
		to, ok2 := minorOf(f[5])
		if !ok1 || !ok2 || to != from+1 {
			return nil, bad("not a single Kubernetes hop")
		}
		_, ok := digests[to]
		if !ok {
			return nil, bad("no pinned swagger for the target version")
		}
		used[to] = true
		for _, n := range []string{f[6], f[7], f[8]} {
			if !reDigits.MatchString(n) {
				return nil, bad("numeric field invalid")
			}
		}
		info, ok := classInfo[f[11]]
		if !ok {
			return nil, bad("unknown result class")
		}
		if f[9] != info.verdict {
			return nil, bad("verdict does not match the result class")
		}
		parts := strings.Split(f[12], "|")
		if len(parts) != 3 || parts[1] != cv[2] || parts[2] != "served-api-static" {
			return nil, bad("reason field has the wrong shape")
		}
		var codes []string
		if parts[0] != "" {
			codes = strings.Split(parts[0], ",")
		}
		for j, c := range codes {
			if !staticReasonCodes[c] || (j > 0 && codes[j-1] >= c) {
				return nil, bad("unknown or unordered reason code")
			}
		}
		if f[13] != "" {
			for _, u := range strings.Split(f[13], ";") {
				const base = "https://github.com/kubernetes/kubernetes/blob/"
				if len(u) > 0 && len(u) < len(base) && strings.HasPrefix(base, u) {
					continue // cut by the recorded length limit
				}
				m := reSourceURL.FindStringSubmatch(u)
				if m == nil || (len(m[1]) == 40 && !commitKnown(digests, m[1])) || (len(m[1]) < 40 && m[2] != "") {
					return nil, bad("source link outside the pinned upstream")
				}
			}
		}
		if f[10] != "" && info.public != ClassCorrectBlock && info.public != ClassFalseAlarm {
			return nil, bad("blocked documents on a result that is not a block")
		}
		key := strings.Join([]string{f[2], f[3], f[4], f[5]}, "\x00")
		if seen[key] {
			return nil, bad("duplicate case")
		}
		seen[key] = true
		if codes == nil {
			codes = []string{}
		}
		rep.Checks = append(rep.Checks, ServedRow{Chart: f[2], Version: cv[1], From: f[4], To: f[5], Class: info.public, Reasons: codes})
		byClass[info.public]++
		for _, c := range codes {
			byReason[c]++
		}
		byHop[f[4]+" to "+f[5]]++
		byChart[f[2]]++
	}
	if len(rep.Checks) == 0 {
		return nil, errors.New("served-API results: no rows")
	}
	// A case's variant is not published, so rows are unique on the public key
	// only after the variant is dropped: sort and keep both.
	sort.SliceStable(rep.Checks, func(i, j int) bool {
		a, b := rep.Checks[i], rep.Checks[j]
		ka := strings.Join([]string{a.Chart, a.Version, pad(a.From), pad(a.To), a.Class, strings.Join(a.Reasons, ",")}, "\x00")
		kb := strings.Join([]string{b.Chart, b.Version, pad(b.From), pad(b.To), b.Class, strings.Join(b.Reasons, ",")}, "\x00")
		return ka < kb
	})
	var tags []int
	for n := range used {
		tags = append(tags, n)
	}
	sort.Ints(tags)
	for _, n := range tags {
		rep.Lists = append(rep.Lists, digests[n])
	}
	rep.Rows = len(rep.Checks)
	rep.Charts = len(byChart)
	for _, c := range classOrder {
		rep.ByClass = append(rep.ByClass, ServedCount{Key: c, Count: byClass[c]})
	}
	rep.ByReason = sortedCounts(byReason, nil)
	rep.ByHop = sortedCounts(byHop, func(a, b string) bool { return pad(a) < pad(b) })
	rep.ByChart = sortedCounts(byChart, nil)
	return rep, nil
}

func commitKnown(d map[int]OracleList, c string) bool {
	for _, o := range d {
		if o.Commit == c {
			return true
		}
	}
	return false
}

func pad(s string) string {
	if n, ok := minorOf(s); ok {
		return fmt.Sprintf("1.%03d", n)
	}
	return s
}

func sortedCounts(m map[string]int, less func(a, b string) bool) []ServedCount {
	out := make([]ServedCount, 0, len(m))
	for k, v := range m {
		out = append(out, ServedCount{Key: k, Count: v})
	}
	if less == nil {
		less = func(a, b string) bool { return a < b }
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i].Key, out[j].Key) })
	return out
}

func servedMarkdown(s *ServedAPIReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n# %s\n\n%s.\n\n", s.Title, strings.ToUpper(s.Statement[:1])+s.Statement[1:])
	fmt.Fprintf(&b, "Oracle: %s. These counts are separate from the kind runs above and are not added to them.\n\n", s.Oracle)
	fmt.Fprintf(&b, "Counts: %d cases from %d public charts.\n\n| Result | Cases |\n|---|---|\n", s.Rows, s.Charts)
	for _, c := range s.ByClass {
		fmt.Fprintf(&b, "| %s | %d |\n", c.Key, c.Count)
	}
	b.WriteString("\nA gap is not a pass. A tool refusal is a case Prufyx declined to evaluate; it is not a pass either.\n\n")
	section := func(title string, cs []ServedCount) {
		fmt.Fprintf(&b, "## %s\n\n| Key | Cases |\n|---|---|\n", title)
		for _, c := range cs {
			fmt.Fprintf(&b, "| %s | %d |\n", cell(c.Key), c.Count)
		}
		b.WriteString("\n")
	}
	section("Cases per reason code (a case may carry several)", s.ByReason)
	section("Cases per Kubernetes hop", s.ByHop)
	section("Cases per chart", s.ByChart)
	b.WriteString("## Pinned upstream API lists\n\n| Tag | Commit | swagger.json sha256 |\n|---|---|---|\n")
	for _, o := range s.Lists {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", cell(o.Tag), cell(o.Commit), cell(o.Sha256))
	}
	b.WriteString("\nEvery case (chart, chart version, Kubernetes hop, result, reason codes) is listed in `qa-e2e.json` under `servedApi.checks`.\n")
	return b.String()
}
