// SPDX-License-Identifier: AGPL-3.0-only

// Package qareport renders the public QA report: the results of Prufyx runs
// against real upgrades on kind clusters, read from the RESULT.json files the
// runs leave behind. The report is display only. It never feeds a verdict.
//
// The inputs are read through a closed schema: an unknown format, an unknown
// schema version, an unknown field, an unknown result form or an unknown reason
// is refused, not skipped. The output is built from an allowlist of fields that
// are each re-validated against a strict pattern; nothing else of the input is
// copied. Equal inputs give equal bytes (no clock, no host data).
package qareport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Schema names the generated JSON document.
const Schema = "prufyx.io/qa-e2e-report/v1"

// Header is the fixed statement printed at the top of the report.
const Header = "Results of Prufyx runs against real upgrades on kind clusters. kind is not production fidelity. Display only: these runs do not change any Prufyx verdict."

// Forms of result of one check against its oracle.
const (
	FormCorrect    = "correct"
	FormWrongPass  = "wrong PASS"
	FormFalseAlarm = "false alarm"
	FormGap        = "gap"
)

const (
	m2bSchema    = "qa-e2e-m2b/RESULT/v1"
	maxInputSize = 4 << 20
	maxRuns      = 200
)

// Counts of checks per form of result.
type Counts struct {
	Correct    int `json:"correct"`
	WrongPass  int `json:"wrongPass"`
	FalseAlarm int `json:"falseAlarm"`
	Gap        int `json:"gap"`
	Rows       int `json:"rows"`
}

func (c *Counts) add(form string) {
	c.Rows++
	switch form {
	case FormCorrect:
		c.Correct++
	case FormWrongPass:
		c.WrongPass++
	case FormFalseAlarm:
		c.FalseAlarm++
	case FormGap:
		c.Gap++
	}
}

// Artifact is one named digest of an input of a check.
type Artifact struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
}

// Check is one row: what Prufyx said against what the oracle observed.
type Check struct {
	App       string     `json:"app"`
	From      string     `json:"from"`
	To        string     `json:"to"`
	Command   string     `json:"command"`
	Result    string     `json:"result"`
	Oracle    string     `json:"oracle"`
	Reason    string     `json:"reason"`
	IDs       []string   `json:"ids"`
	LogDigest string     `json:"logDigest"`
	Artifacts []Artifact `json:"artifacts"`
}

// Run is one kind run.
type Run struct {
	ID            string  `json:"id"`
	K8sFrom       string  `json:"k8sFrom"`
	K8sTo         string  `json:"k8sTo"`
	NodeImageFrom string  `json:"kindNodeImageFrom"`
	NodeImageTo   string  `json:"kindNodeImageTo"`
	PrufyxCommit  string  `json:"prufyxCommit"`
	Counts        Counts  `json:"counts"`
	Checks        []Check `json:"checks"`
}

// NotReportedRun is one run left out by an explicit not-reportable marker.
type NotReportedRun struct {
	ID         string `json:"id"`
	ReasonCode string `json:"reasonCode"`
}

// notReportedCodes is the closed set of reason codes, in report order.
var notReportedCodes = []string{"summary-only", "harness-test", "other"}

func okNotReportedCode(c string) bool {
	for _, k := range notReportedCodes {
		if c == k {
			return true
		}
	}
	return false
}

type notReportedFile struct {
	Reportable *bool  `json:"reportable"`
	ReasonCode string `json:"reason_code"`
}

// notReportedMark reads the explicit opt-out of one run directory: the
// NOT-REPORTED.json marker file, or a top-level "reportable": false in
// RESULT.json (reason code "other"). It returns the reason code, or "" when
// the run is not marked. A malformed marker is refused. A marked run is never
// parsed. The marker's free text is not accepted: unknown keys are refused.
func notReportedMark(runDir string, result []byte) (string, error) {
	p := filepath.Join(runDir, "NOT-REPORTED.json")
	info, lerr := os.Lstat(p)
	code := ""
	if lerr == nil {
		if !info.Mode().IsRegular() || info.Size() > maxInputSize {
			return "", errors.New("NOT-REPORTED.json is not a regular file of bounded size")
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return "", errors.New("cannot read NOT-REPORTED.json")
		}
		var f notReportedFile
		if err := strict(raw, &f); err != nil {
			return "", errors.New("invalid NOT-REPORTED.json")
		}
		if f.Reportable == nil || *f.Reportable || !okNotReportedCode(f.ReasonCode) {
			return "", errors.New("invalid NOT-REPORTED.json: reportable must be false and reason_code one of summary-only, harness-test, other")
		}
		code = f.ReasonCode
	} else if !errors.Is(lerr, os.ErrNotExist) {
		return "", errors.New("cannot read NOT-REPORTED.json")
	}
	if result != nil {
		var probe map[string]json.RawMessage
		if json.Unmarshal(result, &probe) == nil {
			if r, ok := probe["reportable"]; ok {
				var flag bool
				if json.Unmarshal(r, &flag) != nil || flag {
					return "", errors.New("invalid reportable marker in RESULT.json")
				}
				if code == "" {
					code = "other"
				}
			}
		}
	}
	if code != "" {
		if _, err := os.Lstat(filepath.Join(runDir, "SUPERSEDED.json")); err == nil {
			return "", errors.New("run is both not reportable and superseded")
		}
	}
	return code, nil
}

// Report is the whole generated document.
type Report struct {
	Schema string `json:"schema"`
	Header string `json:"header"`
	Counts Counts `json:"counts"`
	// SupersededExcluded counts runs left out because a rerun replaced them;
	// SupersededBy lists the replacing run ids. The recorded reason is never copied.
	SupersededExcluded int      `json:"supersededExcluded"`
	SupersededBy       []string `json:"supersededBy"`
	SupersededRuns     []string `json:"supersededRuns"`
	// NotReported lists runs the operator marked not reportable, by run id and
	// closed reason code only. The marker's free text is never copied.
	NotReported []NotReportedRun `json:"notReported,omitempty"`
	Runs        []Run            `json:"runs"`
	// ServedAPI is the separate served-API section; its counts are never added to the kind counts.
	ServedAPI *ServedAPIReport `json:"servedApi,omitempty"`
}

var (
	reRunID   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	reK8s     = regexp.MustCompile(`^1\.[0-9]{1,2}\.[0-9]{1,2}$`)
	reVersion = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}(\.[0-9]{1,4})?$`)
	reApp     = regexp.MustCompile(`^([a-z0-9][a-z0-9.-]{0,62}|\*|\?)$`)
	reImage   = regexp.MustCompile(`^kindest/node(:v1\.[0-9]{1,2}\.[0-9]{1,2})?@sha256:[0-9a-f]{64}$`)
	reSha     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reCommit  = regexp.MustCompile(`^[0-9a-f]{40}`)
	reArtName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+-]{0,80}$`)
	reCode    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	reRuleID  = regexp.MustCompile(`^kubernetes\.served-api-removal\.[a-z0-9-]{1,80}\.[0-9]+-[0-9]+-[0-9]+-to-[0-9]+-[0-9]+-[0-9]+$`)
)

// deniedOutput are substrings no generated byte may contain: they mark host,
// user or path data, or wording the report must not use.
var deniedOutput = []string{
	"pfspot", "pfgspot", "prod-instance", "192.168.", "airstand", "/home/", "/opt/", "/tmp/", "/root",
	"confirmed", "verified on kubernetes", "every version tested",
}

var reIPv4 = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}`)

var commands = map[string]string{
	"scan":                      "scan",
	"assess":                    "assess",
	"plan":                      "plan",
	"scan+plan":                 "scan+plan",
	"check cert-manager-values": "check-cert-manager-values",
}

var oracleTypes = map[string]string{
	"replay-on-target": "replay-on-target",
	"in-place upgrade": "in-place upgrade",
}

// reasonPrefixes map the start of a recorded verdict to a reason code. The
// recorded text is never copied; only the code is. Longer prefixes first.
var reasonPrefixes = []struct{ prefix, code string }{
	{"BLOCKED ", "BLOCKED"},
	{"NOT CHECKED ", "NOT_CHECKED"},
	{"NO_DATA COMPONENT_NOT_COVERED", "NO_DATA_COMPONENT_NOT_COVERED"},
	{"no path", "NO_PATH"},
	{"not flagged (scan verdict no usable scan output", "NOT_FLAGGED_NO_SCAN_OUTPUT"},
	{"scan failed or produced no usable output", "SCAN_NO_USABLE_OUTPUT"},
	{"scan text output missing or failed", "SCAN_NO_USABLE_OUTPUT"},
	{"no finding for this app (scan verdict UNKNOWN)", "NO_FINDING_SCAN_UNKNOWN"},
	{"no finding for this app's ", "NO_FINDING"},
	{"rc=0: known embedded project", "KNOWN_PROJECT_NO_MATCHING_RULE"},
	{"rc=2: prufyx: invalid CNCF check arguments", "CHECK_INVALID_ARGUMENTS"},
	{"rc=11: UNKNOWN", "UNKNOWN"},
	{"component observed", "COMPONENT_OBSERVED"},
	{"custom resources NOT evaluated", "CUSTOM_RESOURCES_NOT_EVALUATED"},
	{"custom resources evaluated", "CUSTOM_RESOURCES_EVALUATED"},
	{"component not identified by the collector", "COMPONENT_NOT_IDENTIFIED"},
	{"not in observed.components", "NOT_IN_OBSERVED_COMPONENTS"},
	{"assess output missing", "ASSESS_OUTPUT_MISSING"},
	{"cert-manager removed monitor values: UNKNOWN", "UNKNOWN"},
	{"plan: UNKNOWN", "PLAN_UNKNOWN"},
	{"plan: REFUSED", "PLAN_REFUSED"},
	{"stages UNKNOWN", "STAGES_UNKNOWN"},
	{"plan(all apps): REJECTED", "PLAN_REJECTED"},
	{"plan(covered-set): not planned", "NOT_PLANNED"},
	{"plan(covered-set): ", "PLAN_COVERED_SET"},
	{"plan: ", "PLAN_RECORDED"},
}

// reasonPatterns cover verdicts that carry a project name or a count.
var reasonPatterns = []struct {
	re   *regexp.Regexp
	code string
}{
	{regexp.MustCompile(`^[0-9]+ checks? in JSON: `), "ASSESS_CHECKS_IN_JSON"},
	{regexp.MustCompile(`^project [a-z0-9.-]+ absent from the assess JSON`), "PROJECT_ABSENT_FROM_ASSESS"},
	{regexp.MustCompile(`^component [a-z0-9.-]+ refused by the CLI`), "COMPONENT_REFUSED_BY_CLI"},
}

// commandPatterns map a recorded command, which may name a project, to a
// closed command label.
var commandPatterns = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`^catalog checks --project [a-z0-9.-]+ --from --to$`), "catalog-checks"},
	{regexp.MustCompile(`^check cncf --project [a-z0-9.-]+ --from --to$`), "check-cncf"},
	{regexp.MustCompile(`^check project [a-z0-9.-]+ --effective-config$`), "check-project-effective-config"},
	{regexp.MustCompile(`^scan \(oracle A: old apply set on target\)$`), "scan"},
}

func commandLabel(c string) (string, bool) {
	if l, ok := commands[c]; ok {
		return l, true
	}
	for _, p := range commandPatterns {
		if p.re.MatchString(c) {
			return p.label, true
		}
	}
	return "", false
}

func reasonCode(verdict string) (string, error) {
	for _, p := range reasonPatterns {
		if p.re.MatchString(verdict) {
			return p.code, nil
		}
	}
	for _, p := range reasonPrefixes {
		if strings.HasPrefix(verdict, p.prefix) {
			return p.code, nil
		}
	}
	return "", errors.New("unknown verdict form")
}

func form(class string) (string, error) {
	switch class {
	case "correct":
		return FormCorrect, nil
	case "WRONG PASS":
		return FormWrongPass, nil
	case "FALSE ALARM", "false alarm":
		return FormFalseAlarm, nil
	case "gap":
		return FormGap, nil
	}
	return "", errors.New("unknown result form")
}

// ---- closed input shapes ----

type m3File struct {
	RunID              string          `json:"runId"`
	Host               json.RawMessage `json:"host"`
	K8sFrom            string          `json:"k8sFrom"`
	K8sTo              string          `json:"k8sTo"`
	KindVersion        json.RawMessage `json:"kindVersion"`
	Clusters           []m3Cluster     `json:"clusters"`
	Checks             []m3Check       `json:"checks"`
	Logs               json.RawMessage `json:"logs"`
	PrufyxCommit       string          `json:"prufyxCommit"`
	PrufyxCommitSource json.RawMessage `json:"prufyxCommitSource"`
	PrufyxBinary       json.RawMessage `json:"prufyxBinarySha256"`
	StartedAt          json.RawMessage `json:"startedAt"`
	FinishedAt         json.RawMessage `json:"finishedAt"`
	// Converter fields: known, type-checked, never output.
	ConvertedFrom *string `json:"convertedFrom"`
	SummaryFile   *string `json:"summaryFile"`
}

type m3Cluster struct {
	Image string `json:"kindNodeImage"`
	Role  string `json:"role"`
}

type m3Check struct {
	App       string            `json:"app"`
	Artifacts map[string]string `json:"artifactDigests"`
	Assertion struct {
		Command string   `json:"command"`
		IDs     []string `json:"ids"`
		Verdict string   `json:"verdict"`
	} `json:"assertion"`
	Class     string          `json:"class"`
	From      string          `json:"fromVersion"`
	LogDigest string          `json:"logDigest"`
	LogPath   json.RawMessage `json:"logPath"`
	Oracle    struct {
		Observed json.RawMessage `json:"observed"`
		Type     string          `json:"type"`
	} `json:"oracle"`
	Project string `json:"project"`
	Result  string `json:"result"`
	To      string `json:"toVersion"`
	// Converter field: known, type-checked, never output.
	SourceCited *string `json:"sourceCited"`
}

type m2aFile struct {
	RunID         string          `json:"runId"`
	Host          json.RawMessage `json:"host"`
	K8sFrom       string          `json:"k8sFrom"`
	K8sTo         string          `json:"k8sTo"`
	KindFrom      json.RawMessage `json:"kindFrom"`
	KindTo        json.RawMessage `json:"kindTo"`
	NodeImageFrom string          `json:"nodeImageFrom"`
	NodeImageTo   string          `json:"nodeImageTo"`
	PrufyxCommit  string          `json:"prufyxCommit"`
	PrufyxBinary  json.RawMessage `json:"prufyxBinarySha256"`
	PlanAll       json.RawMessage `json:"planAll"`
	PlanVerdict   json.RawMessage `json:"planVerdict"`
	ScanVerdict   json.RawMessage `json:"scanVerdict"`
	Checks        []m2aCheck      `json:"checks"`
	OtherCommands json.RawMessage `json:"otherPrufyxCommands"`
	ImagesPulled  json.RawMessage `json:"imagesPulled"`
}

type m2aCheck struct {
	Project   string            `json:"project"`
	App       string            `json:"app"`
	From      string            `json:"from"`
	To        string            `json:"to"`
	ChartFrom json.RawMessage   `json:"chartFrom"`
	ChartTo   json.RawMessage   `json:"chartTo"`
	Artifacts map[string]string `json:"artifactDigests"`
	Assertion string            `json:"assertion"`
	Oracle    json.RawMessage   `json:"oracle"`
	Result    string            `json:"result"`
	LogDigest string            `json:"logDigest"`
}

type m2bFile struct {
	Schema       string          `json:"schema"`
	RunID        string          `json:"run_id"`
	Host         json.RawMessage `json:"host"`
	K8sFrom      string          `json:"k8s_from"`
	K8sTo        string          `json:"k8s_to"`
	NodeFrom     string          `json:"node_from_image"`
	NodeTo       string          `json:"node_to_image"`
	PrufyxBinary json.RawMessage `json:"prufyx_binary_sha256"`
	PrufyxCommit string          `json:"prufyx_commit"`
	Rows         []m2bRow        `json:"rows"`
	// Informational fields, validated as present JSON and otherwise unused.
	PlanExitAll   json.RawMessage `json:"plan_exit_all_apps"`
	PlanExitCov   json.RawMessage `json:"plan_exit_covered_set"`
	ScanExitCov   json.RawMessage `json:"scan_exit_covered_set"`
	AssessStrict  json.RawMessage `json:"assess_strict_exit"`
	AssessPartial json.RawMessage `json:"assess_partial_exit"`
	KnowledgeRev  json.RawMessage `json:"knowledge_revision"`
	ReplayOld     json.RawMessage `json:"replay_old_docs"`
	ReplayOldRej  json.RawMessage `json:"replay_old_rejected"`
	ReplayCR      json.RawMessage `json:"replay_target_cr_docs"`
	ReplayCRRej   json.RawMessage `json:"replay_target_cr_rejected"`
	ChartDigests  json.RawMessage `json:"chart_manifest_digests"`
	ManifestURLs  json.RawMessage `json:"manifest_urls"`
	ClassCounts   json.RawMessage `json:"class_counts"`
}

type m2bRow struct {
	App     string          `json:"app"`
	From    string          `json:"frm"`
	To      string          `json:"to"`
	Cmd     string          `json:"cmd"`
	Verdict string          `json:"verdict"`
	Oracle  json.RawMessage `json:"oracle"`
	Class   string          `json:"cls"`
	Cite    json.RawMessage `json:"cite"`
}

func strict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("input does not match the closed schema: %v", scrub(err))
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

// scrub keeps decoder errors from echoing input values.
func scrub(err error) string {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return "wrong type for field " + ute.Field
	}
	s := err.Error()
	if strings.HasPrefix(s, "json: unknown field") {
		return "unknown field"
	}
	return "invalid JSON"
}

func okVersion(s string) bool { return s == "" || reVersion.MatchString(s) }

func buildCheck(app, from, to, command, class, oracle, verdict string, ids []string, logDigest string, artifacts map[string]string) (Check, error) {
	var c Check
	var err error
	if !reApp.MatchString(app) {
		return c, errors.New("app outside the allowlist pattern")
	}
	if !okVersion(from) || !okVersion(to) {
		return c, errors.New("version outside the allowlist pattern")
	}
	cmd, ok := commandLabel(command)
	if !ok {
		return c, errors.New("unknown command")
	}
	if c.Result, err = form(class); err != nil {
		return c, err
	}
	if c.Reason, err = reasonCode(verdict); err != nil {
		return c, err
	}
	for _, id := range ids {
		if !reRuleID.MatchString(id) && !reCode.MatchString(id) {
			return c, errors.New("id outside the allowlist patterns")
		}
	}
	if logDigest != "" && !reSha.MatchString(logDigest) {
		return c, errors.New("log digest is not a sha256")
	}
	c.App, c.From, c.To, c.Command, c.Oracle, c.LogDigest = app, from, to, cmd, oracle, logDigest
	c.IDs = append([]string{}, ids...)
	sort.Strings(c.IDs)
	c.Artifacts = []Artifact{}
	for n, d := range artifacts {
		if !reArtName.MatchString(n) || !reSha.MatchString(d) {
			return c, errors.New("artifact entry outside the allowlist patterns")
		}
		c.Artifacts = append(c.Artifacts, Artifact{Name: n, Sha256: d})
	}
	sort.Slice(c.Artifacts, func(i, j int) bool { return c.Artifacts[i].Name < c.Artifacts[j].Name })
	return c, nil
}

func commonRun(id, k8sFrom, k8sTo, imgFrom, imgTo, commit string) (Run, error) {
	r := Run{ID: id}
	if !reRunID.MatchString(id) {
		return r, errors.New("run id outside the allowlist pattern")
	}
	if !reK8s.MatchString(k8sFrom) || !reK8s.MatchString(k8sTo) {
		return r, errors.New("kubernetes version outside the allowlist pattern")
	}
	if !reImage.MatchString(imgFrom) || !reImage.MatchString(imgTo) {
		return r, errors.New("kind node image is not an allowlisted image@digest")
	}
	// The commit may carry a trailing remark in the input; only the leading
	// 40 hex digits are taken and the remark is dropped.
	m := reCommit.FindString(commit)
	if m == "" || (len(commit) > 40 && commit[40] != ' ') {
		return r, errors.New("prufyx commit is not a 40-digit hash")
	}
	r.K8sFrom, r.K8sTo, r.NodeImageFrom, r.NodeImageTo, r.PrufyxCommit = k8sFrom, k8sTo, imgFrom, imgTo, m
	r.Checks = []Check{}
	return r, nil
}

// ParseRun reads one RESULT.json body as the run named id.
func ParseRun(id string, raw []byte) (Run, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Run{}, errors.New("input is not a JSON object")
	}
	switch {
	case probe["schema"] != nil:
		var s string
		if json.Unmarshal(probe["schema"], &s) != nil || s != m2bSchema {
			return Run{}, errors.New("unknown schema version")
		}
		return parseM2b(id, raw)
	case probe["clusters"] != nil:
		return parseM3(id, raw)
	case probe["planAll"] != nil:
		return parseM2a(id, raw)
	}
	return Run{}, errors.New("unknown input format")
}

func parseM3(id string, raw []byte) (Run, error) {
	var f m3File
	if err := strict(raw, &f); err != nil {
		return Run{}, err
	}
	var from, to string
	for _, c := range f.Clusters {
		switch c.Role {
		case "from":
			from = c.Image
		case "to":
			to = c.Image
		default:
			return Run{}, errors.New("unknown cluster role")
		}
	}
	r, err := commonRun(id, f.K8sFrom, f.K8sTo, from, to, f.PrufyxCommit)
	if err != nil {
		return r, err
	}
	for _, c := range f.Checks {
		oracle, ok := oracleTypes[c.Oracle.Type]
		if !ok {
			return r, errors.New("unknown oracle type")
		}
		if err := consistent(c.Class, c.Result); err != nil {
			return r, err
		}
		ck, err := buildCheck(c.App, c.From, c.To, c.Assertion.Command, c.Class, oracle, c.Assertion.Verdict, c.Assertion.IDs, c.LogDigest, c.Artifacts)
		if err != nil {
			return r, err
		}
		r.Checks = append(r.Checks, ck)
	}
	return r, nil
}

func consistent(class, result string) error {
	want := map[string]string{"correct": "confirmed", "WRONG PASS": "refuted", "FALSE ALARM": "refuted", "false alarm": "refuted", "gap": "gap"}
	if w, ok := want[class]; !ok || w != result {
		return errors.New("class and result disagree")
	}
	return nil
}

func parseM2a(id string, raw []byte) (Run, error) {
	var f m2aFile
	if err := strict(raw, &f); err != nil {
		return Run{}, err
	}
	r, err := commonRun(id, f.K8sFrom, f.K8sTo, f.NodeImageFrom, f.NodeImageTo, f.PrufyxCommit)
	if err != nil {
		return r, err
	}
	for _, c := range f.Checks {
		if c.Result != "gap" {
			return r, errors.New("unknown result form")
		}
		app := c.App
		if app == "" {
			app = c.Project
		}
		ck, err := buildCheck(app, c.From, c.To, "plan", c.Result, "unspecified", c.Assertion, nil, c.LogDigest, c.Artifacts)
		if err != nil {
			return r, err
		}
		r.Checks = append(r.Checks, ck)
	}
	return r, nil
}

func parseM2b(id string, raw []byte) (Run, error) {
	var f m2bFile
	if err := strict(raw, &f); err != nil {
		return Run{}, err
	}
	r, err := commonRun(id, f.K8sFrom, f.K8sTo, f.NodeFrom, f.NodeTo, f.PrufyxCommit)
	if err != nil {
		return r, err
	}
	for _, c := range f.Rows {
		if c.Cmd != "plan" {
			return r, errors.New("unknown command")
		}
		ck, err := buildCheck(c.App, c.From, c.To, c.Cmd, c.Class, "unspecified", c.Verdict, nil, "", nil)
		if err != nil {
			return r, err
		}
		r.Checks = append(r.Checks, ck)
	}
	return r, nil
}

type supersededFile struct {
	Superseded   bool   `json:"superseded"`
	SupersededBy string `json:"superseded_by"`
	Reason       string `json:"reason"`
}

// supersededMark reads the supersede markers of one run directory: the
// SUPERSEDED.json file and the superseded/superseded_by/supersede_reason keys
// of RESULT.json. It returns the (validated) replacing run id, or "" when the
// run is not superseded, and the RESULT body without those keys.
func supersededMark(runDir string, result []byte) (by string, rest []byte, err error) {
	rest = result
	marked := false
	if result != nil {
		var probe map[string]json.RawMessage
		if json.Unmarshal(result, &probe) != nil {
			return "", nil, errors.New("input is not a JSON object")
		}
		sup, hasSup := probe["superseded"]
		_, hasBy := probe["superseded_by"]
		_, hasReason := probe["supersede_reason"]
		if hasSup || hasBy || hasReason {
			var flag bool
			if !hasSup || json.Unmarshal(sup, &flag) != nil {
				return "", nil, errors.New("invalid supersede marker")
			}
			if flag {
				marked = true
				if json.Unmarshal(probe["superseded_by"], &by) != nil {
					return "", nil, errors.New("invalid supersede marker")
				}
			}
			delete(probe, "superseded")
			delete(probe, "superseded_by")
			delete(probe, "supersede_reason")
			if rest, err = json.Marshal(probe); err != nil {
				return "", nil, err
			}
		}
	}
	p := filepath.Join(runDir, "SUPERSEDED.json")
	info, lerr := os.Lstat(p)
	if lerr == nil {
		if !info.Mode().IsRegular() || info.Size() > maxInputSize {
			return "", nil, errors.New("SUPERSEDED.json is not a regular file of bounded size")
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return "", nil, errors.New("cannot read SUPERSEDED.json")
		}
		var f supersededFile
		if err := strict(raw, &f); err != nil || !f.Superseded {
			return "", nil, errors.New("invalid SUPERSEDED.json")
		}
		if marked && by != f.SupersededBy {
			return "", nil, errors.New("supersede markers disagree")
		}
		marked, by = true, f.SupersededBy
	} else if !errors.Is(lerr, os.ErrNotExist) {
		return "", nil, errors.New("cannot read SUPERSEDED.json")
	}
	if !marked {
		return "", rest, nil
	}
	if !reRunID.MatchString(by) {
		return "", nil, errors.New("superseded_by is not a run id")
	}
	return by, rest, nil
}

// Build reads every <dir>/<run>/RESULT.json and returns the report. A
// subdirectory without RESULT.json or SUPERSEDED.json is skipped. A superseded
// run is excluded and counted; its replacing run must be a kept run, else the
// input is refused. Anything else unexpected (a symlink, a file that is too
// large, an unknown format) is refused.
func Build(dir string) (*Report, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("cannot read the results directory")
	}
	rep := &Report{Schema: Schema, Header: Header, Runs: []Run{}, SupersededBy: []string{}, SupersededRuns: []string{}}
	var replaced []string
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			return nil, errors.New("symlink in the results directory")
		}
		if !e.IsDir() {
			continue
		}
		runDir := filepath.Join(dir, e.Name())
		path := filepath.Join(runDir, "RESULT.json")
		var raw []byte
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil || !info.Mode().IsRegular() || info.Size() > maxInputSize:
			return nil, fmt.Errorf("run %q: RESULT.json is not a regular file of bounded size", e.Name())
		default:
			if raw, err = os.ReadFile(path); err != nil {
				return nil, fmt.Errorf("run %q: cannot read RESULT.json", e.Name())
			}
		}
		nrCode, err := notReportedMark(runDir, raw)
		if err != nil {
			return nil, fmt.Errorf("run %q: %v", e.Name(), err)
		}
		if nrCode != "" {
			if !reRunID.MatchString(e.Name()) {
				return nil, fmt.Errorf("run %q: directory name outside the run id pattern", e.Name())
			}
			rep.NotReported = append(rep.NotReported, NotReportedRun{ID: e.Name(), ReasonCode: nrCode})
			continue
		}
		by, body, err := supersededMark(runDir, raw)
		if err != nil {
			return nil, fmt.Errorf("run %q: %v", e.Name(), err)
		}
		if by != "" {
			if by == e.Name() {
				return nil, fmt.Errorf("run %q: superseded by itself", e.Name())
			}
			if !reRunID.MatchString(e.Name()) {
				return nil, fmt.Errorf("run %q: directory name outside the run id pattern", e.Name())
			}
			rep.SupersededExcluded++
			rep.SupersededRuns = append(rep.SupersededRuns, e.Name())
			replaced = append(replaced, by)
			continue
		}
		if raw == nil {
			continue
		}
		run, err := ParseRun(e.Name(), body)
		if err != nil {
			return nil, fmt.Errorf("run %q: %v", e.Name(), err)
		}
		sort.SliceStable(run.Checks, func(i, j int) bool {
			a, b := run.Checks[i], run.Checks[j]
			ka := strings.Join([]string{a.App, a.From, a.To, a.Command, a.Reason, strings.Join(a.IDs, ","), a.Result, a.LogDigest}, "\x00")
			kb := strings.Join([]string{b.App, b.From, b.To, b.Command, b.Reason, strings.Join(b.IDs, ","), b.Result, b.LogDigest}, "\x00")
			return ka < kb
		})
		for _, c := range run.Checks {
			run.Counts.add(c.Result)
			rep.Counts.add(c.Result)
		}
		rep.Runs = append(rep.Runs, run)
		if len(rep.Runs) > maxRuns {
			return nil, errors.New("too many runs")
		}
	}
	sort.Slice(rep.Runs, func(i, j int) bool { return rep.Runs[i].ID < rep.Runs[j].ID })
	kept := map[string]bool{}
	for _, r := range rep.Runs {
		kept[r.ID] = true
	}
	seen := map[string]bool{}
	for _, by := range replaced {
		if !kept[by] {
			return nil, errors.New("a superseded run names a replacing run that is not a kept run")
		}
		if !seen[by] {
			seen[by] = true
			rep.SupersededBy = append(rep.SupersededBy, by)
		}
	}
	sort.Strings(rep.SupersededBy)
	sort.Strings(rep.SupersededRuns)
	sort.Slice(rep.NotReported, func(i, j int) bool { return rep.NotReported[i].ID < rep.NotReported[j].ID })
	if len(rep.Runs) == 0 {
		return nil, errors.New("no RESULT.json found")
	}
	return rep, nil
}

// Render returns the JSON and Markdown documents. It refuses output that holds
// a denied substring or an IPv4 address, whatever the input said.
func Render(rep *Report) (jsonDoc, mdDoc []byte, err error) {
	jsonDoc, err = json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	jsonDoc = append(jsonDoc, '\n')
	mdDoc = []byte(markdown(rep))
	for _, doc := range [][]byte{jsonDoc, mdDoc} {
		low := strings.ToLower(string(doc))
		for _, d := range deniedOutput {
			if strings.Contains(low, strings.ToLower(d)) {
				return nil, nil, errors.New("generated output holds a denied string")
			}
		}
		if reIPv4.Match(doc) {
			return nil, nil, errors.New("generated output holds an address")
		}
	}
	return jsonDoc, mdDoc, nil
}

func cell(s string) string {
	if s == "" {
		return "-"
	}
	return "`" + s + "`"
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func markdown(rep *Report) string {
	var b strings.Builder
	b.WriteString("<!-- Generated by prufyx-maintainer qa-report; do not edit by hand. -->\n\n")
	b.WriteString("# QA runs on kind clusters\n\n")
	b.WriteString(rep.Header + "\n\n")
	if len(rep.NotReported) > 0 {
		var parts []string
		for _, code := range notReportedCodes {
			var ids []string
			for _, n := range rep.NotReported {
				if n.ReasonCode == code {
					ids = append(ids, n.ID)
				}
			}
			if len(ids) > 0 {
				parts = append(parts, code+": "+strings.Join(ids, ", "))
			}
		}
		fmt.Fprintf(&b, "Not in this report: %d runs (%s).\n\n", len(rep.NotReported), strings.Join(parts, "; "))
	}
	c := rep.Counts
	fmt.Fprintf(&b, "Counts: %d runs, %d rows: %d correct, %d wrong PASS, %d false alarm, %d gap.\n\n", len(rep.Runs), c.Rows, c.Correct, c.WrongPass, c.FalseAlarm, c.Gap)
	fmt.Fprintf(&b, "Gap rows: %d of %d.\n\n", c.Gap, c.Rows)
	if rep.SupersededExcluded > 0 {
		fmt.Fprintf(&b, "%d superseded runs excluded, replaced by the reruns: %s (excluded: %s).\n\n", rep.SupersededExcluded, strings.Join(rep.SupersededBy, ", "), strings.Join(rep.SupersededRuns, ", "))
	}
	b.WriteString("Forms of result: `correct` means Prufyx and the oracle agree; `wrong PASS` means Prufyx passed what the oracle rejected; `false alarm` means Prufyx blocked what the oracle accepted; `gap` means Prufyx made no claim the oracle could be compared with. A gap is not a pass.\n")
	for _, r := range rep.Runs {
		fmt.Fprintf(&b, "\n## Run `%s`\n\n", r.ID)
		fmt.Fprintf(&b, "- Kubernetes: %s to %s\n", r.K8sFrom, r.K8sTo)
		fmt.Fprintf(&b, "- kind node image from: `%s`\n- kind node image to: `%s`\n", r.NodeImageFrom, r.NodeImageTo)
		fmt.Fprintf(&b, "- Prufyx commit: `%s`\n", r.PrufyxCommit)
		fmt.Fprintf(&b, "- Rows: %d (%d correct, %d wrong PASS, %d false alarm, %d gap)\n\n", r.Counts.Rows, r.Counts.Correct, r.Counts.WrongPass, r.Counts.FalseAlarm, r.Counts.Gap)
		b.WriteString("| App | From | To | Command | Result | Oracle | Reason | Log digest |\n|---|---|---|---|---|---|---|---|\n")
		for _, k := range r.Checks {
			reason := k.Reason
			if len(k.IDs) > 0 {
				reason += " " + strings.Join(k.IDs, " ")
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n", cell(k.App), cell(k.From), cell(k.To), cell(k.Command), k.Result, k.Oracle, cell(reason), cell(short(k.LogDigest)))
		}
	}
	b.WriteString("\nFull digests of logs and inputs are in `qa-e2e.json`.\n")
	if rep.ServedAPI != nil {
		b.WriteString(servedMarkdown(rep.ServedAPI))
	}
	return b.String()
}
