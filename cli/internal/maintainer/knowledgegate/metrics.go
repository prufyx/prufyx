// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode/utf8"
)

// Schemas of the monitoring files.
const (
	MetricsSchema = "prufyx.io/knowledge-gate-metrics/v1"
	AlarmsSchema  = "prufyx.io/knowledge-gate-alarms/v1"
)

// Bounds on the monitoring files: every string is at most 256 bytes, and
// the lists are capped. They hold statistics about knowledge changes only,
// never user data.
const (
	maxMonitorString = 256
	maxMetricProject = 500
	maxMetricNames   = 50
	maxAlarmRecords  = 200
)

// capString cuts s to at most n bytes at a character boundary.
func capString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ProjectCounts counts the changes of one project by class.
type ProjectCounts struct {
	Tightening int `json:"tightening"`
	Loosening  int `json:"loosening"`
}

// MetricsFailures counts what failed.
type MetricsFailures struct {
	Changes int `json:"changes"`
	Checks  int `json:"checks"`
	// Names are the failed checks, sorted, at most 50.
	Names []string `json:"names"`
}

// MetricsLimits reports the limits and how much of each the change used.
type MetricsLimits struct {
	Loosening         int  `json:"loosening"`
	MaxLoosening      int  `json:"maxLoosening"`
	DailyKnown        bool `json:"dailyKnown"`
	DailyBefore       int  `json:"dailyBefore"`
	MaxDailyLoosening int  `json:"maxDailyLoosening"`
}

// Metrics is the per-run metrics file. Apart from DurationMs it is a pure
// function of the report, so two runs over the same input write the same
// bytes.
type Metrics struct {
	Schema string `json:"schema"`
	Mode   string `json:"mode"`
	Result string `json:"result"`
	Paused bool   `json:"paused"`
	Totals Totals `json:"totals"`
	// Classes counts changes by class and kind: a change with two kinds
	// counts once under each.
	Classes  map[string]map[string]int `json:"classes"`
	Projects map[string]ProjectCounts  `json:"projects"`
	// Renewals and Withdrawals count changes of that kind;
	// Rederivations the changed rules admitted by re-derivation, and
	// RederivedUnchanged the rules a --rederive-all run re-derived: every
	// active mechanical rule the change did not already re-derive.
	Renewals           int `json:"renewals"`
	Withdrawals        int `json:"withdrawals"`
	Rederivations      int `json:"rederivations"`
	RederivedUnchanged int `json:"rederivedUnchanged"`
	// Shard is the --rederive-all shard ("" when not re-deriving all);
	// RESTRequests the api.github.com requests the run spent (-1: not
	// counted); CouldNotRun that the budget ran out.
	Shard             string          `json:"shard,omitempty"`
	RESTRequests      int64           `json:"restRequests"`
	CouldNotRun       bool            `json:"couldNotRun"`
	Failures          MetricsFailures `json:"failures"`
	Limits            MetricsLimits   `json:"limits"`
	Breakers          []Breaker       `json:"breakers"`
	Alarms            int             `json:"alarms"`
	AutoMergeEligible bool            `json:"autoMergeEligible"`
	DurationMs        int64           `json:"durationMs"`
}

// NewMetrics derives the metrics of a report; d is the run's duration.
func NewMetrics(r *Report, d time.Duration) Metrics {
	m := Metrics{
		Schema: MetricsSchema, Mode: r.Mode, Result: r.Result, Paused: r.Paused, Totals: r.Totals,
		Classes:  map[string]map[string]int{ClassTightening: {}, ClassLoosening: {}},
		Projects: map[string]ProjectCounts{},
		Failures: MetricsFailures{Names: []string{}}, RederivedUnchanged: r.rederivedUnchanged,
		Limits: MetricsLimits{
			Loosening: r.Limits.Loosening, MaxLoosening: r.Limits.MaxLoosening,
			DailyKnown: r.Daily.Known, DailyBefore: r.Daily.Before, MaxDailyLoosening: r.Daily.Cap,
		},
		Breakers: append([]Breaker{}, r.Breakers...), Alarms: len(r.Alarms), AutoMergeEligible: r.AutoMerge.Eligible,
		DurationMs: d.Milliseconds(), Shard: r.Shard, RESTRequests: -1, CouldNotRun: r.CouldNotRun != "",
	}
	if r.Upstream != nil {
		m.RESTRequests = r.Upstream.RESTRequests
	}
	for i := range m.Breakers {
		m.Breakers[i].Subject = capString(m.Breakers[i].Subject, maxMonitorString)
	}
	for _, c := range r.Changes {
		for _, k := range c.Kinds {
			m.Classes[c.Class][k]++
		}
		key := capString(c.Project, maxMonitorString)
		if _, ok := m.Projects[key]; !ok && len(m.Projects) >= maxMetricProject {
			key = "(other)"
		}
		p := m.Projects[key]
		if c.Class == ClassLoosening {
			p.Loosening++
		} else {
			p.Tightening++
		}
		m.Projects[key] = p
		if containsKind(c.Kinds, KindRenew) {
			m.Renewals++
		}
		if containsKind(c.Kinds, KindWithdraw) {
			m.Withdrawals++
		}
		if c.Proof == ProofRederived {
			m.Rederivations++
		}
		if !c.OK {
			m.Failures.Changes++
		}
	}
	for _, c := range r.Checks {
		if !c.OK {
			m.Failures.Checks++
			m.Failures.Names = append(m.Failures.Names, capString(c.Name, maxMonitorString))
		}
	}
	sort.Strings(m.Failures.Names)
	if len(m.Failures.Names) > maxMetricNames {
		m.Failures.Names = m.Failures.Names[:maxMetricNames]
	}
	return m
}

// AlarmRecord is one alarm in the alarms file.
type AlarmRecord struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// AlarmsDocument is the alarms file.
type AlarmsDocument struct {
	Schema  string        `json:"schema"`
	Mode    string        `json:"mode"`
	Result  string        `json:"result"`
	HeadSHA string        `json:"headSha,omitempty"`
	Alarms  []AlarmRecord `json:"alarms"`
	// Truncated is true when more alarms were raised than the file holds.
	Truncated bool `json:"truncated"`
}

// NewAlarmsDocument lists the report's alarms, each with its kind. Details
// derived from the proposed change are made safe to print and cut to 256
// bytes.
func NewAlarmsDocument(r *Report) AlarmsDocument {
	doc := AlarmsDocument{Schema: AlarmsSchema, Mode: r.Mode, Result: r.Result, Alarms: []AlarmRecord{}}
	if shaRE.MatchString(r.HeadSHA) {
		doc.HeadSHA = r.HeadSHA
	}
	for i, a := range r.Alarms {
		if len(doc.Alarms) >= maxAlarmRecords {
			doc.Truncated = true
			break
		}
		kind := "alarm"
		if i < len(r.alarmKinds) {
			kind = r.alarmKinds[i]
		}
		doc.Alarms = append(doc.Alarms, AlarmRecord{Kind: kind, Detail: capString(logSafe(a), maxMonitorString)})
	}
	return doc
}

// WriteAlarmsMarkdown writes the alarms as a Markdown list for an issue.
func WriteAlarmsMarkdown(w io.Writer, doc AlarmsDocument) {
	fmt.Fprintf(w, "Knowledge gate alarms (result %s, mode %s).\n\n", mdEscape(doc.Result), mdEscape(doc.Mode))
	for _, a := range doc.Alarms {
		fmt.Fprintf(w, "- %s: %s\n", mdEscape(a.Kind), mdEscape(a.Detail))
	}
	if doc.Truncated {
		fmt.Fprintln(w, "- more alarms were raised than are listed here")
	}
	if doc.HeadSHA != "" {
		fmt.Fprintf(w, "\nCommit: %s\n", doc.HeadSHA)
	}
}

// marshalFile encodes a monitoring file: indented, sorted map keys, one
// trailing newline.
func marshalFile(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Through a generic value, whose members encoding/json writes in
	// sorted order at every depth: the file is canonical whatever order
	// the structs declare their fields in.
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	raw, err = json.MarshalIndent(generic, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
