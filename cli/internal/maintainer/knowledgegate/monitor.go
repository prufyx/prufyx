// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"fmt"
	"sort"

	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// Modes of a gate run.
const (
	ModeEnforce = "enforce"
	ModeShadow  = "shadow"
)

// Alarm kinds.
const (
	AlarmLooseningCap = "loosening-cap"
	AlarmDailyLimit   = "daily-limit"
	AlarmWithdrawPack = "withdrawal-breaker-pack"
	AlarmWithdrawProj = "withdrawal-breaker-project"
	AlarmSize         = "size"
)

// Breaker kinds.
const (
	BreakerWithdrawPack    = "withdrawal-pack"
	BreakerWithdrawProject = "withdrawal-project"
)

// Breaker is the state of one circuit breaker. A breaker can only make the
// gate stricter: a tripped one fails the run, an untripped one changes
// nothing.
type Breaker struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	// Observed is the number of rules this change withdraws. Of is the
	// number of active rules of the pack in the base (pack breakers only).
	// Limit is a percent of Of for a pack breaker, a count for a project
	// breaker.
	Observed int  `json:"observed"`
	Of       int  `json:"of,omitempty"`
	Limit    int  `json:"limit"`
	Tripped  bool `json:"tripped"`
}

// DailyReport reports the per-day loosening limit.
type DailyReport struct {
	// Known is false when the caller did not supply the count of loosening
	// changes merged by the automation in the last day.
	Known  bool `json:"known"`
	Before int  `json:"before"`
	Change int  `json:"change"`
	Cap    int  `json:"cap"`
	OK     bool `json:"ok"`
}

// alarm records an alarm of the given kind.
func (r *Report) alarm(kind, format string, args ...any) {
	r.Alarms = append(r.Alarms, fmt.Sprintf(format, args...))
	r.alarmKinds = append(r.alarmKinds, kind)
}

// withdrawalTripped reports whether withdrawing n of total active rules
// exceeds percent. Integer arithmetic: n/total > percent/100.
func withdrawalTripped(n, total, percent int) bool {
	return n*100 > percent*total
}

// breakerChecks applies the withdrawal breakers: a change that withdraws
// more than MaxWithdrawPercent of a pack's active rules (as the base has
// them), or more than MaxWithdrawProject rules of one project, fails and
// raises an alarm. Withdrawing is tightening, so without a breaker one
// change could silently switch off a whole pack's checks.
func (r *Report) breakerChecks(cls *Classification, opts Options) {
	perPack := map[string]int{}
	perProject := map[string]int{}
	recordsPerPack := map[string]int{}
	for _, c := range cls.Changes {
		switch {
		case c.Section != "" && withdrawsRecord(c):
			// A record switched off: a path policy withdrawn, a line
			// attestation removed. Counted apart from rules, so the
			// rule breaker is unchanged by records.
			recordsPerPack[c.Pack]++
			perProject[c.Project]++
		case c.Section == "" && containsKind(c.Kinds, KindWithdraw):
			perPack[c.Pack]++
			perProject[c.Project]++
		}
	}
	packs := make([]string, 0, len(opts.Layout.Packs))
	for _, spec := range opts.Layout.Packs {
		packs = append(packs, spec.Name)
	}
	sort.Strings(packs)
	for _, name := range packs {
		active := 0
		if b := cls.base[name]; b != nil {
			for _, e := range b.Entries {
				if e.Evidence.State == "active" {
					active++
				}
			}
		}
		n := perPack[name]
		b := Breaker{Kind: BreakerWithdrawPack, Subject: name, Observed: n, Of: active, Limit: opts.MaxWithdrawPercent}
		b.Tripped = withdrawalTripped(n, active, opts.MaxWithdrawPercent)
		r.Breakers = append(r.Breakers, b)
		r.add("breaker/withdrawals/"+name, !b.Tripped, "%d of %d active rules withdrawn, breaker above %d percent", n, active, opts.MaxWithdrawPercent)
		if b.Tripped {
			r.alarm(AlarmWithdrawPack, "withdrawal breaker: %d of %d active rules of pack %s withdrawn, above %d percent; nothing is published", n, active, name, opts.MaxWithdrawPercent)
		}
		r.recordBreaker(cls, name, recordsPerPack[name], opts)
	}
	projects := make([]string, 0, len(perProject))
	for p := range perProject {
		projects = append(projects, p)
	}
	sort.Strings(projects)
	var tripped []string
	for _, p := range projects {
		b := Breaker{Kind: BreakerWithdrawProject, Subject: capString(p, maxMonitorString), Observed: perProject[p], Limit: opts.MaxWithdrawProject}
		b.Tripped = b.Observed > opts.MaxWithdrawProject
		r.Breakers = append(r.Breakers, b)
		if b.Tripped {
			tripped = append(tripped, fmt.Sprintf("%s: %d", logSafe(p), b.Observed))
			r.alarm(AlarmWithdrawProj, "withdrawal breaker: %d rules of project %s withdrawn, above %d; nothing is published", b.Observed, logSafe(p), opts.MaxWithdrawProject)
		}
	}
	r.add("breaker/withdrawals-project", len(tripped) == 0, "%d projects with withdrawals, breaker above %d rules of one project%s", len(projects), opts.MaxWithdrawProject, listDetail(tripped))
}

// dailyCheck applies the per-day loosening limit: the loosening changes the
// automation already merged in the last day (counted by the caller from
// the main branch's history) plus this change may not exceed the cap. An
// unknown count passes this check but makes the change ineligible for
// automatic merging; it is never read as zero.
func (r *Report) dailyCheck(opts Options) {
	d := DailyReport{Change: r.Totals.Loosening, Cap: opts.MaxDailyLoosening}
	if opts.DailyLoosening == nil {
		d.OK = true
		r.Daily = d
		r.add("limits/daily", true, "the number of loosening changes merged in the last day was not supplied; the change is not eligible for automatic merging")
		return
	}
	d.Known, d.Before = true, *opts.DailyLoosening
	// A change that loosens nothing never counts against the limit:
	// tightening must always be able to pass.
	d.OK = d.Change == 0 || d.Before+d.Change <= d.Cap
	r.Daily = d
	r.add("limits/daily", d.OK, "%d merged in the last day plus %d in this change, cap %d", d.Before, d.Change, d.Cap)
	if !d.OK {
		r.alarm(AlarmDailyLimit, "daily loosening limit exceeded: %d merged in the last day plus %d in this change is above %d", d.Before, d.Change, d.Cap)
	}
}

// Breaker kind for records.
const BreakerWithdrawRecords = "withdrawal-records"

// withdrawsRecord reports whether a record change switches a record off:
// a line attestation removed or a path policy withdrawn.
func withdrawsRecord(c *Change) bool {
	return c.Class == ClassTightening && (containsKind(c.Kinds, KindWithdraw) || (c.Section == sectionAttestations && containsKind(c.Kinds, KindRemove)))
}

// recordBreaker is the pack breaker for records: a change that switches
// off records (removes line attestations, withdraws path policies) of more
// than MaxWithdrawPercent of the pack's active items fails. The active
// items are the base's active rules and active records together, so a pack
// with few records may still lose one; the rule breaker above counts rules
// alone and is unchanged by records. It is reported only for a pack that
// holds records.
func (r *Report) recordBreaker(cls *Classification, name string, n int, opts Options) {
	b := cls.base[name]
	if b == nil || !b.Spec.Records || (len(b.Records) == 0 && n == 0) {
		return
	}
	active := 0
	for _, e := range b.Entries {
		if e.Evidence.State == "active" {
			active++
		}
	}
	for _, rec := range b.Records {
		if rec.State == upgradepath.StateActive {
			active++
		}
	}
	br := Breaker{Kind: BreakerWithdrawRecords, Subject: name, Observed: n, Of: active, Limit: opts.MaxWithdrawPercent}
	br.Tripped = withdrawalTripped(n, active, opts.MaxWithdrawPercent)
	r.Breakers = append(r.Breakers, br)
	r.add("breaker/withdrawals/"+name+"/records", !br.Tripped, "%d records switched off of %d active rules and records, breaker above %d percent", n, active, opts.MaxWithdrawPercent)
	if br.Tripped {
		r.alarm(AlarmWithdrawPack, "withdrawal breaker: %d records of pack %s switched off, of %d active rules and records, above %d percent; nothing is published", n, name, active, opts.MaxWithdrawPercent)
	}
}
