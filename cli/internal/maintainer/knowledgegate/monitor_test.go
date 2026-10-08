// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// withdrawProject withdraws n active reviewed rules of one project in the
// pack at rel and returns the ids it withdrew.
func withdrawProject(t *testing.T, tr Tree, rel, project string, n int) []string {
	t.Helper()
	var ids []string
	editPack(t, tr, rel, func(p *packDoc) {
		for _, e := range p.entries {
			if len(ids) == n {
				return
			}
			if e["project"] == project && evidenceOf(e)["state"] == "active" {
				evidenceOf(e)["state"] = "withdrawn"
				ids = append(ids, ruleID(e))
			}
		}
	})
	if len(ids) != n {
		t.Fatalf("project %s has fewer than %d active rules", project, n)
	}
	return ids
}

func activeCount(t *testing.T, tr Tree, rel string) int {
	t.Helper()
	n := 0
	for _, e := range readPack(t, tr, rel).entries {
		if evidenceOf(e)["state"] == "active" {
			n++
		}
	}
	return n
}

func hasAlarmKind(r *Report, kind string) bool {
	for _, k := range r.alarmKinds {
		if k == kind {
			return true
		}
	}
	return false
}

func TestWithdrawalThreshold(t *testing.T) {
	for _, tc := range []struct {
		n, total, percent int
		tripped           bool
	}{
		{0, 0, 5, false}, {1, 0, 5, true},
		{5, 100, 5, false}, {6, 100, 5, true}, {4, 100, 5, false},
		{50, 1000, 5, false}, {51, 1000, 5, true},
		{9, 190, 5, false}, {10, 190, 5, true},
		{1, 20, 5, false}, {2, 20, 5, true},
		{100, 100, 100, false},
	} {
		if got := withdrawalTripped(tc.n, tc.total, tc.percent); got != tc.tripped {
			t.Errorf("withdrawalTripped(%d, %d, %d) = %v, want %v", tc.n, tc.total, tc.percent, got, tc.tripped)
		}
	}
}

// A change that withdraws more than the allowed share of a pack, or more
// rules of one project than allowed, fails with an alarm; at the limit it
// passes.
func TestWithdrawalBreaker(t *testing.T) {
	t.Run("pack", func(t *testing.T) {
		base, _ := trees(t)
		active := activeCount(t, base, cncfRulesPath)
		atLimit := active * DefaultMaxWithdrawPercent / 100 // largest n with n/active <= 5 percent
		if withdrawalTripped(atLimit, active, DefaultMaxWithdrawPercent) || !withdrawalTripped(atLimit+1, active, DefaultMaxWithdrawPercent) {
			t.Fatalf("test arithmetic: %d of %d", atLimit, active)
		}
		for _, tc := range []struct {
			name    string
			n       int
			percent int
			fail    bool
		}{
			{"none", 0, 0, false},
			{"one", 1, 0, false},
			{"at the limit", atLimit, 0, false},
			{"one above", atLimit + 1, 0, true},
			{"six percent", (active*6 + 99) / 100, 0, true},
			{"one above, limit raised", atLimit + 1, 10, false},
			{"all, limit 100", active, 100, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				base, head := trees(t)
				// Spread over projects so only the pack breaker can trip.
				editPack(t, head, cncfRulesPath, func(p *packDoc) {
					per := map[any]int{}
					perProject := 5
					if tc.percent == 100 {
						perProject = 1000
					}
					n := 0
					for _, e := range p.entries {
						if n < tc.n && evidenceOf(e)["state"] == "active" && per[e["project"]] < perProject {
							evidenceOf(e)["state"] = "withdrawn"
							per[e["project"]]++
							n++
						}
					}
					if n != tc.n {
						t.Fatalf("withdrew %d of %d", n, tc.n)
					}
				})
				r := runGate(t, Options{Base: base, Head: head, MaxWithdrawPercent: tc.percent, MaxWithdrawProject: 1000})
				if tc.fail {
					requireFail(t, r, "breaker/withdrawals/cncf")
					if !hasAlarmKind(r, AlarmWithdrawPack) {
						t.Fatalf("no pack breaker alarm: %v", r.Alarms)
					}
				} else {
					requirePass(t, r)
					if hasAlarmKind(r, AlarmWithdrawPack) {
						t.Fatalf("alarm without a trip: %v", r.Alarms)
					}
				}
				for _, b := range r.Breakers {
					if b.Kind == BreakerWithdrawPack && b.Subject == "cncf" && (b.Tripped != tc.fail || b.Observed != tc.n || b.Of != active) {
						t.Fatalf("breaker state %+v", b)
					}
				}
			})
		}
	})
	t.Run("project", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			n    int
			max  int
			fail bool
		}{
			{"under", 19, 0, false}, {"at the limit", 20, 0, false}, {"one above", 21, 0, true},
			{"26", 26, 0, true}, {"limit raised", 21, 30, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				base, head := trees(t)
				withdrawProject(t, head, cncfRulesPath, "kubernetes", tc.n)
				// The pack limit is lifted to isolate the project breaker.
				r := runGate(t, Options{Base: base, Head: head, MaxWithdrawPercent: 100, MaxWithdrawProject: tc.max})
				if tc.fail {
					requireFail(t, r, "breaker/withdrawals-project")
					if !hasAlarmKind(r, AlarmWithdrawProj) {
						t.Fatalf("no project alarm: %v", r.Alarms)
					}
				} else {
					requirePass(t, r)
				}
			})
		}
	})
	t.Run("limits subcommand", func(t *testing.T) {
		base, head := trees(t)
		withdrawProject(t, head, cncfRulesPath, "kubernetes", 21)
		lr, err := Limits(Options{Layout: DefaultLayout(), Base: base, Head: head, MaxWithdrawPercent: 100})
		if err != nil || lr.Passed() {
			t.Fatalf("limits must apply the breaker: %v %v", lr.Result, err)
		}
	})
	t.Run("expired and withdrawn-at-birth rules are not withdrawals", func(t *testing.T) {
		base, head := trees(t)
		ids := readPack(t, base, cncfRulesPath).activeReviewed()
		editPack(t, head, cncfRulesPath, func(p *packDoc) {
			for _, id := range ids[:30] {
				ev := evidenceOf(p.find(t, id))
				ev["validUntil"] = shiftTime(t, ev["validUntil"], -time.Hour)
			}
		})
		requirePass(t, runGate(t, Options{Base: base, Head: head}))
	})
}

// With shadow on the report is identical to the enforcing one except for
// the mode and the automatic-merge eligibility, which is false.
func TestShadowMode(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn" })
	strip := func(r *Report) []byte {
		c := *r
		c.Mode, c.AutoMerge = "", AutoMerge{}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	enforce := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	shadow := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin, Shadow: true})
	if !enforce.Passed() || !enforce.AutoMerge.Eligible || enforce.Mode != ModeEnforce {
		t.Fatalf("enforce: pass=%v eligible=%v mode=%q %v", enforce.Passed(), enforce.AutoMerge.Eligible, enforce.Mode, enforce.AutoMerge.Reasons)
	}
	if shadow.Mode != ModeShadow || shadow.AutoMerge.Eligible || !strings.Contains(strings.Join(shadow.AutoMerge.Reasons, " "), "shadow") {
		t.Fatalf("shadow: mode=%q eligible=%v %v", shadow.Mode, shadow.AutoMerge.Eligible, shadow.AutoMerge.Reasons)
	}
	if !bytes.Equal(strip(enforce), strip(shadow)) {
		t.Fatalf("reports differ beyond mode and eligibility:\n%s\n%s", strip(enforce), strip(shadow))
	}
	// A failing change fails the same way in shadow mode.
	editPack(t, head, cncfRulesPath, func(p *packDoc) { ruleOf(p.find(t, ids[1]))["nextAction"] = "Changed." })
	e2 := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin})
	s2 := runGate(t, Options{Base: base, Head: head, Author: DefaultBotLogin, Shadow: true})
	if e2.Passed() || s2.Passed() || !bytes.Equal(strip(e2), strip(s2)) {
		t.Fatalf("a failing change must fail identically in shadow mode: %v %v", e2.Passed(), s2.Passed())
	}
	// Through the command line.
	dir := t.TempDir()
	reportFile := filepath.Join(dir, "r.json")
	commits := filepath.Join(dir, "c.json")
	raw, _ := json.Marshal(botCommits())
	writeFile(t, commits, raw)
	args := []string{"verify", "--base", base.Root, "--head", head.Root, "--now", gateNow.Format(time.RFC3339), "--author", DefaultBotLogin, "--sender", DefaultBotLogin, "--head-sha", testHeadSHA, "--commits", commits, "--daily-loosening-count", "0", "--report", reportFile}
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		ruleOf(p.find(t, ids[1]))["nextAction"] = ruleOf(readPack(t, base, cncfRulesPath).find(t, ids[1]))["nextAction"]
	})
	if code, out := runCLI(t, args...); code != 0 || !strings.Contains(out, "auto-merge: eligible") {
		t.Fatalf("enforce: %d %s", code, out)
	}
	code, out := runCLI(t, append(args, "--shadow")...)
	var rep Report
	data, err := os.ReadFile(reportFile)
	if err != nil || json.Unmarshal(data, &rep) != nil || code != 0 || rep.Mode != ModeShadow || rep.AutoMerge.Eligible || strings.Contains(out, "auto-merge: eligible") {
		t.Fatalf("shadow: %d %v %s", code, err, out)
	}
}

// metricsMust decodes a metrics file strictly and checks it against the
// schema: every member present with its type, nothing else.
func metricsMust(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var generic map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	var typed Metrics
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&typed); err != nil {
		t.Fatalf("metrics do not match the schema: %v", err)
	}
	want := map[string]string{
		"schema": "string", "mode": "string", "result": "string", "paused": "bool", "totals": "object", "classes": "object",
		"projects": "object", "renewals": "number", "withdrawals": "number", "rederivations": "number", "rederivedUnchanged": "number",
		"failures": "object", "limits": "object", "breakers": "array", "alarms": "number", "autoMergeEligible": "bool", "durationMs": "number",
		"restRequests": "number", "couldNotRun": "bool",
	}
	kind := func(v any) string {
		switch v.(type) {
		case string:
			return "string"
		case bool:
			return "bool"
		case json.Number:
			return "number"
		case map[string]any:
			return "object"
		case []any:
			return "array"
		}
		return "other"
	}
	if len(generic) != len(want) {
		t.Fatalf("metrics hold %d members, schema has %d", len(generic), len(want))
	}
	for k, typ := range want {
		v, ok := generic[k]
		if !ok || kind(v) != typ {
			t.Fatalf("metrics member %q: %v (%s), want %s", k, v, kind(v), typ)
		}
	}
	if generic["schema"] != MetricsSchema {
		t.Fatalf("schema %v", generic["schema"])
	}
	// Canonical: re-encoding the generic value reproduces the bytes.
	again, err := json.MarshalIndent(generic, "", "  ")
	if err != nil || !bytes.Equal(append(again, '\n'), raw) {
		t.Fatalf("metrics file is not canonical:\n%s", raw)
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if len(x) > maxMonitorString {
				t.Fatalf("string of %d bytes in metrics", len(x))
			}
		case map[string]any:
			for k, e := range x {
				if len(k) > maxMonitorString {
					t.Fatalf("key of %d bytes in metrics", len(k))
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(generic)
	return generic
}

func TestGateMetrics(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	long := strings.Repeat("p", 400)
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
		ev := evidenceOf(p.find(t, ids[1]))
		ev["validUntil"] = shiftTime(t, ev["validUntil"], -24*time.Hour)
		ev = evidenceOf(p.find(t, ids[2]))
		ev["reviewedAt"] = shiftTime(t, ev["reviewedAt"], 24*time.Hour)
	})
	_ = long
	opts := Options{Base: base, Head: head, Author: DefaultBotLogin}
	r1, r2 := runGate(t, opts), runGate(t, opts)
	m1, err := marshalFile(NewMetrics(r1, 0))
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := marshalFile(NewMetrics(r2, 0))
	if !bytes.Equal(m1, m2) {
		t.Fatalf("metrics differ between identical runs:\n%s\n%s", m1, m2)
	}
	got := metricsMust(t, m1)
	withDuration, _ := marshalFile(NewMetrics(r1, 1500*time.Millisecond))
	if bytes.Equal(withDuration, m1) || !strings.Contains(string(withDuration), `"durationMs": 1500`) {
		t.Fatal("duration not recorded")
	}
	metricsMust(t, withDuration)

	var typed Metrics
	if err := json.Unmarshal(m1, &typed); err != nil {
		t.Fatal(err)
	}
	if typed.Totals.Tightening != 2 || typed.Totals.Loosening != 1 || typed.Withdrawals != 1 || typed.Renewals != 1 || typed.Result != "fail" || typed.Mode != ModeEnforce {
		t.Fatalf("counts %+v", typed)
	}
	if typed.Classes[ClassTightening][KindWithdraw] != 1 || typed.Classes[ClassTightening][KindExpire] != 1 || typed.Classes[ClassLoosening][KindRenew] != 1 {
		t.Fatalf("classes %+v", typed.Classes)
	}
	if typed.Failures.Changes != 1 || typed.Failures.Checks != 0 && typed.Failures.Checks != len(typed.Failures.Names) {
		t.Fatalf("failures %+v", typed.Failures)
	}
	var perProject int
	for _, c := range typed.Projects {
		perProject += c.Tightening + c.Loosening
	}
	if perProject != 3 {
		t.Fatalf("projects %+v", typed.Projects)
	}
	if typed.Limits.MaxLoosening != DefaultMaxLoosening || typed.Limits.MaxDailyLoosening != DefaultMaxDailyLoosening || !typed.Limits.DailyKnown {
		t.Fatalf("limits %+v", typed.Limits)
	}
	if len(typed.Breakers) < 3 {
		t.Fatalf("breakers %+v", typed.Breakers)
	}
	_ = got

	// Hostile strings are cut to 256 bytes and keep the file valid.
	hostile := &Report{Result: "fail", Mode: ModeEnforce, Changes: []*Change{{Project: long + "\n\x00", Class: ClassLoosening, Kinds: []string{KindRenew}}},
		Checks: []Check{{Name: long, OK: false}}, Breakers: []Breaker{{Kind: BreakerWithdrawProject, Subject: long}}}
	raw, err := marshalFile(NewMetrics(hostile, 0))
	if err != nil {
		t.Fatal(err)
	}
	metricsMust(t, raw)
	// Many projects fold into one bucket.
	many := &Report{Mode: ModeEnforce}
	for i := 0; i < maxMetricProject+50; i++ {
		many.Changes = append(many.Changes, &Change{Project: fmt.Sprint("p", i), Class: ClassTightening, Kinds: []string{KindWithdraw}})
	}
	if m := NewMetrics(many, 0); len(m.Projects) != maxMetricProject+1 || m.Projects["(other)"].Tightening != 50 {
		t.Fatalf("project cap: %d", len(m.Projects))
	}
	// Through the command line.
	dir := t.TempDir()
	file := filepath.Join(dir, "gate-metrics.json")
	if code, out := runCLI(t, "verify", "--base", base.Root, "--head", head.Root, "--now", gateNow.Format(time.RFC3339), "--metrics", file); code != 1 {
		t.Fatalf("exit %d %s", code, out)
	}
	cliRaw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	metricsMust(t, cliRaw)
}

func TestGateAlarms(t *testing.T) {
	long := strings.Repeat("p", 400)
	t.Run("every tripped breaker and limit has a record", func(t *testing.T) {
		base, head := trees(t)
		ids := readPack(t, base, cncfRulesPath).activeReviewed()
		withdrawProject(t, head, cncfRulesPath, "kubernetes", 21)
		editPack(t, head, cncfRulesPath, func(p *packDoc) {
			for _, id := range ids[:3] {
				if evidenceOf(p.find(t, id))["state"] == "active" {
					ruleOf(p.find(t, id))["nextAction"] = "Changed."
				}
			}
		})
		five := 5
		r := runGate(t, Options{Base: base, Head: head, MaxLoosening: 2, MaxDailyLoosening: 6, DailyLoosening: &five})
		doc := NewAlarmsDocument(r)
		kinds := map[string]int{}
		for _, a := range doc.Alarms {
			kinds[a.Kind]++
			if len(a.Detail) > maxMonitorString {
				t.Fatalf("alarm of %d bytes", len(a.Detail))
			}
		}
		for _, want := range []string{AlarmLooseningCap, AlarmDailyLimit, AlarmWithdrawPack, AlarmWithdrawProj} {
			if kinds[want] == 0 {
				t.Fatalf("no %s record in %v (alarms %v)", want, kinds, r.Alarms)
			}
		}
		if len(doc.Alarms) != len(r.Alarms) {
			t.Fatalf("%d records for %d alarms", len(doc.Alarms), len(r.Alarms))
		}
		// An alarm only ever accompanies a failing check.
		for _, c := range []string{"limits", "limits/daily", "breaker/withdrawals/cncf", "breaker/withdrawals-project"} {
			if ck, ok := check(r, c); !ok || ck.OK {
				t.Fatalf("check %s: %+v", c, ck)
			}
		}
		raw, err := marshalFile(doc)
		if err != nil {
			t.Fatal(err)
		}
		var back AlarmsDocument
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&back); err != nil || back.Schema != AlarmsSchema || back.Result != "fail" || !reflect.DeepEqual(back.Alarms, doc.Alarms) {
			t.Fatalf("alarms file: %v %+v", err, back)
		}
	})
	t.Run("no alarm without a trip", func(t *testing.T) {
		base, head := trees(t)
		ids := readPack(t, base, cncfRulesPath).activeReviewed()
		editPack(t, head, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn" })
		r := runGate(t, Options{Base: base, Head: head})
		requirePass(t, r)
		if len(r.Alarms) != 0 || len(NewAlarmsDocument(r).Alarms) != 0 {
			t.Fatalf("alarms %v", r.Alarms)
		}
		raw, _ := marshalFile(NewAlarmsDocument(r))
		if !strings.Contains(string(raw), `"alarms": []`) {
			t.Fatalf("empty alarms must be an empty list:\n%s", raw)
		}
	})
	t.Run("hostile text", func(t *testing.T) {
		r := &Report{Result: "fail", Mode: ModeEnforce, HeadSHA: "not a sha\n"}
		r.alarm(AlarmWithdrawProj, "%s", "::set-output name=x::y\n"+long)
		r.alarm(AlarmSize, "%s", strings.Repeat("é", 300))
		doc := NewAlarmsDocument(r)
		if doc.HeadSHA != "" {
			t.Fatal("a head that is not a commit id is not copied")
		}
		for _, a := range doc.Alarms {
			if len(a.Detail) > maxMonitorString || strings.ContainsAny(a.Detail, "\n\r") || strings.HasPrefix(a.Detail, "::") || !json.Valid([]byte(fmt.Sprintf("%q", a.Detail))) {
				t.Fatalf("unsafe alarm %q", a.Detail)
			}
		}
		var md bytes.Buffer
		WriteAlarmsMarkdown(&md, doc)
		if strings.Count(md.String(), "\n- ") != 2 || strings.Contains(md.String(), "<") {
			t.Fatalf("markdown %q", md.String())
		}
	})
	t.Run("command line files", func(t *testing.T) {
		base, head := trees(t)
		withdrawProject(t, head, cncfRulesPath, "kubernetes", 21)
		dir := t.TempDir()
		alarms, md := filepath.Join(dir, "gate-alarms.json"), filepath.Join(dir, "gate-alarms.md")
		code, out := runCLI(t, "verify", "--base", base.Root, "--head", head.Root, "--now", gateNow.Format(time.RFC3339), "--alarms", alarms, "--alarms-markdown", md)
		if code != 1 || !strings.Contains(out, "ALARM withdrawal breaker") {
			t.Fatalf("exit %d %s", code, out)
		}
		raw, _ := os.ReadFile(alarms)
		mdRaw, _ := os.ReadFile(md)
		var doc AlarmsDocument
		if json.Unmarshal(raw, &doc) != nil || len(doc.Alarms) == 0 || !strings.Contains(string(mdRaw), "withdrawal-breaker") {
			t.Fatalf("files: %s / %s", raw, mdRaw)
		}
	})
}

func TestDailyLimit(t *testing.T) {
	base, head := trees(t)
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		for _, id := range ids[:3] {
			ruleOf(p.find(t, id))["nextAction"] = "Changed."
		}
	})
	_, tight := trees(t)
	editPack(t, tight, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn" })
	for _, tc := range []struct {
		name          string
		before, max   int
		fail, tighten bool
	}{
		{"under", 5, 10, false, false},
		{"exactly the cap", 7, 10, false, false},
		{"one over", 8, 10, true, false},
		{"far over", 400, 10, true, false},
		{"nothing before", 0, 3, false, false},
		{"cap smaller than the change", 0, 2, true, false},
		{"tightening is never limited", 1000, 10, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := head
			if tc.tighten {
				h = tight
			}
			before := tc.before
			// The loosening changes fail for lack of a proof; the daily
			// check is read on its own.
			r := runGate(t, Options{Base: base, Head: h, DailyLoosening: &before, MaxDailyLoosening: tc.max})
			c, ok := check(r, "limits/daily")
			if !ok || c.OK == tc.fail {
				t.Fatalf("limits/daily %+v (before %d, cap %d)", c, tc.before, tc.max)
			}
			if r.Daily.OK == tc.fail || !r.Daily.Known || r.Daily.Before != tc.before || r.Daily.Cap != tc.max {
				t.Fatalf("daily %+v", r.Daily)
			}
			if tc.fail != hasAlarmKind(r, AlarmDailyLimit) {
				t.Fatalf("alarm %v for fail=%v", r.Alarms, tc.fail)
			}
			if tc.fail && r.Passed() {
				t.Fatal("over the daily limit but the gate passed")
			}
			if tc.tighten {
				requirePass(t, r)
			}
		})
	}
	t.Run("default cap", func(t *testing.T) {
		n := DefaultMaxDailyLoosening
		r := runGate(t, Options{Base: base, Head: tight, DailyLoosening: &n})
		requirePass(t, r)
		if r.Daily.Cap != 50 {
			t.Fatalf("cap %d", r.Daily.Cap)
		}
	})
	t.Run("count missing: passes, but never eligible", func(t *testing.T) {
		opts := Options{Base: base, Head: tight, Author: DefaultBotLogin, Sender: DefaultBotLogin, HeadSHA: testHeadSHA, Commits: botCommits()}
		r := runGate(t, opts)
		requirePass(t, r)
		if r.Daily.Known || r.AutoMerge.Eligible || !strings.Contains(strings.Join(r.AutoMerge.Reasons, " "), "unknown") {
			t.Fatalf("daily %+v eligible=%v %v", r.Daily, r.AutoMerge.Eligible, r.AutoMerge.Reasons)
		}
		zero := 0
		opts.DailyLoosening = &zero
		if r := runGate(t, opts); !r.AutoMerge.Eligible {
			t.Fatalf("with a count of zero: %v", r.AutoMerge.Reasons)
		}
		// A count of zero is a count; large counts leave tightening eligible.
		big := 100000
		opts.DailyLoosening = &big
		if r := runGate(t, opts); !r.Passed() || !r.AutoMerge.Eligible {
			t.Fatalf("tightening with a large count: %v %v", r.Passed(), r.AutoMerge.Reasons)
		}
	})
}

// makeHistory commits the tree in dir as a new commit and returns its id.
func commitAll(t *testing.T, repo, msg string) string {
	t.Helper()
	gitIn(t, repo, "add", "-A")
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", msg)
	return gitIn(t, repo, "rev-parse", "HEAD")
}

func TestDailyCountFromHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	work, _ := trees(t)
	gitIn(t, work.Root, "init", "-q")
	root := commitAll(t, work.Root, "base")
	ids := readPack(t, work, cncfRulesPath).activeReviewed()
	loosen := func(from, to int) {
		editPack(t, work, cncfRulesPath, func(p *packDoc) {
			for _, id := range ids[from:to] {
				ruleOf(p.find(t, id))["nextAction"] = fmt.Sprintf("Changed %d.", from)
			}
		})
	}
	loosen(0, 2)
	botTwo := commitAll(t, work.Root, "bot loosens two")
	loosen(2, 5)
	humanThree := commitAll(t, work.Root, "human loosens three")
	editPack(t, work, cncfRulesPath, func(p *packDoc) { evidenceOf(p.find(t, ids[10]))["state"] = "withdrawn" })
	botTight := commitAll(t, work.Root, "bot withdraws one")
	loosen(5, 6)
	unknownOne := commitAll(t, work.Root, "unknown author loosens one")
	gitDir := filepath.Join(work.Root, ".git")

	str := func(s string) *string { return &s }
	list := []DailyCommit{
		{SHA: botTwo, Parent: &root, Author: str(DefaultBotLogin)},
		{SHA: humanThree, Parent: &botTwo, Author: str("someone")},
		{SHA: botTight, Parent: &humanThree, Author: str(DefaultBotLogin)},
		{SHA: unknownOne, Parent: &botTight, Author: nil},
	}
	n, err := DailyCount(context.Background(), DefaultLayout(), gitDir, list, DefaultBotLogin)
	if err != nil || n != 3 {
		t.Fatalf("count %d err %v, want 3 (2 by the bot, 1 of unknown author; the person's 3 and the withdrawal do not count)", n, err)
	}
	if n, err := DailyCount(context.Background(), DefaultLayout(), gitDir, nil, ""); err != nil || n != 0 {
		t.Fatalf("empty day: %d %v", n, err)
	}
	// Anything that cannot be classified makes the count fail.
	bad := "0123456789012345678901234567890123456789"
	for name, l := range map[string][]DailyCommit{
		"no parent":        {{SHA: botTwo, Author: str(DefaultBotLogin)}},
		"parent not a sha": {{SHA: botTwo, Parent: str("main"), Author: str(DefaultBotLogin)}},
		"missing object":   {{SHA: bad, Parent: &root, Author: str(DefaultBotLogin)}},
	} {
		if n, err := DailyCount(context.Background(), DefaultLayout(), gitDir, l, DefaultBotLogin); err == nil {
			t.Fatalf("%s: count %d, want an error", name, n)
		}
	}
	// Through the command line.
	dir := t.TempDir()
	rawList, _ := json.Marshal(list)
	file := filepath.Join(dir, "commits.json")
	writeFile(t, file, rawList)
	if code, out := runCLI(t, "daily-count", "--git-dir", gitDir, "--commits", file); code != 0 || strings.TrimSpace(out) != "3" {
		t.Fatalf("daily-count: %d %q", code, out)
	}
	writeFile(t, file, []byte(`[{"sha":"x"}]`))
	if code, _ := runCLI(t, "daily-count", "--git-dir", gitDir, "--commits", file); code != 2 {
		t.Fatalf("bad list exit %d", code)
	}
}

func TestParseDailyCommits(t *testing.T) {
	sha := strings.Repeat("a", 40)
	one := fmt.Sprintf(`[{"sha":%q,"parent":%q,"author":null}]`, sha, sha)
	if l, err := ParseDailyCommits([]byte(one)); err != nil || len(l) != 1 || l[0].Author != nil {
		t.Fatalf("%v %v", l, err)
	}
	for name, raw := range map[string]string{
		"object":           `{}`,
		"short sha":        `[{"sha":"abc"}]`,
		"repeated member":  fmt.Sprintf(`[{"sha":%q,"sha":%q}]`, sha, sha),
		"case variant":     fmt.Sprintf(`[{"sha":%q,"Sha":%q}]`, sha, sha),
		"trailing garbage": one + "x",
		"too many":         "[" + strings.Repeat(fmt.Sprintf(`{"sha":%q},`, sha), MaxDailyCommits) + fmt.Sprintf(`{"sha":%q}]`, sha),
	} {
		if _, err := ParseDailyCommits([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExportOnly(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	gitIn(t, repo, "init", "-q")
	for rel, c := range map[string]string{"a/x.json": "1", "a/b/y.json": "2", "ab/z.json": "3", "top.txt": "4"} {
		writeFile(t, filepath.Join(repo, filepath.FromSlash(rel)), []byte(c))
	}
	commit := commitAll(t, repo, "c")
	out := filepath.Join(t.TempDir(), "e")
	if err := Export(context.Background(), ExportOptions{GitDir: filepath.Join(repo, ".git"), Commit: commit, Out: out, Only: []string{"a/", "top.txt"}}); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]bool{"a/x.json": true, "a/b/y.json": true, "ab/z.json": false, "top.txt": true} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(rel))); (err == nil) != want {
			t.Errorf("%s written=%v, want %v", rel, err == nil, want)
		}
	}
}

// Breakers, the daily limit and shadow mode only ever make the gate
// stricter: over random reports and classifications, a gate that fails
// without them fails with them, and shadow mode never turns an ineligible
// change eligible or changes the result.
func TestBreakersOnlyTighten(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	layout := DefaultLayout()
	projects := []string{"alpha", "beta", "gamma", "delta"}
	kindsFor := map[string][]string{
		ClassTightening: {KindWithdraw, KindExpire, KindAddWithdrawn},
		ClassLoosening:  {KindNew, KindRenew, KindModify, KindReactivate},
	}
	sawTrip, sawPass := false, false
	for i := 0; i < 2000; i++ {
		cls := &Classification{base: map[string]*loadedPack{}}
		for _, spec := range layout.Packs {
			lp := &loadedPack{Spec: spec, Entries: map[string]*entry{}}
			for j, n := 0, rng.Intn(60); j < n; j++ {
				state := "active"
				if rng.Intn(4) == 0 {
					state = "withdrawn"
				}
				lp.Entries[fmt.Sprint("r", j)] = &entry{Evidence: evidenceView{State: state}}
			}
			cls.base[spec.Name] = lp
		}
		for j, n := 0, rng.Intn(40); j < n; j++ {
			class := ClassTightening
			if rng.Intn(3) == 0 {
				class = ClassLoosening
			}
			ks := kindsFor[class]
			c := &Change{Pack: layout.Packs[rng.Intn(len(layout.Packs))].Name, Project: projects[rng.Intn(len(projects))], Class: class, Kinds: []string{ks[rng.Intn(len(ks))]}, OK: true}
			cls.Changes = append(cls.Changes, c)
		}
		opts := Options{Layout: layout}
		opts.MaxWithdrawPercent, opts.MaxWithdrawProject = 1+rng.Intn(20), 1+rng.Intn(10)
		opts.MaxDailyLoosening = 1 + rng.Intn(30)
		if rng.Intn(3) != 0 {
			n := rng.Intn(40)
			opts.DailyLoosening = &n
		}
		opts.Shadow = rng.Intn(2) == 0
		opts.Author, opts.Sender, opts.BotLogin = DefaultBotLogin, DefaultBotLogin, DefaultBotLogin
		opts.HeadSHA, opts.Commits = testHeadSHA, botCommits()
		opts.defaults()

		// Reports as the other checks leave them: random outcomes.
		without := newReport(cls, opts)
		for j, n := 0, rng.Intn(5); j < n; j++ {
			without.add(fmt.Sprint("other", j), rng.Intn(6) != 0, "random")
		}
		with := *without
		with.Checks = append([]Check{}, without.Checks...)
		with.Alarms, with.alarmKinds, with.Breakers = nil, nil, nil
		with.breakerChecks(cls, opts)
		with.dailyCheck(opts)
		without.finish(true)
		with.finish(true)
		if without.Result == "fail" && with.Result == "pass" {
			t.Fatalf("iteration %d: a failing gate passed with the breakers", i)
		}
		if len(with.Checks) <= len(without.Checks) {
			t.Fatal("no breaker check was added")
		}
		// Alarms exactly when something tripped.
		trippedAny := false
		for _, b := range with.Breakers {
			trippedAny = trippedAny || b.Tripped
		}
		if trippedAny && with.Passed() {
			t.Fatalf("iteration %d: a tripped breaker did not fail the gate", i)
		}
		if trippedAny {
			sawTrip = true
		}
		if with.Passed() {
			sawPass = true
		}
		if (len(with.Alarms) > 0) != (trippedAny || !with.Daily.OK) || len(with.Alarms) != len(with.alarmKinds) {
			t.Fatalf("iteration %d: alarms %v vs tripped=%v daily=%+v", i, with.Alarms, trippedAny, with.Daily)
		}

		// Shadow mode: same result, eligibility only lost.
		r := with
		r.ChangedPaths = []string{cncfRulesPath}
		r.Changes = cls.Changes
		enforceOpts, shadowOpts := opts, opts
		enforceOpts.Shadow, shadowOpts.Shadow = false, true
		enforce, shadow := r, r
		enforce.autoMerge(enforceOpts)
		shadow.autoMerge(shadowOpts)
		if shadow.AutoMerge.Eligible || (enforce.AutoMerge.Eligible && !enforce.Passed()) {
			t.Fatalf("iteration %d: shadow eligible=%v, enforce eligible=%v pass=%v", i, shadow.AutoMerge.Eligible, enforce.AutoMerge.Eligible, enforce.Passed())
		}
		if enforce.Result != shadow.Result {
			t.Fatal("shadow mode changed the result")
		}
		// Without a count nothing is eligible.
		noCount := shadowOpts
		noCount.Shadow, noCount.DailyLoosening = false, nil
		nc := r
		nc.autoMerge(noCount)
		if nc.AutoMerge.Eligible {
			t.Fatalf("iteration %d: eligible without a daily count", i)
		}
	}
	if !sawTrip || !sawPass {
		t.Fatalf("the property did not exercise both outcomes (trip=%v pass=%v)", sawTrip, sawPass)
	}
}
