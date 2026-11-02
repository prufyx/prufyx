// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge && prufyx_qa_review

package communityapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

// Observation harness of scripts/qa-auto/review_cases.py (suite "review"). It
// runs only with both build tags and only when QA_REVIEW_OUT names a file:
//
//	QA_REVIEW_OUT=out.json go test -tags 'prufyx_synthetic_knowledge prufyx_qa_review' -run TestQAReviewCrossing ./internal/communityapp/
//
// It asserts nothing. It records the exit code of the same synthetic removal
// crossing rule evaluated through the embedded pack, an explicit store, the
// automatic store choice and `check batch`, so the suite can judge them: a
// crossing BLOCK that only the embedded path reports is a wrong PASS elsewhere.

const (
	qaCortex = "pkg:github/cortexproject/cortex"
	qaThanos = "pkg:github/thanos-io/thanos"
	qaFlag   = "qa-removed-flag"
	qaID     = "cortex.qa-review-crossing.1-8-2-to-1-9-0"
)

type qaProject struct{ slug, comp string }

var (
	qaCortexP = qaProject{"cortex", qaCortex}
	qaThanosP = qaProject{"thanos", qaThanos}
)

func (p qaProject) fact() string { return "component." + p.slug + ".cli_flags_set" }

// qaEntry is a forbid_set_member rule over the project's flag set for 1.8.2 -> 1.9.0.
func qaEntry(p qaProject, id, member string, crossing bool, reviewed, until time.Time) cncfcheck.Entry {
	const rev = "0000000000000000000000000000000000000003"
	cross := ""
	if crossing {
		cross = `"crossing":{"change":{"version":"1.9.0","basis":"REMOVED_IN_RELEASE","sourceId":"release-notes"},"horizon":{"lt":"1.10.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"release-notes"}},`
	}
	rule := `{"id":"` + id + `","operator":"forbid_set_member","subject":{"component":"` + p.comp + `","from":"1.8.2","to":"1.9.0"},` +
		`"setCondition":{"side":"proposed","component":"` + p.comp + `","factId":"` + p.fact() + `","members":["` + member + `"]},` + cross +
		`"evidence":{"state":"active","reviewedAt":"` + reviewed.Format(time.RFC3339) + `","validUntil":"` + until.Format(time.RFC3339) + `","sources":[{"id":"release-notes","url":"https://github.com/` + strings.TrimPrefix(p.comp, "pkg:github/") + `/blob/` + rev + `/CHANGELOG.md","revision":"` + rev + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"RELNOTES_DECLARED_REMOVAL","nextAction":"remove ` + member + ` before upgrading"}`
	return cncfcheck.Entry{Project: p.slug, Description: "Synthetic test-only rule.", RequiredFacts: []cncfcheck.Fact{{Side: "proposed", ID: p.fact(), Component: p.comp, Type: constraintengine.FactSet, Description: "Command-line flags the deployment passes."}}, Rule: json.RawMessage(rule)}
}

func qaInput(p qaProject, member string) string {
	return `{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"` + p.comp + `","version":"1.8.2","facts":[]}]},` +
		`"proposed":{"components":[{"component":"` + p.comp + `","version":"1.9.0","facts":[{"id":"` + p.fact() + `","state":"declared","setValue":{"members":["` + member + `"],"complete":true}}]}]}}`
}

// qaScenario: store is the pack the signed store is built from; embed is the embedded pack the command runs with.
type qaScenario struct {
	name           string
	store, embed   []cncfcheck.Entry
	storeAt, embAt string
	expired        bool
	want           string // block | pass
	modes          string // e (explicit) a (auto) b (batch); default eab
	items          []qaProject
	storeRefused   bool // the store build is expected to be refused (counts as blocked)
}

// qaPinnedNow is the fixed clock of this test, so its output does not depend on the day it runs.
var qaPinnedNow = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func TestQAReviewCrossing(t *testing.T) {
	outPath := os.Getenv("QA_REVIEW_OUT")
	if outPath == "" {
		t.Skip("QA_REVIEW_OUT is not set")
	}
	day := qaPinnedNow.Truncate(24 * time.Hour)
	rv, un := day.AddDate(0, 0, -1), day.AddDate(0, 0, 30)
	plain := qaEntry(qaCortexP, "cortex.qa-review-plain.1-8-2-to-1-9-0", "qa-other-flag", false, rv, un)
	crossing := qaEntry(qaCortexP, qaID, qaFlag, true, rv, un)
	crossing2 := qaEntry(qaCortexP, "cortex.qa-review-crossing2.1-8-2-to-1-9-0", "qa-never-declared", true, rv, un)
	shadow := qaEntry(qaCortexP, qaID, "qa-other-flag", false, rv, un)
	shadowUpper := qaEntry(qaCortexP, strings.ToUpper(qaID), "qa-other-flag", false, rv, un)
	thPlain := qaEntry(qaThanosP, "thanos.qa-review-plain.1-8-2-to-1-9-0", "qa-other-flag", false, rv, un)
	thCross := qaEntry(qaThanosP, "thanos.qa-review-crossing.1-8-2-to-1-9-0", qaFlag, true, rv, un)
	otherPair := qaEntry(qaCortexP, "cortex.qa-review-plain-b.1-8-2-to-1-9-0", "qa-another-flag", false, rv, un)
	const older, same, newer = "2026-10-17T00:00:00Z", "2026-10-29T00:00:00Z", "2026-11-05T00:00:00Z"
	es := func(x ...cncfcheck.Entry) []cncfcheck.Entry { return x }

	res := map[string]any{}
	rec := func(id, want string, code int, stdout, stderr string) {
		text := stdout + stderr
		if len(text) > 300 {
			text = text[:300]
		}
		res[id] = map[string]any{"exit": code, "want": want, "text": text}
	}
	use := func(entries ...cncfcheck.Entry) (func(), error) { return cncfcheck.UseSyntheticKnowledge(nil, entries) }
	writeInputs := func(items []qaProject) map[string]string {
		m := map[string]string{}
		for _, p := range items {
			m[p.slug] = writeCNCFFile(t, p.slug+".json", []byte(qaInput(p, qaFlag)), 0o600)
		}
		return m
	}
	batch := func(items []qaProject, store string) (int, string, string) {
		dir := t.TempDir()
		var parts []string
		for _, p := range items {
			if err := os.WriteFile(filepath.Join(dir, p.slug+".json"), []byte(qaInput(p, qaFlag)), 0o600); err != nil {
				t.Fatal(err)
			}
			parts = append(parts, `{"id":"`+p.slug+`","kind":"cncf","project":"`+p.slug+`","from":"1.8.2","to":"1.9.0","inputPath":"`+p.slug+`.json"}`)
		}
		plan := `{"schema":"prufyx.io/batch-check-plan/v1alpha1","authority":"OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS","knowledge":{"mode":"external_cncf_embedded_community","cncf":"external_signed_local","communityProject":"embedded"},"items":[` + strings.Join(parts, ",") + `]}`
		planPath := filepath.Join(dir, "plan.json")
		if err := os.WriteFile(planPath, []byte(plan), 0o600); err != nil {
			t.Fatal(err)
		}
		return runCNCFCLI(t, "check", "batch", "--plan", planPath, "--root", dir, "--knowledge-db", store, "--format", "json")
	}

	// the embedded control: the crossing rule blocks without any store
	func() {
		restore, err := use(plain, crossing)
		if err != nil {
			t.Fatalf("synthetic knowledge refused: %v", err)
		}
		defer restore()
		in := writeInputs([]qaProject{qaCortexP})
		code, so, se := runCNCFCLI(t, "check", "cncf", "--project", "cortex", "--input", in["cortex"], "--format", "json", "--now", qaPinnedNow.Format(time.RFC3339))
		rec("R1.embedded", "block", code, so, se)
	}()

	scenarios := []qaScenario{
		{name: "base", store: es(plain), embed: es(plain, crossing), want: "block"},
		{name: "store-newer", store: es(plain), embed: es(plain, crossing), storeAt: newer, want: "block"},
		{name: "store-older", store: es(plain), embed: es(plain, crossing), storeAt: older, want: "block"},
		{name: "store-other-rules", store: es(plain, otherPair), embed: es(plain, otherPair, crossing), want: "block"},
		{name: "other-project-crossing", store: es(thPlain), embed: es(thPlain, crossing), want: "pass", items: []qaProject{qaThanosP}}, // thanos: no real rule covers 1.8.2 -> 1.9.0
		{name: "two-crossing-one-passing", store: es(plain), embed: es(plain, crossing, crossing2), want: "block"},
		{name: "mixed-batch", store: es(plain, thPlain), embed: es(plain, crossing, thPlain, thCross), want: "block", modes: "b", items: []qaProject{qaCortexP, qaThanosP}},
		{name: "expired-store", store: es(plain), embed: es(plain, crossing), expired: true, want: "block", modes: "a"},
		{name: "shadow", store: es(shadow), embed: es(plain, crossing), want: "block", modes: "eb"},
		{name: "shadow-upper", store: es(shadowUpper), embed: es(plain, crossing), want: "block", modes: "eb", storeRefused: true},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			useDefaultStoreHome(t)
			autoClock = func() time.Time { return qaPinnedNow }
			if sc.modes == "" {
				sc.modes = "eab"
			}
			if sc.items == nil {
				sc.items = []qaProject{qaCortexP}
			}
			prefix := "R1x." + sc.name
			names := map[string]string{"e": prefix + ".explicit", "a": prefix + ".auto", "b": prefix + ".batch"}
			if sc.name == "base" {
				names = map[string]string{"e": "R1.store-explicit", "a": "R1.auto-store", "b": "R1.batch"}
			}
			if sc.name == "shadow" {
				names = map[string]string{"e": "R1.same-id-shadow", "b": "R1.same-id-shadow-batch"}
			}
			restore, err := use(sc.store...)
			if err != nil {
				if sc.storeRefused {
					for _, m := range sc.modes {
						rec(names[string(m)], sc.want, 3, "synthetic store pack refused: "+err.Error(), "")
					}
					return
				}
				t.Fatalf("store pack refused: %v", err)
			}
			installDefaultStore(t)
			restore()
			restoreEmbed, err := use(sc.embed...)
			if err != nil {
				t.Fatalf("embedded pack refused: %v", err)
			}
			defer restoreEmbed()
			storeAt := sc.storeAt
			if storeAt == "" {
				storeAt = same
			}
			forceComparison(t, storeAt, same, false)
			if sc.expired {
				forceExpired(t)
			}
			store := filepath.Join(os.Getenv("XDG_DATA_HOME"), "prufyx", "knowledge", "cncf-projects")
			in := writeInputs(sc.items)
			base := []string{"check", "cncf", "--project", sc.items[0].slug, "--input", in[sc.items[0].slug], "--format", "json"}
			for _, m := range sc.modes {
				var code int
				var so, se string
				switch m {
				case 'e':
					code, so, se = runCNCFCLI(t, append(base, "--knowledge-db", store)...)
				case 'a':
					code, so, se = runCNCFCLI(t, base...)
				case 'b':
					code, so, se = batch(sc.items, store)
				}
				rec(names[string(m)], sc.want, code, so, se)
			}
		})
	}

	// golden: hops without a crossing rule answer the same with and without a store (shipped knowledge)
	t.Run("golden", func(t *testing.T) {
		useDefaultStoreHome(t)
		autoClock = func() time.Time { return qaPinnedNow }
		installDefaultStore(t)
		forceComparison(t, newer, same, false)
		store := filepath.Join(os.Getenv("XDG_DATA_HOME"), "prufyx", "knowledge", "cncf-projects")
		now := qaPinnedNow.Format(time.RFC3339)
		ky := autoCheckArgs(t, "--format", "json")
		code, so, se := runCNCFCLI(t, append(append([]string{}, ky...), "--knowledge=embedded", "--now", now)...)
		rec("G.kyverno.embedded", "info", code, so, se)
		code, so, se = runCNCFCLI(t, append(append([]string{}, ky...), "--knowledge-db", store)...)
		rec("G.kyverno.explicit", "equal:G.kyverno.embedded", code, so, se)
		code, so, se = runCNCFCLI(t, ky...)
		rec("G.kyverno.auto", "equal:G.kyverno.embedded", code, so, se)
		ing := writeCNCFFile(t, "ing.yaml", []byte("apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: qa\n  namespace: default\nspec:\n  defaultBackend:\n    service:\n      name: s\n      port:\n        number: 80\n"), 0o600)
		k8s := []string{"check", "cncf", "--project", "kubernetes", "--native-resource", ing, "--from", "1.30.0", "--to", "1.31.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete", "--format", "json"}
		code, so, se = runCNCFCLI(t, append(append([]string{}, k8s...), "--now", now)...)
		rec("G.k8s.embedded", "info", code, so, se)
		code, so, se = runCNCFCLI(t, append(append([]string{}, k8s...), "--knowledge-db", store)...)
		rec("G.k8s.explicit", "equal:G.k8s.embedded", code, so, se)
	})

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
