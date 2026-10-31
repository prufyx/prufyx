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
	qaFact   = "component.cortex.cli_flags_set"
	qaFlag   = "qa-removed-flag"
	qaID     = "cortex.qa-review-crossing.1-8-2-to-1-9-0"
)

func qaEntry(id, operator, extra, facts string, reviewed, until time.Time) cncfcheck.Entry {
	const rev = "0000000000000000000000000000000000000003"
	rule := `{"id":"` + id + `","operator":"` + operator + `","subject":{"component":"` + qaCortex + `","from":"1.8.2","to":"1.9.0"},` + extra +
		`"evidence":{"state":"active","reviewedAt":"` + reviewed.Format(time.RFC3339) + `","validUntil":"` + until.Format(time.RFC3339) + `","sources":[{"id":"release-notes","url":"https://github.com/cortexproject/cortex/blob/` + rev + `/CHANGELOG.md","revision":"` + rev + `","contentDigest":"sha256:` + strings.Repeat("0", 64) + `","startLine":1,"endLine":2}]},` +
		`"reasonCode":"RELNOTES_DECLARED_REMOVAL","nextAction":"remove ` + qaFlag + ` before upgrading"}`
	var required []cncfcheck.Fact
	if facts != "" {
		required = []cncfcheck.Fact{{Side: "proposed", ID: qaFact, Component: qaCortex, Type: constraintengine.FactSet, Description: "Command-line flags the deployment passes."}}
	}
	return cncfcheck.Entry{Project: "cortex", Description: "Synthetic test-only rule.", RequiredFacts: required, Rule: json.RawMessage(rule)}
}

func qaOutcome(t *testing.T, res map[string]any, id string, code int, stdout, stderr string) {
	t.Helper()
	text := stdout + stderr
	if len(text) > 400 {
		text = text[:400]
	}
	res[id] = map[string]any{"exit": code, "text": text}
}

func TestQAReviewCrossing(t *testing.T) {
	outPath := os.Getenv("QA_REVIEW_OUT")
	if outPath == "" {
		t.Skip("QA_REVIEW_OUT is not set")
	}
	day := time.Now().UTC().Truncate(24 * time.Hour)
	reviewed, until := day.AddDate(0, 0, -1), day.AddDate(0, 0, 30)
	// pass decides the pair on its own; crossing blocks when the flag is declared;
	// shadow is a non-crossing rule with the crossing rule's id.
	pass := qaEntry("cortex.qa-review-pass.1-8-2-to-1-9-0", "require_component_version",
		`"dependency":{"side":"proposed","component":"`+qaCortex+`","comparison":"gte","version":"1.9.0"},`, "", reviewed, until)
	crossing := qaEntry(qaID, "forbid_set_member",
		`"setCondition":{"side":"proposed","component":"`+qaCortex+`","factId":"`+qaFact+`","members":["`+qaFlag+`"]},`+
			`"crossing":{"change":{"version":"1.9.0","basis":"REMOVED_IN_RELEASE","sourceId":"release-notes"},"horizon":{"lt":"1.10.0","basis":"REVIEWED_THROUGH_MINOR_LINE","sourceId":"release-notes"}},`, "x", reviewed, until)
	shadow := qaEntry(qaID, "forbid_set_member",
		`"setCondition":{"side":"proposed","component":"`+qaCortex+`","factId":"`+qaFact+`","members":["qa-other-flag"]},`, "x", reviewed, until)

	input := `{"schema":"` + constraintengine.InputSchema + `","authority":"` + constraintengine.InputAuthority + `","current":{"components":[{"component":"` + qaCortex + `","version":"1.8.2","facts":[]}]},` +
		`"proposed":{"components":[{"component":"` + qaCortex + `","version":"1.9.0","facts":[{"id":"` + qaFact + `","state":"declared","setValue":{"members":["` + qaFlag + `"],"complete":true}}]}]}}`
	inputPath := writeCNCFFile(t, "input.json", []byte(input), 0o600)
	now := time.Now().UTC().Format(time.RFC3339)
	res := map[string]any{}
	use := func(entries ...cncfcheck.Entry) func() {
		restore, err := cncfcheck.UseSyntheticKnowledge(nil, entries)
		if err != nil {
			t.Fatalf("synthetic knowledge refused: %v", err)
		}
		return restore
	}
	check := func(id string, extra ...string) {
		args := append([]string{"check", "cncf", "--project", "cortex", "--input", inputPath, "--format", "json"}, extra...)
		code, stdout, stderr := runCNCFCLI(t, args...)
		qaOutcome(t, res, id, code, stdout, stderr)
	}
	batch := func(id, store string) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "input.json"), []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		plan := `{"schema":"prufyx.io/batch-check-plan/v1alpha1","authority":"OPERATOR_DECLARED_LOCAL_CANONICAL_INPUTS","knowledge":{"mode":"external_cncf_embedded_community","cncf":"external_signed_local","communityProject":"embedded"},"items":[{"id":"a","kind":"cncf","project":"cortex","from":"1.8.2","to":"1.9.0","inputPath":"input.json"}]}`
		planPath := filepath.Join(dir, "plan.json")
		if err := os.WriteFile(planPath, []byte(plan), 0o600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runCNCFCLI(t, "check", "batch", "--plan", planPath, "--root", dir, "--knowledge-db", store, "--format", "json")
		qaOutcome(t, res, id, code, stdout, stderr)
	}
	// withStore installs a store built from storeEntries, then evaluates under pass+crossing.
	withStore := func(name string, storeEntries []cncfcheck.Entry, run func(store string)) {
		t.Run(name, func(t *testing.T) {
			useDefaultStoreHome(t)
			autoClock = func() time.Time { return time.Now().UTC() }
			restore := use(storeEntries...)
			installDefaultStore(t)
			restore()
			defer use(pass, crossing)()
			forceComparison(t, "2026-10-29T00:00:00Z", "2026-10-29T00:00:00Z", false)
			run(filepath.Join(os.Getenv("XDG_DATA_HOME"), "prufyx", "knowledge", "cncf-projects"))
		})
	}

	func() {
		defer use(pass, crossing)()
		check("R1.embedded", "--now", now)
	}()
	withStore("clean-store", []cncfcheck.Entry{pass}, func(store string) {
		check("R1.store-explicit", "--knowledge-db", store)
		check("R1.auto-store")
		batch("R1.batch", store)
	})
	withStore("shadow-store", []cncfcheck.Entry{shadow}, func(store string) {
		check("R1.same-id-shadow", "--knowledge-db", store)
		batch("R1.same-id-shadow-batch", store)
	})

	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
