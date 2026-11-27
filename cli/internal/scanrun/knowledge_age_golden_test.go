// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/extract/supersedeids"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// ageClocks are evaluation instants before, inside and after the last
// 30 days of the embedded knowledge's rules, derived from the pack.
var ageClocks = func() []struct{ name, now string } {
	before, inside, after := ageInstants()
	return []struct{ name, now string }{{"before", before}, {"inside", inside}, {"after", after}}
}()

// syntheticEmbedded presents a snapshot over synthetic leases the way the
// embedded knowledge presents itself (origin, revision, pack digest and
// projects), so a report differs from an embedded one only if the knowledge
// answers differently.
type syntheticEmbedded struct {
	Embedded
	real    Embedded
	digests map[string]string
}

func (k syntheticEmbedded) Origin() string     { return k.real.Origin() }
func (k syntheticEmbedded) Revision() string   { return k.real.Revision() }
func (k syntheticEmbedded) PackDigest() string { return k.real.PackDigest() }
func (k syntheticEmbedded) Projects() []string { return k.real.Projects() }

func (k syntheticEmbedded) Evaluate(policy cncfcheck.TrustPolicy, project string, facts []string, inputRaw []byte, now time.Time) (Evaluation, error) {
	digest, ok := k.digests[project]
	if !ok {
		return Evaluation{}, ErrIntegrity
	}
	return evaluateSnapshot(k.ScanKnowledge, "external_declared", digest, policy, project, facts, inputRaw, now)
}

// reviewedByPack is the embedded pack in which every Kubernetes record (rule,
// line review, served-API list, upgrade-path policy) reviewed after the instant
// at is reviewed nine days before it, with an end no later than the shipped one
// and within the longest lease. Every other record is the shipped one. The
// second result counts the records changed.
func reviewedByPack(t *testing.T, at time.Time) ([]byte, int) {
	t.Helper()
	var pack map[string]any
	decoder := json.NewDecoder(bytes.NewReader(embeddedPack(t)))
	decoder.UseNumber()
	if err := decoder.Decode(&pack); err != nil {
		t.Fatal(err)
	}
	parse := func(value any) time.Time {
		text, _ := value.(string)
		parsed, err := time.Parse(time.RFC3339, text)
		if err != nil {
			t.Fatalf("lease time %q: %v", text, err)
		}
		return parsed
	}
	changed := 0
	var move func(node any)
	move = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if _, ok := v["reviewedAt"]; ok && parse(v["reviewedAt"]).After(at) {
				reviewed := at.AddDate(0, 0, -9)
				until := parse(v["validUntil"])
				if longest := reviewed.AddDate(0, 0, 89); longest.Before(until) {
					until = longest
				}
				v["reviewedAt"], v["validUntil"] = reviewed.Format(time.RFC3339), until.Format(time.RFC3339)
				// A mechanical record is reviewed when it is derived.
				if _, ok := v["derivedAt"]; ok {
					v["derivedAt"] = v["reviewedAt"]
				}
				changed++
			}
			for _, child := range v {
				move(child)
			}
		case []any:
			for _, child := range v {
				move(child)
			}
		}
	}
	components := map[string]bool{}
	for _, item := range pack["entries"].([]any) {
		entry := item.(map[string]any)
		if entry["project"] == kubernetesSlug {
			move(entry["rule"])
			components[entry["rule"].(map[string]any)["subject"].(map[string]any)["component"].(string)] = true
		}
	}
	for _, section := range []string{"lineAttestations", "servedAPIs", "pathPolicies"} {
		items, _ := pack[section].([]any)
		for _, item := range items {
			if components[item.(map[string]any)["component"].(string)] {
				move(item)
			}
		}
	}
	out, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	return out, changed
}

// ageKnowledge is the knowledge scanned at a clock of ageClocks: the embedded
// knowledge (nil) when every Kubernetes record is reviewed by then. A renewal
// moves the reviews past the earlier clocks, which follow the earliest end of
// all rules; there the Kubernetes target of reviewedByPack is read, as a
// database's target is.
func ageKnowledge(t *testing.T, now string) Knowledge {
	t.Helper()
	at, err := time.Parse(time.RFC3339, now)
	if err != nil {
		t.Fatal(err)
	}
	pack, changed := reviewedByPack(t, at)
	if changed == 0 {
		return nil
	}
	_, targets, err := cncfcheck.BuildExternalTargetsFromPack(pack, "1")
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	bundles := map[string]cncfcheck.ExternalBundle{}
	digests := map[string]string{}
	for _, target := range targets {
		project, _ := cncfcheck.ProjectFromTargetPath(target.Path)
		if project != kubernetesSlug {
			continue
		}
		external, err := cncfcheck.ParseExternalBundle(target.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", project, err)
		}
		bundles[project], digests[project] = external, external.BundleDigest()
	}
	if len(bundles) != 1 {
		t.Fatalf("targets of %d projects, want 1", len(bundles))
	}
	snapshot, err := cncfcheck.NewStoreScanKnowledge(bundles)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return syntheticEmbedded{Embedded: Embedded{snapshot}, real: LoadEmbeddedForTest(t).(Embedded), digests: digests}
}

// useShippedRuleDigests puts the shipped rule's digest in each finding of a
// report made over synthetic leases. A rule digest covers the rule's lease, so
// it is the one field the synthetic leases change; every other byte is
// compared with the golden file as the scan produced it. shipped is a report
// over the embedded knowledge with the same findings.
func useShippedRuleDigests(t *testing.T, report, shipped scanreport.Report) {
	t.Helper()
	digests := map[string]string{}
	for _, finding := range shipped.Findings {
		digests[finding.RuleID] = finding.RuleDigest
	}
	if len(report.Findings) == 0 || len(report.Findings) != len(digests) {
		t.Fatalf("%d findings over synthetic leases, %d shipped", len(report.Findings), len(digests))
	}
	for i, finding := range report.Findings {
		digest, ok := digests[finding.RuleID]
		if !ok || digest == finding.RuleDigest {
			t.Fatalf("finding %s: no shipped digest to replace", finding.RuleID)
		}
		report.Findings[i].RuleDigest = digest
	}
}

// TestScanOutputUnchangedNearExpiry: stdout in every format and the exit
// code of a scan do not depend on how close the knowledge is to its end: the
// golden files were written before the age note existed and only the clock
// they record differs between them.
func TestScanOutputUnchangedNearExpiry(t *testing.T) {
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	extensions := map[string]string{"human": "txt", "json": "json", "sarif": "sarif", "markdown": "md", "csv": "csv"}
	inDir(t, dir, func() {
		for _, clock := range ageClocks {
			knowledge := ageKnowledge(t, clock.now)
			result := scanAt(t, knowledge, clock.now)
			if result.Exit != scanreport.ExitBlocked && result.Exit != scanreport.ExitUnknown {
				t.Fatalf("%s: exit %d", clock.name, result.Exit)
			}
			if knowledge != nil {
				useShippedRuleDigests(t, result.Report, scanAt(t, nil, supersedeids.ClockString()).Report)
			}
			for _, format := range scanreport.Formats() {
				out, err := scanreport.Render(result.Report, format, scanreport.RenderOptions{Verbose: true, ShowPasses: true})
				if err != nil {
					t.Fatal(err)
				}
				// The inside golden files record the shared clock's
				// placeholder: the two instants coincide until a renewal
				// moves the shared clock past the inside instant, which
				// itself follows the earliest end only.
				if clock.name == "inside" {
					out = bytes.ReplaceAll(out, []byte(clock.now), []byte("2001-01-01T00:00:00Z"))
				}
				golden(t, "knowledge-age-"+clock.name+"."+extensions[format], out)
			}
			golden(t, "knowledge-age-"+clock.name+".exit", []byte{byte('0' + result.Exit/10), byte('0' + result.Exit%10), '\n'})
		}
	})
}

// TestScanClockBeforeReviewStaysUnknown: the shipped knowledge decides nothing
// with a rule at a clock before that rule's review. One second earlier the
// removed CronJob is not reported by the rule and the answer is UNKNOWN naming
// the review; at the review instant the rule blocks.
func TestScanClockBeforeReviewStaysUnknown(t *testing.T) {
	id := supersedeids.ID("kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0")
	var reviewed time.Time
	editPack(t, embeddedPack(t), func(project string, rule map[string]any) bool {
		if rule["id"] == id {
			parsed, err := time.Parse(time.RFC3339, rule["evidence"].(map[string]any)["reviewedAt"].(string))
			if err != nil {
				t.Fatal(err)
			}
			reviewed = parsed
		}
		return true
	})
	if reviewed.IsZero() {
		t.Fatalf("no rule %s", id)
	}
	for name, manifest := range map[string]string{"removed": cronjobV1beta1, "served": cronjobV1} {
		dir, _ := files(t, map[string]string{"applyset.yaml": manifest})
		inDir(t, dir, func() {
			result := scanAt(t, nil, reviewed.Add(-time.Second).Format(time.RFC3339))
			if result.Exit != scanreport.ExitUnknown || result.Report.Verdict == scanreport.VerdictPass {
				t.Fatalf("%s before the review: exit %d verdict %s", name, result.Exit, result.Report.Verdict)
			}
			for _, finding := range result.Report.Findings {
				if finding.RuleID == id {
					t.Fatalf("%s before the review: finding %+v", name, finding)
				}
			}
			named := false
			for _, gap := range result.Report.Gaps {
				named = named || gap.Reason == scanreport.ReasonEvidenceExpired && strings.Contains(gap.Detail, id) && strings.Contains(gap.Detail, "clock_before_review")
			}
			if !named {
				t.Fatalf("%s before the review: gaps %+v", name, result.Report.Gaps)
			}
		})
	}
	dir, _ := files(t, map[string]string{"applyset.yaml": cronjobV1beta1})
	inDir(t, dir, func() {
		result := scanAt(t, nil, reviewed.Format(time.RFC3339))
		if result.Exit != scanreport.ExitBlocked || len(result.Report.Findings) != 1 || result.Report.Findings[0].RuleID != id {
			t.Fatalf("at the review: exit %d findings %+v", result.Exit, result.Report.Findings)
		}
	})
}
