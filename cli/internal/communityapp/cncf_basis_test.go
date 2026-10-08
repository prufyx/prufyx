// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/constraintengine"
)

const containerdCanonicalInput = `{"schema":"prufyx.io/operator-declared-constraint-input/v1alpha1","authority":"OPERATOR_DECLARED_MINIMIZED","current":{"components":[{"component":"pkg:github/containerd/containerd","version":"1.7.28","facts":[]}]},"proposed":{"components":[{"component":"pkg:github/containerd/containerd","version":"2.0.0","facts":[{"id":"component.containerd.cri_api","state":"declared","enumValue":"v1"},{"id":"component.containerd.official_bundled_runtimes_only","state":"declared","boolValue":true},{"id":"component.containerd.official_upstream_distribution","state":"declared","boolValue":true},{"id":"component.containerd.selected_runtime_uses_removed_official_shim","state":"declared","boolValue":false}]}]}}`

// TestRequireBasisFlag: the default policy, and any policy that admits every
// shipped rule, reproduce today's output byte for byte; a policy that leaves
// rules out says so in JSON and human output and never exits 0; an invalid
// list is a usage error.
func TestRequireBasisFlag(t *testing.T) {
	t.Parallel()
	const now = "2026-09-20T00:00:00Z"
	input := writeCNCFFile(t, "input.json", []byte(containerdCanonicalInput), 0o600)
	config := writeCNCFFile(t, "config.toml", containerdNativeTOML("2", "io.containerd.grpc.v1.cri", "selected", "io.containerd.runc.v2", ""), 0o600)
	routes := map[string][]string{
		"generic": {"check", "cncf", "--project", "containerd", "--input", input, "--now", now},
		"native":  containerdCheckArgs(config, "selected", now)[:len(containerdCheckArgs(config, "selected", now))-2],
	}
	for name, base := range routes {
		for _, format := range []string{"human", "json"} {
			args := append(append([]string(nil), base...), "--format", format)
			code, want, stderr := runCNCFCLI(t, args...)
			if code != ExitOK || stderr != "" {
				t.Fatalf("%s %s: default code=%d stderr=%s stdout=%s", name, format, code, stderr, want)
			}
			if strings.Contains(want, "trust policy") || strings.Contains(want, "trustPolicy") || strings.Contains(want, "model consensus") {
				t.Fatalf("%s %s: default output mentions the policy:\n%s", name, format, want)
			}
			for _, list := range []string{"reviewed", "reviewed,mechanical,empirical,consensus", "lead,consensus,empirical,mechanical,reviewed"} {
				code, got, stderr := runCNCFCLI(t, append(args, "--require-basis", list)...)
				if code != ExitOK || stderr != "" || got != want {
					t.Fatalf("%s %s --require-basis %s: code=%d stderr=%s\n%s\nwant\n%s", name, format, list, code, stderr, got, want)
				}
			}
			code, got, stderr := runCNCFCLI(t, append(args, "--require-basis", "mechanical")...)
			if code != ExitUnknown || stderr != "" {
				t.Fatalf("%s %s mechanical: code=%d stderr=%s stdout=%s", name, format, code, stderr, got)
			}
			if format == "json" {
				if !regexp.MustCompile(`"trustPolicy":\{"requiredBasis":\["mechanical"\],"excludedRules":[1-9][0-9]*\}`).MatchString(got) || strings.Contains(got, `"ruleId"`) {
					t.Fatalf("%s json:\n%s", name, got)
				}
				continue
			}
			if !regexp.MustCompile(`trust policy: evidence basis mechanical only; [1-9][0-9]* rules? left out, so the result cannot pass\n`).MatchString(got) {
				t.Fatalf("%s human:\n%s", name, got)
			}
			if name == "native" && !strings.Contains(got, policyLeftOutLine+"\n") {
				t.Fatalf("native human lacks the left-out line:\n%s", got)
			}
		}
	}
	for _, bad := range []string{"", "model", "reviewed,reviewed", "reviewed, mechanical", "Reviewed", "any"} {
		code, stdout, stderr := runCNCFCLI(t, append(append([]string(nil), routes["generic"]...), "--require-basis", bad)...)
		if code != ExitUsage || stdout != "" || !strings.Contains(stderr, "--require-basis") {
			t.Fatalf("%q: code=%d stdout=%s stderr=%s", bad, code, stdout, stderr)
		}
	}
	code, stdout, _ := runCNCFCLI(t, "check", "cncf", "--help")
	if code != ExitOK || !strings.Contains(stdout, "--require-basis LIST") {
		t.Fatalf("help lacks the flag:\n%s", stdout)
	}
}

// TestBasisOutput: each new basis has its own basis line; the headline note
// about model consensus appears exactly when a finding relies on it; a lead
// prints as an unverified lead and never as a status line.
func TestBasisOutput(t *testing.T) {
	t.Parallel()
	consensusBlocked := constraintengine.Claim{RuleID: "kubernetes.consensus-blocked", Operator: "forbid_target_version", Status: "BLOCKED", ReasonCode: "FEATURE_REMOVED", NextAction: "plan the reviewed route", EvidenceBasis: constraintengine.BasisConsensus}
	consensusQuiet := constraintengine.Claim{RuleID: "kubernetes.consensus-quiet", Operator: "forbid_predicate_value", Status: constraintengine.StatusNoKnownIssue, ReasonCode: constraintengine.ReasonConsensusNoKnownIssue, NextAction: "remove the setting", EvidenceBasis: constraintengine.BasisConsensus}
	lead := constraintengine.Claim{RuleID: "kubernetes.lead", Operator: "forbid_target_version", Status: constraintengine.StatusNotice, ReasonCode: constraintengine.ReasonLeadNotVerified, NextAction: "check the release notes", EvidenceBasis: constraintengine.BasisLead}
	leadQuiet := constraintengine.Claim{RuleID: "kubernetes.lead-quiet", Operator: "forbid_predicate_value", Status: constraintengine.StatusNoKnownIssue, ReasonCode: constraintengine.ReasonLeadNoKnownIssue, NextAction: "check the release notes", EvidenceBasis: constraintengine.BasisLead}
	empirical := constraintengine.Claim{RuleID: "kubernetes.empirical", Operator: "forbid_target_version", Status: "PASS", ReasonCode: "FEATURE_REMOVED", NextAction: "none", EvidenceBasis: constraintengine.BasisEmpirical}
	reviewed := constraintengine.Claim{RuleID: "kubernetes.reviewed", Operator: "forbid_target_version", Status: "PASS", ReasonCode: "FEATURE_REMOVED", NextAction: "none"}

	headline := func(claims []constraintengine.Claim, disclosure *cncfcheck.TrustPolicyDisclosure) string {
		var out bytes.Buffer
		if err := writeBasisHeadline(&out, claims, disclosure); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if got := headline([]constraintengine.Claim{reviewed, empirical, lead, leadQuiet}, nil); got != "" {
		t.Fatalf("headline without consensus: %q", got)
	}
	if got := headline([]constraintengine.Claim{consensusBlocked}, nil); got != "1 finding relies on model consensus\n" {
		t.Fatalf("headline=%q", got)
	}
	if got := headline([]constraintengine.Claim{consensusBlocked, consensusQuiet, reviewed}, &cncfcheck.TrustPolicyDisclosure{RequiredBasis: []string{"reviewed", "consensus"}, ExcludedRules: 2, ExcludedLeadRules: 1}); got != "trust policy: evidence basis reviewed, consensus only; 2 rules left out, so the result cannot pass\ntrust policy: 1 unverified lead not shown; add lead to --require-basis to list it\n2 findings rely on model consensus\n" {
		t.Fatalf("headline=%q", got)
	}

	// Per-claim output through the shared writers.
	summary := summarizeClaims([]constraintengine.Claim{reviewed, consensusBlocked, consensusQuiet, lead, leadQuiet, empirical}, false)
	if summary.passes != 2 || len(summary.shown) != 2 || len(summary.notices) != 2 {
		t.Fatalf("summary=%+v", summary)
	}
	var out bytes.Buffer
	if err := writeNativeClaims(&out, summary, []constraintengine.Claim{reviewed, consensusBlocked, consensusQuiet, lead, leadQuiet, empirical}); err != nil {
		t.Fatal(err)
	}
	want := "kubernetes.consensus-blocked: BLOCKED (FEATURE_REMOVED)\nnext action: plan the reviewed route\n" +
		"evidence basis: two independent model readings, citations verified; may block, never passes\n" +
		"kubernetes.consensus-quiet: NO_KNOWN_ISSUE (CONSENSUS_NO_KNOWN_ISSUE)\nnext action: remove the setting\n" +
		"evidence basis: two independent model readings, citations verified; may block, never passes\n" +
		"unverified lead (does not block): kubernetes.lead\nworth checking: check the release notes\n" +
		"evidence basis: one unverified model reading; never blocks or passes\n" +
		"2 rules PASS (not listed; use --show-passes)\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	if line := empirical.EvidenceBasisLine(); line != "evidence basis: reproduced with upstream artifacts; may block or pass" {
		t.Fatalf("empirical line=%q", line)
	}
	// A report holding only leads says no rule decided the transition.
	out.Reset()
	if err := writeNoVerdictLine(&out, []constraintengine.Claim{lead}); err != nil || out.String() != noVerdictLeadLine+"\n" {
		t.Fatalf("no-verdict line=%q", out.String())
	}
	for _, line := range strings.Split(want, "\n") {
		if len(line) > 256 {
			t.Fatalf("line over 256 bytes: %q", line)
		}
	}
}

// TestCheckRoutesUseTrustPolicy: every check cncf route evaluates through
// the command's trust policy. No route file calls a policy-less evaluation
// entry, and every external evaluation binds the policy.
func TestCheckRoutesUseTrustPolicy(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	direct := regexp.MustCompile(`cncfcheck\.(Check|CheckRule|CheckFacts|Replay|AssessScope)\(|cncfcheck\.Checker\{|cncfknowledge\.EvaluateVerified\(`)
	// Any Evaluate call is an ExternalBundle evaluation unless it belongs
	// to one of these packages, which hold no CNCF rules.
	evaluate := regexp.MustCompile(`(\w+)\.(Evaluate|EvaluateRule)\(`)
	otherEvaluators := map[string]bool{"certmanagervalues": true, "prometheusmode": true, "batchcheck": true}
	policyBinding := regexp.MustCompile(`WithTrustPolicy\(|TrustPolicy:|\.trust\s*=`)
	external := regexp.MustCompile(`cncfknowledge\.(EvaluateCurrent|ReplayHistorical)\(([^)]*)`)
	checked := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if match := direct.Find(raw); match != nil {
			t.Fatalf("%s evaluates without the trust policy: %s", file, match)
		}
		for _, match := range evaluate.FindAllSubmatch(raw, -1) {
			if !otherEvaluators[string(match[1])] {
				t.Fatalf("%s evaluates a bundle directly: %s", file, match[0])
			}
		}
		// Only the policy helpers bind a policy, and only the flag parser
		// sets the command's policy.
		for _, match := range policyBinding.FindAll(raw, -1) {
			setter := file == "cncf.go" && bytes.HasPrefix(match, []byte(".trust"))
			if file != "cncf_trust_policy.go" && !setter {
				t.Fatalf("%s binds a trust policy outside the helpers: %s", file, match)
			}
		}
		for _, match := range external.FindAllSubmatch(raw, -1) {
			checked++
			if !bytes.HasPrefix(match[2], []byte("r.withTrustPolicy(")) {
				t.Fatalf("%s: external evaluation without the trust policy: %s", file, match[0])
			}
		}
		// External evaluation goes through evaluateCurrent, which binds the
		// policy (the match above checks its single call).
		checked += bytes.Count(raw, []byte("r.cncfChecker()."))
		checked += bytes.Count(raw, []byte("r.evaluateCurrent("))
	}
	if checked < 40 {
		t.Fatalf("only %d evaluation calls found; the scan no longer sees the routes", checked)
	}
}

// TestTrustPolicyReachesExternalRequests: external requests carry the
// command's trust policy.
func TestTrustPolicyReachesExternalRequests(t *testing.T) {
	t.Parallel()
	policy, err := cncfcheck.ParseTrustPolicy("reviewed")
	if err != nil {
		t.Fatal(err)
	}
	r := runtime{trust: policy}
	if got := r.withTrustPolicy(cncfknowledge.Request{Project: "kyverno"}); got.TrustPolicy.String() != "reviewed" || got.Project != "kyverno" {
		t.Fatalf("request=%+v", got)
	}
}

// TestExternalRouteShowsTrustPolicy: the external printer states the trust
// policy's exclusions, and the check cannot pass.
func TestExternalRouteShowsTrustPolicy(t *testing.T) {
	t.Parallel()
	fixture := makeExternalCLIFixture(t)
	importExternalCLIRevision2(t, &fixture)
	input := writeCNCFFile(t, "active-input.json", []byte(kyvernoInputTrue), 0o600)
	args := append(externalCLIArgs(fixture, input, "2", fixture.manifest.Revisions[1].BundleDigest, fixture.receipt2.TrustReceiptDigest), "--require-basis", "mechanical")
	code, stdout, stderr := runCNCFCLI(t, args...)
	if code != ExitUnknown || stderr != "" || !strings.Contains(stdout, "trust policy: evidence basis mechanical only; 1 rule left out, so the result cannot pass\n") {
		t.Fatalf("code=%d stderr=%s stdout:\n%s", code, stderr, stdout)
	}
	code, stdout, _ = runCNCFCLI(t, append(args, "--format", "json")...)
	if code != ExitUnknown || !strings.Contains(stdout, `"trustPolicy":{"requiredBasis":["mechanical"],"excludedRules":1}`) {
		t.Fatalf("code=%d json:\n%s", code, stdout)
	}
}
