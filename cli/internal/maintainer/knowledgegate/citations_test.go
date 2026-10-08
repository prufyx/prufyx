// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/maintainer/rulecheck"
)

const (
	citeCommit = "d25610acbea3cd0e57f924f9f6bd9df99a7e33a3"
	citeTag    = "7a501744aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	citeBlob   = "a/b.go"
)

var citeBytes = []byte("line one\nline two\n")

// fakeUpstream is an offline resolver and fetcher: an unknown revision or
// URL is an error, like a network failure.
type fakeUpstream struct {
	kinds map[string]rulecheck.ObjectKind
	files map[string][]byte
	calls int
	// unreachable lists commits GitHub serves that are not in the history;
	// reachErr lists commits whose reachability lookup fails.
	unreachable map[string]bool
	reachErr    map[string]error
}

func (f *fakeUpstream) RevisionReachable(_ context.Context, owner, repo, sha string) (bool, error) {
	f.calls++
	if err := f.reachErr[sha]; err != nil {
		return false, err
	}
	return !f.unreachable[sha], nil
}

func (f *fakeUpstream) ResolveRevision(_ context.Context, owner, repo, sha string) (rulecheck.ObjectKind, error) {
	f.calls++
	if k, ok := f.kinds[owner+"/"+repo+"@"+sha]; ok {
		return k, nil
	}
	return rulecheck.ObjectKind{}, errors.New("network unreachable")
}

func (f *fakeUpstream) FetchRawBlob(_ context.Context, rawURL string) ([]byte, error) {
	f.calls++
	if b, ok := f.files[rawURL]; ok {
		return b, nil
	}
	return nil, errors.New("network unreachable")
}

func healthyUpstream() *fakeUpstream {
	return &fakeUpstream{
		kinds: map[string]rulecheck.ObjectKind{
			"acme/widget@" + citeCommit: {Commit: true},
			"acme/widget@" + citeTag:    {PeeledCommit: citeCommit},
		},
		files: map[string][]byte{
			"https://raw.githubusercontent.com/acme/widget/" + citeCommit + "/" + citeBlob: citeBytes,
		},
	}
}

func (f *fakeUpstream) verifier() *rulecheck.CitationVerifier {
	return &rulecheck.CitationVerifier{Resolver: f, Fetcher: f}
}

func citeSource(revision, digest string, start, end int) map[string]any {
	return map[string]any{
		"id": "cite-src", "url": "https://github.com/acme/widget/blob/" + revision + "/" + citeBlob,
		"revision": revision, "contentDigest": digest, "startLine": start, "endLine": end,
	}
}

var goodDigest = func() string { h := sha256.Sum256(citeBytes); return "sha256:" + hex.EncodeToString(h[:]) }()

// addRuleCiting adds a copy of an active reviewed rule that cites src.
func addRuleCiting(t *testing.T, head Tree, src map[string]any) string {
	t.Helper()
	var added string
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		ids := p.activeReviewed()
		e := deepCopy(p.find(t, ids[0])).(map[string]any)
		added = ids[0] + "-cited"
		ruleOf(e)["id"] = added
		evidenceOf(e)["sources"] = []any{src}
		p.entries = append(p.entries, e)
		p.sortByID()
	})
	return added
}

func citationCheckOf(t *testing.T, r *Report) Check {
	t.Helper()
	c, ok := check(r, CheckCitations)
	if !ok {
		t.Fatalf("no %q check in %+v", CheckCitations, r.Checks)
	}
	return c
}

// An added rule is verified against upstream with the same checks as
// `rule verify-citations`; every way of not establishing a fact fails.
func TestGateCitationsOfAddedRule(t *testing.T) {
	bad := "sha256:" + strings.Repeat("0", 64)
	tests := []struct {
		name     string
		src      map[string]any
		upstream func() *fakeUpstream
		wantOK   bool
		want     string
	}{
		{"pass", citeSource(citeCommit, goodDigest, 1, 2), healthyUpstream, true, "each revision is a commit"},
		{"tag object", citeSource(citeTag, goodDigest, 1, 2), healthyUpstream, false, "revision-not-commit"},
		{"digest mismatch", citeSource(citeCommit, bad, 1, 2), healthyUpstream, false, "content-digest-mismatch"},
		{"span past the end of the file", citeSource(citeCommit, goodDigest, 1, 4), healthyUpstream, false, "line-range-fetched"},
		{"fetch failure", citeSource(citeCommit, goodDigest, 1, 2), func() *fakeUpstream {
			u := healthyUpstream()
			u.files = nil
			return u
		}, false, "fetch-failed"},
		{"resolver failure", citeSource(citeCommit, goodDigest, 1, 2), func() *fakeUpstream {
			u := healthyUpstream()
			u.kinds = nil
			return u
		}, false, "revision-unresolved"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, head := trees(t)
			id := addRuleCiting(t, head, tc.src)
			r := runGate(t, Options{Base: base, Head: head, Citations: tc.upstream().verifier()})
			c := citationCheckOf(t, r)
			if c.OK != tc.wantOK || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("citations check = %+v, want ok=%v containing %q", c, tc.wantOK, tc.want)
			}
			if !tc.wantOK {
				if r.Passed() {
					t.Fatal("the gate must fail when a citation fails")
				}
				if !strings.Contains(c.Detail, id) {
					t.Fatalf("detail does not name the rule %s: %s", id, c.Detail)
				}
			}
		})
	}
}

// Without an upstream source the check cannot run: it fails, it does not skip.
func TestGateCitationsFailClosedWithoutVerifier(t *testing.T) {
	base, head := trees(t)
	addRuleCiting(t, head, citeSource(citeCommit, goodDigest, 1, 2))
	r := runGateExact(t, Options{Base: base, Head: head})
	c := citationCheckOf(t, r)
	if c.OK || !strings.Contains(c.Detail, "no upstream source is configured") || r.Passed() {
		t.Fatalf("check %+v passed=%v", c, r.Passed())
	}
}

// Only changed rules are checked: an unchanged pack, and a withdrawal of a
// rule whose citation has rotted, never fail on citations, and the
// verifier is not even called.
func TestGateCitationsOnlyForChangedRules(t *testing.T) {
	rotten := &fakeUpstream{}
	base, head := trees(t)
	r := runGate(t, Options{Base: base, Head: head, Citations: rotten.verifier()})
	if c := citationCheckOf(t, r); !c.OK || rotten.calls != 0 {
		t.Fatalf("unchanged pack: %+v calls %d", c, rotten.calls)
	}
	ids := readPack(t, base, cncfRulesPath).activeReviewed()
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		evidenceOf(p.find(t, ids[0]))["state"] = "withdrawn"
		ev := evidenceOf(p.find(t, ids[1]))
		ev["validUntil"] = shiftTime(t, ev["validUntil"], -24*time.Hour)
	})
	r = runGate(t, Options{Base: base, Head: head, Citations: rotten.verifier()})
	if c := citationCheckOf(t, r); !c.OK || rotten.calls != 0 {
		t.Fatalf("tightening change: %+v calls %d", c, rotten.calls)
	}
	requirePass(t, r)
}

// A changed rule with no source at all is not a pass.
func TestGateCitationsRuleWithoutSources(t *testing.T) {
	items := []rulecheck.CitationItem{{ID: "r.empty"}}
	report, err := healthyUpstream().verifier().VerifyItems(context.Background(), items)
	if err != nil || report.Pass {
		t.Fatalf("report %+v err %v", report, err)
	}
}

type recordingCitations struct{ items []rulecheck.CitationItem }

func (r *recordingCitations) VerifyItems(_ context.Context, items []rulecheck.CitationItem) (rulecheck.CitationReport, error) {
	r.items = items
	return rulecheck.CitationReport{Pass: true}, nil
}

// Changed path policies and line attestations are listed with their sources;
// an unchanged record, a removed attestation and a withdrawn policy are not.
func TestGateCitationsOfRecords(t *testing.T) {
	const att, pol = "lineAttestations", "pathPolicies"
	cases := []struct {
		name string
		edit func(d map[string]any)
		want []string
	}{
		{"nothing changed", func(d map[string]any) {}, nil},
		{"policy changed", func(d map[string]any) { sectionRecord(d, pol, 0)["policy"] = "direct" }, []string{"pathPolicy " + recordComponent}},
		{"attestation changed", func(d map[string]any) { sectionRecord(d, att, 0)["ruleIds"] = []any{"a.rule"} }, []string{"lineAttestation " + recordComponent + " 1.30 " + lineattest.FamilyKubernetesRemovedServedGVK}},
		{"policy withdrawn", func(d map[string]any) { sectionRecord(d, pol, 0)["evidence"].(map[string]any)["state"] = "withdrawn" }, nil},
		{"attestation removed", func(d map[string]any) { delete(d, att) }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, head := recordPair(t, tc.edit)
			cls := &Classification{Changes: diffPacks(base, head)}
			rec := &recordingCitations{}
			r := &Report{}
			r.citationCheck(context.Background(), cls, Options{Citations: rec})
			var got []string
			for _, it := range rec.items {
				if !it.Record || len(it.Sources) == 0 {
					t.Fatalf("item %+v", it)
				}
				got = append(got, it.ID)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("items %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("items %v, want %v", got, tc.want)
				}
			}
			if !r.Checks[0].OK {
				t.Fatalf("check %+v", r.Checks[0])
			}
		})
	}

	// A record whose source does not verify fails the check.
	base, head := recordPair(t, func(d map[string]any) { sectionRecord(d, pol, 0)["policy"] = "direct" })
	cls := &Classification{Changes: diffPacks(base, head)}
	r := &Report{}
	r.citationCheck(context.Background(), cls, Options{Citations: (&fakeUpstream{}).verifier()})
	if c := r.Checks[0]; c.OK || !strings.Contains(c.Detail, "pathPolicy "+recordComponent) {
		t.Fatalf("check %+v", c)
	}
}

// The explicit offline mode verifies nothing, so it is never a pass: the
// check fails with a clear reason, the gate fails, and the change is never
// eligible for automatic merge (also not as a pointer value).
func TestGateCitationsOfflineModeIsNeverAPass(t *testing.T) {
	for name, offline := range map[string]CitationChecker{"value": OfflineCitations{}, "pointer": &OfflineCitations{}} {
		t.Run(name, func(t *testing.T) {
			base, head := trees(t)
			addRuleCiting(t, head, citeSource(citeCommit, goodDigest, 1, 2))
			opts := Options{Base: base, Head: head, Citations: offline, Author: DefaultBotLogin, Sender: DefaultBotLogin}
			r := runGate(t, opts)
			c := citationCheckOf(t, r)
			if c.OK || !strings.Contains(c.Detail, "not verified (offline fixture)") {
				t.Fatalf("check %+v", c)
			}
			if r.Passed() || r.AutoMerge.Eligible {
				t.Fatalf("passed=%v eligible=%v", r.Passed(), r.AutoMerge.Eligible)
			}
		})
	}
}

// A commit served for the repository but not in its history (a fork-only
// commit, a compare answer of diverged or 404) or one whose reachability
// cannot be established fails the check through the gate.
func TestGateCitationsRevisionReachability(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reach func(f *fakeUpstream)
		want  string
	}{
		{"reachable", func(f *fakeUpstream) {}, "each revision is a commit"},
		{"fork-only", func(f *fakeUpstream) { f.unreachable = map[string]bool{citeCommit: true} }, "revision-not-in-upstream"},
		{"api error", func(f *fakeUpstream) { f.reachErr = map[string]error{citeCommit: errors.New("compare: HTTP 502")} }, "could not establish"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, head := trees(t)
			addRuleCiting(t, head, citeSource(citeCommit, goodDigest, 1, 2))
			up := healthyUpstream()
			tc.reach(up)
			r := runGate(t, Options{Base: base, Head: head, Citations: up.verifier()})
			c := citationCheckOf(t, r)
			if c.OK != (tc.name == "reachable") || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("check %+v", c)
			}
		})
	}
}

// Renewals, reactivations and repins of rules and records are loosening
// changes; each must reach the verifier with its sources. A regression in
// citationItems that filtered on Kinds would be caught here.
func TestGateCitationsRenewalReactivationRepinReachVerifier(t *testing.T) {
	ruleCases := []struct {
		name string
		prep func(t *testing.T, p *packDoc, id string)
		// applied to base and head
		edit func(t *testing.T, ev map[string]any)
	}{
		{"renewal", func(*testing.T, *packDoc, string) {}, func(t *testing.T, ev map[string]any) {
			ev["validUntil"] = shiftTime(t, ev["validUntil"], 24*time.Hour)
		}},
		{"reactivation", func(t *testing.T, p *packDoc, id string) { evidenceOf(p.find(t, id))["state"] = "withdrawn" }, func(t *testing.T, ev map[string]any) {
			ev["state"] = "active"
		}},
		{"repin", func(*testing.T, *packDoc, string) {}, func(t *testing.T, ev map[string]any) {
			ev["sources"].([]any)[0].(map[string]any)["contentDigest"] = "sha256:" + strings.Repeat("1", 64)
		}},
	}
	for _, tc := range ruleCases {
		t.Run("rule "+tc.name, func(t *testing.T) {
			base, head := trees(t)
			id := readPack(t, base, cncfRulesPath).activeReviewed()[0]
			// Only the classification is needed, so the generated files
			// are not regenerated for these edits.
			if tc.name == "reactivation" {
				p := readPack(t, base, cncfRulesPath)
				tc.prep(t, p, id)
				p.write(t, base, cncfRulesPath)
				p = readPack(t, head, cncfRulesPath)
				tc.prep(t, p, id)
				p.write(t, head, cncfRulesPath)
			}
			p := readPack(t, head, cncfRulesPath)
			tc.edit(t, evidenceOf(p.find(t, id)))
			p.write(t, head, cncfRulesPath)
			cls, err := Classify(DefaultLayout(), base, head)
			if err != nil {
				t.Fatal(err)
			}
			rec := &recordingCitations{}
			r := &Report{}
			r.citationCheck(context.Background(), cls, Options{Citations: rec})
			found := false
			for _, it := range rec.items {
				if it.ID == id && !it.Record && len(it.Sources) > 0 {
					found = true
				}
			}
			if !found || !r.Checks[0].OK {
				t.Fatalf("%s of %s did not reach the verifier: %+v", tc.name, id, rec.items)
			}
		})
	}
	recordCases := map[string]func(t *testing.T, ev map[string]any){
		"renewal": func(t *testing.T, ev map[string]any) {
			ev["validUntil"] = shiftTime(t, ev["validUntil"], 24*time.Hour)
		},
		"repin": func(t *testing.T, ev map[string]any) {
			ev["sources"].([]any)[0].(map[string]any)["contentDigest"] = "sha256:" + strings.Repeat("1", 64)
		},
	}
	for name, edit := range recordCases {
		t.Run("path policy "+name, func(t *testing.T) {
			base, head := recordPair(t, func(d map[string]any) { edit(t, sectionRecord(d, "pathPolicies", 0)["evidence"].(map[string]any)) })
			rec := &recordingCitations{}
			r := &Report{}
			r.citationCheck(context.Background(), &Classification{Changes: diffPacks(base, head)}, Options{Citations: rec})
			if len(rec.items) != 1 || !rec.items[0].Record || rec.items[0].ID != "pathPolicy "+recordComponent {
				t.Fatalf("items %+v", rec.items)
			}
		})
	}
}

// --source github wires the real citation verifier with the hardened GitHub
// client and the raw fetcher (and the same token as the gate's reader);
// fixture wires the offline mode; no source wires nothing, which fails closed.
func TestSourceFlagWiresCitationVerifier(t *testing.T) {
	env := func(k string) string {
		if k == "GITHUB_TOKEN" {
			return "t0ken"
		}
		return ""
	}
	src, checker, err := sourceFlag("github", 7*time.Minute, env)
	if err != nil {
		t.Fatal(err)
	}
	gh, ok := src.(*GitHubSource)
	if !ok || gh.Token != "t0ken" {
		t.Fatalf("source %#v", src)
	}
	v, ok := checker.(*rulecheck.CitationVerifier)
	if !ok {
		t.Fatalf("checker %T is not the real verifier", checker)
	}
	objects, ok := v.Resolver.(rulecheck.GitHubObjects)
	if !ok || objects.Token != "t0ken" {
		t.Fatalf("resolver %#v", v.Resolver)
	}
	if _, ok := v.Fetcher.(rulecheck.HTTPFetcher); !ok || v.Timeout != 7*time.Minute {
		t.Fatalf("fetcher %#v timeout %v", v.Fetcher, v.Timeout)
	}
	// The resolver carries the per-repository cache (NewGitHubObjects): two
	// commits of one repository cost one repository lookup and one tag
	// listing, not one each.
	var repoCalls, tagCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/widget":
			repoCalls.Add(1)
			fmt.Fprint(w, `{"default_branch":"main"}`)
		case r.URL.Path == "/repos/acme/widget/tags":
			tagCalls.Add(1)
			fmt.Fprint(w, "[]")
		default:
			fmt.Fprint(w, `{"status":"ahead"}`)
		}
	}))
	defer server.Close()
	objects.APIBase, objects.Client = server.URL, server.Client()
	for _, sha := range []string{strings.Repeat("a", 40), strings.Repeat("b", 40)} {
		if reachable, err := objects.RevisionReachable(context.Background(), "acme", "widget", sha); err != nil || !reachable {
			t.Fatalf("reachable %v %v", reachable, err)
		}
	}
	if repoCalls.Load() != 1 || tagCalls.Load() != 1 {
		t.Fatalf("repository lookups %d, tag listings %d: the resolver is not the cached NewGitHubObjects", repoCalls.Load(), tagCalls.Load())
	}
	if _, checker, err = sourceFlag("fixture:/x", time.Minute, env); err != nil || !isOffline(checker) {
		t.Fatalf("fixture: %T %v", checker, err)
	}
	if src, checker, err = sourceFlag("", time.Minute, env); err != nil || src != nil || checker != nil {
		t.Fatalf("no source: %v %v %v", src, checker, err)
	}
	for _, bad := range []string{"gitlab", "fixture:"} {
		if _, _, err := sourceFlag(bad, time.Minute, env); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// The nightly workflow stays read-only and supply-chain clean: scheduled
// and manual triggers only, contents: read, every action pinned by commit,
// no secrets, no credentials kept in the checkout, nothing written back.
func TestCitationsNightlyWorkflowShape(t *testing.T) {
	path := filepath.Join(repoRoot, ".github", "workflows", "citations-nightly.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	for trigger := range wf.On {
		if trigger != "schedule" && trigger != "workflow_dispatch" {
			t.Fatalf("unexpected trigger %s", trigger)
		}
	}
	if len(wf.On) != 2 {
		t.Fatalf("triggers %v", wf.On)
	}
	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		t.Fatalf("permissions %v, want contents: read only", wf.Permissions)
	}
	text := string(raw)
	if strings.Contains(text, "secrets.") {
		t.Fatal("the nightly must not use secrets")
	}
	for _, forbidden := range []string{"pull_request", "gh pr", "git push", "contents: write", "pull-requests", "issues:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("the nightly must not contain %q", forbidden)
		}
	}
	job, ok := wf.Jobs["citations"]
	if !ok || len(job.Permissions) != 0 {
		t.Fatal("no citations job, or it widens permissions")
	}
	pinned := regexp.MustCompile(`^[\w.-]+/[\w.-]+@[0-9a-f]{40}$`)
	uses := map[string]bool{}
	for _, s := range job.Steps {
		if s.Uses == "" {
			continue
		}
		if !pinned.MatchString(s.Uses) {
			t.Fatalf("action %q is not pinned by commit", s.Uses)
		}
		uses[s.Uses] = true
		if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["persist-credentials"] != false {
			t.Fatal("checkout must not persist credentials")
		}
	}
	// The same pinned commits as the gate workflow.
	gate, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatal(err)
	}
	for use := range uses {
		if !strings.Contains(string(gate), use) {
			t.Fatalf("%s is not the commit the gate workflow pins", use)
		}
	}
	if !strings.Contains(text, "rule verify-citations") || !strings.Contains(text, "GITHUB_TOKEN: ${{ github.token }}") {
		t.Fatal("the nightly no longer runs rule verify-citations with the read-only token")
	}
}
