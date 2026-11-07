// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	cncfRules    = "cli/internal/cncfcheck/data/rules.json"
	projectRules = "cli/internal/projectcheck/data/rules.json"
	projectsFile = "cli/internal/projectcheck/data/projects.json"
	committed    = "2026-11-01T10:00:00Z"
	later        = "2026-11-02T10:00:00Z"
	earlier      = "2026-10-31T10:00:00Z"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE="+committed, "GIT_COMMITTER_DATE="+committed,
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func readme(rules, projects, decided string) string {
	return "# x\n\n<!-- coverage:begin -->\nGenerated.\n\n| Executable rules | Count |\n| --- | --- |\n" +
		"| CNCF source rules, active | " + rules + " across 53 projects (1 withdrawn, not used) |\n" +
		"| Projects with a check | " + projects + " |\n" +
		"| Decided | " + decided + " of 78 |\n<!-- coverage:end -->\n\ntail\n"
}

func rulesJSON(descs ...string) string {
	var parts []string
	for _, d := range descs {
		parts = append(parts, fmt.Sprintf(`{"description":%q,"project":"p","requiredFacts":[],"rule":{}}`, d))
	}
	return `{"schema":"s","entries":[` + strings.Join(parts, ",") + `],"lineAttestations":[]}`
}

func write(t *testing.T, dir, rel, body string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newRepo(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	write(t, dir, "README.md", readme("252", "67", "44"))
	write(t, dir, cncfRules, rulesJSON("one"))
	write(t, dir, projectRules, rulesJSON("pone"))
	write(t, dir, projectsFile, `{"schema":"s","projects":[{"slug":"a"}]}`)
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "base")
	return dir, git(t, dir, "rev-parse", "HEAD")
}

// mergePR lands a branch on main with a merge commit and returns (merge, head).
func mergePR(t *testing.T, dir string, n int, files map[string]string) (string, string) {
	t.Helper()
	br := fmt.Sprintf("factory/export-%012x", n)
	git(t, dir, "checkout", "-q", "-b", br, "main")
	for p, b := range files {
		write(t, dir, p, b)
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "change")
	head := git(t, dir, "rev-parse", "HEAD")
	git(t, dir, "checkout", "-q", "main")
	git(t, dir, "merge", "-q", "--no-ff", "-m", fmt.Sprintf("Merge pull request #%d from prufyx/%s", n, br), br)
	return git(t, dir, "rev-parse", "HEAD"), head
}

func strictGate(head string) string {
	return "QA batch gate on the exact head: GATE " + head[:8] + " WRONGPASS=0 MISMATCH=0 ERR=0 cases=12 head=" + head
}

func prInput(n int, head, author string, comments ...Comment) PRInput {
	return PRInput{Number: n, Head: head, Author: author, Ref: fmt.Sprintf("factory/export-%012x", n), Title: "export", Comments: comments}
}

const trustedID int64 = 1001

func airstand(body, at string) Comment {
	return Comment{Author: "airstand", AuthorID: trustedID, CreatedAt: at, UpdatedAt: at, Body: body}
}

func build(t *testing.T, dir, base string, in Input) (*Packet, error) {
	t.Helper()
	return Build(context.Background(), Options{Repo: dir, Base: base, Head: "main", PreviousRevision: 7, Input: in, TrustedUserIDs: []int64{trustedID}})
}

func findEntry(t *testing.T, p *Packet, n int) Entry {
	t.Helper()
	for _, e := range p.Entries {
		if e.Number == n {
			return e
		}
	}
	t.Fatalf("no entry for PR %d", n)
	return Entry{}
}

func TestVerifiedDataPRAndDeltas(t *testing.T) {
	dir, base := newRepo(t)
	merge, head := mergePR(t, dir, 10, map[string]string{
		cncfRules:   rulesJSON("one", "two"),
		"README.md": readme("253", "67", "44"),
	})
	in := Input{Schema: InputSchema, PRs: []PRInput{prInput(10, head, "prufyx-bot",
		airstand(strictGate(head), later), airstand("DATA REVIEW: GO "+head+"\nbody", later))}}
	p, err := build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	e := findEntry(t, p, 10)
	if e.Class != ClassData || e.Gate.Status != Verified || e.Review.Status != Verified || e.MergeCommit != merge || e.Head != head {
		t.Fatalf("entry = %+v", e)
	}
	if p.Schema != PacketSchema || p.PreviousRevision.Revision != 7 || p.PreviousRevision.SourceCommit != base || p.SourceCommit != merge {
		t.Fatalf("header = %+v", p)
	}
	if got := p.Deltas.Rules; len(got) != 3 || got[0].Path != cncfRules || len(got[0].Added) != 1 || got[0].Before != 1 || got[0].After != 2 {
		t.Fatalf("rules delta = %+v", got)
	}
	if len(p.Deltas.Readme) == 0 || p.Deltas.Readme[0].Before != "252 across 53 projects (1 withdrawn, not used)" || p.Deltas.Readme[0].Decrease {
		t.Fatalf("readme delta = %+v", p.Deltas.Readme)
	}
	if p.Summary.DataPRs != 1 || p.Summary.Verified != 1 || p.Summary.Unverified != 0 || p.Summary.NonData != 0 {
		t.Fatalf("summary = %+v", p.Summary)
	}
}

func TestLegacyGateAndReviewShapesAreUnverifiedNotOmitted(t *testing.T) {
	dir, base := newRepo(t)
	_, head := mergePR(t, dir, 424, map[string]string{cncfRules: rulesJSON("one", "two")})
	in := Input{Schema: InputSchema, PRs: []PRInput{prInput(424, head, "prufyx-bot",
		airstand("QA batch gate on the exact head: GATE "+head[:8]+" WRONGPASS=0 MISMATCH=0 ERR=0 base=20c70964 exit=0", later),
		airstand("Data review at "+head[:8]+": GO", later))}}
	p, err := build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	e := findEntry(t, p, 424)
	if e.Gate.Status != Unverified || !strings.Contains(e.Gate.Line, "base=20c70964") || e.Gate.Reason == "" {
		t.Fatalf("gate = %+v", e.Gate)
	}
	if e.Review.Status != Unverified || !strings.Contains(e.Review.Line, "Data review at") {
		t.Fatalf("review = %+v", e.Review)
	}
	if p.Summary.Unverified != 1 {
		t.Fatalf("summary = %+v", p.Summary)
	}
}

func TestMissingGateIsListedUnverified(t *testing.T) {
	dir, base := newRepo(t)
	_, head := mergePR(t, dir, 11, map[string]string{cncfRules: rulesJSON("one", "two")})
	p, err := build(t, dir, base, Input{Schema: InputSchema, PRs: []PRInput{prInput(11, head, "prufyx-bot")}})
	if err != nil {
		t.Fatal(err)
	}
	e := findEntry(t, p, 11)
	if e.Gate.Status != Unverified || e.Review.Status != Unverified || e.Gate.Reason == "" {
		t.Fatalf("entry = %+v", e)
	}
}

func TestMarkerRejections(t *testing.T) {
	dir, base := newRepo(t)
	_, head := mergePR(t, dir, 12, map[string]string{cncfRules: rulesJSON("one", "two")})
	other := strings.Repeat("a", 40)
	cases := map[string][]Comment{
		"stale":     {airstand(strictGate(head), earlier), airstand("DATA REVIEW: GO "+head, earlier)},
		"foreign":   {{Author: "mallory", AuthorID: 2002, CreatedAt: later, UpdatedAt: later, Body: strictGate(head)}, {Author: "mallory", AuthorID: 2002, CreatedAt: later, UpdatedAt: later, Body: "DATA REVIEW: GO " + head}},
		"wrongsha":  {airstand(strictGate(other), later), airstand("DATA REVIEW: GO "+other, later)},
		"nogo":      {airstand(strictGate(head), later), airstand("DATA REVIEW: NO-GO "+head, later)},
		"nonzero":   {airstand("QA batch gate on the exact head: GATE "+head[:8]+" WRONGPASS=1 MISMATCH=0 ERR=0 head="+head, later), airstand("DATA REVIEW: GO "+head, later)},
		"notfirst":  {airstand(strictGate(head), later), airstand("hello\nDATA REVIEW: GO "+head, later)},
		"badstatus": {},
	}
	// expected (gate verified, review verified)
	want := map[string][2]bool{"nogo": {true, false}, "nonzero": {false, true}, "notfirst": {true, false}}
	for name, comments := range cases {
		in := Input{Schema: InputSchema, PRs: []PRInput{prInput(12, head, "prufyx-bot", comments...)}}
		if name == "badstatus" {
			in.PRs[0].Statuses = []Status{{Context: "qa-gate", State: "success", Creator: "mallory", CreatorID: 2002, ID: 1}}
		}
		p, err := build(t, dir, base, in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		e := findEntry(t, p, 12)
		if got := (e.Gate.Status == Verified); got != want[name][0] {
			t.Errorf("%s: gate verified=%v: %+v", name, got, e.Gate)
		}
		if got := (e.Review.Status == Verified); got != want[name][1] {
			t.Errorf("%s: review verified=%v: %+v", name, got, e.Review)
		}
	}
}

func TestQAGateStatusCounts(t *testing.T) {
	dir, base := newRepo(t)
	_, head := mergePR(t, dir, 13, map[string]string{cncfRules: rulesJSON("one", "two")})
	in := Input{Schema: InputSchema, PRs: []PRInput{prInput(13, head, "prufyx-bot", airstand("DATA REVIEW: GO "+head, later))}}
	in.PRs[0].Statuses = []Status{{Context: "qa-gate", State: "failure", Creator: "airstand", CreatorID: trustedID, ID: 1}, {Context: "qa-gate", State: "success", Creator: "airstand", CreatorID: trustedID, ID: 2}}
	p, err := build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	if e := findEntry(t, p, 13); e.Gate.Status != Verified || e.Gate.Source != "status" {
		t.Fatalf("gate = %+v", e.Gate)
	}
}

func TestNonDataTrustPathAndDirectCommits(t *testing.T) {
	dir, base := newRepo(t)
	_, h1 := mergePR(t, dir, 20, map[string]string{"cli/internal/x/x.go": "package x\n"})
	_, h2 := mergePR(t, dir, 21, map[string]string{".github/workflows/knowledge-publish.yml": "name: x\n"})
	_, h3 := mergePR(t, dir, 22, map[string]string{cncfRules: rulesJSON("one", "two"), "scripts/x.sh": "#!/bin/sh\n"})
	write(t, dir, "direct.txt", "x")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "direct")
	in := Input{Schema: InputSchema, PRs: []PRInput{
		prInput(20, h1, "prufyx-bot"), prInput(21, h2, "airstand"), prInput(22, h3, "prufyx-bot")}}
	p, err := build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	if findEntry(t, p, 20).Class != ClassNonData || findEntry(t, p, 21).Class != ClassTrustPath || findEntry(t, p, 22).Class != ClassTrustPath {
		t.Fatalf("classes: %+v", p.Entries)
	}
	if len(p.DirectCommits) != 1 || p.Summary.NonData != 1 || p.Summary.TrustPath != 2 || p.Summary.DirectCommits != 1 {
		t.Fatalf("direct=%v summary=%+v", p.DirectCommits, p.Summary)
	}
	md := p.Markdown()
	for _, want := range []string{"NON-DATA CHANGE IN RANGE", "TRUST-PATH CHANGE", "DIRECT COMMIT"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
}

func TestUnknownPRAndUnknownAuthorFailClosed(t *testing.T) {
	dir, base := newRepo(t)
	_, h1 := mergePR(t, dir, 30, map[string]string{cncfRules: rulesJSON("one", "two")})
	mergePR(t, dir, 31, map[string]string{projectRules: rulesJSON("pone", "ptwo")})
	in := Input{Schema: InputSchema, PRs: []PRInput{prInput(30, h1, "someone-else")}}
	p, err := build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	if findEntry(t, p, 30).Class != ClassNonData || findEntry(t, p, 31).Class != ClassNonData {
		t.Fatalf("classes: %+v", p.Entries)
	}
}

func TestInputHeadMismatchIsUnverified(t *testing.T) {
	dir, base := newRepo(t)
	_, head := mergePR(t, dir, 14, map[string]string{cncfRules: rulesJSON("one", "two")})
	stale := strings.Repeat("b", 40)
	in := Input{Schema: InputSchema, PRs: []PRInput{prInput(14, stale, "prufyx-bot",
		airstand(strictGate(head), later), airstand("DATA REVIEW: GO "+head, later))}}
	p, err := build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	if e := findEntry(t, p, 14); e.Gate.Status != Unverified || e.Review.Status != Unverified {
		t.Fatalf("entry = %+v", e)
	}
}

func TestReadmeDecreaseFlagged(t *testing.T) {
	dir, base := newRepo(t)
	_, head := mergePR(t, dir, 15, map[string]string{"README.md": readme("252", "66", "44")})
	p, err := build(t, dir, base, Input{Schema: InputSchema, PRs: []PRInput{prInput(15, head, "prufyx-bot")}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range p.Deltas.Readme {
		if r.Label == "Projects with a check" && r.Decrease {
			found = true
		}
	}
	if !found || p.Summary.Decreases != 1 {
		t.Fatalf("readme = %+v summary=%+v", p.Deltas.Readme, p.Summary)
	}
}

func TestDeterministicAndDigests(t *testing.T) {
	dir, base := newRepo(t)
	_, h1 := mergePR(t, dir, 41, map[string]string{cncfRules: rulesJSON("one", "two")})
	_, h2 := mergePR(t, dir, 40, map[string]string{projectsFile: `{"schema":"s","projects":[{"slug":"a"},{"slug":"b"}]}`})
	in := Input{Schema: InputSchema, PRs: []PRInput{
		prInput(41, h1, "prufyx-bot", airstand(strictGate(h1), later)), prInput(40, h2, "prufyx-bot")}}
	var outs [][]byte
	var mds []string
	var pk *Packet
	for i := 0; i < 2; i++ {
		p, err := build(t, dir, base, in)
		if err != nil {
			t.Fatal(err)
		}
		b, err := p.JSON()
		if err != nil {
			t.Fatal(err)
		}
		outs, mds, pk = append(outs, b), append(mds, p.Markdown()), p
	}
	if !bytes.Equal(outs[0], outs[1]) || mds[0] != mds[1] {
		t.Fatal("output differs between runs")
	}
	if pk.Entries[0].Number != 41 || pk.Entries[1].Number != 40 {
		t.Fatalf("entries must follow merge order: %+v", pk.Entries)
	}
	canon, err := json.Marshal(pk.Entries)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon)
	if pk.ContentDigest != "sha256:"+hex.EncodeToString(sum[:]) || !strings.HasPrefix(pk.PacketDigest, "sha256:") || pk.PacketDigest == pk.ContentDigest {
		t.Fatalf("digests: %s %s", pk.ContentDigest, pk.PacketDigest)
	}
	if !json.Valid(outs[0]) || !bytes.Contains(outs[0], []byte(`"contentDigest"`)) {
		t.Fatal("bad json")
	}
}

func TestEmptyRangeYieldsEmptyPacket(t *testing.T) {
	dir, base := newRepo(t)
	p, err := build(t, dir, base, Input{Schema: InputSchema})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 0 || p.ContentDigest == "" {
		t.Fatalf("packet = %+v", p)
	}
}

func TestErrorsAreFailClosed(t *testing.T) {
	dir, base := newRepo(t)
	_, head := mergePR(t, dir, 50, map[string]string{cncfRules: rulesJSON("one", "two")})
	good := Input{Schema: InputSchema, PRs: []PRInput{prInput(50, head, "prufyx-bot")}}
	badTime := good
	badTime.PRs = []PRInput{prInput(50, head, "prufyx-bot", airstand("x", "not-a-time"))}
	dup := Input{Schema: InputSchema, PRs: []PRInput{prInput(50, head, "a"), prInput(50, head, "b")}}
	badSha := Input{Schema: InputSchema, PRs: []PRInput{prInput(50, "xyz", "a")}}
	for name, in := range map[string]Input{"time": badTime, "dup": dup, "sha": badSha, "schema": {Schema: "nope"}} {
		if _, err := build(t, dir, base, in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// base not an ancestor of head
	if _, err := Build(context.Background(), Options{Repo: dir, Base: "main", Head: base, Input: good}); err == nil {
		t.Error("reversed range accepted")
	}
	if _, err := Build(context.Background(), Options{Repo: dir, Base: "nosuchrev", Head: "main", Input: good}); err == nil {
		t.Error("unknown base accepted")
	}
	// unparsable rules file at head
	mergePR(t, dir, 51, map[string]string{cncfRules: "{not json"})
	if _, err := build(t, dir, base, good); err == nil {
		t.Error("unparsable rules.json accepted")
	}
}

func TestParseInputStrict(t *testing.T) {
	if _, err := ParseInput(strings.NewReader(`{"schema":"` + InputSchema + `","prs":[],"extra":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := ParseInput(strings.NewReader(`{"schema":"` + InputSchema + `","prs":[]} trailing`)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := ParseInput(strings.NewReader(`{"schema":"` + InputSchema + `","prs":[]}`)); err != nil {
		t.Error(err)
	}
}

func TestRunWritesNothingOnError(t *testing.T) {
	dir, base := newRepo(t)
	out := t.TempDir()
	inPath := filepath.Join(out, "in.json")
	write(t, out, "in.json", `{"schema":"bogus"}`)
	var so, se bytes.Buffer
	err := Run([]string{"--repo", dir, "--base", base, "--head", "main", "--previous-revision", "7", "--input", inPath,
		"--out-json", filepath.Join(out, "p.json"), "--out-md", filepath.Join(out, "p.md"), "--trusted-user-ids", "1001"}, &so, &se)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, f := range []string{"p.json", "p.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err == nil {
			t.Errorf("%s written on error", f)
		}
	}
	write(t, out, "in.json", `{"schema":"`+InputSchema+`","prs":[]}`)
	if err := Run([]string{"--repo", dir, "--base", base, "--head", "main", "--previous-revision", "7", "--input", inPath,
		"--out-json", filepath.Join(out, "p.json"), "--out-md", filepath.Join(out, "p.md"), "--trusted-user-ids", "1001"}, &so, &se); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"p.json", "p.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("%s missing", f)
		}
	}
}

// verifiedInput builds a data PR that would be fully VERIFIED with the given comments.
func dataPR(t *testing.T, n int, comments func(head string) []Comment) (string, string, Input) {
	t.Helper()
	dir, base := newRepo(t)
	_, head := mergePR(t, dir, n, map[string]string{cncfRules: rulesJSON("one", "two")})
	return dir, base, Input{Schema: InputSchema, PRs: []PRInput{prInput(n, head, "prufyx-bot", comments(head)...)}}
}

func TestEditedMarkerIsUnverified(t *testing.T) {
	dir, base, in := dataPR(t, 40, func(h string) []Comment {
		g, r := airstand(strictGate(h), later), airstand("DATA REVIEW: GO "+h, later)
		g.UpdatedAt, r.UpdatedAt = "2026-11-03T10:00:00Z", "2026-11-03T10:00:00Z"
		return []Comment{g, r}
	})
	p, err := build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	e := findEntry(t, p, 40)
	for name, m := range map[string]Marker{"gate": e.Gate, "review": e.Review} {
		if m.Status != Unverified || !strings.Contains(m.Reason, "edited") {
			t.Errorf("%s = %+v", name, m)
		}
	}
}

func TestMarkerMatchesUserIDNotLogin(t *testing.T) {
	dir, base, in := dataPR(t, 41, func(h string) []Comment {
		g, r := airstand(strictGate(h), later), airstand("DATA REVIEW: GO "+h, later)
		g.AuthorID, r.AuthorID = 2002, 2002 // login airstand, other account id
		return []Comment{g, r}
	})
	in.PRs[0].Statuses = []Status{{Context: "qa-gate", State: "success", Creator: "airstand", CreatorID: 2002, ID: 1}}
	p, err := build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	if e := findEntry(t, p, 41); e.Gate.Status != Unverified || e.Review.Status != Unverified {
		t.Fatalf("login-only match accepted: %+v", e)
	}
	// the other direction: another login, trusted id, is accepted
	dir, base, in = dataPR(t, 42, func(h string) []Comment {
		g, r := airstand(strictGate(h), later), airstand("DATA REVIEW: GO "+h, later)
		g.Author, r.Author = "renamed", "renamed"
		return []Comment{g, r}
	})
	p, err = build(t, dir, base, in)
	if err != nil {
		t.Fatal(err)
	}
	if e := findEntry(t, p, 42); e.Gate.Status != Verified || e.Review.Status != Verified {
		t.Fatalf("trusted id rejected: %+v", e)
	}
}

func TestEmptyOrInvalidTrustedIDsFailClosed(t *testing.T) {
	dir, base, in := dataPR(t, 43, func(h string) []Comment { return nil })
	for name, ids := range map[string][]int64{"empty": nil, "zero": {0}, "negative": {-5}} {
		_, err := Build(context.Background(), Options{Repo: dir, Base: base, Head: "main", PreviousRevision: 7, Input: in, TrustedUserIDs: ids})
		if err == nil {
			t.Errorf("%s trusted ids accepted", name)
		}
	}
}

func TestInputRejectsBadMarkerFields(t *testing.T) {
	good := `{"schema":"` + InputSchema + `","prs":[{"number":1,"head":"` + strings.Repeat("a", 40) + `","comments":[{"author":"a","authorId":1,"createdAt":"2026-11-02T10:00:00Z","updatedAt":"%s","body":"x"}]}]}`
	if _, err := ParseInput(strings.NewReader(fmt.Sprintf(good, "2026-11-02T10:00:00Z"))); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseInput(strings.NewReader(fmt.Sprintf(good, "yesterday"))); err == nil {
		t.Error("bad updatedAt accepted")
	}
	if _, err := ParseInput(strings.NewReader(fmt.Sprintf(good, ""))); err == nil {
		t.Error("empty updatedAt accepted")
	}
	if _, err := ParseInput(strings.NewReader(`{"schema":"prufyx.io/knowledge-packet-input/v1","prs":[]}`)); err == nil {
		t.Error("v1 input accepted")
	}
}

func TestTrustPathClassCoversPacketAndPackageProducers(t *testing.T) {
	paths := []string{
		".github/workflows/x.yml", "cli/internal/knowledgepin/a.go", "cli/internal/maintainer/knowledgepacket/a.go",
		"cli/cmd/prufyx-maintainer/main.go", "cli/internal/knowledge/open.go", "cli/internal/knowledgereleaseplan/a.go", "scripts/x.sh",
	}
	for i, path := range paths {
		dir, base := newRepo(t)
		_, head := mergePR(t, dir, 50+i, map[string]string{path: "x\n", cncfRules: rulesJSON("one", "two")})
		p, err := build(t, dir, base, Input{Schema: InputSchema, PRs: []PRInput{prInput(50+i, head, "prufyx-bot")}})
		if err != nil {
			t.Fatal(err)
		}
		if e := findEntry(t, p, 50+i); e.Class != ClassTrustPath {
			t.Errorf("%s: class %s", path, e.Class)
		}
	}
}

func TestReadmeOutsideCoverageBlockIsNonData(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"inside block": {readme("253", "67", "44"), ClassData},
		"tail":         {strings.Replace(readme("252", "67", "44"), "tail", "tail with free text", 1), ClassNonData},
		"head":         {strings.Replace(readme("252", "67", "44"), "# x", "# y", 1), ClassNonData},
		"both":         {strings.Replace(readme("253", "67", "44"), "tail", "free text", 1), ClassNonData},
		"no markers":   {"# x\nno block\n", ClassNonData},
	}
	i := 0
	for name, c := range cases {
		i++
		dir, base := newRepo(t)
		_, head := mergePR(t, dir, 70+i, map[string]string{"README.md": c.body})
		p, err := build(t, dir, base, Input{Schema: InputSchema, PRs: []PRInput{prInput(70+i, head, "prufyx-bot")}})
		if name == "no markers" {
			if err == nil {
				t.Errorf("%s: expected delta error", name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if e := findEntry(t, p, 70+i); e.Class != c.want {
			t.Errorf("%s: class %s (%s), want %s", name, e.Class, e.ClassReason, c.want)
		}
	}
}

func TestMarkdownStatesAutomationDomainAndSelfReferenceResidual(t *testing.T) {
	dir, base := newRepo(t)
	p, err := build(t, dir, base, Input{Schema: InputSchema, PRs: []PRInput{}})
	if err != nil {
		t.Fatal(err)
	}
	md := p.Markdown()
	for _, want := range []string{
		"code at the signing commit generated this packet about itself",
		"a trust-path change can lie in its own packet",
		"the independent control is the merge-time check, not the packet",
		"both trusted logins live in the automation domain",
		"markers are claims by the automation",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
}
