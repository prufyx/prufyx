// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// repoRoot is this source tree's repository root.
var repoRoot = filepath.Join("..", "..", "..", "..")

// knowledgeFiles are the repository files the default layout reads.
var knowledgeFiles = []string{
	"cli/internal/cncfcheck/data/landscape-projects.json",
	"cli/internal/cncfcheck/data/priority-portfolio.json",
	"cli/internal/cncfcheck/data/rules.json",
	"cli/internal/cncfcheck/data/corpus-attestation.json",
	"cli/internal/projectcheck/data/projects.json",
	"cli/internal/projectcheck/data/rules.json",
	"cli/internal/projectcheck/data/corpus-attestation.json",
	"cli/internal/certmanagervalues/source-contract-v1.json",
	"cli/internal/certmanagervalues/source-contract-v1-latest.json",
	"cli/internal/prometheusmode/source-contract-v1.json",
	"cli/internal/spiffex509svid/data/profile.json",
	"cli/internal/cloudeventsstructuredjson/data/profile.json",
	"cli/internal/tikvgcpv2/data/profile.json",
	"cli/internal/communityapp/cncf_prepare.go",
	"cli/docs/data/selected-source-records-v1.json",
	"cli/docs/generated/community-support-inventory.json",
	"cli/docs/generated/community-support-inventory.md",
}

func writeFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// copyKnowledge copies the knowledge files of this repository into a new
// tree.
func copyKnowledge(t *testing.T) Tree {
	t.Helper()
	root := t.TempDir()
	for _, rel := range knowledgeFiles {
		raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(root, filepath.FromSlash(rel)), raw)
	}
	return Tree{Root: root}
}

// trees returns a base and a head copy of the repository's knowledge.
func trees(t *testing.T) (Tree, Tree) {
	t.Helper()
	return copyKnowledge(t), copyKnowledge(t)
}

type packDoc struct {
	fields  map[string]json.RawMessage
	entries []map[string]any
}

func readPack(t *testing.T, tr Tree, rel string) *packDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tr.Root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	p := &packDoc{}
	if err := json.Unmarshal(raw, &p.fields); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(p.fields["entries"]))
	dec.UseNumber()
	if err := dec.Decode(&p.entries); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *packDoc) write(t *testing.T, tr Tree, rel string) {
	t.Helper()
	entries, err := json.Marshal(p.entries)
	if err != nil {
		t.Fatal(err)
	}
	p.fields["entries"] = entries
	raw, err := json.MarshalIndent(p.fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(rel)), append(raw, '\n'))
}

func ruleOf(e map[string]any) map[string]any     { return e["rule"].(map[string]any) }
func evidenceOf(e map[string]any) map[string]any { return ruleOf(e)["evidence"].(map[string]any) }
func ruleID(e map[string]any) string             { return ruleOf(e)["id"].(string) }

func (p *packDoc) find(t *testing.T, id string) map[string]any {
	t.Helper()
	for _, e := range p.entries {
		if ruleID(e) == id {
			return e
		}
	}
	t.Fatalf("rule %s not in pack", id)
	return nil
}

// activeReviewed returns the ids of active reviewed rules without a range,
// sorted.
func (p *packDoc) activeReviewed() []string {
	var out []string
	for _, e := range p.entries {
		ev := evidenceOf(e)
		if ev["state"] == "active" && ev["basis"] == nil && ruleOf(e)["range"] == nil {
			out = append(out, ruleID(e))
		}
	}
	sort.Strings(out)
	return out
}

func (p *packDoc) sortByID() {
	sort.Slice(p.entries, func(i, j int) bool { return ruleID(p.entries[i]) < ruleID(p.entries[j]) })
}

// editPack applies edit to a pack of the tree and regenerates the files
// derived from it (corpus attestation, support inventory), as the factory
// does before it proposes a change.
func editPack(t *testing.T, tr Tree, rel string, edit func(p *packDoc)) {
	t.Helper()
	p := readPack(t, tr, rel)
	edit(p)
	p.write(t, tr, rel)
	regenerate(t, tr)
}

func regenerate(t *testing.T, tr Tree) {
	t.Helper()
	layout := DefaultLayout()
	for _, spec := range layout.Packs {
		raw, err := spec.Attest(tr)
		if err != nil {
			t.Fatalf("regenerate %s attestation: %v", spec.Name, err)
		}
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(spec.AttestationPath)), raw)
	}
	for _, g := range layout.Generated {
		j, md, err := g.Generate(tr)
		if err != nil {
			t.Fatalf("regenerate %s: %v", g.JSONPath, err)
		}
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(g.JSONPath)), j)
		writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(g.MarkdownPath)), []byte(md))
	}
}

func shiftTime(t *testing.T, v any, d time.Duration) string {
	t.Helper()
	at, err := time.Parse(time.RFC3339, v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return at.Add(d).UTC().Format(time.RFC3339)
}

var gateNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func runGate(t *testing.T, opts Options) *Report {
	t.Helper()
	if opts.Layout.Packs == nil {
		opts.Layout = DefaultLayout()
	}
	if opts.Now.IsZero() {
		opts.Now = gateNow
	}
	pinBaseKeys(&opts)
	fromBot(&opts)
	r, err := Verify(context.Background(), opts)
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	return r
}

func check(r *Report, name string) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

func change(t *testing.T, r *Report, id string) *Change {
	t.Helper()
	for _, c := range r.Changes {
		if c.RuleID == id {
			return c
		}
	}
	t.Fatalf("no change for rule %s", id)
	return nil
}

func failedChecks(r *Report) []string {
	var out []string
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c.Name+": "+c.Detail)
		}
	}
	for _, c := range r.Changes {
		if !c.OK {
			out = append(out, c.RuleID+": "+c.Detail)
		}
	}
	return out
}

func requirePass(t *testing.T, r *Report) {
	t.Helper()
	if !r.Passed() {
		t.Fatalf("gate failed:\n%s", strings.Join(failedChecks(r), "\n"))
	}
}

func requireFail(t *testing.T, r *Report, want string) {
	t.Helper()
	if r.Passed() {
		t.Fatal("gate passed, want a failure")
	}
	for _, f := range failedChecks(r) {
		if strings.Contains(f, want) {
			return
		}
	}
	t.Fatalf("no failure mentions %q:\n%s", want, strings.Join(failedChecks(r), "\n"))
}

// pinBaseKeys stands in for the repository variable that pins the owner
// approval key file: unless a test sets ApprovalKeysDigest itself ("none"
// for no digest), it pins the base's key file as it is.
func pinBaseKeys(opts *Options) {
	switch opts.ApprovalKeysDigest {
	case "none":
		opts.ApprovalKeysDigest = ""
	case "":
		if raw, err := opts.Base.Read(opts.Layout.ApprovalKeysPath, MaxFileBytes); err == nil {
			opts.ApprovalKeysDigest = pinnedDigest(raw)
		}
	}
}

// testHeadSHA stands for the head commit of a test change.
const testHeadSHA = "0123456789abcdef0123456789abcdef01234567"

// botCommits is the commit list of a change made entirely by the
// automation account: one commit it authored, committed and GitHub
// verified, ending at testHeadSHA.
func botCommits() *CommitList {
	c := CommitRecord{SHA: testHeadSHA, Author: &loginField{DefaultBotLogin}, Committer: &loginField{DefaultBotLogin}}
	c.Commit.Verification.Verified = true
	return &CommitList{Status: "ahead", AheadBy: 1, TotalCommits: 1, Commits: []CommitRecord{c}}
}

// fromBot completes a change a test attributes to the automation account
// (Author set, no Sender and no commit list): the run was triggered by it
// and every commit is its own.
func fromBot(opts *Options) {
	if opts.Author == DefaultBotLogin && opts.Sender == "" && opts.Commits == nil {
		opts.Sender, opts.HeadSHA, opts.Commits = DefaultBotLogin, testHeadSHA, botCommits()
	}
}
