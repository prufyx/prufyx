// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// batchPathOf is where the fixture's signed onboarding batch lies in the head.
func batchPathOf(f *onboardingFixture, rec OnboardingRecord) string {
	return filepath.Join(f.head.Root, filepath.FromSlash(DefaultLayout().Onboarding.Dir), rec.BatchID+".json")
}

func additionsMember() string {
	return `"additions": {"entryDigest": "sha256:` + strings.Repeat("0", 64) + `", "tagFileSha256": "sha256:` + strings.Repeat("1", 64) + `"}`
}

func requireNoMemberAdmitted(t *testing.T, r *Report) {
	t.Helper()
	t.Logf("failed checks: %s", strings.Join(failedChecks(r), " | "))
	for _, ch := range r.Changes {
		if ch.Member != "" && ch.OK {
			t.Fatalf("member change admitted: %+v", ch)
		}
	}
}

// A v2 file, and a v1 file, that carry an additions member are refused as O1
// through the real gate; the members of the project are never admitted.
func TestOnboardingAdditionsMemberDowngradeO1(t *testing.T) {
	t.Parallel()
	for name, schema := range map[string]string{"v1": OnboardingSchema, "v2": OnboardingSchemaV2} {
		t.Run(name, func(t *testing.T) {
			f := newOnboardingFixture(t)
			rec := f.record(t)
			f.sign(t, rec)
			p := batchPathOf(f, rec)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b = bytes.Replace(b, []byte(`"artifacts"`), []byte(additionsMember()+`, "artifacts"`), 1)
			b = bytes.Replace(b, []byte(`"`+OnboardingSchema+`"`), []byte(`"`+schema+`"`), 1)
			writeFile(t, p, b)
			r := f.gate(t)
			requireFail(t, r, "O1:")
			requireNoMemberAdmitted(t, r)
		})
	}
}

// A real v3 file whose schema is rewritten to v1 or v2 is the same downgrade:
// the older decoder has no additions member and refuses it as O1.
func TestOnboardingV3RecordPresentedAsOlderSchemaO1(t *testing.T) {
	t.Parallel()
	for name, schema := range map[string]string{"v1": OnboardingSchema, "v2": OnboardingSchemaV2} {
		t.Run(name, func(t *testing.T) {
			f := newV3Fixture(t)
			rec := f.record(t)
			f.sign(t, rec)
			p := batchPathOf(f, rec)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(b, []byte(`"`+OnboardingSchemaV3+`"`)) {
				t.Fatal("not a v3 file")
			}
			writeFile(t, p, bytes.Replace(b, []byte(`"`+OnboardingSchemaV3+`"`), []byte(`"`+schema+`"`), 1))
			r := f.gate(t)
			requireFail(t, r, "O1:")
			requireNoMemberAdmitted(t, r)
		})
	}
}

// A v1 record (no additions) never admits a change that touches the
// additions file or a tag file, whichever of the two paths changes.
func TestOnboardingPlainRecordAdditionsPathsFailClosed(t *testing.T) {
	t.Parallel()
	cases := map[string]func(t *testing.T, f *onboardingFixture){
		"additions file and tag file": func(t *testing.T, f *onboardingFixture) { addLines(t, f.head, obSlug) },
		"tag file only": func(t *testing.T, f *onboardingFixture) {
			writeFile(t, tagPath(f.head, obSlug), []byte(addTags))
		},
		"additions file only": func(t *testing.T, f *onboardingFixture) {
			addLines(t, f.head, obSlug)
			if err := os.Remove(tagPath(f.head, obSlug)); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOnboardingFixture(t)
			edit(t, f)
			rec, _ := f.tryRecord(t)
			f.sign(t, rec)
			r := f.gate(t)
			if r.Passed() {
				t.Fatal("a plain v1 record admitted a change to the additions paths")
			}
			requireNoMemberAdmitted(t, r)
		})
	}
}

// The same v1 record rewritten as a v2 envelope (a downgrade of the signing
// domain) fails closed too, with additions paths in the change.
func TestOnboardingPlainRecordAsV2AdditionsPathsFailClosed(t *testing.T) {
	t.Parallel()
	f := newOnboardingFixture(t)
	addLines(t, f.head, obSlug)
	rec, _ := f.tryRecord(t)
	f.sign(t, rec)
	p := batchPathOf(f, rec)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, bytes.Replace(b, []byte(`"`+OnboardingSchema+`"`), []byte(`"`+OnboardingSchemaV2+`"`), 1))
	r := f.gate(t)
	if r.Passed() {
		t.Fatal("a v1 record presented as v2 admitted a change to the additions paths")
	}
	requireNoMemberAdmitted(t, r)
}

// A change to the additions file and a tag file with no record at all (no
// onboarding change, no batch) is human-data: the gate's checks hold its
// contents, but nothing admits it automatically. It is never auto-merge
// eligible and no member change is admitted by a record.
func TestAdditionsPathsNoRecordNeverAutoMerges(t *testing.T) {
	t.Parallel()
	base, head := trees(t)
	addLines(t, head, "zz-new")
	r := runGate(t, Options{Base: base, Head: head})
	if r.AutoMerge.Eligible {
		t.Fatalf("a record-less change to the additions paths is auto-merge eligible: %+v", r.AutoMerge)
	}
	requireNoMemberAdmitted(t, r)
	if _, ok := check(r, CheckOnboarding); ok {
		t.Fatal("an onboarding check ran without an onboarding record")
	}
	if _, ok := check(r, CheckBatch); ok {
		t.Fatal("a batch check ran without a batch record")
	}
}

// A knowledge batch (renewed rules) that also changes the additions file or a
// tag file is refused; the batch admits only its own paths.
func TestKnowledgeBatchRefusesAdditionsPaths(t *testing.T) {
	t.Parallel()
	cases := map[string]func(t *testing.T, f batchFixture){
		"additions file and tag file": func(t *testing.T, f batchFixture) { addLines(t, f.head, "zz-new") },
		"tag file only": func(t *testing.T, f batchFixture) {
			writeFile(t, tagPath(f.head, "zz-new"), []byte(addTags))
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newBatchFixture(t, 3)
			edit(t, f)
			f.signAndWrite(t, f.record(t))
			r := runGate(t, Options{Base: f.base, Head: f.head})
			if r.Passed() {
				t.Fatal("a knowledge batch admitted a change to the additions paths")
			}
			requireNoMemberAdmitted(t, r)
		})
	}
}

// A plain batch that edits the lines additions file of an earlier project
// (no new project) fails closed.
func TestKnowledgeBatchRefusesAlteredAdditionsFile(t *testing.T) {
	t.Parallel()
	f := newBatchFixture(t, 3)
	addLines(t, f.base, "zz-old")
	addLines(t, f.head, "zz-old")
	f.signAndWrite(t, f.record(t))
	writeFile(t, tagPath(f.head, "zz-old"), []byte(addTags+"x\n"))
	r := runGate(t, Options{Base: f.base, Head: f.head})
	if r.Passed() {
		t.Fatal("a knowledge batch admitted an altered tag file")
	}
	if joined := strings.Join(failedChecks(r), "\n"); !strings.Contains(joined, "zz-old") {
		t.Fatalf("the refusal does not name the altered tag file:\n%s", joined)
	}
}
