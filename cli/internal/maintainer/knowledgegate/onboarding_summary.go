// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/crdversions"
)

// The review summary of an onboarding batch: Markdown rendered from the
// record and the two trees only (no clock, no request counts, no text the
// change supplies outside its data files), so the gate renders it again and
// compares its digest with the one the owner signed. Every character outside
// printable ASCII is escaped (termSafe).

func (st *onboardingState) summary(rec OnboardingRecord) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	sampled := map[int]bool{}
	for _, i := range rec.Sample {
		sampled[i] = true
	}
	rows := projectsBySlug(st.head.projects)
	var attest, added []string
	for _, p := range rec.Projects {
		if p.Kind == OnboardingKindAttest {
			attest = append(attest, p.Slug)
		} else {
			added = append(added, p.Slug)
		}
	}
	w("# Onboarding batch %s\n\n", cell(rec.BatchID))
	w("Candidate: %s. Projects: %d (at most %d). Sample read in full: %d. Nonce: %s.\n\n", cell(rec.CandidateID), len(rec.Projects), MaxOnboardingProjects, len(rec.Sample), cell(rec.Nonce))
	if len(attest) > 0 {
		w("**Attestation turned on: %s.** An attesting target can turn answers into a scope-complete PASS once its line attestations are admitted. The gate admits it only when its own dry run attests the newest pair; the refuted-claims count is the proposal's own.\n\n", cell(strings.Join(attest, ", ")))
	}
	w("New projects: %s.\n\n", cell(orNone(added)))
	w("Signing registers each new project's custom-resource version set and adds its target and table row. It admits no rule, record or attestation: those enter later, re-derived by the gate. The claims counts below are reported by the proposal and are not checked by the gate.\n\n")
	w("| Side | Pack revision | Registry | Table | Targets |\n| --- | --- | --- | --- | --- |\n")
	for _, s := range []struct {
		name string
		v    OnboardingState
	}{{"base", rec.Base}, {"head", rec.Head}} {
		w("| %s | %s | %s | %s | %s |\n", s.name, cell(s.v.PackRevision), cell(s.v.RegistryDigest), cell(s.v.TableDigest), cell(s.v.TargetsDigest))
	}
	w("\nChange set: %s.\n\n", cell(rec.ChangeSetDigest))
	w("## Projects (%d)\n\n", len(rec.Projects))
	w("| # | Slug | Kind | Repository | Paths | Groups | Pair | Scan findings | Claims (confirmed/undetermined/refuted) | Read |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for i, p := range rec.Projects {
		repo, paths := "", ""
		if t, err := crdversions.LoadTarget(crdversions.TargetFileName(p.Slug), st.head.targets[crdversions.TargetFileName(p.Slug)]); err == nil {
			repo = t.Repo
			var list []string
			for _, ps := range t.Paths {
				list = append(list, ps.Path)
			}
			paths = strings.Join(list, ", ")
		}
		read := ""
		if sampled[i] || p.Kind == OnboardingKindAttest {
			read = "in full"
		}
		c := p.Proof.Claims
		w("| %d | %s | %s | %s | %s | %s | %s -> %s | %d | %d/%d/%d | %s |\n", i, cell(p.Slug), p.Kind, cell(repo), cell(paths), cell(strings.Join(p.Groups, ", ")),
			cell(p.Proof.Pair.FromTag), cell(p.Proof.Pair.ToTag), len(p.Proof.Scan), c.Confirmed, c.Undetermined, c.Refuted, read)
	}
	w("\n## Projects to read in full\n")
	for i, p := range rec.Projects {
		if !sampled[i] && p.Kind != OnboardingKindAttest {
			continue
		}
		name := crdversions.TargetFileName(p.Slug)
		w("\n### #%d %s (%s)\n\n", i, cell(p.Slug), p.Kind)
		w("Target %s (sha256 %s):\n\n```json\n%s\n```\n\n", cell(name), cell(shortDigest(CandidateDigest(st.head.targets[name]))), termSafe(strings.TrimSuffix(string(st.head.targets[name]), "\n")))
		if row, ok := rows[p.Slug]; ok {
			raw, _ := json.MarshalIndent(row, "", "  ")
			w("Table row:\n\n```json\n%s\n```\n\nGroup citations:\n\n", termSafe(string(raw)))
			for _, g := range row.Groups {
				w("- %s: <%s>\n", cell(g.Name), cell(g.Source))
			}
			w("\n")
		}
		pr := p.Proof
		w("Dry run: %s (%s) -> %s (%s). Claims ledger %s: %d confirmed, %d undetermined, %d refuted.\n\n", cell(pr.Pair.FromTag), pr.Pair.FromCommit, cell(pr.Pair.ToTag), pr.Pair.ToCommit, cell(pr.Claims.Ledger), pr.Claims.Confirmed, pr.Claims.Undetermined, pr.Claims.Refuted)
		if len(pr.Scan) > 0 {
			w("| Scan class | Path | sha256 |\n| --- | --- | --- |\n")
			for _, f := range pr.Scan {
				w("| %s | %s | %s |\n", cell(f.Class), cell(f.Path), cell(f.SHA256))
			}
			w("\n")
		}
	}
	return b.String()
}

func orNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, ", ")
}
