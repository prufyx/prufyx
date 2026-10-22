// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// A NEW reviewed path policy (no record in the base) is admitted only with
// an owner approval for exactly that record (subject pathPolicy, base state
// absent); every other reviewed path policy change stays renewal-only.

// reviewedPolicy is a reviewed path policy of component, reviewed two hours
// before the gate's clock.
func reviewedPolicy(t *testing.T, p *packDoc, component, policy, state string) map[string]any {
	t.Helper()
	src := deepCopy(evidenceOf(p.find(t, "kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0"))["sources"].([]any)[0]).(map[string]any)
	return map[string]any{
		"component": component, "policy": policy,
		"evidence": map[string]any{
			"state": state, "reviewedAt": gateNow.Add(-2 * time.Hour).Format(time.RFC3339),
			"validUntil": gateNow.Add(50 * 24 * time.Hour).Format(time.RFC3339), "sources": []any{src},
		},
	}
}

func setPolicies(t *testing.T, p *packDoc, policies []map[string]any) {
	t.Helper()
	raw, err := json.Marshal(policies)
	if err != nil {
		t.Fatal(err)
	}
	p.fields["pathPolicies"] = raw
	// A pack carries exactly the schema of its highest feature: path policies.
	p.fields["schema"] = json.RawMessage(`"prufyx.io/cncf-source-rule-pack/v1alpha5"`)
}

// policyTrees returns a base holding the policy of baseState ("": none) and
// a head holding it active as headPolicy.
func policyTrees(t *testing.T, baseState, headPolicy string) (Tree, Tree) {
	t.Helper()
	base, head := trees(t)
	if baseState != "" {
		editPack(t, base, cncfRulesPath, func(p *packDoc) {
			setPolicies(t, p, []map[string]any{reviewedPolicy(t, p, recordComponent, "sequential_minor", baseState)})
		})
	}
	editPack(t, head, cncfRulesPath, func(p *packDoc) {
		setPolicies(t, p, []map[string]any{reviewedPolicy(t, p, recordComponent, headPolicy, "active")})
	})
	return base, head
}

func policyApproval(id, scope, base, digest string) ApprovalRecord {
	return ApprovalRecord{
		BaseDigest: base, CandidateDigest: digest, CandidateID: "cand-1", DecidedAt: gateNow.Add(-time.Hour).Format(time.RFC3339),
		Decision: "approve", Identity: "airstand", Pack: "cncf", RuleID: id,
		Subject: ApprovalSubjectPathPolicy, Scope: scope,
	}
}

func TestGateNewPathPolicyApproval(t *testing.T) {
	t.Parallel()
	key := newApprovalKey(t)
	id := reviewedPolicyID
	setup := func(t *testing.T) (Tree, Tree) {
		base, head := policyTrees(t, "", "sequential_minor")
		key.pinBoth(t, base, head, "airstand")
		return base, head
	}
	run := func(t *testing.T, base, head Tree) *Report {
		return runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin})
	}
	sign := func(t *testing.T, head Tree, rec ApprovalRecord) {
		writeFile(t, approvalPath(head, id), key.sign(t, rec))
	}

	t.Run("valid", func(t *testing.T) {
		base, head := setup(t)
		sign(t, head, policyApproval(id, recordComponent, ApprovalBaseAbsent, recordDigest(t, head, id)))
		r := run(t, base, head)
		requireAdmittedButUnsplit(t, r)
		c := change(t, r, id)
		if c.Proof != ProofApproval || c.Class != ClassLoosening || c.Kinds[0] != KindNew || c.Section != "pathPolicies" || !c.OK {
			t.Fatalf("change %+v", c)
		}
		if rc, _ := check(r, "knowledge-records"); !rc.OK {
			t.Fatalf("records %+v", rc)
		}
	})

	otherComponent := "pkg:github/helm/helm"
	cases := map[string]struct {
		edit func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options
		want string
	}{
		"no approval": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			rec.RuleID = ""
			return Options{}
		}, "no owner approval"},
		"rule approval for the record": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			rec.Subject, rec.Scope = "", ""
			return Options{}
		}, "approves a different kind of subject"},
		"line attestation subject": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			rec.Subject, rec.Scope = ApprovalSubjectLineAttestation, recordComponent+" kubernetes.removed-served-gvk 1.25"
			return Options{}
		}, "approves a different kind of subject"},
		"other scope": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			rec.Scope = otherComponent
			return Options{}
		}, "approves a different rule"},
		"other record id": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			rec.RuleID = evidencerepin.PathPolicyRecordID(otherComponent)
			return Options{}
		}, "approves a different rule"},
		"record changed after approval": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			// The approval is signed over the record as it is now; the
			// policy is edited afterwards.
			writeFile(t, approvalPath(head, id), key.sign(t, *rec))
			editPack(t, head, cncfRulesPath, func(p *packDoc) {
				setPolicies(t, p, []map[string]any{reviewedPolicy(t, p, recordComponent, "direct", "active")})
			})
			rec.RuleID = ""
			return Options{}
		}, "candidate digest does not match"},
		"base state other than absent": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			// SignedApprovalBytes refuses such a record, so a hand-made file
			// signs the bytes itself.
			rec.BaseDigest = rec.CandidateDigest
			body, err := json.Marshal(*rec)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.MarshalIndent(ApprovalEnvelope{Schema: ApprovalSchema, Record: *rec, KeyID: ApprovalKeyID(key.public),
				Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key.private, append([]byte(ApprovalDomain), body...)))}, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, approvalPath(head, id), append(raw, '\n'))
			rec.RuleID = ""
			return Options{}
		}, "field out of range"},
		"approval already in the base": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			writeFile(t, approvalPath(base, id), key.sign(t, *rec))
			return Options{}
		}, "already in the base"},
		"approval already in the base, re-encoded": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			signed := key.sign(t, *rec)
			writeFile(t, approvalPath(base, id), signed)
			var compact bytes.Buffer
			if err := json.Compact(&compact, signed); err != nil {
				t.Fatal(err)
			}
			writeFile(t, approvalPath(head, id), append(compact.Bytes(), '\n'))
			rec.RuleID = ""
			return Options{}
		}, "already in the base"},
		"approval already in the base, signed by another key": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			other := newApprovalKey(t)
			for _, tr := range []Tree{base, head} {
				raw, err := json.MarshalIndent(ApprovalKeys{
					Schema: ApprovalKeysSchema, Role: ApprovalKeyRole, Owners: []string{"airstand"},
					Keys: []ApprovalKey{
						{KeyID: ApprovalKeyID(key.public), PublicKey: hexKey(key), NotAfter: "2027-10-01T00:00:00Z"},
						{KeyID: ApprovalKeyID(other.public), PublicKey: hexKey(other), NotAfter: "2027-10-01T00:00:00Z"},
					},
				}, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(tr.Root, filepath.FromSlash(DefaultLayout().ApprovalKeysPath)), raw)
			}
			writeFile(t, approvalPath(base, id), other.sign(t, *rec))
			return Options{}
		}, "already in the base"},
		// An approval decided later is in the base: decisions only move forward.
		"later decision in the base": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			later := *rec
			later.DecidedAt = gateNow.Add(-30 * time.Minute).Format(time.RFC3339)
			later.CandidateID = "cand-2"
			writeFile(t, approvalPath(base, "path-policy.elsewhere"), key.sign(t, later))
			return Options{}
		}, "decided at the same time or later"},
		"kill switch": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			writeFile(t, head.Root+"/factory/PAUSE", nil)
			return Options{}
		}, "kill switch"},
		"older than 14 days": {func(t *testing.T, base, head Tree, rec *ApprovalRecord) Options {
			rec.DecidedAt = gateNow.Add(-15 * 24 * time.Hour).Format(time.RFC3339)
			return Options{}
		}, "older than 14 days"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			base, head := setup(t)
			rec := policyApproval(id, recordComponent, ApprovalBaseAbsent, recordDigest(t, head, id))
			o := Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin}
			if got := tc.edit(t, base, head, &rec); got.Base.Root != "" {
				o = got
			}
			if rec.RuleID != "" {
				sign(t, head, rec)
			}
			r := runGate(t, o)
			requireFail(t, r, tc.want)
			if c := change(t, r, id); c.OK {
				t.Fatalf("admitted: %+v", c)
			}
		})
	}

	// An existing record stays renewal-only: a withdrawn record is not
	// reactivated and an active one is not edited, approval or not.
	for name, baseState := range map[string]string{"withdrawn base reactivated": "withdrawn", "active base edited": "active"} {
		t.Run(name, func(t *testing.T) {
			base, head := policyTrees(t, baseState, "direct")
			key.pinBoth(t, base, head, "airstand")
			sign(t, head, policyApproval(id, recordComponent, ApprovalBaseAbsent, recordDigest(t, head, id)))
			r := run(t, base, head)
			requireFail(t, r, "changes only by renewal")
			if c := change(t, r, id); c.OK {
				t.Fatalf("admitted: %+v", c)
			}
		})
	}

	// A batch in the same change admits no path policy, even with its own
	// approval.
	t.Run("batch present", func(t *testing.T) {
		f := newBatchFixture(t, 1)
		f.signAndWrite(t, f.record(t))
		editPack(t, f.head, cncfRulesPath, func(p *packDoc) {
			setPolicies(t, p, []map[string]any{reviewedPolicy(t, p, recordComponent, "sequential_minor", "active")})
		})
		writeFile(t, approvalPath(f.head, id), f.key.sign(t, policyApproval(id, recordComponent, ApprovalBaseAbsent, recordDigest(t, f.head, id))))
		r := runGate(t, Options{Base: f.base, Head: f.head, Source: fixtureSource})
		requireFail(t, r, "carrying a batch approval admits no path policy")
		if c := change(t, r, id); c.OK {
			t.Fatalf("admitted: %+v", c)
		}
	})

	// The approval key changes in the same change: records-trust fails.
	t.Run("key change in the same change", func(t *testing.T) {
		base, head := setup(t)
		sign(t, head, policyApproval(id, recordComponent, ApprovalBaseAbsent, recordDigest(t, head, id)))
		newApprovalKey(t).pin(t, head, "airstand")
		raw, err := os.ReadFile(filepath.Join(head.Root, filepath.FromSlash(approvalKeys)))
		if err != nil {
			t.Fatal(err)
		}
		r := runGate(t, Options{Base: base, Head: head, Source: fixtureSource, Author: DefaultBotLogin, ApprovalKeysDigest: pinnedDigest(raw)})
		if c, ok := check(r, "records-trust"); !ok || c.OK {
			t.Fatalf("records-trust %+v", c)
		}
		if r.Passed() {
			t.Fatal("gate passed")
		}
	})
}

func hexKey(k testApprovalKey) string { return hex.EncodeToString(k.public) }

func policyFixture(t *testing.T) signFixture {
	t.Helper()
	base, head := policyTrees(t, "", "sequential_minor")
	return pinFixture(t, base, head, reviewedPolicyID)
}

func (f signFixture) policySubjectArgs() []string {
	args := f.recordSubjectArgs(f.id)
	args[1] = "pathPolicy"
	return args
}

func (f signFixture) policySignArgs(keyArgs ...string) []string {
	args := append([]string{"sign"}, f.policySubjectArgs()...)
	args = append(args, "--identity", "airstand", "--candidate-id", "pr-42", "--output", f.out())
	return append(args, keyArgs...)
}

func (f signFixture) policyVerifyArgs() []string {
	return append([]string{"verify", "--approval", f.out(), "--base-root", f.base.Root}, f.policySubjectArgs()...)
}

// A path policy approval written by "approval sign" is admitted by the gate
// and "approval verify" accepts it; a changed record, a missing --base-root
// and --rule are refused.
func TestApprovalSignPathPolicyRoundTrip(t *testing.T) {
	t.Parallel()
	f := policyFixture(t)
	requireCode(t, runApproval(t, f.key.pemKey(t), signNow, f.policySignArgs("--key-stdin")...), 0, "new path policy cncf/"+f.id)
	r := runGate(t, Options{Base: f.base, Head: f.head, Source: fixtureSource, Author: DefaultBotLogin, ApprovalKeysDigest: f.keysDigest})
	requireAdmittedButUnsplit(t, r)
	if c := change(t, r, f.id); c.Proof != ProofApproval {
		t.Fatalf("proof %q", c.Proof)
	}
	requireCode(t, runApproval(t, nil, gateNow, f.policyVerifyArgs()...), 0, "approval OK")

	t.Run("record edited after signing", func(t *testing.T) {
		editPack(t, f.head, cncfRulesPath, func(p *packDoc) {
			setPolicies(t, p, []map[string]any{reviewedPolicy(t, p, recordComponent, "direct", "active")})
		})
		requireCode(t, runApproval(t, nil, gateNow, f.policyVerifyArgs()...), 1, "approval REFUSED")
	})
	t.Run("verify without --base-root", func(t *testing.T) {
		args := f.policyVerifyArgs()
		args = append(args[:3], args[5:]...) // drop --base-root DIR
		requireCode(t, runApproval(t, nil, gateNow, args...), 2, "--base-root is required")
	})
	t.Run("rule flag", func(t *testing.T) {
		g := policyFixture(t)
		requireCode(t, runApproval(t, g.key.pemKey(t), signNow, append(g.policySignArgs("--key-stdin"), "--rule", "x")...), 2, "takes --record ID, not --rule")
	})
}

// The signer refuses what the gate would refuse: a record the base holds
// (any edit), a mechanical or missing record, a line attestation.
func TestPathPolicyApprovalSubject(t *testing.T) {
	t.Parallel()
	spec := recordLayout().Packs[0]
	base, _, _ := recordPack(t, gateNow, false)
	withMechanical, _, _ := recordPack(t, gateNow, true)
	edit := func(t *testing.T, raw []byte, change func(doc map[string]any)) []byte {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		change(doc)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	noPolicy := edit(t, base, func(doc map[string]any) { delete(doc, "pathPolicies") })
	sub, err := PathPolicyApprovalSubject(spec, noPolicy, base, reviewedPolicyID)
	if err != nil || sub.Kind != ApprovalSubjectPathPolicy || sub.Scope != recordComponent || sub.Base != nil || sub.BaseDigest() != ApprovalBaseAbsent {
		t.Fatalf("new policy: %+v, %v", sub, err)
	}
	for name, tc := range map[string]struct {
		base, head []byte
		id, want   string
	}{
		"unchanged existing": {base, base, reviewedPolicyID, "exists in the base"},
		"existing renewed": {base, edit(t, base, func(doc map[string]any) {
			ev := sectionRecord(doc, "pathPolicies", 0)["evidence"].(map[string]any)
			ev["validUntil"] = shiftTime(t, ev["validUntil"], 24*time.Hour)
		}), reviewedPolicyID, "exists in the base"},
		"existing edited": {base, edit(t, base, func(doc map[string]any) { sectionRecord(doc, "pathPolicies", 0)["policy"] = "direct" }), reviewedPolicyID, "exists in the base"},
		"missing":         {noPolicy, noPolicy, reviewedPolicyID, "has no record"},
		"mechanical basis": {noPolicy, edit(t, base, func(doc map[string]any) {
			ev := sectionRecord(doc, "pathPolicies", 0)["evidence"].(map[string]any)
			ev["basis"] = "mechanical"
			ev["extractor"] = map[string]any{"id": "x", "version": "1.0.0", "codeDigest": "sha256:" + strings.Repeat("a", 64)}
			ev["derivedAt"] = ev["reviewedAt"]
		}), reviewedPolicyID, "an approval admits only a reviewed path policy"},
		"line attestation": {noPolicy, withMechanical, reviewedAttestationID, "is not a path policy"},
		"bad id":           {noPolicy, base, "a b", "not a valid approval record ID"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PathPolicyApprovalSubject(spec, tc.base, tc.head, tc.id); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestApprovalValidatePathPolicy(t *testing.T) {
	t.Parallel()
	ok := policyApproval(reviewedPolicyID, recordComponent, ApprovalBaseAbsent, "sha256:"+strings.Repeat("a", 64))
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(r *ApprovalRecord){
		"base digest": func(r *ApprovalRecord) { r.BaseDigest = r.CandidateDigest },
		"line scope":  func(r *ApprovalRecord) { r.Scope = recordComponent + " kubernetes.removed-served-gvk 1.25" },
		"empty scope": func(r *ApprovalRecord) { r.Scope = "" },
		"not a purl":  func(r *ApprovalRecord) { r.Scope = "kubernetes/kubernetes" },
	} {
		r := ok
		mod(&r)
		if err := r.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
